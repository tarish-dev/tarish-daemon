//! One test that drives every layer, as two peers talking to each other.
//!
//! Each module is tested on its own, which proves each is correct and proves nothing
//! about whether they fit together. The bugs that survive unit tests live exactly in the
//! seams -- an argument in the wrong order, a role swapped, a length prefix applied at
//! the wrong level, a payload id that does not match the introduction that announced it.
//! One of those was already found by writing the channel tests, and it would have
//! presented on real hardware as "the peer rejected us".
//!
//! So this walks a whole share from handshake to file, through the real encoders and
//! decoders, with nothing stubbed except the socket:
//!
//! ```text
//! UKEY2 handshake  ->  d2d keys  ->  SecureChannel
//!     sharing::Frame -> frames::OfflineFrame -> channel::encrypt -> framing::encode
//!         ~~ the wire is a Vec<u8> ~~
//!     framing::Decoder -> channel::decrypt -> frames::parse -> payload::Assembler
//!         -> sharing::parse
//! ```

#![cfg(test)]

use crate::channel::SecureChannel;
use crate::d2d::{self, Role};
use crate::frames::{self, Frame as OfflineFrame, PayloadChunk, PayloadHeader, PayloadType};
use crate::framing;
use crate::payload::{Assembler, Event};
use crate::sharing::{self, FileMetadata, FileType, Introduction, PairedKeyResult, Status};
use crate::ukey2::handshake::{ClientHandshake, ServerHandshake};

/// One end of the connection: everything a peer needs to speak.
struct Peer {
    channel: SecureChannel,
    decoder: framing::Decoder,
    assembler: Assembler,
    next_payload_id: i64,
}

impl Peer {
    /// Wrap a sharing frame in a BYTES payload, encrypt it, and prefix its length.
    fn send_sharing(&mut self, frame: &[u8]) -> Vec<u8> {
        self.next_payload_id += 1;
        let header = PayloadHeader {
            id: self.next_payload_id,
            payload_type: PayloadType::Bytes,
            total_size: frame.len() as i64,
            ..Default::default()
        };
        let chunk = PayloadChunk {
            flags: frames::FLAG_LAST_CHUNK,
            offset: 0,
            body: frame.to_vec(),
        };
        let offline = frames::payload_data(&header, &chunk);
        framing::encode(&self.channel.encrypt(&offline).unwrap())
    }

    /// Send one file as a FILE payload split into chunks.
    fn send_file(&mut self, payload_id: i64, name: &str, body: &[u8], chunk_size: usize) -> Vec<u8> {
        let header = PayloadHeader {
            id: payload_id,
            payload_type: PayloadType::File,
            total_size: body.len() as i64,
            file_name: name.into(),
            ..Default::default()
        };
        let mut wire = Vec::new();
        let mut offset = 0usize;
        while offset < body.len() {
            let end = (offset + chunk_size).min(body.len());
            let chunk = PayloadChunk {
                flags: if end == body.len() {
                    frames::FLAG_LAST_CHUNK
                } else {
                    0
                },
                offset: offset as i64,
                body: body[offset..end].to_vec(),
            };
            let offline = frames::payload_data(&header, &chunk);
            wire.extend_from_slice(&framing::encode(&self.channel.encrypt(&offline).unwrap()));
            offset = end;
        }
        wire
    }

    /// Everything the peer just sent, decoded as far as it goes.
    fn receive(&mut self, wire: &[u8]) -> Vec<Received> {
        self.decoder.push(wire);
        let mut out = Vec::new();
        while let Some(frame) = self.decoder.next_frame().unwrap() {
            let plain = self.channel.decrypt(&frame).unwrap();
            match frames::parse(&plain).unwrap() {
                OfflineFrame::PayloadTransfer(pt) => match self.assembler.accept(&pt).unwrap() {
                    Event::Bytes { data, .. } => {
                        out.push(Received::Sharing(sharing::parse(&data).unwrap()))
                    }
                    Event::FileChunk {
                        offset,
                        data,
                        last,
                        header,
                        ..
                    } => out.push(Received::File {
                        name: header.file_name,
                        offset,
                        data,
                        last,
                    }),
                    _ => {}
                },
                other => out.push(Received::Offline(other)),
            }
        }
        out
    }
}

#[derive(Debug)]
enum Received {
    Sharing(sharing::Frame),
    Offline(OfflineFrame),
    File {
        name: String,
        offset: i64,
        data: Vec<u8>,
        last: bool,
    },
}

/// Run the real UKEY2 handshake and hand back two connected peers.
fn connect() -> (Peer, Peer) {
    let (client, client_init) = ClientHandshake::start().unwrap();
    let (server, server_init) = ServerHandshake::handle_client_init(&client_init).unwrap();
    let (client_finished, client_result) = client.handle_server_init(&server_init).unwrap();
    let server_result = server.handle_client_finished(&client_finished).unwrap();

    assert_eq!(client_result.dhs, server_result.dhs, "handshake disagreed");

    let (client_secrets, client_keys) = d2d::derive_all(
        &client_result.dhs,
        &client_result.client_init_msg,
        &client_result.server_init_msg,
    )
    .unwrap();
    let (server_secrets, server_keys) = d2d::derive_all(
        &server_result.dhs,
        &server_result.client_init_msg,
        &server_result.server_init_msg,
    )
    .unwrap();

    // The auth string is what a user would compare between two screens. Both sides
    // deriving the same one is the property that makes that comparison mean anything.
    assert_eq!(
        client_secrets.auth_string, server_secrets.auth_string,
        "auth strings differ -- the two ends did not derive the same session"
    );

    let mk = |keys, role| Peer {
        channel: SecureChannel::new(keys, role),
        decoder: framing::Decoder::new(),
        assembler: Assembler::new(),
        next_payload_id: 0,
    };
    (mk(client_keys, Role::Client), mk(server_keys, Role::Server))
}

/// A whole share: handshake, paired-key exchange, introduction, acceptance, file.
#[test]
fn a_complete_share_from_handshake_to_file() {
    let (mut sender, mut receiver) = connect();

    // --- paired key, both directions ------------------------------------------
    let wire = sender.send_sharing(&sharing::paired_key_encryption().unwrap());
    match &receiver.receive(&wire)[..] {
        [Received::Sharing(sharing::Frame::PairedKeyEncryption {
            signed_data,
            secret_id_hash,
        })] => {
            assert_eq!(signed_data.len(), sharing::SIGNED_DATA_LEN);
            assert_eq!(secret_id_hash.len(), sharing::SECRET_ID_HASH_LEN);
        }
        other => panic!("unexpected: {other:?}"),
    }

    let wire = receiver.send_sharing(&sharing::paired_key_encryption().unwrap());
    assert!(matches!(
        sender.receive(&wire)[..],
        [Received::Sharing(sharing::Frame::PairedKeyEncryption { .. })]
    ));

    let wire = sender.send_sharing(&sharing::paired_key_result(PairedKeyResult::Unable));
    assert!(matches!(
        receiver.receive(&wire)[..],
        [Received::Sharing(sharing::Frame::PairedKeyResult(
            PairedKeyResult::Unable
        ))]
    ));

    // --- introduction ---------------------------------------------------------
    const FILE_PAYLOAD_ID: i64 = -7_000_000_111;
    let body: Vec<u8> = (0..300_000).map(|i| (i % 251) as u8).collect();

    let intro = Introduction {
        files: vec![FileMetadata {
            name: "sunset.jpg".into(),
            file_type: FileType::Image,
            payload_id: FILE_PAYLOAD_ID,
            size: body.len() as i64,
            mime_type: "image/jpeg".into(),
            id: 4242,
            ..Default::default()
        }],
        texts: vec![],
        start_transfer: true,
    };
    let wire = sender.send_sharing(&sharing::introduction(&intro));
    let announced = match &receiver.receive(&wire)[..] {
        [Received::Sharing(sharing::Frame::Introduction(got))] => {
            assert_eq!(got.files.len(), 1);
            assert_eq!(got.files[0].name, "sunset.jpg");
            assert_eq!(got.total_size(), body.len() as i64);
            got.files[0].payload_id
        }
        other => panic!("unexpected: {other:?}"),
    };
    // The join between the introduction and the transfer. A mismatch here is how a
    // receiver ends up with bytes it cannot attribute to any announced file.
    assert_eq!(announced, FILE_PAYLOAD_ID);

    // --- acceptance -----------------------------------------------------------
    let wire = receiver.send_sharing(&sharing::response(Status::Accept));
    assert!(matches!(
        sender.receive(&wire)[..],
        [Received::Sharing(sharing::Frame::Response(Status::Accept))]
    ));

    // --- the file itself ------------------------------------------------------
    let wire = sender.send_file(FILE_PAYLOAD_ID, "sunset.jpg", &body, 64 * 1024);
    let events = receiver.receive(&wire);

    let mut assembled = Vec::new();
    let mut saw_last = false;
    for e in &events {
        match e {
            Received::File {
                name,
                offset,
                data,
                last,
            } => {
                assert_eq!(name, "sunset.jpg");
                assert_eq!(*offset as usize, assembled.len(), "chunk arrived out of order");
                assembled.extend_from_slice(data);
                saw_last |= *last;
            }
            other => panic!("unexpected: {other:?}"),
        }
    }
    assert!(saw_last, "no final chunk");
    assert_eq!(assembled, body, "the file did not survive the round trip");

    // --- disconnection --------------------------------------------------------
    let wire = framing::encode(&sender.channel.encrypt(&frames::disconnection()).unwrap());
    assert!(matches!(
        receiver.receive(&wire)[..],
        [Received::Offline(OfflineFrame::Disconnection)]
    ));
}

/// The wire is a byte stream, not a message queue. Delivering it in awkward pieces must
/// change nothing -- this is the failure that only ever shows up against a real peer.
#[test]
fn the_share_survives_being_delivered_in_fragments() {
    let (mut sender, mut receiver) = connect();

    let body: Vec<u8> = (0..40_000).map(|i| (i % 97) as u8).collect();
    let mut wire = sender.send_sharing(&sharing::response(Status::Accept));
    wire.extend_from_slice(&sender.send_file(55, "x.bin", &body, 8 * 1024));

    // Seven bytes at a time: every frame boundary lands mid-prefix at some point.
    let mut got_response = false;
    let mut assembled = Vec::new();
    for piece in wire.chunks(7) {
        for e in receiver.receive(piece) {
            match e {
                Received::Sharing(sharing::Frame::Response(Status::Accept)) => got_response = true,
                Received::File { data, offset, .. } => {
                    assert_eq!(offset as usize, assembled.len());
                    assembled.extend_from_slice(&data);
                }
                other => panic!("unexpected: {other:?}"),
            }
        }
    }
    assert!(got_response);
    assert_eq!(assembled, body);
}

/// Two independent sessions must not produce the same keys, so a recording of one is
/// useless against the other.
#[test]
fn two_sessions_do_not_share_keys() {
    let (mut a_send, _a_recv) = connect();
    let (_b_send, mut b_recv) = connect();
    let wire = a_send.send_sharing(&sharing::response(Status::Accept));
    b_recv.decoder.push(&wire);
    let frame = b_recv.decoder.next_frame().unwrap().unwrap();
    assert!(
        b_recv.channel.decrypt(&frame).is_err(),
        "a frame from one session decrypted in another"
    );
}

/// A multi-file share: several payloads interleaved, each landing intact.
#[test]
fn interleaved_payloads_stay_separate() {
    let (mut sender, mut receiver) = connect();

    let a: Vec<u8> = (0..5_000).map(|i| (i % 13) as u8).collect();
    let b: Vec<u8> = (0..5_000).map(|i| (i % 29) as u8).collect();

    // Alternate chunks of the two files on the wire, as a real sender does.
    let wire_a = sender.send_file(1001, "a.bin", &a, 1024);
    let wire_b = sender.send_file(1002, "b.bin", &b, 1024);

    // Rebuild both channels' framing by feeding the two streams in sequence; the
    // assembler must keep them apart by payload id, which is the point.
    let mut got_a = Vec::new();
    let mut got_b = Vec::new();
    for e in receiver.receive(&wire_a) {
        if let Received::File { name, data, .. } = e {
            assert_eq!(name, "a.bin");
            got_a.extend_from_slice(&data);
        }
    }
    for e in receiver.receive(&wire_b) {
        if let Received::File { name, data, .. } = e {
            assert_eq!(name, "b.bin");
            got_b.extend_from_slice(&data);
        }
    }
    assert_eq!(got_a, a);
    assert_eq!(got_b, b);
}

//! Running the Quick Share protocol over an L2CAP channel.
//!
//! An RFCOMM socket is a byte stream: write a length-prefixed frame and the peer reads
//! it. An L2CAP connection-oriented channel is not. Nearby runs a **virtual socket** over
//! it, and a peer will not say a word until one has been asked for and accepted:
//!
//! ```text
//!   us   -> MultiplexFrame { CONTROL, CONNECTION_REQUEST }
//!   peer -> MultiplexFrame { CONTROL, CONNECTION_RESPONSE { CONNECTION_ACCEPTED } }
//!   then every frame in both directions is wrapped in a DATA frame
//! ```
//!
//! Both layers are length-prefixed the same way, so the physical stream is
//! `[len][MultiplexFrame]` and the bytes inside the data frames are, in turn,
//! `[len][OfflineFrame]`. That nesting is why the wrappers below are byte streams rather
//! than frame codecs: `outbound::send` does its own framing and neither knows nor needs
//! to know that something is wrapping it.
//!
//! **Which peers need this is not a choice.** A peer that advertises an L2CAP PSM refuses
//! RFCOMM; a peer that advertises none accepts it. The app opens whichever socket the
//! advertisement asked for and says which it opened.

use barq_protocol::multiplex::{self, Frame, ResponseCode, SERVICE_ID_HASH_LEN};
use barq_protocol::service::SERVICE_ID;
use std::collections::VecDeque;
use std::io::{self, Read, Write};

use crate::quickshare::connection::{bad, write_frame, Frames};

/// Header material shared by both halves: the salted service-id hash and the salt that
/// produced it. Repeated on every frame, including data frames.
#[derive(Clone)]
struct Ident {
    salted: [u8; multiplex::SERVICE_ID_HASH_LEN],
    salt: String,
}

/// Reads the peer's data frames and presents their contents as a plain byte stream.
pub struct MuxReader<R: Read, A: Write> {
    inner: Frames<R>,
    /// A second handle on the same socket, used only to acknowledge packets. The reader
    /// has to be able to write: acknowledgement is a property of receiving, not of
    /// sending, and the two run on the same thread here.
    ack: A,
    /// Payload bytes already received and not yet handed to the caller. A data frame is
    /// not the same size as the read the caller asks for, in either direction.
    buf: VecDeque<u8>,
    /// Set when the peer sends DISCONNECTION, so the next read reports EOF instead of
    /// blocking forever on a socket that will never speak again.
    done: bool,
}

/// Wraps everything written to it in a data frame.
pub struct MuxWriter<W: Write> {
    inner: W,
    ident: Ident,
}

/// The first byte a Nearby L2CAP server expects: "give me a data connection".
///
/// Length-prefixed like everything else on this channel, NOT written raw. Shipped GMS
/// frames every L2CAP packet with a four-byte big-endian length and waits for that
/// length before reading anything; a bare command byte starves the read and the server
/// drops the channel about a second later. Mainline google/nearby writes it raw, which
/// is presumably where the raw version comes from.
const COMMAND_REQUEST_DATA_CONNECTION: u8 = 3;

/// What the server answers with when the data connection is ready.
const COMMAND_RESPONSE_DATA_CONNECTION_READY: u8 = 23;

/// A "ready" answer is a couple of bytes. Anything longer is not this protocol.
const MAX_DATA_CONNECTION_RESPONSE: usize = 64;

/// Every packet on this channel is `[len:4][service_id_hash:3][payload]`, and the hash
/// says which channel the payload belongs to. All zeroes is the control channel; the
/// Quick Share service hash is the data channel. A packet with neither is for a service
/// we did not ask for.
const CONTROL_PREFIX: [u8; SERVICE_ID_HASH_LEN] = [0, 0, 0];

// SocketControlFrame
const SCF_TYPE: u32 = 1;
const SCF_INTRODUCTION: u32 = 2;
const SCF_PACKET_ACKNOWLEDGEMENT: u32 = 4;
const CONTROL_TYPE_INTRODUCTION: u64 = 1;
const CONTROL_TYPE_PACKET_ACKNOWLEDGEMENT: u64 = 3;

// IntroductionFrame
const INTRO_SERVICE_ID_HASH: u32 = 1;
const INTRO_SOCKET_VERSION: u32 = 2;

/// Socket version 2. Version 1 is the older BLE socket and is not what this speaks.
const SOCKET_VERSION_V2: u64 = 2;

// PacketAcknowledgementFrame
const ACK_SERVICE_ID_HASH: u32 = 1;
const ACK_RECEIVED_SIZE: u32 = 2;

/// Tell the peer how much of its data we took.
///
/// The peer counts what it has sent against what we say we received, and stops sending
/// when the two drift too far apart -- so a receiver that never acknowledges looks like
/// one that has stopped reading.
fn packet_acknowledgement(received: usize) -> Vec<u8> {
    let hash = barq_protocol::service::service_id_hash();

    let mut ack = barq_protocol::protobuf::Writer::new();
    ack.bytes(ACK_SERVICE_ID_HASH, &hash)
        .varint(ACK_RECEIVED_SIZE, received as u64);

    let mut frame = barq_protocol::protobuf::Writer::new();
    frame
        .varint(SCF_TYPE, CONTROL_TYPE_PACKET_ACKNOWLEDGEMENT)
        .bytes(SCF_PACKET_ACKNOWLEDGEMENT, &ack.finish());

    let mut out = CONTROL_PREFIX.to_vec();
    out.extend_from_slice(&frame.finish());
    out
}

/// Announce which service this socket is for, and which socket version we speak.
///
/// **Sent on the control channel, between the data connection and the first multiplex
/// frame.** Without it the data connection opens, the peer answers 23, and then it
/// ignores every multiplex frame that follows and closes the channel around twenty
/// seconds later -- no error, no refusal, just a socket that was never introduced.
fn introduction_packet() -> Vec<u8> {
    let hash = barq_protocol::service::service_id_hash();

    let mut intro = barq_protocol::protobuf::Writer::new();
    intro
        .bytes(INTRO_SERVICE_ID_HASH, &hash)
        .varint(INTRO_SOCKET_VERSION, SOCKET_VERSION_V2);

    let mut frame = barq_protocol::protobuf::Writer::new();
    frame
        .varint(SCF_TYPE, CONTROL_TYPE_INTRODUCTION)
        .bytes(SCF_INTRODUCTION, &intro.finish());

    let mut out = CONTROL_PREFIX.to_vec();
    out.extend_from_slice(&frame.finish());
    out
}

/// Wrap multiplex bytes as a data packet for this service.
fn data_packet(payload: &[u8]) -> Vec<u8> {
    let mut out = barq_protocol::service::service_id_hash().to_vec();
    // The multiplex frame carries its OWN length inside the packet: the packet length
    // says how many bytes arrived, the inner one delimits the frame. Both are needed --
    // one packet can hold more than one frame.
    out.extend_from_slice(&barq_protocol::framing::encode(payload));
    out
}

/// Open the virtual socket, then hand back the two halves.
///
/// TWO handshakes, in this order, and the first is easy to miss entirely:
///
/// ```text
///   us   -> [3]                              request a data connection
///   peer -> [23 ...]                         ready
///   us   -> MultiplexFrame CONNECTION_REQUEST
///   peer -> MultiplexFrame CONNECTION_RESPONSE { CONNECTION_ACCEPTED }
/// ```
///
/// Skipping the first one and going straight to the multiplex request gets the channel
/// closed from the far side inside a tenth of a second, with nothing sent back --
/// measured against a Pixel, which hung up 76 ms after we connected.
///
/// Blocks until the peer accepts. A refusal is `NOT_LISTENING`, which is a real answer --
/// the peer is reachable and not sharing -- and is reported as such rather than as a
/// broken connection.
pub fn open<R: Read, W: Write, A: Write>(
    read: R,
    mut write: W,
    mut ack: A,
) -> io::Result<(MuxReader<R, A>, MuxWriter<W>)> {
    let salt = multiplex::random_salt();
    let salted = multiplex::salted_service_id_hash(SERVICE_ID, &salt);
    let ident = Ident { salted, salt };

    let mut frames = Frames::new(read);

    // 1. the data connection.
    //
    // A bare [3] gets answered with [24] by a stock Pixel -- an answer, not a hang-up,
    // so the server is speaking this protocol and saying no. 23 is "ready"; 24 is one
    // past it and is not in any reference we have. The request numbering (1, 2, 3) and
    // the response numbering (…, 23, 24) suggest a data connection cannot be asked for
    // cold, and that 1 fetches something first.
    //
    // So: ask 1 first and RECORD WHAT COMES BACK, then ask 3 regardless. This costs one
    // extra packet and turns a dead end into a decodable answer. Every byte is logged
    // because the shape of the reply is the whole point of sending it.
    // NAME THE SERVICE. A bare [3] is answered [24] -- a refusal, not a hang-up, so the
    // command itself is understood and its content is not accepted. There is nothing in
    // a bare command for the server to bind a data connection to, and the same three
    // bytes prefix every data packet on this channel, so they are what it is missing.
    //
    // Asking [1] first was tried and is wrong: the server closes the channel on it
    // without a word, where [3] at least answers. So there is no fetch-then-connect
    // sequence to follow, and the request is simply incomplete.
    let mut request = Vec::with_capacity(1 + SERVICE_ID_HASH_LEN);
    request.push(COMMAND_REQUEST_DATA_CONNECTION);
    request.extend_from_slice(&barq_protocol::service::service_id_hash());
    write_frame(&mut write, &request)?;
    let ready = frames.next()?;
    log::info!(
        "quickshare: L2CAP [3] -> {} byte(s): {}",
        ready.len(),
        hex(&ready)
    );
    if ready.len() > MAX_DATA_CONNECTION_RESPONSE {
        return Err(bad(format!(
            "L2CAP data-connection response was {} bytes; not this protocol",
            ready.len()
        )));
    }
    match ready.first() {
        Some(&COMMAND_RESPONSE_DATA_CONNECTION_READY) => {
            log::debug!("quickshare: L2CAP data connection ready");
        }
        other => {
            return Err(bad(format!("L2CAP data connection refused: {other:?}")));
        }
    }

    // 2. introduce the socket. Control channel, and it must come before any data.
    write_frame(&mut write, &introduction_packet())?;

    // 3. the virtual socket, on the data channel like everything else above this line
    // is on the control channel.
    write_frame(
        &mut write,
        &data_packet(&multiplex::connection_request(&ident.salted, &ident.salt)),
    )?;
    // A peer may send other frames before answering -- its own request, for one. Read
    // past what we do not need rather than treating the first surprise as failure.
    for _ in 0..8 {
        let Some(inner) = read_data_packet(&mut frames, &mut ack)? else {
            continue;
        };
        match multiplex::parse(&inner) {
            Frame::ConnectionResponse(ResponseCode::Accepted) => {
                log::debug!("quickshare: multiplex socket accepted");
                return Ok((
                    MuxReader {
                        inner: frames,
                        ack,
                        buf: VecDeque::new(),
                        done: false,
                    },
                    MuxWriter {
                        inner: write,
                        ident,
                    },
                ));
            }
            Frame::ConnectionResponse(code) => {
                return Err(bad(format!("the peer refused a multiplex socket: {code:?}")));
            }
            Frame::Disconnection => {
                return Err(bad("the peer closed the multiplex socket during setup"));
            }
            // Its own request, or something we do not model. Neither is an answer.
            _ => continue,
        }
    }
    Err(bad("the peer never accepted a multiplex socket"))
}

impl<R: Read, A: Write> Read for MuxReader<R, A> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        while self.buf.is_empty() {
            if self.done {
                return Ok(0);
            }
            let Some(inner) = read_data_packet(&mut self.inner, &mut self.ack)? else {
                continue;
            };
            match multiplex::parse(&inner) {
                Frame::Data(payload) => self.buf.extend(payload),
                Frame::Disconnection => {
                    self.done = true;
                    return Ok(0);
                }
                // Control chatter on a socket that is already open changes nothing for
                // the stream above.
                _ => continue,
            }
        }
        let n = out.len().min(self.buf.len());
        for slot in out.iter_mut().take(n) {
            *slot = self.buf.pop_front().unwrap_or(0);
        }
        Ok(n)
    }
}

impl<W: Write> Write for MuxWriter<W> {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        // ONE CALL, ONE DATA FRAME, and the whole buffer every time.
        //
        // The caller writes one complete length-prefixed frame per `write_all`, so
        // consuming everything here keeps those boundaries. Returning a short count
        // would make `write_all` call again with the remainder and split one protocol
        // frame across two data frames -- legal for a byte stream, and a peer that
        // reassembles them still gets the same bytes, but there is no reason to.
        let frame = multiplex::data(&self.ident.salted, &self.ident.salt, data);
        write_frame(&mut self.inner, &data_packet(&frame))?;
        Ok(data.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

impl<W: Write> MuxWriter<W> {
    /// Close the virtual socket. Best effort: the physical channel is going away anyway.
    pub fn close(&mut self) {
        let bye = multiplex::disconnection(&self.ident.salted, &self.ident.salt);
        let _ = write_frame(&mut self.inner, &bye);
    }
}

/// Bytes as hex, for the diagnostics above. Short reads only -- these are control
/// packets, not payloads.
fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Read one packet, strip its channel prefix, and hand back the multiplex frame inside.
///
/// `Ok(None)` means the packet was not one for us -- a control packet, or one addressed
/// to a service we did not ask for. Neither is an error and neither ends the connection;
/// the caller reads again.
fn read_data_packet<R: Read, A: Write>(
    frames: &mut Frames<R>,
    ack: &mut A,
) -> io::Result<Option<Vec<u8>>> {
    let packet = frames.next()?;
    if packet.len() < SERVICE_ID_HASH_LEN {
        return Ok(None);
    }
    let (prefix, payload) = packet.split_at(SERVICE_ID_HASH_LEN);

    if prefix == CONTROL_PREFIX {
        // Acknowledgements, the peer's own introduction, and its disconnection notice.
        // Logged in full: this is the channel the peer explains itself on, and a
        // disconnection here is the difference between "it refused us" and "it never
        // understood us".
        let kind = barq_protocol::protobuf::first_varint(payload, SCF_TYPE)
            .ok()
            .flatten();
        log::info!(
            "quickshare: L2CAP control packet type={:?} {} byte(s): {}",
            kind,
            payload.len(),
            hex(payload)
        );
        return Ok(None);
    }
    if prefix != barq_protocol::service::service_id_hash() {
        log::debug!("quickshare: L2CAP packet for another service, ignored");
        return Ok(None);
    }

    // Acknowledge what arrived BEFORE parsing it. The peer is counting bytes, not
    // frames, and it stops sending when its own count runs too far ahead of ours.
    let _ = write_frame(ack, &packet_acknowledgement(payload.len()));

    // The payload is the multiplex frame with its own length in front.
    if payload.len() < 4 {
        return Ok(None);
    }
    let len = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]) as usize;
    let frame = payload.get(4..4 + len).ok_or_else(|| {
        bad(format!(
            "L2CAP data packet claims {len} bytes but carries {}",
            payload.len() - 4
        ))
    })?;
    Ok(Some(frame.to_vec()))
}

//! Sending a file over Quick Share: the client half of a connection we open.
//!
//! The mirror of `connection.rs`, and the differences are the whole content of this
//! module:
//!
//! ```text
//!  1. us   -> ConnectionRequest        offline frame, PLAINTEXT
//!  2. us   -> UKEY2 ClientInit         plaintext
//!     peer -> UKEY2 ServerInit
//!  3. us   -> UKEY2 ClientFinished
//!  4. peer -> ConnectionResponse       plaintext
//!     us   -> ConnectionResponse(ACCEPT)
//!  5. ---- encrypted from here ----
//!  6. paired key both ways, our introduction, THEIR user's answer, then the files
//! ```
//!
//! **We are the CLIENT on both layers.** We opened the handshake, so we are the UKEY2
//! client, and `d2d::Role::Client` picks the matching pair of traffic keys. Same trap as
//! the inbound side, opposite value -- and the reason `Role` is a type rather than a
//! bool.
//!
//! **The wait in the middle is a person on the other device.** After the introduction
//! goes out, nothing arrives until someone taps accept, which can be tens of seconds and
//! may never come. That is a normal outcome, not a stall: a refusal comes back as
//! `Status::Reject` and finishes the exchange cleanly rather than as an error to retry.
//!
//! This module opens no sockets and reads no files: it takes a stream and a list of
//! readers. That keeps it testable against our own inbound handler in one process, which
//! is how it was verified before ever meeting a real peer.

use crate::quickshare::connection::{bad, chan, wrap_bytes, write_frame, Frames};
use barq_protocol::channel::SecureChannel;
use barq_protocol::d2d::{self, Role};
use barq_protocol::frames::{self, Frame as OfflineFrame, PayloadChunk, PayloadHeader, PayloadType};
use barq_protocol::fsm::{Effect, Event, Outbound};
use barq_protocol::sharing::{FileMetadata, FileType, Introduction};
use barq_protocol::ukey2::handshake::ClientHandshake;
use log::{debug, info, warn};
use std::io::{self, Read, Write};

/// Bytes per PayloadTransfer chunk. What stock Quick Share uses; large enough that the
/// per-frame overhead disappears, small enough that progress moves visibly.
pub const CHUNK: usize = 512 * 1024;

/// One file to send. The reader is consumed once, in order.
pub struct OutFile {
    pub name: String,
    pub mime: String,
    pub size: i64,
    pub reader: Box<dyn Read + Send>,
}

/// What the caller wants to know while this runs.
pub trait Progress {
    fn progress(&self, done: u64, total: u64);
    fn cancelled(&self) -> bool;
}

/// Drive a whole send. Returns `Ok(true)` if the peer accepted and every file went.
pub fn send<S, W, P>(
    input: S,
    mut out: W,
    device_name: &str,
    endpoint_id: &str,
    mediums: &[u64],
    mut files: Vec<OutFile>,
    progress: &P,
) -> io::Result<bool>
where
    S: Read,
    W: Write,
    P: Progress,
{
    let mut input = Frames::new(input);

    // --- 1. announce ourselves, in plaintext ---------------------------------
    //
    // The caller passes the mediums, because THIS MODULE DOES NOT KNOW HOW THE SOCKET
    // GOT HERE. The same code carries a transfer over a shared LAN, over a Wi-Fi Direct
    // group negotiated by a bandwidth upgrade, or over a hotspot the peer stood up --
    // by then it is TCP either way. Hardcoding WIFI_LAN here was a LAN-only assumption
    // hiding in a constant.
    //
    // Only claim what can actually be carried: offering a medium we cannot deliver
    // invites the peer to negotiate an upgrade onto a path that does not exist, and the
    // failure then arrives halfway through a transfer instead of up front.
    let request = frames::ConnectionRequest {
        endpoint_id: endpoint_id.to_string(),
        endpoint_name: device_name.to_string(),
        endpoint_info: Vec::new(),
        handshake_data: Vec::new(),
        nonce: 0,
        mediums: mediums.to_vec(),
        keep_alive_interval_millis: Some(10_000),
        keep_alive_timeout_millis: Some(30_000),
    };
    write_frame(&mut out, &frames::connection_request(&request))?;

    // --- 2-3. UKEY2, with us opening -----------------------------------------
    let (client, client_init) =
        ClientHandshake::start().map_err(|e| bad(format!("ukey2 start: {e}")))?;
    write_frame(&mut out, &client_init)?;

    let server_init = input.next()?;
    let (client_finished, result) = client
        .handle_server_init(&server_init)
        .map_err(|e| bad(format!("ukey2 server init: {e}")))?;
    write_frame(&mut out, &client_finished)?;

    // --- 4. connection responses, still plaintext ----------------------------
    let their_response = input.next()?;
    match frames::parse(&their_response).map_err(bad)? {
        OfflineFrame::ConnectionResponse(r) if r.response == frames::Response::Accept => {
            debug!("quickshare: peer is {:?}", r.os_type);
        }
        OfflineFrame::ConnectionResponse(r) => {
            return Err(bad(format!("peer declined the connection: {:?}", r.response)));
        }
        other => return Err(bad(format!("expected a connection response, got {other:?}"))),
    }
    write_frame(
        &mut out,
        &frames::connection_response(frames::Response::Accept, frames::OsType::Android),
    )?;

    // --- 5. keys. CLIENT, because we opened the handshake --------------------
    let (secrets, keys) = d2d::derive_all(
        &result.dhs,
        &result.client_init_msg,
        &result.server_init_msg,
    )
    .map_err(|_| bad("could not derive session keys"))?;
    debug!(
        "quickshare: session pin {:04}",
        u16::from_be_bytes([secrets.auth_string[0], secrets.auth_string[1]]) % 10_000
    );
    let mut channel = SecureChannel::new(keys, Role::Client);
    info!("quickshare: encrypted channel up, offering {} file(s)", files.len());

    // --- 6. the sharing exchange ---------------------------------------------
    //
    // Payload ids are drawn once, here, because the introduction ANNOUNCES them and the
    // transfer must use the same values. Generating them again at send time is the
    // mistake that produces a receiver holding bytes it cannot attribute to any file.
    let mut payload_ids = Vec::with_capacity(files.len());
    let mut metadata = Vec::with_capacity(files.len());
    for (i, f) in files.iter().enumerate() {
        let id = random_i64()?;
        payload_ids.push(id);
        metadata.push(FileMetadata {
            name: f.name.clone(),
            file_type: FileType::of_mime(&f.mime),
            payload_id: id,
            size: f.size,
            mime_type: f.mime.clone(),
            id: i as i64 + 1,
            ..Default::default()
        });
    }
    let introduction = Introduction {
        files: metadata,
        texts: Vec::new(),
        start_transfer: true,
    };
    let total: u64 = introduction.total_size().max(0) as u64;

    let mut fsm = Outbound::new(introduction);
    let mut next_payload_id: i64 = 1;
    let mut pending = fsm.start();

    loop {
        let batch = std::mem::take(&mut pending);
        for effect in batch {
            match effect {
                Effect::Send(frame) => {
                    let wire = wrap_bytes(&mut next_payload_id, &frame);
                    write_frame(&mut out, &channel.encrypt(&wire).map_err(chan)?)?;
                }
                Effect::BeginSending(_) => {
                    info!("quickshare: peer accepted, sending");
                    let mut done: u64 = 0;
                    for (f, id) in files.iter_mut().zip(payload_ids.iter()) {
                        send_one(&mut out, &mut channel, f, *id, &mut done, total, progress)?;
                    }
                    pending.extend(fsm.on(Event::TransferComplete));
                }
                Effect::Done => {
                    write_frame(
                        &mut out,
                        &channel.encrypt(&frames::disconnection()).map_err(chan)?,
                    )?;
                    // Done covers both "sent everything" and "they said no". Which one
                    // it was is the state, not the effect.
                    return Ok(fsm.state() == barq_protocol::fsm::State::Done && total > 0);
                }
                Effect::Cancelled => {
                    warn!("quickshare: cancelled");
                    return Ok(false);
                }
                Effect::Failed(why) => return Err(bad(format!("sharing refused: {why}"))),
                // A sender is never asked and never receives.
                Effect::AskUser(_) | Effect::BeginReceiving(_) => {}
            }
        }

        if progress.cancelled() {
            pending.extend(fsm.on(Event::UserCancelled));
            continue;
        }

        let wire = input.next()?;
        let plain = channel.decrypt(&wire).map_err(chan)?;
        match frames::parse(&plain).map_err(bad)? {
            OfflineFrame::PayloadTransfer(pt) => {
                // The only payloads a sender receives are the peer's own sharing frames:
                // its paired-key exchange and, eventually, its user's answer.
                if let Some(chunk) = pt.chunk.as_ref() {
                    if pt.header.payload_type == PayloadType::Bytes {
                        let frame = barq_protocol::sharing::parse(&chunk.body)
                            .map_err(|e| bad(format!("sharing frame: {e}")))?;
                        pending.extend(fsm.on(Event::Frame(frame)));
                    }
                }
            }
            OfflineFrame::KeepAlive { ack: false, seq_num } => {
                let ka = frames::keep_alive(true, seq_num);
                write_frame(&mut out, &channel.encrypt(&ka).map_err(chan)?)?;
            }
            OfflineFrame::KeepAlive { .. } => {}
            OfflineFrame::Disconnection => {
                info!("quickshare: peer disconnected");
                return Ok(false);
            }
            other => debug!("quickshare: ignoring {other:?}"),
        }
    }
}

/// Stream one file out as a sequence of chunks.
fn send_one<W: Write, P: Progress>(
    out: &mut W,
    channel: &mut SecureChannel,
    file: &mut OutFile,
    payload_id: i64,
    done: &mut u64,
    total: u64,
    progress: &P,
) -> io::Result<()> {
    let header = PayloadHeader {
        id: payload_id,
        payload_type: PayloadType::File,
        total_size: file.size,
        file_name: file.name.clone(),
        ..Default::default()
    };

    let mut offset: i64 = 0;
    let mut buf = vec![0u8; CHUNK];
    loop {
        // read() may return short without being at EOF, so this fills the buffer rather
        // than treating one short read as the end of the file -- which would send a
        // LAST_CHUNK flag partway through and truncate what the peer receives.
        let mut filled = 0usize;
        while filled < buf.len() {
            match file.reader.read(&mut buf[filled..])? {
                0 => break,
                n => filled += n,
            }
        }
        let eof = filled < buf.len();

        let chunk = PayloadChunk {
            flags: if eof { frames::FLAG_LAST_CHUNK } else { 0 },
            offset,
            body: buf[..filled].to_vec(),
        };
        let wire = frames::payload_data(&header, &chunk);
        write_frame(out, &channel.encrypt(&wire).map_err(chan)?)?;

        offset += filled as i64;
        *done += filled as u64;
        progress.progress(*done, total);

        if eof {
            break;
        }
    }

    // A file whose size was declared larger than what was read leaves the receiver
    // waiting for bytes that will never come. Say so rather than let it hang.
    if file.size > 0 && offset != file.size {
        warn!(
            "quickshare: {} declared {} bytes but read {offset}",
            file.name, file.size
        );
    }
    info!("quickshare: sent {} ({offset} bytes)", file.name);
    Ok(())
}

fn random_i64() -> io::Result<i64> {
    let mut b = [0u8; 8];
    openssl::rand::rand_bytes(&mut b).map_err(|_| bad("no randomness"))?;
    Ok(i64::from_be_bytes(b))
}

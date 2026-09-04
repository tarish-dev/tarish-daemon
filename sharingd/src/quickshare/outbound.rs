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
//!  4. us   -> ConnectionResponse(ACCEPT)  plaintext -- WE GO FIRST
//!     peer -> ConnectionResponse
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
    //
    // WHO WE ARE, in the same encoding a receiver advertises over BLE.
    //
    // This was an empty vector, on the reading that a sender is already identified by
    // endpoint_name. It is not: a stock receiver builds its "X wants to share" prompt
    // from endpoint_info and reads endpoint_name only as a legacy fallback, so an empty
    // one leaves it with a request it cannot show anyone.
    //
    // The metadata key is 16 random bytes rather than zeros. We have no Google account
    // to root a contact certificate in, so nothing can decrypt it and nothing needs to
    // -- but an all-zero key is a value a peer can recognise as unset, and a receiver
    // that recognises it may treat us as a device with no identity at all.
    let mut metadata = [0u8; super::endpoint::METADATA_LEN];
    // SAFETY: writing exactly METADATA_LEN bytes into a buffer of that size.
    unsafe {
        libc::getrandom(
            metadata.as_mut_ptr() as *mut libc::c_void,
            metadata.len(),
            0,
        );
    }
    let endpoint_info = super::endpoint::EndpointInfo {
        // Version 1, not 0. Zero is what a field left unset looks like.
        version: 1,
        hidden: false,
        device_type: super::endpoint::DeviceType::Phone,
        metadata,
        device_name: Some(device_name.to_string()),
    }
    .encode();

    let request = frames::ConnectionRequest {
        endpoint_id: endpoint_id.to_string(),
        endpoint_name: device_name.to_string(),
        endpoint_info,
        handshake_data: Vec::new(),
        nonce: 0,
        mediums: mediums.to_vec(),
        keep_alive_interval_millis: Some(frames::KEEP_ALIVE_INTERVAL_MILLIS),
        // Ten minutes, not thirty seconds. The peer schedules its own KEEP_ALIVE
        // cadence against this, and thirty seconds is shorter than a user takes to
        // accept a transfer.
        keep_alive_timeout_millis: Some(frames::KEEP_ALIVE_TIMEOUT_MILLIS),
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
    //
    // SEND FIRST, THEN RECEIVE. Not the other way round.
    //
    // This read the peer's response before sending ours, which is a deadlock against
    // any peer that does the same -- and a stock receiver does. Both sides sit on a
    // blocking read until one times out, so the symptom is a socket that connected,
    // carried a whole UKEY2 handshake, and then went silent with no error on either
    // end. Windows happens to send first, which is why it worked there and only there.
    //
    // There is no negotiation to lose by going first: we already decided to accept when
    // we opened the connection.
    write_frame(
        &mut out,
        &frames::connection_response(frames::Response::Accept, frames::OsType::Android),
    )?;

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
    for f in files.iter() {
        let id = random_i64()?;
        payload_ids.push(id);
        metadata.push(FileMetadata {
            name: f.name.clone(),
            file_type: FileType::of_mime(&f.mime),
            payload_id: id,
            size: f.size,
            mime_type: f.mime.clone(),
            // THE SAME VALUE as payload_id, not an index.
            //
            // The two fields are separate in the schema and it is tempting to number
            // attachments 1..n, which is what this did. A Samsung receiver keys its
            // receive-side bookkeeping on `id`, so an id that matches nothing it was
            // told about discards the attachment -- with a single NULL_MESSAGE line at
            // the medium layer and no error anywhere the user can see.
            id,
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
                    for wire in wrap_bytes(&mut next_payload_id, &frame) {
                        write_frame(&mut out, &channel.encrypt(&wire).map_err(chan)?)?;
                    }
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
                    // ASK, then WAIT. We advertised safe_to_disconnect_version in the
                    // connection response, so a bare close is a broken promise: the peer
                    // still has bytes in its read pipeline, and a TCP FIN arriving before
                    // it drains marks every payload still in there as failed. The
                    // transfer then succeeds on our side and fails on theirs.
                    write_frame(
                        &mut out,
                        &channel
                            .encrypt(&frames::disconnection(true, false))
                            .map_err(chan)?,
                    )?;
                    drain_for_safe_disconnect(&mut input, &mut channel);
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
            OfflineFrame::Disconnection { request_safe, .. } => {
                info!("quickshare: peer disconnected");
                if request_safe {
                    // They asked; answering costs one frame and lets them close cleanly
                    // instead of timing us out.
                    let ack = frames::disconnection(false, true);
                    let _ = channel
                        .encrypt(&ack)
                        .map_err(chan)
                        .and_then(|w| write_frame(&mut out, &w));
                }
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

        // Data chunks NEVER carry the flag, not even the last one. See the terminator
        // below -- fusing them is a silent data-loss bug, not an optimisation.
        if filled > 0 {
            let chunk = PayloadChunk {
                flags: 0,
                offset,
                body: buf[..filled].to_vec(),
            };
            let wire = frames::payload_data(&header, &chunk);
            write_frame(out, &channel.encrypt(&wire).map_err(chan)?)?;

            offset += filled as i64;
            *done += filled as u64;
            progress.progress(*done, total);
        }

        if eof {
            break;
        }
    }

    // THE TERMINATOR IS ITS OWN FRAME: no body, the flag, and the final offset.
    //
    // This used to ride on the last data chunk -- one frame carrying both the bytes and
    // the LAST_CHUNK flag. That is accepted by our own receiver and by anything that
    // reads the flag after consuming the body, so it round-trips perfectly in tests.
    //
    // A stock Samsung receiver discards the whole payload. It decrypts the frame, the
    // safe-disconnect handshake completes, the transfer looks finished from our side,
    // and no file is written -- the UI says it could not receive the file. The only
    // trace is a NULL_MESSAGE line at the medium layer.
    //
    // BYTES payloads already use this two-frame shape, which is what made the
    // difference easy to miss: the same encoder, one path correct and one not.
    let terminator = PayloadChunk {
        flags: frames::FLAG_LAST_CHUNK,
        offset,
        body: Vec::new(),
    };
    let wire = frames::payload_data(&header, &terminator);
    write_frame(out, &channel.encrypt(&wire).map_err(chan)?)?;

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

/// Wait for the peer to acknowledge our safe-disconnect request, then let the socket go.
///
/// Best effort by design. Every outcome here is fine -- the ack arrives, the peer sends
/// its own disconnection, or the socket ends -- and none of them changes whether the
/// transfer succeeded. What is NOT fine is closing immediately, which is the thing this
/// exists to avoid.
///
/// There is no timeout because there is no timer to hang this on: the underlying socket
/// is the app's, and it closes its end when the transfer finishes. A peer that answers
/// nothing gives us an EOF, which ends the loop.
fn drain_for_safe_disconnect<S: Read>(input: &mut Frames<S>, channel: &mut SecureChannel) {
    // A handful of frames, not an unbounded read: a peer that keeps talking after being
    // told we are leaving should not keep us here.
    for _ in 0..8 {
        let Ok(wire) = input.next() else { return };
        let Ok(plain) = channel.decrypt(&wire) else {
            return;
        };
        match frames::parse(&plain) {
            Ok(OfflineFrame::Disconnection { ack_safe: true, .. }) => {
                debug!("quickshare: peer acknowledged the disconnect");
                return;
            }
            // Their own goodbye is just as good an answer: they are done reading.
            Ok(OfflineFrame::Disconnection { .. }) => return,
            Ok(_) => continue,
            Err(_) => return,
        }
    }
}

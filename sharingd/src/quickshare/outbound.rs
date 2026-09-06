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
use tarish_protocol::channel::SecureChannel;
use tarish_protocol::d2d::{self, Role};
use tarish_protocol::frames::{self, Frame as OfflineFrame, PayloadChunk, PayloadHeader, PayloadType};
use tarish_protocol::fsm::{Effect, Event, Outbound};
use tarish_protocol::payload::{Assembler, Event as PayloadEvent};
use tarish_protocol::sharing::{FileMetadata, FileType, Introduction};
use tarish_protocol::upgrade;
use tarish_protocol::ukey2::handshake::ClientHandshake;
use log::{debug, info, warn};
use std::io::{self, Read, Write};
use std::time::Duration;

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
    /// Have a person confirm the PIN before anything is sent, and say whether they got
    /// it right. Blocks: the answer comes from a human reading the other device.
    ///
    /// The value is passed IN, not out. Whoever implements this must check it without
    /// showing it -- a sender that displays its own copy lets someone confirm a transfer
    /// without ever looking at the receiver, which is the one thing this prevents.
    fn confirm_pin(&self, pin: &str) -> bool;
}

/// Drive a whole send. Returns `Ok(true)` if the peer accepted and every file went.
/// The two halves of whatever socket we are on.
///
/// **Boxed so they can be REPLACED mid-transfer.** A bandwidth upgrade moves the same
/// encrypted conversation onto a different socket: the keys and sequence numbers carry
/// over untouched -- `SecureChannel` holds no transport, which is what makes this a swap
/// rather than a renegotiation -- but every read and write after the handover has to go
/// somewhere else. Generic parameters cannot express that; a boxed pair can.
pub type Reader = Box<dyn Read + Send>;
pub type Writer = Box<dyn Write + Send>;

pub fn send<P>(
    input: Reader,
    mut out: Writer,
    device_name: &str,
    endpoint_id: &str,
    mediums: &[u64],
    mut files: Vec<OutFile>,
    progress: &P,
) -> io::Result<bool>
where
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
    // How this transfer is allowed to END is decided here, at the start. See
    // `finish_cleanly`.
    let peer_safe_disconnect;
    match frames::parse(&their_response).map_err(bad)? {
        OfflineFrame::ConnectionResponse(r) if r.response == frames::Response::Accept => {
            peer_safe_disconnect = r.safe_to_disconnect_version >= 1;
            debug!(
                "quickshare: peer is {:?}, safe-disconnect v{}",
                r.os_type, r.safe_to_disconnect_version
            );
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
    // The whole auth string, through the real derivation -- see `tarish_protocol::pin`.
    // This was the first two bytes as a big-endian u16 mod 10000, which produces a
    // four-digit number that is stable and session-specific and simply not the peer's.
    let session_pin = tarish_protocol::pin::derive(&secrets.auth_string);
    // Deliberately not logged. `logcat` is readable by anything with the log group on a
    // userdebug build, and a PIN sitting in a log is a PIN nobody had to read off the
    // other device.
    debug!("quickshare: session pin derived");
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

    let mut assembler = Assembler::new();
    let mut fsm = Outbound::new(introduction);
    let mut next_payload_id: i64 = 1;
    let mut pending = fsm.start();
    // The PIN is confirmed AFTER the introduction goes out, not before, because the
    // receiver only puts its copy on screen once it has one. Nothing that matters has
    // been sent by then -- the files wait behind the peer's acceptance either way.
    let mut pin_checked = false;

    loop {
        // DRAIN EVERY EFFECT BEFORE READING AGAIN.
        //
        // An effect can produce more effects -- notably, finishing the files pushes
        // TransferComplete, which produces Done. This took ONE batch per read, so those
        // trailing effects sat in `pending` while we blocked on the peer, and how the
        // transfer ended depended on what the peer happened to send next: something
        // innocuous and we would loop round and finish cleanly, its own Disconnection
        // first and we would report the transfer "not accepted" -- with the file already
        // delivered. Two runs of the same file, one of each.
        //
        // From the peer's side it is worse: it has every byte, sits at 100%, and waits
        // for a sender that will not close the session until the peer speaks first.
        // Whoever blinks last decides whether it says done or failed.
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
                    finish_cleanly(&mut out, &mut channel, peer_safe_disconnect)?;
                    // Done covers both "sent everything" and "they said no". Which one
                    // it was is the state, not the effect.
                    return Ok(fsm.state() == tarish_protocol::fsm::State::Done && total > 0);
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

        if !pin_checked {
            pin_checked = true;
            if !progress.confirm_pin(&session_pin) {
                warn!("quickshare: the PIN was not confirmed; sending nothing");
                let bye = frames::disconnection(peer_safe_disconnect, false);
                let _ = channel
                    .encrypt(&bye)
                    .map_err(chan)
                    .and_then(|w| write_frame(&mut out, &w));
                return Ok(false);
            }

            // ASK FOR A FASTER MEDIUM, here, before the files.
            //
            // A stock receiver never offers one unprompted -- it advertises
            // autoUpgradeBandwidth:false and waits. Asked now rather than after the peer
            // accepts, so its listener comes up while a human is still reading the
            // prompt instead of adding a round trip once they have tapped.
            //
            // WIFI_LAN only. Wi-Fi Direct means standing up a P2P group, which is
            // framework API the daemon cannot reach; claiming it would invite an offer
            // we would have to decline.
            let ask = upgrade::path_request(&[upgrade::Medium::WifiLan]);
            write_frame(&mut out, &channel.encrypt(&ask).map_err(chan)?)?;
            debug!("quickshare: asked for a Wi-Fi LAN upgrade");
        }

        if progress.cancelled() {
            pending.extend(fsm.on(Event::UserCancelled));
            continue;
        }

        // Only now, with nothing left to do locally, wait on the peer.
        if !pending.is_empty() {
            continue;
        }
        let wire = input.next()?;
        let plain = channel.decrypt(&wire).map_err(chan)?;
        match frames::parse(&plain).map_err(bad)? {
            OfflineFrame::PayloadTransfer(pt) => {
                // The only payloads a sender receives are the peer's own sharing frames:
                // its paired-key exchange and, eventually, its user's answer.
                //
                // THROUGH THE ASSEMBLER, exactly as the inbound path does. This parsed
                // each chunk body directly as a sharing frame, which works only if every
                // BYTES payload arrives as a single chunk. It does not: a stock peer
                // sends the body and the LAST_CHUNK terminator as two frames, and the
                // terminator's body is EMPTY. Parsing that as a sharing frame fails with
                // "no v1 frame" and killed the whole transfer -- a frame the peer sent
                // correctly, rejected by us, one step after the encrypted channel came
                // up. The exact mirror of the send-side bug, on the same payload shape.
                match assembler.accept(&pt).map_err(|e| bad(e.to_string()))? {
                    PayloadEvent::Bytes { data, .. } => {
                        let frame = tarish_protocol::sharing::parse(&data)
                            .map_err(|e| bad(format!("sharing frame: {e}")))?;
                        pending.extend(fsm.on(Event::Frame(frame)));
                    }
                    // A sender is offered no files, and a partial payload is not news.
                    _ => {}
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
            OfflineFrame::BandwidthUpgrade(body) => {
                // TAKE IT IF WE CAN, SAY SO IF WE CANNOT.
                //
                // Silence is not a neutral answer: the peer has a listener open and is
                // waiting for us either to appear on it or to fail it, and a transfer
                // that ends with the negotiation still open is reported failed even when
                // every byte arrived.
                match upgrade::parse(&body) {
                    Ok(upgrade::Frame::PathAvailable(path)) => {
                        match adopt(&path, endpoint_id, &mut input, &mut out, &mut channel) {
                            Ok(true) => {
                                info!(
                                    "quickshare: upgraded to {:?}; the rest goes over that",
                                    path.medium
                                );
                            }
                            Ok(false) => {}
                            Err(e) => {
                                // NOT fatal. An upgrade is an optimisation, and the old
                                // socket is still good -- treating this as a connection
                                // failure would turn a slow transfer into no transfer.
                                warn!("quickshare: upgrade failed ({e}); staying put");
                                let no = frames::bandwidth_upgrade(&upgrade::failure());
                                write_frame(&mut out, &channel.encrypt(&no).map_err(chan)?)?;
                            }
                        }
                    }
                    Ok(other) => debug!("quickshare: upgrade frame {other:?}, ignored"),
                    Err(e) => debug!("quickshare: unreadable upgrade frame ({e})"),
                }
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

    let started = std::time::Instant::now();
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
    // The RATE, not just the total. "Slow" is not a number, and the two candidates --
    // the radio and our own send window -- are only distinguishable by one.
    let secs = started.elapsed().as_secs_f64().max(0.001);
    info!(
        "quickshare: sent {} ({offset} bytes in {:.1}s, {:.0} KB/s)",
        file.name,
        secs,
        offset as f64 / 1024.0 / secs
    );
    Ok(())
}

fn random_i64() -> io::Result<i64> {
    let mut b = [0u8; 8];
    openssl::rand::rand_bytes(&mut b).map_err(|_| bad("no randomness"))?;
    Ok(i64::from_be_bytes(b))
}

/// End the session the way THIS peer requires, which is not the same for every peer.
///
/// The peer told us in its ConnectionResponse, and getting this wrong looks identical
/// either way from here: we sent every byte and the peer says the transfer failed.
///
/// **A peer that supports safe-disconnect (version >= 1)** -- stock Android, Samsung,
/// and us -- wants to be told. Closing without asking is a bare FIN, and anything still
/// in its read pipeline is marked failed.
///
/// **A peer with version 0** -- the default, and what Windows Quick Share reports --
/// wants the opposite. It treats a Disconnection that arrives before it has finished
/// writing the file as a FAILED transfer, however many bytes it already has. So we say
/// nothing and let it finish and close first.
///
/// We had both of these wrong in turn. Sending nothing and waiting for the peer to speak
/// made the ending a race, which is why the same file succeeded and failed on alternate
/// attempts. Then sending the Disconnection unconditionally made it deterministic --
/// deterministically wrong against Windows, which is version 0. The field was there in
/// its response the whole time.
///
/// Credit: Bada's `OutboundConnectionDriver.peerSafeToDisconnectVersion`, which names
/// Windows Quick Share and the "Can't complete transfer" it produces.
fn finish_cleanly<W: Write>(
    out: &mut W,
    channel: &mut SecureChannel,
    peer_safe_disconnect: bool,
) -> io::Result<()> {
    if peer_safe_disconnect {
        write_frame(
            out,
            &channel
                .encrypt(&frames::disconnection(true, false))
                .map_err(chan)?,
        )?;
    } else {
        debug!("quickshare: peer cannot be disconnected; letting it finish first");
    }
    // Either way, do not pull the socket out from under a peer that is still reading.
    // A sleep rather than a read: a read that waits for a peer which has simply stopped
    // talking never returns, and that hang cost a transfer that had already succeeded.
    std::thread::sleep(std::time::Duration::from_millis(1500));
    Ok(())
}

/// Move the conversation onto the medium the peer just offered.
///
/// Returns `Ok(true)` when the swap happened and `input`/`out` now point at the new
/// socket, `Ok(false)` when the offer was one we cannot use (and we said so), and `Err`
/// when the attempt failed part-way. **None of these is fatal to the transfer** -- the
/// caller stays on the old socket and keeps going, because an upgrade is an optimisation
/// and losing it should cost speed, not the file.
///
/// The order is not ours to choose, and each step has a reason:
///
/// ```text
///   connect the new socket
///   -> CLIENT_INTRODUCTION            NEW socket, PLAINTEXT
///   <- CLIENT_INTRODUCTION_ACK        NEW socket, plaintext, only if promised
///   -> LAST_WRITE_TO_PRIOR_CHANNEL    OLD socket, encrypted
///   <- SAFE_TO_CLOSE_PRIOR_CHANNEL    OLD socket, encrypted
///   ...everything after: the SAME secure channel, over the new socket
/// ```
///
/// **The introduction is plaintext and the frames after it are not.** The new socket has
/// no handshake of its own -- it inherits the keys and, importantly, the SEQUENCE NUMBERS
/// of the channel already running. That is why `SecureChannel` is passed through rather
/// than rebuilt: a fresh one would restart at sequence 1 and the peer would refuse every
/// frame as a replay.
///
/// The introduction carries our endpoint id because that is what the peer keys the new
/// socket back to its existing session on. Get it wrong and the connection is accepted
/// and then ignored.
fn adopt(
    path: &upgrade::UpgradePath,
    endpoint_id: &str,
    input: &mut Frames<Reader>,
    out: &mut Writer,
    channel: &mut SecureChannel,
) -> io::Result<bool> {
    // Only Wi-Fi LAN, which is the one that needs no radio work: the peer hands us an
    // address on a network we are already on. Hotspot and Wi-Fi Direct mean joining a
    // network, which is framework API a native daemon cannot reach.
    let Some(lan) = path.lan.as_ref() else {
        debug!("quickshare: offered {:?}, which we cannot join", path.medium);
        let no = frames::bandwidth_upgrade(&upgrade::failure());
        write_frame(out, &channel.encrypt(&no).map_err(chan)?)?;
        return Ok(false);
    };

    // The address arrives as raw bytes in network order: four for IPv4, sixteen for
    // IPv6. Anything else is not an address and connecting to a guess would hang.
    let ip: std::net::IpAddr = match lan.ip.len() {
        4 => std::net::Ipv4Addr::new(lan.ip[0], lan.ip[1], lan.ip[2], lan.ip[3]).into(),
        16 => {
            let mut b = [0u8; 16];
            b.copy_from_slice(&lan.ip);
            std::net::Ipv6Addr::from(b).into()
        }
        n => {
            debug!("quickshare: upgrade offered a {n}-byte address; not one we can use");
            let no = frames::bandwidth_upgrade(&upgrade::failure());
            write_frame(out, &channel.encrypt(&no).map_err(chan)?)?;
            return Ok(false);
        }
    };
    let Ok(port) = u16::try_from(lan.port) else {
        debug!("quickshare: upgrade offered port {}, out of range", lan.port);
        let no = frames::bandwidth_upgrade(&upgrade::failure());
        write_frame(out, &channel.encrypt(&no).map_err(chan)?)?;
        return Ok(false);
    };
    let addr = std::net::SocketAddr::new(ip, port);
    info!("quickshare: upgrading to Wi-Fi LAN at {addr}");
    // Bounded: an address we cannot reach must cost seconds, not the transfer. The peer
    // may be on a network we can see but not route to.
    let sock = std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(5))?;
    // The frames here are small and request/response; Nagle would add a round trip to
    // each one for no benefit.
    let _ = sock.set_nodelay(true);
    sock.set_read_timeout(Some(Duration::from_secs(10)))?;

    let mut new_out: Writer = Box::new(sock.try_clone()?);
    let mut new_in = Frames::new(Box::new(sock) as Reader);

    // 1. announce ourselves on the new socket, IN PLAINTEXT.
    write_frame(&mut new_out, &upgrade::client_introduction(endpoint_id))?;

    // 2. the ack, only when the peer said it would send one. Waiting for one that is
    //    not coming stalls until the read timeout and then abandons a working upgrade.
    if path.supports_introduction_ack {
        let reply = new_in.next()?;
        let body = frames::upgrade_body(&reply)
            .ok_or_else(|| bad("the new socket answered with something else"))?;
        match upgrade::parse(&body).map_err(bad)? {
            upgrade::Frame::ClientIntroductionAck => {}
            other => return Err(bad(format!("expected an introduction ack, got {other:?}"))),
        }
    }

    // 3. tell the old socket we are done with it, and wait to be released. Encrypted,
    //    because the old channel never stopped being the secure one.
    let last = frames::bandwidth_upgrade(&upgrade::last_write_to_prior());
    write_frame(out, &channel.encrypt(&last).map_err(chan)?)?;

    // A stock peer starts its own teardown as soon as our introduction lands, so this
    // usually arrives immediately. Bounded reads: anything else on the old socket is
    // application traffic that will be re-read on the new one.
    for _ in 0..8 {
        let wire = input.next()?;
        let plain = channel.decrypt(&wire).map_err(chan)?;
        if let Ok(OfflineFrame::BandwidthUpgrade(b)) = frames::parse(&plain) {
            if let Ok(upgrade::Frame::SafeToClosePrior { .. }) = upgrade::parse(&b) {
                break;
            }
        }
    }

    // 4. the swap. Same channel, same keys, same sequence numbers -- different fd.
    *input = new_in;
    *out = new_out;
    Ok(true)
}

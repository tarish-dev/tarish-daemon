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

    /// Join a network the peer stood up, and hand back a socket connected to it.
    ///
    /// THE DAEMON CANNOT DO THIS ITSELF. Joining a Wi-Fi Direct group is
    /// `WifiP2pManager.connect()`, framework API a native service cannot reach -- the
    /// same boundary that puts BLE scanning in the app. So the protocol half stays here
    /// and the radio half goes out to whoever implements this.
    ///
    /// Blocks: forming a group takes seconds on real hardware. `None` means the join did
    /// not happen -- no client bound, no permission, a driver that would not form a group,
    /// or the client declined -- and is not an error. The transfer continues on the
    /// transport it already has, only slower.
    fn join_wifi(&self, req: &WifiJoin) -> Option<std::net::TcpStream>;
}

/// A network a peer has stood up for us, and where to reach it once we are on it.
///
/// Hotspot and Wi-Fi Direct share this shape because the caller does the same two things
/// with both -- join by name and passphrase, then open a TCP socket. `medium` is what
/// says which framework call joins it.
pub struct WifiJoin<'a> {
    pub medium: upgrade::Medium,
    pub ssid: &'a str,
    pub passphrase: &'a str,
    /// Where to connect once joined. Empty means the peer named no address and the joiner
    /// is to use the network's own gateway, which for a Wi-Fi Direct group is the group
    /// owner -- something the framework reports and we would otherwise be guessing.
    pub gateway: &'a str,
    pub port: u16,
    /// The channel in MHz, or 0. A hint for the radio; never a reason to refuse.
    pub frequency: i32,
}

/// Drive a whole send. Returns `Ok(true)` if the peer accepted and every file went.
/// The two halves of whatever socket we are on.
///
/// **Boxed so they can be REPLACED mid-transfer.** A bandwidth upgrade moves the same
/// encrypted conversation onto a different socket: the keys and sequence numbers carry
/// over untouched -- `SecureChannel` holds no transport, which is what makes this a swap
/// rather than a renegotiation -- but every read and write after the handover has to go
/// somewhere else. Generic parameters cannot express that; a boxed pair can.
pub type Reader = Box<dyn super::connection::ReadReady + Send>;
pub type Writer = Box<dyn Write + Send>;

pub fn send<P>(
    input: Reader,
    mut out: Writer,
    device_name: &str,
    endpoint_id: &str,
    bootstrap: upgrade::Medium,
    mediums: &[u64],
    mut files: Vec<OutFile>,
    progress: &P,
) -> io::Result<bool>
where
    P: Progress,
{
    let mut input = Frames::new(input);
    // Set when a bandwidth upgrade moves us onto a real socket, so the end of the send can
    // wait for that socket to drain before the transfer is called finished. See DRAIN_MAX.
    let mut out_fd: Option<std::os::fd::RawFd> = None;

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
    let mut solicited = false;
    // How long the payload may be held back waiting for an offer, once asked for. Set when
    // the request goes out, cleared the moment anything answers it. None means nothing is
    // outstanding and the payload starts at once -- the LAN case, and every case after the
    // negotiation has resolved either way.
    let mut upgrade_deadline: Option<std::time::Instant> = None;
    // DECRYPTED frames read while waiting for an offer that were not about the upgrade.
    //
    // The peer keeps talking during that window -- keep-alives, its own sharing frames,
    // possibly a disconnection -- and those belong to the main loop, not to the wait.
    //
    // PLAINTEXT, and that is not a detail. Queuing the encrypted frame would have the main
    // loop decrypt it a second time, and SecureChannel counts sequence numbers: the second
    // decrypt fails, and it fails on a frame the peer sent correctly.
    let mut deferred: std::collections::VecDeque<Vec<u8>> = std::collections::VecDeque::new();

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
                    // WAIT FOR THE OFFER BEFORE COMMITTING TO THE SLOW TRANSPORT.
                    //
                    // Measured: the request went out 1.86s before the peer accepted, and a
                    // Wi-Fi Direct group takes 4-8s to form. Without this the payload was
                    // already streaming over Bluetooth at 148 KB/s by the time the offer
                    // could arrive, and nothing read it again until the transfer had
                    // finished -- so an offer and no offer looked identical.
                    //
                    // Seconds spent here are cheap against what they buy: the same file
                    // took 142.7s over Bluetooth and 0.9s over Wi-Fi.
                    if let Some(deadline) = upgrade_deadline.take() {
                        wait_for_upgrade(
                            deadline,
                            endpoint_id,
                            &mut input,
                            &mut out,
                            &mut channel,
                            progress,
                            &mut deferred,
                            &mut out_fd,
                        )?;
                    }
                    info!("quickshare: peer accepted, sending");
                    let mut done: u64 = 0;
                    let mut finished = true;
                    for (f, id) in files.iter_mut().zip(payload_ids.iter()) {
                        if !send_one(&mut out, &mut channel, f, *id, &mut done, total, progress)? {
                            finished = false;
                            break;
                        }
                    }
                    // UserCancelled rather than TransferComplete, so the FSM sends the
                    // peer its cancel frame instead of claiming the transfer finished.
                    // Telling it nothing leaves it waiting for bytes that stopped coming.
                    pending.extend(fsm.on(if finished {
                        Event::TransferComplete
                    } else {
                        Event::UserCancelled
                    }));
                }
                Effect::Done => {
                    finish_cleanly(&mut input, &mut out, &mut channel, peer_safe_disconnect, out_fd)?;
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

        if !solicited {
            solicited = true;
            // ASK FOR A FASTER MEDIUM AS EARLY AS POSSIBLE, AND ONLY WHEN THIS ONE IS SLOW.
            //
            // Gated on what we bootstrapped over. On a LAN transport there is nothing
            // faster to move to -- we are already at 22 MB/s -- and asking anyway invites
            // the peer to stand up a Wi-Fi Direct group and tear down a working link in
            // the middle of a transfer. Bada gates the same request the same way, on the
            // CURRENT medium rather than the original one, for exactly that reason.
            //
            // Before the PIN wait, not after. Forming a group takes 4-8s on real hardware
            // and the peer cannot start until asked, so every second spent waiting for a
            // human to read four digits is a second the group could have been forming.
            // Asked afterwards, the request went out and the payload followed almost
            // immediately, leaving the offer no window to arrive in.
            if bootstrap == upgrade::Medium::Bluetooth {
                let ask = upgrade::path_request(&[upgrade::Medium::WifiDirect]);
                write_frame(&mut out, &channel.encrypt(&ask).map_err(chan)?)?;
                upgrade_deadline = Some(std::time::Instant::now() + UPGRADE_OFFER_WAIT);
                debug!("quickshare: asked for a Wi-Fi Direct upgrade");
            } else {
                debug!("quickshare: on {bootstrap:?} already; not asking to upgrade");
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
        }

        if progress.cancelled() {
            pending.extend(fsm.on(Event::UserCancelled));
            continue;
        }

        // Only now, with nothing left to do locally, wait on the peer.
        if !pending.is_empty() {
            continue;
        }
        // Deferred first: these were read during the upgrade wait and are older than
        // anything still on the transport. Already decrypted -- see `deferred`.
        let plain = match deferred.pop_front() {
            Some(p) => p,
            None => {
                let wire = input.next()?;
                channel.decrypt(&wire).map_err(chan)?
            }
        };
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
                on_upgrade_frame(
                    &body,
                    endpoint_id,
                    &mut input,
                    &mut out,
                    &mut channel,
                    progress,
                    &mut deferred,
                    &mut out_fd,
                )?;
                // Whatever came of it, stop holding the payload for one.
                upgrade_deadline = None;
            }
            other => debug!("quickshare: ignoring {other:?}"),
        }
    }
}

/// Stream one file out as a sequence of chunks.
/// Stream one file. `Ok(false)` means the user cancelled part-way through.
fn send_one<W: Write, P: Progress>(
    out: &mut W,
    channel: &mut SecureChannel,
    file: &mut OutFile,
    payload_id: i64,
    done: &mut u64,
    total: u64,
    progress: &P,
) -> io::Result<bool> {
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
        // CANCEL IS CHECKED HERE, NOT ONLY BETWEEN FILES.
        //
        // The main loop tests this once per iteration, but this function does not return
        // until the whole file has gone -- so over Bluetooth at 148 KB/s a 21 MB file made
        // Cancel do nothing for 142 seconds. The daemon was working as written; the button
        // was dead, the app never got onTransferFinished, and the only way out was to kill
        // it. Per chunk is cheap: one atomic load per 64 KB.
        if progress.cancelled() {
            warn!(
                "quickshare: cancelled {} bytes into {}",
                offset, file.name
            );
            return Ok(false);
        }
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
    Ok(true)
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
/// How long to wait for the socket's send queue to reach the peer before we let go.
///
/// A CEILING ON AN OBSERVABLE EVENT, unlike the linger below. `write_all` returning means
/// the bytes are in the KERNEL's send buffer, not that the peer has them, and `TIOCOUTQ`
/// reports exactly how many are still outstanding. Reaching zero is a real acknowledgement
/// from the far end, so this ends the moment the transfer is genuinely on the peer.
///
/// Generous, because the alternative is what it was built to stop: 20 MB written in 12.9 s
/// at 1589 KB/s leaves megabytes in flight, and anything shorter than they take to drain
/// truncates the transfer.
const DRAIN_MAX: Duration = Duration::from_secs(30);

/// Bytes written to this socket that the peer has not acknowledged yet.
///
/// `None` if the socket cannot answer, which is treated as "nothing outstanding" rather
/// than as a reason to wait -- a descriptor that will not report cannot be waited on.
fn unacked(fd: std::os::fd::RawFd) -> Option<u32> {
    let mut n: libc::c_int = 0;
    // SAFETY: TIOCOUTQ writes a single c_int through the pointer, which is what is passed.
    let rc = unsafe { libc::ioctl(fd, libc::TIOCOUTQ, &mut n) };
    if rc == 0 && n >= 0 {
        Some(n as u32)
    } else {
        None
    }
}

/// How long a completed send leaves the socket open before closing it.
///
/// A GRACE PERIOD FOR SOMETHING UNOBSERVABLE, and deliberately a fixed one. What must not
/// happen is closing under a peer that is still reading, and nothing on the wire says when a
/// peer has finished reading -- a close only says it has finished WRITING. See the note in
/// `finish_cleanly` for the evening this was learned the hard way.
const LINGER_MAX: std::time::Duration = std::time::Duration::from_millis(1500);

fn finish_cleanly<W: Write>(
    input: &mut Frames<Reader>,
    out: &mut W,
    channel: &mut SecureChannel,
    peer_safe_disconnect: bool,
    out_fd: Option<std::os::fd::RawFd>,
) -> io::Result<()> {
    // WAIT FOR THE BYTES TO REACH THE PEER BEFORE ANNOUNCING THE TRANSFER IS OVER.
    //
    // `write_all` returning says the payload is in the kernel's send buffer. It says
    // nothing about the peer having it. Declaring completion there ends the transfer, and
    // ending the transfer releases the AWDL hold, and releasing that hold brings AWDL back
    // and takes the P2P slot out from under the Wi-Fi Direct group the data is still
    // draining through. The remaining megabytes go nowhere.
    //
    // Measured 2026-09-26 against a stock Quick Share receiver:
    //
    //   22:46:18  sent 20971520 bytes in 12.9s, 1589 KB/s   <- our write_all returned
    //   22:46:19  transfer complete; released the AWDL hold <- radio taken back
    //   22:47:25  NearbySharing: "Time's up! Canceling ...
    //             since we haven't seen a transfer update in a while."
    //
    // The peer sat sending keep-alives for a minute waiting for bytes that could no longer
    // reach it, while our side reported success. TIOCOUTQ is the honest signal and this
    // ends the moment it reaches zero.
    if let Some(fd) = out_fd {
        let by = std::time::Instant::now() + DRAIN_MAX;
        loop {
            match unacked(fd) {
                Some(0) | None => break,
                Some(left) => {
                    if std::time::Instant::now() >= by {
                        warn!(
                            "quickshare: {left} B still unacknowledged after {DRAIN_MAX:?}; \
                             closing anyway"
                        );
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(20));
                }
            }
        }
    }
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
    // A TIMED LINGER, AND IT HAS TO BE. Do not "improve" this into waiting for an event.
    //
    // The requirement is not to pull the socket out from under a peer that is still READING.
    // There is no event for that. A peer closing its end tells us it has stopped SENDING,
    // which is a different thing entirely -- TCP half-close exists precisely so a peer can
    // say "nothing more from me" while it is still draining what we sent.
    //
    // This was briefly changed to return as soon as the read failed, on the reasoning that
    // the close was the event being waited for. It is not, and treating it as one closes the
    // connection under a receiver that is still writing the file out: our side reports the
    // transfer complete and the peer's never finishes. Reverted the same evening it shipped.
    //
    // So the fixed wait stands. It is not a guess at how long something takes -- it is a
    // grace period for something that cannot be observed, which is the one case where a
    // fixed wait is the right primitive rather than a lazy one.
    std::thread::sleep(LINGER_MAX);
    let _ = input;
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
/// Get onto the medium the peer offered.
///
/// Two ways, and the difference is whether a radio has to be joined. Wi-Fi LAN hands us
/// an address on a network we are already on, so the daemon dials it. Wi-Fi Direct and
/// hotspot mean joining a network, which is framework API this process cannot reach, so
/// the client does it and hands the socket back.
///
/// `Ok(None)` is a decline, not a failure: an offer we cannot take, or a client that
/// would not take it. The caller answers UPGRADE_FAILURE once, in one place -- this used
/// to be four copies of that write, one per way of giving up.
/// How long the payload waits for an offer after asking for a faster medium.
///
/// Twelve seconds. Group formation was measured at 4-8s on a Pixel and a slow first-time
/// driver init pushes past that, so a shorter wait would abandon upgrades that were about
/// to work. It is only ever paid when we asked -- which is only from Bluetooth -- and only
/// until the peer answers, so a peer that declines promptly costs nothing.
const UPGRADE_OFFER_WAIT: Duration = Duration::from_secs(12);

/// How long to wait for the peer to release the OLD channel after we say we are done.
///
/// Short: a stock peer starts its teardown as soon as our introduction lands on the new
/// socket, so this normally returns at once. It exists so a peer that never answers costs
/// five seconds rather than the whole transfer.
const SAFE_TO_CLOSE_WAIT: Duration = Duration::from_secs(5);

/// How long the peer has to acknowledge our introduction on the NEW socket.
///
/// Only waited for when the peer said it sends one. The socket is already connected by
/// then, so this is a round trip on a fresh Wi-Fi link and ten seconds is generous.
const INTRODUCTION_ACK_WAIT: Duration = Duration::from_secs(10);

/// What we report as our Wi-Fi association frequency when releasing the old channel.
///
/// The schema's own "not set". We are handing over BECAUSE there was no usable network, so
/// there is no frequency to report, and inventing one would be worse than saying nothing.
const STA_FREQUENCY_UNKNOWN: i32 = -1;

/// How long a single write may make no progress before the transfer is called failed.
///
/// This exists so a stalled transfer FAILS instead of hanging. A hung transfer is worse
/// than a failed one: it holds the radio, never reports an outcome, and leaves the peer
/// mid-session so nothing else can connect either.
const WRITE_STALL_TIMEOUT: Duration = Duration::from_secs(20);

/// Hold the payload until the peer answers the upgrade request, or the deadline passes.
///
/// Anything the peer says that is NOT about the upgrade is queued for the main loop rather
/// than handled here: keep-alives, its own sharing frames, a disconnection. Handling them
/// in two places is how a transfer starts behaving differently depending on when a frame
/// happened to arrive.
///
/// Never fails for want of an offer. A peer that will not upgrade is the ordinary case and
/// the transfer continues on the transport it has.
fn wait_for_upgrade<P>(
    deadline: std::time::Instant,
    endpoint_id: &str,
    input: &mut Frames<Reader>,
    out: &mut Writer,
    channel: &mut SecureChannel,
    progress: &P,
    deferred: &mut std::collections::VecDeque<Vec<u8>>,
    out_fd: &mut Option<std::os::fd::RawFd>,
) -> io::Result<()>
where
    P: Progress,
{
    loop {
        let Some(left) = deadline.checked_duration_since(std::time::Instant::now()) else {
            debug!("quickshare: no upgrade offer arrived; sending on this transport");
            return Ok(());
        };
        if progress.cancelled() {
            return Ok(());
        }
        // Woken at least every half second so a cancel during the wait is noticed rather
        // than sitting out the whole deadline.
        let Some(wire) = input.next_within(left.min(Duration::from_millis(500)))? else {
            continue;
        };
        let plain = channel.decrypt(&wire).map_err(chan)?;
        match frames::parse(&plain).map_err(bad)? {
            OfflineFrame::BandwidthUpgrade(body) => {
                on_upgrade_frame(&body, endpoint_id, input, out, channel, progress, deferred, out_fd)?;
                return Ok(());
            }
            // Not ours. Hand the PLAINTEXT to the main loop -- decrypting it again there
            // would advance the sequence numbers twice for one frame.
            _ => deferred.push_back(plain),
        }
    }
}

/// Act on a BANDWIDTH_UPGRADE_NEGOTIATION frame from the peer.
///
/// TAKE IT IF WE CAN, SAY SO IF WE CANNOT. Silence is not a neutral answer: the peer has a
/// listener open and is waiting for us either to appear on it or to fail it, and a transfer
/// that ends with the negotiation still open is reported failed even when every byte
/// arrived.
///
/// Its own function because it is needed in two places -- the main read loop, and the wait
/// before the payload starts. Duplicating it would mean an offer that arrives in one window
/// being handled differently from one that arrives in the other.
fn on_upgrade_frame<P>(
    body: &[u8],
    endpoint_id: &str,
    input: &mut Frames<Reader>,
    out: &mut Writer,
    channel: &mut SecureChannel,
    progress: &P,
    deferred: &mut std::collections::VecDeque<Vec<u8>>,
    out_fd: &mut Option<std::os::fd::RawFd>,
) -> io::Result<()>
where
    P: Progress,
{
    match upgrade::parse(body) {
        Ok(upgrade::Frame::PathAvailable(path)) => {
            match adopt(&path, endpoint_id, input, out, channel, progress, deferred, out_fd) {
                Ok(true) => info!(
                    "quickshare: upgraded to {:?}; the rest goes over that",
                    path.medium
                ),
                Ok(false) => {}
                Err(e) => {
                    // NOT fatal. An upgrade is an optimisation, and the old socket is
                    // still good -- treating this as a connection failure would turn a
                    // slow transfer into no transfer.
                    warn!("quickshare: upgrade failed ({e}); staying put");
                    let no = upgrade::failure();
                    write_frame(out, &channel.encrypt(&no).map_err(chan)?)?;
                }
            }
        }
        Ok(other) => debug!("quickshare: upgrade frame {other:?}, ignored"),
        Err(e) => debug!("quickshare: unreadable upgrade frame ({e})"),
    }
    Ok(())
}

fn acquire<P>(path: &upgrade::UpgradePath, progress: &P) -> io::Result<Option<std::net::TcpStream>>
where
    P: Progress,
{
    if let Some(w) = path.wifi.as_ref() {
        let Ok(port) = u16::try_from(w.port) else {
            debug!("quickshare: upgrade offered port {}, out of range", w.port);
            return Ok(None);
        };
        // "0.0.0.0" is the schema's default and means "whatever the network's gateway
        // turns out to be" -- it is not an address to connect to. Normalised to empty so
        // the client has one thing to test rather than two.
        let gateway = if w.gateway == "0.0.0.0" { "" } else { w.gateway.as_str() };
        info!(
            "quickshare: peer offered {:?} as {:?}; asking the app to join",
            path.medium, w.ssid
        );
        let req = WifiJoin {
            medium: path.medium,
            ssid: &w.ssid,
            passphrase: &w.password,
            gateway,
            port,
            frequency: w.frequency,
        };
        return Ok(progress.join_wifi(&req));
    }

    let Some(lan) = path.lan.as_ref() else {
        debug!("quickshare: offered {:?}, which carried no way to reach it", path.medium);
        return Ok(None);
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
            return Ok(None);
        }
    };
    let Ok(port) = u16::try_from(lan.port) else {
        debug!("quickshare: upgrade offered port {}, out of range", lan.port);
        return Ok(None);
    };
    // THE PEER CHOOSES THIS ADDRESS, SO IT HAS TO BE CHECKED.
    //
    // Until now anything that parsed as 4 or 16 bytes was connected to. A hostile peer
    // could therefore aim this daemon at a public host, at another machine on the LAN, or
    // at 127.0.0.1 — turning a share into a request generator pointed wherever it liked.
    // It costs nothing to refuse: a bandwidth upgrade only ever addresses a peer that is
    // already link-adjacent.
    if !is_plausible_peer(ip) {
        warn!("quickshare: upgrade offered {ip}, which is not a local address — refusing");
        return Ok(None);
    }

    let addr = std::net::SocketAddr::new(ip, port);
    info!("quickshare: upgrading to Wi-Fi LAN at {addr}");
    // Bounded: an address we cannot reach must cost seconds, not the transfer. The peer
    // may be on a network we can see but not route to.
    Ok(Some(std::net::TcpStream::connect_timeout(
        &addr,
        Duration::from_secs(5),
    )?))
}

/// Could this plausibly be a peer on a network we are attached to?
///
/// A bandwidth upgrade points at a device that is already link-adjacent: a Wi-Fi Direct
/// group owner on 192.168.49.0/24, or a peer on the same private LAN. Nothing else is ever
/// a legitimate answer, so everything else is refused.
///
/// REFUSED, and each for its own reason:
///   loopback      127.0.0.0/8, ::1 — would aim the daemon at services on THIS device,
///                 which is the most valuable target a remote peer could pick
///   unspecified   0.0.0.0, :: — connect() treats these as localhost
///   multicast     not a unicast peer
///   broadcast     255.255.255.255
///   link-local    169.254.0.0/16 and fe80::/10 — a v6 link-local needs a scope id to be
///                 meaningful and this path has none, so it can only misroute. AirDrop's
///                 own link-local traffic does NOT come through here; it is bound to
///                 tlink0 on a different path entirely.
///   anything else globally routable — a public address is never a peer
///
/// This is deliberately a SCOPE test rather than a subnet test. Checking membership of a
/// live interface's prefix would be a little stronger, but it needs SIOCGIFNETMASK, and
/// this domain's ioctl allowlist was just narrowed by measurement — adding a syscall that
/// turns out to be denied would trade a real hole for a silent failure. The protection is
/// near-identical in practice: a prefix test also permits any other host on the same LAN,
/// which is the one case this does not exclude either. Tighten it to a prefix test only
/// with a measured run proving the ioctl is allowed.
fn is_plausible_peer(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => {
            if v4.is_loopback()
                || v4.is_unspecified()
                || v4.is_multicast()
                || v4.is_broadcast()
                || v4.is_link_local()
                || v4.is_documentation()
            {
                return false;
            }
            // RFC1918 only: 10/8, 172.16/12, 192.168/16. Covers Wi-Fi Direct's
            // 192.168.49.0/24 and every ordinary home or office LAN.
            v4.is_private()
        }
        std::net::IpAddr::V6(v6) => {
            if v6.is_loopback() || v6.is_unspecified() || v6.is_multicast() {
                return false;
            }
            let o = v6.octets();
            // fe80::/10 link-local — unusable without a scope id, which we do not carry.
            if o[0] == 0xfe && (o[1] & 0xc0) == 0x80 {
                return false;
            }
            // An IPv4-mapped address would otherwise smuggle a public v4 target through
            // the v6 branch, so re-check it as v4.
            if let Some(m) = v6.to_ipv4_mapped() {
                return is_plausible_peer(std::net::IpAddr::V4(m));
            }
            // fc00::/7 unique-local. Anything else is globally routable, so not a peer.
            (o[0] & 0xfe) == 0xfc
        }
    }
}

fn adopt<P>(
    path: &upgrade::UpgradePath,
    endpoint_id: &str,
    input: &mut Frames<Reader>,
    out: &mut Writer,
    channel: &mut SecureChannel,
    progress: &P,
    deferred: &mut std::collections::VecDeque<Vec<u8>>,
    out_fd: &mut Option<std::os::fd::RawFd>,
) -> io::Result<bool>
where
    P: Progress,
{
    let Some(sock) = acquire(path, progress)? else {
        let no = upgrade::failure();
        write_frame(out, &channel.encrypt(&no).map_err(chan)?)?;
        return Ok(false);
    };
    // The frames here are small and request/response; Nagle would add a round trip to
    // each one for no benefit.
    let _ = sock.set_nodelay(true);
    // A WRITE TIMEOUT, AND IT IS NOT OPTIONAL.
    //
    // Without it a peer that accepts the TCP connection and then never reads parks the
    // transfer thread in sk_stream_wait_memory FOREVER: measured with 6.3 MB in Send-Q and
    // the thread still there minutes later. Nothing times out, so the transfer never
    // finishes, so onTransferFinished never fires, so the app never releases the Wi-Fi
    // Direct group -- and every later attempt fails with "L2CAP data connection refused:
    // 24" because the peer is still tangled in the session we never ended. One stall
    // poisoned the device until it was rebooted.
    //
    // Twenty seconds of no progress at all on a freshly formed Wi-Fi link is broken, not
    // slow: the same link moves 22 MB/s when it works.
    let _ = sock.set_write_timeout(Some(WRITE_STALL_TIMEOUT));
    // DELIBERATELY NO SO_RCVTIMEO. This set a 10s read timeout for the introduction ack
    // below, and the timeout then STAYED ON THE SOCKET for the whole transfer -- so the
    // main loop's wait for the peer's acceptance, which is a human tapping a button, would
    // fail the transfer after ten seconds. next_within bounds the one read that needs
    // bounding and leaves the socket blocking, which is what every read after the handover
    // wants.

    // Kept so the end of the send can wait for this socket to drain -- see finish_cleanly.
    // Valid for as long as the boxed halves below live, which is the rest of the transfer.
    {
        use std::os::fd::AsRawFd;
        *out_fd = Some(sock.as_raw_fd());
    }
    let mut new_out: Writer = Box::new(sock.try_clone()?);
    let mut new_in = Frames::new(Box::new(sock) as Reader);

    // 1. announce ourselves on the new socket, IN PLAINTEXT.
    write_frame(&mut new_out, &upgrade::client_introduction(endpoint_id))?;

    // 2. the ack, only when the peer said it would send one. Waiting for one that is
    //    not coming stalls until the read timeout and then abandons a working upgrade.
    if path.supports_introduction_ack {
        let Some(reply) = new_in.next_within(INTRODUCTION_ACK_WAIT)? else {
            return Err(bad("the new socket never acknowledged our introduction"));
        };
        let body = frames::upgrade_body(&reply)
            .ok_or_else(|| bad("the new socket answered with something else"))?;
        match upgrade::parse(&body).map_err(bad)? {
            upgrade::Frame::ClientIntroductionAck => {}
            other => return Err(bad(format!("expected an introduction ack, got {other:?}"))),
        }
    }

    // 3. tell the old socket we are done with it, and wait to be released. Encrypted,
    //    because the old channel never stopped being the secure one.
    let last = upgrade::last_write_to_prior();
    write_frame(out, &channel.encrypt(&last).map_err(chan)?)?;

    // FOUR FRAMES, NOT TWO. This is the whole handover and skipping half of it looks
    // exactly like the peer ignoring us:
    //
    //   1. we send LAST_WRITE_TO_PRIOR      (done above)
    //   2. the peer sends ITS LAST_WRITE_TO_PRIOR
    //   3. WE send SAFE_TO_CLOSE_PRIOR      <- this was missing entirely
    //   4. the peer sends ITS SAFE_TO_CLOSE_PRIOR
    //
    // Without step 3 the peer never stops reading the old channel and never starts on the
    // new one. Measured: ESTAB with Send-Q at 7,200,944 bytes to 192.168.49.1, the transfer
    // thread parked in sk_stream_wait_memory, and "no safe-to-close from the peer" -- which
    // reads as the peer being broken when it is waiting for a frame we owed it.
    //
    // Step 2 is not waited for strictly: a stock GMS host sends its own LAST_WRITE as soon
    // as our introduction lands and does not wait for ours, so the two can cross. Both are
    // accepted in either order, and step 3 goes out as soon as we have seen either.
    //
    // BOUNDED IN TIME, and every other frame KEPT.
    //
    // This was bounded only in count -- eight reads -- on a socket with no read timeout,
    // so a peer that said nothing here blocked the transfer thread forever: the group was
    // joined, the socket was connected, and nothing moved again. Which is what happened.
    //
    // And the frames it read were decrypted and thrown away, under a comment claiming they
    // would "be re-read on the new one". They would not: a frame consumed here is gone, and
    // decrypting it has already advanced the sequence numbers. The peer's acceptance can
    // arrive in this window -- it is the same channel -- and discarding it leaves the FSM
    // waiting for an answer that was received and dropped.
    let deadline = std::time::Instant::now() + SAFE_TO_CLOSE_WAIT;
    let mut we_released = false;
    let mut peer_released = false;
    while !peer_released {
        let Some(left) = deadline.checked_duration_since(std::time::Instant::now()) else {
            break;
        };
        let Some(wire) = input.next_within(left)? else {
            break;
        };
        let plain = channel.decrypt(&wire).map_err(chan)?;
        let mut handled = false;
        if let Ok(OfflineFrame::BandwidthUpgrade(b)) = frames::parse(&plain) {
            match upgrade::parse(&b) {
                Ok(upgrade::Frame::LastWriteToPrior) => {
                    handled = true;
                    if !we_released {
                        // OUR safe-to-close. The peer will not touch the new socket until
                        // it has this.
                        let ok = upgrade::safe_to_close_prior(STA_FREQUENCY_UNKNOWN);
                        write_frame(out, &channel.encrypt(&ok).map_err(chan)?)?;
                        we_released = true;
                        debug!("quickshare: released the old channel");
                    }
                }
                Ok(upgrade::Frame::SafeToClosePrior { .. }) => {
                    handled = true;
                    peer_released = true;
                }
                _ => {}
            }
        }
        // Anything else belongs to the conversation, not to the handover.
        if !handled {
            deferred.push_back(plain);
        }
    }
    if !we_released {
        // The peer's LAST_WRITE never arrived, but it is owed our release either way --
        // a stock host sends its own without waiting for ours, so a crossed or lost frame
        // must not leave us silently withholding the one thing it is waiting for.
        let ok = upgrade::safe_to_close_prior(STA_FREQUENCY_UNKNOWN);
        write_frame(out, &channel.encrypt(&ok).map_err(chan)?)?;
        debug!("quickshare: released the old channel unprompted");
    }
    if !peer_released {
        // Swap anyway. The peer has our CLIENT_INTRODUCTION and our release, so from its
        // side the new channel is the live one -- staying on the old socket after
        // introducing ourselves on the new one is the worse of the two guesses.
        warn!("quickshare: no safe-to-close from the peer; switching over regardless");
    }

    // 4. the swap. Same channel, same keys, same sequence numbers -- different fd.
    *input = new_in;
    *out = new_out;
    Ok(true)
}

#[cfg(test)]
mod upgrade_address_tests {
    use super::is_plausible_peer;
    use std::net::IpAddr;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn accepts_a_wifi_direct_group_owner_and_ordinary_lans() {
        // The single most common real answer: Android's Wi-Fi Direct group owner.
        assert!(is_plausible_peer(ip("192.168.49.1")));
        assert!(is_plausible_peer(ip("192.168.1.42")));
        assert!(is_plausible_peer(ip("10.0.0.7")));
        assert!(is_plausible_peer(ip("172.16.5.5")));
        assert!(is_plausible_peer(ip("fd00::1"))); // unique-local v6
    }

    #[test]
    fn refuses_pointing_the_daemon_at_this_device() {
        assert!(!is_plausible_peer(ip("127.0.0.1")));
        assert!(!is_plausible_peer(ip("127.0.0.53")));
        assert!(!is_plausible_peer(ip("::1")));
        assert!(!is_plausible_peer(ip("0.0.0.0")));
        assert!(!is_plausible_peer(ip("::")));
    }

    #[test]
    fn refuses_the_public_internet() {
        assert!(!is_plausible_peer(ip("8.8.8.8")));
        assert!(!is_plausible_peer(ip("1.1.1.1")));
        assert!(!is_plausible_peer(ip("2001:4860:4860::8888")));
        // 172.32/16 is OUTSIDE the 172.16/12 private block — an easy off-by-one.
        assert!(!is_plausible_peer(ip("172.32.0.1")));
        // Carrier-grade NAT is not our LAN either.
        assert!(!is_plausible_peer(ip("100.64.0.1")));
    }

    #[test]
    fn refuses_multicast_broadcast_and_link_local() {
        assert!(!is_plausible_peer(ip("224.0.0.251")));
        assert!(!is_plausible_peer(ip("255.255.255.255")));
        assert!(!is_plausible_peer(ip("169.254.1.1")));
        assert!(!is_plausible_peer(ip("ff02::fb")));
        assert!(!is_plausible_peer(ip("fe80::1")));
    }

    /// The v6 branch must not become a way to smuggle a public v4 target.
    #[test]
    fn refuses_ipv4_mapped_public_addresses() {
        assert!(!is_plausible_peer(ip("::ffff:8.8.8.8")));
        assert!(!is_plausible_peer(ip("::ffff:127.0.0.1")));
        // ...but a mapped private address is still a plausible peer.
        assert!(is_plausible_peer(ip("::ffff:192.168.49.1")));
    }
}

//! One inbound Quick Share connection, from TCP accept to the last byte on disk.
//!
//! This is the I/O loop around `libtarish_protocol`. Everything it decides is in the
//! crate; everything it *does* -- read, write, ask, create a file -- is here, which is
//! why the protocol is testable without a socket and this is testable without a phone.
//!
//! The sequence, which is not negotiable and is easy to get subtly wrong:
//!
//! ```text
//!  1. peer -> ConnectionRequest        offline frame, PLAINTEXT
//!  2. peer -> UKEY2 ClientInit         plaintext
//!     us   -> UKEY2 ServerInit
//!  3. peer -> UKEY2 ClientFinished
//!  4. us   -> ConnectionResponse(ACCEPT)   offline frame, still PLAINTEXT
//!  5. peer -> ConnectionResponse            plaintext
//!  6. ---- everything after this point is encrypted ----
//!  7. paired key both ways, introduction, the user's answer, then the files
//! ```
//!
//! **We are the SERVER on both layers, and those are two separate facts.** We answered
//! the UKEY2 handshake, so we are the UKEY2 server; and `d2d::Role::Server` selects
//! which pair of the four traffic keys encrypts and which verifies. Getting the second
//! one backwards produces a connection that completes every step above and then cannot
//! decrypt a single frame -- the protocol crate has a test for exactly that failure
//! because it is the one most likely to be introduced here.
//!
//! **Steps 4 and 10 are different frames with the same name.** The `ConnectionResponse`
//! at step 4 is the Nearby *Connections* one and is plaintext; the acceptance the user
//! gives later is the Nearby *Sharing* one, encrypted, and lives in `sharing::response`.
//! They are different protos.

use crate::{Callbacks, Transfers};
use tarish_protocol::channel::SecureChannel;
use tarish_protocol::d2d::{self, Role};
use tarish_protocol::frames::{self, Frame as OfflineFrame, PayloadChunk, PayloadHeader, PayloadType};
use tarish_protocol::framing;
use tarish_protocol::fsm::{Effect, Event, Inbound};
use tarish_protocol::payload::{Assembler, Event as PayloadEvent};
use tarish_protocol::sharing::{self, FileMetadata};
use tarish_protocol::ukey2::handshake::ServerHandshake;
use log::{debug, info, warn};
use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::time::Duration;

/// What the daemon must provide. Kept to four things so this module can be exercised
/// with an in-memory implementation.
pub trait Host {
    /// Ask the person. Blocks until they answer or it times out. `false` means refuse.
    fn ask(&self, from: &str, files: &[FileMetadata]) -> bool;
    /// Open somewhere to put a file, given the name the PEER chose.
    ///
    /// The implementation must treat that name as hostile -- this is the only place that
    /// knows what a path means here, which is why the protocol crate deliberately does
    /// not try to sanitise it.
    fn create(&self, name: &str) -> io::Result<Box<dyn Write + Send>>;
    /// Progress, in bytes.
    fn progress(&self, done: u64, total: u64);
    /// Has the user cancelled locally?
    fn cancelled(&self) -> bool;
}

/// Tell every registered client something happened.
///
/// A client that died holding a callback must not break receiving for the next one, so
/// failures are logged and skipped rather than propagated.
fn notify<F>(callbacks: &Callbacks, f: F)
where
    F: Fn(&binder::Strong<dyn crate::ITarishCallback>) -> binder::Result<()>,
{
    let Ok(cbs) = callbacks.lock() else {
        warn!("quickshare: callback list poisoned");
        return;
    };
    for cb in cbs.iter() {
        if let Err(e) = f(cb) {
            debug!("quickshare: callback failed: {e:?}");
        }
    }
}

/// A transport that can say whether input is waiting, without consuming it.
///
/// Needed for exactly one thing: waiting a bounded time for a bandwidth-upgrade offer
/// before committing a payload to the slow transport we bootstrapped on. A plain `Read`
/// cannot express that -- its only option is to block indefinitely -- and blocking on an
/// offer that is not coming would hang every transfer to a peer that declines to upgrade.
///
/// `Ok(false)` means nothing arrived in time. A transport that cannot answer should return
/// `Ok(false)` rather than blocking: the caller uses this to decide whether waiting is
/// possible at all, and a transport that cannot be waited on should simply not be.
pub trait ReadReady: std::io::Read {
    fn ready_within(&self, d: Duration) -> io::Result<bool>;
}

/// POLLIN with a timeout. Shared by every descriptor-backed transport.
fn fd_ready(fd: std::os::fd::RawFd, d: Duration) -> io::Result<bool> {
    let mut p = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    let ms = i32::try_from(d.as_millis()).unwrap_or(i32::MAX);
    // SAFETY: one initialised pollfd, and the count matches.
    let r = unsafe { libc::poll(&mut p, 1, ms) };
    if r < 0 {
        let e = io::Error::last_os_error();
        // A signal is not an answer. Report "nothing waiting" and let the caller's own
        // deadline decide whether to ask again, rather than failing a working transfer.
        if e.kind() == io::ErrorKind::Interrupted {
            return Ok(false);
        }
        return Err(e);
    }
    Ok(r > 0)
}

/// So a `Box<dyn ReadReady + Send>` is itself a `ReadReady`.
///
/// The transport is boxed because a bandwidth upgrade REPLACES it mid-transfer, and without
/// this the trait stops at the box: `Frames<Box<dyn ReadReady>>` would have no
/// `next_within`. `Read` already gets the same treatment from std, which is why its absence
/// here is easy to miss.
impl<T: ReadReady + ?Sized> ReadReady for Box<T> {
    fn ready_within(&self, d: Duration) -> io::Result<bool> {
        (**self).ready_within(d)
    }
}

impl ReadReady for std::fs::File {
    fn ready_within(&self, d: Duration) -> io::Result<bool> {
        use std::os::fd::AsRawFd;
        fd_ready(self.as_raw_fd(), d)
    }
}

impl ReadReady for std::net::TcpStream {
    fn ready_within(&self, d: Duration) -> io::Result<bool> {
        use std::os::fd::AsRawFd;
        fd_ready(self.as_raw_fd(), d)
    }
}

/// Reads length-prefixed frames off a stream.
pub(crate) struct Frames<S> {
    stream: S,
    decoder: framing::Decoder,
    buf: [u8; 16 * 1024],
}

impl<S: Read> Frames<S> {
    pub(crate) fn new(stream: S) -> Self {
        Self {
            stream,
            decoder: framing::Decoder::new(),
            buf: [0u8; 16 * 1024],
        }
    }

    /// The next whole frame, reading more from the stream until there is one.
    pub(crate) fn next(&mut self) -> io::Result<Vec<u8>> {
        loop {
            if let Some(f) = self
                .decoder
                .next_frame()
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?
            {
                return Ok(f);
            }
            let n = self.stream.read(&mut self.buf)?;
            if n == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "peer closed the connection",
                ));
            }
            self.decoder.push(&self.buf[..n]);
        }
    }
}

impl<S: ReadReady> Frames<S> {
    /// The next whole frame, if one is decodable already or arrives within `d`.
    ///
    /// `None` on timeout, and that is not an error -- the caller asked whether something
    /// was coming and the answer was no.
    ///
    /// THE DECODER IS CHECKED FIRST, and that is not an optimisation. It holds bytes read
    /// off the transport by a previous call, so a whole frame can be sitting in it while
    /// the descriptor has nothing left to offer. Polling the transport alone would report
    /// "nothing waiting" and skip a frame already in hand.
    pub(crate) fn next_within(&mut self, d: Duration) -> io::Result<Option<Vec<u8>>> {
        let deadline = std::time::Instant::now() + d;
        loop {
            if let Some(f) = self
                .decoder
                .next_frame()
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?
            {
                return Ok(Some(f));
            }
            let left = match deadline.checked_duration_since(std::time::Instant::now()) {
                Some(l) => l,
                None => return Ok(None),
            };
            if !self.stream.ready_within(left)? {
                return Ok(None);
            }
            let n = self.stream.read(&mut self.buf)?;
            if n == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "peer closed the connection",
                ));
            }
            self.decoder.push(&self.buf[..n]);
        }
    }
}

/// Serve one connection. Returns the names written, or an error.
pub fn serve<S, H>(
    stream: S,
    mut out: impl Write,
    host: &H,
    transfers: &Transfers,
    callbacks: &Callbacks,
) -> io::Result<Vec<String>>
where
    S: Read,
    H: Host,
{
    let mut input = Frames::new(stream);

    // --- 1. the connection request, in plaintext -----------------------------
    let first = input.next()?;
    let peer_name = match frames::parse(&first).map_err(bad)? {
        OfflineFrame::ConnectionRequest(req) => {
            debug!(
                "quickshare: request from {:?} ({:?}), mediums {:?}",
                req.endpoint_name, req.endpoint_id, req.mediums
            );
            if req.endpoint_name.is_empty() {
                "A nearby device".to_string()
            } else {
                req.endpoint_name
            }
        }
        other => {
            return Err(bad(format!("expected a connection request, got {other:?}")));
        }
    };

    // --- 2-3. UKEY2, with us answering ---------------------------------------
    let client_init = input.next()?;
    let (server, server_init) = ServerHandshake::handle_client_init(&client_init)
        .map_err(|e| bad(format!("ukey2 client init: {e}")))?;
    write_frame(&mut out, &server_init)?;

    let client_finished = input.next()?;
    let result = server
        .handle_client_finished(&client_finished)
        .map_err(|e| bad(format!("ukey2 client finished: {e}")))?;

    // --- 4-5. connection responses, still plaintext ---------------------------
    write_frame(
        &mut out,
        &frames::connection_response(frames::Response::Accept, frames::OsType::Android),
    )?;
    let their_response = input.next()?;
    match frames::parse(&their_response).map_err(bad)? {
        OfflineFrame::ConnectionResponse(r) if r.response == frames::Response::Accept => {}
        OfflineFrame::ConnectionResponse(r) => {
            return Err(bad(format!("peer declined the connection: {:?}", r.response)));
        }
        other => return Err(bad(format!("expected a connection response, got {other:?}"))),
    }

    // --- 6. keys. SERVER, because we answered the handshake -------------------
    let (secrets, keys) = d2d::derive_all(
        &result.dhs,
        &result.client_init_msg,
        &result.server_init_msg,
    )
    .map_err(|_| bad("could not derive session keys"))?;
    // Four digits of the auth string, the value stock Quick Share shows so two people
    // can compare screens. Logged rather than surfaced because there is nowhere to show
    // it yet; it is the same value the peer computes.
    debug!(
        "quickshare: session pin {:04}",
        u16::from_be_bytes([secrets.auth_string[0], secrets.auth_string[1]]) % 10_000
    );
    let mut channel = SecureChannel::new(keys, Role::Server);
    info!("quickshare: encrypted channel up with {peer_name:?}");

    // --- 7. the sharing exchange ----------------------------------------------
    let mut fsm = Inbound::new();
    let mut assembler = Assembler::new();
    let mut next_payload_id: i64 = 1;
    let mut sinks: HashMap<i64, Box<dyn Write + Send>> = HashMap::new();
    let mut expected: HashMap<i64, FileMetadata> = HashMap::new();
    let mut written: Vec<String> = Vec::new();
    let mut done_bytes: u64 = 0;
    let mut total_bytes: u64 = 0;
    let mut transfer_id: i64 = 0;

    let mut pending = fsm.start();
    loop {
        // Perform whatever the machine asked for before reading again.
        //
        // Taken out first rather than drained in place: handling an effect can produce
        // MORE effects -- asking the user yields their answer, which yields the response
        // frame -- and those go on the same queue we are walking.
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
                Effect::AskUser(intro) => {
                    total_bytes = intro.total_size().max(0) as u64;
                    transfer_id = transfers.begin(false);
                    let names: Vec<String> = intro.files.iter().map(|f| f.name.clone()).collect();
                    info!(
                        "quickshare: offer {transfer_id} from {peer_name:?}: {} file(s) {names:?}",
                        names.len()
                    );
                    // PROTOCOL_QUICKSHARE, so the app badges the prompt correctly
                    // rather than calling every incoming transfer AirDrop.
                    notify(callbacks, |cb| {
                        cb.onTransferOffered(
                            transfer_id,
                            &peer_name,
                            &names,
                            total_bytes as i64,
                            1,
                        )
                    });

                    let accepted = host.ask(&peer_name, &intro.files);
                    // Fed back as an EVENT. The machine will not accept on its own under
                    // any sequence of peer frames, which is the property the prompt
                    // exists for.
                    pending.extend(fsm.on(if accepted {
                        Event::UserAccepted
                    } else {
                        Event::UserRejected
                    }));
                }
                Effect::BeginReceiving(intro) => {
                    for f in &intro.files {
                        expected.insert(f.payload_id, f.clone());
                    }
                    info!("quickshare: accepted, expecting {} payload(s)", expected.len());
                }
                Effect::BeginSending(_) => { /* we never send on an inbound connection */ }
                Effect::Done => {
                    // We advertised safe_to_disconnect_version in our response, so ask
                    // rather than just going -- same contract as the sending side.
                    write_frame(
                        &mut out,
                        &channel
                            .encrypt(&frames::disconnection(true, false))
                            .map_err(chan)?,
                    )?;
                    if transfer_id != 0 {
                        transfers.finish(transfer_id);
                    }
                    return Ok(written);
                }
                Effect::Cancelled => {
                    warn!("quickshare: cancelled");
                    if transfer_id != 0 {
                        transfers.finish(transfer_id);
                    }
                    return Ok(written);
                }
                Effect::Failed(why) => {
                    if transfer_id != 0 {
                        transfers.finish(transfer_id);
                    }
                    return Err(bad(format!("sharing refused: {why}")));
                }
            }
        }

        if host.cancelled() {
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
                match assembler.accept(&pt).map_err(|e| bad(e.to_string()))? {
                    PayloadEvent::Bytes { data, .. } => {
                        let frame = sharing::parse(&data)
                            .map_err(|e| bad(format!("sharing frame: {e}")))?;
                        pending.extend(fsm.on(Event::Frame(frame)));
                    }
                    PayloadEvent::FileChunk {
                        id,
                        data,
                        last,
                        header,
                        ..
                    } => {
                        // A payload nobody announced. Refusing it is the whole point of
                        // the introduction: without this check a peer could push files
                        // the user was never shown and never approved.
                        let Some(meta) = expected.get(&id) else {
                            return Err(bad(format!("payload {id} was never announced")));
                        };
                        let name = if meta.name.is_empty() {
                            header.file_name.clone()
                        } else {
                            meta.name.clone()
                        };
                        let sink = match sinks.get_mut(&id) {
                            Some(s) => s,
                            None => {
                                let s = host.create(&name)?;
                                sinks.insert(id, s);
                                written.push(name.clone());
                                sinks.get_mut(&id).expect("just inserted")
                            }
                        };
                        sink.write_all(&data)?;
                        done_bytes += data.len() as u64;
                        host.progress(done_bytes, total_bytes);
                        notify(callbacks, |cb| {
                            cb.onTransferProgress(
                                transfer_id,
                                done_bytes as i64,
                                total_bytes as i64,
                            )
                        });

                        if last {
                            if let Some(mut s) = sinks.remove(&id) {
                                s.flush()?;
                            }
                            expected.remove(&id);
                            info!("quickshare: payload {id} complete ({name})");
                            if expected.is_empty() {
                                pending.extend(fsm.on(Event::TransferComplete));
                            }
                        }
                    }
                    PayloadEvent::Cancelled { id } => {
                        warn!("quickshare: peer cancelled payload {id}");
                        sinks.remove(&id);
                        pending.extend(fsm.on(Event::UserCancelled));
                    }
                    PayloadEvent::Failed { id } => {
                        return Err(bad(format!("peer reported an error on payload {id}")));
                    }
                    PayloadEvent::Pending => {}
                }
            }
            OfflineFrame::KeepAlive { ack: false, seq_num } => {
                // Answer, or the peer decides we are gone and drops a live transfer.
                let ka = frames::keep_alive(true, seq_num);
                write_frame(&mut out, &channel.encrypt(&ka).map_err(chan)?)?;
            }
            OfflineFrame::KeepAlive { .. } => {}
            OfflineFrame::Disconnection { request_safe, .. } => {
                info!("quickshare: peer disconnected");
                if request_safe {
                    // The sender is holding its socket open waiting for this. Without it
                    // it closes on a timeout and may mark the transfer failed -- after
                    // we already wrote the file.
                    let ack = frames::disconnection(false, true);
                    let _ = channel
                        .encrypt(&ack)
                        .map_err(chan)
                        .and_then(|w| write_frame(&mut out, &w));
                }
                if transfer_id != 0 {
                    transfers.finish(transfer_id);
                }
                return Ok(written);
            }
            other => debug!("quickshare: ignoring {other:?}"),
        }
    }
}

/// Wrap a sharing frame in a single-chunk BYTES payload.
/// Wrap one sharing frame as a BYTES payload: **two** PayloadTransfer frames.
///
/// The body and the LAST_CHUNK flag do not travel together. This produced one fused
/// frame -- body plus flag -- which our own receiver reads correctly, so it round-trips
/// in tests and looks right on the wire. A stock receiver reassembles nothing from it:
/// the payload never completes, so the sharing frame inside it is never delivered.
///
/// That is what an introduction that reaches a peer and produces no accept prompt looks
/// like. Every sharing frame goes through here -- paired key, introduction, response --
/// so the fused shape broke all of them at once and in the same invisible way.
///
/// The terminator's offset is the total size, not zero.
pub(crate) fn wrap_bytes(next_id: &mut i64, frame: &[u8]) -> Vec<Vec<u8>> {
    *next_id += 1;
    let header = PayloadHeader {
        id: *next_id,
        payload_type: PayloadType::Bytes,
        total_size: frame.len() as i64,
        ..Default::default()
    };
    let data = PayloadChunk {
        flags: 0,
        offset: 0,
        body: frame.to_vec(),
    };
    let terminator = PayloadChunk {
        flags: frames::FLAG_LAST_CHUNK,
        offset: frame.len() as i64,
        body: Vec::new(),
    };
    vec![
        frames::payload_data(&header, &data),
        frames::payload_data(&header, &terminator),
    ]
}

pub(crate) fn write_frame(out: &mut impl Write, payload: &[u8]) -> io::Result<()> {
    out.write_all(&framing::encode(payload))?;
    out.flush()
}

pub(crate) fn bad(e: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, e.to_string())
}

pub(crate) fn chan(e: tarish_protocol::channel::Error) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, e.to_string())
}

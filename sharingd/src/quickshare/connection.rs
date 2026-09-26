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
use tarish_protocol::upgrade;
use log::{debug, info, warn};
use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::time::Duration;

/// What the daemon must provide. Kept to four things so this module can be exercised
/// with an in-memory implementation.
pub trait Host {
    /// The transfer id this connection is already registered under.
    ///
    /// ONE id per transfer. This file used to mint a second with `transfers.begin()` for
    /// the offer it announced, so the client tracked one number and the daemon tracked
    /// another: accepts were dropped, and progress, completion and cancellation were all
    /// reported against an id the client had never heard of.
    fn id(&self) -> i64;

    /// Ask the person. Blocks until they answer or it times out. `false` means refuse.
    ///
    /// `transfer_id` IS THE ID THE CLIENT WAS TOLD, and the host must wait on exactly it.
    /// It used to be absent, so QsHost waited on its own connection id while
    /// onTransferOffered announced a different one -- and Transfers::await_answer drops
    /// answers whose id does not match, deliberately, so every accept was discarded and
    /// every incoming Quick Share transfer timed out "unanswered".
    fn ask(&self, transfer_id: i64, from: &str, files: &[FileMetadata]) -> bool;
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

    /// Stand up a Wi-Fi Direct group for the sender to join, and say how to reach it.
    ///
    /// THE RECEIVER HOSTS: whoever gets UPGRADE_PATH_REQUEST creates the network. Only the
    /// client can, so this goes out to it and blocks -- forming a group takes seconds.
    ///
    /// `None` declines, which is ordinary rather than an error. The transfer then continues
    /// on the transport it already has, only slower. The default is exactly that, so a Host
    /// with no radio behind it simply never upgrades.
    fn host_group(&self) -> Option<WifiGroup> {
        None
    }

    /// Throw away everything created for this transfer.
    ///
    /// Called when the transfer is cancelled mid-stream. serve() writes each file straight
    /// to its destination as the bytes arrive, so a cancel leaves a TRUNCATED file behind;
    /// without this it is indistinguishable from a completed one and gets collected as if
    /// whole. The default is a no-op, for a host with nothing on disk to roll back.
    fn discard(&self) {}
}

/// What an inbound connection ended up doing, so the caller can tell a completed transfer
/// from a cancelled one -- the two must not be reported the same way, and a cancel must not
/// look like "received N files".
pub enum ServeOutcome {
    /// Files that landed. Empty means the peer connected but sent nothing (a probe, or a
    /// refusal), which is not a fault.
    Received(Vec<String>),
    /// The peer cancelled mid-stream. Any partial has already been discarded by serve().
    Cancelled,
}

/// A network we have stood up for a sender to join.
pub struct WifiGroup {
    pub ssid: String,
    pub passphrase: String,
    /// This device's address on the group, which the sender connects to.
    pub go_address: String,
    /// The channel in MHz, or 0 when unknown. A hint, never a requirement.
    pub frequency: i32,
}

/// Tell every registered client something happened.
///
/// A client that died holding a callback must not break receiving for the next one, so
/// failures are logged and skipped rather than propagated.
fn notify<F>(callbacks: &Callbacks, f: F)
where
    F: Fn(&binder::Strong<dyn crate::ITarishCallback>) -> binder::Result<()>,
{
    let Ok(mut cbs) = callbacks.lock() else {
        warn!("quickshare: callback list poisoned");
        return;
    };
    // DEAD_OBJECT UNREGISTERS; EVERYTHING ELSE DOES NOT. A client that is merely busy, or
    // that threw, keeps its callback -- the next event may well reach it. A dead one never
    // will, and progress fires per chunk, so keeping it means a failed transaction for every
    // chunk of every remaining file. Measured 2026-09-25 on a 20 MB off-network receive: 82
    // DEAD_OBJECT transactions in 1.3 s against an app that had already gone. The AirDrop
    // server side has always done this (httpd.rs); this path had not.
    let before = cbs.len();
    cbs.retain(|cb| match f(cb) {
        Ok(()) => true,
        Err(e) if e.transaction_error() == binder::StatusCode::DEAD_OBJECT => false,
        Err(e) => {
            debug!("quickshare: callback failed: {e:?}");
            true
        }
    });
    if cbs.len() != before {
        info!(
            "quickshare: dropped {} dead callback(s); {} left",
            before - cbs.len(),
            cbs.len()
        );
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

/// How long the sender has to join the group we stood up and introduce itself.
///
/// It has to form an association and open a socket, on a network that did not exist a moment
/// ago. Generous, because the alternative to waiting is a transfer that crawls.
const JOIN_WAIT: Duration = Duration::from_secs(25);

/// The host side of a bandwidth upgrade: stand up a group, offer it, take the sender onto it.
///
/// The mirror of `adopt()` on the send side, and the same four-frame handover seen from the
/// other end:
///
///   1. we offer  UPGRADE_PATH_AVAILABLE  on the old channel
///   2. the sender connects and sends CLIENT_INTRODUCTION on the NEW one, in plaintext
///   3. we send LAST_WRITE_TO_PRIOR unprompted -- the sender waits for it before releasing
///   4. the sender sends SAFE_TO_CLOSE, we answer with ours, and the swap happens
///
/// `Ok(false)` means we stayed put, which is never fatal: an upgrade is an optimisation and
/// treating its failure as a connection failure turns a slow transfer into no transfer.
fn offer_group<H: Host>(
    host: &H,
    input: &mut Frames<Reader>,
    out: &mut Writer,
    channel: &mut SecureChannel,
    deferred: &mut std::collections::VecDeque<Vec<u8>>,
) -> io::Result<bool> {
    // A LISTENER FIRST, so the offer can never name a port nothing is on. Bound to
    // 0.0.0.0 rather than to the group address: the p2p interface does not exist yet when
    // this runs, and binding to an address that has not appeared fails.
    let listener = match std::net::TcpListener::bind(("0.0.0.0", 0)) {
        Ok(l) => l,
        Err(e) => {
            debug!("quickshare: no listener for an upgrade ({e})");
            let no = upgrade::failure();
            write_frame(out, &channel.encrypt(&no).map_err(chan)?)?;
            return Ok(false);
        }
    };
    let port = listener.local_addr().map(|a| a.port()).unwrap_or(0);

    let Some(group) = host.host_group() else {
        debug!("quickshare: the client would not host a group");
        let no = upgrade::failure();
        write_frame(out, &channel.encrypt(&no).map_err(chan)?)?;
        return Ok(false);
    };
    info!(
        "quickshare: hosting {:?} on {}:{port} for the sender",
        group.ssid, group.go_address
    );

    let path = upgrade::UpgradePath {
        medium: upgrade::Medium::WifiDirect,
        wifi: Some(upgrade::WifiCredentials {
            ssid: group.ssid,
            password: group.passphrase,
            port: port as i32,
            gateway: group.go_address,
            frequency: group.frequency,
        }),
        lan: None,
        // We do send one, and saying so is what lets the sender wait for it rather than
        // guessing. A sender told "no ack" proceeds without waiting, which is also correct
        // -- but then an ack it did not expect turns up on a channel it is about to reuse.
        supports_introduction_ack: true,
        supports_disabling_encryption: false,
    };
    write_frame(out, &channel.encrypt(&upgrade::path_available(&path)).map_err(chan)?)?;

    // The sender now has to associate with a network that did not exist a second ago.
    listener
        .set_nonblocking(false)
        .and_then(|_| listener.set_ttl(64))
        .ok();
    let (sock, from) = match accept_within(&listener, JOIN_WAIT) {
        Some(x) => x,
        None => {
            debug!("quickshare: the sender never joined; staying put");
            let no = upgrade::failure();
            write_frame(out, &channel.encrypt(&no).map_err(chan)?)?;
            return Ok(false);
        }
    };
    let _ = sock.set_nodelay(true);
    // Same reason as every other socket here: a peer that stops reading must cost this
    // transfer, not a thread that never returns.
    let _ = sock.set_write_timeout(Some(Duration::from_secs(20)));
    info!("quickshare: the sender joined from {from}");

    let mut new_in = Frames::new(Box::new(sock.try_clone()?) as Reader);
    let mut new_out: Writer = Box::new(sock);

    // The introduction arrives in PLAINTEXT: the new channel carries no keys of its own.
    let Some(intro) = new_in.next_within(Duration::from_secs(10))? else {
        debug!("quickshare: the sender connected but never introduced itself");
        let no = upgrade::failure();
        write_frame(out, &channel.encrypt(&no).map_err(chan)?)?;
        return Ok(false);
    };
    match frames::upgrade_body(&intro).map(|b| upgrade::parse(&b)) {
        Some(Ok(upgrade::Frame::ClientIntroduction { .. })) => {}
        other => {
            debug!("quickshare: the new socket opened with {other:?}, not an introduction");
            let no = upgrade::failure();
            write_frame(out, &channel.encrypt(&no).map_err(chan)?)?;
            return Ok(false);
        }
    }
    write_frame(&mut new_out, &upgrade::client_introduction_ack())?;

    // OUR LAST_WRITE, UNPROMPTED. The sender will not send SAFE_TO_CLOSE until it has this,
    // so a host that stays quiet here leaves it waiting for a frame that is never coming --
    // the exact stall that cost most of a day from the other side.
    write_frame(out, &channel.encrypt(&upgrade::last_write_to_prior()).map_err(chan)?)?;

    // Then the release exchange on the OLD channel, bounded. Anything else is the
    // conversation and goes to the main loop rather than being dropped.
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    let mut released = false;
    while !released {
        let Some(left) = deadline.checked_duration_since(std::time::Instant::now()) else {
            break;
        };
        let Some(wire) = input.next_within(left)? else {
            break;
        };
        let plain = channel.decrypt(&wire).map_err(chan)?;
        let mut handled = false;
        if let Some(body) = frames::upgrade_body(&plain) {
            match upgrade::parse(&body) {
                Ok(upgrade::Frame::SafeToClosePrior { .. }) => {
                    handled = true;
                    released = true;
                }
                // Its LAST_WRITE crossing ours. Nothing to answer.
                Ok(upgrade::Frame::LastWriteToPrior) => handled = true,
                _ => {}
            }
        }
        if !handled {
            deferred.push_back(plain);
        }
    }
    // Ours goes out either way: the sender is owed it, and a lost or crossed frame must not
    // leave us withholding the one thing it is waiting for.
    let bye = upgrade::safe_to_close_prior(upgrade::STA_FREQUENCY_NOT_SET);
    write_frame(out, &channel.encrypt(&bye).map_err(chan)?)?;
    if !released {
        warn!("quickshare: no safe-to-close from the sender; switching over regardless");
    }

    *input = new_in;
    *out = new_out;
    Ok(true)
}

/// Accept one connection, or give up. `set_read_timeout` does not apply to accept, so this
/// polls the listener rather than blocking on it forever.
fn accept_within(
    listener: &std::net::TcpListener,
    within: Duration,
) -> Option<(std::net::TcpStream, std::net::SocketAddr)> {
    let deadline = std::time::Instant::now() + within;
    listener.set_nonblocking(true).ok()?;
    while std::time::Instant::now() < deadline {
        match listener.accept() {
            Ok((s, a)) => {
                let _ = s.set_nonblocking(false);
                let _ = listener.set_nonblocking(false);
                return Some((s, a));
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(_) => break,
        }
    }
    let _ = listener.set_nonblocking(false);
    None
}

/// Serve one connection. Returns the names written, or an error.
/// BOXED SO THEY CAN BE REPLACED MID-TRANSFER, exactly as on the send side.
///
/// A bandwidth upgrade moves the same encrypted conversation onto a different socket: the
/// keys and sequence numbers carry over untouched, because SecureChannel holds no transport.
/// Every read and write after the handover has to go somewhere else, and a generic parameter
/// cannot express that.
pub type Reader = Box<dyn ReadReady + Send>;
pub type Writer = Box<dyn Write + Send>;

pub fn serve<H>(
    stream: Reader,
    mut out: Writer,
    bootstrap: upgrade::Medium,
    host: &H,
    transfers: &Transfers,
    callbacks: &Callbacks,
) -> io::Result<ServeOutcome>
where
    H: Host,
{
    // Only worth upgrading FROM a slow transport. On a LAN socket we are already at tens of
    // megabytes and standing up a Wi-Fi Direct group would tear down a working link to get
    // something slower -- the same gate the send path needs, for the same reason.
    let bootstrap_is_slow = bootstrap == upgrade::Medium::Bluetooth;
    let mut input = Frames::new(stream);
    let mut deferred: std::collections::VecDeque<Vec<u8>> = std::collections::VecDeque::new();
    // Whether the conversation has already moved to a faster socket.
    let mut upgraded = false;

    // --- 1. the connection request, in plaintext -----------------------------
    let first = input.next()?;
    let peer_name = match frames::parse(&first).map_err(bad)? {
        OfflineFrame::ConnectionRequest(req) => {
            debug!(
                "quickshare: request from {:?} ({:?}), mediums {:?}",
                req.endpoint_name, req.endpoint_id, req.mediums
            );
            // THE NAME IS IN endpoint_info, NOT IN endpoint_name.
            //
            // A stock peer puts its EndpointInfo -- flags, a 2-byte salt, a 14-byte
            // encrypted metadata key, then a length-prefixed name -- in this field, and
            // `endpoint_name` is that same structure run through a lossy String conversion.
            // Using it directly put the binary prefix on screen:
            //
            //     offer from \ufffd\ufffd\ufffdC8EW?\ufffd\ufffd13\ufffdv\ufffdK-Desktop5090
            //
            // and the mangling is not recoverable afterwards, which is why this parses the
            // BYTES. Falls back to the raw string only when the structure does not parse,
            // so a peer that fills the field differently still gets a name of some kind.
            tarish_protocol::ble::name_from_endpoint_info(&req.endpoint_info)
                .or_else(|| {
                    let n = req.endpoint_name.trim();
                    (!n.is_empty()).then(|| n.to_string())
                })
                .unwrap_or_else(|| "A nearby device".to_string())
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
    // `_secrets` is unused while PIN verification is disabled (it fed the PIN derivation —
    // see docs/PIN-DISABLED.md); un-underscore it to revive.
    let (_secrets, keys) = d2d::derive_all(
        &result.dhs,
        &result.client_init_msg,
        &result.server_init_msg,
    )
    .map_err(|_| bad("could not derive session keys"))?;
    // PIN VERIFICATION INTENTIONALLY DISABLED — see docs/PIN-DISABLED.md. The confirmation
    // PIN is no longer derived or shown: it only ever applied to Quick Share (never AirDrop)
    // and cannot work against a stock Quick Share peer, so requiring it was inconsistent for
    // no security gain. The derivation is kept commented for revival:
    //   let session_pin = tarish_protocol::pin::derive(&secrets.auth_string);
    //   debug!("quickshare: session pin derived");
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
    // Throttle progress reporting. Every FileChunk used to fire onTransferProgress, which on
    // a slow transport (Bluetooth, thousands of small chunks) flooded the app with oneway
    // binder calls -- each progress notify() posts a Notification token to system_server, and
    // the receiver was KILLED for "too many Binders sent to uid 1000" mid-transfer. Emit at
    // most ~1% steps (and always the final one), matching the send path.
    let mut reported_bytes: u64 = 0;
    let mut transfer_id: i64 = 0;
    // WHERE THE RECEIVE LOOP'S TIME ACTUALLY GOES.
    //
    // This loop does 47 MB/s over the LAN and 800 KB/s over Wi-Fi Direct with the same buffer,
    // the same decoder and the same disk. 800 KB/s at the measured 16 ms round trip is ~12.8 KB
    // per RTT, which is one 16 KiB read per round trip — a lockstep, not a bandwidth limit. Four
    // theories have already died guessing at which step waits, so the loop now reports it:
    // microseconds inside the socket read, the decrypt, the reassembler, and the file write,
    // with the frame count. Whichever dominates is the answer; if none does, the wait is
    // somewhere this does not cover and that is worth knowing too.
    let (mut us_read, mut us_decrypt, mut us_assemble, mut us_write) = (0u128, 0u128, 0u128, 0u128);
    // The first pass measured those four and they came to 83 ms for 512 KB — 6 MB/s of capability
    // in a transfer running at 797 KB/s. So the time is NOT in reading, decrypting, reassembling
    // or writing, and the useful number is the one that says so: wall clock against the sum of
    // the parts. Whatever is left over is the bug's hiding place. These two are the leading
    // suspects for it — the progress callback is a binder round trip into an app that has been
    // seen to die mid-transfer, and the response write is the only other thing on the hot path.
    let (mut us_notify, mut us_respond) = (0u128, 0u128);
    let wall = std::time::Instant::now();
    let mut frames_in: u64 = 0;
    let mut last_timing = std::time::Instant::now();

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
                    // NOT transfers.begin() -- see Host::id.
                    transfer_id = host.id();
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
                    // PIN VERIFICATION INTENTIONALLY DISABLED — see docs/PIN-DISABLED.md.
                    // No PIN is shown on the receiver any more (it is not derived above):
                    //   notify(callbacks, |cb| cb.onTransferPinDisplay(transfer_id, &session_pin));

                    let accepted = host.ask(transfer_id, &peer_name, &intro.files);
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

                    // OFFER A FASTER MEDIUM NOW, UNPROMPTED. A sender never asks.
                    //
                    // The roles are not sender and receiver, they are DISCOVERER and
                    // ADVERTISER, and the rule is role-based: the advertiser hosts the new
                    // network and the discoverer joins it. Receiving makes us the
                    // advertiser, so the offer has to come from us. Two things in a stock
                    // peer's own log say so:
                    //
                    //   BandwidthUpgradeManager has processed endpoint disconnection ...
                    //   because there is no current BandwidthUpgradeMedium
                    //       -- a sender that never set one up, i.e. never asked
                    //
                    //   ProcessBandwidthUpgradePathAvailableEvent ignored by Advertiser
                    //       -- an advertiser refuses to JOIN, so it can only host
                    //
                    // Waiting for an UPGRADE_PATH_REQUEST here waits forever, which is why
                    // every inbound transfer ran at Bluetooth speed while the very same
                    // phone had happily hosted a group for us minutes earlier.
                    //
                    // Before the acceptance goes out, deliberately: the sender waits for our
                    // response and will not stream until it arrives, so doing this first
                    // means the handover never races the payload.
                    if !upgraded && bootstrap_is_slow {
                        match offer_group(host, &mut input, &mut out, &mut channel, &mut deferred) {
                            Ok(true) => {
                                upgraded = true;
                                info!("quickshare: upgraded the inbound transfer to Wi-Fi Direct");
                            }
                            Ok(false) => debug!("quickshare: staying on this transport"),
                            // Never fatal: the transfer is fine where it is, only slower.
                            Err(e) => warn!("quickshare: could not upgrade ({e}); staying put"),
                        }
                    }
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
                    return Ok(ServeOutcome::Received(written));
                }
                Effect::Cancelled => {
                    // Drop the writers first so the files are closed, then let the host
                    // delete whatever it opened. A partial left in the inbox would be
                    // collected by the app as if it were a whole file.
                    warn!("quickshare: cancelled — discarding the partial");
                    sinks.clear();
                    host.discard();
                    if transfer_id != 0 {
                        transfers.finish(transfer_id);
                    }
                    return Ok(ServeOutcome::Cancelled);
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
        // Frames read during a handover that were not part of it. PLAINTEXT: decrypting
        // one twice would advance the sequence numbers twice for a single frame.
        let plain = match deferred.pop_front() {
            Some(p) => p,
            None => {
                let t_read = std::time::Instant::now();
                let wire = input.next()?;
                us_read += t_read.elapsed().as_micros();
                frames_in += 1;
                let t_dec = std::time::Instant::now();
                let out = channel.decrypt(&wire).map_err(chan)?;
                us_decrypt += t_dec.elapsed().as_micros();
                out
            }
        };
        match frames::parse(&plain).map_err(bad)? {
            OfflineFrame::PayloadTransfer(pt) => {
                let t_asm = std::time::Instant::now();
                let asm = assembler.accept(&pt).map_err(|e| bad(e.to_string()))?;
                us_assemble += t_asm.elapsed().as_micros();
                match asm {
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
                        let t_w = std::time::Instant::now();
                        sink.write_all(&data)?;
                        us_write += t_w.elapsed().as_micros();
                        done_bytes += data.len() as u64;
                        // Report on ~1% steps, on the first chunk, and always on the last one
                        // of a payload. A step of 0 (unknown total) falls back to every 512 KiB.
                        let step = (total_bytes / 100).max(512 * 1024);
                        if last_timing.elapsed() >= Duration::from_secs(2) {
                            last_timing = std::time::Instant::now();
                            let acc = us_read + us_decrypt + us_assemble + us_write
                                + us_notify + us_respond;
                            let w = wall.elapsed().as_micros();
                            info!(
                                "quickshare: rx cost — wall {} ms for {} bytes in {} frames | \
                                 read {} decrypt {} assemble {} write {} notify {} respond {} \
                                 | UNACCOUNTED {} ms ({}%)",
                                w / 1000, done_bytes, frames_in,
                                us_read / 1000, us_decrypt / 1000, us_assemble / 1000,
                                us_write / 1000, us_notify / 1000, us_respond / 1000,
                                w.saturating_sub(acc) / 1000,
                                if w > 0 { 100 * w.saturating_sub(acc) / w } else { 0 }
                            );
                        }
                        if last || reported_bytes == 0 || done_bytes - reported_bytes >= step {
                            reported_bytes = done_bytes;
                            let t_n = std::time::Instant::now();
                            host.progress(done_bytes, total_bytes);
                            notify(callbacks, |cb| {
                                cb.onTransferProgress(
                                    transfer_id,
                                    done_bytes as i64,
                                    total_bytes as i64,
                                )
                            });
                            us_notify += t_n.elapsed().as_micros();
                        }

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
            OfflineFrame::BandwidthUpgrade(body) => {
                // A SENDER ASKING US TO GO FASTER. We are the receiver, so we host: stand up
                // a Wi-Fi Direct group, offer it, and move the conversation onto it.
                //
                // Anything we cannot do here answers UPGRADE_FAILURE rather than going
                // quiet. The sender has asked and is waiting; silence costs it a timeout,
                // and it is the state that made this hard to debug from the other side.
                match upgrade::parse(&body) {
                    Ok(upgrade::Frame::PathRequest { mediums }) => {
                        if !mediums.contains(&upgrade::Medium::WifiDirect) {
                            debug!("quickshare: sender asked for {mediums:?}, none of which we host");
                            let no = upgrade::failure();
                            write_frame(&mut out, &channel.encrypt(&no).map_err(chan)?)?;
                        } else {
                            match offer_group(host, &mut input, &mut out, &mut channel, &mut deferred)? {
                                true => info!("quickshare: upgraded the inbound transfer to Wi-Fi Direct"),
                                false => debug!("quickshare: staying on this transport"),
                            }
                        }
                    }
                    Ok(other) => debug!("quickshare: upgrade frame {other:?}, ignored"),
                    Err(e) => debug!("quickshare: unreadable upgrade frame ({e})"),
                }
            }
            OfflineFrame::KeepAlive { ack: false, seq_num } => {
                // Answer, or the peer decides we are gone and drops a live transfer.
                let ka = frames::keep_alive(true, seq_num);
                {
                    let t_r = std::time::Instant::now();
                    write_frame(&mut out, &channel.encrypt(&ka).map_err(chan)?)?;
                    us_respond += t_r.elapsed().as_micros();
                }
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
                return Ok(ServeOutcome::Received(written));
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

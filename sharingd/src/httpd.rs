//! The AirDrop HTTPS server — the last thing standing between us and being listed.
//!
//! A sender does not show a device because it answered mDNS. It resolves the SRV
//! record, opens **TLS** to that port and sends `POST /Discover`; the device appears in
//! the AirDrop UI only if that returns a valid plist. Barq advertised port 8770 with
//! nothing bound to it, so no peer could ever have listed us regardless of how correct
//! the mDNS side was.
//!
//! This lives in `barqsharingd`, which holds no capabilities, because everything here
//! parses input from any device on the link.
//!
//! **Scope: everyone-mode only.** Contacts-only AirDrop proves identity with an
//! Apple-issued validation record that cannot be generated, must be extracted from a
//! real Apple device, and expires yearly. We omit `ReceiverRecordData` and appear as an
//! unknown device, which is honest. A self-signed certificate is sufficient: the peer
//! does not validate ours.

use crate::plist::{self, Value};
use log::{debug, error, info, warn};
use openssl::asn1::Asn1Time;
use openssl::bn::{BigNum, MsbOption};
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::rsa::Rsa;
use openssl::ssl::{SslAcceptor, SslMethod};
use openssl::x509::{X509Builder, X509NameBuilder};
use std::io::{self, Read, Write};
use std::net::{Ipv6Addr, SocketAddrV6, TcpListener, TcpStream};
use std::time::Duration;

/// Cap on the request head we will buffer. AirDrop's requests are small; anything
/// larger is either a mistake or an attempt to make us allocate.
const MAX_HEAD: usize = 16 * 1024;

/// Cap on a request body we will buffer. Content-Length is attacker-controlled.
///
/// **8 MiB, not 64 KiB.** An `/Ask` for a PHOTO carries a `FileIcon` preview per file,
/// so its body is orders of magnitude larger than one for a document, which carries
/// none. At 64 KiB every photo from an iPhone 17 was refused while every document went
/// through -- a failure that looked device-specific because preview size tracks camera
/// resolution, not iOS version. Measured: `/Discover` is ~3.8 KB, a single-photo `/Ask`
/// exceeds 64 KiB.
///
/// `/Upload` is streamed and never counted against this; only `/Discover` and `/Ask`
/// are buffered, and both are answered and closed before any file data moves.
const MAX_BODY: usize = 8 * 1024 * 1024;

/// Where received archives land. Private to this daemon, which cannot reach shared
/// storage: the app moves them to Downloads/Barq, where Quick Share puts its own.
const INBOX: &str = "/data/misc/barq/inbox";

/// Report progress at most once per this many bytes.
const PROGRESS_STEP: u64 = 256 * 1024;

/// A slow or silent peer must not hold a connection open indefinitely.
const IO_TIMEOUT: Duration = Duration::from_secs(15);

/// How long a non-blocking accept waits between tries. Short enough that a peer
/// does not notice, long enough that an idle listener is not a wakeup source.
const ACCEPT_POLL: Duration = Duration::from_millis(250);

/// Check the interface every this many accept polls -- about two seconds.
const IFACE_CHECK_EVERY: u32 = 8;

/// How long an offer waits on screen before it is refused.
///
/// The sender shows "Waiting…" for as long as this takes, which is what an Apple
/// receiver does too. Long enough to pick the phone up and read the prompt; short
/// enough that a device left face-down does not hold the connection open all day.
const ASK_TIMEOUT: Duration = Duration::from_secs(45);

/// What to do with the connection after answering a request.
enum Disposition {
    KeepAlive,
    Close,
}

pub struct Httpd {
    acceptor: SslAcceptor,
    listener: TcpListener,
    /// What we bound to, kept so `serve` can tell when it has been replaced.
    iface: String,
    addr: Ipv6Addr,
    scope: u32,
    discover_body: Vec<u8>,
    ask_body: Vec<u8>,
    discoverable: crate::Discoverable,
    callbacks: crate::Callbacks,
    transfers: crate::Transfers,
    /// Policy said confirmation is not required, so accept without asking.
    auto_accept: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

/// Who is offering, and what.
///
/// Best-effort by design: a peer controls this body, so every field is optional and a
/// body that will not parse yields empty strings rather than a refusal. The prompt is
/// still shown -- "something wants to send you a file" with no name is a worse prompt
/// but a far better outcome than accepting silently because the plist was odd.
fn describe_offer(body: &[u8]) -> (String, Vec<String>) {
    let Some(v) = plist::parse(body) else {
        return (String::new(), Vec::new());
    };
    let from = v
        .get("SenderComputerName")
        .and_then(|s| s.as_str())
        .unwrap_or_default()
        .to_string();

    let mut names = Vec::new();
    if let Some(plist::Val::Array(items)) = v.get("Files") {
        for it in items {
            // FileName is what Apple sends; FileBomPath is the archive path and is the
            // only thing present on some senders, so fall back to its last component.
            let n = it
                .get("FileName")
                .and_then(|s| s.as_str())
                .or_else(|| it.get("FileBomPath").and_then(|s| s.as_str()))
                .unwrap_or_default();
            let leaf = n.rsplit('/').next().unwrap_or(n);
            if !leaf.is_empty() {
                names.push(leaf.to_string());
            }
        }
    }
    (from, names)
}

impl Httpd {
    /// Bind TLS on `iface`'s link-local address at `port`.
    pub fn new(
        iface: &str,
        port: u16,
        name: &str,
        model: &str,
        discoverable: crate::Discoverable,
        callbacks: crate::Callbacks,
        transfers: crate::Transfers,
        auto_accept: std::sync::Arc<std::sync::atomic::AtomicBool>,
    ) -> std::io::Result<Self> {
        let addr = crate::mdns::link_local_of(iface).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::AddrNotAvailable,
                format!("{iface} has no link-local address yet"),
            )
        })?;
        // A link-local address is ambiguous without its interface, so the scope id is
        // part of the address rather than an optional extra.
        let scope = crate::mdns::ifindex_of(iface)?;
        let sock = SocketAddrV6::new(addr, port, 0, scope);
        let listener = TcpListener::bind(sock)?;
        info!("listening on [{addr}%{iface}]:{port}");

        let acceptor = build_acceptor().map_err(|e| {
            std::io::Error::other(format!("TLS setup failed: {e}"))
        })?;

        // Precomputed: being listed needs no dynamic logic, so the body is built once.
        // ReceiverRecordData is deliberately absent -- see the module comment.
        let discover_body = plist::dict(&[
            ("ReceiverComputerName", Value::Str(name.to_string())),
            ("ReceiverModelName", Value::Str(model.to_string())),
            (
                "ReceiverMediaCapabilities",
                Value::Data(br#"{"Version":1}"#.to_vec()),
            ),
        ]);

        // /Ask answers with the same identity, minus the media capabilities.
        let ask_body = plist::dict(&[
            ("ReceiverModelName", Value::Str(model.to_string())),
            ("ReceiverComputerName", Value::Str(name.to_string())),
        ]);

        Ok(Self {
            acceptor,
            listener,
            iface: iface.to_string(),
            addr,
            scope,
            discover_body,
            ask_body,
            discoverable,
            callbacks,
            transfers,
            auto_accept,
        })
    }

    /// Accept forever. Each connection is handled on its own thread and closed after
    /// one exchange, because AirDrop sets `Connection: close` on every response.
    pub fn serve(&self) {
        // Non-blocking accept, so this loop can notice the interface going out from
        // under it.
        //
        // A blocking accept() on a socket bound to an address that no longer exists
        // does not return and does not error -- it simply waits for a connection that
        // can never arrive. serve() would sit there for the life of the process while
        // the rebind loop outside waited for it to come back, and receiving would stay
        // dead until the daemon was restarted by hand.
        //
        // That mattered little while barqd held the link from boot to shutdown. Now
        // that the radio is released whenever nothing wants it, mosey0 disappears and
        // returns with a NEW index routinely, so this is the difference between a
        // stack that survives the second transfer and one that does not.
        if self.listener.set_nonblocking(true).is_err() {
            // Better to serve with the old blocking behaviour than not to serve.
            warn!("listener will not poll — cannot detect {} being replaced", self.iface);
        }

        let mut ticks = 0u32;
        loop {
            match self.listener.accept() {
                Ok((stream, _)) => {
                    // The listener is non-blocking; the accepted socket must not be,
                    // or every read in the transfer path returns WouldBlock.
                    let _ = stream.set_nonblocking(false);
                    self.serve_one(stream);
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    ticks += 1;
                    // Roughly every two seconds, not every poll: this asks the kernel
                    // for the interface list, which is far more expensive than the
                    // accept it is riding along with.
                    if ticks % IFACE_CHECK_EVERY == 0 && self.iface_changed() {
                        info!("{} was replaced — dropping the listener to rebind", self.iface);
                        return;
                    }
                    std::thread::sleep(ACCEPT_POLL);
                }
                Err(e) => {
                    // Return rather than spin. The caller re-creates the listener a few
                    // seconds later, which is the recovery for anything durable here;
                    // continuing would busy-loop on a socket that keeps failing.
                    warn!("accept failed: {e} — rebinding");
                    return;
                }
            }
        }
    }

    /// Everything that happens on one accepted connection.
    fn serve_one(&self, stream: TcpStream) {
        // REFUSE OURSELVES, at the door.
        //
        // Everything that stops this device listing itself as a peer lives in the mDNS
        // browser, and that is the right place for it -- but it is one place, and it
        // has already been wrong once: a phone discovered itself, connected to its own
        // link-local address, and prompted the person to accept a file from
        // themselves.
        //
        // This costs one comparison against the address we are bound to and does not
        // care how the connection came to be attempted. Discovery deciding correctly
        // and the server refusing anyway are two independent answers to the same
        // question, which is what you want for the one that ends in a prompt.
        if let Ok(std::net::SocketAddr::V6(a)) = stream.peer_addr() {
            if *a.ip() == self.addr {
                debug!("refused a connection from our own address {}", self.addr);
                return;
            }
        }

        let peer = stream.peer_addr().map(|a| a.to_string()).unwrap_or_default();
        let _ = stream.set_read_timeout(Some(IO_TIMEOUT));
        let _ = stream.set_write_timeout(Some(IO_TIMEOUT));

        match self.acceptor.accept(stream) {
            Ok(mut tls) => {
                debug!("TLS handshake ok from {peer}");
                if let Err(e) = self.serve_connection(&mut tls) {
                    debug!("{peer}: {e}");
                }
                // Drain whatever the peer still has queued before dropping the
                // socket. Closing with unread bytes in the receive buffer makes
                // the kernel send RST rather than FIN, and a client that gets RST
                // discards the response it already received and retries at once.
                //
                // Content-Length is not enough on its own: a chunked request has
                // none, so the body reader takes nothing and the bytes stay
                // queued. Draining is framing-agnostic and cheap.
                drain(&mut tls);
            }
            // Not an error worth shouting about: anything on the link may probe
            // this port, and Apple itself opens and drops connections.
            Err(e) => debug!("TLS handshake from {peer} failed: {e}"),
        }
    }

    /// Has the interface we are bound to been replaced, or gone?
    ///
    /// Both halves matter. A new index with the same address still means a different
    /// interface, and an address change on the same index means our bound address is
    /// no longer local. Either way the listener is holding something dead.
    fn iface_changed(&self) -> bool {
        match (
            crate::mdns::link_local_of(&self.iface),
            crate::mdns::ifindex_of(&self.iface),
        ) {
            (Some(addr), Ok(scope)) => addr != self.addr || scope != self.scope,
            _ => true,
        }
    }

    /// Serve requests on one connection until the peer asks to close.
    ///
    /// **`/Ask` arrives with `Connection: keep-alive` because the Mac intends to send
    /// `/Upload` on the SAME connection.** Answering keep-alive and then hanging up
    /// means the upload never arrives: the peer finds the connection gone, retries
    /// `/Ask` once, and gives up. That is a transfer that fails with no error anywhere
    /// -- the log shows two accepted `/Ask`s and no `/Upload`.
    fn serve_connection<S: Read + Write>(&self, tls: &mut S) -> std::io::Result<()> {
        loop {
            match self.handle(tls)? {
                Disposition::KeepAlive => continue,
                Disposition::Close => return Ok(()),
            }
        }
    }

    fn handle<S: Read + Write>(&self, tls: &mut S) -> std::io::Result<Disposition> {
        let head = read_head(tls)?;
        let mut parts = head.split_whitespace();
        let method = parts.next().unwrap_or_default();
        let path = parts.next().unwrap_or_default();
        info!("{method} {path}");
        // The full head, once. We have been inferring what the peer wants from the
        // reply it rejects; this is the peer stating it directly.
        debug!("head: {}", head.replace("\r\n", " | ").trim_end());

        // Log what the PEER sends, not just what we answer. The request is the only
        // place an Apple device states what it expects; everything we know about the
        // response so far is inference. Guessing at wire formats has been wrong twice
        // in this project and measuring has been right every time.
        // Control routes have small bodies and are read into memory. /Upload is NOT:
        // a transfer can be any size, and buffering it would make MAX_BODY a silent
        // truncation point -- the daemon would report success on a partial archive,
        // which is worse than failing.
        let body = if path == "/Upload" {
            Vec::new()
        } else {
            let (b, desynced) = read_body(tls, &head);
            if desynced {
                // Unread bytes remain in the socket, so this connection cannot carry
                // another request. Say so and close: a peer that gets 413 reports a
                // failure, whereas one that gets silence waits forever.
                warn!("{path}: body too large — answering 413 and closing");
                respond(tls, 413, None, false)?;
                return Ok(Disposition::Close);
            }
            if !b.is_empty() {
                // Bounded dump. A photo /Ask runs to megabytes of preview data, and
                // hexing all of it costs twice that in logcat for no extra insight --
                // the interesting keys are at the front of the plist.
                const DUMP: usize = 2048;
                if b.len() <= DUMP {
                    debug!("{path} request body ({} bytes): {}", b.len(), hex(&b));
                } else {
                    debug!(
                        "{path} request body ({} bytes, first {DUMP}): {}",
                        b.len(),
                        hex(&b[..DUMP])
                    );
                }
            }
            b
        };
        let _ = &body;

        // /Ask arrives with Connection: keep-alive while /Discover uses close, so
        // this cannot be hardcoded -- answer what the peer asked for.
        let keep_alive = header(&head, "connection")
            .map(|v| v.eq_ignore_ascii_case("keep-alive"))
            .unwrap_or(false);

        match (method, path) {
            // Apple probes this before anything else; failing it is enough to be dropped.
            // Say nothing at all while invisible.
            //
            // Withdrawing the mDNS record is necessary but not sufficient: a peer that
            // still has us cached, or that was told about us by something else, asks
            // /Discover and we answered with this device's NAME. That is what kept the
            // phone on a Mac's AirDrop list with the screen off -- the record was gone,
            // but anything that asked directly was told who we are and got a device to
            // draw. An invisible device does not identify itself.
            ("HEAD", "/") if !self.visible() => {
                debug!("HEAD / refused — not discoverable");
                respond(tls, 401, None, false)?;
                return Ok(Disposition::Close);
            }
            ("POST", "/Discover") if !self.visible() => {
                info!("/Discover refused — not discoverable");
                respond(tls, 401, None, false)?;
                return Ok(Disposition::Close);
            }

            ("HEAD", "/") => respond(tls, 200, None, keep_alive)?,
            ("POST", "/Discover") => respond(tls, 200, Some(&self.discover_body), keep_alive)?,

            // "May I send you this?" Accepting is what turns the sender's UI into a
            // transfer. We accept unconditionally for now: there is no client to ask,
            // and the alternative is refusing every file. A prompt belongs here once
            // the app exists, and until then this is a deliberate open door -- said
            // plainly rather than buried.
            // Visibility is the whole consent model for now: a device that is not
            // discoverable refuses transfers outright rather than prompting. Answering
            // 401 is what the peer already understands -- it reports "Declined".
            ("POST", "/Ask") if !self.visible() => {
                info!("/Ask refused — not discoverable");
                respond(tls, 401, None, false)?;
                return Ok(Disposition::Close);
            }
            ("POST", "/Ask") => {
                // A new transfer starts here, not at /Upload: /Ask is the first point
                // the peer commits, and the UI should show something before any bytes
                // arrive rather than sitting idle through the whole handshake.
                let id = self.transfers.begin();
                let (from, names) = describe_offer(&body);
                info!("offer {id} from {from:?}: {} file(s) {names:?}", names.len());
                self.offered(id, &from, &names);

                // ASK, do not assume. Answering 200 here unconditionally meant any
                // device in range could put a file on this one while the app was open,
                // with no prompt and no record -- visibility was the entire consent
                // model. It is a person's decision, so a person makes it.
                //
                // This blocks the accept loop for up to ASK_TIMEOUT. That is deliberate
                // and matches the protocol: the peer is holding this connection open
                // waiting for exactly this answer, and will send /Upload on it.
                // An administrator may turn the prompt off. The transfer is still
                // registered and still shown, so it appears in the UI and in the
                // received list -- what is skipped is the QUESTION, not the record.
                let answer = if self.auto_accept.load(std::sync::atomic::Ordering::SeqCst) {
                    info!("offer {id} auto-accepted — policy does not require confirmation");
                    self.transfers.answer(id, true);
                    Some(true)
                } else {
                    self.transfers.await_answer(id, ASK_TIMEOUT)
                };
                match answer {
                    Some(true) => {
                        info!("offer {id} accepted");
                        respond(tls, 200, Some(&self.ask_body), keep_alive)?
                    }
                    Some(false) => {
                        info!("offer {id} declined");
                        self.transfers.finish(id);
                        // 401 is what an Apple receiver sends on decline, and what our
                        // own sender already reads back as "Declined".
                        respond(tls, 401, None, false)?;
                        return Ok(Disposition::Close);
                    }
                    None => {
                        warn!("offer {id} went unanswered for {ASK_TIMEOUT:?} — refusing");
                        self.transfers.finish(id);
                        respond(tls, 401, None, false)?;
                        return Ok(Disposition::Close);
                    }
                }
            }

            // Gated on an ACCEPTED OFFER, not on visibility.
            //
            // The consent for these bytes was given at /Ask, and it does not evaporate
            // because the visibility timer lapsed between the prompt and the upload --
            // that would fail a transfer the user agreed to, halfway through, for no
            // reason they could see. current() is non-zero only between an accepted
            // /Ask and the upload that follows it, which is exactly the window.
            //
            // It also closes the other door: /Ask and /Upload normally share one
            // connection, but nothing stops a peer opening a fresh one and posting
            // straight to /Upload, walking right past the prompt.
            ("POST", "/Upload") if self.transfers.current() == 0 => {
                warn!("/Upload with no accepted offer — refused");
                respond(tls, 401, None, false)?;
                return Ok(Disposition::Close);
            }

            ("POST", "/Upload") => {
                let id = self.transfers.current();
                match self.receive_upload(tls, &head, id) {
                    Ok(path) => {
                        info!("/Upload stored at {path}");
                        self.transfers.finish(id);
                        respond(tls, 200, None, keep_alive)?
                    }
                    Err(e) => {
                        error!("/Upload failed: {e}");
                        // -1 tells the client this ended without files rather than
                        // leaving its progress bar stuck at whatever it last saw.
                        self.each_callback(|cb| cb.onTransferFinished(id, -1));
                        self.transfers.finish(id);
                        respond(tls, 500, None, false)?;
                        return Ok(Disposition::Close);
                    }
                }
            }

            _ => respond(tls, 401, None, keep_alive)?,
        }
        Ok(if keep_alive { Disposition::KeepAlive } else { Disposition::Close })
    }

    /// Stream an upload straight to disk.
    ///
    /// Never buffered: a transfer can be any size, and holding one in a daemon's heap
    /// is both a memory bomb and the flaw the reference Go implementation flagged in
    /// its own notes ("relies on memory 100%").
    ///
    /// The archive lands in this daemon's private directory and stays there. We are
    /// `nobody` with no capabilities and deliberately cannot reach shared storage;
    /// moving files to Downloads/Barq -- where Quick Share puts its own -- is the app's
    /// job, because that is the side with the standing to write there and to tell
    /// MediaStore about it.
    /// Tell clients a transfer has been accepted and is about to send.
    ///
    /// The file names are not known yet: they live in the /Ask plist, and Barq has a
    /// plist writer but no reader. Sending an empty list is honest -- the UI shows
    /// "receiving" without inventing names it does not have.
    fn offered(&self, id: i64, from: &str, names: &[String]) {
        // totalBytes is 0: Apple's /Ask carries file names and types but no sizes, so
        // reporting anything else would be inventing it.
        // AirDrop: this server only ever speaks it. Quick Share offers will arrive
        // through their own path and name themselves.
        self.each_callback(|cb| cb.onTransferOffered(id, from, names, 0, 0));
    }

    fn progress(&self, id: i64, done: u64, total: u64) {
        self.each_callback(|cb| cb.onTransferProgress(id, done as i64, total as i64));
    }

    fn each_callback<F>(&self, f: F)
    where
        F: Fn(&binder::Strong<dyn crate::IBarqCallback>) -> binder::Result<()>,
    {
        let cbs = match self.callbacks.lock() {
            Ok(c) => c,
            Err(e) => {
                warn!("callback list poisoned: {e}");
                return;
            }
        };
        for cb in cbs.iter() {
            // A client that died holding a callback must not break receiving for the
            // next one, so failures are logged and skipped.
            if let Err(e) = f(cb) {
                debug!("callback failed: {e:?}");
            }
        }
    }

    fn visible(&self) -> bool {
        self.discoverable.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Tell any registered client that files have arrived.
    ///
    /// Failures are logged and ignored: a client that died holding a callback must not
    /// be able to break receiving for the next one.
    fn announce(&self, id: i64, names: &[String]) {
        let n = names.len() as i32;
        self.each_callback(|cb| cb.onTransferFinished(id, n));
    }

    /// Unpack a received archive into the inbox.
    ///
    /// The payload is Apple's block-framed compression wrapper around a cpio archive in
    /// the odc dialect -- see framed.rs for the container and why it is not gzip.
    fn extract(&self, archive: &str) -> std::io::Result<Vec<String>> {
        // `new`, `read_next` and `finish` come from the CpioReader trait, so it has to
        // be in scope even though it is never named below.
        use cpio_archive::CpioReader as _;

        let f = std::fs::File::open(archive)?;
        let mut r = cpio_archive::odc::OdcReader::new(std::io::BufReader::new(
            crate::framed::FramedReader::new(f),
        ));
        let mut names = Vec::new();

        loop {
            let header = match r.read_next().map_err(cpio_err)? {
                Some(h) => h,
                None => break,
            };
            let name = header.name().to_string();
            let size = header.file_size();
            let is_dir = header.mode() & 0o170000 == 0o040000;
            drop(header);

            // What must not become a file:
            //   "."         the archive's own root
            //   "._<name>"  AppleDouble sidecars -- macOS resource-fork metadata that
            //               accompanies every file. Writing them out leaves a hidden
            //               junk file beside each real one, which is what a naive
            //               extractor does. Half a real transfer is these: four photos
            //               arrived as nine entries.
            //   directories we flatten into the inbox rather than recreating a tree
            //
            // TRAILER!!! needs no check -- the reader never emits it.
            let leaf = safe_leaf(&name);
            let skip = match &leaf {
                None => true,
                Some(l) => l.starts_with("._") || is_dir || size == 0,
            };
            if skip {
                debug!("skipping {name:?} ({size} bytes)");
                // finish() advances past a member we did not read.
                r.finish().map_err(cpio_err)?;
                continue;
            }
            let leaf = leaf.expect("checked above");

            let dest = non_clobbering(INBOX, &leaf);
            let mut out = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&dest)?;
            // OdcReader is BOTH Iterator and Read, so `.take()` is ambiguous --
            // Iterator::take counts elements, Read::take counts bytes. Name the trait.
            let mut limited = Read::take(&mut r, size);
            let copied = io::copy(&mut limited, &mut out)?;
            if copied != size {
                warn!("{dest}: expected {size} bytes, wrote {copied}");
            }
            info!("extracted {dest} ({copied} bytes)");
            r.finish().map_err(cpio_err)?;
            if let Some(leaf) = std::path::Path::new(&dest).file_name() {
                names.push(leaf.to_string_lossy().into_owned());
            }
        }
        Ok(names)
    }

    fn receive_upload<S: Read>(&self, s: &mut S, head: &str, id: i64) -> std::io::Result<String> {
        // No create_dir_all here: init makes /data/misc/barq/inbox at post-fs-data,
        // and calling it anyway cost a real transfer. create_dir_all stats the path
        // first, `getattr` on the directory was not in our policy, so it could not tell
        // the directory existed, tried to create it, and returned EEXIST -- reported as
        // "File exists" on a perfectly good inbox.
        //
        // Not asking is better than asking for a permission we do not need.
        // A random name, never anything the peer supplies: a filename from the wire is
        // attacker-controlled and has no business steering a path.
        //
        // An earlier version numbered these by counting directory entries, which is
        // broken in two ways that both fail silently: the count drops once the app
        // collects an archive, so the next transfer reuses a name, and two concurrent
        // uploads read the same count and race. create_new below turns any collision
        // into an error instead of a silent truncation.
        let (path, mut f) = create_unique(INBOX, "cpio")?;

        // The peer states the whole payload size up front in its own header, which is
        // what makes a real percentage possible: the body is chunked, so Content-Length
        // is absent and the stream alone cannot say how far along it is.
        let total = header(head, "totalbytes")
            .and_then(|v| v.trim().parse::<u64>().ok())
            .unwrap_or(0);

        let mut sniff = Vec::new();
        let mut last_report = 0u64;
        // Throttled: a callback per 8 KB chunk would cross binder thousands of times for
        // one photo and slow the transfer it is reporting on.
        let mut on_progress = |done: u64| {
            if total > 0 && done.saturating_sub(last_report) >= PROGRESS_STEP {
                last_report = done;
                self.progress(id, done, total);
            }
        };
        let cancelled = || self.transfers.is_cancelled(id);

        let written = if header(head, "transfer-encoding")
            .map(|v| v.to_ascii_lowercase().contains("chunked"))
            .unwrap_or(false)
        {
            stream_chunked(s, &mut f, &mut sniff, &mut on_progress, &cancelled)?
        } else {
            let len = header(head, "content-length")
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(total);
            stream_exact(s, &mut f, len, &mut sniff, &mut on_progress, &cancelled)?
        };

        if self.transfers.is_cancelled(id) {
            // The partial archive is useless and the user asked for it to stop, so it
            // goes rather than lingering as a file nobody can open.
            let _ = std::fs::remove_file(&path);
            return Err(std::io::Error::new(
                std::io::ErrorKind::Interrupted,
                "cancelled by the user",
            ));
        }
        self.progress(id, written, if total > 0 { total } else { written });

        info!("/Upload: {written} bytes received");
        drop(f);

        match self.extract(&path) {
            Ok(names) => {
                info!("/Upload: extracted {} file(s)", names.len());
                // The archive has served its purpose. Keeping it would double the
                // storage every transfer costs and leave the user's files lying around
                // in a second form they cannot see or delete.
                if let Err(e) = std::fs::remove_file(&path) {
                    warn!("could not remove {path}: {e}");
                }
                self.announce(id, &names);
            }
            // Kept on failure: it is the only copy of what the peer sent, and deleting
            // it would destroy the evidence needed to work out why.
            Err(e) => error!("/Upload: extraction failed ({e}) — archive kept at {path}"),
        }
        Ok(path)
    }
}

/// Read until the end of the request head, bounded.
///
/// The body is read separately by `read_body`, which bounds itself rather than
/// trusting the declared Content-Length.
fn read_head<S: Read>(s: &mut S) -> std::io::Result<String> {
    let mut buf = Vec::with_capacity(1024);
    let mut byte = [0u8; 1];
    while buf.len() < MAX_HEAD {
        let n = s.read(&mut byte)?;
        if n == 0 {
            break;
        }
        buf.push(byte[0]);
        if buf.ends_with(b"\r\n\r\n") {
            return Ok(String::from_utf8_lossy(&buf).into_owned());
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        "request head too large or truncated",
    ))
}

/// Read the request body.
///
/// **AirDrop sends `Transfer-Encoding: chunked` and no `Content-Length`.** That was
/// measured, not assumed, and it matters more than it looks: a reader that only
/// understands Content-Length takes nothing, leaves the bytes queued, and the socket
/// then closes with unread data -- which makes the kernel send RST instead of FIN. The
/// peer discards the response it already received and retries immediately. That is
/// what an 8035-request-per-forty-minutes storm against a byte-correct reply looked
/// like.
///
/// Bounded by MAX_BODY throughout: both the declared length and the chunk sizes are
/// attacker-controlled, and allocating on either is the obvious way to be exhausted.
///
/// Returns `(body, desynced)`. `desynced` means the body was larger than we would
/// buffer and unread bytes remain in the socket, so the connection can no longer be
/// reused -- the caller must answer and close rather than loop. Silently truncating
/// instead is what left an iPhone waiting forever on a photo: the leftover body bytes
/// were read as the next request head ("request head too large or truncated"), the
/// `/Ask` was never answered, and the sender's UI hung with nothing to cancel.
fn read_body<S: Read>(s: &mut S, head: &str) -> (Vec<u8>, bool) {
    if header(head, "transfer-encoding")
        .map(|v| v.to_ascii_lowercase().contains("chunked"))
        .unwrap_or(false)
    {
        return read_chunked(s);
    }
    let declared = header(head, "content-length")
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(0);
    if declared > MAX_BODY {
        warn!("body of {declared} bytes exceeds {MAX_BODY} — refusing");
        return (Vec::new(), true);
    }
    (read_exact_bounded(s, declared), false)
}

/// Case-insensitive header lookup.
fn header<'a>(head: &'a str, name: &str) -> Option<&'a str> {
    head.lines().find_map(|l| {
        let (k, v) = l.split_once(':')?;
        k.trim().eq_ignore_ascii_case(name).then(|| v.trim())
    })
}

fn read_exact_bounded<S: Read>(s: &mut S, len: usize) -> Vec<u8> {
    if len == 0 {
        return Vec::new();
    }
    let mut buf = vec![0u8; len];
    let mut got = 0;
    while got < len {
        match s.read(&mut buf[got..]) {
            Ok(0) => break,
            Ok(n) => got += n,
            Err(_) => break,
        }
    }
    buf.truncate(got);
    buf
}

/// RFC 7230 chunked transfer decoding.
///
/// Each chunk is a hex length, CRLF, that many bytes, CRLF; a zero length ends the
/// body, optionally followed by trailers we skip. Deliberately small and strict --
/// this parses input from any device on the link.
fn read_chunked<S: Read>(s: &mut S) -> (Vec<u8>, bool) {
    let mut out = Vec::new();
    loop {
        let line = match read_line(s) {
            Some(l) => l,
            None => break,
        };
        // A chunk-size may carry ";ext" parameters we do not use.
        let size_txt = line.split(';').next().unwrap_or("").trim();
        let size = match usize::from_str_radix(size_txt, 16) {
            Ok(n) => n,
            Err(_) => break, // malformed: stop rather than guess
        };
        if size == 0 {
            // Trailers until a blank line, then done.
            while let Some(l) = read_line(s) {
                if l.is_empty() {
                    break;
                }
            }
            break;
        }
        if out.len() + size > MAX_BODY {
            warn!("chunked body exceeds {MAX_BODY} bytes — refusing");
            return (out, true);
        }
        let chunk = read_exact_bounded(s, size);
        let short = chunk.len() < size;
        out.extend_from_slice(&chunk);
        if short {
            break; // peer went away mid-chunk
        }
        let _ = read_line(s); // trailing CRLF after the chunk data
    }
    (out, false)
}

/// One CRLF-terminated line, bounded so a peer cannot make us grow forever.
fn read_line<S: Read>(s: &mut S) -> Option<String> {
    let mut buf = Vec::with_capacity(32);
    let mut b = [0u8; 1];
    while buf.len() < 256 {
        match s.read(&mut b) {
            Ok(0) | Err(_) => return None,
            Ok(_) => {}
        }
        if b[0] == b'\n' {
            while buf.last() == Some(&b'\r') {
                buf.pop();
            }
            return Some(String::from_utf8_lossy(&buf).into_owned());
        }
        buf.push(b[0]);
    }
    None
}

/// Read and discard anything still pending, briefly, so the close is graceful.
fn drain<S: Read>(s: &mut S) {
    let mut sink = [0u8; 2048];
    for _ in 0..8 {
        match s.read(&mut sink) {
            Ok(0) => return,
            Ok(_) => continue,
            Err(_) => return, // timeout or reset: nothing useful left to do
        }
    }
}

/// Turn an archive entry's name into a safe leaf filename.
///
/// **A name inside an archive is attacker-controlled**, and the classic way to abuse it
/// is path traversal: an entry called `../../../data/local/tmp/x`, or an absolute path,
/// escapes the directory it was supposed to land in. Taking only the final component
/// removes the whole class rather than trying to detect it.
///
/// Returns None for anything that cannot be a filename at all, so the caller has to
/// decide what to do rather than being handed a silently-mangled path.
pub fn safe_leaf(entry_name: &str) -> Option<String> {
    let leaf = entry_name
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or("")
        .trim()
        .to_string();
    if leaf.is_empty() || leaf == "." || leaf == ".." {
        return None;
    }
    // NUL cannot appear in a path, and a leading dot would hide the file.
    if leaf.contains('\0') {
        return None;
    }
    Some(leaf)
}

/// A destination path that never overwrites an existing file.
///
/// Two files can legitimately arrive with the same name -- the same photo sent twice,
/// or a `IMG_0001.jpg` that already exists -- and silently replacing the older one
/// loses data that was not ours to lose. Disambiguates the way a browser does:
/// `photo.jpg`, then `photo (1).jpg`, then `photo (2).jpg`.
///
/// Checks with `create_new` at the caller rather than testing existence and then
/// creating, which would be a race.
pub fn non_clobbering(dir: &str, leaf: &str) -> String {
    let (stem, ext) = match leaf.rsplit_once('.') {
        // A leading dot is a hidden file, not an extension.
        Some((s, e)) if !s.is_empty() => (s, format!(".{e}")),
        _ => (leaf, String::new()),
    };
    let mut candidate = format!("{dir}/{leaf}");
    let mut n = 1;
    while std::path::Path::new(&candidate).exists() {
        candidate = format!("{dir}/{stem} ({n}){ext}");
        n += 1;
        if n > 9999 {
            break; // give up disambiguating rather than spin
        }
    }
    candidate
}

/// Create a file with a random name that cannot collide with an existing one.
///
/// `create_new` sets O_EXCL, so an existing file is an error rather than a silent
/// truncation. Retried a few times because randomness does not excuse ignoring the
/// race; 16 hex characters make a collision effectively impossible, and the retry is
/// there so "effectively" never has to be trusted.
fn create_unique(dir: &str, ext: &str) -> std::io::Result<(String, std::fs::File)> {
    for _ in 0..8 {
        let path = format!("{dir}/{}.{ext}", random_hex());
        match std::fs::OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(f) => return Ok((path, f)),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::AlreadyExists,
        "could not find an unused name",
    ))
}

/// 16 hex characters from the kernel CSPRNG.
fn random_hex() -> String {
    let mut b = [0u8; 8];
    // SAFETY: getrandom(2) writing exactly b.len() bytes into a live buffer.
    let n = unsafe { libc::getrandom(b.as_mut_ptr() as *mut libc::c_void, b.len(), 0) };
    if n != b.len() as isize {
        // Never fall back to something predictable: a guessable name in a shared
        // directory is a way for another process to pre-create or swap the file.
        // Time is not a substitute for randomness, so fail loudly instead.
        error!("getrandom failed — refusing to invent a name");
        return String::from("getrandom-failed");
    }
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Copy a chunked body to `out`, keeping the first bytes for format sniffing.
fn stream_chunked<S: Read, W: std::io::Write>(
    s: &mut S,
    out: &mut W,
    sniff: &mut Vec<u8>,
    on_progress: &mut dyn FnMut(u64),
    cancelled: &dyn Fn() -> bool,
) -> std::io::Result<u64> {
    let mut total = 0u64;
    let mut buf = [0u8; 8192];
    loop {
        let line = match read_line(s) {
            Some(l) => l,
            None => break,
        };
        let size_txt = line.split(';').next().unwrap_or("").trim();
        let size = match usize::from_str_radix(size_txt, 16) {
            Ok(n) => n,
            Err(_) => break,
        };
        if size == 0 {
            while let Some(l) = read_line(s) {
                if l.is_empty() {
                    break;
                }
            }
            break;
        }
        let mut left = size;
        while left > 0 {
            let want = left.min(buf.len());
            let n = s.read(&mut buf[..want])?;
            if n == 0 {
                return Ok(total); // peer went away mid-chunk
            }
            if sniff.len() < 16 {
                sniff.extend_from_slice(&buf[..n.min(16 - sniff.len())]);
            }
            out.write_all(&buf[..n])?;
            total += n as u64;
            left -= n;
            on_progress(total);
            if cancelled() {
                return Ok(total);
            }
        }
        let _ = read_line(s); // CRLF after chunk data
    }
    out.flush()?;
    Ok(total)
}

fn stream_exact<S: Read, W: std::io::Write>(
    s: &mut S,
    out: &mut W,
    len: u64,
    sniff: &mut Vec<u8>,
    on_progress: &mut dyn FnMut(u64),
    cancelled: &dyn Fn() -> bool,
) -> std::io::Result<u64> {
    let mut total = 0u64;
    let mut buf = [0u8; 8192];
    while total < len {
        let want = ((len - total) as usize).min(buf.len());
        let n = s.read(&mut buf[..want])?;
        if n == 0 {
            break;
        }
        if sniff.len() < 16 {
            sniff.extend_from_slice(&buf[..n.min(16 - sniff.len())]);
        }
        out.write_all(&buf[..n])?;
        total += n as u64;
        on_progress(total);
        if cancelled() {
            return Ok(total);
        }
    }
    out.flush()?;
    Ok(total)
}

/// Leaf names of files waiting to be collected.
///
/// `.cpio` is excluded: an archive only survives extraction failure, and handing a
/// client a container it cannot read would be worse than saying nothing.
pub fn received_files() -> Vec<String> {
    let mut out = Vec::new();
    if let Ok(entries) = std::fs::read_dir(INBOX) {
        for e in entries.flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            if !name.ends_with(".cpio") {
                out.push(name);
            }
        }
    }
    out.sort();
    out
}

/// Open a received file by leaf name.
///
/// The name is reduced to a leaf before use, so a caller cannot walk out of the inbox
/// with `../` or an absolute path even though the caller here is our own client.
pub fn open_received(name: &str) -> std::io::Result<std::fs::File> {
    std::fs::File::open(inbox_path(name)?)
}

pub fn delete_received(name: &str) -> std::io::Result<()> {
    std::fs::remove_file(inbox_path(name)?)
}

fn inbox_path(name: &str) -> std::io::Result<String> {
    match safe_leaf(name) {
        Some(leaf) if !leaf.ends_with(".cpio") => Ok(format!("{INBOX}/{leaf}")),
        _ => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "not a collectable file name",
        )),
    }
}

/// cpio-archive's error type is not io::Error; give it one shape at the boundary.
fn cpio_err(e: cpio_archive::Error) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string())
}

fn hex(b: &[u8]) -> String {
    let mut out = String::with_capacity(b.len() * 2);
    for x in b {
        out.push_str(&format!("{x:02x}"));
    }
    out
}

/// Write an HTTP/1.1 response.
///
/// HTTP/1.1 explicitly, and `Connection: close` on every response. Apple's stack does
/// not expect HTTP/2 here, and a server that keeps the connection open stalls the
/// exchange in a way that produces no useful error on either side.
fn respond<S: Write>(
    s: &mut S,
    status: u16,
    body: Option<&[u8]>,
    keep_alive: bool,
) -> std::io::Result<()> {
    let reason = match status {
        200 => "OK",
        413 => "Payload Too Large",
        _ => "Unauthorized",
    };
    let body = body.unwrap_or(&[]);
    let conn = if keep_alive { "keep-alive" } else { "close" };
    let mut head = format!(
        "HTTP/1.1 {status} {reason}\r\nConnection: {conn}\r\nContent-Length: {}\r\n",
        body.len()
    );
    if !body.is_empty() {
        head.push_str("Content-Type: application/octet-stream\r\n");
    }
    head.push_str("\r\n");
    s.write_all(head.as_bytes())?;
    if !body.is_empty() {
        s.write_all(body)?;
    }
    s.flush()
}

/// A self-signed certificate, generated fresh at each start.
///
/// Not persisted deliberately: the peer does not validate it, nothing pins it, and a
/// key that never touches storage cannot be stolen from storage.
fn build_acceptor() -> Result<SslAcceptor, openssl::error::ErrorStack> {
    let rsa = Rsa::generate(2048)?;
    let key = PKey::from_rsa(rsa)?;

    let mut name = X509NameBuilder::new()?;
    name.append_entry_by_text("CN", "Barq")?;
    let name = name.build();

    let mut serial = BigNum::new()?;
    serial.rand(159, MsbOption::MAYBE_ZERO, false)?;

    let mut b = X509Builder::new()?;
    b.set_version(2)?;                       // 2 == X.509 v3
    let serial = serial.to_asn1_integer()?;
    b.set_serial_number(&serial)?;
    b.set_subject_name(&name)?;
    b.set_issuer_name(&name)?;               // self-signed: issuer is subject
    b.set_pubkey(&key)?;
    let not_before = Asn1Time::days_from_now(0)?;
    let not_after = Asn1Time::days_from_now(365)?;
    b.set_not_before(&not_before)?;
    b.set_not_after(&not_after)?;
    b.sign(&key, MessageDigest::sha256())?;
    let cert = b.build();

    let mut acc = SslAcceptor::mozilla_intermediate(SslMethod::tls())?;
    acc.set_private_key(&key)?;
    acc.set_certificate(&cert)?;
    acc.check_private_key()?;
    Ok(acc.build())
}

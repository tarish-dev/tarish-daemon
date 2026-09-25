//! Sending: phone to an Apple device.
//!
//! The mirror of the receive path. We resolve a peer from mDNS, open TLS to the port its
//! SRV record advertises, and run the same three-step exchange an Apple sender runs:
//!
//! ```text
//! POST /Discover   who are you            -> the peer's name, if it will tell us
//! POST /Ask        may I send you this    -> 200 means the user accepted
//! POST /Upload     the payload            -> framed-zlib around a cpio odc archive
//! ```
//!
//! `/Ask` and `/Upload` go over **one connection**, because that is what a Mac does and
//! the receiver is entitled to expect it.
//!
//! **Everyone-mode only**, matching the receive side: no `SenderRecordData`, no client
//! certificate, and we do not validate theirs. Contacts-only needs an Apple validation
//! record that cannot be generated.

use flate2::write::GzEncoder;
use flate2::Compression;
use crate::plist::{self, Value};
use cpio_archive::odc::{OdcBuilder, OdcHeader};
use log::{debug, info, warn};
use openssl::ssl::{SslConnector, SslMethod, SslStream, SslVerifyMode};
// POLLIN-with-a-deadline, already implemented for TcpStream for the Quick Share upgrade
// wait. Same need here: wait for a peer without going deaf to a cancel.
use crate::quickshare::connection::ReadReady;
use std::io::{self, Read, Write};
use std::net::{Ipv6Addr, SocketAddrV6, TcpStream};
use std::time::Duration;

/// Bulk I/O on the socket. A peer that goes silent this long during a payload is gone.
const IO_TIMEOUT: Duration = Duration::from_secs(30);

/// How long to wait for `/Ask` to be answered.
///
/// THIS ONE IS A PERSON, NOT A SOCKET, and that is the whole reason it is separate.
/// `/Ask` puts a prompt on the peer's screen and then waits for someone to pick the phone
/// up and tap Accept. `IO_TIMEOUT` used to cover this read too, so any offer not answered
/// within 30s died with EAGAIN — while the prompt was still sitting there, unanswered. The
/// send was reported as failed and the person had done nothing wrong.
///
/// Measured on blazer 2026-09-25, to the tenth of a second:
/// ```text
/// 02:48:23.499  -> POST /Ask ... Content-Length: 396
/// 02:48:53.924  send 7 failed: Try again (os error 11)
/// ```
/// 30.4s — the timeout, not the link. iOS keeps an AirDrop prompt up for around a minute,
/// so this has to outlast the prompt rather than race it. It is not a liveness check: the
/// TCP connection is already established and the peer is demonstrably there.
const ASK_TIMEOUT: Duration = Duration::from_secs(180);

/// How often to surface from the `/Ask` wait to check whether the send was cancelled.
/// Short enough that Cancel feels immediate, long enough not to spin on poll().
const ASK_POLL: Duration = Duration::from_millis(250);

/// Where a peer lives, resolved from its mDNS records.
pub struct Target {
    pub addr: Ipv6Addr,
    pub port: u16,
    pub scope: u32,
}

/// One file to send: an open descriptor and the name it should arrive under.
pub struct Item {
    pub file: std::fs::File,
    pub name: String,
    pub size: u64,
}

/// Ask a peer who it is.
///
/// Returns the display name if it gives one. A peer that refuses `/Discover` is not
/// necessarily unreachable -- it may simply not be discoverable to us -- so the caller
/// decides what to do rather than this treating it as fatal.
pub fn discover(target: &Target) -> io::Result<Option<String>> {
    let mut tls = connect(target)?;
    // Everyone mode: an empty body. A sender in contacts mode would put its
    // SenderRecordData here, which is exactly the thing we cannot produce.
    let body = plist::dict(&[]);
    request(&mut tls, "/Discover", &body, false)?;
    let (status, reply) = read_response(&mut tls)?;
    if status != 200 {
        debug!("/Discover -> {status}");
        return Ok(None);
    }
    Ok(plist::parse(&reply)
        .and_then(|v| v.get("ReceiverComputerName").and_then(|n| n.as_str()).map(String::from)))
}

/// Offer files, then send them if the peer accepts.
///
/// `progress` is called with bytes written so far; `cancelled` is polled between blocks
/// so a cancel takes effect promptly rather than at the end of the archive.
pub fn send(
    target: &Target,
    items: Vec<Item>,
    sender_name: &str,
    sender_model: &str,
    mut progress: impl FnMut(u64, u64),
    cancelled: impl Fn() -> bool,
) -> io::Result<()> {
    if items.is_empty() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "nothing to send"));
    }
    let total: u64 = items.iter().map(|i| i.size).sum();

    let mut tls = connect(target)?;

    // --- /Ask -------------------------------------------------------------
    let ask = ask_body(&items, sender_name, sender_model);
    request(&mut tls, "/Ask", &ask, true)?;
    // WAIT IN SLICES, AND DO NOT TOUCH THE SOCKET TIMEOUT.
    //
    // Widening SO_RCVTIMEO to ASK_TIMEOUT would work but buys a long window in which a
    // cancel does nothing: the thread is parked inside one blocking read, and `cancelled`
    // is not consulted until it returns. Polling for readability instead keeps Cancel live
    // the whole time the prompt is up, and leaves IO_TIMEOUT in place for the payload — so
    // there is no timeout to restore and no path that can leak the wide one.
    //
    // `pending()` first: OpenSSL buffers whole records, so bytes it has already decrypted
    // are invisible to poll() on the fd, and waiting on the descriptor for data we are
    // holding would stall until the deadline.
    let deadline = std::time::Instant::now() + ASK_TIMEOUT;
    while tls.ssl().pending() == 0 && !tls.get_ref().ready_within(ASK_POLL)? {
        if cancelled() {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "cancelled while waiting for the peer to accept",
            ));
        }
        if std::time::Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "the peer never answered the offer — it was neither accepted nor declined",
            ));
        }
    }
    let (status, _) = read_response(&mut tls)?;
    if status == 0 {
        // NOT A DECLINE. Status 0 means no status line came back at all: the peer closed the
        // connection without answering. Seen on blazer 2026-09-25 — /Discover answered 200 with
        // a full body, then /Ask was closed 0.8s later with zero bytes — and it was reported to
        // the operator as "the peer declined (0)". Nobody had declined anything; no prompt was
        // ever shown. iOS does this when it is not in a receptive state (its "Everyone" window
        // has lapsed, or the receiver is otherwise not accepting offers), so the honest message
        // is about the peer's state, not the person's choice. It is also NOT PermissionDenied,
        // so the caller must not map it to STATUS_DECLINED.
        return Err(io::Error::new(
            io::ErrorKind::ConnectionAborted,
            "the peer closed the connection without answering the offer — no prompt was shown; \
             check that AirDrop on that device is set to Everyone and it is awake",
        ));
    }
    if status != 200 {
        // 401 is the peer declining, which is a normal outcome and not a fault.
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("the peer declined ({status})"),
        ));
    }
    info!("peer accepted, sending {} item(s), {total} bytes", items.len());

    // --- /Upload ----------------------------------------------------------
    //
    // Chunked, because the framed archive is produced as it is read and its final size
    // is not known until the last block. TotalBytes carries the raw payload size so the
    // peer can show a percentage, exactly as we rely on when receiving.
    let head = format!(
        "POST /Upload HTTP/1.1\r\n\
         Connection: close\r\n\
         Content-Type: application/x-cpio\r\n\
         Accept: */*\r\n\
         User-Agent: AirDrop/1.0\r\n\
         Accept-Language: en-us\r\n\
         TotalBytes: {total}\r\n\
         Transfer-Encoding: chunked\r\n\r\n"
    );
    tls.write_all(head.as_bytes())?;

    // GZIP, not the block-framed container.
    //
    // The two directions are NOT symmetric, which cost a transfer to discover. Apple's
    // sender wraps its cpio in a block-framed zlib container -- that is what arrives
    // when a Mac sends to us, and what framed.rs decodes. But an Apple RECEIVER expects
    // an ordinary gzip stream, which is what opendrop sends and what interoperates.
    // Mirroring the receive format back at the peer made it reset the connection the
    // moment bytes started arriving.
    let sent = {
        let chunker = ChunkedWriter { inner: &mut tls };
        let mut gz = GzEncoder::new(chunker, Compression::default());
        let mut done = 0u64;
        {
            let mut cpio = OdcBuilder::new(&mut gz);
            for mut item in items {
                if cancelled() {
                    return Err(io::Error::new(io::ErrorKind::Interrupted, "cancelled"));
                }
                let mut header: OdcHeader = cpio.next_header();
                // "./name" matches FileBomPath in the /Ask body. A receiver looks the
                // entry up by that path, so the two have to agree exactly.
                header.name = format!("./{}", item.name);
                header.file_size = item.size;
                header.mode = 0o100644;
                // Report progress WHILE the file streams, not just once when it finishes.
                // A single-file send used to call progress() one time, at 100%, so the
                // sender's ring only ever spun -- the counting reader now reports
                // incrementally, throttled to ~1% steps so it does not flood the callback.
                let step = (total / 100).max(64 * 1024);
                let seen = {
                    let mut counting = Counting {
                        inner: &mut item.file,
                        seen: 0,
                        base: done,
                        total,
                        last: done,
                        step,
                        report: &mut progress,
                        cancelled: &cancelled,
                    };
                    cpio.append_header_with_reader(header, &mut counting)
                        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
                    counting.seen
                };
                done += seen;
                progress(done, total);
            }
            cpio.finish()
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
        }
        let chunker = gz.finish()?;
        chunker.end()?;
        done
    };

    let (status, _) = read_response(&mut tls)?;
    if status != 200 {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!("upload rejected ({status})"),
        ));
    }
    info!("sent {sent} bytes");
    Ok(())
}

// ------------------------------------------------------------------ plumbing ---

/// How long a SYN to a link-local peer may go unanswered. Five seconds is generous for a
/// device one radio hop away; the kernel's default is over two minutes of retries, and that
/// is what a /Discover probe sat in on 2026-09-25 (17:01:19 -> "Connection timed out" at
/// 17:03:35) while the peer stayed hidden as unnamed. Task #51 asked for this bound.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// And the TLS handshake. It used to run under IO_TIMEOUT (30 s), which is sized for a bulk
/// read, not for two round trips: a handshake the peer will not finish should fail in
/// seconds so the caller can try again.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

fn connect(target: &Target) -> io::Result<SslStream<TcpStream>> {
    // A link-local address is meaningless without its interface, so the scope id is
    // part of the address rather than an optional extra.
    let sock = SocketAddrV6::new(target.addr, target.port, 0, target.scope);
    let tcp = TcpStream::connect_timeout(&sock.into(), CONNECT_TIMEOUT)?;
    // Short while the handshake runs; widened to the bulk value once it is done.
    tcp.set_read_timeout(Some(HANDSHAKE_TIMEOUT))?;
    tcp.set_write_timeout(Some(HANDSHAKE_TIMEOUT))?;

    let mut b = SslConnector::builder(SslMethod::tls())
        .map_err(|e| io::Error::other(format!("TLS setup: {e}")))?;
    // Apple presents a self-signed certificate and does not validate ours either --
    // opendrop notes "we accept self-signed certificates as does Apple". Verification
    // here would reject every real peer.
    b.set_verify(SslVerifyMode::NONE);
    // configure() and connect() fail with different error types, so they cannot chain.
    let config = b
        .build()
        .configure()
        .map_err(|e| io::Error::other(format!("TLS configure: {e}")))?
        // There is no hostname to check -- the peer is a link-local address with a
        // self-signed certificate -- so SNI and hostname verification are both off.
        .use_server_name_indication(false)
        .verify_hostname(false);

    let tls = config
        .connect("tarish", tcp)
        .map_err(|e| io::Error::other(format!("TLS handshake: {e}")))?;
    tls.get_ref().set_read_timeout(Some(IO_TIMEOUT))?;
    tls.get_ref().set_write_timeout(Some(IO_TIMEOUT))?;
    Ok(tls)
}

fn request<S: Write>(tls: &mut S, path: &str, body: &[u8], keep_alive: bool) -> io::Result<()> {
    // These headers are not decoration. A receiver that does not recognise the client
    // closes the connection without answering at all -- which is exactly what happened:
    // /Discover was tolerated, /Ask got zero bytes back and no status line. Apple's own
    // requests to us carry User-Agent: AirDrop/1.0, and opendrop sends this same set.
    let head = format!(
        "POST {path} HTTP/1.1\r\n\
         Connection: {}\r\n\
         Content-Type: application/octet-stream\r\n\
         Accept: */*\r\n\
         User-Agent: AirDrop/1.0\r\n\
         Accept-Language: en-us\r\n\
         Accept-Encoding: br, gzip, deflate\r\n\
         Content-Length: {}\r\n\r\n",
        if keep_alive { "keep-alive" } else { "close" },
        body.len()
    );
    debug!("-> {}", head.replace("\r\n", " | ").trim_end());
    tls.write_all(head.as_bytes())?;
    tls.write_all(body)?;
    tls.flush()
}

/// Read a response head and body. Bounded: the peer's declared length is not trusted.
fn read_response<S: Read>(tls: &mut S) -> io::Result<(u16, Vec<u8>)> {
    const MAX: usize = 256 * 1024;
    let mut head = Vec::with_capacity(512);
    let mut b = [0u8; 1];
    while head.len() < 16 * 1024 {
        if tls.read(&mut b)? == 0 {
            break;
        }
        head.push(b[0]);
        if head.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    let text = String::from_utf8_lossy(&head).into_owned();
    // Log what the peer actually said. A status of 0 means nothing parseable came back
    // at all, which is a different problem from a refusal and was being reported as one.
    debug!("response head ({} bytes): {:?}", head.len(), text.replace("\r\n", " | "));
    let status = text
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(0);
    if status == 0 {
        warn!("no parseable status line from the peer");
    }

    // Apple replies CHUNKED, not with a Content-Length. Reading only Content-Length
    // yields an empty body and a peer that looks like it said nothing -- which is
    // exactly how "did not give a name" was produced by a peer answering 200 OK with
    // its name in the body. The same mistake broke the receive side first.
    let chunked = text.lines().any(|l| {
        l.split_once(':')
            .map(|(k, v)| {
                k.trim().eq_ignore_ascii_case("transfer-encoding")
                    && v.to_ascii_lowercase().contains("chunked")
            })
            .unwrap_or(false)
    });

    let body = if chunked {
        read_chunked_body(tls, MAX)?
    } else {
        let len = text
            .lines()
            .find_map(|l| {
                let (k, v) = l.split_once(':')?;
                k.trim().eq_ignore_ascii_case("content-length").then(|| v.trim())
            })
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(0)
            .min(MAX);
        let mut buf = vec![0u8; len];
        let mut got = 0;
        while got < len {
            match tls.read(&mut buf[got..]) {
                Ok(0) | Err(_) => break,
                Ok(n) => got += n,
            }
        }
        buf.truncate(got);
        buf
    };
    debug!("response body: {} bytes", body.len());
    // WHAT AN APPLE RECEIVER ACTUALLY ADVERTISES.
    //
    // Our own /Discover answers ReceiverMediaCapabilities as {"Version":1}, which
    // declares no codec support at all -- so an iPhone sending us a video converts it
    // first, which is minutes of silent work on a large file and is why it sits on
    // "Waiting". iPhone to iPhone is immediate because no conversion is needed.
    //
    // The fix needs the real shape of that field, and the only authority on it is a
    // real Apple device answering the same request. Printed as text where it is
    // printable, since the capabilities blob is JSON inside a plist.
    if log::log_enabled!(log::Level::Debug) {
        let shown: String = body
            .iter()
            .take(1400)
            .map(|&b| if (0x20..0x7f).contains(&b) { b as char } else { '.' })
            .collect();
        debug!("response body text: {shown}");
    }
    Ok((status, body))
}

/// RFC 7230 chunked decoding for a response body, bounded.
fn read_chunked_body<S: Read>(tls: &mut S, max: usize) -> io::Result<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        let line = match read_crlf_line(tls) {
            Some(l) => l,
            None => break,
        };
        let size = match usize::from_str_radix(line.split(';').next().unwrap_or("").trim(), 16) {
            Ok(n) => n,
            Err(_) => break,
        };
        if size == 0 {
            // Trailers, then done.
            while let Some(l) = read_crlf_line(tls) {
                if l.is_empty() {
                    break;
                }
            }
            break;
        }
        if out.len() + size > max {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "response body too large"));
        }
        let mut chunk = vec![0u8; size];
        let mut got = 0;
        while got < size {
            match tls.read(&mut chunk[got..]) {
                Ok(0) | Err(_) => break,
                Ok(n) => got += n,
            }
        }
        chunk.truncate(got);
        let short = got < size;
        out.extend_from_slice(&chunk);
        if short {
            break;
        }
        let _ = read_crlf_line(tls);   // CRLF after the chunk data
    }
    Ok(out)
}

fn read_crlf_line<S: Read>(tls: &mut S) -> Option<String> {
    let mut buf = Vec::with_capacity(16);
    let mut b = [0u8; 1];
    while buf.len() < 256 {
        match tls.read(&mut b) {
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

/// Wraps writes in HTTP chunked framing.
struct ChunkedWriter<'a, S: Write> {
    inner: &'a mut S,
}

impl<S: Write> ChunkedWriter<'_, S> {
    /// The zero-length chunk that ends the body. Without it the peer waits forever.
    fn end(self) -> io::Result<()> {
        self.inner.write_all(b"0\r\n\r\n")?;
        self.inner.flush()
    }
}

impl<S: Write> Write for ChunkedWriter<'_, S> {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        if data.is_empty() {
            return Ok(0);   // a zero-length chunk would terminate the body early
        }
        self.inner.write_all(format!("{:x}\r\n", data.len()).as_bytes())?;
        self.inner.write_all(data)?;
        self.inner.write_all(b"\r\n")?;
        Ok(data.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// Counts bytes as they stream past, so progress reflects real reads rather than the
/// size a caller claimed.
struct Counting<'a, R: Read> {
    inner: &'a mut R,
    seen: u64,
    base: u64,
    total: u64,
    last: u64,
    step: u64,
    report: &'a mut dyn FnMut(u64, u64),
    /// Checked on EVERY read, which is the only place a cancel can land mid-file.
    cancelled: &'a dyn Fn() -> bool,
}

impl<R: Read> Read for Counting<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        // CANCEL IS CHECKED HERE, NOT ONLY BETWEEN FILES.
        //
        // The loop in send() checks `cancelled()` once per item, before the item starts. A
        // whole file then streams inside a single append_header_with_reader call, so for a
        // one-file send the flag was read exactly once -- at the beginning -- and never again.
        // Pressing cancel did nothing and the transfer ran to completion. Reported on
        // hardware: "multiple time trying to cancel it continue", on a 20 MB single-file send.
        //
        // This reader is already the per-chunk hook (it is how progress is reported), so it is
        // where the check belongs. Interrupted is the same error the between-files check
        // raises, so the caller's handling is unchanged.
        if (self.cancelled)() {
            return Err(io::Error::new(io::ErrorKind::Interrupted, "cancelled"));
        }
        let n = self.inner.read(buf)?;
        self.seen += n as u64;
        // Report on ~1% steps (`step`) so a large file does not spam the binder callback.
        let done = self.base + self.seen;
        if done >= self.last + self.step {
            self.last = done;
            (self.report)(done, self.total);
        }
        Ok(n)
    }
}

// --------------------------------------------------------------- the /Ask body ---

fn ask_body(items: &[Item], sender_name: &str, sender_model: &str) -> Vec<u8> {
    let files: Vec<Value> = items
        .iter()
        .map(|i| {
            Value::Dict(vec![
                ("FileName".into(), Value::Str(i.name.clone())),
                ("FileType".into(), Value::Str(uti_for(&i.name).to_string())),
                // Must match the cpio entry path exactly: the receiver looks the entry
                // up by this, so "./name" in both places or it finds nothing.
                ("FileBomPath".into(), Value::Str(format!("./{}", i.name))),
                ("FileIsDirectory".into(), Value::Bool(false)),
                ("ConvertMediaFormats".into(), Value::Bool(false)),
            ])
        })
        .collect();

    plist::encode(&Value::Dict(vec![
        ("SenderComputerName".into(), Value::Str(sender_name.to_string())),
        // A per-session identifier. The reference implementations both send one; a
        // receiver may key its accept/decline state off it.
        ("SenderID".into(), Value::Str(sender_id())),
        ("SenderModelName".into(), Value::Str(sender_model.to_string())),
        // Apple's own sender identifies as Finder. A receiver may key behaviour off
        // this, and claiming to be something it has never seen invites a refusal.
        ("BundleID".into(), Value::Str("com.apple.finder".to_string())),
        ("ConvertMediaFormats".into(), Value::Bool(false)),
        ("Files".into(), Value::Array(files)),
    ]))
}

/// A random per-session sender identifier, in the shape Apple uses.
///
/// Generated once per process rather than per transfer, so a receiver that remembers a
/// decision sees the same sender across a session.
fn sender_id() -> String {
    use std::sync::OnceLock;
    static ID: OnceLock<String> = OnceLock::new();
    ID.get_or_init(|| {
        let mut b = [0u8; 8];
        // SAFETY: getrandom(2) filling a live buffer of the stated length.
        let n = unsafe { libc::getrandom(b.as_mut_ptr() as *mut libc::c_void, b.len(), 0) };
        if n != b.len() as isize {
            return "0000000000000000".to_string();
        }
        b.iter().map(|x| format!("{x:02X}")).collect()
    })
    .clone()
}

/// Apple uniform type identifier for a filename.
///
/// The receiver groups an offer by type, and a wrong UTI can make it refuse the batch:
/// images and videos travel together, anything else only with its own kind. Unknown
/// extensions get `public.data`, which is the honest answer and is accepted alone.
fn uti_for(name: &str) -> &'static str {
    let ext = name.rsplit_once('.').map(|(_, e)| e.to_ascii_lowercase()).unwrap_or_default();
    match ext.as_str() {
        "jpg" | "jpeg" => "public.jpeg",
        "png" => "public.png",
        "gif" => "com.compuserve.gif",
        "heic" => "public.heic",
        "heif" => "public.heif",
        "webp" => "org.webmproject.webp",
        "tiff" | "tif" => "public.tiff",
        "mov" => "com.apple.quicktime-movie",
        "mp4" | "m4v" => "public.mpeg-4",
        "pdf" => "com.adobe.pdf",
        "txt" => "public.plain-text",
        "zip" => "public.zip-archive",
        "mp3" => "public.mp3",
        "m4a" => "com.apple.m4a-audio",
        _ => "public.data",
    }
}

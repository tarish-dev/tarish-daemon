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
use std::io::{Read, Write};
use std::net::{SocketAddrV6, TcpListener};
use std::time::Duration;

/// Cap on the request head we will buffer. AirDrop's requests are small; anything
/// larger is either a mistake or an attempt to make us allocate.
const MAX_HEAD: usize = 16 * 1024;

/// Cap on a request body we will buffer. Content-Length is attacker-controlled.
const MAX_BODY: usize = 64 * 1024;

/// Where received archives land. Private to this daemon, which cannot reach shared
/// storage: the app moves them to Downloads/Barq, where Quick Share puts its own.
const INBOX: &str = "/data/misc/barq/inbox";

/// A slow or silent peer must not hold a connection open indefinitely.
const IO_TIMEOUT: Duration = Duration::from_secs(15);

pub struct Httpd {
    acceptor: SslAcceptor,
    listener: TcpListener,
    discover_body: Vec<u8>,
    ask_body: Vec<u8>,
}

impl Httpd {
    /// Bind TLS on `iface`'s link-local address at `port`.
    pub fn new(iface: &str, port: u16, name: &str, model: &str) -> std::io::Result<Self> {
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

        Ok(Self { acceptor, listener, discover_body, ask_body })
    }

    /// Accept forever. Each connection is handled on its own thread and closed after
    /// one exchange, because AirDrop sets `Connection: close` on every response.
    pub fn serve(&self) {
        for stream in self.listener.incoming() {
            let stream = match stream {
                Ok(s) => s,
                Err(e) => {
                    warn!("accept failed: {e}");
                    continue;
                }
            };
            let peer = stream.peer_addr().map(|a| a.to_string()).unwrap_or_default();
            let _ = stream.set_read_timeout(Some(IO_TIMEOUT));
            let _ = stream.set_write_timeout(Some(IO_TIMEOUT));

            match self.acceptor.accept(stream) {
                Ok(mut tls) => {
                    debug!("TLS handshake ok from {peer}");
                    if let Err(e) = self.handle(&mut tls) {
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
    }

    fn handle<S: Read + Write>(&self, tls: &mut S) -> std::io::Result<()> {
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
            let b = read_body(tls, &head);
            if !b.is_empty() {
                debug!("{path} request body ({} bytes): {}", b.len(), hex(&b));
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
            ("HEAD", "/") => respond(tls, 200, None, keep_alive)?,
            ("POST", "/Discover") => respond(tls, 200, Some(&self.discover_body), keep_alive)?,

            // "May I send you this?" Accepting is what turns the sender's UI into a
            // transfer. We accept unconditionally for now: there is no client to ask,
            // and the alternative is refusing every file. A prompt belongs here once
            // the app exists, and until then this is a deliberate open door -- said
            // plainly rather than buried.
            ("POST", "/Ask") => {
                info!("accepting transfer from a peer (no prompt — no client yet)");
                respond(tls, 200, Some(&self.ask_body), keep_alive)?
            }

            ("POST", "/Upload") => {
                match self.receive_upload(tls, &head) {
                    Ok(path) => {
                        info!("/Upload stored at {path}");
                        respond(tls, 200, None, keep_alive)?
                    }
                    Err(e) => {
                        error!("/Upload failed: {e}");
                        respond(tls, 500, None, false)?
                    }
                }
            }

            _ => respond(tls, 401, None, keep_alive)?,
        }
        Ok(())
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
    fn receive_upload<S: Read>(&self, s: &mut S, head: &str) -> std::io::Result<String> {
        std::fs::create_dir_all(INBOX)?;
        // Named by arrival order, never by anything the peer supplies: a filename from
        // the wire is attacker-controlled and has no business steering a path.
        let n = std::fs::read_dir(INBOX).map(|d| d.count()).unwrap_or(0);
        let path = format!("{INBOX}/{n:05}.cpio");
        let mut f = std::fs::File::create(&path)?;

        let mut sniff = Vec::new();
        let written = if header(head, "transfer-encoding")
            .map(|v| v.to_ascii_lowercase().contains("chunked"))
            .unwrap_or(false)
        {
            stream_chunked(s, &mut f, &mut sniff)?
        } else {
            let len = header(head, "content-length")
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(0);
            stream_exact(s, &mut f, len, &mut sniff)?
        };

        // Apple may gzip the cpio and nothing in the request declares it, so sniff.
        // libarchive hides this from implementations built on it; ours has to look.
        let gzipped = sniff.len() > 2 && sniff[0] == 0x1f && sniff[1] == 0x8b;
        let magic: String = sniff.iter().take(6).map(|b| *b as char).collect();
        info!(
            "/Upload: {written} bytes, {}, leading bytes {magic:?}",
            if gzipped { "gzip" } else { "not gzip" }
        );
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
fn read_body<S: Read>(s: &mut S, head: &str) -> Vec<u8> {
    if header(head, "transfer-encoding")
        .map(|v| v.to_ascii_lowercase().contains("chunked"))
        .unwrap_or(false)
    {
        return read_chunked(s);
    }
    let len = header(head, "content-length")
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(0)
        .min(MAX_BODY);
    read_exact_bounded(s, len)
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
fn read_chunked<S: Read>(s: &mut S) -> Vec<u8> {
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
            break;
        }
        let chunk = read_exact_bounded(s, size);
        let short = chunk.len() < size;
        out.extend_from_slice(&chunk);
        if short {
            break; // peer went away mid-chunk
        }
        let _ = read_line(s); // trailing CRLF after the chunk data
    }
    out
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

/// Copy a chunked body to `out`, keeping the first bytes for format sniffing.
fn stream_chunked<S: Read, W: std::io::Write>(
    s: &mut S,
    out: &mut W,
    sniff: &mut Vec<u8>,
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
    }
    out.flush()?;
    Ok(total)
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
    let reason = if status == 200 { "OK" } else { "Unauthorized" };
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

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
use log::{debug, info, warn};
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

/// A slow or silent peer must not hold a connection open indefinitely.
const IO_TIMEOUT: Duration = Duration::from_secs(15);

pub struct Httpd {
    acceptor: SslAcceptor,
    listener: TcpListener,
    discover_body: Vec<u8>,
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

        Ok(Self { acceptor, listener, discover_body })
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

        // Log what the PEER sends, not just what we answer. The request is the only
        // place an Apple device states what it expects; everything we know about the
        // response so far is inference. Guessing at wire formats has been wrong twice
        // in this project and measuring has been right every time.
        let body = read_body(tls, &head);
        if !body.is_empty() {
            debug!("{path} request body ({} bytes): {}", body.len(), hex(&body));
        }

        match (method, path) {
            // Apple probes this before anything else; failing it is enough to be dropped.
            ("HEAD", "/") => respond(tls, 200, None),
            ("POST", "/Discover") => respond(tls, 200, Some(&self.discover_body)),
            // /Ask and /Upload are what a transfer needs. Being LISTED does not, so they
            // are deliberately not implemented yet and say so rather than half-answering.
            ("POST", "/Ask") | ("POST", "/Upload") => {
                warn!("{path} not implemented — receiving is not built yet");
                respond(tls, 401, None)
            }
            _ => respond(tls, 401, None),
        }
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

/// Read the request body, if the head declared one.
///
/// Bounded by MAX_BODY regardless of what Content-Length claims: the length is
/// attacker-controlled and allocating on it is the obvious way to be made to
/// exhaust memory.
fn read_body<S: Read>(s: &mut S, head: &str) -> Vec<u8> {
    let len = head
        .lines()
        .find_map(|l| {
            let (k, v) = l.split_once(':')?;
            k.trim().eq_ignore_ascii_case("content-length").then(|| v.trim())
        })
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(0)
        .min(MAX_BODY);
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
fn respond<S: Write>(s: &mut S, status: u16, body: Option<&[u8]>) -> std::io::Result<()> {
    let reason = if status == 200 { "OK" } else { "Unauthorized" };
    let body = body.unwrap_or(&[]);
    let mut head = format!(
        "HTTP/1.1 {status} {reason}\r\nConnection: close\r\nContent-Length: {}\r\n",
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

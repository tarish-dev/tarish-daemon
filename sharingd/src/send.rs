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

use crate::framed::FramedWriter;
use crate::plist::{self, Value};
use cpio_archive::odc::{OdcBuilder, OdcHeader};
use log::{debug, info};
use openssl::ssl::{SslConnector, SslMethod, SslStream, SslVerifyMode};
use std::io::{self, Read, Write};
use std::net::{Ipv6Addr, SocketAddrV6, TcpStream};
use std::time::Duration;

const IO_TIMEOUT: Duration = Duration::from_secs(30);

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
    let (status, _) = read_response(&mut tls)?;
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
         TotalBytes: {total}\r\n\
         Transfer-Encoding: chunked\r\n\r\n"
    );
    tls.write_all(head.as_bytes())?;

    let sent = {
        let chunker = ChunkedWriter { inner: &mut tls };
        let mut framed = FramedWriter::new(chunker);
        let mut done = 0u64;
        {
            let mut cpio = OdcBuilder::new(&mut framed);
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
                let mut counting = Counting { inner: &mut item.file, seen: 0 };
                cpio.append_header_with_reader(header, &mut counting)
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
                done += counting.seen;
                progress(done, total);
            }
            cpio.finish()
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
        }
        let chunker = framed.finish()?;
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

fn connect(target: &Target) -> io::Result<SslStream<TcpStream>> {
    // A link-local address is meaningless without its interface, so the scope id is
    // part of the address rather than an optional extra.
    let sock = SocketAddrV6::new(target.addr, target.port, 0, target.scope);
    let tcp = TcpStream::connect(sock)?;
    tcp.set_read_timeout(Some(IO_TIMEOUT))?;
    tcp.set_write_timeout(Some(IO_TIMEOUT))?;

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

    config
        .connect("barq", tcp)
        .map_err(|e| io::Error::other(format!("TLS handshake: {e}")))
}

fn request<S: Write>(tls: &mut S, path: &str, body: &[u8], keep_alive: bool) -> io::Result<()> {
    let head = format!(
        "POST {path} HTTP/1.1\r\n\
         Connection: {}\r\n\
         Content-Type: application/octet-stream\r\n\
         Content-Length: {}\r\n\r\n",
        if keep_alive { "keep-alive" } else { "close" },
        body.len()
    );
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
    let status = text
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(0);

    let len = text
        .lines()
        .find_map(|l| {
            let (k, v) = l.split_once(':')?;
            k.trim().eq_ignore_ascii_case("content-length").then(|| v.trim())
        })
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(0)
        .min(MAX);

    let mut body = vec![0u8; len];
    let mut got = 0;
    while got < len {
        match tls.read(&mut body[got..]) {
            Ok(0) | Err(_) => break,
            Ok(n) => got += n,
        }
    }
    body.truncate(got);
    Ok((status, body))
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
}

impl<R: Read> Read for Counting<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.seen += n as u64;
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
                ("ConvertedMediaFormats".into(), Value::Bool(false)),
            ])
        })
        .collect();

    plist::encode(&Value::Dict(vec![
        ("SenderComputerName".into(), Value::Str(sender_name.to_string())),
        ("SenderModelName".into(), Value::Str(sender_model.to_string())),
        // Apple's own sender identifies as Finder. A receiver may key behaviour off
        // this, and claiming to be something it has never seen invites a refusal.
        ("BundleID".into(), Value::Str("com.apple.finder".to_string())),
        ("ConvertMediaFormats".into(), Value::Bool(false)),
        ("Files".into(), Value::Array(files)),
    ]))
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

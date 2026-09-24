//! Just enough DNS wire format for mDNS.
//!
//! Deliberately hand-written and deliberately small: this parses packets from
//! any device on the link, so it is the most exposed code in Tarish. Everything
//! here is bounds-checked, allocates nothing unbounded, and never trusts a
//! length or an offset from the wire.
//!
//! Compression pointers are the classic footgun — a packet can point a name back
//! at itself and spin forever. `read_name` caps both the number of jumps and the
//! total name length.

// Record types. A and TXT are not consumed yet -- TXT carries AirDrop's flags
// and the friendlier peer name, and is the next thing this module will read --
// but they are part of the wire vocabulary and belong with the rest.
#[allow(dead_code)]
pub const TYPE_A: u16 = 1;
pub const TYPE_PTR: u16 = 12;
#[allow(dead_code)]
pub const TYPE_TXT: u16 = 16;
pub const TYPE_NSEC: u16 = 47;
pub const TYPE_AAAA: u16 = 28;
pub const TYPE_SRV: u16 = 33;

const MAX_JUMPS: usize = 16;
const MAX_NAME: usize = 255;

pub struct Reader<'a> {
    pub buf: &'a [u8],
    pub pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Reader { buf, pos: 0 }
    }

    pub fn u8(&mut self) -> Option<u8> {
        let v = *self.buf.get(self.pos)?;
        self.pos += 1;
        Some(v)
    }

    pub fn u16(&mut self) -> Option<u16> {
        let hi = self.u8()? as u16;
        let lo = self.u8()? as u16;
        Some((hi << 8) | lo)
    }

    pub fn u32(&mut self) -> Option<u32> {
        let a = self.u16()? as u32;
        let b = self.u16()? as u32;
        Some((a << 16) | b)
    }

    pub fn bytes(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(n)?;
        let s = self.buf.get(self.pos..end)?;
        self.pos = end;
        Some(s)
    }

    /// Read a (possibly compressed) domain name. Advances `pos` past the name as
    /// it appears here, following pointers only to read.
    pub fn name(&mut self) -> Option<String> {
        let mut out = String::new();
        let mut pos = self.pos;
        let mut jumps = 0usize;
        let mut advanced = false;

        loop {
            let len = *self.buf.get(pos)? as usize;

            if len & 0xC0 == 0xC0 {
                // Compression pointer: two bytes, target is the low 14 bits.
                let lo = *self.buf.get(pos + 1)? as usize;
                let target = ((len & 0x3F) << 8) | lo;
                if !advanced {
                    self.pos = pos + 2;
                    advanced = true;
                }
                jumps += 1;
                if jumps > MAX_JUMPS || target >= self.buf.len() {
                    return None; // malicious or malformed: a pointer loop
                }
                pos = target;
                continue;
            }

            if len == 0 {
                if !advanced {
                    self.pos = pos + 1;
                }
                break;
            }

            pos += 1;
            let label = self.buf.get(pos..pos + len)?;
            if out.len() + label.len() + 1 > MAX_NAME {
                return None;
            }
            if !out.is_empty() {
                out.push('.');
            }
            // Labels are not required to be UTF-8; anything that is not is a
            // packet we do not care about.
            out.push_str(std::str::from_utf8(label).ok()?);
            pos += len;
        }
        Some(out)
    }
}

pub struct Question {
    pub name: String,
    pub qtype: u16,
}

pub struct Record {
    pub name: String,
    pub rtype: u16,
    /// Seconds the peer says this record stays valid.
    ///
    /// Was parsed and thrown away. Discovery then had no idea how long a peer expected to
    /// remain listed and fell back to a fixed timeout shorter than the TTLs real peers
    /// send, so peers were dropped while still perfectly valid. See `Peer::expires_at`.
    pub ttl: u32,
    pub rdata: Vec<u8>,
    /// Offset of rdata within the original packet, needed because names inside
    /// rdata may use compression pointers relative to the whole packet.
    pub rdata_at: usize,
}

/// Everything we care about in one packet: what was asked, and what was told.
pub struct Message {
    pub questions: Vec<Question>,
    pub records: Vec<Record>,
}

/// Parse a packet. mDNS makes no hard distinction between query and response --
/// a packet can carry both -- so both halves are returned and the caller decides.
pub fn parse(buf: &[u8]) -> Option<Message> {
    let mut r = Reader::new(buf);
    let _id = r.u16()?;
    let _flags = r.u16()?;
    let qd = r.u16()?;
    let an = r.u16()?;
    let ns = r.u16()?;
    let ar = r.u16()?;

    // A question count that cannot fit is a packet we do not need to be polite to.
    if qd > 64 {
        return None;
    }
    let mut questions = Vec::with_capacity((qd as usize).min(8));
    for _ in 0..qd {
        let name = r.name()?;
        let qtype = r.u16()?;
        let _qclass = r.u16()?;
        questions.push(Question { name, qtype });
    }

    let total = (an as usize) + (ns as usize) + (ar as usize);
    // A packet claiming thousands of records in a few hundred bytes is not one
    // we need to be polite about.
    if total > 128 {
        return None;
    }

    let mut out = Vec::with_capacity(total.min(32));
    for _ in 0..total {
        let name = r.name()?;
        let rtype = r.u16()?;
        let _class = r.u16()?;
        let ttl = r.u32()?;
        let rdlen = r.u16()? as usize;
        let at = r.pos;
        let rdata = r.bytes(rdlen)?.to_vec();
        out.push(Record { name, rtype, ttl, rdata, rdata_at: at });
    }
    Some(Message { questions, records: out })
}

/// Encode a domain name. No compression: our packets are small, and emitting
/// pointers is where a responder gets subtly wrong in ways peers tolerate
/// silently until one does not.
pub fn encode_name(n: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(n.len() + 2);
    for label in n.split('.') {
        if label.is_empty() {
            continue;
        }
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    out
}

/// One resource record, ready to append.
pub fn record(name: &str, rtype: u16, ttl: u32, rdata: &[u8], flush: bool) -> Vec<u8> {
    let mut out = encode_name(name);
    out.extend_from_slice(&rtype.to_be_bytes());
    // The top bit of the class is mDNS's cache-flush bit: "this is authoritative,
    // drop anything else you have for this name".
    let class: u16 = if flush { 0x8001 } else { 0x0001 };
    out.extend_from_slice(&class.to_be_bytes());
    out.extend_from_slice(&ttl.to_be_bytes());
    out.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
    out.extend_from_slice(rdata);
    out
}

/// Wrap answers in a response header.
pub fn response(answers: &[Vec<u8>]) -> Vec<u8> {
    let mut p = Vec::with_capacity(256);
    p.extend_from_slice(&0u16.to_be_bytes());        // id: 0 for mDNS
    p.extend_from_slice(&0x8400u16.to_be_bytes());   // response, authoritative
    p.extend_from_slice(&0u16.to_be_bytes());        // qdcount
    p.extend_from_slice(&(answers.len() as u16).to_be_bytes());
    p.extend_from_slice(&0u16.to_be_bytes());        // nscount
    p.extend_from_slice(&0u16.to_be_bytes());        // arcount
    for a in answers {
        p.extend_from_slice(a);
    }
    p
}

/// NSEC rdata: "this name exists, and has exactly these record types".
///
/// Not decoration. It is the correct answer to a query for a type we do not
/// have — when a peer asks our host for an A record and we only publish AAAA,
/// silence reads as "no such host" and the peer drops us, while an NSEC says
/// "that host is mine, it has AAAA and nothing else". Mosey sends these for
/// both its instance and its host; Tarish did not, and that is a good candidate
/// for why an Apple peer resolved us and then gave up.
///
/// Format: next-domain-name, then type bitmaps in (window, length, bits) blocks.
/// Only window 0 is needed — every type we use is below 256.
pub fn nsec_rdata(next_name: &str, types: &[u16]) -> Vec<u8> {
    let mut out = encode_name(next_name);
    let max = types.iter().copied().max().unwrap_or(0);
    let len = (max / 8) as usize + 1;
    let mut bitmap = vec![0u8; len];
    for &t in types {
        // Bit order within a byte is most-significant-first.
        bitmap[(t / 8) as usize] |= 0x80 >> (t % 8);
    }
    out.push(0);              // window block 0
    out.push(len as u8);      // bitmap length
    out.extend_from_slice(&bitmap);
    out
}

/// Encode TXT rdata from key=value strings. Each entry is length-prefixed.
pub fn txt_rdata(entries: &[&str]) -> Vec<u8> {
    let mut out = Vec::new();
    if entries.is_empty() {
        out.push(0); // an empty TXT is a single zero-length string, not nothing
        return out;
    }
    for e in entries {
        let b = e.as_bytes();
        let n = b.len().min(255);
        out.push(n as u8);
        out.extend_from_slice(&b[..n]);
    }
    out
}

/// Build a PTR query for a service type, e.g. `_airdrop._tcp.local`.
///
/// `unicast` sets the QU bit (RFC 6762 §5.4), asking the responder to answer us DIRECTLY.
///
/// WHY THAT MATTERS, because the obvious choice is the wrong one. A QM (multicast-response)
/// query is more efficient — every listener learns from one answer — but a responder that has
/// recently multicast the same record will NOT repeat it. Apple's does exactly this. So we
/// queried every 4s and drew silence, and only saw a peer when it happened to announce
/// unsolicited.
///
/// That is the whole of "I need to go to receive and come back to send to see it", reported
/// on hardware for BOTH a MacBook and an iPhone: switching to receive makes US announce, the
/// peers react to a new device, and their reaction is what we finally hear. Passive browsing
/// never worked; the toggle was doing the work.
///
/// A QU question is answered directly and is not suppressed by a recent multicast, which is
/// precisely the "new participant wants an immediate answer" case §5.4 describes.
pub fn query_with(service: &str, unicast: bool) -> Vec<u8> {
    let mut p = Vec::with_capacity(64);
    p.extend_from_slice(&[0, 0]); // id: 0 for mDNS
    p.extend_from_slice(&[0, 0]); // flags: standard query
    p.extend_from_slice(&[0, 1]); // qdcount
    p.extend_from_slice(&[0, 0, 0, 0, 0, 0]); // an, ns, ar
    for label in service.split('.') {
        p.push(label.len() as u8);
        p.extend_from_slice(label.as_bytes());
    }
    p.push(0);
    p.extend_from_slice(&TYPE_PTR.to_be_bytes());
    // qclass IN, with the top bit as QU when we need an answer we cannot be denied.
    const QU: u16 = 0x8000;
    p.extend_from_slice(&(if unicast { QU | 1 } else { 1 }).to_be_bytes());
    p
}

/// A QM query — multicast response, so every listener learns. Cheaper, and correct when we
/// are merely refreshing something we already know about.
pub fn query(service: &str) -> Vec<u8> {
    query_with(service, false)
}

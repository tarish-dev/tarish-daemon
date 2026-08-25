//! Just enough Apple binary plist to answer `/Discover`.
//!
//! AirDrop bodies are `bplist00`, and no plist crate exists in the AOSP tree. Only the
//! writer is needed and only for flat dictionaries of strings and byte blobs, so this
//! is deliberately the smallest thing that produces a valid document rather than a
//! general plist library.
//!
//! Layout: the 8-byte magic, then objects, then a table of their offsets, then a
//! 32-byte trailer describing the table. Object 0 is the root.

/// A value in a plist being written.
///
/// Nesting is supported because `/Ask` needs it: its `Files` key holds an array of
/// dictionaries, one per file. An earlier version wrote flat dictionaries only, which
/// was enough for `/Discover` and not for sending.
#[derive(Clone)]
pub enum Value {
    Str(String),
    Data(Vec<u8>),
    Bool(bool),
    Array(Vec<Value>),
    Dict(Vec<(String, Value)>),
}

/// Encode a flat dictionary. Kept because most callers want exactly this.
pub fn dict(pairs: &[(&str, Value)]) -> Vec<u8> {
    encode(&Value::Dict(
        pairs.iter().map(|(k, v)| (k.to_string(), v.clone())).collect(),
    ))
}

/// Encode any value as a binary plist.
///
/// Two passes: walk the tree assigning every value an object index, then write the
/// objects, the offset table and the trailer. References are indices into that table,
/// which is why the walk has to complete before anything is written.
pub fn encode(root: &Value) -> Vec<u8> {
    let mut objects: Vec<Node> = Vec::new();
    flatten(root, &mut objects);

    let ref_size = byte_width(objects.len() as u64);
    let mut out = Vec::with_capacity(256);
    out.extend_from_slice(b"bplist00");
    let mut offsets = Vec::with_capacity(objects.len());

    for node in &objects {
        offsets.push(out.len());
        match node {
            Node::Bool(b) => out.push(if *b { 0x09 } else { 0x08 }),
            Node::Str(s) => write_string(&mut out, s),
            Node::Data(d) => {
                write_marker(&mut out, 0x40, d.len());
                out.extend_from_slice(d);
            }
            Node::Array(children) => {
                write_marker(&mut out, 0xA0, children.len());
                for c in children {
                    write_uint(&mut out, *c as u64, ref_size);
                }
            }
            Node::Dict(keys, values) => {
                write_marker(&mut out, 0xD0, keys.len());
                for k in keys {
                    write_uint(&mut out, *k as u64, ref_size);
                }
                for v in values {
                    write_uint(&mut out, *v as u64, ref_size);
                }
            }
        }
    }

    let table_start = out.len();
    let offset_size = byte_width(table_start as u64);
    for off in &offsets {
        write_uint(&mut out, *off as u64, offset_size);
    }

    out.extend_from_slice(&[0u8; 5]);
    out.push(0);                    // sort version
    out.push(offset_size);
    out.push(ref_size);
    out.extend_from_slice(&(objects.len() as u64).to_be_bytes());
    out.extend_from_slice(&0u64.to_be_bytes());        // root is object 0
    out.extend_from_slice(&(table_start as u64).to_be_bytes());
    out
}

/// An object with its children already resolved to indices.
enum Node {
    Bool(bool),
    Str(String),
    Data(Vec<u8>),
    Array(Vec<usize>),
    Dict(Vec<usize>, Vec<usize>),
}

/// Assign `v` the next object index and append its children after it.
///
/// Breadth-order rather than depth-order: the root must be object 0, and reserving a
/// slot before recursing is what keeps that true for every container.
fn flatten(v: &Value, out: &mut Vec<Node>) -> usize {
    let index = out.len();
    match v {
        Value::Bool(b) => out.push(Node::Bool(*b)),
        Value::Str(s) => out.push(Node::Str(s.clone())),
        Value::Data(d) => out.push(Node::Data(d.clone())),
        Value::Array(items) => {
            out.push(Node::Array(Vec::new()));   // reserve this slot first
            let kids: Vec<usize> = items.iter().map(|i| flatten(i, out)).collect();
            out[index] = Node::Array(kids);
        }
        Value::Dict(entries) => {
            out.push(Node::Dict(Vec::new(), Vec::new()));
            // Keys before values, matching how the reader walks them.
            let keys: Vec<usize> = entries
                .iter()
                .map(|(k, _)| flatten(&Value::Str(k.clone()), out))
                .collect();
            let values: Vec<usize> = entries.iter().map(|(_, v)| flatten(v, out)).collect();
            out[index] = Node::Dict(keys, values);
        }
    }
    index
}

/// A marker byte carries its length in the low nibble when it fits, and otherwise
/// escapes to a following integer. Getting this wrong produces a document that parses
/// as truncated rather than as invalid, which is harder to spot.
fn write_marker(out: &mut Vec<u8>, kind: u8, len: usize) {
    if len < 0x0F {
        out.push(kind | len as u8);
    } else {
        out.push(kind | 0x0F);
        write_int_object(out, len as u64);
    }
}

/// An integer used as a length: marker 0x1n where 2^n is the byte count.
fn write_int_object(out: &mut Vec<u8>, v: u64) {
    let (marker, width) = if v <= u8::MAX as u64 {
        (0x10, 1)
    } else if v <= u16::MAX as u64 {
        (0x11, 2)
    } else {
        (0x12, 4)
    };
    out.push(marker);
    write_uint(out, v, width);
}

/// ASCII where possible, UTF-16BE otherwise.
///
/// The device name reaches this, and a name with any non-ASCII character encoded as
/// ASCII would be silently mangled on the peer's screen.
fn write_string(out: &mut Vec<u8>, s: &str) {
    if s.is_ascii() {
        write_marker(out, 0x50, s.len());
        out.extend_from_slice(s.as_bytes());
    } else {
        let units: Vec<u16> = s.encode_utf16().collect();
        write_marker(out, 0x60, units.len());
        for u in units {
            out.extend_from_slice(&u.to_be_bytes());
        }
    }
}

fn write_uint(out: &mut Vec<u8>, v: u64, width: u8) {
    let b = v.to_be_bytes();
    out.extend_from_slice(&b[8 - width as usize..]);
}

/// Smallest power-of-two byte width that holds `max`. Plist sizes are 1, 2, 4 or 8.
fn byte_width(max: u64) -> u8 {
    if max <= u8::MAX as u64 {
        1
    } else if max <= u16::MAX as u64 {
        2
    } else if max <= u32::MAX as u64 {
        4
    } else {
        8
    }
}


// ---------------------------------------------------------------- reading ---
//
// Reading is a separate concern from writing and a far more dangerous one: every byte
// here came from another device on the link. Offsets, lengths and object references are
// all attacker-controlled, so each is checked against the buffer before use and object
// references are followed only once per lookup -- a plist can reference itself, and a
// naive resolver would recurse until the stack ran out.

/// A value read back out of a binary plist.
#[derive(Debug, Clone, PartialEq)]
pub enum Val {
    Str(String),
    Data(Vec<u8>),
    Int(i64),
    Bool(bool),
    Array(Vec<Val>),
    Dict(Vec<(String, Val)>),
    Other,
}

impl Val {
    /// Look a key up in a dictionary. `None` for anything that is not a dict.
    pub fn get(&self, key: &str) -> Option<&Val> {
        match self {
            Val::Dict(entries) => entries.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Val::Str(s) => Some(s),
            _ => None,
        }
    }
}

/// How deep a nested plist may go before we refuse it.
///
/// Not a real structural limit -- AirDrop's bodies are two or three deep. It exists so a
/// hostile plist cannot drive us into unbounded recursion.
const MAX_DEPTH: usize = 16;

/// How many objects a single container may hold.
const MAX_ELEMENTS: usize = 4096;

pub fn parse(buf: &[u8]) -> Option<Val> {
    if buf.len() < 40 || &buf[..8] != b"bplist00" {
        return None;
    }
    let trailer = &buf[buf.len() - 32..];
    let offset_size = trailer[6] as usize;
    let ref_size = trailer[7] as usize;
    let num_objects = be(&trailer[8..16]) as usize;
    let root = be(&trailer[16..24]) as usize;
    let table_start = be(&trailer[24..32]) as usize;

    if offset_size == 0 || offset_size > 8 || ref_size == 0 || ref_size > 8 {
        return None;
    }
    if num_objects == 0 || num_objects > MAX_ELEMENTS || root >= num_objects {
        return None;
    }
    // The offset table has to fit inside the buffer, checked before any read of it.
    let table_len = num_objects.checked_mul(offset_size)?;
    if table_start.checked_add(table_len)? > buf.len() {
        return None;
    }

    let p = Parser { buf, table_start, offset_size, ref_size, num_objects };
    p.object(root, 0)
}

struct Parser<'a> {
    buf: &'a [u8],
    table_start: usize,
    offset_size: usize,
    ref_size: usize,
    num_objects: usize,
}

impl<'a> Parser<'a> {
    fn offset_of(&self, index: usize) -> Option<usize> {
        if index >= self.num_objects {
            return None;
        }
        let at = self.table_start + index * self.offset_size;
        let raw = be(self.buf.get(at..at + self.offset_size)?) as usize;
        (raw < self.buf.len()).then_some(raw)
    }

    fn object(&self, index: usize, depth: usize) -> Option<Val> {
        if depth > MAX_DEPTH {
            return None;
        }
        let at = self.offset_of(index)?;
        let marker = *self.buf.get(at)?;
        let kind = marker >> 4;
        let low = (marker & 0x0F) as usize;

        match kind {
            0x0 => match marker {
                0x08 => Some(Val::Bool(false)),
                0x09 => Some(Val::Bool(true)),
                _ => Some(Val::Other),
            },
            0x1 => {
                // Integers are 2^low bytes wide, big-endian.
                let width = 1usize << low;
                let bytes = self.buf.get(at + 1..at + 1 + width)?;
                Some(Val::Int(be(bytes) as i64))
            }
            0x4 => {
                let (len, body) = self.sized(at, low, depth)?;
                Some(Val::Data(self.buf.get(body..body + len)?.to_vec()))
            }
            0x5 => {
                let (len, body) = self.sized(at, low, depth)?;
                let raw = self.buf.get(body..body + len)?;
                Some(Val::Str(String::from_utf8_lossy(raw).into_owned()))
            }
            0x6 => {
                // UTF-16BE: the length is in code units, not bytes.
                let (units, body) = self.sized(at, low, depth)?;
                let bytes = units.checked_mul(2)?;
                let raw = self.buf.get(body..body + bytes)?;
                let u16s: Vec<u16> = raw
                    .chunks_exact(2)
                    .map(|c| u16::from_be_bytes([c[0], c[1]]))
                    .collect();
                Some(Val::Str(String::from_utf16_lossy(&u16s)))
            }
            0xA => {
                let (count, body) = self.sized(at, low, depth)?;
                if count > MAX_ELEMENTS {
                    return None;
                }
                let mut out = Vec::with_capacity(count.min(64));
                for i in 0..count {
                    let r = self.reference(body, i)?;
                    out.push(self.object(r, depth + 1)?);
                }
                Some(Val::Array(out))
            }
            0xD => {
                let (count, body) = self.sized(at, low, depth)?;
                if count > MAX_ELEMENTS {
                    return None;
                }
                let mut out = Vec::with_capacity(count.min(64));
                for i in 0..count {
                    // Keys come first, then values, each a reference.
                    let kr = self.reference(body, i)?;
                    let vr = self.reference(body, count + i)?;
                    let key = match self.object(kr, depth + 1)? {
                        Val::Str(k) => k,
                        // A non-string key is not something AirDrop produces; skipping
                        // it is safer than inventing a name for it.
                        _ => continue,
                    };
                    out.push((key, self.object(vr, depth + 1)?));
                }
                Some(Val::Dict(out))
            }
            _ => Some(Val::Other),
        }
    }

    /// Decode a marker's length, which either fits in the low nibble or escapes to a
    /// following integer object. Returns the count and where the body starts.
    fn sized(&self, at: usize, low: usize, depth: usize) -> Option<(usize, usize)> {
        if low != 0x0F {
            return Some((low, at + 1));
        }
        let m = *self.buf.get(at + 1)?;
        if m >> 4 != 0x1 {
            return None;   // the escape must be an integer
        }
        let width = 1usize << (m & 0x0F);
        let bytes = self.buf.get(at + 2..at + 2 + width)?;
        let _ = depth;
        Some((be(bytes) as usize, at + 2 + width))
    }

    fn reference(&self, body: usize, i: usize) -> Option<usize> {
        let at = body.checked_add(i.checked_mul(self.ref_size)?)?;
        Some(be(self.buf.get(at..at + self.ref_size)?) as usize)
    }
}

/// Big-endian integer of 1..=8 bytes.
fn be(b: &[u8]) -> u64 {
    b.iter().fold(0u64, |acc, x| (acc << 8) | *x as u64)
}

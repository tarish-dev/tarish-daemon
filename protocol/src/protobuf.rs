//! Just enough protobuf wire format to speak Quick Share.
//!
//! No protobuf crate is vendored in the AOSP tree, and adding one is a chore that buys
//! little here: the messages are small, the wire format is four rules, and hand-rolling
//! keeps this crate dependency-free — which is what lets it build outside the tree at
//! all. tarishd already encodes StartMoseyConfig the same way.
//!
//! Only the two wire types Quick Share uses are constructed: varint (0) and
//! length-delimited (2). The other three are SKIPPED rather than rejected when reading,
//! because a peer is free to add fields we do not model and refusing them would turn a
//! forward-compatible protocol into a brittle one.
//!
//! Deliberately not a protobuf library: no schemas, no required-field checking, no
//! defaults. Callers know their own messages, and the type system is not doing that work
//! here — the tests are.

use std::fmt;

const WIRE_VARINT: u32 = 0;
const WIRE_I64: u32 = 1;
const WIRE_BYTES: u32 = 2;
const WIRE_I32: u32 = 5;

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    /// Ran off the end of the buffer mid-value.
    Truncated,
    /// A varint longer than 10 bytes, which cannot fit in a u64.
    VarintTooLong,
    /// Wire types 3 and 4 are the deprecated group markers; nothing in Quick Share
    /// uses them and skipping one correctly requires tracking nesting.
    UnsupportedWireType(u32),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Truncated => write!(f, "protobuf: truncated"),
            Error::VarintTooLong => write!(f, "protobuf: varint too long"),
            Error::UnsupportedWireType(w) => write!(f, "protobuf: unsupported wire type {w}"),
        }
    }
}

// ---------------------------------------------------------------- writing ---

#[derive(Default)]
pub struct Writer {
    buf: Vec<u8>,
}

impl Writer {
    pub fn new() -> Self {
        Self { buf: Vec::new() }
    }

    fn put_varint(&mut self, mut v: u64) {
        while v >= 0x80 {
            self.buf.push((v as u8 & 0x7f) | 0x80);
            v >>= 7;
        }
        self.buf.push(v as u8);
    }

    fn put_tag(&mut self, field: u32, wire: u32) {
        self.put_varint(((field as u64) << 3) | wire as u64);
    }

    /// A varint field: integers, bools and enums all encode this way.
    pub fn varint(&mut self, field: u32, v: u64) -> &mut Self {
        self.put_tag(field, WIRE_VARINT);
        self.put_varint(v);
        self
    }

    /// A length-delimited field: bytes, strings and nested messages are identical on
    /// the wire, which is why nested messages are written by serializing them first.
    pub fn bytes(&mut self, field: u32, v: &[u8]) -> &mut Self {
        self.put_tag(field, WIRE_BYTES);
        self.put_varint(v.len() as u64);
        self.buf.extend_from_slice(v);
        self
    }

    pub fn finish(self) -> Vec<u8> {
        self.buf
    }
}

// ---------------------------------------------------------------- reading ---

#[derive(Debug, PartialEq, Eq)]
pub enum Field<'a> {
    Varint(u32, u64),
    Bytes(u32, &'a [u8]),
}

pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn varint(&mut self) -> Result<u64, Error> {
        let mut out: u64 = 0;
        let mut shift = 0u32;
        loop {
            if self.pos >= self.buf.len() {
                return Err(Error::Truncated);
            }
            // 10 groups of 7 bits is the most a u64 can hold; beyond that a peer is
            // either broken or trying to make us shift past 63 and wrap.
            if shift > 63 {
                return Err(Error::VarintTooLong);
            }
            let b = self.buf[self.pos];
            self.pos += 1;
            out |= ((b & 0x7f) as u64) << shift;
            if b & 0x80 == 0 {
                return Ok(out);
            }
            shift += 7;
        }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        // Checked add: a length near u64::MAX from a hostile peer must not wrap into
        // a small end offset and hand back a slice we never validated.
        let end = self.pos.checked_add(n).ok_or(Error::Truncated)?;
        if end > self.buf.len() {
            return Err(Error::Truncated);
        }
        let s = &self.buf[self.pos..end];
        self.pos = end;
        Ok(s)
    }

    /// Next field, or None at the end. Fields with a wire type we do not model are
    /// skipped, so unknown fields from a newer peer are ignored rather than fatal.
    pub fn next_field(&mut self) -> Option<Result<Field<'a>, Error>> {
        if self.pos >= self.buf.len() {
            return None;
        }
        let tag = match self.varint() {
            Ok(t) => t,
            Err(e) => return Some(Err(e)),
        };
        let field = (tag >> 3) as u32;
        let wire = (tag & 0x7) as u32;
        match wire {
            WIRE_VARINT => Some(self.varint().map(|v| Field::Varint(field, v))),
            WIRE_BYTES => {
                let len = match self.varint() {
                    Ok(l) => l,
                    Err(e) => return Some(Err(e)),
                };
                let len = match usize::try_from(len) {
                    Ok(l) => l,
                    Err(_) => return Some(Err(Error::Truncated)),
                };
                Some(self.take(len).map(|b| Field::Bytes(field, b)))
            }
            WIRE_I64 => match self.take(8) {
                Ok(_) => self.next_field(),
                Err(e) => Some(Err(e)),
            },
            WIRE_I32 => match self.take(4) {
                Ok(_) => self.next_field(),
                Err(e) => Some(Err(e)),
            },
            other => Some(Err(Error::UnsupportedWireType(other))),
        }
    }
}

/// Collect the fields we care about, ignoring the rest.
///
/// Later occurrences win, which is what protobuf specifies for non-repeated fields and
/// is worth stating because the opposite choice is silently interoperable most of the
/// time.
pub fn first_bytes<'a>(buf: &'a [u8], field: u32) -> Result<Option<&'a [u8]>, Error> {
    let mut r = Reader::new(buf);
    let mut found = None;
    while let Some(f) = r.next_field() {
        if let Field::Bytes(n, v) = f? {
            if n == field {
                found = Some(v);
            }
        }
    }
    Ok(found)
}

pub fn first_varint(buf: &[u8], field: u32) -> Result<Option<u64>, Error> {
    let mut r = Reader::new(buf);
    let mut found = None;
    while let Some(f) = r.next_field() {
        if let Field::Varint(n, v) = f? {
            if n == field {
                found = Some(v);
            }
        }
    }
    Ok(found)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varint_round_trips_at_the_boundaries() {
        for v in [0u64, 1, 127, 128, 300, 16383, 16384, u32::MAX as u64, u64::MAX] {
            let mut w = Writer::new();
            w.varint(1, v);
            let buf = w.finish();
            assert_eq!(first_varint(&buf, 1).unwrap(), Some(v), "value {v}");
        }
    }

    #[test]
    fn bytes_round_trip_including_empty() {
        for payload in [&b""[..], &b"x"[..], &[0u8; 300][..]] {
            let mut w = Writer::new();
            w.bytes(2, payload);
            let buf = w.finish();
            assert_eq!(first_bytes(&buf, 2).unwrap(), Some(payload));
        }
    }

    /// Known encoding, checked by hand against the wire format rather than against our
    /// own writer: field 1 varint 150 is `08 96 01`.
    #[test]
    fn matches_the_documented_wire_encoding() {
        let mut w = Writer::new();
        w.varint(1, 150);
        assert_eq!(w.finish(), vec![0x08, 0x96, 0x01]);

        let mut w = Writer::new();
        w.bytes(2, b"testing");
        assert_eq!(
            w.finish(),
            vec![0x12, 0x07, b't', b'e', b's', b't', b'i', b'n', b'g']
        );
    }

    #[test]
    fn unknown_fields_are_skipped_not_fatal() {
        // field 3 fixed64, field 4 fixed32, neither of which we ever construct
        let mut buf = vec![(3 << 3) | WIRE_I64 as u8];
        buf.extend_from_slice(&[0u8; 8]);
        buf.push((4 << 3) | WIRE_I32 as u8);
        buf.extend_from_slice(&[0u8; 4]);
        let mut w = Writer::new();
        w.bytes(5, b"kept");
        buf.extend_from_slice(&w.finish());
        assert_eq!(first_bytes(&buf, 5).unwrap(), Some(&b"kept"[..]));
    }

    #[test]
    fn truncation_is_an_error_not_a_panic() {
        // length says 10, only 2 bytes follow
        let buf = vec![(1 << 3) | WIRE_BYTES as u8, 10, b'a', b'b'];
        assert_eq!(first_bytes(&buf, 1), Err(Error::Truncated));
        // varint with the continuation bit set and nothing after it
        let buf = vec![(1 << 3) | WIRE_VARINT as u8, 0x80];
        assert_eq!(first_varint(&buf, 1), Err(Error::Truncated));
    }

    /// A hostile length must not wrap the end offset and yield an unchecked slice.
    #[test]
    fn absurd_length_does_not_wrap() {
        let mut buf = vec![(1 << 3) | WIRE_BYTES as u8];
        // u64::MAX as a varint
        for _ in 0..9 {
            buf.push(0xff);
        }
        buf.push(0x01);
        assert!(first_bytes(&buf, 1).is_err());
    }

    #[test]
    fn overlong_varint_is_rejected() {
        let mut buf = vec![(1 << 3) | WIRE_VARINT as u8];
        buf.extend_from_slice(&[0xff; 12]);
        assert_eq!(first_varint(&buf, 1), Err(Error::VarintTooLong));
    }
}

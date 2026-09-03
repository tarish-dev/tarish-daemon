//! Length-prefixed framing: the layer between a byte stream and whole messages.
//!
//! Every Quick Share message on the TCP connection is preceded by a **4-byte big-endian
//! unsigned length**. That is the entire format. What makes it worth its own module is
//! that a stream does not deliver messages, it delivers bytes: a frame arrives split
//! across three reads, or three frames arrive in one, and code that assumes one read is
//! one frame works perfectly against a local test and fails against a real peer.
//!
//! So this is a decoder that is fed whatever arrives and yields frames when it has them,
//! with no notion of a socket. Sans-IO keeps the awkward part -- the boundaries -- under
//! test at every possible split, which is not something a live peer will reliably
//! reproduce for you.
//!
//! ```text
//! [len:u32 BE][payload ... len bytes][len:u32 BE][payload ...]
//! ```

use std::fmt;

/// Width of the length prefix. Fixed by the protocol.
pub const LENGTH_PREFIX: usize = 4;

/// Largest frame we will accept, 5 MiB.
///
/// A declared length at or above this is refused rather than allocated. Real payloads
/// are chunked by `PayloadTransferFrame` to a few hundred KiB, so a legitimate peer never
/// approaches it -- the cap exists only so that four attacker-controlled bytes cannot ask
/// this process to reserve an arbitrary amount of memory.
pub const MAX_FRAME: usize = 5 * 1024 * 1024;

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    /// The peer declared a frame we refuse to buffer.
    Oversize(usize),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Oversize(n) => {
                write!(f, "framing: peer declared a {n}-byte frame, limit is {MAX_FRAME}")
            }
        }
    }
}

/// Prepend the length prefix. The result goes on the wire as one write.
pub fn encode(payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(LENGTH_PREFIX + payload.len());
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

/// Accumulates bytes and hands back whole frames.
///
/// Deliberately not generic over a reader: the caller owns the socket, this owns the
/// boundaries. That split is what lets every awkward case be a unit test.
#[derive(Default)]
pub struct Decoder {
    buf: Vec<u8>,
}

impl Decoder {
    pub fn new() -> Self {
        Self { buf: Vec::new() }
    }

    /// Feed whatever just arrived. Any length is fine, including a single byte.
    pub fn push(&mut self, bytes: &[u8]) {
        self.buf.extend_from_slice(bytes);
    }

    /// The next complete frame, if there is one.
    ///
    /// `Ok(None)` means "not yet, feed me more" -- it is not an error, and treating a
    /// short read as a failure is the most common way to break a stream protocol.
    pub fn next_frame(&mut self) -> Result<Option<Vec<u8>>, Error> {
        if self.buf.len() < LENGTH_PREFIX {
            return Ok(None);
        }
        let len = u32::from_be_bytes([self.buf[0], self.buf[1], self.buf[2], self.buf[3]]) as usize;

        // Checked as soon as the PREFIX is complete, before waiting for a body that would
        // never be allowed anyway. Waiting first would let a peer pin 5 MiB of our memory
        // per connection by sending a large prefix and then nothing.
        if len >= MAX_FRAME {
            return Err(Error::Oversize(len));
        }
        if self.buf.len() < LENGTH_PREFIX + len {
            return Ok(None);
        }
        let frame = self.buf[LENGTH_PREFIX..LENGTH_PREFIX + len].to_vec();
        self.buf.drain(..LENGTH_PREFIX + len);
        Ok(Some(frame))
    }

    /// Bytes held but not yet formed into a frame. For tests and diagnostics.
    pub fn buffered(&self) -> usize {
        self.buf.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_one_frame() {
        let mut d = Decoder::new();
        d.push(&encode(b"hello"));
        assert_eq!(d.next_frame().unwrap(), Some(b"hello".to_vec()));
        assert_eq!(d.next_frame().unwrap(), None);
        assert_eq!(d.buffered(), 0);
    }

    #[test]
    fn several_frames_in_one_push() {
        let mut d = Decoder::new();
        let mut wire = encode(b"one");
        wire.extend_from_slice(&encode(b"two"));
        wire.extend_from_slice(&encode(b"three"));
        d.push(&wire);
        assert_eq!(d.next_frame().unwrap(), Some(b"one".to_vec()));
        assert_eq!(d.next_frame().unwrap(), Some(b"two".to_vec()));
        assert_eq!(d.next_frame().unwrap(), Some(b"three".to_vec()));
        assert_eq!(d.next_frame().unwrap(), None);
    }

    /// The case a real socket produces and a local test usually does not: the frame
    /// arrives one byte at a time, including its prefix split across reads.
    #[test]
    fn a_frame_split_byte_by_byte_still_arrives() {
        let payload = vec![0xABu8; 300];
        let wire = encode(&payload);
        let mut d = Decoder::new();
        for (i, b) in wire.iter().enumerate() {
            d.push(&[*b]);
            let got = d.next_frame().unwrap();
            if i + 1 == wire.len() {
                assert_eq!(got, Some(payload.clone()), "should complete on the last byte");
            } else {
                assert_eq!(got, None, "must not yield early at byte {i}");
            }
        }
    }

    /// Every possible split point of a two-frame stream.
    #[test]
    fn every_split_point_yields_the_same_frames() {
        let mut wire = encode(b"alpha");
        wire.extend_from_slice(&encode(b"beta"));
        for cut in 0..=wire.len() {
            let mut d = Decoder::new();
            d.push(&wire[..cut]);
            let mut got = Vec::new();
            while let Some(f) = d.next_frame().unwrap() {
                got.push(f);
            }
            d.push(&wire[cut..]);
            while let Some(f) = d.next_frame().unwrap() {
                got.push(f);
            }
            assert_eq!(
                got,
                vec![b"alpha".to_vec(), b"beta".to_vec()],
                "split at {cut}"
            );
        }
    }

    #[test]
    fn an_empty_frame_is_a_frame() {
        let mut d = Decoder::new();
        d.push(&encode(b""));
        assert_eq!(d.next_frame().unwrap(), Some(Vec::new()));
    }

    /// Refused as soon as the prefix is readable, without waiting for a body.
    #[test]
    fn an_oversize_declaration_is_refused_immediately() {
        let mut d = Decoder::new();
        d.push(&(MAX_FRAME as u32).to_be_bytes());
        assert_eq!(d.next_frame(), Err(Error::Oversize(MAX_FRAME)));
        assert_eq!(d.buffered(), LENGTH_PREFIX, "nothing was consumed");
    }

    #[test]
    fn the_largest_legal_frame_is_accepted() {
        let payload = vec![7u8; MAX_FRAME - 1];
        let mut d = Decoder::new();
        d.push(&encode(&payload));
        assert_eq!(d.next_frame().unwrap().map(|f| f.len()), Some(MAX_FRAME - 1));
    }

    /// u32::MAX must not wrap into a small length and hand back a slice we never had.
    #[test]
    fn a_hostile_length_does_not_wrap() {
        let mut d = Decoder::new();
        d.push(&[0xFF, 0xFF, 0xFF, 0xFF]);
        d.push(b"short");
        assert!(matches!(d.next_frame(), Err(Error::Oversize(_))));
    }

    #[test]
    fn the_prefix_is_big_endian() {
        // 1 byte of payload encodes as 00 00 00 01, not 01 00 00 00.
        assert_eq!(&encode(b"x")[..4], &[0, 0, 0, 1]);
    }
}

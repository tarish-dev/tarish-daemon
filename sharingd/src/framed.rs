//! Apple's block-framed compression wrapper around the cpio payload.
//!
//! `/Upload` arrives with `Content-Type: application/x-cpio`, and it is **not** a cpio
//! archive. It is a sequence of blocks:
//!
//! ```text
//! [4-byte big-endian header]   bit 31 set -> stored (raw), clear -> deflate
//!                              bits 0..30 -> block length in bytes
//! [block data]
//! ... repeated to end of stream ...
//! ```
//!
//! Concatenating the decoded blocks yields the cpio stream.
//!
//! **Measured, not documented.** Neither opendrop nor GoOpenDrop describes this:
//! opendrop hands the body to libarchive, which detects and unwraps it silently, and
//! GoOpenDrop only ever sniffed for gzip (`1f 8b`), which this is not. Two real
//! transfers decoded to exactly zero trailing bytes, which is what gives confidence
//! the framing is understood rather than merely plausible.
//!
//! The high bit tripped the first attempt: a header of `0x80020000` read as a length of
//! 2147614720 and looked like a corrupt stream, when it is a 131072-byte stored block.

use flate2::read::ZlibDecoder;
use std::io::{self, Read};

/// Refuse a single block larger than this. The length is attacker-controlled and this
/// runs in the process that parses input from any device on the link.
const MAX_BLOCK: usize = 8 * 1024 * 1024;

const STORED: u32 = 0x8000_0000;
const LEN_MASK: u32 = 0x7FFF_FFFF;

/// Streams the decoded bytes, decompressing one block at a time.
///
/// Streaming rather than decode-then-parse: a transfer can be any size, and holding a
/// whole archive in memory is both a memory bomb and the flaw the reference Go
/// implementation recorded against itself.
pub struct FramedReader<R: Read> {
    inner: R,
    buf: Vec<u8>,
    pos: usize,
    ended: bool,
}

impl<R: Read> FramedReader<R> {
    pub fn new(inner: R) -> Self {
        Self { inner, buf: Vec::new(), pos: 0, ended: false }
    }

    /// Decode the next block into `buf`. Returns false at end of stream.
    fn next_block(&mut self) -> io::Result<bool> {
        let mut hdr = [0u8; 4];
        match read_full(&mut self.inner, &mut hdr)? {
            0 => return Ok(false),          // clean end
            4 => {}
            _ => return Ok(false),          // truncated header: stop, do not guess
        }
        let hdr = u32::from_be_bytes(hdr);
        let stored = hdr & STORED != 0;
        let len = (hdr & LEN_MASK) as usize;
        if len == 0 {
            return Ok(false);
        }
        if len > MAX_BLOCK {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("block of {len} bytes exceeds the {MAX_BLOCK} cap"),
            ));
        }
        let mut block = vec![0u8; len];
        if read_full(&mut self.inner, &mut block)? != len {
            return Ok(false);               // peer went away mid-block
        }
        self.buf = if stored {
            block
        } else {
            let mut out = Vec::with_capacity(len * 4);
            ZlibDecoder::new(&block[..]).read_to_end(&mut out)?;
            out
        };
        self.pos = 0;
        Ok(true)
    }
}

impl<R: Read> Read for FramedReader<R> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        while self.pos >= self.buf.len() {
            if self.ended || !self.next_block()? {
                self.ended = true;
                return Ok(0);
            }
        }
        let n = (self.buf.len() - self.pos).min(out.len());
        out[..n].copy_from_slice(&self.buf[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }
}

/// Read until the buffer is full or the source ends; returns how many bytes were read.
fn read_full<R: Read>(r: &mut R, buf: &mut [u8]) -> io::Result<usize> {
    let mut got = 0;
    while got < buf.len() {
        match r.read(&mut buf[got..]) {
            Ok(0) => break,
            Ok(n) => got += n,
            Err(ref e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(got)
}

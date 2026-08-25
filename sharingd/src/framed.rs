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


// ---------------------------------------------------------------- writing ---

use flate2::write::ZlibEncoder;
use flate2::Compression;
use std::io::Write;

/// Block size we emit. Apple's own stored blocks were 131072 bytes, so this matches
/// what its receiver already handles rather than picking a size and hoping.
const BLOCK: usize = 128 * 1024;

/// Writes the block-framed container Apple expects around a cpio stream.
///
/// Each block is deflated and prefixed with a 4-byte big-endian header; the top bit
/// would mark a stored block, which we never emit -- deflate of incompressible data is
/// only marginally larger, and always compressing keeps one path instead of two.
///
/// `finish()` must be called: the last partial block is only written there, and dropping
/// the writer without it produces an archive that is short by up to one block. Drop
/// cannot do it because flushing can fail and a Drop impl has nowhere to report that.
pub struct FramedWriter<W: Write> {
    inner: W,
    buf: Vec<u8>,
}

impl<W: Write> FramedWriter<W> {
    pub fn new(inner: W) -> Self {
        Self { inner, buf: Vec::with_capacity(BLOCK) }
    }

    fn emit(&mut self) -> io::Result<()> {
        if self.buf.is_empty() {
            return Ok(());
        }
        let mut enc = ZlibEncoder::new(Vec::with_capacity(self.buf.len() / 2), Compression::default());
        enc.write_all(&self.buf)?;
        let block = enc.finish()?;
        if block.len() > 0x7FFF_FFFF {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "block too large to frame"));
        }
        self.inner.write_all(&(block.len() as u32).to_be_bytes())?;
        self.inner.write_all(&block)?;
        self.buf.clear();
        Ok(())
    }

    /// Flush the tail block and hand back the underlying writer.
    pub fn finish(mut self) -> io::Result<W> {
        self.emit()?;
        self.inner.flush()?;
        Ok(self.inner)
    }
}

impl<W: Write> Write for FramedWriter<W> {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        let mut rest = data;
        while !rest.is_empty() {
            let space = BLOCK - self.buf.len();
            let take = space.min(rest.len());
            self.buf.extend_from_slice(&rest[..take]);
            rest = &rest[take..];
            if self.buf.len() == BLOCK {
                self.emit()?;
            }
        }
        Ok(data.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        // Deliberately NOT emitting a partial block here. cpio writes small headers
        // between files and a flush per header would produce a block per entry, which
        // compresses badly and looks nothing like what Apple sends. finish() is what
        // ends the stream.
        self.inner.flush()
    }
}

//! Reassembling payloads from chunks, and refusing the ones that are trying something.
//!
//! A payload arrives as a sequence of `PayloadTransfer` frames sharing an id. BYTES
//! payloads are small and carry the sharing protocol's own frames, so they are buffered
//! here and handed back whole. FILE payloads can be gigabytes, so they are never
//! buffered -- each chunk is handed to the caller as it arrives, with its offset already
//! validated, and the caller decides where the bytes go.
//!
//! **This is the layer that reads attacker-controlled lengths and offsets**, so it is
//! where the checks belong rather than in whatever writes the file:
//!
//! - a chunk's offset must be exactly the bytes received so far. Not "within range", not
//!   "at most" -- exactly. Anything else is a peer asking us to leave a hole in a file or
//!   to write backwards over what it already sent, and neither has a legitimate use on a
//!   single ordered TCP connection.
//! - a payload may not exceed its declared `total_size`. A peer that declares 10 bytes
//!   and sends 10 GB is otherwise limited only by the disk.
//! - a BYTES payload is capped outright, because it is buffered in memory here.
//!
//! Names are NOT sanitised here, deliberately. This crate has no filesystem, so it does
//! not know what the caller will do with a name, and a path-traversal check that runs in
//! the wrong place is worse than none -- it reads as protection while the real write
//! happens somewhere else. The daemon that opens the file does that check.

use crate::frames::{PacketType, PayloadHeader, PayloadTransfer, PayloadType};
use std::collections::HashMap;
use std::fmt;

/// Largest BYTES payload we will buffer, 1 MiB.
///
/// BYTES payloads carry sharing frames -- an introduction listing files, a response, a
/// paired-key frame. The largest realistic one is an introduction for a few hundred
/// attachments, which is kilobytes. A megabyte is far above anything legitimate and far
/// below anything that matters to this process.
pub const MAX_BYTES_PAYLOAD: usize = 1024 * 1024;

/// What came out of a chunk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// A BYTES payload is complete. This is a sharing frame; parse it with
    /// `crate::sharing::parse`.
    Bytes { id: i64, data: Vec<u8> },
    /// Part of a file. Already offset-checked; write it at `offset`.
    FileChunk {
        id: i64,
        offset: i64,
        data: Vec<u8>,
        last: bool,
        header: PayloadHeader,
    },
    /// The peer cancelled this payload.
    Cancelled { id: i64 },
    /// The peer reported an error on this payload.
    Failed { id: i64 },
    /// Nothing to report yet -- a partial BYTES payload, or a frame we ignore.
    Pending,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    /// A chunk did not start where the previous one ended.
    Offset { id: i64, expected: i64, got: i64 },
    /// More bytes arrived than the payload declared.
    Overrun { id: i64, declared: i64 },
    /// A buffered BYTES payload grew past what we will hold.
    TooLarge { id: i64, limit: usize },
    /// Negative offset or size. A peer sending one is not confused, it is probing.
    Negative { id: i64 },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Offset { id, expected, got } => {
                write!(f, "payload {id}: chunk at {got}, expected {expected}")
            }
            Error::Overrun { id, declared } => {
                write!(f, "payload {id}: more data than the declared {declared} bytes")
            }
            Error::TooLarge { id, limit } => {
                write!(f, "payload {id}: buffered payload exceeds {limit} bytes")
            }
            Error::Negative { id } => write!(f, "payload {id}: negative offset or size"),
        }
    }
}

struct InFlight {
    header: PayloadHeader,
    received: i64,
    /// Only for BYTES. A FILE payload is never buffered.
    buffer: Vec<u8>,
}

/// Tracks every payload currently arriving.
///
/// Several are in flight at once during a multi-file transfer, which is why this is a
/// map keyed by id rather than a single current payload.
#[derive(Default)]
pub struct Assembler {
    in_flight: HashMap<i64, InFlight>,
}

impl Assembler {
    pub fn new() -> Self {
        Self {
            in_flight: HashMap::new(),
        }
    }

    /// Feed one `PayloadTransfer` frame.
    pub fn accept(&mut self, pt: &PayloadTransfer) -> Result<Event, Error> {
        let id = pt.header.id;

        match pt.packet_type {
            PacketType::Control => {
                // 1 = PAYLOAD_ERROR, 2 = PAYLOAD_CANCELED.
                let event = pt.control.map(|(e, _)| e).unwrap_or(0);
                self.in_flight.remove(&id);
                return Ok(match event {
                    2 => Event::Cancelled { id },
                    _ => Event::Failed { id },
                });
            }
            PacketType::Data => {}
            // ACKs and unknown packet types carry no data for us.
            _ => return Ok(Event::Pending),
        }

        let Some(chunk) = pt.chunk.as_ref() else {
            return Ok(Event::Pending);
        };

        if chunk.offset < 0 || pt.header.total_size < 0 {
            return Err(Error::Negative { id });
        }

        let entry = self.in_flight.entry(id).or_insert_with(|| InFlight {
            header: pt.header.clone(),
            received: 0,
            buffer: Vec::new(),
        });

        // EXACTLY where the last chunk ended. See the module docs: a hole or a rewrite
        // has no legitimate use on one ordered connection, and permitting either turns a
        // stream of chunks into an arbitrary-write primitive against the caller's file.
        if chunk.offset != entry.received {
            let expected = entry.received;
            self.in_flight.remove(&id);
            return Err(Error::Offset {
                id,
                expected,
                got: chunk.offset,
            });
        }

        let len = chunk.body.len() as i64;
        let total = entry.received.saturating_add(len);
        if entry.header.total_size > 0 && total > entry.header.total_size {
            let declared = entry.header.total_size;
            self.in_flight.remove(&id);
            return Err(Error::Overrun { id, declared });
        }

        let is_bytes = entry.header.payload_type == PayloadType::Bytes;
        if is_bytes && total as usize > MAX_BYTES_PAYLOAD {
            self.in_flight.remove(&id);
            return Err(Error::TooLarge {
                id,
                limit: MAX_BYTES_PAYLOAD,
            });
        }

        entry.received = total;
        let last = chunk.is_last();

        if is_bytes {
            entry.buffer.extend_from_slice(&chunk.body);
            if last {
                let done = self.in_flight.remove(&id).expect("just inserted");
                return Ok(Event::Bytes {
                    id,
                    data: done.buffer,
                });
            }
            return Ok(Event::Pending);
        }

        let header = entry.header.clone();
        if last {
            self.in_flight.remove(&id);
        }
        Ok(Event::FileChunk {
            id,
            offset: chunk.offset,
            data: chunk.body.clone(),
            last,
            header,
        })
    }

    /// Forget a payload, e.g. because the user cancelled locally.
    pub fn cancel(&mut self, id: i64) {
        self.in_flight.remove(&id);
    }

    /// Bytes received so far for a payload, for progress reporting.
    pub fn received(&self, id: i64) -> i64 {
        self.in_flight.get(&id).map(|p| p.received).unwrap_or(0)
    }

    /// How many payloads are part-way through.
    pub fn in_flight(&self) -> usize {
        self.in_flight.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frames::{PayloadChunk, FLAG_LAST_CHUNK};

    fn header(id: i64, ty: PayloadType, total: i64) -> PayloadHeader {
        PayloadHeader {
            id,
            payload_type: ty,
            total_size: total,
            ..Default::default()
        }
    }

    fn data(h: &PayloadHeader, offset: i64, body: &[u8], last: bool) -> PayloadTransfer {
        PayloadTransfer {
            packet_type: PacketType::Data,
            header: h.clone(),
            chunk: Some(PayloadChunk {
                flags: if last { FLAG_LAST_CHUNK } else { 0 },
                offset,
                body: body.to_vec(),
            }),
            control: None,
        }
    }

    #[test]
    fn a_bytes_payload_is_returned_whole() {
        let h = header(1, PayloadType::Bytes, 9);
        let mut a = Assembler::new();
        assert_eq!(a.accept(&data(&h, 0, b"abc", false)).unwrap(), Event::Pending);
        assert_eq!(a.accept(&data(&h, 3, b"def", false)).unwrap(), Event::Pending);
        assert_eq!(
            a.accept(&data(&h, 6, b"ghi", true)).unwrap(),
            Event::Bytes {
                id: 1,
                data: b"abcdefghi".to_vec()
            }
        );
        assert_eq!(a.in_flight(), 0, "completed payload was not released");
    }

    #[test]
    fn a_file_payload_is_streamed_not_buffered() {
        let h = header(2, PayloadType::File, 6);
        let mut a = Assembler::new();
        match a.accept(&data(&h, 0, b"abc", false)).unwrap() {
            Event::FileChunk { offset, data, last, .. } => {
                assert_eq!((offset, data, last), (0, b"abc".to_vec(), false));
            }
            other => panic!("wrong event: {other:?}"),
        }
        match a.accept(&data(&h, 3, b"def", true)).unwrap() {
            Event::FileChunk { offset, last, .. } => {
                assert_eq!((offset, last), (3, true));
            }
            other => panic!("wrong event: {other:?}"),
        }
        assert_eq!(a.in_flight(), 0);
    }

    /// The check this module exists for. A hole would let a peer choose where in a file
    /// its bytes land.
    #[test]
    fn a_chunk_that_skips_forward_is_refused() {
        let h = header(3, PayloadType::File, 100);
        let mut a = Assembler::new();
        a.accept(&data(&h, 0, b"abc", false)).unwrap();
        assert_eq!(
            a.accept(&data(&h, 50, b"xyz", false)),
            Err(Error::Offset {
                id: 3,
                expected: 3,
                got: 50
            })
        );
    }

    /// And backwards, which would let it rewrite bytes already delivered.
    #[test]
    fn a_chunk_that_rewinds_is_refused() {
        let h = header(4, PayloadType::File, 100);
        let mut a = Assembler::new();
        a.accept(&data(&h, 0, b"abcdef", false)).unwrap();
        assert_eq!(
            a.accept(&data(&h, 2, b"XX", false)),
            Err(Error::Offset {
                id: 4,
                expected: 6,
                got: 2
            })
        );
    }

    #[test]
    fn a_negative_offset_is_refused() {
        let h = header(5, PayloadType::File, 10);
        let mut a = Assembler::new();
        assert_eq!(
            a.accept(&data(&h, -1, b"x", false)),
            Err(Error::Negative { id: 5 })
        );
    }

    /// Declaring ten bytes and sending more must not be allowed to fill a disk.
    #[test]
    fn exceeding_the_declared_size_is_refused() {
        let h = header(6, PayloadType::File, 4);
        let mut a = Assembler::new();
        a.accept(&data(&h, 0, b"abcd", false)).unwrap();
        assert_eq!(
            a.accept(&data(&h, 4, b"more", false)),
            Err(Error::Overrun { id: 6, declared: 4 })
        );
    }

    /// A payload that declares no size is still bounded when it is buffered.
    #[test]
    fn an_undeclared_bytes_payload_is_still_capped() {
        let h = header(7, PayloadType::Bytes, 0);
        let mut a = Assembler::new();
        let chunk = vec![0u8; 64 * 1024];
        let mut offset = 0i64;
        loop {
            match a.accept(&data(&h, offset, &chunk, false)) {
                Ok(_) => offset += chunk.len() as i64,
                Err(Error::TooLarge { limit, .. }) => {
                    assert_eq!(limit, MAX_BYTES_PAYLOAD);
                    return;
                }
                Err(e) => panic!("wrong error: {e:?}"),
            }
            assert!(offset < 4 * MAX_BYTES_PAYLOAD as i64, "cap never applied");
        }
    }

    /// A FILE payload is not buffered, so the same volume must flow without complaint.
    #[test]
    fn a_large_file_payload_is_not_capped() {
        let h = header(8, PayloadType::File, 8 * 1024 * 1024);
        let mut a = Assembler::new();
        let chunk = vec![0u8; 512 * 1024];
        let mut offset = 0i64;
        for _ in 0..16 {
            a.accept(&data(&h, offset, &chunk, false)).unwrap();
            offset += chunk.len() as i64;
        }
        assert_eq!(a.received(8), 8 * 1024 * 1024);
    }

    /// Several payloads at once, which is what a multi-file share does.
    #[test]
    fn payloads_do_not_interfere() {
        let a1 = header(100, PayloadType::File, 6);
        let b1 = header(200, PayloadType::File, 6);
        let mut a = Assembler::new();
        a.accept(&data(&a1, 0, b"aaa", false)).unwrap();
        a.accept(&data(&b1, 0, b"bbb", false)).unwrap();
        assert_eq!(a.received(100), 3);
        assert_eq!(a.received(200), 3);
        a.accept(&data(&a1, 3, b"AAA", true)).unwrap();
        assert_eq!(a.in_flight(), 1, "only the finished one should be released");
        assert_eq!(a.received(200), 3);
    }

    #[test]
    fn a_control_frame_cancels_and_releases() {
        let h = header(9, PayloadType::File, 100);
        let mut a = Assembler::new();
        a.accept(&data(&h, 0, b"abc", false)).unwrap();
        let control = PayloadTransfer {
            packet_type: PacketType::Control,
            header: h.clone(),
            chunk: None,
            control: Some((2, 3)),
        };
        assert_eq!(a.accept(&control).unwrap(), Event::Cancelled { id: 9 });
        assert_eq!(a.in_flight(), 0);
    }

    #[test]
    fn a_control_error_is_reported_as_failure() {
        let h = header(10, PayloadType::File, 100);
        let mut a = Assembler::new();
        let control = PayloadTransfer {
            packet_type: PacketType::Control,
            header: h,
            chunk: None,
            control: Some((1, 0)),
        };
        assert_eq!(a.accept(&control).unwrap(), Event::Failed { id: 10 });
    }

    /// A refused chunk must drop the payload rather than leave a half-state that the
    /// next chunk could continue from.
    #[test]
    fn a_refused_payload_is_released() {
        let h = header(11, PayloadType::File, 100);
        let mut a = Assembler::new();
        a.accept(&data(&h, 0, b"abc", false)).unwrap();
        assert!(a.accept(&data(&h, 99, b"x", false)).is_err());
        assert_eq!(a.in_flight(), 0, "a refused payload stayed in flight");
    }

    #[test]
    fn an_empty_final_chunk_completes_a_payload() {
        let h = header(12, PayloadType::Bytes, 3);
        let mut a = Assembler::new();
        a.accept(&data(&h, 0, b"abc", false)).unwrap();
        assert_eq!(
            a.accept(&data(&h, 3, b"", true)).unwrap(),
            Event::Bytes {
                id: 12,
                data: b"abc".to_vec()
            }
        );
    }

    #[test]
    fn a_frame_with_no_chunk_is_ignored() {
        let pt = PayloadTransfer {
            packet_type: PacketType::Data,
            header: header(13, PayloadType::File, 10),
            chunk: None,
            control: None,
        };
        let mut a = Assembler::new();
        assert_eq!(a.accept(&pt).unwrap(), Event::Pending);
    }
}

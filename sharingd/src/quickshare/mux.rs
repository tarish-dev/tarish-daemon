//! Running the Quick Share protocol over an L2CAP channel.
//!
//! RFCOMM hands you a byte stream and the protocol can be written straight to it. L2CAP
//! does not: Nearby runs its own socket layer on top, and a peer ignores everything until
//! that layer has been set up.
//!
//! ```text
//!   us   -> [3][fc9f5e]                     request a data connection for our service
//!   peer -> [23]                            ready
//!   us   -> control INTRODUCTION{fc9f5e,V2} name the service and socket version
//!   then  -> the ordinary OfflineFrame stream, in data packets
//! ```
//!
//! Every packet is `[len:4][service_id_hash:3][payload]`. `00 00 00` is the control
//! channel -- introductions, acknowledgements, disconnections -- and the service hash is
//! the data channel. Data payloads are the normal length-prefixed `OfflineFrame` stream,
//! so `outbound::send` frames as it always does and never learns anything is wrapping it.
//!
//! **There is no multiplex layer here, and that cost a night.** Nearby has one -- a
//! virtual socket with its own CONNECTION_REQUEST, implemented in
//! `barq_protocol::multiplex` -- and a stock Pixel does not use it. Its own log says so:
//!
//! ```text
//!   onIncomingConnection(BLE) mode: LEGACY ... failed to initialize the connection
//!   java.io.IOException: In readConnectionRequestFrame, expected a CONNECTION_REQUEST
//!   v1 OfflineFrame but got a UNKNOWN_FRAME_TYPE frame instead
//! ```
//!
//! LEGACY mode means one service per channel and no multiplexing, so the first thing
//! after the introduction must be the Nearby CONNECTION_REQUEST itself. A MultiplexFrame
//! there is acknowledged by byte count and then the socket is closed, which from our side
//! looked exactly like a peer that had refused us.
//!
//! **Which peers need any of this is not a choice.** A peer advertising an L2CAP PSM
//! refuses RFCOMM; a peer advertising none accepts it. The app opens whichever socket the
//! advertisement asked for and says which it opened.

use barq_protocol::multiplex::SERVICE_ID_HASH_LEN;
use std::collections::VecDeque;
use std::io::{self, Read, Write};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use crate::quickshare::connection::{bad, write_frame, Frames};

/// The first byte a Nearby L2CAP server expects: "give me a data connection".
///
/// Length-prefixed like everything else on this channel, NOT written raw. Shipped GMS
/// frames every L2CAP packet with a four-byte big-endian length and waits for that
/// length before reading anything; a bare command byte starves the read and the server
/// drops the channel about a second later.
///
/// It carries the service-id hash. A bare `[3]` is answered `[24]` -- understood and
/// refused, because there is nothing in it for the server to bind a connection to.
const COMMAND_REQUEST_DATA_CONNECTION: u8 = 3;

/// What the server answers with when the data connection is ready.
const COMMAND_RESPONSE_DATA_CONNECTION_READY: u8 = 23;

/// A "ready" answer is a couple of bytes. Anything longer is not this protocol.
const MAX_DATA_CONNECTION_RESPONSE: usize = 64;

/// Every packet is `[len:4][service_id_hash:3][payload]`, and the hash says which channel
/// the payload belongs to. All zeroes is control; the service hash is data.
const CONTROL_PREFIX: [u8; SERVICE_ID_HASH_LEN] = [0, 0, 0];

// SocketControlFrame
const SCF_TYPE: u32 = 1;
const SCF_INTRODUCTION: u32 = 2;
const SCF_PACKET_ACKNOWLEDGEMENT: u32 = 4;
const CONTROL_TYPE_INTRODUCTION: u64 = 1;
const CONTROL_TYPE_PACKET_ACKNOWLEDGEMENT: u64 = 3;

// IntroductionFrame
const INTRO_SERVICE_ID_HASH: u32 = 1;
const INTRO_SOCKET_VERSION: u32 = 2;

// PacketAcknowledgementFrame
const ACK_SERVICE_ID_HASH: u32 = 1;
const ACK_RECEIVED_SIZE: u32 = 2;

/// Socket version 2. Version 1 is the older BLE socket and is not what this speaks.
const SOCKET_VERSION_V2: u64 = 2;

/// The most payload we put in one packet.
///
/// The channel's MTU is 65535 and a 512 KiB file chunk does not fit in it. Splitting is
/// safe because the data channel is a STREAM -- the peer concatenates payloads and parses
/// length-prefixed frames out of them -- so a frame may span packets and nothing above
/// this layer notices.
const MAX_PACKET_PAYLOAD: usize = 16 * 1024;

/// How far ahead of the peer's acknowledgements we allow ourselves to get.
///
/// **This is the whole reason the pump below exists.** Writing goes into the app's socket
/// pair, which the app drains into the radio at radio speed; without a limit we hand over
/// a megabyte in 200 ms, report the transfer complete, and close the socket while most of
/// the file is still queued. The peer then fails a transfer we called a success.
///
/// The peer tells us exactly how much it has taken, in every PACKET_ACKNOWLEDGEMENT. So
/// we count what we send, count what it confirms, and refuse to get more than this far
/// apart.
///
/// **The size of it is a throughput decision, not a safety one.** Every time we hit the
/// limit we stop until an acknowledgement comes back, and on BLE that wait is a
/// connection interval -- tens of milliseconds during which the radio has nothing to
/// send. At 64 KiB and 16 KiB packets only four packets were ever in flight, which made
/// the link stall on almost every one. This allows sixteen.
///
/// Correctness does not depend on it: `drain` still waits for the peer to confirm
/// everything before the socket may close, so a wider window means more bytes in the air,
/// not a weaker guarantee.
const MAX_BYTES_IN_FLIGHT: u64 = 256 * 1024;

/// How long to wait for the peer to catch up before giving up on it.
const ACK_TIMEOUT: Duration = Duration::from_secs(30);

/// Shared between the pump thread and the two halves.
struct Shared {
    state: Mutex<State>,
    changed: Condvar,
}

struct State {
    /// Bytes of data payload the peer has confirmed receiving.
    acked: u64,
    /// Inbound stream bytes, already stripped of their packet framing.
    inbox: VecDeque<u8>,
    /// The pump has stopped: peer disconnected, socket closed, or a read failed.
    closed: bool,
}

impl Shared {
    fn close(&self) {
        if let Ok(mut st) = self.state.lock() {
            st.closed = true;
        }
        self.changed.notify_all();
    }
}

/// Reads the peer's data packets and presents their contents as a plain byte stream.
pub struct MuxReader {
    shared: Arc<Shared>,
}

/// Wraps everything written to it in data packets, and paces itself against the peer.
pub struct MuxWriter<W: Write> {
    inner: W,
    shared: Arc<Shared>,
    /// Bytes of data payload handed to the socket so far.
    sent: u64,
}

/// Tell the peer how much of its data we took.
fn packet_acknowledgement(received: usize) -> Vec<u8> {
    let hash = barq_protocol::service::service_id_hash();

    let mut ack = barq_protocol::protobuf::Writer::new();
    ack.bytes(ACK_SERVICE_ID_HASH, &hash)
        .varint(ACK_RECEIVED_SIZE, received as u64);

    let mut frame = barq_protocol::protobuf::Writer::new();
    frame
        .varint(SCF_TYPE, CONTROL_TYPE_PACKET_ACKNOWLEDGEMENT)
        .bytes(SCF_PACKET_ACKNOWLEDGEMENT, &ack.finish());

    let mut out = CONTROL_PREFIX.to_vec();
    out.extend_from_slice(&frame.finish());
    out
}

/// Announce which service this socket is for, and which socket version we speak.
///
/// Sent on the control channel between the data connection and the first data packet.
/// Without it the data connection opens, the peer answers 23, and then it ignores every
/// packet that follows and closes the channel about twenty seconds later.
fn introduction_packet() -> Vec<u8> {
    let hash = barq_protocol::service::service_id_hash();

    let mut intro = barq_protocol::protobuf::Writer::new();
    intro
        .bytes(INTRO_SERVICE_ID_HASH, &hash)
        .varint(INTRO_SOCKET_VERSION, SOCKET_VERSION_V2);

    let mut frame = barq_protocol::protobuf::Writer::new();
    frame
        .varint(SCF_TYPE, CONTROL_TYPE_INTRODUCTION)
        .bytes(SCF_INTRODUCTION, &intro.finish());

    let mut out = CONTROL_PREFIX.to_vec();
    out.extend_from_slice(&frame.finish());
    out
}

/// Wrap payload bytes as a data packet for this service.
fn data_packet(payload: &[u8]) -> Vec<u8> {
    let mut out = barq_protocol::service::service_id_hash().to_vec();
    // `payload` is already part of a length-prefixed OfflineFrame stream. Framing it
    // again would put two lengths in front of one frame.
    out.extend_from_slice(payload);
    out
}

/// Open the socket, then hand back the two halves.
///
/// ```text
///   us   -> [3][fc9f5e]                     request a data connection for our service
///   peer -> [23]                            ready
///   us   -> control INTRODUCTION{fc9f5e,V2} name the service and socket version
///   then  -> the ordinary OfflineFrame stream, in data packets
/// ```
pub fn open<R, W, A>(read: R, mut write: W, ack: A) -> io::Result<(MuxReader, MuxWriter<W>)>
where
    R: Read + Send + 'static,
    W: Write,
    A: Write + Send + 'static,
{
    let mut frames = Frames::new(read);

    // 1. the data connection, naming the service.
    let mut request = Vec::with_capacity(1 + SERVICE_ID_HASH_LEN);
    request.push(COMMAND_REQUEST_DATA_CONNECTION);
    request.extend_from_slice(&barq_protocol::service::service_id_hash());
    write_frame(&mut write, &request)?;

    let ready = frames.next()?;
    if ready.len() > MAX_DATA_CONNECTION_RESPONSE {
        return Err(bad(format!(
            "L2CAP data-connection response was {} bytes; not this protocol",
            ready.len()
        )));
    }
    match ready.first() {
        Some(&COMMAND_RESPONSE_DATA_CONNECTION_READY) => {
            log::debug!("quickshare: L2CAP data connection ready");
        }
        other => return Err(bad(format!("L2CAP data connection refused: {other:?}"))),
    }

    // 2. introduce the socket. Control channel, and it must come before any data.
    write_frame(&mut write, &introduction_packet())?;

    // 3. the pump. Everything the peer says from here is read on its own thread, so
    // acknowledgements keep arriving while we are busy sending -- which is what makes
    // the pacing in `write` possible at all.
    let shared = Arc::new(Shared {
        state: Mutex::new(State {
            acked: 0,
            inbox: VecDeque::new(),
            closed: false,
        }),
        changed: Condvar::new(),
    });
    let pump_shared = Arc::clone(&shared);
    std::thread::Builder::new()
        .name("barq-qs-l2cap".into())
        .spawn(move || pump(frames, ack, pump_shared))?;

    Ok((
        MuxReader {
            shared: Arc::clone(&shared),
        },
        MuxWriter {
            inner: write,
            shared,
            sent: 0,
        },
    ))
}

/// Read packets forever: acknowledge data, record the peer's counts, queue the stream.
fn pump<R: Read, A: Write>(mut frames: Frames<R>, mut ack: A, shared: Arc<Shared>) {
    loop {
        let packet = match frames.next() {
            Ok(p) => p,
            Err(e) => {
                log::debug!("quickshare: L2CAP pump ended: {e}");
                break;
            }
        };
        if packet.len() < SERVICE_ID_HASH_LEN {
            continue;
        }
        let (prefix, payload) = packet.split_at(SERVICE_ID_HASH_LEN);

        if prefix == CONTROL_PREFIX {
            let kind = barq_protocol::protobuf::first_varint(payload, SCF_TYPE)
                .ok()
                .flatten();
            if kind == Some(CONTROL_TYPE_PACKET_ACKNOWLEDGEMENT) {
                // How much of what WE sent the peer has taken. The pacing in `write`
                // waits on this and nothing else.
                if let Ok(Some(a)) =
                    barq_protocol::protobuf::first_bytes(payload, SCF_PACKET_ACKNOWLEDGEMENT)
                {
                    if let Ok(Some(size)) =
                        barq_protocol::protobuf::first_varint(a, ACK_RECEIVED_SIZE)
                    {
                        if let Ok(mut st) = shared.state.lock() {
                            // AN INCREMENT, not a total. Each acknowledgement reports the
                            // size of the packet it is answering, so they are summed.
                            //
                            // Read as a running total this sticks at a couple of hundred
                            // bytes -- the size of one handshake frame -- the send window
                            // closes after the first few kilobytes and never reopens, and
                            // the transfer hangs immediately after the peer accepts. The
                            // evidence was already in the log: our 174-byte
                            // ConnectionRequest was acknowledged 174, and the 143-byte
                            // ClientInit after it was acknowledged 143, not 317.
                            st.acked = st.acked.saturating_add(size);
                        }
                        shared.changed.notify_all();
                    }
                }
            } else {
                log::debug!("quickshare: L2CAP control packet type={kind:?}");
                // A disconnection notice, which ends the stream.
                if kind == Some(2) {
                    break;
                }
            }
            continue;
        }
        if prefix != barq_protocol::service::service_id_hash() {
            log::debug!("quickshare: L2CAP packet for another service, ignored");
            continue;
        }

        // Acknowledge before queueing. The peer counts bytes and stops sending when its
        // own count runs too far ahead of ours.
        let _ = write_frame(&mut ack, &packet_acknowledgement(payload.len()));

        if let Ok(mut st) = shared.state.lock() {
            st.inbox.extend(payload);
        }
        shared.changed.notify_all();
    }
    shared.close();
}

impl Read for MuxReader {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let mut st = self
            .shared
            .state
            .lock()
            .map_err(|_| bad("L2CAP state poisoned"))?;
        loop {
            if !st.inbox.is_empty() {
                let n = out.len().min(st.inbox.len());
                for slot in out.iter_mut().take(n) {
                    *slot = st.inbox.pop_front().unwrap_or(0);
                }
                return Ok(n);
            }
            if st.closed {
                return Ok(0);
            }
            st = self
                .shared
                .changed
                .wait(st)
                .map_err(|_| bad("L2CAP state poisoned"))?;
        }
    }
}

impl<W: Write> Write for MuxWriter<W> {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        // Split to fit the channel, and pace against the peer between pieces.
        for piece in data.chunks(MAX_PACKET_PAYLOAD) {
            self.wait_for_room()?;
            write_frame(&mut self.inner, &data_packet(piece))?;
            self.sent += piece.len() as u64;
        }
        Ok(data.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

impl<W: Write> MuxWriter<W> {
    /// Block until the peer is within `MAX_BYTES_IN_FLIGHT` of us.
    fn wait_for_room(&mut self) -> io::Result<()> {
        let mut st = self
            .shared
            .state
            .lock()
            .map_err(|_| bad("L2CAP state poisoned"))?;
        while !st.closed && self.sent.saturating_sub(st.acked) > MAX_BYTES_IN_FLIGHT {
            let (guard, timeout) = self
                .shared
                .changed
                .wait_timeout(st, ACK_TIMEOUT)
                .map_err(|_| bad("L2CAP state poisoned"))?;
            st = guard;
            if timeout.timed_out() {
                return Err(bad(format!(
                    "the peer stopped acknowledging: sent {}, confirmed {}",
                    self.sent, st.acked
                )));
            }
        }
        Ok(())
    }

    /// Wait for the peer to confirm everything we sent.
    ///
    /// Called on the way out, because "the transfer finished" has to mean the bytes
    /// arrived and not that we finished writing them into a buffer.
    pub fn drain(&mut self) -> io::Result<()> {
        let mut st = self
            .shared
            .state
            .lock()
            .map_err(|_| bad("L2CAP state poisoned"))?;
        while !st.closed && st.acked < self.sent {
            let (guard, timeout) = self
                .shared
                .changed
                .wait_timeout(st, ACK_TIMEOUT)
                .map_err(|_| bad("L2CAP state poisoned"))?;
            st = guard;
            if timeout.timed_out() {
                return Err(bad(format!(
                    "the peer confirmed only {} of {} bytes",
                    st.acked, self.sent
                )));
            }
        }
        Ok(())
    }
}

impl<W: Write> Drop for MuxWriter<W> {
    fn drop(&mut self) {
        // The last chance to notice that the peer never got what we "sent". Dropping
        // happens before the socket is closed, which is exactly when this matters.
        if let Err(e) = self.drain() {
            log::warn!("quickshare: {e}");
        }
    }
}

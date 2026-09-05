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

use crate::quickshare::connection::{bad, write_frame, Frames};

/// Reads the peer's data frames and presents their contents as a plain byte stream.
pub struct MuxReader<R: Read, A: Write> {
    inner: Frames<R>,
    /// A second handle on the same socket, used only to acknowledge packets. The reader
    /// has to be able to write: acknowledgement is a property of receiving, not of
    /// sending, and the two run on the same thread here.
    ack: A,
    /// Payload bytes already received and not yet handed to the caller. A data frame is
    /// not the same size as the read the caller asks for, in either direction.
    buf: VecDeque<u8>,
    /// Set when the peer sends DISCONNECTION, so the next read reports EOF instead of
    /// blocking forever on a socket that will never speak again.
    done: bool,
}

/// Wraps everything written to it in a data frame.
pub struct MuxWriter<W: Write> {
    inner: W,
}

/// The first byte a Nearby L2CAP server expects: "give me a data connection".
///
/// Length-prefixed like everything else on this channel, NOT written raw. Shipped GMS
/// frames every L2CAP packet with a four-byte big-endian length and waits for that
/// length before reading anything; a bare command byte starves the read and the server
/// drops the channel about a second later. Mainline google/nearby writes it raw, which
/// is presumably where the raw version comes from.
const COMMAND_REQUEST_DATA_CONNECTION: u8 = 3;

/// What the server answers with when the data connection is ready.
const COMMAND_RESPONSE_DATA_CONNECTION_READY: u8 = 23;

/// A "ready" answer is a couple of bytes. Anything longer is not this protocol.
const MAX_DATA_CONNECTION_RESPONSE: usize = 64;

/// Every packet on this channel is `[len:4][service_id_hash:3][payload]`, and the hash
/// says which channel the payload belongs to. All zeroes is the control channel; the
/// Quick Share service hash is the data channel. A packet with neither is for a service
/// we did not ask for.
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

/// Socket version 2. Version 1 is the older BLE socket and is not what this speaks.
const SOCKET_VERSION_V2: u64 = 2;

// PacketAcknowledgementFrame
const ACK_SERVICE_ID_HASH: u32 = 1;
const ACK_RECEIVED_SIZE: u32 = 2;

/// Tell the peer how much of its data we took.
///
/// The peer counts what it has sent against what we say we received, and stops sending
/// when the two drift too far apart -- so a receiver that never acknowledges looks like
/// one that has stopped reading.
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
/// **Sent on the control channel, between the data connection and the first multiplex
/// frame.** Without it the data connection opens, the peer answers 23, and then it
/// ignores every multiplex frame that follows and closes the channel around twenty
/// seconds later -- no error, no refusal, just a socket that was never introduced.
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

/// Wrap multiplex bytes as a data packet for this service.
fn data_packet(payload: &[u8]) -> Vec<u8> {
    let mut out = barq_protocol::service::service_id_hash().to_vec();
    // `payload` is ALREADY a complete length-prefixed OfflineFrame -- the caller framed
    // it. Framing it again would put two lengths in front of one frame, which is the
    // shape a multiplex peer wants and this one does not.
    out.extend_from_slice(payload);
    out
}

/// Open the virtual socket, then hand back the two halves.
///
/// TWO handshakes, in this order, and the first is easy to miss entirely:
///
/// ```text
///   us   -> [3]                              request a data connection
///   peer -> [23 ...]                         ready
///   us   -> MultiplexFrame CONNECTION_REQUEST
///   peer -> MultiplexFrame CONNECTION_RESPONSE { CONNECTION_ACCEPTED }
/// ```
///
/// Skipping the first one and going straight to the multiplex request gets the channel
/// closed from the far side inside a tenth of a second, with nothing sent back --
/// measured against a Pixel, which hung up 76 ms after we connected.
///
/// Blocks until the peer accepts. A refusal is `NOT_LISTENING`, which is a real answer --
/// the peer is reachable and not sharing -- and is reported as such rather than as a
/// broken connection.
pub fn open<R: Read, W: Write, A: Write>(
    read: R,
    mut write: W,
    ack: A,
) -> io::Result<(MuxReader<R, A>, MuxWriter<W>)> {
    let mut frames = Frames::new(read);

    // 1. the data connection.
    //
    // A bare [3] gets answered with [24] by a stock Pixel -- an answer, not a hang-up,
    // so the server is speaking this protocol and saying no. 23 is "ready"; 24 is one
    // past it and is not in any reference we have. The request numbering (1, 2, 3) and
    // the response numbering (…, 23, 24) suggest a data connection cannot be asked for
    // cold, and that 1 fetches something first.
    //
    // So: ask 1 first and RECORD WHAT COMES BACK, then ask 3 regardless. This costs one
    // extra packet and turns a dead end into a decodable answer. Every byte is logged
    // because the shape of the reply is the whole point of sending it.
    // NAME THE SERVICE. A bare [3] is answered [24] -- a refusal, not a hang-up, so the
    // command itself is understood and its content is not accepted. There is nothing in
    // a bare command for the server to bind a data connection to, and the same three
    // bytes prefix every data packet on this channel, so they are what it is missing.
    //
    // Asking [1] first was tried and is wrong: the server closes the channel on it
    // without a word, where [3] at least answers. So there is no fetch-then-connect
    // sequence to follow, and the request is simply incomplete.
    let mut request = Vec::with_capacity(1 + SERVICE_ID_HASH_LEN);
    request.push(COMMAND_REQUEST_DATA_CONNECTION);
    request.extend_from_slice(&barq_protocol::service::service_id_hash());
    write_frame(&mut write, &request)?;
    let ready = frames.next()?;
    log::info!(
        "quickshare: L2CAP [3] -> {} byte(s): {}",
        ready.len(),
        hex(&ready)
    );
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
        other => {
            return Err(bad(format!("L2CAP data connection refused: {other:?}")));
        }
    }

    // 2. introduce the socket. Control channel, and it must come before any data.
    write_frame(&mut write, &introduction_packet())?;

    // No multiplex handshake follows. The next thing on this channel is the caller's
    // own ConnectionRequest, which is what the peer is waiting to read.
    Ok((
        MuxReader {
            inner: frames,
            ack,
            buf: VecDeque::new(),
            done: false,
        },
        MuxWriter { inner: write },
    ))
}

impl<R: Read, A: Write> Read for MuxReader<R, A> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        while self.buf.is_empty() {
            if self.done {
                return Ok(0);
            }
            match read_data_packet(&mut self.inner, &mut self.ack)? {
                // The payload IS the stream: length-prefixed OfflineFrames, which the
                // layer above parses. Nothing here looks inside.
                Some(payload) => self.buf.extend(payload),
                None => continue,
            }
        }
        let n = out.len().min(self.buf.len());
        for slot in out.iter_mut().take(n) {
            *slot = self.buf.pop_front().unwrap_or(0);
        }
        Ok(n)
    }
}

impl<W: Write> Write for MuxWriter<W> {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        // ONE CALL, ONE DATA FRAME, and the whole buffer every time.
        //
        // The caller writes one complete length-prefixed frame per `write_all`, so
        // consuming everything here keeps those boundaries. Returning a short count
        // would make `write_all` call again with the remainder and split one protocol
        // frame across two data frames -- legal for a byte stream, and a peer that
        // reassembles them still gets the same bytes, but there is no reason to.
        write_frame(&mut self.inner, &data_packet(data))?;
        Ok(data.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

impl<W: Write> MuxWriter<W> {
    /// Nothing to close at this layer: the physical channel going away is the close.
    pub fn close(&mut self) {}
}

/// Bytes as hex, for the diagnostics above. Short reads only -- these are control
/// packets, not payloads.
fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Read one packet, strip its channel prefix, and hand back the multiplex frame inside.
///
/// `Ok(None)` means the packet was not one for us -- a control packet, or one addressed
/// to a service we did not ask for. Neither is an error and neither ends the connection;
/// the caller reads again.
fn read_data_packet<R: Read, A: Write>(
    frames: &mut Frames<R>,
    ack: &mut A,
) -> io::Result<Option<Vec<u8>>> {
    let packet = frames.next()?;
    if packet.len() < SERVICE_ID_HASH_LEN {
        return Ok(None);
    }
    let (prefix, payload) = packet.split_at(SERVICE_ID_HASH_LEN);

    if prefix == CONTROL_PREFIX {
        // Acknowledgements, the peer's own introduction, and its disconnection notice.
        // Logged in full: this is the channel the peer explains itself on, and a
        // disconnection here is the difference between "it refused us" and "it never
        // understood us".
        let kind = barq_protocol::protobuf::first_varint(payload, SCF_TYPE)
            .ok()
            .flatten();
        log::info!(
            "quickshare: L2CAP control packet type={:?} {} byte(s): {}",
            kind,
            payload.len(),
            hex(payload)
        );
        return Ok(None);
    }
    if prefix != barq_protocol::service::service_id_hash() {
        log::debug!("quickshare: L2CAP packet for another service, ignored");
        return Ok(None);
    }

    // Acknowledge what arrived BEFORE handing it on. The peer counts bytes, not frames,
    // and it stops sending when its own count runs too far ahead of ours.
    let _ = write_frame(ack, &packet_acknowledgement(payload.len()));

    Ok(Some(payload.to_vec()))
}

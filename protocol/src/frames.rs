//! Offline frames — the Nearby Connections message layer.
//!
//! Everything on a Quick Share connection after the UKEY2 handshake is an `OfflineFrame`:
//! the connection request and its response, keep-alives, disconnection, and the payload
//! chunks that carry the actual files. The Nearby *Sharing* protocol (introductions,
//! paired-key verification, accept/reject) rides INSIDE payloads, so it is a layer above
//! this one and is not modelled here.
//!
//! ```text
//! OfflineFrame { version: V1, v1: V1Frame { type, <one of the frame bodies> } }
//! ```
//!
//! Two decisions worth stating, because both are the kind that look wrong later:
//!
//! **Unknown frame types parse to `Frame::Unknown` rather than failing.** A peer is free
//! to send frame types this build does not model -- there are thirteen in the schema and
//! we act on six -- and refusing the connection because one arrived would turn a
//! forward-compatible protocol into a brittle one. The caller ignores what it does not
//! handle.
//!
//! **Field presence is not enforced on parse.** proto2 marks everything `optional`, so a
//! missing field is a legal encoding rather than corruption. Meaning is decided by the
//! layer that acts on it, which is the only layer that knows whether the field mattered.

use crate::protobuf::{self, Field, Reader, Writer};
use std::fmt;

// OfflineFrame
const OF_VERSION: u32 = 1;
const OF_V1: u32 = 2;
const VERSION_V1: u64 = 1;

// V1Frame
const V1_TYPE: u32 = 1;
const V1_CONNECTION_REQUEST: u32 = 2;
const V1_CONNECTION_RESPONSE: u32 = 3;
const V1_PAYLOAD_TRANSFER: u32 = 4;
const V1_KEEP_ALIVE: u32 = 6;
const V1_DISCONNECTION: u32 = 7;

// V1Frame.FrameType
const T_CONNECTION_REQUEST: u64 = 1;
const T_CONNECTION_RESPONSE: u64 = 2;
const T_PAYLOAD_TRANSFER: u64 = 3;
const T_BANDWIDTH_UPGRADE: u64 = 4;
const T_KEEP_ALIVE: u64 = 5;
const T_DISCONNECTION: u64 = 6;

// ConnectionRequestFrame
const CR_ENDPOINT_ID: u32 = 1;
const CR_ENDPOINT_NAME: u32 = 2;
const CR_HANDSHAKE_DATA: u32 = 3;
const CR_NONCE: u32 = 4;
const CR_MEDIUMS: u32 = 5;
const CR_ENDPOINT_INFO: u32 = 6;
const CR_KEEPALIVE_INTERVAL: u32 = 8;
const CR_KEEPALIVE_TIMEOUT: u32 = 9;

// ConnectionResponseFrame
const RSP_STATUS: u32 = 1;
const RSP_HANDSHAKE_DATA: u32 = 2;
const RSP_RESPONSE: u32 = 3;
const RSP_OS_INFO: u32 = 4;

// OsInfo
const OS_TYPE: u32 = 1;

// PayloadTransferFrame
const PT_PACKET_TYPE: u32 = 1;
const PT_PAYLOAD_HEADER: u32 = 2;
const PT_PAYLOAD_CHUNK: u32 = 3;
const PT_CONTROL_MESSAGE: u32 = 4;

// PayloadTransferFrame.PayloadHeader
const PH_ID: u32 = 1;
const PH_TYPE: u32 = 2;
const PH_TOTAL_SIZE: u32 = 3;
const PH_IS_SENSITIVE: u32 = 4;
const PH_FILE_NAME: u32 = 5;
const PH_PARENT_FOLDER: u32 = 6;

// PayloadTransferFrame.PayloadChunk
const PC_FLAGS: u32 = 1;
const PC_OFFSET: u32 = 2;
const PC_BODY: u32 = 3;

// PayloadTransferFrame.ControlMessage
const CM_EVENT: u32 = 1;
const CM_OFFSET: u32 = 2;

// KeepAliveFrame
const KA_ACK: u32 = 1;
const KA_SEQ_NUM: u32 = 2;

/// Which medium a connection is being requested over. AWDL is 13, which is how Apple
/// hardware appears; Quick Share over a LAN is WIFI_LAN.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub enum Medium {
    Bluetooth = 2,
    WifiHotspot = 3,
    Ble = 4,
    WifiLan = 5,
    WifiAware = 6,
    WifiDirect = 8,
    Awdl = 13,
}

/// What the peer said about our connection request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Response {
    Unknown = 0,
    Accept = 1,
    Reject = 2,
}

impl Response {
    fn from(v: u64) -> Self {
        match v {
            1 => Response::Accept,
            2 => Response::Reject,
            _ => Response::Unknown,
        }
    }
}

/// The OS a peer claims to be. Advisory: it changes nothing we do, but it is the only
/// signal about what is on the other end and it belongs in a log when a transfer fails.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OsType {
    Unknown = 0,
    Android = 1,
    ChromeOs = 2,
    Windows = 3,
    Apple = 4,
    Linux = 100,
}

impl OsType {
    fn from(v: u64) -> Self {
        match v {
            1 => OsType::Android,
            2 => OsType::ChromeOs,
            3 => OsType::Windows,
            4 => OsType::Apple,
            100 => OsType::Linux,
            _ => OsType::Unknown,
        }
    }
}

/// Payload kinds. BYTES carries the sharing protocol's own frames; FILE carries a file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayloadType {
    Unknown = 0,
    Bytes = 1,
    File = 2,
    Stream = 3,
}

impl PayloadType {
    fn from(v: u64) -> Self {
        match v {
            1 => PayloadType::Bytes,
            2 => PayloadType::File,
            3 => PayloadType::Stream,
            _ => PayloadType::Unknown,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketType {
    Unknown = 0,
    Data = 1,
    Control = 2,
    PayloadAck = 3,
}

impl PacketType {
    fn from(v: u64) -> Self {
        match v {
            1 => PacketType::Data,
            2 => PacketType::Control,
            3 => PacketType::PayloadAck,
            _ => PacketType::Unknown,
        }
    }
}

/// Set on the final chunk of a payload. The receiver has no other way to know a transfer
/// finished, because total_size may be absent on a stream.
pub const FLAG_LAST_CHUNK: u64 = 0x1;

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ConnectionRequest {
    pub endpoint_id: String,
    pub endpoint_name: String,
    pub endpoint_info: Vec<u8>,
    pub handshake_data: Vec<u8>,
    pub nonce: i64,
    pub mediums: Vec<u64>,
    pub keep_alive_interval_millis: Option<u64>,
    pub keep_alive_timeout_millis: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionResponse {
    pub response: Response,
    pub os_type: OsType,
    pub handshake_data: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PayloadHeader {
    pub id: i64,
    pub payload_type: PayloadType,
    pub total_size: i64,
    pub is_sensitive: bool,
    pub file_name: String,
    pub parent_folder: String,
}

impl Default for PayloadType {
    fn default() -> Self {
        PayloadType::Unknown
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PayloadChunk {
    pub flags: u64,
    pub offset: i64,
    pub body: Vec<u8>,
}

impl PayloadChunk {
    pub fn is_last(&self) -> bool {
        self.flags & FLAG_LAST_CHUNK != 0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PayloadTransfer {
    pub packet_type: PacketType,
    pub header: PayloadHeader,
    pub chunk: Option<PayloadChunk>,
    /// (event, offset) from a ControlMessage: 1 = error, 2 = cancelled.
    pub control: Option<(u64, i64)>,
}

/// One decoded frame. `Unknown` carries the type number so a log can name what was
/// ignored rather than saying nothing happened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Frame {
    ConnectionRequest(ConnectionRequest),
    ConnectionResponse(ConnectionResponse),
    PayloadTransfer(PayloadTransfer),
    KeepAlive { ack: bool, seq_num: u64 },
    Disconnection,
    BandwidthUpgrade(Vec<u8>),
    Unknown(u64),
}

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    Protobuf(protobuf::Error),
    Malformed(&'static str),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Protobuf(e) => write!(f, "frames: {e}"),
            Error::Malformed(w) => write!(f, "frames: malformed ({w})"),
        }
    }
}

impl From<protobuf::Error> for Error {
    fn from(e: protobuf::Error) -> Self {
        Error::Protobuf(e)
    }
}

// ------------------------------------------------------------------ encoding ---

fn offline(frame_type: u64, field: u32, body: &[u8]) -> Vec<u8> {
    let mut v1 = Writer::new();
    v1.varint(V1_TYPE, frame_type).bytes(field, body);
    let v1 = v1.finish();

    let mut of = Writer::new();
    of.varint(OF_VERSION, VERSION_V1).bytes(OF_V1, &v1);
    of.finish()
}

/// Build a ConnectionRequest.
///
/// `endpoint_info` is the advertisement blob the peer already saw over mDNS or BLE; it
/// carries the display name. Sending it again here is not redundant -- a peer that
/// connected from a BLE advertisement has only a truncated form of it.
pub fn connection_request(req: &ConnectionRequest) -> Vec<u8> {
    let mut w = Writer::new();
    w.bytes(CR_ENDPOINT_ID, req.endpoint_id.as_bytes())
        .bytes(CR_ENDPOINT_NAME, req.endpoint_name.as_bytes())
        .bytes(CR_HANDSHAKE_DATA, &req.handshake_data)
        .varint(CR_NONCE, req.nonce as u64);
    for m in &req.mediums {
        w.varint(CR_MEDIUMS, *m);
    }
    w.bytes(CR_ENDPOINT_INFO, &req.endpoint_info);
    if let Some(v) = req.keep_alive_interval_millis {
        w.varint(CR_KEEPALIVE_INTERVAL, v);
    }
    if let Some(v) = req.keep_alive_timeout_millis {
        w.varint(CR_KEEPALIVE_TIMEOUT, v);
    }
    offline(T_CONNECTION_REQUEST, V1_CONNECTION_REQUEST, &w.finish())
}

/// Build a ConnectionResponse.
///
/// `status` is written as well as `response` because it is the field older peers read.
/// It is marked deprecated in the schema, and omitting it makes a peer that predates
/// `response` see a default of 0 and treat an acceptance as a rejection.
pub fn connection_response(response: Response, os: OsType) -> Vec<u8> {
    let mut os_info = Writer::new();
    os_info.varint(OS_TYPE, os as u64);

    let mut w = Writer::new();
    w.varint(RSP_STATUS, if response == Response::Accept { 0 } else { 1 })
        .varint(RSP_RESPONSE, response as u64)
        .bytes(RSP_OS_INFO, &os_info.finish())
        .bytes(RSP_HANDSHAKE_DATA, &[]);
    offline(T_CONNECTION_RESPONSE, V1_CONNECTION_RESPONSE, &w.finish())
}

/// Build one DATA packet: the header identifying the payload, and this chunk of it.
///
/// The header is repeated on EVERY chunk. That is not redundancy to optimise away -- the
/// receiver matches chunks to payloads by the id in the header, and several payloads are
/// in flight at once during a multi-file transfer.
pub fn payload_data(header: &PayloadHeader, chunk: &PayloadChunk) -> Vec<u8> {
    let mut h = Writer::new();
    h.varint(PH_ID, header.id as u64)
        .varint(PH_TYPE, header.payload_type as u64)
        .varint(PH_TOTAL_SIZE, header.total_size as u64)
        .varint(PH_IS_SENSITIVE, header.is_sensitive as u64);
    if !header.file_name.is_empty() {
        h.bytes(PH_FILE_NAME, header.file_name.as_bytes());
    }
    if !header.parent_folder.is_empty() {
        h.bytes(PH_PARENT_FOLDER, header.parent_folder.as_bytes());
    }

    let mut c = Writer::new();
    c.varint(PC_FLAGS, chunk.flags)
        .varint(PC_OFFSET, chunk.offset as u64)
        .bytes(PC_BODY, &chunk.body);

    let mut w = Writer::new();
    w.varint(PT_PACKET_TYPE, PacketType::Data as u64)
        .bytes(PT_PAYLOAD_HEADER, &h.finish())
        .bytes(PT_PAYLOAD_CHUNK, &c.finish());
    offline(T_PAYLOAD_TRANSFER, V1_PAYLOAD_TRANSFER, &w.finish())
}

/// Build a CONTROL packet — used to cancel or report an error on a payload in flight.
pub fn payload_control(header: &PayloadHeader, event: u64, offset: i64) -> Vec<u8> {
    let mut h = Writer::new();
    h.varint(PH_ID, header.id as u64)
        .varint(PH_TYPE, header.payload_type as u64)
        .varint(PH_TOTAL_SIZE, header.total_size as u64);

    let mut cm = Writer::new();
    cm.varint(CM_EVENT, event).varint(CM_OFFSET, offset as u64);

    let mut w = Writer::new();
    w.varint(PT_PACKET_TYPE, PacketType::Control as u64)
        .bytes(PT_PAYLOAD_HEADER, &h.finish())
        .bytes(PT_CONTROL_MESSAGE, &cm.finish());
    offline(T_PAYLOAD_TRANSFER, V1_PAYLOAD_TRANSFER, &w.finish())
}

pub fn keep_alive(ack: bool, seq_num: u64) -> Vec<u8> {
    let mut w = Writer::new();
    w.varint(KA_ACK, ack as u64).varint(KA_SEQ_NUM, seq_num);
    offline(T_KEEP_ALIVE, V1_KEEP_ALIVE, &w.finish())
}

pub fn disconnection() -> Vec<u8> {
    offline(T_DISCONNECTION, V1_DISCONNECTION, &[])
}

// ------------------------------------------------------------------ decoding ---

/// Parse an `OfflineFrame`.
pub fn parse(bytes: &[u8]) -> Result<Frame, Error> {
    let v1 = protobuf::first_bytes(bytes, OF_V1)?.ok_or(Error::Malformed("no v1 frame"))?;

    let mut ty = None;
    let mut body: Option<(u32, &[u8])> = None;
    let mut r = Reader::new(v1);
    while let Some(f) = r.next_field() {
        match f? {
            Field::Varint(V1_TYPE, v) => ty = Some(v),
            Field::Bytes(n, b) => body = Some((n, b)),
            _ => {}
        }
    }
    let ty = ty.ok_or(Error::Malformed("no frame type"))?;

    // Dispatch on the TYPE field, then take the body that matches it. A frame whose
    // type and body disagree is a peer bug; trusting the type is what the schema means.
    let body = body.map(|(_, b)| b).unwrap_or(&[]);

    Ok(match ty {
        T_CONNECTION_REQUEST => Frame::ConnectionRequest(parse_connection_request(body)?),
        T_CONNECTION_RESPONSE => Frame::ConnectionResponse(parse_connection_response(body)?),
        T_PAYLOAD_TRANSFER => Frame::PayloadTransfer(parse_payload_transfer(body)?),
        T_KEEP_ALIVE => {
            let ack = protobuf::first_varint(body, KA_ACK)?.unwrap_or(0) != 0;
            let seq_num = protobuf::first_varint(body, KA_SEQ_NUM)?.unwrap_or(0);
            Frame::KeepAlive { ack, seq_num }
        }
        T_DISCONNECTION => Frame::Disconnection,
        T_BANDWIDTH_UPGRADE => Frame::BandwidthUpgrade(body.to_vec()),
        other => Frame::Unknown(other),
    })
}

fn parse_connection_request(b: &[u8]) -> Result<ConnectionRequest, Error> {
    let mut out = ConnectionRequest::default();
    let mut r = Reader::new(b);
    while let Some(f) = r.next_field() {
        match f? {
            Field::Bytes(CR_ENDPOINT_ID, v) => out.endpoint_id = string(v),
            Field::Bytes(CR_ENDPOINT_NAME, v) => out.endpoint_name = string(v),
            Field::Bytes(CR_ENDPOINT_INFO, v) => out.endpoint_info = v.to_vec(),
            Field::Bytes(CR_HANDSHAKE_DATA, v) => out.handshake_data = v.to_vec(),
            Field::Varint(CR_NONCE, v) => out.nonce = v as i64,
            Field::Varint(CR_MEDIUMS, v) => out.mediums.push(v),
            Field::Varint(CR_KEEPALIVE_INTERVAL, v) => out.keep_alive_interval_millis = Some(v),
            Field::Varint(CR_KEEPALIVE_TIMEOUT, v) => out.keep_alive_timeout_millis = Some(v),
            _ => {}
        }
    }
    Ok(out)
}

fn parse_connection_response(b: &[u8]) -> Result<ConnectionResponse, Error> {
    let response = match protobuf::first_varint(b, RSP_RESPONSE)? {
        Some(v) => Response::from(v),
        // Fall back to the deprecated status field: 0 meant accepted there. A peer old
        // enough to omit `response` still says yes this way, and reading only the new
        // field would silently treat its acceptance as unknown.
        None => match protobuf::first_varint(b, RSP_STATUS)? {
            Some(0) => Response::Accept,
            Some(_) => Response::Reject,
            None => Response::Unknown,
        },
    };
    let os_type = match protobuf::first_bytes(b, RSP_OS_INFO)? {
        Some(os) => OsType::from(protobuf::first_varint(os, OS_TYPE)?.unwrap_or(0)),
        None => OsType::Unknown,
    };
    Ok(ConnectionResponse {
        response,
        os_type,
        handshake_data: protobuf::first_bytes(b, RSP_HANDSHAKE_DATA)?
            .unwrap_or(&[])
            .to_vec(),
    })
}

fn parse_payload_transfer(b: &[u8]) -> Result<PayloadTransfer, Error> {
    let packet_type = PacketType::from(protobuf::first_varint(b, PT_PACKET_TYPE)?.unwrap_or(0));

    let header = match protobuf::first_bytes(b, PT_PAYLOAD_HEADER)? {
        Some(h) => PayloadHeader {
            id: protobuf::first_varint(h, PH_ID)?.unwrap_or(0) as i64,
            payload_type: PayloadType::from(protobuf::first_varint(h, PH_TYPE)?.unwrap_or(0)),
            total_size: protobuf::first_varint(h, PH_TOTAL_SIZE)?.unwrap_or(0) as i64,
            is_sensitive: protobuf::first_varint(h, PH_IS_SENSITIVE)?.unwrap_or(0) != 0,
            file_name: protobuf::first_bytes(h, PH_FILE_NAME)?.map(string).unwrap_or_default(),
            parent_folder: protobuf::first_bytes(h, PH_PARENT_FOLDER)?
                .map(string)
                .unwrap_or_default(),
        },
        None => PayloadHeader::default(),
    };

    let chunk = match protobuf::first_bytes(b, PT_PAYLOAD_CHUNK)? {
        Some(c) => Some(PayloadChunk {
            flags: protobuf::first_varint(c, PC_FLAGS)?.unwrap_or(0),
            offset: protobuf::first_varint(c, PC_OFFSET)?.unwrap_or(0) as i64,
            body: protobuf::first_bytes(c, PC_BODY)?.unwrap_or(&[]).to_vec(),
        }),
        None => None,
    };

    let control = match protobuf::first_bytes(b, PT_CONTROL_MESSAGE)? {
        Some(c) => Some((
            protobuf::first_varint(c, CM_EVENT)?.unwrap_or(0),
            protobuf::first_varint(c, CM_OFFSET)?.unwrap_or(0) as i64,
        )),
        None => None,
    };

    Ok(PayloadTransfer {
        packet_type,
        header,
        chunk,
        control,
    })
}

/// Lossy on purpose. A peer's file name is attacker-controlled and may not be UTF-8;
/// refusing the whole frame over a bad byte in a display string would drop a transfer
/// that is otherwise fine. What this must never do is panic.
fn string(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connection_request_round_trips() {
        let req = ConnectionRequest {
            endpoint_id: "ABCD".into(),
            endpoint_name: "Pixel".into(),
            endpoint_info: vec![1, 2, 3],
            handshake_data: vec![],
            nonce: 12345,
            mediums: vec![Medium::WifiLan as u64, Medium::Ble as u64],
            keep_alive_interval_millis: Some(5000),
            keep_alive_timeout_millis: Some(30000),
        };
        match parse(&connection_request(&req)).unwrap() {
            Frame::ConnectionRequest(got) => assert_eq!(got, req),
            other => panic!("wrong frame: {other:?}"),
        }
    }

    #[test]
    fn connection_response_round_trips() {
        for r in [Response::Accept, Response::Reject] {
            match parse(&connection_response(r, OsType::Android)).unwrap() {
                Frame::ConnectionResponse(got) => {
                    assert_eq!(got.response, r);
                    assert_eq!(got.os_type, OsType::Android);
                }
                other => panic!("wrong frame: {other:?}"),
            }
        }
    }

    /// A peer that predates the `response` field says yes with `status = 0`.
    #[test]
    fn a_legacy_status_only_acceptance_is_understood() {
        let mut w = Writer::new();
        w.varint(RSP_STATUS, 0);
        let body = offline(T_CONNECTION_RESPONSE, V1_CONNECTION_RESPONSE, &w.finish());
        match parse(&body).unwrap() {
            Frame::ConnectionResponse(got) => assert_eq!(got.response, Response::Accept),
            other => panic!("wrong frame: {other:?}"),
        }
    }

    #[test]
    fn payload_data_round_trips() {
        let header = PayloadHeader {
            id: -998877,
            payload_type: PayloadType::File,
            total_size: 1_500_000,
            is_sensitive: false,
            file_name: "holiday.jpg".into(),
            parent_folder: "".into(),
        };
        let chunk = PayloadChunk {
            flags: FLAG_LAST_CHUNK,
            offset: 524288,
            body: vec![0xEE; 64],
        };
        match parse(&payload_data(&header, &chunk)).unwrap() {
            Frame::PayloadTransfer(pt) => {
                assert_eq!(pt.packet_type, PacketType::Data);
                assert_eq!(pt.header, header);
                let got = pt.chunk.unwrap();
                assert_eq!(got, chunk);
                assert!(got.is_last());
            }
            other => panic!("wrong frame: {other:?}"),
        }
    }

    /// A negative payload id must survive the round trip. Quick Share generates them
    /// randomly across the whole int64 range, so half of them have the top bit set --
    /// truncating to u32 or clamping at zero would collide two payloads into one.
    #[test]
    fn a_negative_payload_id_survives() {
        let header = PayloadHeader {
            id: i64::MIN + 1,
            payload_type: PayloadType::Bytes,
            total_size: 10,
            ..Default::default()
        };
        let chunk = PayloadChunk::default();
        match parse(&payload_data(&header, &chunk)).unwrap() {
            Frame::PayloadTransfer(pt) => assert_eq!(pt.header.id, i64::MIN + 1),
            other => panic!("wrong frame: {other:?}"),
        }
    }

    #[test]
    fn control_message_round_trips() {
        let header = PayloadHeader {
            id: 42,
            payload_type: PayloadType::File,
            ..Default::default()
        };
        match parse(&payload_control(&header, 2, 4096)).unwrap() {
            Frame::PayloadTransfer(pt) => {
                assert_eq!(pt.packet_type, PacketType::Control);
                assert_eq!(pt.control, Some((2, 4096)));
            }
            other => panic!("wrong frame: {other:?}"),
        }
    }

    #[test]
    fn keep_alive_and_disconnection_round_trip() {
        match parse(&keep_alive(true, 7)).unwrap() {
            Frame::KeepAlive { ack, seq_num } => {
                assert!(ack);
                assert_eq!(seq_num, 7);
            }
            other => panic!("wrong frame: {other:?}"),
        }
        assert_eq!(parse(&disconnection()).unwrap(), Frame::Disconnection);
    }

    /// Forward compatibility: a frame type we do not model must not fail the connection.
    #[test]
    fn an_unmodelled_frame_type_is_reported_not_refused() {
        let body = offline(11, 12, b"whatever"); // AUTO_RECONNECT
        assert_eq!(parse(&body).unwrap(), Frame::Unknown(11));
    }

    #[test]
    fn a_non_utf8_filename_does_not_panic() {
        let mut h = Writer::new();
        h.varint(PH_ID, 1)
            .varint(PH_TYPE, PayloadType::File as u64)
            .bytes(PH_FILE_NAME, &[0xFF, 0xFE, b'a']);
        let mut w = Writer::new();
        w.varint(PT_PACKET_TYPE, PacketType::Data as u64)
            .bytes(PT_PAYLOAD_HEADER, &h.finish());
        let body = offline(T_PAYLOAD_TRANSFER, V1_PAYLOAD_TRANSFER, &w.finish());
        match parse(&body).unwrap() {
            Frame::PayloadTransfer(pt) => assert!(!pt.header.file_name.is_empty()),
            other => panic!("wrong frame: {other:?}"),
        }
    }

    #[test]
    fn truncation_errors_rather_than_panicking() {
        let full = payload_data(&PayloadHeader::default(), &PayloadChunk::default());
        for cut in 0..full.len() {
            let _ = parse(&full[..cut]);
        }
    }

    #[test]
    fn garbage_does_not_panic() {
        for len in 0..64 {
            let junk: Vec<u8> = (0..len).map(|i| (i * 37 + 11) as u8).collect();
            let _ = parse(&junk);
        }
    }
}

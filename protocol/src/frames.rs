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
const V1_BANDWIDTH_UPGRADE: u32 = 5;
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
const CR_MEDIUM_METADATA: u32 = 7;
const CR_KEEPALIVE_INTERVAL: u32 = 8;
const CR_KEEPALIVE_TIMEOUT: u32 = 9;
const CR_CONNECTIONS_DEVICE: u32 = 12;

// MediumMetadata
const MM_SUPPORTS_5GHZ: u32 = 1;
const MM_SUPPORTS_6GHZ: u32 = 4;
const MM_MOBILE_RADIO: u32 = 5;
const MM_AP_FREQUENCY: u32 = 6;

/// `ap_frequency` when we are not associated with an AP. Signed, so it is written as a
/// ten-byte varint -- protobuf sign-extends a negative int32 to 64 bits.
const AP_FREQUENCY_NONE: u64 = -1i32 as i64 as u64;

// ConnectionsDevice
const CD_ENDPOINT_ID: u32 = 1;
const CD_ENDPOINT_TYPE: u32 = 2;
const CD_ENDPOINT_INFO: u32 = 4;

/// `EndpointType.CONNECTIONS_ENDPOINT`. The other values describe Presence devices,
/// which is a different discovery stack.
const ENDPOINT_TYPE_CONNECTIONS: u64 = 1;

// ConnectionResponseFrame
const RSP_STATUS: u32 = 1;
const RSP_HANDSHAKE_DATA: u32 = 2;
const RSP_RESPONSE: u32 = 3;
const RSP_OS_INFO: u32 = 4;
const RSP_MULTIPLEX_BITMASK: u32 = 5;
const RSP_SAFE_TO_DISCONNECT: u32 = 7;
const RSP_KEEPALIVE_TIMEOUT: u32 = 9;

/// "No medium supports multiplexing", which is true of us: one socket, one stream.
///
/// Absence and zero are different things here. The field must be PRESENT and zero --
/// see `connection_response`.
const MULTIPLEX_SOCKET_BITMASK_NONE: u64 = 0;

/// The version of the safe-to-disconnect handshake we claim. Anything below 1 reads as
/// "this peer cannot disconnect safely".
const SAFE_TO_DISCONNECT_VERSION: u64 = 1;

/// Ten minutes. Both sides of the handshake advertise it, and it is what a stock peer
/// schedules its own KEEP_ALIVE cadence against.
pub const KEEP_ALIVE_TIMEOUT_MILLIS: u64 = 600_000;

/// Ten seconds, which is what stock Android emits.
pub const KEEP_ALIVE_INTERVAL_MILLIS: u64 = 10_000;

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

// DisconnectionFrame
const DC_REQUEST_SAFE: u32 = 1;
const DC_ACK_SAFE: u32 = 2;

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
    /// What the peer claims about the safe-disconnect handshake, and **the field that
    /// decides how a transfer is allowed to end.**
    ///
    /// `0` -- the default, and what Windows Quick Share reports -- means the peer has
    /// safe-disconnect DISABLED. Such a peer treats a Disconnection arriving before it
    /// has finished writing the file as a FAILED transfer, however many bytes it
    /// received. `>= 1` means it can be told we are leaving.
    pub safe_to_disconnect_version: u64,
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
    /// `request_safe_to_disconnect` asks the peer to drain its read pipeline and
    /// answer before the socket goes away; `ack_safe_to_disconnect` is that answer.
    /// Both false is the old unqualified "I am going now".
    Disconnection {
        request_safe: bool,
        ack_safe: bool,
    },
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
/// `MediumMetadata`, describing this device's radios.
///
/// Every value is a truthful "no": we do not offer a Wi-Fi upgrade path of our own, so
/// claiming 5 GHz or 6 GHz support would invite a peer to negotiate onto one. The fields
/// are written explicitly rather than left absent because absence and false are different
/// things to the peer that reads them -- see `connection_request`.
fn medium_metadata() -> Vec<u8> {
    let mut w = Writer::new();
    w.varint(MM_SUPPORTS_5GHZ, 0)
        .varint(MM_SUPPORTS_6GHZ, 0)
        .varint(MM_MOBILE_RADIO, 0)
        .varint(MM_AP_FREQUENCY, AP_FREQUENCY_NONE);
    w.finish()
}

/// `ConnectionsDevice`, which repeats the endpoint id and info inside a `Device` oneof.
///
/// It is genuinely redundant -- both values are already fields 1 and 6 of the request --
/// but a stock receiver reads the oneof, not the flat fields. See `connection_request`.
fn connections_device(endpoint_id: &str, endpoint_info: &[u8]) -> Vec<u8> {
    let mut w = Writer::new();
    w.bytes(CD_ENDPOINT_ID, endpoint_id.as_bytes())
        .varint(CD_ENDPOINT_TYPE, ENDPOINT_TYPE_CONNECTIONS)
        .bytes(CD_ENDPOINT_INFO, endpoint_info);
    w.finish()
}

/// Build a ConnectionRequest.
///
/// **Two fields here are derived rather than taken from `req`, and both are required by
/// stock Quick Share on Android.** `medium_metadata` and `connections_device` carry no
/// information a caller could get wrong, and forgetting them is not a visible mistake:
/// the receiver accepts the socket, reads a request it will not dispatch, and says
/// nothing at all. Deriving them here means no caller can omit them.
///
/// That failure is what "RFCOMM connects to an Android peer and then nothing happens"
/// was. Windows Quick Share is laxer -- it completed the whole handshake against a
/// request missing both, took the introduction, and only then reported that it could not
/// complete the transfer. Credit: Bada's `OutboundFrames.connectionRequest`, whose
/// comment records that endpoint_id and endpoint_info alone stopped being enough on
/// Android 14.
pub fn connection_request(req: &ConnectionRequest) -> Vec<u8> {
    let mut w = Writer::new();
    w.bytes(CR_ENDPOINT_ID, req.endpoint_id.as_bytes())
        .bytes(CR_ENDPOINT_NAME, req.endpoint_name.as_bytes())
        .bytes(CR_HANDSHAKE_DATA, &req.handshake_data)
        .varint(CR_NONCE, req.nonce as u64);
    for m in &req.mediums {
        w.varint(CR_MEDIUMS, *m);
    }
    w.bytes(CR_ENDPOINT_INFO, &req.endpoint_info)
        .bytes(CR_MEDIUM_METADATA, &medium_metadata());
    if let Some(v) = req.keep_alive_interval_millis {
        w.varint(CR_KEEPALIVE_INTERVAL, v);
    }
    if let Some(v) = req.keep_alive_timeout_millis {
        w.varint(CR_KEEPALIVE_TIMEOUT, v);
    }
    w.bytes(
        CR_CONNECTIONS_DEVICE,
        &connections_device(&req.endpoint_id, &req.endpoint_info),
    );
    offline(T_CONNECTION_REQUEST, V1_CONNECTION_REQUEST, &w.finish())
}

/// Build a ConnectionResponse.
///
/// `status` is written as well as `response` because it is the field older peers read.
/// It is marked deprecated in the schema, and omitting it makes a peer that predates
/// `response` see a default of 0 and treat an acceptance as a rejection.
///
/// **Three more fields exist only to satisfy a receiver, and all three fail silently.**
/// A stock peer that finds any of them missing closes the socket without a frame --
/// after our ACCEPT, before its own -- which looks like the network dropping rather than
/// like a rejection:
///
/// - `multiplex_socket_bitmask` must be PRESENT and zero. Zero means "no medium
///   multiplexes", which is what we do; absent means the peer cannot tell.
/// - `safe_to_disconnect_version` below 1 reads as "cannot disconnect safely", and the
///   receiver drops us before it ever shows a consent dialog.
/// - `keep_alive_timeout_millis` is the newest of the three and the last to be found.
///
/// Empty `handshake_data` is NOT written. It carried nothing, and this frame is compared
/// field-for-field by the peer -- the shape below is the one observed to work.
///
/// Both directions send this same shape, because the peer validating it does not know
/// which role we are playing. Credit: Bada's `OutboundFrames.connectionResponse`, which
/// records each field against the device that needed it.
pub fn connection_response(response: Response, os: OsType) -> Vec<u8> {
    let mut os_info = Writer::new();
    os_info.varint(OS_TYPE, os as u64);

    let mut w = Writer::new();
    w.varint(RSP_STATUS, if response == Response::Accept { 0 } else { 1 })
        .varint(RSP_RESPONSE, response as u64)
        .bytes(RSP_OS_INFO, &os_info.finish())
        .varint(RSP_MULTIPLEX_BITMASK, MULTIPLEX_SOCKET_BITMASK_NONE)
        .varint(RSP_SAFE_TO_DISCONNECT, SAFE_TO_DISCONNECT_VERSION)
        .varint(RSP_KEEPALIVE_TIMEOUT, KEEP_ALIVE_TIMEOUT_MILLIS);
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

/// Wrap a bandwidth-upgrade body in an offline frame.
///
/// The body itself is built by `crate::upgrade`, which owns that schema. This is only
/// the envelope, so the two layers do not have to know each other's field numbers.
pub fn bandwidth_upgrade(body: &[u8]) -> Vec<u8> {
    offline(T_BANDWIDTH_UPGRADE, V1_BANDWIDTH_UPGRADE, body)
}

/// The inner bytes of a bandwidth-upgrade frame, or None if it is not one.
///
/// Saves every caller writing the same match, and keeps `Frame::BandwidthUpgrade`
/// carrying raw bytes rather than making this module depend on the upgrade schema.
pub fn upgrade_body(bytes: &[u8]) -> Option<Vec<u8>> {
    match parse(bytes).ok()? {
        Frame::BandwidthUpgrade(b) => Some(b),
        _ => None,
    }
}

pub fn keep_alive(ack: bool, seq_num: u64) -> Vec<u8> {
    let mut w = Writer::new();
    w.varint(KA_ACK, ack as u64).varint(KA_SEQ_NUM, seq_num);
    offline(T_KEEP_ALIVE, V1_KEEP_ALIVE, &w.finish())
}

/// Build a DisconnectionFrame.
///
/// **`request_safe` must be true whenever we advertised `safe_to_disconnect_version`,**
/// which `connection_response` always does. The two form a contract: having claimed we
/// can disconnect safely, closing the socket without asking is a bare TCP FIN, and a
/// stock receiver marks every payload still in its read pipeline as failed. The
/// transfer completes on our side and fails on theirs.
///
/// After sending it, wait for the peer's ack (or its own Disconnection) before closing.
pub fn disconnection(request_safe: bool, ack_safe: bool) -> Vec<u8> {
    let mut w = Writer::new();
    if request_safe {
        w.varint(DC_REQUEST_SAFE, 1);
    }
    if ack_safe {
        w.varint(DC_ACK_SAFE, 1);
    }
    offline(T_DISCONNECTION, V1_DISCONNECTION, &w.finish())
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
        T_DISCONNECTION => {
            let b = protobuf::first_bytes(v1, V1_DISCONNECTION)?.unwrap_or(&[]);
            Frame::Disconnection {
                request_safe: protobuf::first_varint(b, DC_REQUEST_SAFE)?.unwrap_or(0) != 0,
                ack_safe: protobuf::first_varint(b, DC_ACK_SAFE)?.unwrap_or(0) != 0,
            }
        }
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
        // Absent means 0 means "do not disconnect me". The default is the strict case
        // on purpose: a peer that says nothing is treated as one that cannot cope.
        safe_to_disconnect_version: protobuf::first_varint(b, RSP_SAFE_TO_DISCONNECT)?
            .unwrap_or(0),
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

    // ------------------------------------------------------- required fields ---
    //
    // The tests below assert PRESENCE, and they exist because every one of these fields
    // fails silently. A stock peer missing any of them closes the socket without sending
    // a frame, so nothing above this layer can tell a missing field from a radio going
    // out of range.
    //
    // A round-trip test cannot catch this: our own parser is happy either way, which is
    // exactly how they came to be missing in the first place. These assert against the
    // encoded bytes instead.

    /// Dig the nested ConnectionRequest out of a built frame.
    fn request_body(bytes: &[u8]) -> Vec<u8> {
        let v1 = protobuf::first_bytes(bytes, OF_V1).unwrap().expect("no V1Frame");
        protobuf::first_bytes(v1, V1_CONNECTION_REQUEST)
            .unwrap()
            .expect("no ConnectionRequest")
            .to_vec()
    }

    /// Dig the nested ConnectionResponse out of a built frame.
    fn response_body(bytes: &[u8]) -> Vec<u8> {
        let v1 = protobuf::first_bytes(bytes, OF_V1).unwrap().expect("no V1Frame");
        protobuf::first_bytes(v1, V1_CONNECTION_RESPONSE)
            .unwrap()
            .expect("no ConnectionResponse")
            .to_vec()
    }

    fn sample_request() -> ConnectionRequest {
        ConnectionRequest {
            endpoint_id: "ABCD".into(),
            endpoint_name: "Pixel".into(),
            endpoint_info: vec![0x21, 0xAA, 0xBB],
            handshake_data: vec![],
            nonce: 0,
            mediums: vec![Medium::Bluetooth as u64, Medium::WifiLan as u64],
            keep_alive_interval_millis: Some(KEEP_ALIVE_INTERVAL_MILLIS),
            keep_alive_timeout_millis: Some(KEEP_ALIVE_TIMEOUT_MILLIS),
        }
    }

    /// Without this a stock Android receiver accepts the socket and never answers.
    #[test]
    fn a_request_carries_medium_metadata() {
        let body = request_body(&connection_request(&sample_request()));
        let meta = protobuf::first_bytes(&body, CR_MEDIUM_METADATA)
            .unwrap()
            .expect("no medium_metadata in the request");

        // Present AND false. Absent is a different thing to the peer that reads it,
        // which is the whole reason these are written out rather than left at a default.
        assert_eq!(protobuf::first_varint(meta, MM_SUPPORTS_5GHZ).unwrap(), Some(0));
        assert_eq!(protobuf::first_varint(meta, MM_SUPPORTS_6GHZ).unwrap(), Some(0));
        assert_eq!(protobuf::first_varint(meta, MM_MOBILE_RADIO).unwrap(), Some(0));
        // -1 sign-extended to 64 bits, which is what protobuf does with a negative
        // int32: ten bytes on the wire. A naive cast would write one and mean 2^32-1.
        assert_eq!(
            protobuf::first_varint(meta, MM_AP_FREQUENCY).unwrap(),
            Some(u64::MAX)
        );
    }

    /// The same failure as above, and the same silence.
    #[test]
    fn a_request_carries_a_connections_device() {
        let req = sample_request();
        let body = request_body(&connection_request(&req));
        let device = protobuf::first_bytes(&body, CR_CONNECTIONS_DEVICE)
            .unwrap()
            .expect("no connections_device in the request");

        // It repeats the endpoint id and info, which are already fields 1 and 6 of the
        // request. Redundant on the wire; read in preference to the flat fields.
        assert_eq!(
            protobuf::first_bytes(device, CD_ENDPOINT_ID).unwrap(),
            Some(req.endpoint_id.as_bytes())
        );
        assert_eq!(
            protobuf::first_bytes(device, CD_ENDPOINT_INFO).unwrap(),
            Some(&req.endpoint_info[..])
        );
        assert_eq!(
            protobuf::first_varint(device, CD_ENDPOINT_TYPE).unwrap(),
            Some(ENDPOINT_TYPE_CONNECTIONS)
        );
    }

    /// A sender with no endpoint_info is a sender the receiver cannot name, and the
    /// consent prompt is built from it. This is what it was for weeks.
    #[test]
    fn an_empty_endpoint_info_is_visible_as_empty() {
        let mut req = sample_request();
        req.endpoint_info = Vec::new();
        let body = request_body(&connection_request(&req));
        assert_eq!(
            protobuf::first_bytes(&body, CR_ENDPOINT_INFO).unwrap(),
            Some(&[][..]),
            "an empty endpoint_info should still be encoded, not silently dropped"
        );
    }

    /// Three fields, and a receiver that drops us without a word when any is absent.
    #[test]
    fn a_response_carries_the_fields_a_stock_receiver_checks_for() {
        let body = response_body(&connection_response(Response::Accept, OsType::Android));

        // Zero, and PRESENT. This is the one most easily "optimised away" as a default.
        assert_eq!(
            protobuf::first_varint(&body, RSP_MULTIPLEX_BITMASK).unwrap(),
            Some(0)
        );
        assert_eq!(
            protobuf::first_varint(&body, RSP_SAFE_TO_DISCONNECT).unwrap(),
            Some(1)
        );
        assert_eq!(
            protobuf::first_varint(&body, RSP_KEEPALIVE_TIMEOUT).unwrap(),
            Some(KEEP_ALIVE_TIMEOUT_MILLIS)
        );
        // The empty handshake_data we used to write is gone. This frame is compared
        // field-for-field, and an extra empty field is a difference.
        assert_eq!(
            protobuf::first_bytes(&body, RSP_HANDSHAKE_DATA).unwrap(),
            None
        );
    }

    /// Both directions send the same response shape, because the peer validating it does
    /// not know which role we are playing.
    #[test]
    fn a_rejection_carries_them_too() {
        let body = response_body(&connection_response(Response::Reject, OsType::Android));
        assert_eq!(
            protobuf::first_varint(&body, RSP_MULTIPLEX_BITMASK).unwrap(),
            Some(0)
        );
        assert_eq!(
            protobuf::first_varint(&body, RSP_SAFE_TO_DISCONNECT).unwrap(),
            Some(1)
        );
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
        assert_eq!(
            parse(&disconnection(false, false)).unwrap(),
            Frame::Disconnection {
                request_safe: false,
                ack_safe: false
            }
        );
        // The shape we actually send: having advertised safe_to_disconnect_version, a
        // disconnection that does not request it is a bare FIN to the peer.
        assert_eq!(
            parse(&disconnection(true, false)).unwrap(),
            Frame::Disconnection {
                request_safe: true,
                ack_safe: false
            }
        );
        assert_eq!(
            parse(&disconnection(false, true)).unwrap(),
            Frame::Disconnection {
                request_safe: false,
                ack_safe: true
            }
        );
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

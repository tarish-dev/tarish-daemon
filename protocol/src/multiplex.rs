//! Nearby's multiplex layer — the virtual socket an L2CAP channel carries.
//!
//! **An L2CAP connection-oriented channel is not a byte stream you can write frames to.**
//! Open one to a stock peer, send a ConnectionRequest, and nothing comes back: the peer is
//! waiting to be asked for a virtual socket first. That handshake is this module.
//!
//! ```text
//!   us   -> MultiplexFrame { CONTROL, header, CONNECTION_REQUEST }
//!   peer -> MultiplexFrame { CONTROL, header, CONNECTION_RESPONSE { CONNECTION_ACCEPTED } }
//!   both -> MultiplexFrame { DATA, header, data = <one OfflineFrame> }   ... and on
//! ```
//!
//! Every frame is length-prefixed exactly like the transport above it, so `framing`
//! handles that and nothing here does.
//!
//! **Why the header repeats on every frame.** `salted_service_id_hash` names which
//! service the virtual socket belongs to — one physical channel can carry several — and
//! the salt is sent alongside so the peer can recompute the hash and match it. Both the
//! hash and the salt that produced it go in every frame, including data frames.
//!
//! WHERE THIS IS NEEDED, AND WHERE IT IS NOT
//!
//! Only on L2CAP. RFCOMM to the same peer is a plain stream and multiplexing it would
//! break it, which is why the transport decides and this module is just bytes.
//!
//! Which one a peer wants is not a preference, it is in its advertisement: a peer that
//! publishes an L2CAP PSM refuses RFCOMM, and a peer that publishes none accepts it. See
//! `ble::Advertisement::psm`.
//!
//! Format credit: Bada's `NearbyMultiplexFrames.kt` (Apache 2.0) and
//! `multiplex_frames.proto`.

use crate::protobuf::{self, Writer};
use openssl::hash::{hash, MessageDigest};

// MultiplexFrame
const MF_HEADER: u32 = 1;
const MF_FRAME_TYPE: u32 = 2;
const MF_CONTROL_FRAME: u32 = 3;
const MF_DATA_FRAME: u32 = 4;

const FRAME_TYPE_CONTROL: u64 = 1;
const FRAME_TYPE_DATA: u64 = 2;

// MultiplexFrameHeader
const HDR_SALTED_HASH: u32 = 1;
const HDR_SALT: u32 = 2;

// MultiplexControlFrame
const CF_TYPE: u32 = 1;
const CF_CONNECTION_REQUEST: u32 = 2;
const CF_CONNECTION_RESPONSE: u32 = 3;
const CF_DISCONNECT: u32 = 4;

const CONTROL_CONNECTION_REQUEST: u64 = 1;
const CONTROL_CONNECTION_RESPONSE: u64 = 2;
const CONTROL_DISCONNECTION: u64 = 3;

// ConnectionResponseFrame
const RSP_CODE: u32 = 1;

// MultiplexDataFrame
const DF_DATA: u32 = 1;

/// Three bytes, the same width as the service-id hash in an advertisement.
pub const SERVICE_ID_HASH_LEN: usize = 3;

/// How the peer answered our request for a virtual socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponseCode {
    Unknown = 0,
    Accepted = 1,
    /// The peer has no listener for this service. A real answer, not an error: it means
    /// the far side is not sharing right now.
    NotListening = 2,
}

impl ResponseCode {
    fn from(v: u64) -> Self {
        match v {
            1 => ResponseCode::Accepted,
            2 => ResponseCode::NotListening,
            _ => ResponseCode::Unknown,
        }
    }
}

/// A decoded multiplex frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Frame {
    ConnectionRequest,
    ConnectionResponse(ResponseCode),
    Disconnection,
    /// One frame of the stream the virtual socket carries.
    Data(Vec<u8>),
    /// Something we do not model. Ignored rather than fatal, for the same reason
    /// `frames::Frame::Unknown` exists.
    Unknown,
}

/// `sha256(service_id + salt)[..3]`.
///
/// The salt is concatenated as text, not mixed in as bytes, which is worth stating
/// because it looks like a keyed hash and is not.
pub fn salted_service_id_hash(service_id: &str, salt: &str) -> [u8; SERVICE_ID_HASH_LEN] {
    let mut out = [0u8; SERVICE_ID_HASH_LEN];
    let mut input = String::with_capacity(service_id.len() + salt.len());
    input.push_str(service_id);
    input.push_str(salt);
    if let Ok(d) = hash(MessageDigest::sha256(), input.as_bytes()) {
        out.copy_from_slice(&d[..SERVICE_ID_HASH_LEN]);
    }
    out
}

/// The salt for a session: eight random bytes as lowercase hex, which is the shape a
/// stock peer expects to echo back.
pub fn random_salt() -> String {
    let mut b = [0u8; 8];
    // A failure here would give a fixed salt, which still produces a valid hash and a
    // working socket -- it is not key material, it only distinguishes services.
    let _ = openssl::rand::rand_bytes(&mut b);
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn header(salted: &[u8], salt: &str) -> Vec<u8> {
    let mut w = Writer::new();
    w.bytes(HDR_SALTED_HASH, salted).bytes(HDR_SALT, salt.as_bytes());
    w.finish()
}

/// Ask the peer to open a virtual socket for this service.
pub fn connection_request(salted: &[u8], salt: &str) -> Vec<u8> {
    let mut control = Writer::new();
    control
        .varint(CF_TYPE, CONTROL_CONNECTION_REQUEST)
        // PRESENT AND EMPTY. The request carries no fields, but the oneof arm has to be
        // set or the peer sees a control frame with no request in it.
        .bytes(CF_CONNECTION_REQUEST, &[]);

    let mut w = Writer::new();
    w.bytes(MF_HEADER, &header(salted, salt))
        .varint(MF_FRAME_TYPE, FRAME_TYPE_CONTROL)
        .bytes(MF_CONTROL_FRAME, &control.finish());
    w.finish()
}

/// Answer someone else's request. We are the client today, so this exists for symmetry
/// and for the tests to talk to themselves.
pub fn connection_response(salted: &[u8], salt: &str, code: ResponseCode) -> Vec<u8> {
    let mut rsp = Writer::new();
    rsp.varint(RSP_CODE, code as u64);

    let mut control = Writer::new();
    control
        .varint(CF_TYPE, CONTROL_CONNECTION_RESPONSE)
        .bytes(CF_CONNECTION_RESPONSE, &rsp.finish());

    let mut w = Writer::new();
    w.bytes(MF_HEADER, &header(salted, salt))
        .varint(MF_FRAME_TYPE, FRAME_TYPE_CONTROL)
        .bytes(MF_CONTROL_FRAME, &control.finish());
    w.finish()
}

/// Tell the peer the virtual socket is closing.
pub fn disconnection(salted: &[u8], salt: &str) -> Vec<u8> {
    let mut control = Writer::new();
    control
        .varint(CF_TYPE, CONTROL_DISCONNECTION)
        .bytes(CF_DISCONNECT, &[]);

    let mut w = Writer::new();
    w.bytes(MF_HEADER, &header(salted, salt))
        .varint(MF_FRAME_TYPE, FRAME_TYPE_CONTROL)
        .bytes(MF_CONTROL_FRAME, &control.finish());
    w.finish()
}

/// Wrap one byte string — in practice one `OfflineFrame` — as a data frame.
pub fn data(salted: &[u8], salt: &str, payload: &[u8]) -> Vec<u8> {
    let mut df = Writer::new();
    df.bytes(DF_DATA, payload);

    let mut w = Writer::new();
    w.bytes(MF_HEADER, &header(salted, salt))
        .varint(MF_FRAME_TYPE, FRAME_TYPE_DATA)
        .bytes(MF_DATA_FRAME, &df.finish());
    w.finish()
}

/// Decode a multiplex frame.
///
/// The header is not checked against our own salted hash: a frame for another service on
/// a channel we opened for one service is not something we can act on either way, and
/// refusing it here would turn a stranger's frame into a dropped connection.
pub fn parse(bytes: &[u8]) -> Frame {
    let frame_type = protobuf::first_varint(bytes, MF_FRAME_TYPE)
        .ok()
        .flatten()
        .unwrap_or(0);

    if frame_type == FRAME_TYPE_DATA {
        if let Ok(Some(df)) = protobuf::first_bytes(bytes, MF_DATA_FRAME) {
            if let Ok(Some(payload)) = protobuf::first_bytes(df, DF_DATA) {
                return Frame::Data(payload.to_vec());
            }
        }
        return Frame::Unknown;
    }

    let Ok(Some(control)) = protobuf::first_bytes(bytes, MF_CONTROL_FRAME) else {
        return Frame::Unknown;
    };
    match protobuf::first_varint(control, CF_TYPE).ok().flatten() {
        Some(CONTROL_CONNECTION_REQUEST) => Frame::ConnectionRequest,
        Some(CONTROL_CONNECTION_RESPONSE) => {
            let code = protobuf::first_bytes(control, CF_CONNECTION_RESPONSE)
                .ok()
                .flatten()
                .and_then(|r| protobuf::first_varint(r, RSP_CODE).ok().flatten())
                .unwrap_or(0);
            Frame::ConnectionResponse(ResponseCode::from(code))
        }
        Some(CONTROL_DISCONNECTION) => Frame::Disconnection,
        _ => Frame::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::service::SERVICE_ID;

    #[test]
    fn a_connection_request_round_trips() {
        let salt = "0011223344556677";
        let h = salted_service_id_hash(SERVICE_ID, salt);
        assert_eq!(parse(&connection_request(&h, salt)), Frame::ConnectionRequest);
    }

    #[test]
    fn a_response_round_trips_every_code() {
        let salt = "abcdef0011223344";
        let h = salted_service_id_hash(SERVICE_ID, salt);
        for code in [
            ResponseCode::Accepted,
            ResponseCode::NotListening,
            ResponseCode::Unknown,
        ] {
            assert_eq!(
                parse(&connection_response(&h, salt, code)),
                Frame::ConnectionResponse(code)
            );
        }
    }

    #[test]
    fn a_data_frame_carries_its_payload_unchanged() {
        let salt = random_salt();
        let h = salted_service_id_hash(SERVICE_ID, &salt);
        let payload = b"\x08\x01\x12\x03abc".to_vec();
        assert_eq!(parse(&data(&h, &salt, &payload)), Frame::Data(payload));
    }

    #[test]
    fn an_empty_data_frame_is_still_a_data_frame() {
        let salt = random_salt();
        let h = salted_service_id_hash(SERVICE_ID, &salt);
        assert_eq!(parse(&data(&h, &salt, &[])), Frame::Data(Vec::new()));
    }

    #[test]
    fn a_disconnection_round_trips() {
        let salt = random_salt();
        let h = salted_service_id_hash(SERVICE_ID, &salt);
        assert_eq!(parse(&disconnection(&h, salt.as_str())), Frame::Disconnection);
    }

    /// The salt is appended as TEXT to the service name. Checked against the digest
    /// rather than against our own output, because agreeing with ourselves proves
    /// nothing about whether a peer can match the hash.
    #[test]
    fn the_salted_hash_is_sha256_of_the_name_and_salt_concatenated() {
        let salt = "deadbeef";
        let want = hash(MessageDigest::sha256(), b"NearbySharingdeadbeef").unwrap();
        assert_eq!(salted_service_id_hash(SERVICE_ID, salt), want[..3]);
    }

    /// Different salts must give different hashes, or the header identifies nothing.
    #[test]
    fn a_different_salt_gives_a_different_hash() {
        assert_ne!(
            salted_service_id_hash(SERVICE_ID, "00000000"),
            salted_service_id_hash(SERVICE_ID, "00000001")
        );
    }

    /// Without the salt it is the plain service-id hash, which is a different value and
    /// would be matched against the wrong thing.
    #[test]
    fn the_salted_hash_is_not_the_plain_one() {
        assert_ne!(
            salted_service_id_hash(SERVICE_ID, "0011223344556677"),
            crate::service::service_id_hash()
        );
    }

    #[test]
    fn the_salt_is_sixteen_hex_characters() {
        let s = random_salt();
        assert_eq!(s.len(), 16, "eight bytes as hex");
        assert!(s.bytes().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(s, random_salt(), "a fixed salt would be a bug");
    }

    #[test]
    fn garbage_is_not_mistaken_for_a_frame() {
        assert_eq!(parse(&[]), Frame::Unknown);
        assert_eq!(parse(&[0xFF, 0xFF, 0xFF]), Frame::Unknown);
    }

    /// A control frame whose oneof arm is missing must not read as a request.
    #[test]
    fn a_control_frame_with_no_body_is_unknown() {
        let mut w = Writer::new();
        w.bytes(MF_HEADER, &header(&[1, 2, 3], "salt"))
            .varint(MF_FRAME_TYPE, FRAME_TYPE_CONTROL)
            .bytes(MF_CONTROL_FRAME, &[]);
        assert_eq!(parse(&w.finish()), Frame::Unknown);
    }

    #[test]
    fn truncation_does_not_panic() {
        let salt = random_salt();
        let h = salted_service_id_hash(SERVICE_ID, &salt);
        let full = data(&h, &salt, b"a longer payload to cut through");
        for cut in 0..full.len() {
            let _ = parse(&full[..cut]);
        }
    }
}

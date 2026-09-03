//! Quick Share over BLE: the wake-up pulse, and the advertisement that finds peers.
//!
//! Two separate things live here, and this module originally conflated them.
//!
//! **The FastInitiation pulse** (`0xFE2C`, below) is a doorbell: a sender with an active
//! share intent broadcasts it to wake idle receivers. It carries no name, no address and
//! no endpoint to connect to.
//!
//! **The endpoint advertisement** (`0xFEF3`, at the bottom) is the directory, and it is
//! what discovery actually uses. It carries the endpoint id and endpoint info.
//!
//! That distinction was established by measurement, not by reading. In a capture taken
//! beside an actively-sharing Android device and a Windows machine running Quick Share,
//! there were **zero** `0xFE2C` pulses over several minutes and hundreds of `0xFEF3`
//! advertisements. An earlier version of this file said the pulse was "how devices notice
//! each other with no network", which is wrong: it is how a sender wakes a receiver that
//! is already able to be found.
//!
//! ```text
//!   fc 12 8e VV PP UU AA AA AA AA AA AA AA AA SS HH HH HH HH HH HH HH HH
//!   |-model id-| |             uwb              | salt |-- secret_id_hash --|
//!                 ^  ^
//!                 |  adjusted tx power
//!                 metadata: version(3) type(3) uwb(1) sender_cert(1)
//! ```
//!
//! 23 bytes, which fits inside the 31-byte legacy advertising PDU alongside the 16-bit
//! service-data wrapper. That budget is why the format is this cramped.
//!
//! **Two bytes here are field-test knowledge, not schema, and both fail quietly.**
//!
//! The metadata byte is `0x00`, not `0x01`. Setting the low bit marks
//! `sender_cert_supported`, and Samsung's One UI reads the result as `type=SILENT` --
//! a pulse that is received, parsed, and then deliberately ignored. It looks exactly
//! like a device that is out of range.
//!
//! The `secret_id_hash` must be NON-ZERO. Samsung treats an all-zero hash as "no real
//! share intent" and demotes the pulse the same way, regardless of what the metadata
//! byte says. Hashing the endpoint id gives a stable non-zero value and costs nothing.
//!
//! Pure computation, no Android: the app owns the radio and hands these bytes to
//! `BluetoothLeAdvertiser`, which is what lets the format be tested here.

use openssl::hash::{hash, MessageDigest};

/// Quick Share's assigned 16-bit service UUID. Stock Quick Share, Windows Quick Share
/// and NearDrop all use it.
pub const SERVICE_UUID_16: u16 = 0xFE2C;

/// The same UUID in the 128-bit form a scan filter compares against, derived by
/// substituting into the Bluetooth Base UUID.
pub const SERVICE_UUID_128: &str = "0000fe2c-0000-1000-8000-00805f9b34fb";

/// `kFastInitModelId` — the magic that says this pulse is Quick Share.
const MODEL_ID: [u8; 3] = [0xFC, 0x12, 0x8E];

/// `version=0, type=kNotify=0, uwb=0, sender_cert=0`.
///
/// NOT 0x01. See the module docs: the low bit gets a Samsung receiver to classify the
/// pulse as SILENT and ignore it, which is indistinguishable from being out of range.
const METADATA: u8 = 0x00;

/// The unsigned negation of `kAdjustedTxPower` (-66 dBm).
const TX_POWER: u8 = 0x42;

const PREFIX_LEN: usize = 14;
const SALT_LEN: usize = 1;
/// Truncated SHA-256 over the endpoint id.
pub const SECRET_ID_HASH_LEN: usize = 8;
/// 14 fixed + 1 salt + 8 hash.
pub const PAYLOAD_LEN: usize = PREFIX_LEN + SALT_LEN + SECRET_ID_HASH_LEN;

/// A decoded pulse. Deliberately thin -- there is nothing else in it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FastInit {
    /// Per-session, so a receiver can dedupe back-to-back broadcasts.
    pub salt: u8,
    /// Identifies the sender across pulses without naming it.
    pub secret_id_hash: [u8; SECRET_ID_HASH_LEN],
}

/// The 8-byte hash a given endpoint id produces.
pub fn secret_id_hash(endpoint_id: &str) -> [u8; SECRET_ID_HASH_LEN] {
    let mut out = [0u8; SECRET_ID_HASH_LEN];
    // SHA-256 cannot fail on a byte slice; an empty id would still hash, and the caller
    // is prevented from passing one by `build`.
    if let Ok(d) = hash(MessageDigest::sha256(), endpoint_id.as_bytes()) {
        out.copy_from_slice(&d[..SECRET_ID_HASH_LEN]);
    }
    out
}

/// Build a pulse for `endpoint_id` with a caller-supplied salt.
///
/// The salt is a parameter rather than drawn here so it can stay stable across a
/// Bluetooth restart within one share session -- a receiver that dedupes on it should
/// see one session, not two.
pub fn build(endpoint_id: &str, salt: u8) -> Option<Vec<u8>> {
    if endpoint_id.is_empty() {
        return None;
    }
    let mut out = Vec::with_capacity(PAYLOAD_LEN);
    out.extend_from_slice(&MODEL_ID);
    out.push(METADATA);
    out.push(TX_POWER);
    // uwb_metadata and the 8-byte uwb_address, all zero: we do not advertise UWB.
    out.extend_from_slice(&[0u8; 9]);
    out.push(salt);
    out.extend_from_slice(&secret_id_hash(endpoint_id));
    debug_assert_eq!(out.len(), PAYLOAD_LEN);
    Some(out)
}

/// Build with a fresh random salt.
pub fn build_random(endpoint_id: &str) -> Option<Vec<u8>> {
    let mut b = [0u8; 1];
    openssl::rand::rand_bytes(&mut b).ok()?;
    build(endpoint_id, b[0])
}

/// Is this service data a Quick Share pulse?
///
/// Checks the model id and the length only. The metadata and power bytes are NOT
/// required to match ours -- other implementations legitimately differ there, and a
/// scanner that insisted on our own values would ignore stock senders.
pub fn is_fast_init(data: &[u8]) -> bool {
    data.len() >= PAYLOAD_LEN && data[..3] == MODEL_ID
}

/// Decode a pulse, or None if it is not one.
pub fn parse(data: &[u8]) -> Option<FastInit> {
    if !is_fast_init(data) {
        return None;
    }
    let mut hash = [0u8; SECRET_ID_HASH_LEN];
    hash.copy_from_slice(&data[PREFIX_LEN + SALT_LEN..PAYLOAD_LEN]);
    Some(FastInit {
        salt: data[PREFIX_LEN],
        secret_id_hash: hash,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_pulse_is_twenty_three_bytes() {
        let p = build("ABCD", 0x5A).unwrap();
        assert_eq!(p.len(), PAYLOAD_LEN);
        assert_eq!(p.len(), 23);
        // Comfortably inside the legacy advertising budget, which is the constraint the
        // whole format is shaped by.
        assert!(p.len() + 4 <= 31, "will not fit a legacy advertising PDU");
    }

    /// The exact bytes, checked against the documented layout rather than against our
    /// own builder -- otherwise the test only proves the code agrees with itself.
    #[test]
    fn the_prefix_is_the_documented_literal() {
        let p = build("ABCD", 0x00).unwrap();
        assert_eq!(&p[..3], &[0xFC, 0x12, 0x8E], "model id");
        assert_eq!(p[3], 0x00, "metadata must be 0x00, not 0x01");
        assert_eq!(p[4], 0x42, "adjusted tx power");
        assert_eq!(&p[5..14], &[0u8; 9], "uwb fields are zero");
    }

    /// The regression this guards is invisible on the wire: a Samsung receiver parses
    /// the pulse, classifies it SILENT, and ignores it. It looks like being out of range.
    #[test]
    fn the_metadata_byte_never_sets_the_sender_cert_bit() {
        for id in ["A", "ABCD", "an endpoint"] {
            let p = build(id, 0x11).unwrap();
            assert_eq!(p[3] & 0x01, 0, "sender_cert bit set for {id:?}");
        }
    }

    /// Samsung demotes an all-zero hash the same way. Any real endpoint id must produce
    /// a non-zero one.
    #[test]
    fn the_secret_id_hash_is_never_all_zero() {
        for id in ["A", "ABCD", "WXYZ", "Pixel 10 Pro XL"] {
            let h = secret_id_hash(id);
            assert_ne!(h, [0u8; SECRET_ID_HASH_LEN], "all-zero hash for {id:?}");
        }
    }

    #[test]
    fn the_hash_is_stable_and_distinct() {
        assert_eq!(secret_id_hash("ABCD"), secret_id_hash("ABCD"));
        assert_ne!(secret_id_hash("ABCD"), secret_id_hash("ABCE"));
    }

    /// SHA-256("ABCD") =
    /// e12e115acf4552b2568b55e93cbd39394c4ef81c82447fafc997882a02d23677,
    /// so the first eight bytes are the hash we embed. Checked against the digest rather
    /// than against our own output.
    #[test]
    fn the_hash_is_the_first_eight_bytes_of_sha256() {
        let full = hash(MessageDigest::sha256(), b"ABCD").unwrap();
        assert_eq!(secret_id_hash("ABCD")[..], full[..8]);
    }

    #[test]
    fn a_pulse_round_trips() {
        let p = build("WXYZ", 0x7E).unwrap();
        let got = parse(&p).unwrap();
        assert_eq!(got.salt, 0x7E);
        assert_eq!(got.secret_id_hash, secret_id_hash("WXYZ"));
    }

    #[test]
    fn an_empty_endpoint_id_is_refused() {
        assert!(build("", 0).is_none());
    }

    /// A scanner must accept pulses whose metadata differs from ours -- other
    /// implementations set those bytes differently and are still Quick Share.
    #[test]
    fn a_foreign_metadata_byte_is_still_recognised() {
        let mut p = build("ABCD", 1).unwrap();
        p[3] = 0x01; // what an older sender emits
        p[4] = 0x40; // a different tx power
        assert!(is_fast_init(&p));
        assert!(parse(&p).is_some());
    }

    #[test]
    fn other_service_data_is_not_mistaken_for_a_pulse() {
        assert!(!is_fast_init(&[]));
        assert!(!is_fast_init(&[0xFC, 0x12, 0x8E])); // right magic, too short
        let mut wrong = build("ABCD", 1).unwrap();
        wrong[0] = 0x00;
        assert!(!is_fast_init(&wrong));
        assert!(parse(&wrong).is_none());
    }

    #[test]
    fn truncation_does_not_panic() {
        let p = build("ABCD", 1).unwrap();
        for cut in 0..p.len() {
            assert!(parse(&p[..cut]).is_none());
        }
    }

    #[test]
    fn a_random_salt_still_produces_a_valid_pulse() {
        let a = build_random("ABCD").unwrap();
        assert!(is_fast_init(&a));
        assert_eq!(parse(&a).unwrap().secret_id_hash, secret_id_hash("ABCD"));
    }
}

// --------------------------------------------------- the endpoint advertisement ---
//
// The FastInit pulse above is a doorbell. THIS is the directory: the Nearby Connections
// BLE advertisement, on service 0xFEF3, is what actually carries a peer's identity and
// is how a Quick Share device is found with no network.
//
// Worth stating plainly, because this module originally claimed otherwise: in a capture
// taken next to an actively-sharing Android device and a Windows machine running Quick
// Share, there were ZERO 0xFE2C pulses over several minutes, and hundreds of 0xFEF3
// advertisements. Discovery happens here.
//
// The layout below is READ FROM CAPTURED TRAFFIC, not from a specification, and the
// parts that are guesses are marked as such. Three independent samples from two devices
// agreed on every field asserted here.
//
//     4a 17 23 | 39 32 58 4d | 11 | 32 <16 more> | xx xx
//     |  |  |    |             |    |              |
//     |  |  |    |             |    |              two trailing bytes, purpose unknown
//     |  |  |    |             |    endpoint info: flags, 2-byte salt, 14-byte key
//     |  |  |    |             endpoint info length, 0x11 = 17
//     |  |  |    endpoint id, four ASCII characters ("92XM", "WDKH", "BRJ6")
//     |  |  constant across every sample; meaning not established
//     |  constant across every sample; 0x17 = 23 = payload length minus four
//     version and flags; bit 1 set marks a fast advertisement

/// Nearby Connections' assigned service. Quick Share advertises its endpoints here.
pub const NEARBY_SERVICE_UUID_16: u16 = 0xFEF3;

/// Where the endpoint id starts, and how long it is.
const ADVERT_ENDPOINT_ID_AT: usize = 3;
/// Four ASCII characters, the same identifier that appears in a ConnectionRequest and
/// in the mDNS instance name.
pub const ENDPOINT_ID_LEN: usize = 4;
/// The byte holding the endpoint-info length.
const ADVERT_INFO_LEN_AT: usize = 7;
/// Shortest thing that can still contain an endpoint id and an info length.
const ADVERT_MIN_LEN: usize = ADVERT_INFO_LEN_AT + 1;

/// A peer found over BLE.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Advertisement {
    /// Four ASCII characters identifying the endpoint.
    pub endpoint_id: String,
    /// Opaque here. For Quick Share it is flags, a 2-byte salt, and a 14-byte encrypted
    /// metadata key -- decrypting the name needs a contact certificate we do not have
    /// and do not want, so it is carried rather than interpreted.
    pub endpoint_info: Vec<u8>,
}

/// Parse a Nearby Connections BLE advertisement.
///
/// Conservative on purpose: the layout came from captures, so this validates what it can
/// (the endpoint id is printable ASCII, the declared info length fits) and refuses
/// anything else rather than returning fields it is not confident in. A wrong endpoint id
/// is worse than no peer -- it produces a connection attempt to something that will not
/// answer.
pub fn parse_advertisement(data: &[u8]) -> Option<Advertisement> {
    if data.len() < ADVERT_MIN_LEN + ENDPOINT_ID_LEN {
        return None;
    }
    let id = &data[ADVERT_ENDPOINT_ID_AT..ADVERT_ENDPOINT_ID_AT + ENDPOINT_ID_LEN];
    // Every endpoint id seen on the wire is printable ASCII, and ours is generated that
    // way too. Anything else means this is not the advertisement shape we decoded.
    if !id.iter().all(|c| c.is_ascii_graphic()) {
        return None;
    }
    let info_len = data[ADVERT_INFO_LEN_AT] as usize;
    let start = ADVERT_INFO_LEN_AT + 1;
    if info_len == 0 || start + info_len > data.len() {
        return None;
    }
    Some(Advertisement {
        endpoint_id: String::from_utf8_lossy(id).into_owned(),
        endpoint_info: data[start..start + info_len].to_vec(),
    })
}

#[cfg(test)]
mod advertisement_tests {
    use super::*;

    /// Captured 2026-09-03 from two devices running stock Quick Share, on 0xFEF3.
    /// See docs/QUICKSHARE-VECTORS.md.
    const CAPTURED: [&str; 3] = [
        "4a17233932584d1132b3480eb85b8b562fcefb2077e73494e5f264",
        "4a172357444b4811320f75aa376a6c91683c1583cf24accd3c2536",
        "4a172342524a361132e88e4a78a8c8399b84fcc5a2404ee85f2d94",
    ];

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// The whole point: real bytes from real devices, decoded.
    #[test]
    fn the_captured_advertisements_decode() {
        let want = ["92XM", "WDKH", "BRJ6"];
        for (hex, id) in CAPTURED.iter().zip(want) {
            let a = parse_advertisement(&unhex(hex)).expect("should parse");
            assert_eq!(a.endpoint_id, id);
            // 1 flags + 2 salt + 14 key. That this is exactly 17 across three samples
            // from two devices is what makes the layout credible.
            assert_eq!(a.endpoint_info.len(), 17);
        }
    }

    #[test]
    fn an_endpoint_id_that_is_not_ascii_is_refused() {
        let mut b = unhex(CAPTURED[0]);
        b[ADVERT_ENDPOINT_ID_AT] = 0x00;
        assert!(parse_advertisement(&b).is_none());
    }

    /// A declared length running past the buffer must be refused, not truncated into
    /// something that looks like a peer.
    #[test]
    fn an_overlong_info_length_is_refused() {
        let mut b = unhex(CAPTURED[0]);
        b[ADVERT_INFO_LEN_AT] = 0xFF;
        assert!(parse_advertisement(&b).is_none());
    }

    /// The idle background advertisements seen in the same capture are 17 bytes and a
    /// different shape. They must not be mistaken for peers.
    #[test]
    fn the_idle_background_advertisements_are_not_peers() {
        for hex in [
            "5120001111020000232000557834460000",
            "512210001002040803200082db0adb0000",
            "5128000010024020231000158513940000",
        ] {
            let b = unhex(hex);
            if let Some(a) = parse_advertisement(&b) {
                panic!("idle advertisement parsed as peer {a:?}");
            }
        }
    }

    #[test]
    fn truncation_does_not_panic() {
        let b = unhex(CAPTURED[0]);
        for cut in 0..b.len() {
            let _ = parse_advertisement(&b[..cut]);
        }
    }
}

//! The Quick Share BLE beacon — how devices notice each other with no network.
//!
//! This is the **FastInitiation** pulse: a sender with an active share intent broadcasts
//! it on service `0xFE2C`, and nearby receivers wake up and start advertising themselves
//! properly. It is a doorbell, not a directory — it carries no name, no address and no
//! endpoint to connect to. What it does is get a receiver that was idle to become
//! discoverable, which is the step that makes discovery possible without a network for
//! anything to be discovered *on*.
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

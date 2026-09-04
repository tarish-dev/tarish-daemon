//! Quick Share's service identity, and the addresses derived from it.
//!
//! Everything here comes from one string, `"NearbySharing"`. Nearby Connections derives
//! its mDNS service type, its BLE service-id hash, and its Bluetooth RFCOMM service UUID
//! from that name, so a peer can be found and reached without any of those values being
//! configured or exchanged.
//!
//! Derivation credit: Bada's `NearbyServiceId.kt` (Apache 2.0), which is where the
//! Bluetooth UUID derivation came from. It is not guessable from a capture — an RFCOMM
//! service UUID never appears on the air.

use openssl::hash::{hash, MessageDigest};

/// The service name every derivation below starts from.
pub const SERVICE_ID: &str = "NearbySharing";

/// `sha256("NearbySharing")[..3]`, the fingerprint in a BLE advertisement.
pub fn service_id_hash() -> [u8; 3] {
    let mut out = [0u8; 3];
    if let Ok(d) = hash(MessageDigest::sha256(), SERVICE_ID.as_bytes()) {
        out.copy_from_slice(&d[..3]);
    }
    out
}

/// The RFCOMM service UUID a stock Quick Share peer listens on.
///
/// **This is how you connect to a peer with no network.** BLE discovery gives a Bluetooth
/// MAC; this gives the service on it to open. Neither is guessable from a capture, because
/// an RFCOMM service UUID never appears on the air — it is looked up over SDP.
///
/// A type-3 (MD5, name-based) UUID over the service name, which is what
/// `UUID.nameUUIDFromBytes` produces and what Nearby Connections' Bluetooth Classic
/// transport uses.
///
/// **Do not confuse it with an implementation's own listener.** Bada, for instance,
/// defaults its RFCOMM provider to `…f16da7b16c1a` under the service name
/// `BadaQuickShareRfcomm` — one byte different from the derived value, and deliberately
/// its own. Connecting to a stock peer on that UUID finds nothing, and finds it silently:
/// SDP simply reports no such service.
pub fn bluetooth_service_uuid() -> String {
    let d = match hash(MessageDigest::md5(), SERVICE_ID.as_bytes()) {
        Ok(d) => d,
        // MD5 over a fixed 13-byte string cannot fail; the fallback keeps this
        // infallible for callers rather than making every one of them handle an error
        // that cannot happen.
        Err(_) => return String::new(),
    };
    let mut b = [0u8; 16];
    b.copy_from_slice(&d[..16]);
    // RFC 4122: version 3 in the high nibble of byte 6, variant 10x in byte 8.
    b[6] = (b[6] & 0x0f) | 0x30;
    b[8] = (b[8] & 0x3f) | 0x80;

    let h: String = b.iter().map(|x| format!("{x:02x}")).collect();
    format!(
        "{}-{}-{}-{}-{}",
        &h[0..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..32]
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pinned. If this value changes, every stock peer becomes unreachable over
    /// Bluetooth and nothing says why — SDP just reports no such service.
    #[test]
    fn the_bluetooth_service_uuid_is_the_derived_one() {
        assert_eq!(
            bluetooth_service_uuid(),
            "a82efa21-ae5c-3dde-9bbc-f16da7b16c5a"
        );
    }

    /// The value Bada defaults its own RFCOMM listener to differs in the last byte.
    /// Asserting they are different is the point: it is exactly the sort of thing that
    /// gets copied across by eye and then fails silently.
    #[test]
    fn it_is_not_badas_own_listener_uuid() {
        assert_ne!(
            bluetooth_service_uuid(),
            "a82efa21-ae5c-3dde-9bbc-f16da7b16c1a"
        );
    }

    #[test]
    fn it_is_a_well_formed_version_3_uuid() {
        let u = bluetooth_service_uuid();
        assert_eq!(u.len(), 36);
        // Version nibble.
        assert_eq!(u.as_bytes()[14], b'3');
        // Variant: 8, 9, a or b.
        assert!(matches!(u.as_bytes()[19], b'8' | b'9' | b'a' | b'b'));
    }

    /// The same three bytes the BLE advertisement carries, from the same name.
    #[test]
    fn the_service_id_hash_matches_the_advertisement_fingerprint() {
        assert_eq!(service_id_hash(), crate::ble::SERVICE_ID_HASH);
    }
}

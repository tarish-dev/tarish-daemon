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
// BLE advertisement, on service 0xFEF3, carries a peer's identity and -- crucially -- its
// Bluetooth MAC, which is how a device is reached when there is no network at all.
//
// Worth stating plainly, because this module originally claimed otherwise: in a capture
// taken next to an actively-sharing Android device and a Windows machine running Quick
// Share, there were ZERO 0xFE2C pulses over several minutes and hundreds of 0xFEF3
// advertisements. Discovery happens here.
//
// FORMAT CREDIT: the field names and their meanings are Bada's
// (core-protocol/.../endpoint/BleServiceData.kt, Apache 2.0). This layout was first
// reconstructed here from captures, which got the structure right and the labels wrong --
// "constant across samples, meaning not established" turned out to be a body length and a
// version/PCP byte. Reading Bada settled all of it.
//
//     body:  versPCP | [service_id_hash 3] | endpoint_id 4 | info_len | EndpointInfo | [mac 6]
//
// `versPCP` packs version (3 bits) and PCP (5 bits); stock peers emit version 1, PCP_HIGH,
// giving 0x23. The service-id hash and the trailing MAC are present in the REGULAR form
// and absent from the FAST form, which is the whole difference between them.
//
// The body sits inside a frame whose header differs between captures -- two bytes on the
// Android peers, eight on the Windows one. Rather than hardcode either, the body is found
// by its own internal consistency: a version byte followed by the service-id hash, then a
// four-character ASCII endpoint id and a length that fits. That is robust to a wrapper we
// have not fully characterised, and refuses anything that merely looks similar.

/// Nearby Connections' assigned service. Quick Share advertises its endpoints here.
pub const NEARBY_SERVICE_UUID_16: u16 = 0xFEF3;

/// `sha256("NearbySharing")[..3]` — marks an advertisement as Quick Share rather than
/// some other Nearby Connections service.
pub const SERVICE_ID_HASH: [u8; 3] = [0xFC, 0x9F, 0x5E];

/// Four ASCII characters, the same identifier that appears in a ConnectionRequest and in
/// the mDNS instance name.
pub const ENDPOINT_ID_LEN: usize = 4;
/// Bluetooth Classic MAC, in the regular form only.
const MAC_LEN: usize = 6;
/// Two bytes of device token sit between the body and the optional trailing fields.
const DEVICE_TOKEN_LEN: usize = 2;
/// Bit 0 of the trailing-field mask: an L2CAP PSM follows.
const EXTRA_FIELD_PSM: u8 = 0x01;
/// Where the name length sits inside EndpointInfo: after flags, a 2-byte salt and a
/// 14-byte encrypted metadata key.
const NAME_LEN_AT: usize = 17;

/// A peer found over BLE.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Advertisement {
    /// Four ASCII characters identifying the endpoint.
    pub endpoint_id: String,
    /// Flags, a 2-byte salt, a 14-byte encrypted metadata key, and -- when the peer is
    /// visible to everyone -- a length-prefixed device name after them.
    pub endpoint_info: Vec<u8>,
    /// The name, when the peer published one in the clear. `None` for a contacts-only
    /// peer, whose name is inside the encrypted key and needs a certificate rooted in a
    /// Google account to read. That is not a gap to close: a device that will not say its
    /// name in the clear is one we cannot identify, and reporting the endpoint id is
    /// honest.
    pub device_name: Option<String>,
    /// Whether the advertisement carried the NearbySharing service-id hash.
    ///
    /// Only the REGULAR form has one. A fast advertisement omits it entirely, so a peer
    /// found that way is structurally valid but not *provably* Quick Share -- the same
    /// service carries other Nearby services in the same shape. Reported rather than
    /// decided here: the caller knows whether it would rather miss a peer or list one it
    /// cannot talk to.
    pub verified: bool,
    /// **How to reach this peer with no network.** Present in the regular form; `None` in
    /// the fast form, and `None` when the advertiser zeroed it, which means it has no
    /// BR/EDR listener to connect to.
    pub bluetooth_mac: Option<String>,
    /// The L2CAP connection-oriented-channel PSM the peer is listening on, if it
    /// published one.
    ///
    /// **This is a peer saying where to connect, and it is not decoration.** A stock
    /// Pixel advertising a PSM refuses an RFCOMM connection on the Nearby service --
    /// accepted and closed inside 200 ms, no frame either way -- while a Windows peer,
    /// which publishes no PSM, accepts RFCOMM and completes a whole transfer. Same
    /// sender, same code, opposite outcome; the PSM is what tells them apart.
    ///
    /// It sits in the OPTIONAL trailing fields, after the frame's own device token, so
    /// it is easy to advertise and easy to never notice.
    pub psm: Option<u16>,
}

/// Pull the device name out of endpoint info, if it is there in the clear.
/// The device name out of an EndpointInfo structure, when the peer published one.
///
/// Public because the same structure arrives two ways: in a BLE advertisement, and in a
/// ConnectionRequest's `endpoint_info`. One decoder for both -- parsing it a second time
/// elsewhere is how the two drift.
pub fn name_from_endpoint_info(info: &[u8]) -> Option<String> {
    name_from_info(info)
}

fn name_from_info(info: &[u8]) -> Option<String> {
    let len = *info.get(NAME_LEN_AT)? as usize;
    let start = NAME_LEN_AT + 1;
    let end = start.checked_add(len)?;
    if len == 0 || end > info.len() {
        return None;
    }
    let name = String::from_utf8_lossy(&info[start..end]).into_owned();
    // A name of control characters is not a name. Refusing keeps a peer list honest
    // rather than filling it with squares.
    if name.chars().any(|c| c.is_control()) {
        return None;
    }
    Some(name)
}

/// All zeroes means "no BR/EDR listener", not an address.
fn format_mac(b: &[u8]) -> Option<String> {
    if b.len() != MAC_LEN || b.iter().all(|&x| x == 0) {
        return None;
    }
    Some(
        b.iter()
            .map(|x| format!("{x:02X}"))
            .collect::<Vec<_>>()
            .join(":"),
    )
}

/// Parse a Quick Share BLE endpoint advertisement.
///
/// Finds the body wherever it sits rather than assuming a frame header, and validates
/// what it finds. Returning a wrong endpoint id would be worse than returning nothing --
/// it produces a connection attempt to something that will never answer.
/// Build the REGULAR form of a Quick Share endpoint advertisement.
///
/// The mirror of `framed`/`body_at`, and deliberately the regular form only:
///
/// ```text
///   0x48 | hash:3 | len:4 | body | token:2 | mask:1 [psm:2]
///   body = versPCP:1 | hash:3 | endpoint_id:4 | info_len:1 | info | mac:6
/// ```
///
/// The fast form omits the service-id hash, which is exactly what makes a peer found that
/// way unverifiable -- `parse_advertisement` marks it `verified: false`. A receiver has no
/// reason to be less identifiable than it can be, so we always publish the hash.
///
/// `psm` is the L2CAP PSM to publish, or `None`. It is not cosmetic: a peer that sees a PSM
/// opens an L2CAP channel and REFUSES RFCOMM, and a peer that sees none does the opposite.
/// Publish what is actually listening.
///
/// The round-trip against real captures is the test that matters -- `parse_advertisement`
/// was built from a Pixel's and a Windows machine's own bytes, so anything it reads back
/// identically is a shape those devices produce.
pub fn build_advertisement(
    endpoint_id: &str,
    endpoint_info: &[u8],
    bluetooth_mac: Option<[u8; MAC_LEN]>,
    device_token: [u8; DEVICE_TOKEN_LEN],
    psm: Option<u16>,
) -> Option<Vec<u8>> {
    if endpoint_id.len() != ENDPOINT_ID_LEN
        || !endpoint_id.bytes().all(|c| c.is_ascii_graphic())
        || endpoint_info.is_empty()
        || endpoint_info.len() > u8::MAX as usize
    {
        return None;
    }

    let mut body = Vec::new();
    // versPCP = 0x23: version 1 in the top three bits, PCP 3 in the low five. Both captured
    // devices send exactly this. An earlier version of this function sent 0x16, which was
    // the info_len byte misread out of the same capture -- and nothing rejects a wrong
    // version, the advertisement is simply never recognised.
    body.push(0x23);
    body.extend_from_slice(&SERVICE_ID_HASH);
    body.extend_from_slice(endpoint_id.as_bytes());
    body.push(endpoint_info.len() as u8);
    body.extend_from_slice(endpoint_info);
    if let Some(mac) = bluetooth_mac {
        body.extend_from_slice(&mac);
        // TWO ZERO BYTES after the address, inside the body. Both captures carry them and
        // the decoder ignores them, so their meaning is unknown -- which is exactly why they
        // are reproduced rather than dropped. A body two bytes shorter than every real one
        // is a difference we would be choosing without knowing what it costs.
        body.extend_from_slice(&[0, 0]);
    }

    let mut out = Vec::new();
    // Header: version 2, socket version 2, regular form. Matches both captures.
    out.push(0x48);
    out.extend_from_slice(&SERVICE_ID_HASH);
    out.extend_from_slice(&(body.len() as u32).to_be_bytes());
    out.extend_from_slice(&body);
    out.extend_from_slice(&device_token);
    // NO MASK BYTE AT ALL when there is no PSM. The Windows capture ends at the device
    // token; the Pixel one carries mask 0x01 and a PSM. So the field is absent rather than
    // zero, and this followed a guess -- with a confident comment attached -- until the two
    // captures were actually compared.
    if let Some(p) = psm.filter(|p| *p != 0) {
        out.push(EXTRA_FIELD_PSM);
        out.extend_from_slice(&p.to_be_bytes());
    }
    Some(out)
}

pub fn parse_advertisement(data: &[u8]) -> Option<Advertisement> {
    // The framed read FIRST, because it is the only one that can find the trailing
    // fields. The body is length-delimited, so the extras start at a known offset; the
    // scan below cannot know where the body ended and so can never see a PSM.
    if let Some(a) = framed(data) {
        return Some(a);
    }

    // FALLBACK: find the body by its own internal consistency.
    //
    // Kept because it is what worked before the frame header was understood, and a
    // wrapper we have not characterised should degrade to "a peer with no PSM" rather
    // than to "no peer". A peer found this way is still reachable over Bluetooth.
    for i in 1..data.len().saturating_sub(SERVICE_ID_HASH.len()) {
        if data[i..i + SERVICE_ID_HASH.len()] != SERVICE_ID_HASH {
            continue;
        }
        if let Some(a) = body_at(data, i - 1, true) {
            return Some(a);
        }
    }
    body_at(data, 2, false)
}

/// Nearby's Mediums frame: a header, a length-delimited body, a device token, and
/// optional trailing fields.
///
/// ```text
///   fast     0x4A | len:1  | body | token:2 | [mask:1 [psm:2] [rx_len:1 rx:n]]
///   regular  0x48 | hash:3 | len:4 | body | token:2 | [mask ...]
/// ```
///
/// Format credit: Bada's `BleAdvertisement.kt` (Apache 2.0). Reconstructing this from
/// captures got as far as the body and stopped there -- the trailing bytes read as
/// padding, and a PSM is two of them.
fn framed(data: &[u8]) -> Option<Advertisement> {
    let header = *data.first()?;
    let version = (header & 0xE0) >> 5;
    let socket_version = (header & 0x1C) >> 2;
    let fast = header & 0x02 != 0;
    // Refuses anything whose header is not a version this format has ever had, which is
    // what stops an unrelated 0xFEF3 service being read as a peer.
    if !(1..=2).contains(&version) || !(1..=2).contains(&socket_version) {
        return None;
    }

    let mut o = 1usize;
    let body_len = if fast {
        let n = *data.get(o)? as usize;
        o += 1;
        n
    } else {
        if data.get(o..o + SERVICE_ID_HASH.len())? != SERVICE_ID_HASH {
            return None;
        }
        o += SERVICE_ID_HASH.len();
        let n = u32::from_be_bytes(data.get(o..o + 4)?.try_into().ok()?) as usize;
        o += 4;
        n
    };

    let body_start = o;
    let body_end = o.checked_add(body_len)?;
    if body_end > data.len() {
        return None;
    }
    let mut advert = body_at(data, body_start, !fast)?;

    // Past the body: two bytes of device token, then the optional fields.
    let mut p = body_end.checked_add(DEVICE_TOKEN_LEN)?;
    if let Some(&mask) = data.get(p) {
        p += 1;
        if mask & EXTRA_FIELD_PSM != 0 {
            let raw = data.get(p..p + 2)?;
            let psm = u16::from_be_bytes([raw[0], raw[1]]);
            // Zero is "no listener", not PSM 0.
            if psm != 0 {
                advert.psm = Some(psm);
            }
        }
    }
    Some(advert)
}

/// Read a body starting at `at`, where `at` is the version byte.
fn body_at(data: &[u8], at: usize, regular: bool) -> Option<Advertisement> {
    let mut o = at.checked_add(1)?; // past versPCP
    if regular {
        o = o.checked_add(SERVICE_ID_HASH.len())?;
    }
    let id_end = o.checked_add(ENDPOINT_ID_LEN)?;
    let id = data.get(o..id_end)?;
    // Every endpoint id on the wire is printable ASCII, and ours is generated that way.
    // This is what stops a run of arbitrary bytes being read as a peer.
    if !id.iter().all(|c| c.is_ascii_graphic()) {
        return None;
    }
    let info_len = *data.get(id_end)? as usize;
    let info_start = id_end + 1;
    let info_end = info_start.checked_add(info_len)?;
    if info_len == 0 || info_end > data.len() {
        return None;
    }
    let info = data[info_start..info_end].to_vec();

    let bluetooth_mac = if regular {
        data.get(info_end..info_end + MAC_LEN).and_then(format_mac)
    } else {
        None
    };

    Some(Advertisement {
        endpoint_id: String::from_utf8_lossy(id).into_owned(),
        device_name: name_from_info(&info),
        endpoint_info: info,
        verified: regular,
        bluetooth_mac,
        // Filled by `framed`, which is the only caller that knows where the body ended.
        psm: None,
    })
}

#[cfg(test)]
mod advertisement_tests {
    use super::*;

    /// Captured 2026-09-05, side by side, on the same scan.
    ///
    /// These two decide which socket a sender opens, and they disagree. The Pixel
    /// publishes an L2CAP PSM and REFUSES an RFCOMM connection on the Nearby service --
    /// accepted, then closed within 200 ms, not a frame in either direction. The Windows
    /// machine publishes no PSM and completes a whole transfer over RFCOMM. Same sender,
    /// same code.
    const PIXEL_WITH_PSM: &str = "48fc9f5e0000002723fc9f5e574c545116223113fb32e346953\
6c622a25dd0711d85044b2d4e36541fcd6972640000e6a50100b1";
    const WINDOWS_NO_PSM: &str = "48fc9f5e0000002b23fc9f5e443742301a06ce1b46b462fc3fd\
d42301dd5ac4eed5c084b2d50726f4172749cc7d3e40de9000064ea";

    #[test]
    fn a_pixel_publishes_the_l2cap_psm_it_listens_on() {
        let a = parse_advertisement(&unhex(PIXEL_WITH_PSM)).expect("should parse");
        assert_eq!(a.endpoint_id, "WLTQ");
        assert_eq!(a.device_name.as_deref(), Some("K-N6"));
        assert_eq!(a.bluetooth_mac.as_deref(), Some("54:1F:CD:69:72:64"));
        assert!(a.verified);
        assert_eq!(a.psm, Some(177), "the PSM is the whole point of this vector");
    }

    /// The other half of the pair. A peer with no PSM must report None rather than a
    /// stray number read out of the token bytes -- connecting L2CAP to a made-up PSM
    /// fails in exactly the way that looks like the peer being asleep.
    #[test]
    fn a_windows_peer_publishes_no_psm() {
        let a = parse_advertisement(&unhex(WINDOWS_NO_PSM)).expect("should parse");
        assert_eq!(a.endpoint_id, "D7B0");
        assert_eq!(a.device_name.as_deref(), Some("K-ProArt"));
        assert_eq!(a.bluetooth_mac.as_deref(), Some("9C:C7:D3:E4:0D:E9"));
        assert_eq!(a.psm, None);
    }

    /// The fast form carries no trailing fields at all, and reading past its body must
    /// not invent one.
    #[test]
    fn the_fast_form_reports_no_psm() {
        for v in CAPTURED {
            let a = parse_advertisement(&unhex(v)).expect("should parse");
            assert_eq!(a.psm, None, "fast form should carry no PSM: {v}");
        }
    }

    /// Truncation anywhere must not panic and must not produce a half-read PSM.
    #[test]
    fn a_truncated_advertisement_yields_no_psm() {
        let full = unhex(PIXEL_WITH_PSM);
        for cut in 0..full.len() - 1 {
            if let Some(a) = parse_advertisement(&full[..cut]) {
                assert_eq!(a.psm, None, "partial PSM read at {cut} bytes");
            }
        }
    }

    /// Captured 2026-09-03 from two devices running stock Quick Share, on 0xFEF3.
    /// See docs/QUICKSHARE-VECTORS.md.
    const CAPTURED: [&str; 3] = [
        "4a17233932584d1132b3480eb85b8b562fcefb2077e73494e5f264",
        "4a172357444b4811320f75aa376a6c91683c1583cf24accd3c2536",
        "4a172342524a361132e88e4a78a8c8399b84fcc5a2404ee85f2d94",
    ];

    /// THE ENCODER MUST REPRODUCE A REAL DEVICE, BYTE FOR BYTE.
    ///
    /// Deliberately not a round trip through our own decoder: that passes with a wrong
    /// version byte, a missing pad and an invented mask, because the decoder ignores all
    /// three. These are the bytes a Pixel and a Windows machine actually put on the air, and
    /// any difference from them is one we would be choosing blind.
    ///
    /// It caught exactly that. versPCP was being sent as 0x16 -- the info_len byte, misread
    /// out of this same capture -- with no zero pad after the address and a mask byte where
    /// Windows sends nothing. Nothing rejects any of it: the advertisement is simply never
    /// recognised, and the device is invisible with no error on either side.
    #[test]
    fn the_encoder_reproduces_real_advertisements() {
        for (name, hex) in [("Pixel", PIXEL_WITH_PSM), ("Windows", WINDOWS)] {
            let want = unhex(hex);
            let a = parse_advertisement(&want).expect("the capture should parse");
            let mac = a.bluetooth_mac.as_deref().map(|m| {
                let mut out = [0u8; MAC_LEN];
                for (i, part) in m.split(':').enumerate() {
                    out[i] = u8::from_str_radix(part, 16).unwrap();
                }
                out
            });
            // The device token sits between the body and the extras and the decoder does not
            // surface it, so take it from the capture -- this test is about everything else.
            let body_len = u32::from_be_bytes(want[4..8].try_into().unwrap()) as usize;
            let token = [want[8 + body_len], want[9 + body_len]];

            let got = build_advertisement(&a.endpoint_id, &a.endpoint_info, mac, token, a.psm)
                .unwrap_or_else(|| panic!("{name}: refused to build"));
            let hexed = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
            assert_eq!(
                hexed(&got),
                hexed(&want),
                "{name}: what we build differs from what the device sends"
            );
        }
    }

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// A Windows machine running Quick Share, visible to everyone. Captured 2026-09-03
    /// on 0xFEF3 -- and ONLY visible once the scanner asked for extended advertisements.
    const WINDOWS: &str = "48fc9f5e0000002b23fc9f5e425146551a06233429a1567e52933345\
fc86671defa6084b2d50726f4172749cc7d3e40de9000056ce";

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
            // No name in the clear: these are the contacts-only form.
            assert_eq!(a.device_name, None);
            // And no service-id hash, because the fast form has none.
            assert!(!a.verified);
        }
    }

    /// The one that matters: a real peer, identified by name, with no network and no
    /// Google account anywhere in the picture.
    #[test]
    fn the_windows_machine_decodes_with_its_name() {
        let a = parse_advertisement(&unhex(WINDOWS)).expect("should parse");
        assert_eq!(a.endpoint_id, "BQFU");
        // 1 flags + 2 salt + 14 key + 1 length + 8 name.
        assert!(a.verified, "carried the NearbySharing service-id hash");
        assert_eq!(a.endpoint_info.len(), 26);
        assert_eq!(a.device_name.as_deref(), Some("K-ProArt"));
        // THE POINT OF THE WHOLE EXERCISE: how to reach this peer with no network.
        assert_eq!(a.bluetooth_mac.as_deref(), Some("9C:C7:D3:E4:0D:E9"));
    }

    /// The fast form carries no MAC, and must not invent one from whatever follows.
    #[test]
    fn the_fast_form_has_no_bluetooth_mac() {
        for hex in CAPTURED {
            let a = parse_advertisement(&unhex(hex)).expect("should parse");
            assert_eq!(a.bluetooth_mac, None);
        }
    }

    /// An advertiser with no BR/EDR listener zeroes the field. That is "nothing to
    /// connect to", not an address of 00:00:00:00:00:00.
    #[test]
    fn a_zeroed_mac_is_reported_as_absent() {
        let mut b = unhex(WINDOWS);
        for i in 43..49 {
            b[i] = 0;
        }
        let a = parse_advertisement(&b).expect("still parses");
        assert_eq!(a.bluetooth_mac, None);
    }

    /// A name length running past the buffer must yield no name rather than a panic or
    /// a slice of whatever followed.
    #[test]
    fn an_overlong_name_length_yields_no_name() {
        let mut b = unhex(WINDOWS);
        // The name-length byte sits 17 into the endpoint info, which starts at 17.
        b[17 + 17] = 0xFF;
        let a = parse_advertisement(&b).expect("still parses");
        assert_eq!(a.device_name, None);
    }

    /// In the fast form the endpoint id sits at offset 3, after the frame header and the
    /// version byte. Corrupting it must yield nothing rather than a peer named with
    /// control characters.
    #[test]
    fn an_endpoint_id_that_is_not_ascii_is_refused() {
        let mut b = unhex(CAPTURED[0]);
        b[3] = 0x00;
        assert!(parse_advertisement(&b).is_none());
    }

    /// A declared length running past the buffer must be refused, not truncated into
    /// something that looks like a peer.
    /// A declared length running past the buffer must be refused, not truncated into
    /// something that looks like a peer.
    #[test]
    fn an_overlong_info_length_is_refused() {
        let mut b = unhex(CAPTURED[0]);
        b[7] = 0xFF;
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

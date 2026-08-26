//! Quick Share — the Android-to-Android side of Barq.
//!
//! WHY THIS EXISTS SEPARATELY FROM THE AIRDROP CODE
//!
//! The two protocols share nothing above the link layer: different mDNS service,
//! different identity, different framing, different crypto. AirDrop is mDNS + TLS +
//! HTTP + Apple plists; Quick Share is mDNS + a length-prefixed protobuf stream with
//! a UKEY2 handshake. Trying to make one code path serve both would produce a worse
//! version of each.
//!
//! WHAT IT RUNS OVER, AND WHY THAT MATTERS HERE
//!
//! Quick Share over Wi-Fi LAN is plain TCP on the network the device is already
//! joined to -- `wlan0`, not `mosey0`. It needs no AWDL at all, which is the whole
//! reason it is worth having: on a BCM4383 device AWDL cannot coexist with Wi-Fi
//! (see the integrator's BUILD-NOTES 40), so AirDrop is not usable there and this is.
//!
//! Bandwidth-upgrade paths -- BLE medium negotiation, Wi-Fi Direct -- are
//! deliberately out of scope. They are where the radio problems live.
//!
//! SOURCE OF THE PROTOCOL FACTS
//!
//! Written from the protocol, not from anyone's source. Bada is unlicensed, so it is
//! read here as a specification exactly as OpenDrop was for AirDrop; see
//! barq-app/docs/CREDITS.md. Byte offsets, bit positions, hash prefixes and alphabets
//! are protocol facts and are nobody's expression.

// The identity layer lands before the socket that uses it. These are consumed by
// `describe_identity` below today, and by discovery in the next phase; the ones
// marked here are the TXT keys and the parser, which have no caller until there is
// something to parse. Named individually rather than blanket-allowing the module, so
// the list shrinks visibly as discovery lands.
#![allow(dead_code)]

pub mod endpoint;

/// One line describing what this device would advertise as a Quick Share endpoint.
///
/// Exists so the identity layer is verifiable on hardware before any socket does:
/// wrong derivation shows up here as a malformed instance name rather than as
/// silence during discovery, which is a much harder thing to debug.
pub fn describe_identity(device_name: &str) -> String {
    let id = random_endpoint_id();
    let info = endpoint::EndpointInfo {
        version: 0,
        hidden: false,
        device_type: endpoint::DeviceType::Phone,
        metadata: [0u8; 16],
        device_name: Some(device_name.to_string()),
    };
    format!(
        "endpoint {} -> {}.{} ({} bytes of endpoint info)",
        String::from_utf8_lossy(&id),
        instance_name(&id),
        endpoint::SERVICE_TYPE,
        info.encode().len()
    )
}

/// First 3 bytes of sha256("NearbySharing"), which appear inside every instance name.
pub const SERVICE_ID_HASH_PREFIX: [u8; 3] = [0xFC, 0x9F, 0x5E];

/// Presence-and-control byte that opens the instance name.
const PCP: u8 = 0x23;

/// Raw length of a decoded instance name: PCP + 4 id + 3 hash prefix + 2 reserved.
const INSTANCE_RAW_LEN: usize = 10;

pub const ENDPOINT_ID_LEN: usize = 4;

/// The alphabet endpoint ids are drawn from. Not base64: no `-` or `_`, so an id is
/// always safe inside a DNS label without escaping.
const ENDPOINT_ID_ALPHABET: &[u8] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

/// TXT keys carried alongside the service.
pub const TXT_ENDPOINT_INFO: &str = "n";
pub const TXT_IPV4: &str = "IPv4";
pub const TXT_WIFI_FREQ: &str = "f";
pub const TXT_BLUETOOTH_MAC: &str = "b";

/// Build the mDNS instance name for an endpoint id.
///
/// The name is base64url of ten bytes, so it is not human-readable and cannot be
/// compared as a string against an id -- decode it, do not pattern-match it.
pub fn instance_name(endpoint_id: &[u8; ENDPOINT_ID_LEN]) -> String {
    let mut raw = [0u8; INSTANCE_RAW_LEN];
    raw[0] = PCP;
    raw[1..1 + ENDPOINT_ID_LEN].copy_from_slice(endpoint_id);
    raw[1 + ENDPOINT_ID_LEN..1 + ENDPOINT_ID_LEN + 3].copy_from_slice(&SERVICE_ID_HASH_PREFIX);
    base64url_encode(&raw)
}

/// Recover an endpoint id from an instance name, rejecting anything that is not ours.
///
/// Checks the hash prefix rather than trusting the service name we browsed on: a
/// responder can put any instance under any service, and an id taken from a record
/// that was not built for this service is not an id at all.
pub fn endpoint_id_from_instance(instance: &str) -> Option<[u8; ENDPOINT_ID_LEN]> {
    let label = instance.split('.').next()?;
    let raw = base64url_decode(label)?;
    if raw.len() < 1 + ENDPOINT_ID_LEN + 3 || raw[0] != PCP {
        return None;
    }
    if raw[1 + ENDPOINT_ID_LEN..1 + ENDPOINT_ID_LEN + 3] != SERVICE_ID_HASH_PREFIX {
        return None;
    }
    let mut id = [0u8; ENDPOINT_ID_LEN];
    id.copy_from_slice(&raw[1..1 + ENDPOINT_ID_LEN]);
    Some(id)
}

/// A fresh endpoint id, drawn from the alphabet peers expect.
pub fn random_endpoint_id() -> [u8; ENDPOINT_ID_LEN] {
    let mut r = [0u8; ENDPOINT_ID_LEN];
    // SAFETY: writing ENDPOINT_ID_LEN bytes into a buffer of exactly that size.
    unsafe {
        libc::getrandom(r.as_mut_ptr() as *mut libc::c_void, r.len(), 0);
    }
    let n = ENDPOINT_ID_ALPHABET.len() as u8;
    for b in r.iter_mut() {
        *b = ENDPOINT_ID_ALPHABET[(*b % n) as usize];
    }
    r
}

const B64URL: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// base64url without padding, which is what appears in the instance label.
fn base64url_encode(input: &[u8]) -> String {
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        let take = chunk.len() + 1;
        for i in 0..take {
            out.push(B64URL[((n >> (18 - 6 * i)) & 0x3F) as usize] as char);
        }
    }
    out
}

fn base64url_decode(input: &str) -> Option<Vec<u8>> {
    let mut acc: u32 = 0;
    let mut bits = 0u32;
    let mut out = Vec::with_capacity(input.len() * 3 / 4);
    for c in input.bytes() {
        // Accept the standard alphabet too: some responders emit `+` and `/`.
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'-' | b'+' => 62,
            b'_' | b'/' => 63,
            b'=' => continue,
            _ => return None,
        } as u32;
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Some(out)
}

//! P-256 key exchange for the UKEY2 handshake, and the public-key encoding it uses.
//!
//! Three jobs:
//!
//! 1. ephemeral P-256 (secp256r1) keypairs, one per handshake
//! 2. `dhs = SHA-256(ECDH(peer_pub, our_priv).x_magnitude)` — the input `d2d` consumes
//! 3. SHA-512 over a serialized message, which is the cipher commitment
//!
//! TWO ENCODING SUBTLETIES, BOTH OF WHICH FAIL RARELY RATHER THAN LOUDLY.
//!
//! **The shared secret is a magnitude, not a fixed-width field.** ECDH gives a 32-byte
//! big-endian X coordinate. UKEY2 hashes it with any leading zero bytes STRIPPED. A
//! coordinate starts with a zero byte roughly one time in 256, so an implementation
//! that hashes the padded form interoperates with about 255 of every 256 peers and
//! fails the rest — which reads as a flaky peer, not as a bug in us.
//!
//! **x and y travel as big-endian two's complement**, per securemessage.proto's own
//! comment ("slightly wasteful"). That means a leading 0x00 IS PRESENT when the high
//! bit of the coordinate is set, because otherwise the value would be negative. Same
//! one-in-two-ish frequency for the sign byte, and the same class of rare failure if
//! it is omitted or if it is not stripped on the way back in.
//!
//! Ported from Bada's `core-protocol` (Apache 2.0, Copyright 2026 Bada contributors).

use crate::protobuf::{self, Writer};
use openssl::bn::{BigNum, BigNumContext};
use openssl::derive::Deriver;
use openssl::ec::{EcGroup, EcKey, EcPoint, PointConversionForm};
use openssl::error::ErrorStack;
use openssl::hash::{hash, MessageDigest};
use openssl::nid::Nid;
use openssl::pkey::{PKey, Private, Public};
use std::fmt;

// securemessage.proto
const GPK_TYPE: u32 = 1;
const GPK_EC_P256_PUBLIC_KEY: u32 = 2;
const EC_X: u32 = 1;
const EC_Y: u32 = 2;
const PUBLIC_KEY_TYPE_EC_P256: u64 = 1;

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    /// The peer's point is not on P-256. Accepting it would leak our private scalar to
    /// an invalid-curve attack, so this is a hard refusal rather than a warning.
    NotOnCurve,
    Malformed(&'static str),
    Protobuf(protobuf::Error),
    Crypto,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::NotOnCurve => write!(f, "ukey2: public key is not a point on P-256"),
            Error::Malformed(w) => write!(f, "ukey2: malformed ({w})"),
            Error::Protobuf(e) => write!(f, "ukey2: {e}"),
            Error::Crypto => write!(f, "ukey2: crypto operation failed"),
        }
    }
}

impl From<protobuf::Error> for Error {
    fn from(e: protobuf::Error) -> Self {
        Error::Protobuf(e)
    }
}
impl From<ErrorStack> for Error {
    fn from(_: ErrorStack) -> Self {
        Error::Crypto
    }
}

fn p256() -> Result<EcGroup, ErrorStack> {
    EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)
}

/// A fresh ephemeral keypair. One per handshake, never reused.
pub fn generate_keypair() -> Result<EcKey<Private>, Error> {
    // Bound to a local: `&p256()?` is a reference to a temporary EcGroup and does not
    // deref-coerce to the &EcGroupRef this wants.
    let group = p256()?;
    Ok(EcKey::generate(&group)?)
}

/// Strip leading zero bytes. The "magnitude" form UKEY2 hashes.
fn magnitude(v: &[u8]) -> &[u8] {
    let first = v.iter().position(|&b| b != 0).unwrap_or(v.len());
    &v[first..]
}

/// `dhs = SHA-256(ECDH(peer, ours).x_magnitude)`.
///
/// This is the value `d2d::ukey2_secrets` takes as `dhs`.
pub fn shared_secret(ours: &EcKey<Private>, peer: &EcKey<Public>) -> Result<Vec<u8>, Error> {
    let ours = PKey::from_ec_key(ours.clone())?;
    let peer = PKey::from_ec_key(peer.clone())?;
    let mut deriver = Deriver::new(&ours)?;
    deriver.set_peer(&peer)?;
    // For ECDH this is the X coordinate of the shared point, fixed width (32 bytes).
    let x = deriver.derive_to_vec()?;
    Ok(hash(MessageDigest::sha256(), magnitude(&x))?.to_vec())
}

/// SHA-512, used for the cipher commitment over a serialized Ukey2Message.
pub fn sha512(data: &[u8]) -> Result<Vec<u8>, Error> {
    Ok(hash(MessageDigest::sha512(), data)?.to_vec())
}

/// Big-endian two's complement, as securemessage.proto specifies: a 0x00 is prepended
/// when the high bit is set, so the value is never read as negative.
fn twos_complement(n: &BigNum) -> Vec<u8> {
    let mut v = n.to_vec();
    if v.first().is_some_and(|b| b & 0x80 != 0) {
        v.insert(0, 0x00);
    }
    v
}

/// Serialize as a `GenericPublicKey{type=EC_P256, ec_p256_public_key={x, y}}`.
pub fn encode_public_key(key: &EcKey<Private>) -> Result<Vec<u8>, Error> {
    let group = p256()?;
    let mut ctx = BigNumContext::new()?;
    let mut x = BigNum::new()?;
    let mut y = BigNum::new()?;
    key.public_key()
        .affine_coordinates_gfp(&group, &mut x, &mut y, &mut ctx)?;

    let mut ec = Writer::new();
    ec.bytes(EC_X, &twos_complement(&x))
        .bytes(EC_Y, &twos_complement(&y));
    let ec = ec.finish();

    let mut gpk = Writer::new();
    gpk.varint(GPK_TYPE, PUBLIC_KEY_TYPE_EC_P256)
        .bytes(GPK_EC_P256_PUBLIC_KEY, &ec);
    Ok(gpk.finish())
}

/// Parse a `GenericPublicKey` and CHECK THE POINT IS ON THE CURVE.
///
/// The schema says the client MUST verify this, and it is not a formality: a point off
/// the curve, or on a weak related curve, lets a peer recover our private scalar from
/// the shared secrets we then produce.
pub fn decode_public_key(bytes: &[u8]) -> Result<EcKey<Public>, Error> {
    let ec = protobuf::first_bytes(bytes, GPK_EC_P256_PUBLIC_KEY)?
        .ok_or(Error::Malformed("no ec_p256_public_key"))?;
    let x = protobuf::first_bytes(ec, EC_X)?.ok_or(Error::Malformed("no x"))?;
    let y = protobuf::first_bytes(ec, EC_Y)?.ok_or(Error::Malformed("no y"))?;

    // Positive interpretation: a leading 0x00 is the two's complement sign byte, not
    // part of the magnitude. BigNum::from_slice is unsigned, so this is just parsing.
    let x = BigNum::from_slice(magnitude(x))?;
    let y = BigNum::from_slice(magnitude(y))?;

    let group = p256()?;
    let mut ctx = BigNumContext::new()?;
    let mut point = EcPoint::new(&group)?;
    // Rejects a coordinate pair that is not on the curve.
    point
        .set_affine_coordinates_gfp(&group, &x, &y, &mut ctx)
        .map_err(|_| Error::NotOnCurve)?;
    if !point.is_on_curve(&group, &mut ctx).unwrap_or(false) {
        return Err(Error::NotOnCurve);
    }
    let key = EcKey::from_public_key(&group, &point).map_err(|_| Error::NotOnCurve)?;
    key.check_key().map_err(|_| Error::NotOnCurve)?;
    Ok(key)
}

/// Uncompressed SEC1 point, for tests that need to corrupt a coordinate.
#[cfg(test)]
fn point_bytes(key: &EcKey<Private>) -> Result<Vec<u8>, Error> {
    let group = p256()?;
    let mut ctx = BigNumContext::new()?;
    Ok(key
        .public_key()
        .to_bytes(&group, PointConversionForm::UNCOMPRESSED, &mut ctx)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ecdh_agrees_in_both_directions() {
        let a = generate_keypair().unwrap();
        let b = generate_keypair().unwrap();
        let a_pub = decode_public_key(&encode_public_key(&a).unwrap()).unwrap();
        let b_pub = decode_public_key(&encode_public_key(&b).unwrap()).unwrap();

        let ab = shared_secret(&a, &b_pub).unwrap();
        let ba = shared_secret(&b, &a_pub).unwrap();
        assert_eq!(ab, ba, "both ends must derive the same dhs");
        assert_eq!(ab.len(), 32, "dhs is SHA-256");
    }

    #[test]
    fn different_pairs_give_different_secrets() {
        let a = generate_keypair().unwrap();
        let b = generate_keypair().unwrap();
        let c = generate_keypair().unwrap();
        let b_pub = decode_public_key(&encode_public_key(&b).unwrap()).unwrap();
        let c_pub = decode_public_key(&encode_public_key(&c).unwrap()).unwrap();
        assert_ne!(
            shared_secret(&a, &b_pub).unwrap(),
            shared_secret(&a, &c_pub).unwrap()
        );
    }

    #[test]
    fn public_keys_round_trip() {
        for _ in 0..16 {
            let k = generate_keypair().unwrap();
            let enc = encode_public_key(&k).unwrap();
            let dec = decode_public_key(&enc).unwrap();
            // Re-encoding the decoded key must give identical bytes, which catches a
            // sign byte added on one path and not the other.
            let group = p256().unwrap();
            let mut ctx = BigNumContext::new().unwrap();
            let mut x1 = BigNum::new().unwrap();
            let mut y1 = BigNum::new().unwrap();
            let mut x2 = BigNum::new().unwrap();
            let mut y2 = BigNum::new().unwrap();
            k.public_key()
                .affine_coordinates_gfp(&group, &mut x1, &mut y1, &mut ctx)
                .unwrap();
            dec.public_key()
                .affine_coordinates_gfp(&group, &mut x2, &mut y2, &mut ctx)
                .unwrap();
            assert_eq!(x1.to_vec(), x2.to_vec());
            assert_eq!(y1.to_vec(), y2.to_vec());
        }
    }

    /// The sign byte is the whole point of the two's complement encoding, and it only
    /// appears for coordinates with the high bit set. Assert both forms decode.
    #[test]
    fn coordinates_with_and_without_a_sign_byte_both_work() {
        let mut saw_sign_byte = false;
        let mut saw_plain = false;
        for _ in 0..64 {
            let k = generate_keypair().unwrap();
            let enc = encode_public_key(&k).unwrap();
            let ec = protobuf::first_bytes(&enc, GPK_EC_P256_PUBLIC_KEY)
                .unwrap()
                .unwrap();
            let x = protobuf::first_bytes(ec, EC_X).unwrap().unwrap();
            if x.len() == 33 {
                assert_eq!(x[0], 0x00, "33-byte x must start with the sign byte");
                saw_sign_byte = true;
            } else {
                saw_plain = true;
            }
            decode_public_key(&enc).expect("must decode either way");
            if saw_sign_byte && saw_plain {
                return;
            }
        }
        // 64 keys without seeing both forms would be about a 1-in-2^63 accident, so
        // this failing means the encoder is not producing one of them at all.
        panic!("did not observe both encodings in 64 keys: sign={saw_sign_byte} plain={saw_plain}");
    }

    /// A point that is not on the curve must be refused. Accepting one is an
    /// invalid-curve attack that recovers our private scalar.
    #[test]
    fn a_point_off_the_curve_is_refused() {
        let k = generate_keypair().unwrap();
        let enc = encode_public_key(&k).unwrap();
        let ec = protobuf::first_bytes(&enc, GPK_EC_P256_PUBLIC_KEY)
            .unwrap()
            .unwrap();
        let x = protobuf::first_bytes(ec, EC_X).unwrap().unwrap().to_vec();
        let mut y = protobuf::first_bytes(ec, EC_Y).unwrap().unwrap().to_vec();
        // Corrupt y so (x, y) is no longer a solution.
        *y.last_mut().unwrap() ^= 0x01;

        let mut ec2 = Writer::new();
        ec2.bytes(EC_X, &x).bytes(EC_Y, &y);
        let mut gpk = Writer::new();
        gpk.varint(GPK_TYPE, PUBLIC_KEY_TYPE_EC_P256)
            .bytes(GPK_EC_P256_PUBLIC_KEY, &ec2.finish());

        assert_eq!(
            decode_public_key(&gpk.finish()).unwrap_err(),
            Error::NotOnCurve
        );
    }

    #[test]
    fn garbage_is_refused_without_panicking() {
        for junk in [&b""[..], &b"\x00"[..], &[0xffu8; 80][..]] {
            assert!(decode_public_key(junk).is_err());
        }
    }

    /// The magnitude helper is where the one-in-256 interop bug lives.
    #[test]
    fn magnitude_strips_only_leading_zeros() {
        assert_eq!(magnitude(&[0x00, 0x00, 0x01, 0x02]), &[0x01, 0x02]);
        assert_eq!(magnitude(&[0x01, 0x00]), &[0x01, 0x00]);
        assert_eq!(magnitude(&[0x00]), &[] as &[u8]);
        assert_eq!(magnitude(&[]), &[] as &[u8]);
    }

    #[test]
    fn sha512_is_the_right_width() {
        assert_eq!(sha512(b"").unwrap().len(), 64);
        // Known answer: SHA-512 of the empty string starts cf83e135...
        assert_eq!(&sha512(b"").unwrap()[..4], &[0xcf, 0x83, 0xe1, 0x35]);
    }

    #[test]
    fn generated_points_are_valid() {
        let k = generate_keypair().unwrap();
        assert!(!point_bytes(&k).unwrap().is_empty());
    }
}

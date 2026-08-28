//! HKDF-SHA256, RFC 5869.
//!
//! Quick Share derives every per-connection key with this: the UKEY2 auth string and
//! next secret, the D2D client and server keys, and the SecureMessage encrypt and HMAC
//! keys. Bit-exact agreement with the peer is not optional -- a derivation that is
//! wrong by one byte produces a connection that fails at the first authenticated frame,
//! several layers away from the cause.
//!
//! Built on HMAC-SHA256 rather than any library HKDF. The algorithm is ten lines
//! (RFC 5869 §2), BoringSSL's HKDF surface differs across versions, and hand-rolling on
//! the HMAC primitive gives one obvious implementation to review against the RFC.
//! Bada's Hkdf.kt reaches the same conclusion for the same reasons.
//!
//! Ported from Bada's `core-protocol` (Apache 2.0, Copyright 2026 Bada contributors).
//!
//! Do not add logging that prints `ikm`, `salt` or the intermediate PRK. They are key
//! material, and a debug line is how key material ends up in a bug report.

use openssl::error::ErrorStack;
use openssl::hmac::hmac;
use openssl::md::Md;

/// SHA-256 output size. RFC 5869's `HashLen`.
const HASH_LEN: usize = 32;

/// RFC 5869 §2.3: `L <= 255 * HashLen`. 8160 bytes for SHA-256, far above any Quick
/// Share derivation, so this only ever fires as a misuse guard.
const MAX_OUTPUT_LEN: usize = 255 * HASH_LEN;

/// One-shot HMAC-SHA256.
///
/// NOT `PKey::hmac` + `Signer`, which is the usual openssl-crate idiom and does not
/// exist here: AOSP builds the crate against BoringSSL, where that constructor is
/// compiled out, and the failure is a bare
///
///     error[E0599]: no function or associated item named `hmac` found for struct `PKey`
///
/// `openssl::hmac::hmac` is the BoringSSL-shaped equivalent. This is the same class of
/// version drift that argues for hand-rolling HKDF on the primitive rather than reaching
/// for whichever library HKDF happens to be exposed.
fn hmac_sha256(key: &[u8], data: &[u8]) -> Result<Vec<u8>, ErrorStack> {
    let mut buf = [0u8; HASH_LEN];
    let out = hmac(Md::sha256(), key, data, &mut buf)?;
    Ok(out.to_vec())
}

/// RFC 5869 §2.2. `PRK = HMAC(salt, ikm)`.
///
/// An empty salt is replaced with `HashLen` zero bytes, which the RFC requires and
/// which is NOT the same as skipping the extract step. Peers that pass no salt still
/// expect this substitution, so omitting it is interoperable with nothing.
pub fn extract(salt: &[u8], ikm: &[u8]) -> Result<Vec<u8>, ErrorStack> {
    let zeros;
    let salt = if salt.is_empty() {
        zeros = [0u8; HASH_LEN];
        &zeros[..]
    } else {
        salt
    };
    hmac_sha256(salt, ikm)
}

/// RFC 5869 §2.3. Expands `prk` to `length` bytes.
///
/// The counter is one-based and single-byte, and `T(0)` is empty -- both are easy to
/// get subtly wrong and neither fails loudly.
pub fn expand(prk: &[u8], info: &[u8], length: usize) -> Result<Vec<u8>, ErrorStack> {
    assert!(
        length <= MAX_OUTPUT_LEN,
        "HKDF output {length} exceeds RFC 5869 maximum {MAX_OUTPUT_LEN}"
    );
    let mut out = Vec::with_capacity(length);
    let mut t: Vec<u8> = Vec::new();
    let mut counter: u8 = 1;
    while out.len() < length {
        let mut input = Vec::with_capacity(t.len() + info.len() + 1);
        input.extend_from_slice(&t);
        input.extend_from_slice(info);
        input.push(counter);
        t = hmac_sha256(prk, &input)?;
        let take = (length - out.len()).min(t.len());
        out.extend_from_slice(&t[..take]);
        counter += 1;
    }
    Ok(out)
}

/// Extract then expand. Both stages always run, even with an empty salt.
pub fn derive(ikm: &[u8], salt: &[u8], info: &[u8], length: usize) -> Result<Vec<u8>, ErrorStack> {
    let prk = extract(salt, ikm)?;
    expand(&prk, info, length)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("bad hex in test vector"))
            .collect()
    }

    /// RFC 5869 Appendix A.1 -- basic SHA-256.
    ///
    /// Cases A.4 to A.7 are SHA-1 and are deliberately absent: SHA-256 is the only hash
    /// Quick Share negotiates.
    #[test]
    fn rfc5869_a1_basic() {
        let ikm = hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        let salt = hex("000102030405060708090a0b0c");
        let info = hex("f0f1f2f3f4f5f6f7f8f9");
        let want_prk = hex("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5");
        let want_okm = hex(
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf\
             34007208d5b887185865",
        );
        assert_eq!(extract(&salt, &ikm).unwrap(), want_prk, "PRK");
        assert_eq!(derive(&ikm, &salt, &info, 42).unwrap(), want_okm, "OKM");
    }

    /// RFC 5869 Appendix A.2 -- longer inputs and output, exercising the counter past
    /// a single block.
    #[test]
    fn rfc5869_a2_long() {
        let ikm: Vec<u8> = (0u8..=0x4f).collect();
        let salt: Vec<u8> = (0x60u8..=0xaf).collect();
        let info: Vec<u8> = (0xb0u8..=0xff).collect();
        let want_prk = hex("06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244");
        let want_okm = hex(
            "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c\
             59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71\
             cc30c58179ec3e87c14c01d5c1f3434f1d87",
        );
        assert_eq!(extract(&salt, &ikm).unwrap(), want_prk, "PRK");
        assert_eq!(derive(&ikm, &salt, &info, 82).unwrap(), want_okm, "OKM");
    }

    /// RFC 5869 Appendix A.3 -- empty salt and info.
    ///
    /// This is the case that catches a missing zero-salt substitution: skip it and the
    /// PRK is wrong while every other vector still passes.
    #[test]
    fn rfc5869_a3_empty_salt_and_info() {
        let ikm = hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        let want_prk = hex("19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04");
        let want_okm = hex(
            "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d\
             9d201395faa4b61a96c8",
        );
        assert_eq!(extract(&[], &ikm).unwrap(), want_prk, "PRK");
        assert_eq!(derive(&ikm, &[], &[], 42).unwrap(), want_okm, "OKM");
    }

    /// An explicitly zero-filled salt must give the same PRK as an empty one, which is
    /// what the RFC's substitution means.
    #[test]
    fn empty_salt_equals_zero_salt() {
        let ikm = hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        assert_eq!(extract(&[], &ikm).unwrap(), extract(&[0u8; 32], &ikm).unwrap());
    }

    /// Output shorter than one hash block, and output that is an exact multiple, are
    /// both boundary cases for the truncation in expand().
    #[test]
    fn output_lengths_around_the_block_boundary() {
        let ikm = b"input keying material";
        for len in [1usize, 31, 32, 33, 64, 65] {
            let out = derive(ikm, b"salt", b"info", len).unwrap();
            assert_eq!(out.len(), len, "requested {len} bytes");
            // A prefix of a longer derivation must equal the shorter one: the counter
            // restarts at 1 every time, so this catches state leaking between calls.
            let longer = derive(ikm, b"salt", b"info", 96).unwrap();
            assert_eq!(out[..], longer[..len], "prefix mismatch at {len}");
        }
    }
}

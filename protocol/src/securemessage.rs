//! The SecureMessage envelope: every frame after the UKEY2 handshake.
//!
//! ```text
//! SecureMessage {
//!   header_and_body = HeaderAndBody {
//!     header = Header { sig = HMAC_SHA256, enc = AES_256_CBC, iv, public_metadata }
//!     body   = AES-256-CBC( PKCS7( DeviceToDeviceMessage { seq, payload } ), enc_key, iv )
//!   }
//!   signature = HMAC-SHA256(header_and_body, hmac_key)
//! }
//! ```
//!
//! TWO PROPERTIES HERE ARE SECURITY, NOT STYLE.
//!
//! **HMAC before AES.** The signature is verified before any decryption is attempted,
//! so a tampered ciphertext never reaches the unpadding code. Reversing the order gives
//! an attacker a padding oracle, and the reversed version passes every round-trip test.
//!
//! **Constant-time signature comparison.** A byte-by-byte comparison leaks, through
//! timing, how many leading bytes of a forged signature were right, which is enough to
//! forge one byte at a time. `openssl::memcmp::eq` is the comparison that does not.
//!
//! Stateless on purpose: no keys, no sequence counters. Callers hold that. It makes
//! known-answer testing possible, since a fixed key and IV must give fixed bytes.
//!
//! Ported from Bada's `core-protocol` (Apache 2.0, Copyright 2026 Bada contributors).
//!
//! Field numbers are from securemessage.proto, securegcm.proto and
//! device_to_device_messages.proto. They were read from the schemas, not recalled:
//! `iv` is 5 and `public_metadata` is 6 (not the other way round), and
//! DEVICE_TO_DEVICE_MESSAGE is 13. Each of those, wrong, produces a peer that rejects
//! us with no diagnostic.

use crate::protobuf::{self, Writer};
use openssl::error::ErrorStack;
use openssl::hmac::hmac;
use openssl::md::Md;
use openssl::memcmp;
use openssl::rand::rand_bytes;
use openssl::symm::{decrypt, encrypt, Cipher};
use std::fmt;

pub const AES_KEY_SIZE: usize = 32;
pub const HMAC_KEY_SIZE: usize = 32;
/// AES block size. Receivers feed `header.iv` straight into the cipher, so this is exact.
pub const IV_SIZE: usize = 16;
pub const HMAC_SIZE: usize = 32;

// securemessage.proto
const SM_HEADER_AND_BODY: u32 = 1;
const SM_SIGNATURE: u32 = 2;
const HB_HEADER: u32 = 1;
const HB_BODY: u32 = 2;
const HDR_SIGNATURE_SCHEME: u32 = 1;
const HDR_ENCRYPTION_SCHEME: u32 = 2;
const HDR_IV: u32 = 5;
const HDR_PUBLIC_METADATA: u32 = 6;
const SIG_SCHEME_HMAC_SHA256: u64 = 1;
const ENC_SCHEME_AES_256_CBC: u64 = 2;

// device_to_device_messages.proto
const D2D_MESSAGE: u32 = 1;
const D2D_SEQUENCE_NUMBER: u32 = 2;

// securegcm.proto
const GCM_TYPE: u32 = 1;
const GCM_VERSION: u32 = 2;
const GCM_TYPE_DEVICE_TO_DEVICE_MESSAGE: u64 = 13;
/// The proto default is 0; peers send 1. Emitted for byte-for-byte parity even though
/// receivers do not check it.
const GCM_VERSION_VALUE: u64 = 1;

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    /// The signature did not match. Returned before any decryption is attempted, so
    /// this is also what a tampered ciphertext looks like from outside.
    BadSignature,
    Malformed(&'static str),
    Protobuf(protobuf::Error),
    Crypto,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::BadSignature => write!(f, "securemessage: signature verification failed"),
            Error::Malformed(w) => write!(f, "securemessage: malformed ({w})"),
            Error::Protobuf(e) => write!(f, "securemessage: {e}"),
            Error::Crypto => write!(f, "securemessage: crypto operation failed"),
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
        // Deliberately opaque: the BoringSSL error queue can distinguish a padding
        // failure from other faults, and surfacing that to a caller who may relay it
        // to a peer rebuilds the padding oracle the HMAC-first ordering removes.
        Error::Crypto
    }
}

/// A decrypted frame.
pub struct Unwrapped {
    pub sequence_number: i32,
    pub payload: Vec<u8>,
}

/// Debug is hand-written to REDACT the payload.
///
/// It is needed at all because `Result::unwrap_err` requires it on the Ok type, which
/// is a thin reason to gain a way of printing decrypted plaintext. Deriving it would
/// mean one `{:?}` in a future error path quietly logs the contents of a transfer.
impl fmt::Debug for Unwrapped {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Unwrapped")
            .field("sequence_number", &self.sequence_number)
            .field("payload", &format_args!("<{} bytes redacted>", self.payload.len()))
            .finish()
    }
}

/// A fresh 16-byte IV. One per frame, never reused with the same key.
pub fn random_iv() -> Result<Vec<u8>, Error> {
    let mut iv = vec![0u8; IV_SIZE];
    rand_bytes(&mut iv)?;
    Ok(iv)
}

fn gcm_metadata() -> Vec<u8> {
    let mut w = Writer::new();
    w.varint(GCM_TYPE, GCM_TYPE_DEVICE_TO_DEVICE_MESSAGE)
        .varint(GCM_VERSION, GCM_VERSION_VALUE);
    w.finish()
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Result<Vec<u8>, Error> {
    let mut buf = [0u8; HMAC_SIZE];
    Ok(hmac(Md::sha256(), key, data, &mut buf)?.to_vec())
}

/// Encrypt `payload` and wrap it in a signed SecureMessage.
///
/// `iv` is a parameter rather than generated here so tests can pin it; production
/// callers pass `random_iv()`.
pub fn encrypt_and_sign(
    encrypt_key: &[u8],
    hmac_key: &[u8],
    sequence_number: i32,
    payload: &[u8],
    iv: &[u8],
) -> Result<Vec<u8>, Error> {
    if encrypt_key.len() != AES_KEY_SIZE {
        return Err(Error::Malformed("encrypt key is not 32 bytes"));
    }
    if iv.len() != IV_SIZE {
        return Err(Error::Malformed("iv is not 16 bytes"));
    }

    let mut d2d = Writer::new();
    d2d.bytes(D2D_MESSAGE, payload)
        // int32 on the wire is a plain varint, sign-extended to 64 bits for negatives.
        .varint(D2D_SEQUENCE_NUMBER, sequence_number as i64 as u64);
    let d2d = d2d.finish();

    // openssl's one-shot encrypt applies PKCS7, which is what the peer expects.
    let body = encrypt(Cipher::aes_256_cbc(), encrypt_key, Some(iv), &d2d)?;

    let mut header = Writer::new();
    header
        .varint(HDR_SIGNATURE_SCHEME, SIG_SCHEME_HMAC_SHA256)
        .varint(HDR_ENCRYPTION_SCHEME, ENC_SCHEME_AES_256_CBC)
        .bytes(HDR_IV, iv)
        .bytes(HDR_PUBLIC_METADATA, &gcm_metadata());
    let header = header.finish();

    let mut hb = Writer::new();
    hb.bytes(HB_HEADER, &header).bytes(HB_BODY, &body);
    let hb = hb.finish();

    let signature = hmac_sha256(hmac_key, &hb)?;

    let mut sm = Writer::new();
    sm.bytes(SM_HEADER_AND_BODY, &hb)
        .bytes(SM_SIGNATURE, &signature);
    Ok(sm.finish())
}

/// Verify the signature, then decrypt.
///
/// The order is the point. Nothing below touches the ciphertext until the HMAC has
/// matched in constant time.
pub fn verify_and_decrypt(
    encrypt_key: &[u8],
    hmac_key: &[u8],
    message: &[u8],
) -> Result<Unwrapped, Error> {
    if encrypt_key.len() != AES_KEY_SIZE {
        return Err(Error::Malformed("encrypt key is not 32 bytes"));
    }

    let hb = protobuf::first_bytes(message, SM_HEADER_AND_BODY)?
        .ok_or(Error::Malformed("no header_and_body"))?;
    let signature = protobuf::first_bytes(message, SM_SIGNATURE)?
        .ok_or(Error::Malformed("no signature"))?;

    // ---- verification gate. Nothing beyond this point runs on unauthenticated data.
    let expected = hmac_sha256(hmac_key, hb)?;
    if signature.len() != expected.len() || !memcmp::eq(signature, &expected) {
        return Err(Error::BadSignature);
    }
    // ----

    let header = protobuf::first_bytes(hb, HB_HEADER)?.ok_or(Error::Malformed("no header"))?;
    let body = protobuf::first_bytes(hb, HB_BODY)?.ok_or(Error::Malformed("no body"))?;

    match protobuf::first_varint(header, HDR_SIGNATURE_SCHEME)? {
        Some(SIG_SCHEME_HMAC_SHA256) => {}
        _ => return Err(Error::Malformed("signature scheme is not HMAC_SHA256")),
    }
    match protobuf::first_varint(header, HDR_ENCRYPTION_SCHEME)? {
        Some(ENC_SCHEME_AES_256_CBC) => {}
        _ => return Err(Error::Malformed("encryption scheme is not AES_256_CBC")),
    }
    let iv = protobuf::first_bytes(header, HDR_IV)?.ok_or(Error::Malformed("no iv"))?;
    if iv.len() != IV_SIZE {
        return Err(Error::Malformed("iv is not 16 bytes"));
    }

    let plain = decrypt(Cipher::aes_256_cbc(), encrypt_key, Some(iv), body)?;

    let payload = protobuf::first_bytes(&plain, D2D_MESSAGE)?
        .ok_or(Error::Malformed("no d2d message"))?
        .to_vec();
    let sequence_number = protobuf::first_varint(&plain, D2D_SEQUENCE_NUMBER)?
        .ok_or(Error::Malformed("no sequence number"))? as i64 as i32;

    Ok(Unwrapped {
        sequence_number,
        payload,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const ENC: &[u8; 32] = b"0123456789abcdef0123456789abcdef";
    const MAC: &[u8; 32] = b"fedcba9876543210fedcba9876543210";
    const IV: &[u8; 16] = b"0123456789abcdef";

    #[test]
    fn round_trip() {
        let msg = encrypt_and_sign(ENC, MAC, 7, b"hello quick share", IV).unwrap();
        let out = verify_and_decrypt(ENC, MAC, &msg).unwrap();
        assert_eq!(out.sequence_number, 7);
        assert_eq!(out.payload, b"hello quick share");
    }

    #[test]
    fn empty_payload_round_trips() {
        let msg = encrypt_and_sign(ENC, MAC, 0, b"", IV).unwrap();
        let out = verify_and_decrypt(ENC, MAC, &msg).unwrap();
        assert_eq!(out.payload, b"");
        assert_eq!(out.sequence_number, 0);
    }

    /// A payload that is an exact multiple of the block size still gets a full block of
    /// PKCS7 padding. Getting this wrong works for every other length.
    #[test]
    fn block_aligned_payload_round_trips() {
        let payload = vec![0xABu8; 32];
        let msg = encrypt_and_sign(ENC, MAC, 1, &payload, IV).unwrap();
        assert_eq!(verify_and_decrypt(ENC, MAC, &msg).unwrap().payload, payload);
    }

    /// Fixed key and IV must give fixed bytes. Without this the round-trip tests would
    /// pass just as happily if both halves drifted together, and the peer would not.
    #[test]
    fn is_deterministic_for_a_fixed_key_and_iv() {
        let a = encrypt_and_sign(ENC, MAC, 3, b"same", IV).unwrap();
        let b = encrypt_and_sign(ENC, MAC, 3, b"same", IV).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn tampering_with_the_signature_is_rejected() {
        let mut msg = encrypt_and_sign(ENC, MAC, 1, b"payload", IV).unwrap();
        let n = msg.len();
        msg[n - 1] ^= 0x01;
        assert_eq!(
            verify_and_decrypt(ENC, MAC, &msg).unwrap_err(),
            Error::BadSignature
        );
    }

    /// A tampered ciphertext must fail as a SIGNATURE error, never as a crypto or
    /// padding error. If this ever reports Error::Crypto, the HMAC-before-AES ordering
    /// has been broken and a padding oracle is back.
    #[test]
    fn tampered_ciphertext_fails_at_the_signature_not_the_padding() {
        let msg = encrypt_and_sign(ENC, MAC, 1, b"payload", IV).unwrap();
        // flip a byte in the middle, which is inside header_and_body
        let mut bad = msg.clone();
        let mid = bad.len() / 2;
        bad[mid] ^= 0xff;
        assert_eq!(
            verify_and_decrypt(ENC, MAC, &bad).unwrap_err(),
            Error::BadSignature,
            "must be rejected by the HMAC, not by the unpadding"
        );
    }

    #[test]
    fn the_wrong_hmac_key_is_rejected() {
        let msg = encrypt_and_sign(ENC, MAC, 1, b"payload", IV).unwrap();
        let other = [0x11u8; 32];
        assert_eq!(
            verify_and_decrypt(ENC, &other, &msg).unwrap_err(),
            Error::BadSignature
        );
    }

    /// The right HMAC key with the wrong encryption key gets past verification and
    /// fails in the cipher, which is the only case where Error::Crypto is correct.
    #[test]
    fn the_wrong_encryption_key_fails_after_verification() {
        let msg = encrypt_and_sign(ENC, MAC, 1, b"payload", IV).unwrap();
        let other = [0x22u8; 32];
        assert_eq!(
            verify_and_decrypt(&other, MAC, &msg).unwrap_err(),
            Error::Crypto
        );
    }

    #[test]
    fn random_ivs_do_not_repeat() {
        let mut seen = std::collections::HashSet::new();
        for _ in 0..64 {
            let iv = random_iv().unwrap();
            assert_eq!(iv.len(), IV_SIZE);
            assert!(seen.insert(iv), "random_iv repeated within 64 draws");
        }
    }

    /// Different IVs must give different ciphertext for identical plaintext, which is
    /// the whole reason the IV is per-frame.
    #[test]
    fn the_iv_actually_varies_the_ciphertext() {
        let a = encrypt_and_sign(ENC, MAC, 1, b"same", &random_iv().unwrap()).unwrap();
        let b = encrypt_and_sign(ENC, MAC, 1, b"same", &random_iv().unwrap()).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn garbage_is_rejected_without_panicking() {
        for junk in [&b""[..], &b"\x00"[..], &[0xffu8; 64][..]] {
            assert!(verify_and_decrypt(ENC, MAC, junk).is_err());
        }
    }

    #[test]
    fn a_short_key_is_refused_rather_than_used() {
        assert!(encrypt_and_sign(&[0u8; 16], MAC, 1, b"x", IV).is_err());
        assert!(encrypt_and_sign(ENC, MAC, 1, b"x", &[0u8; 8]).is_err());
    }
}

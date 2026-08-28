//! The traffic keys that follow a successful UKEY2 handshake.
//!
//! Three stages, each one HKDF-SHA256 call. Drift in any salt, info string or input
//! ordering produces keys that fail to decrypt over the air — and it fails as a peer
//! that stops answering, not as an error naming the cause.
//!
//! ```text
//! ukey_info  = client_init || server_init          (raw bytes, NOT length-prefixed)
//!
//! stage 1 — UKEY2
//!   auth_string  = HKDF(ikm = dhs,         salt = "UKEY2 v1 auth", info = ukey_info)
//!   next_secret  = HKDF(ikm = dhs,         salt = "UKEY2 v1 next", info = ukey_info)
//!
//! stage 2 — D2D, per direction
//!   d2d_client   = HKDF(ikm = next_secret, salt = SHA256("D2D"),   info = "client")
//!   d2d_server   = HKDF(ikm = next_secret, salt = SHA256("D2D"),   info = "server")
//!
//! stage 3 — SecureMessage, split into encrypt and HMAC
//!   *_encrypt    = HKDF(ikm = d2d_*,       salt = SHA256("SecureMessage"), info = "ENC:2")
//!   *_hmac       = HKDF(ikm = d2d_*,       salt = SHA256("SecureMessage"), info = "SIG:1")
//! ```
//!
//! Every output is 32 bytes: AES-256 and HMAC-SHA256.
//!
//! Ported from Bada's `core-protocol` (Apache 2.0, Copyright 2026 Bada contributors),
//! which notes that bit-exact parity with NearDrop's `finalizeKeyExchange` is required.
//!
//! Never log any value in this module. All of them gate confidentiality and integrity
//! of every frame on the connection.

use crate::hkdf;
use openssl::error::ErrorStack;
use openssl::hash::{hash, MessageDigest};

/// AES-256 / HMAC-SHA256. Every key in the chain is this size.
pub const KEY_SIZE: usize = 32;

const UKEY2_AUTH_SALT: &[u8] = b"UKEY2 v1 auth";
const UKEY2_NEXT_SALT: &[u8] = b"UKEY2 v1 next";

/// `SHA256("D2D")`. Hardcoded rather than computed so the value is reviewable inline
/// against the reference implementations; `d2d_salt_is_sha256_of_d2d` asserts it.
const D2D_SALT: [u8; 32] = [
    0x82, 0xAA, 0x55, 0xA0, 0xD3, 0x97, 0xF8, 0x83, 0x46, 0xCA, 0x1C, 0xEE, 0x8D, 0x39, 0x09, 0xB9,
    0x5F, 0x13, 0xFA, 0x7D, 0xEB, 0x1D, 0x4A, 0xB3, 0x83, 0x76, 0xB8, 0x25, 0x6D, 0xA8, 0x55, 0x10,
];

/// `SHA256("SecureMessage")`. Same reasoning as D2D_SALT.
const SM_SALT: [u8; 32] = [
    0xBF, 0x9D, 0x2A, 0x53, 0xC6, 0x36, 0x16, 0xD7, 0x5D, 0xB0, 0xA7, 0x16, 0x5B, 0x91, 0xC1, 0xEF,
    0x73, 0xE5, 0x37, 0xF2, 0x42, 0x74, 0x05, 0xFA, 0x23, 0x61, 0x0A, 0x4B, 0xE6, 0x57, 0x64, 0x2E,
];

const INFO_CLIENT: &[u8] = b"client";
const INFO_SERVER: &[u8] = b"server";
const INFO_ENCRYPT: &[u8] = b"ENC:2";
const INFO_HMAC: &[u8] = b"SIG:1";

/// Which end of the connection we are.
///
/// This exists as a type rather than a bool because the send/receive selection below
/// is the single most error-prone step in the stack: swapping it produces a session
/// that completes its handshake and then cannot read anything the peer sends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Client,
    Server,
}

/// The four traffic keys. Two per direction.
#[derive(Clone)]
pub struct SessionKeys {
    pub client_encrypt: Vec<u8>,
    pub client_hmac: Vec<u8>,
    pub server_encrypt: Vec<u8>,
    pub server_hmac: Vec<u8>,
}

impl SessionKeys {
    /// Keys for frames WE send: `(encrypt, hmac)`.
    ///
    /// The whole role swap lives here and in `recv`, so there is one place to be
    /// wrong and one place to check.
    pub fn send(&self, role: Role) -> (&[u8], &[u8]) {
        match role {
            Role::Client => (&self.client_encrypt, &self.client_hmac),
            Role::Server => (&self.server_encrypt, &self.server_hmac),
        }
    }

    /// Keys for frames the PEER sends: `(encrypt, hmac)`.
    pub fn recv(&self, role: Role) -> (&[u8], &[u8]) {
        match role {
            Role::Client => (&self.server_encrypt, &self.server_hmac),
            Role::Server => (&self.client_encrypt, &self.client_hmac),
        }
    }
}

/// Everything stage 1 produces. `auth_string` is shown to the user for verification;
/// `next_secret` feeds stages 2 and 3 and must never leave the process.
pub struct Ukey2Secrets {
    pub auth_string: Vec<u8>,
    pub next_secret: Vec<u8>,
}

/// Stage 1. `client_init` and `server_init` are the raw serialized handshake messages,
/// concatenated in that order and NOT length-prefixed.
pub fn ukey2_secrets(
    dhs: &[u8],
    client_init: &[u8],
    server_init: &[u8],
) -> Result<Ukey2Secrets, ErrorStack> {
    let mut info = Vec::with_capacity(client_init.len() + server_init.len());
    info.extend_from_slice(client_init);
    info.extend_from_slice(server_init);
    Ok(Ukey2Secrets {
        auth_string: hkdf::derive(dhs, UKEY2_AUTH_SALT, &info, KEY_SIZE)?,
        next_secret: hkdf::derive(dhs, UKEY2_NEXT_SALT, &info, KEY_SIZE)?,
    })
}

/// Stages 2 and 3, from the stage 1 `next_secret`.
pub fn session_keys(next_secret: &[u8]) -> Result<SessionKeys, ErrorStack> {
    let d2d_client = hkdf::derive(next_secret, &D2D_SALT, INFO_CLIENT, KEY_SIZE)?;
    let d2d_server = hkdf::derive(next_secret, &D2D_SALT, INFO_SERVER, KEY_SIZE)?;
    Ok(SessionKeys {
        client_encrypt: hkdf::derive(&d2d_client, &SM_SALT, INFO_ENCRYPT, KEY_SIZE)?,
        client_hmac: hkdf::derive(&d2d_client, &SM_SALT, INFO_HMAC, KEY_SIZE)?,
        server_encrypt: hkdf::derive(&d2d_server, &SM_SALT, INFO_ENCRYPT, KEY_SIZE)?,
        server_hmac: hkdf::derive(&d2d_server, &SM_SALT, INFO_HMAC, KEY_SIZE)?,
    })
}

/// The whole chain: handshake output in, traffic keys out.
pub fn derive_all(
    dhs: &[u8],
    client_init: &[u8],
    server_init: &[u8],
) -> Result<(Ukey2Secrets, SessionKeys), ErrorStack> {
    let secrets = ukey2_secrets(dhs, client_init, server_init)?;
    let keys = session_keys(&secrets.next_secret)?;
    Ok((secrets, keys))
}

fn sha256(data: &[u8]) -> Result<Vec<u8>, ErrorStack> {
    Ok(hash(MessageDigest::sha256(), data)?.to_vec())
}

/// The intermediate D2D keys, exposed only so tests can assert stage 2 separately
/// from stage 3. Nothing outside this module should need them.
#[cfg(test)]
fn d2d_keys(next_secret: &[u8]) -> Result<(Vec<u8>, Vec<u8>), ErrorStack> {
    Ok((
        hkdf::derive(next_secret, &D2D_SALT, INFO_CLIENT, KEY_SIZE)?,
        hkdf::derive(next_secret, &D2D_SALT, INFO_SERVER, KEY_SIZE)?,
    ))
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

    /// Bada's D2DKeyDerivationVectors.primary. Every stage is asserted separately, so
    /// a failure names which one drifted instead of only reporting a wrong final key.
    fn vector() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let dhs = hex("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff");
        // "CLIENTINIT" then 0x00..0x1f
        let mut client_init = b"CLIENTINIT".to_vec();
        client_init.extend(0u8..=0x1f);
        // "SERVERINIT" then 0x20..0x3f
        let mut server_init = b"SERVERINIT".to_vec();
        server_init.extend(0x20u8..=0x3f);
        (dhs, client_init, server_init)
    }

    #[test]
    fn stage1_ukey2_secrets() {
        let (dhs, ci, si) = vector();
        let s = ukey2_secrets(&dhs, &ci, &si).unwrap();
        assert_eq!(
            s.auth_string,
            hex("57fbc2bd6859ab0c4a900f5a936249a34f710c49363a7c4a96134c36a812c4e8"),
            "authString"
        );
        assert_eq!(
            s.next_secret,
            hex("b0c16a7ef577fe20c638354db7ca5c97aa4953a75b2443223e854e2e5a081668"),
            "nextSecret"
        );
    }

    #[test]
    fn stage2_d2d_keys() {
        let (dhs, ci, si) = vector();
        let s = ukey2_secrets(&dhs, &ci, &si).unwrap();
        let (client, server) = d2d_keys(&s.next_secret).unwrap();
        assert_eq!(
            client,
            hex("dc012fe41bf4d1414318282aee1ad92205fdde7cd20ebcc9c9249d5493b1e238"),
            "d2dClient"
        );
        assert_eq!(
            server,
            hex("21383b4fab61ada496d32cd72bd3bcde302653b569e5a874134249348a42f1d9"),
            "d2dServer"
        );
    }

    #[test]
    fn stage3_session_keys() {
        let (dhs, ci, si) = vector();
        let (_, k) = derive_all(&dhs, &ci, &si).unwrap();
        assert_eq!(
            k.client_encrypt,
            hex("8270749c4000b76f74060f5417577ed7eef1798810beb0583e1fd35e7aa81ad4"),
            "clientEncrypt"
        );
        assert_eq!(
            k.client_hmac,
            hex("66324fd288e0aa496aa9265e0f5b46a1bb157889347a11ee767ba829d8745613"),
            "clientHmac"
        );
        assert_eq!(
            k.server_encrypt,
            hex("faf1c47ac8b37af412816c856681ed33c871345132a3c0252a8b1313e552912f"),
            "serverEncrypt"
        );
        assert_eq!(
            k.server_hmac,
            hex("f75d953f97063d53d52ba3b9093604da64fc7cde621dc65779acbaa81fe61d92"),
            "serverHmac"
        );
    }

    /// The hardcoded salts must actually be the digests they claim to be. Without this
    /// a transcription error in either constant would look like a protocol difference.
    #[test]
    fn salts_are_the_digests_they_claim() {
        assert_eq!(sha256(b"D2D").unwrap(), D2D_SALT, "SHA256(\"D2D\")");
        assert_eq!(
            sha256(b"SecureMessage").unwrap(),
            SM_SALT,
            "SHA256(\"SecureMessage\")"
        );
    }

    /// What one end sends, the other must receive. This is the swap that produces a
    /// session which handshakes cleanly and then reads nothing.
    #[test]
    fn roles_are_mirror_images() {
        let (dhs, ci, si) = vector();
        let (_, k) = derive_all(&dhs, &ci, &si).unwrap();
        assert_eq!(k.send(Role::Client), k.recv(Role::Server), "client -> server");
        assert_eq!(k.send(Role::Server), k.recv(Role::Client), "server -> client");
        // And the two directions must not be the same keys, or the mirror above would
        // hold trivially while offering no separation at all.
        assert_ne!(k.send(Role::Client), k.send(Role::Server), "directions differ");
    }

    /// Both init messages feed one info string in a fixed order, so swapping them must
    /// change every key. Catches a concatenation written the wrong way round.
    #[test]
    fn init_message_order_matters() {
        let (dhs, ci, si) = vector();
        let a = ukey2_secrets(&dhs, &ci, &si).unwrap();
        let b = ukey2_secrets(&dhs, &si, &ci).unwrap();
        assert_ne!(a.auth_string, b.auth_string);
        assert_ne!(a.next_secret, b.next_secret);
    }
}

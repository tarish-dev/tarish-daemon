//! The UKEY2 handshake: how two devices that have never met agree on `dhs`.
//!
//! The output feeds `crate::d2d`, which turns it into the four traffic keys, which
//! `crate::securemessage` then uses for every frame. Those three layers are done; this
//! is the one that produces their input.
//!
//! Shape of the exchange:
//!
//! ```text
//! client -> ClientInit    version, random, cipher_commitments[{P256_SHA512, SHA512(ClientFinished)}]
//! server -> ServerInit    version, random, handshake_cipher, public_key
//! client -> ClientFinished public_key
//!
//! both:   dhs = SHA-256(ECDH(peer_public, own_private).x_magnitude)
//! ```
//!
//! The commitment is what stops a server choosing its key after seeing the client's:
//! the client publishes SHA-512 of its final message up front, and the server checks
//! it once the real message arrives.

pub mod crypto;
pub mod handshake;

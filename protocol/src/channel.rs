//! The secure channel: keys, sequence numbers, and the direction they belong to.
//!
//! `securemessage` is stateless by design and `d2d` only derives keys. Something has to
//! hold the pair of them together with the two counters, and that is this. It is the
//! smallest object that can be handed a frame and produce wire bytes.
//!
//! ```text
//! send:  frame bytes -> D2D { seq, payload } -> AES-256-CBC -> HMAC -> SecureMessage
//! recv:  the reverse, and then the sequence number is CHECKED
//! ```
//!
//! **Sequence numbers are validated, not just carried.** They exist so that a frame
//! cannot be replayed or silently dropped, and a channel that reads the counter without
//! checking it has the field but not the property. Ours must increase by exactly one:
//! a repeat is a replay, a gap means a frame went missing, and both end the connection
//! rather than being tolerated. Nothing in Quick Share legitimately reorders frames --
//! they arrive on one TCP connection in the order they were written.
//!
//! **Direction is a type, not a bool.** Which of the four keys encrypts and which
//! verifies depends on whether we are the client or the server, and getting it backwards
//! produces a session that completes its handshake perfectly and then cannot read a
//! single frame the peer sends. `d2d::Role` carries it, and this module never decides it
//! -- it is fixed at construction from how the connection was made.

use crate::d2d::{Role, SessionKeys};
use crate::securemessage;
use std::fmt;

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    /// The MAC did not verify, or the message would not parse. Deliberately one error:
    /// distinguishing them tells an attacker which half of a forgery was wrong.
    NotAuthentic,
    /// The peer's sequence number was not the one that must come next.
    Sequence { expected: i32, got: i32 },
    Crypto,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::NotAuthentic => write!(f, "channel: frame did not authenticate"),
            Error::Sequence { expected, got } => {
                write!(f, "channel: expected sequence {expected}, got {got}")
            }
            Error::Crypto => write!(f, "channel: crypto operation failed"),
        }
    }
}

/// An established, encrypted channel to one peer.
pub struct SecureChannel {
    keys: SessionKeys,
    role: Role,
    send_seq: i32,
    recv_seq: i32,
}

impl SecureChannel {
    /// Both counters start at 0, so the first frame in each direction carries 1.
    pub fn new(keys: SessionKeys, role: Role) -> Self {
        Self {
            keys,
            role,
            send_seq: 0,
            recv_seq: 0,
        }
    }

    /// Encrypt and sign one frame. The result is the SecureMessage bytes, ready for the
    /// length-prefix layer.
    pub fn encrypt(&mut self, payload: &[u8]) -> Result<Vec<u8>, Error> {
        // Incremented BEFORE use, so the first frame is 1 rather than 0. A peer that
        // sees 0 treats it as an uninitialised channel.
        self.send_seq = self.send_seq.wrapping_add(1);
        let (enc, mac) = self.keys.send(self.role);
        let iv = securemessage::random_iv().map_err(|_| Error::Crypto)?;
        securemessage::encrypt_and_sign(enc, mac, self.send_seq, payload, &iv)
            .map_err(|_| Error::Crypto)
    }

    /// Verify, decrypt, and check the sequence number.
    ///
    /// On any failure the channel is left unchanged, so a rejected frame cannot advance
    /// the receive counter and open a gap for the next one to slip through.
    pub fn decrypt(&mut self, wire: &[u8]) -> Result<Vec<u8>, Error> {
        let (enc, mac) = self.keys.recv(self.role);
        let out = securemessage::verify_and_decrypt(enc, mac, wire).map_err(|_| Error::NotAuthentic)?;

        let expected = self.recv_seq.wrapping_add(1);
        if out.sequence_number != expected {
            return Err(Error::Sequence {
                expected,
                got: out.sequence_number,
            });
        }
        self.recv_seq = expected;
        Ok(out.payload)
    }

    /// How many frames we have sent and received. For diagnostics; a channel that stops
    /// working is much easier to place when both counters are in the log.
    pub fn counters(&self) -> (i32, i32) {
        (self.send_seq, self.recv_seq)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::d2d;

    /// Build the two ends of one session, as the handshake would.
    fn pair() -> (SecureChannel, SecureChannel) {
        let keys = d2d::session_keys(&[0x42u8; 32]).unwrap();
        (
            SecureChannel::new(keys.clone(), Role::Client),
            SecureChannel::new(keys, Role::Server),
        )
    }

    #[test]
    fn a_frame_survives_the_round_trip() {
        let (mut client, mut server) = pair();
        let wire = client.encrypt(b"hello there").unwrap();
        assert_eq!(server.decrypt(&wire).unwrap(), b"hello there");
    }

    #[test]
    fn both_directions_work_independently() {
        let (mut client, mut server) = pair();
        for i in 0..10u8 {
            let up = client.encrypt(&[i; 16]).unwrap();
            assert_eq!(server.decrypt(&up).unwrap(), vec![i; 16]);
            let down = server.encrypt(&[i + 100; 16]).unwrap();
            assert_eq!(client.decrypt(&down).unwrap(), vec![i + 100; 16]);
        }
        assert_eq!(client.counters(), (10, 10));
        assert_eq!(server.counters(), (10, 10));
    }

    /// The first frame must be sequence 1. A peer that receives 0 reads the channel as
    /// uninitialised.
    #[test]
    fn the_first_frame_is_sequence_one() {
        let (mut client, _) = pair();
        client.encrypt(b"x").unwrap();
        assert_eq!(client.counters().0, 1);
    }

    /// The property sequence numbers exist for. Replaying a captured frame must fail
    /// even though its MAC is perfectly valid.
    #[test]
    fn a_replayed_frame_is_refused() {
        let (mut client, mut server) = pair();
        let wire = client.encrypt(b"pay me twice").unwrap();
        assert!(server.decrypt(&wire).is_ok());
        assert_eq!(
            server.decrypt(&wire),
            Err(Error::Sequence { expected: 2, got: 1 })
        );
    }

    /// A dropped frame must be noticed rather than skipped over.
    #[test]
    fn a_gap_is_refused() {
        let (mut client, mut server) = pair();
        let _first = client.encrypt(b"one").unwrap();
        let second = client.encrypt(b"two").unwrap();
        assert_eq!(
            server.decrypt(&second),
            Err(Error::Sequence { expected: 1, got: 2 })
        );
    }

    /// A rejected frame must not advance the counter, or the frame after it would be
    /// accepted into the gap the rejection created.
    #[test]
    fn a_rejected_frame_does_not_advance_the_counter() {
        let (mut client, mut server) = pair();
        let _skipped = client.encrypt(b"one").unwrap();
        let second = client.encrypt(b"two").unwrap();
        assert!(server.decrypt(&second).is_err());
        assert_eq!(server.counters().1, 0, "counter moved on a rejected frame");
    }

    /// Swapping the roles is the single most likely mistake in this stack: the handshake
    /// completes and then nothing can be read.
    #[test]
    fn two_channels_with_the_same_role_cannot_talk() {
        let keys = d2d::session_keys(&[9u8; 32]).unwrap();
        let mut a = SecureChannel::new(keys.clone(), Role::Client);
        let mut b = SecureChannel::new(keys, Role::Client);
        let wire = a.encrypt(b"hello").unwrap();
        assert_eq!(b.decrypt(&wire), Err(Error::NotAuthentic));
    }

    #[test]
    fn a_tampered_frame_is_refused() {
        let (mut client, mut server) = pair();
        let mut wire = client.encrypt(b"the original message").unwrap();
        let n = wire.len();
        wire[n / 2] ^= 0x01;
        assert_eq!(server.decrypt(&wire), Err(Error::NotAuthentic));
    }

    #[test]
    fn a_foreign_key_is_refused() {
        let (mut client, _) = pair();
        let other = d2d::session_keys(&[0xAAu8; 32]).unwrap();
        let mut eavesdropper = SecureChannel::new(other, Role::Server);
        let wire = client.encrypt(b"secret").unwrap();
        assert_eq!(eavesdropper.decrypt(&wire), Err(Error::NotAuthentic));
    }

    #[test]
    fn an_empty_payload_round_trips() {
        let (mut client, mut server) = pair();
        let wire = client.encrypt(b"").unwrap();
        assert_eq!(server.decrypt(&wire).unwrap(), b"");
    }

    /// Chunks are hundreds of KiB, so this is the size that actually flows.
    #[test]
    fn a_large_payload_round_trips() {
        let (mut client, mut server) = pair();
        let big: Vec<u8> = (0..512 * 1024).map(|i| (i % 251) as u8).collect();
        let wire = client.encrypt(&big).unwrap();
        assert_eq!(server.decrypt(&wire).unwrap(), big);
    }

    #[test]
    fn garbage_does_not_panic() {
        let (_, mut server) = pair();
        for len in 0..96 {
            let junk: Vec<u8> = (0..len).map(|i| (i * 31 + 5) as u8).collect();
            assert!(server.decrypt(&junk).is_err());
        }
    }
}

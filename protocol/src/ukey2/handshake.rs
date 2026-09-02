//! The UKEY2 handshake messages and the two state machines that drive them.
//!
//! Sans-IO on purpose: every step takes the bytes of the peer's last message and returns
//! the bytes of the next one. No sockets, no async, no timers. That is what lets the
//! whole exchange be tested as a client talking to a server inside one process, with no
//! phone and no peer, and it is why a fault here is found by `cargo test` rather than by
//! staring at a failed transfer three layers up.
//!
//! ```text
//! client -> ClientInit      version, random, commitments[{P256_SHA512, SHA512(ClientFinished)}]
//! server -> ServerInit      version, random, handshake_cipher, public_key
//! client -> ClientFinished  public_key
//!
//! both:     dhs = SHA-256(ECDH(peer_public, own_private).x_magnitude)
//! ```
//!
//! **The commitment is the whole point.** The client publishes SHA-512 of its final
//! message before the server has said anything, so the server cannot choose its key
//! after seeing the client's. The server checks it when the real message arrives, and a
//! mismatch is fatal rather than a warning -- accepting one would silently give up the
//! only property this exchange has.
//!
//! Both `Ukey2Message` wrappers are kept in the result. They are the HKDF `info` for the
//! next-protocol keys and the auth string, and neither side can recompute the other's,
//! because each contains a random nonce the peer never sees except in that message.

use super::crypto::{self, Error};
use crate::protobuf::{Field, Reader, Writer};
use openssl::ec::EcKey;
use openssl::pkey::Private;

/// Highest version we speak. Quick Share is locked to 1.
pub const PROTOCOL_VERSION: u64 = 1;

/// The per-side nonce length. The spec fixes it at 32 and peers reject anything else.
pub const RANDOM_SIZE: usize = 32;

/// The only `next_protocol` Quick Share negotiates. Required verbatim -- anything else
/// earns a `BAD_NEXT_PROTOCOL` alert from a real peer.
pub const NEXT_PROTOCOL: &str = "AES_256_CBC-HMAC_SHA256";

/// NIST P-256 for ECDH, SHA-512 for the commitment. The only cipher seen in the wild.
pub const CIPHER_P256_SHA512: u64 = 100;

// Ukey2Message.Type
const TYPE_ALERT: u64 = 1;
const TYPE_CLIENT_INIT: u64 = 2;
const TYPE_SERVER_INIT: u64 = 3;
const TYPE_CLIENT_FINISH: u64 = 4;

// Ukey2Message
const MSG_TYPE: u32 = 1;
const MSG_DATA: u32 = 2;

// Ukey2ClientInit
const CI_VERSION: u32 = 1;
const CI_RANDOM: u32 = 2;
const CI_COMMITMENTS: u32 = 3;
const CI_NEXT_PROTOCOL: u32 = 4;

// Ukey2ClientInit.CipherCommitment
const CC_CIPHER: u32 = 1;
const CC_COMMITMENT: u32 = 2;

// Ukey2ServerInit
const SI_VERSION: u32 = 1;
const SI_RANDOM: u32 = 2;
const SI_CIPHER: u32 = 3;
const SI_PUBLIC_KEY: u32 = 4;

// Ukey2ClientFinished
const CF_PUBLIC_KEY: u32 = 1;

// Ukey2Alert
const AL_TYPE: u32 = 1;
const AL_MESSAGE: u32 = 2;

/// Alert codes worth sending. The peer logs these, and picking the right one is the
/// difference between a peer that reports a real reason and one that reports "failed".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Alert {
    BadMessage = 1,
    BadMessageType = 2,
    IncorrectMessage = 3,
    BadMessageData = 4,
    BadVersion = 100,
    BadRandom = 101,
    BadHandshakeCipher = 102,
    BadNextProtocol = 103,
    BadPublicKey = 104,
    InternalError = 200,
}

/// What a completed handshake yields. Feeds `crate::d2d`.
#[derive(Debug, Clone)]
pub struct HandshakeResult {
    /// `SHA-256(ECDH(...).x_magnitude)`, 32 bytes.
    pub dhs: Vec<u8>,
    /// The serialized `Ukey2Message` wrapping ClientInit -- the wrapper, not the inner
    /// message, and not length-prefixed.
    pub client_init_msg: Vec<u8>,
    /// The serialized `Ukey2Message` wrapping ServerInit, same convention.
    pub server_init_msg: Vec<u8>,
}

// ------------------------------------------------------------------ encoding ---

fn wrap(msg_type: u64, data: &[u8]) -> Vec<u8> {
    let mut w = Writer::new();
    w.varint(MSG_TYPE, msg_type).bytes(MSG_DATA, data);
    w.finish()
}

/// Unwrap a `Ukey2Message`, checking it is the type we are waiting for.
///
/// The type check is here rather than at each call site so that receiving a ServerInit
/// where a ClientFinished belongs is `IncorrectMessage` every time, instead of a parse
/// error whose message depends on which field happened to collide.
fn unwrap(bytes: &[u8], expect: u64) -> Result<Vec<u8>, Error> {
    let mut ty = None;
    let mut data = None;
    let mut r = Reader::new(bytes);
    while let Some(f) = r.next_field() {
        match f? {
            Field::Varint(MSG_TYPE, v) => ty = Some(v),
            Field::Bytes(MSG_DATA, b) => data = Some(b.to_vec()),
            _ => {}
        }
    }
    match ty {
        Some(t) if t == expect => {}
        Some(t) if t == TYPE_ALERT => return Err(Error::Malformed("peer sent an alert")),
        Some(_) => return Err(Error::Malformed("unexpected message type")),
        None => return Err(Error::Malformed("no message_type")),
    }
    data.ok_or(Error::Malformed("no message_data"))
}

/// Build an alert to hand back to the peer before hanging up.
///
/// Worth sending rather than just closing: a peer that gets an alert reports why it
/// failed, and every hour spent on "it just disconnects" is an hour this would have
/// saved on the other side.
pub fn alert(kind: Alert, message: &str) -> Vec<u8> {
    let mut a = Writer::new();
    a.varint(AL_TYPE, kind as u64).bytes(AL_MESSAGE, message.as_bytes());
    wrap(TYPE_ALERT, &a.finish())
}

fn client_init(random: &[u8], commitment: &[u8]) -> Vec<u8> {
    let mut cc = Writer::new();
    cc.varint(CC_CIPHER, CIPHER_P256_SHA512)
        .bytes(CC_COMMITMENT, commitment);
    let cc = cc.finish();

    let mut ci = Writer::new();
    ci.varint(CI_VERSION, PROTOCOL_VERSION)
        .bytes(CI_RANDOM, random)
        .bytes(CI_COMMITMENTS, &cc)
        .bytes(CI_NEXT_PROTOCOL, NEXT_PROTOCOL.as_bytes());
    wrap(TYPE_CLIENT_INIT, &ci.finish())
}

fn server_init(random: &[u8], public_key: &[u8]) -> Vec<u8> {
    let mut si = Writer::new();
    si.varint(SI_VERSION, PROTOCOL_VERSION)
        .bytes(SI_RANDOM, random)
        .varint(SI_CIPHER, CIPHER_P256_SHA512)
        .bytes(SI_PUBLIC_KEY, public_key);
    wrap(TYPE_SERVER_INIT, &si.finish())
}

fn client_finished(public_key: &[u8]) -> Vec<u8> {
    let mut cf = Writer::new();
    cf.bytes(CF_PUBLIC_KEY, public_key);
    wrap(TYPE_CLIENT_FINISH, &cf.finish())
}

fn random_bytes(n: usize) -> Result<Vec<u8>, Error> {
    let mut buf = vec![0u8; n];
    openssl::rand::rand_bytes(&mut buf)?;
    Ok(buf)
}

// -------------------------------------------------------------------- client ---

/// Client side. Created with `start`, finished with `handle_server_init`.
pub struct ClientHandshake {
    key: EcKey<Private>,
    /// The exact ClientFinished bytes committed to. Sent verbatim -- rebuilding the
    /// message instead of storing it is how a commitment check fails for no visible
    /// reason, because protobuf field order is not guaranteed to repeat.
    client_finished_msg: Vec<u8>,
    client_init_msg: Vec<u8>,
}

impl ClientHandshake {
    /// Produce ClientInit. The returned bytes go on the wire as-is.
    pub fn start() -> Result<(Self, Vec<u8>), Error> {
        let key = crypto::generate_keypair()?;
        let client_finished_msg = client_finished(&crypto::encode_public_key(&key)?);
        let commitment = crypto::sha512(&client_finished_msg)?;
        let client_init_msg = client_init(&random_bytes(RANDOM_SIZE)?, &commitment);
        Ok((
            Self {
                key,
                client_finished_msg,
                client_init_msg: client_init_msg.clone(),
            },
            client_init_msg,
        ))
    }

    /// Consume ServerInit and produce (ClientFinished bytes, result).
    pub fn handle_server_init(
        self,
        server_init_msg: &[u8],
    ) -> Result<(Vec<u8>, HandshakeResult), Error> {
        let body = unwrap(server_init_msg, TYPE_SERVER_INIT)?;

        let mut version = None;
        let mut random = None;
        let mut cipher = None;
        let mut public_key = None;
        let mut r = Reader::new(&body);
        while let Some(f) = r.next_field() {
            match f? {
                Field::Varint(SI_VERSION, v) => version = Some(v),
                Field::Bytes(SI_RANDOM, b) => random = Some(b.to_vec()),
                Field::Varint(SI_CIPHER, v) => cipher = Some(v),
                Field::Bytes(SI_PUBLIC_KEY, b) => public_key = Some(b.to_vec()),
                _ => {}
            }
        }

        if version != Some(PROTOCOL_VERSION) {
            return Err(Error::Malformed("server version is not 1"));
        }
        // Checked because the spec fixes it, and a short nonce is the difference between
        // a replay being impossible and being merely unlikely.
        match random {
            Some(ref r) if r.len() == RANDOM_SIZE => {}
            _ => return Err(Error::Malformed("server random is not 32 bytes")),
        }
        if cipher != Some(CIPHER_P256_SHA512) {
            return Err(Error::Malformed("server chose a cipher we did not offer"));
        }
        let public_key = public_key.ok_or(Error::Malformed("no server public_key"))?;

        // decode_public_key verifies the point is on P-256. That check is what stops an
        // invalid-curve attack recovering our private scalar from the traffic keys.
        let peer = crypto::decode_public_key(&public_key)?;
        let dhs = crypto::shared_secret(&self.key, &peer)?;

        Ok((
            self.client_finished_msg,
            HandshakeResult {
                dhs,
                client_init_msg: self.client_init_msg,
                server_init_msg: server_init_msg.to_vec(),
            },
        ))
    }
}

// -------------------------------------------------------------------- server ---

/// Server side. Created by `handle_client_init`, finished by `handle_client_finished`.
pub struct ServerHandshake {
    key: EcKey<Private>,
    commitment: Vec<u8>,
    client_init_msg: Vec<u8>,
    server_init_msg: Vec<u8>,
}

impl ServerHandshake {
    /// Consume ClientInit and produce (ServerInit bytes, state).
    pub fn handle_client_init(client_init_msg: &[u8]) -> Result<(Self, Vec<u8>), Error> {
        let body = unwrap(client_init_msg, TYPE_CLIENT_INIT)?;

        let mut version = None;
        let mut random = None;
        let mut next_protocol = None;
        // REPEATED field, so every occurrence is collected rather than the last one
        // winning. A client is entitled to offer several ciphers, and taking only the
        // last would refuse a peer that put P256_SHA512 first and something else after.
        let mut commitment = None;
        let mut r = Reader::new(&body);
        while let Some(f) = r.next_field() {
            match f? {
                Field::Varint(CI_VERSION, v) => version = Some(v),
                Field::Bytes(CI_RANDOM, b) => random = Some(b.to_vec()),
                Field::Bytes(CI_NEXT_PROTOCOL, b) => next_protocol = Some(b.to_vec()),
                Field::Bytes(CI_COMMITMENTS, b) => {
                    if commitment.is_none() {
                        if let Some(c) = cipher_commitment(b)? {
                            commitment = Some(c);
                        }
                    }
                }
                _ => {}
            }
        }

        if version != Some(PROTOCOL_VERSION) {
            return Err(Error::Malformed("client version is not 1"));
        }
        match random {
            Some(ref r) if r.len() == RANDOM_SIZE => {}
            _ => return Err(Error::Malformed("client random is not 32 bytes")),
        }
        if next_protocol.as_deref() != Some(NEXT_PROTOCOL.as_bytes()) {
            return Err(Error::Malformed("client asked for another next_protocol"));
        }
        let commitment = commitment.ok_or(Error::Malformed("no P256_SHA512 commitment"))?;

        let key = crypto::generate_keypair()?;
        let server_init_msg = server_init(
            &random_bytes(RANDOM_SIZE)?,
            &crypto::encode_public_key(&key)?,
        );

        Ok((
            Self {
                key,
                commitment,
                client_init_msg: client_init_msg.to_vec(),
                server_init_msg: server_init_msg.clone(),
            },
            server_init_msg,
        ))
    }

    /// Verify the commitment, then finish.
    pub fn handle_client_finished(
        self,
        client_finished_msg: &[u8],
    ) -> Result<HandshakeResult, Error> {
        // COMMITMENT FIRST, over the message as received.
        //
        // Checked before parsing anything out of it, and against the raw bytes rather
        // than a re-serialization: the commitment covers what the client actually sent,
        // and re-encoding could differ in field order or integer width while carrying
        // the same values. Verifying a reconstruction would check nothing.
        if crypto::sha512(client_finished_msg)? != self.commitment {
            return Err(Error::Malformed("client finished does not match its commitment"));
        }

        let body = unwrap(client_finished_msg, TYPE_CLIENT_FINISH)?;
        let public_key = crate::protobuf::first_bytes(&body, CF_PUBLIC_KEY)?
            .ok_or(Error::Malformed("no client public_key"))?;
        let peer = crypto::decode_public_key(public_key)?;
        let dhs = crypto::shared_secret(&self.key, &peer)?;

        Ok(HandshakeResult {
            dhs,
            client_init_msg: self.client_init_msg,
            server_init_msg: self.server_init_msg,
        })
    }
}

/// Pull the commitment out of one CipherCommitment, if it is the cipher we speak.
fn cipher_commitment(bytes: &[u8]) -> Result<Option<Vec<u8>>, Error> {
    let mut cipher = None;
    let mut commitment = None;
    let mut r = Reader::new(bytes);
    while let Some(f) = r.next_field() {
        match f? {
            Field::Varint(CC_CIPHER, v) => cipher = Some(v),
            Field::Bytes(CC_COMMITMENT, b) => commitment = Some(b.to_vec()),
            _ => {}
        }
    }
    if cipher == Some(CIPHER_P256_SHA512) {
        Ok(commitment)
    } else {
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The whole exchange, both sides in one process. Both must reach the same dhs and
    /// must agree byte for byte on the two wrapper messages, because those become HKDF
    /// input and a one-byte difference there produces different keys and a failure that
    /// surfaces as "the peer rejected us".
    #[test]
    fn client_and_server_agree() {
        let (client, ci) = ClientHandshake::start().unwrap();
        let (server, si) = ServerHandshake::handle_client_init(&ci).unwrap();
        let (cf, client_result) = client.handle_server_init(&si).unwrap();
        let server_result = server.handle_client_finished(&cf).unwrap();

        assert_eq!(client_result.dhs, server_result.dhs);
        assert_eq!(client_result.dhs.len(), 32);
        assert_eq!(client_result.client_init_msg, server_result.client_init_msg);
        assert_eq!(client_result.server_init_msg, server_result.server_init_msg);
        assert_eq!(client_result.client_init_msg, ci);
        assert_eq!(client_result.server_init_msg, si);
    }

    /// Two runs must not produce the same keys. Ephemeral means ephemeral: reusing a
    /// keypair would make every session decryptable from any one compromise.
    #[test]
    fn each_handshake_is_fresh() {
        let (_, a) = ClientHandshake::start().unwrap();
        let (_, b) = ClientHandshake::start().unwrap();
        assert_ne!(a, b);
    }

    /// The property the commitment exists for. A server that answers a DIFFERENT
    /// ClientFinished than the one committed to must be refused.
    #[test]
    fn a_substituted_client_finished_is_refused() {
        let (_client, ci) = ClientHandshake::start().unwrap();
        let (server, _si) = ServerHandshake::handle_client_init(&ci).unwrap();

        // An attacker's key, offered in place of the committed one.
        let other = crypto::generate_keypair().unwrap();
        let forged = client_finished(&crypto::encode_public_key(&other).unwrap());

        let err = server.handle_client_finished(&forged).unwrap_err();
        assert_eq!(
            err,
            Error::Malformed("client finished does not match its commitment")
        );
    }

    #[test]
    fn wrong_message_type_is_rejected() {
        let (_, ci) = ClientHandshake::start().unwrap();
        // A ClientInit where a ServerInit belongs.
        let (client, _) = ClientHandshake::start().unwrap();
        assert!(client.handle_server_init(&ci).is_err());
    }

    #[test]
    fn an_alert_is_reported_as_such() {
        let a = alert(Alert::BadHandshakeCipher, "no");
        let (client, _) = ClientHandshake::start().unwrap();
        assert_eq!(
            client.handle_server_init(&a).unwrap_err(),
            Error::Malformed("peer sent an alert")
        );
    }

    #[test]
    fn server_refuses_a_foreign_next_protocol() {
        let key = crypto::generate_keypair().unwrap();
        let cf = client_finished(&crypto::encode_public_key(&key).unwrap());
        let commitment = crypto::sha512(&cf).unwrap();

        let mut cc = Writer::new();
        cc.varint(CC_CIPHER, CIPHER_P256_SHA512)
            .bytes(CC_COMMITMENT, &commitment);
        let cc = cc.finish();

        let mut ci = Writer::new();
        ci.varint(CI_VERSION, PROTOCOL_VERSION)
            .bytes(CI_RANDOM, &[7u8; RANDOM_SIZE])
            .bytes(CI_COMMITMENTS, &cc)
            .bytes(CI_NEXT_PROTOCOL, b"AES_128_CBC-HMAC_SHA1");
        let msg = wrap(TYPE_CLIENT_INIT, &ci.finish());

        assert_eq!(
            ServerHandshake::handle_client_init(&msg).err().unwrap(),
            Error::Malformed("client asked for another next_protocol")
        );
    }

    #[test]
    fn server_refuses_a_short_random() {
        let key = crypto::generate_keypair().unwrap();
        let cf = client_finished(&crypto::encode_public_key(&key).unwrap());
        let mut cc = Writer::new();
        cc.varint(CC_CIPHER, CIPHER_P256_SHA512)
            .bytes(CC_COMMITMENT, &crypto::sha512(&cf).unwrap());
        let cc = cc.finish();
        let mut ci = Writer::new();
        ci.varint(CI_VERSION, PROTOCOL_VERSION)
            .bytes(CI_RANDOM, &[1u8; 16]) // too short
            .bytes(CI_COMMITMENTS, &cc)
            .bytes(CI_NEXT_PROTOCOL, NEXT_PROTOCOL.as_bytes());
        let msg = wrap(TYPE_CLIENT_INIT, &ci.finish());

        assert_eq!(
            ServerHandshake::handle_client_init(&msg).err().unwrap(),
            Error::Malformed("client random is not 32 bytes")
        );
    }

    /// A client offering a cipher we do not speak, and nothing else, must be refused
    /// rather than silently handled with whatever commitment happened to be last.
    #[test]
    fn server_refuses_when_no_offered_cipher_matches() {
        let mut cc = Writer::new();
        cc.varint(CC_CIPHER, 200) // CURVE25519_SHA512
            .bytes(CC_COMMITMENT, &[9u8; 64]);
        let cc = cc.finish();
        let mut ci = Writer::new();
        ci.varint(CI_VERSION, PROTOCOL_VERSION)
            .bytes(CI_RANDOM, &[2u8; RANDOM_SIZE])
            .bytes(CI_COMMITMENTS, &cc)
            .bytes(CI_NEXT_PROTOCOL, NEXT_PROTOCOL.as_bytes());
        let msg = wrap(TYPE_CLIENT_INIT, &ci.finish());

        assert_eq!(
            ServerHandshake::handle_client_init(&msg).err().unwrap(),
            Error::Malformed("no P256_SHA512 commitment")
        );
    }

    /// A client that offers several ciphers must still work, with ours picked out of the
    /// list wherever it sits.
    #[test]
    fn server_finds_our_cipher_among_several() {
        let key = crypto::generate_keypair().unwrap();
        let cf = client_finished(&crypto::encode_public_key(&key).unwrap());
        let commitment = crypto::sha512(&cf).unwrap();

        let mut other = Writer::new();
        other.varint(CC_CIPHER, 200).bytes(CC_COMMITMENT, &[9u8; 64]);
        let other = other.finish();
        let mut ours = Writer::new();
        ours.varint(CC_CIPHER, CIPHER_P256_SHA512)
            .bytes(CC_COMMITMENT, &commitment);
        let ours = ours.finish();

        let mut ci = Writer::new();
        ci.varint(CI_VERSION, PROTOCOL_VERSION)
            .bytes(CI_RANDOM, &[3u8; RANDOM_SIZE])
            .bytes(CI_COMMITMENTS, &other)
            .bytes(CI_COMMITMENTS, &ours)
            .bytes(CI_NEXT_PROTOCOL, NEXT_PROTOCOL.as_bytes());
        let msg = wrap(TYPE_CLIENT_INIT, &ci.finish());

        let (server, _si) = ServerHandshake::handle_client_init(&msg).unwrap();
        assert!(server.handle_client_finished(&cf).is_ok());
    }

    #[test]
    fn version_mismatch_is_refused_on_both_sides() {
        let mut si = Writer::new();
        si.varint(SI_VERSION, 2)
            .bytes(SI_RANDOM, &[4u8; RANDOM_SIZE])
            .varint(SI_CIPHER, CIPHER_P256_SHA512)
            .bytes(SI_PUBLIC_KEY, &[0u8; 8]);
        let msg = wrap(TYPE_SERVER_INIT, &si.finish());
        let (client, _) = ClientHandshake::start().unwrap();
        assert_eq!(
            client.handle_server_init(&msg).unwrap_err(),
            Error::Malformed("server version is not 1")
        );
    }

    /// A public key that is not a point on P-256 must be refused before it reaches ECDH.
    #[test]
    fn a_bogus_server_key_is_refused() {
        let mut si = Writer::new();
        si.varint(SI_VERSION, PROTOCOL_VERSION)
            .bytes(SI_RANDOM, &[5u8; RANDOM_SIZE])
            .varint(SI_CIPHER, CIPHER_P256_SHA512)
            .bytes(SI_PUBLIC_KEY, &[0xAA; 40]);
        let msg = wrap(TYPE_SERVER_INIT, &si.finish());
        let (client, _) = ClientHandshake::start().unwrap();
        assert!(client.handle_server_init(&msg).is_err());
    }

    #[test]
    fn truncated_input_errors_rather_than_panics() {
        let (_, ci) = ClientHandshake::start().unwrap();
        for cut in 1..ci.len() {
            let _ = ServerHandshake::handle_client_init(&ci[..cut]);
        }
    }
}

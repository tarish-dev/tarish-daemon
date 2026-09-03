//! The Quick Share / Nearby Connections protocol, with no Android in it.
//!
//! Everything here is pure computation over bytes: no binder, no framework, no
//! interface names, no filesystem. That is what lets it be tested against known-answer
//! vectors on a build host instead of only on a phone, and it is why the code that
//! parses input from a stranger lives in a crate with no capabilities to abuse.
//!
//! Ported from Bada's `core-protocol` (Apache 2.0, Copyright 2026 Bada contributors),
//! which makes the same split for the same reasons and reads as a specification of the
//! protocol rather than as Android code.
//!
//! Layering, bottom up. Each layer is finished and verified before the one above it
//! starts, because a fault low down presents as a failure high up:
//!
//! | layer | state |
//! |---|---|
//! | `hkdf` — RFC 5869 key derivation | **done**, RFC vectors |
//! | `d2d` — post-handshake traffic keys | **done**, Bada vectors |
//! | `securemessage` — signed+encrypted envelope | **done** |
//! | `ukey2::crypto` — P-256 ECDH, key encoding | **done** |
//! | UKEY2 handshake messages and state machine | **done**, both sides round-trip |
//! | `protobuf` — minimal wire codec | **done** |
//! | `framing` — 4-byte length prefix | **done** |
//! | `frames` — offline frames | **done** |
//! | connection state machines | next |
//! | sharing FSM, payload | not started |
//!
//! Discovery is NOT here: it is in barqsharingd, because it needs sockets and an
//! interface name. It is done and verified against Google's Quick Share for Windows --
//! see `docs/QUICKSHARE-VECTORS.md`.

pub mod d2d;
pub mod frames;
pub mod framing;
pub mod hkdf;
pub mod protobuf;
pub mod securemessage;
pub mod ukey2;

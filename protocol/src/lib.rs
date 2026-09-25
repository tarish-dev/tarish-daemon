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
//! | layer | module | state |
//! |---|---|---|
//! | minimal protobuf wire codec | `protobuf` | **done** |
//! | RFC 5869 key derivation | `hkdf` | **done**, RFC vectors |
//! | P-256 ECDH and key encoding | `ukey2::crypto` | **done** |
//! | the UKEY2 handshake, both sides | `ukey2::handshake` | **done**, round-trips |
//! | post-handshake traffic keys | `d2d` | **done**, Bada vectors |
//! | signed + encrypted envelope | `securemessage` | **done** |
//! | keys, sequence numbers, direction | `channel` | **done** |
//! | 4-byte length prefix | `framing` | **done** |
//! | Nearby Connections messages | `frames` | **done** |
//! | chunk reassembly and its bounds | `payload` | **done** |
//! | Nearby Sharing messages | `sharing` | **done** |
//! | what may happen when | `fsm` | **done** |
//! | moving onto a faster medium | `upgrade` | **done** |
//! | the BLE wake-up pulse and endpoint advertisement | `ble` | **done** |
//! | Apple's BLE state message: will that iPhone take an AirDrop now | `apple` | **done**, measured on two iPhones |
//! | service identity and the addresses from it | `service` | **done** |
//! | the whole stack, two peers | `end_to_end` | **done**, one share start to finish |
//!
//! What is NOT here, and where it belongs instead:
//!
//! - **the socket, and discovery** — tarishsharingd, which needs an interface name and a
//!   multicast group. This crate never reads or writes a socket, which is why every
//!   awkward case above is a unit test rather than something to reproduce with two
//!   phones. mDNS discovery is done and verified against Google's Quick Share for
//!   Windows; the captured vectors are in `docs/QUICKSHARE-VECTORS.md`.
//! - **the filesystem** — tarishsharingd. `payload` validates offsets and lengths but does
//!   not sanitise names, because a path-traversal check belongs where the file is
//!   actually opened; anywhere else it reads as protection while the real write happens
//!   elsewhere.
//! - **BLE advertising and scanning** — the app. A native daemon cannot reach framework
//!   Bluetooth.
//! - **the radios for an upgrade** — the app. `upgrade` decides what to say and when;
//!   standing up a Wi-Fi Direct group or a hotspot, and BLE discovery before any of it,
//!   need framework APIs a native daemon cannot reach.

#[cfg(test)]
mod end_to_end;

pub mod apple;
pub mod ble;
pub mod channel;
pub mod d2d;
pub mod frames;
pub mod fsm;
pub mod framing;
pub mod hkdf;
pub mod multiplex;
pub mod payload;
pub mod pin;
pub mod protobuf;
pub mod sharing;
pub mod securemessage;
pub mod service;
pub mod ukey2;
pub mod upgrade;

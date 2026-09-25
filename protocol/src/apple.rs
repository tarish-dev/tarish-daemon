//! Apple Continuity advertisements: the one bit that says whether an iPhone will take an
//! AirDrop right now.
//!
//! **Why this exists.** iOS advertises its `_airdrop._tcp` records with a TTL of 4500 s
//! and sends a goodbye only on a graceful withdrawal. Screen off, AirDrop switched off, or
//! walking away sends nothing over mDNS, so a browser keeps the peer for seventy-five
//! minutes and the person taps a device that cannot answer: connection refused, a
//! "decline" nobody made, or a two-minute hang on an unanswered SYN. The withdrawal
//! signal is not on Wi-Fi at all. It is on BLE, and it is what an iPhone and stock Quick
//! Share both use to show a peer as "screen off" and then drop it.
//!
//! **Layout**, inside a manufacturer-specific AD structure under Apple's company id
//! `0x004C`. One structure can carry several messages back to back, each
//! `type, length, payload`:
//!
//! ```text
//!   10 05 FF AA T1 T2 T3        Nearby Info: type 0x10, 5 bytes: flags, action, auth tag
//!   05 12 00×8 01 HH×8 00       AirDrop:     type 0x05, 18 bytes: version, contact hashes
//! ```
//!
//! **What the flags byte means — MEASURED, not read from a specification.** Apple publishes
//! none. Taken 2026-09-25 off the air, one action at a time, on two iPhones with different
//! action bytes (an iPhone Mini, action `0x1e`; an iPhone Air, action `0x18`):
//!
//! | state                                  | flags        |
//! |----------------------------------------|--------------|
//! | AirDrop Receiving Off, unlocked        | `0x21`       |
//! | AirDrop Everyone, unlocked             | `0x61`, `0x64`, `0x65` |
//! | screen locked (Everyone still on)      | `0x21`       |
//! | unlocked again                         | `0x61`       |
//! | `+0x08` for ~25 s after any change     | a flicker, not a state |
//!
//! So bit `0x40` is **receptive to AirDrop right now** -- AirDrop on AND unlocked. Locking
//! and switching Receiving Off both clear it, which is why stock labels both as "screen
//! off": they look the same on the air, and they are the same for a sender. The low bits
//! vary between devices and are not interpreted here.
//!
//! **What silence means.** Switching Bluetooth off in Settings ends with total silence from
//! the device's addresses within about ten seconds (after a ~20 s burst at `0x68`). The
//! Control Centre tile does NOT: advertising continues and the bit is untouched, because
//! AirDrop is still live. A device whose addresses have all gone quiet is gone.
//!
//! **What this does not tell you.** The advertising address is random and rotates on every
//! state change -- both phones rotated at lock and at Everyone-on -- so it is not an
//! identity, and it cannot be mapped to an mDNS peer directly. The auth tag is resolvable
//! only by devices sharing the owner's iCloud keys. A Mac's flags have NOT been measured.
//! The caller counts devices; it does not name them.
//!
//! Pure computation, no Android: the app owns the radio and forwards the manufacturer
//! data bytes it scanned, which is what lets the decoder be tested here against the bytes
//! that were actually captured.

/// Apple's Bluetooth SIG company identifier.
pub const COMPANY_ID: u16 = 0x004C;

/// Message type: the AirDrop sender beacon -- the share sheet is open.
pub const TYPE_AIRDROP: u8 = 0x05;

/// Message type: Nearby Info -- the device's own state, sent continuously.
pub const TYPE_NEARBY_INFO: u8 = 0x10;

/// The flags bit that is set while the device will accept an AirDrop. See the module
/// docs for the measurement behind it.
pub const FLAG_RECEPTIVE: u8 = 0x40;

/// One Nearby Info message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NearbyInfo {
    pub flags: u8,
    pub action: u8,
}

impl NearbyInfo {
    /// AirDrop on and the device unlocked -- the state in which an offer gets a prompt.
    pub fn receptive(&self) -> bool {
        self.flags & FLAG_RECEPTIVE != 0
    }
}

/// One AirDrop sender beacon. Kept for logging and for a future contact match; it says
/// nothing about receptivity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AirDropBeacon {
    pub version: u8,
    /// Four two-byte truncated SHA-256 hashes: Apple ID, phone, email, email. All zero
    /// when the sender claims no identity, which is what our own beacon sends.
    pub hashes: [[u8; 2]; 4],
}

/// A message found in Apple manufacturer data.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Message {
    NearbyInfo(NearbyInfo),
    AirDrop(AirDropBeacon),
    /// A type this module does not interpret, with its type byte.
    Other(u8),
}

/// Every message in one manufacturer-data payload (the bytes AFTER the company id).
///
/// Stops at the first length that does not fit: a truncated advertisement yields what
/// was whole and never panics, because this input comes from a stranger's radio.
pub fn parse(data: &[u8]) -> Vec<Message> {
    let mut out = Vec::new();
    let mut i = 0;
    while i + 2 <= data.len() {
        let t = data[i];
        let len = data[i + 1] as usize;
        let body = match data.get(i + 2..i + 2 + len) {
            Some(b) => b,
            None => break,
        };
        i += 2 + len;
        out.push(match t {
            TYPE_NEARBY_INFO if body.len() >= 2 => {
                Message::NearbyInfo(NearbyInfo { flags: body[0], action: body[1] })
            }
            // 8 zero bytes, version, 4 × 2-byte hashes, trailer.
            TYPE_AIRDROP if body.len() >= 17 => {
                let mut hashes = [[0u8; 2]; 4];
                for (n, h) in hashes.iter_mut().enumerate() {
                    h.copy_from_slice(&body[9 + 2 * n..11 + 2 * n]);
                }
                Message::AirDrop(AirDropBeacon { version: body[8], hashes })
            }
            other => Message::Other(other),
        });
    }
    out
}

/// The Nearby Info message in a payload, if there is one.
pub fn nearby_info(data: &[u8]) -> Option<NearbyInfo> {
    parse(data).into_iter().find_map(|m| match m {
        Message::NearbyInfo(n) => Some(n),
        _ => None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // Captured 2026-09-25 from an iPhone Air (action 0x18) by a btmon capture beside it,
    // locked and then unlocked. The three auth-tag bytes are zeroed here: the decoder
    // does not read them, and they are derived from that phone's own keys, so they have
    // no place in a public repository. Type, length, flags and action are as captured.
    const AIR_LOCKED: [u8; 7] = [0x10, 0x05, 0x21, 0x18, 0x00, 0x00, 0x00];
    const AIR_RECEPTIVE: [u8; 7] = [0x10, 0x05, 0x61, 0x18, 0x00, 0x00, 0x00];
    // Our own beacon as seen by the same capture: version 1, no identity claimed.
    const OUR_BEACON: [u8; 20] = [
        0x05, 0x12, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ];

    #[test]
    fn locked_iphone_is_not_receptive() {
        let n = nearby_info(&AIR_LOCKED).unwrap();
        assert_eq!(n, NearbyInfo { flags: 0x21, action: 0x18 });
        assert!(!n.receptive());
    }

    #[test]
    fn unlocked_everyone_is_receptive() {
        let n = nearby_info(&AIR_RECEPTIVE).unwrap();
        assert_eq!(n.flags, 0x61);
        assert!(n.receptive());
    }

    #[test]
    fn mini_flag_values_measured_on_the_other_phone() {
        // The Mini (action 0x1e) reads 0x64/0x65 receptive and 0x21 locked; only the
        // 0x40 bit is relied on, so the low bits differing between phones is fine.
        for flags in [0x64u8, 0x65] {
            assert!(NearbyInfo { flags, action: 0x1e }.receptive(), "0x{flags:02x}");
        }
        assert!(!NearbyInfo { flags: 0x21, action: 0x1e }.receptive());
        // The ~20 s burst before Bluetooth-off in Settings still carries the bit; the
        // device is then found gone by silence, not by this flag.
        assert!(NearbyInfo { flags: 0x68, action: 0x1e }.receptive());
    }

    #[test]
    fn airdrop_beacon_decodes_version_and_hashes() {
        match parse(&OUR_BEACON).as_slice() {
            [Message::AirDrop(b)] => {
                assert_eq!(b.version, 1);
                assert_eq!(b.hashes, [[0, 0]; 4]);
            }
            other => panic!("{other:?}"),
        }
        assert!(nearby_info(&OUR_BEACON).is_none());
    }

    #[test]
    fn several_messages_in_one_payload() {
        // Handoff (0x0c) first, then Nearby Info -- the packing an iPhone with an
        // active Handoff app uses. Nearby Info must still be found.
        let mut d = vec![0x0c, 0x0e];
        d.extend_from_slice(&[0xaa; 14]);
        d.extend_from_slice(&AIR_RECEPTIVE);
        let msgs = parse(&d);
        assert_eq!(msgs.len(), 2);
        assert_eq!(msgs[0], Message::Other(0x0c));
        assert_eq!(nearby_info(&d).unwrap().flags, 0x61);
    }

    #[test]
    fn truncated_input_never_panics() {
        for n in 0..AIR_RECEPTIVE.len() {
            let _ = parse(&AIR_RECEPTIVE[..n]);
        }
        // A length that overruns the buffer yields nothing rather than a slice panic.
        assert!(parse(&[0x10, 0x20, 0x61]).is_empty());
        assert!(parse(&[]).is_empty());
        // Nearby Info with too short a body is not a NearbyInfo.
        assert_eq!(parse(&[0x10, 0x01, 0x61]), vec![Message::Other(0x10)]);
    }
}

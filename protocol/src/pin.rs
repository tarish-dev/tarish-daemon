//! The four-digit PIN a person compares across two screens.
//!
//! This is the only part of the handshake a human checks. UKEY2 gives both ends the same
//! `auth_string` only if nobody sat in the middle, so two matching PINs mean the channel
//! is end-to-end. A PIN that does not match the peer's is worse than showing none at all:
//! it teaches the user that mismatches are normal.
//!
//! ```text
//!   hash = 0, multiplier = 1
//!   for each byte b of auth_string:
//!       hash       = (hash + (b as i8) * multiplier) % 9973
//!       multiplier = (multiplier * 31) % 9973
//!   pin = abs(hash), left-padded to four digits
//! ```
//!
//! **The bytes are SIGNED.** `0xFF` contributes -1, not 255. An unsigned port produces a
//! plausible four-digit number that never matches a real peer -- the vector for a single
//! `0xFF` byte is "0001", and an unsigned reading gives "0255". That is the whole reason
//! that vector exists.
//!
//! **The remainder is truncated, not floored**, so `hash` may be negative until the final
//! `abs`. Rust's `%` on `i32` already does this; a language whose `%` floors would need
//! correcting here.
//!
//! Nine of the ten known-answer vectors below come from Bada's `PinVectors.kt`
//! (Apache 2.0), which in turn cross-checks Apple's `pinCodeFromAuthKey`. They are a
//! foreign implementation's answers, which is the point: our own round trip would agree
//! with any consistent mistake.

/// Chosen by the protocol, not by us. A prime just under 10000, which is what keeps the
/// result inside four digits without a second modulo.
const PIN_MODULUS: i32 = 9973;

/// The multiplier is raised to the power of the byte's position, one step at a time.
const MULTIPLIER_STEP: i32 = 31;

const PIN_DIGITS: usize = 4;

/// Derive the confirmation PIN from a UKEY2 `auth_string`.
///
/// Always four ASCII digits. An empty input gives "0000" rather than an error: there is
/// no such thing as a malformed auth string here, only a short one.
pub fn derive(auth_string: &[u8]) -> String {
    let mut hash: i32 = 0;
    let mut multiplier: i32 = 1;
    for &b in auth_string {
        // The cast is the contract. `b as i8` sign-extends; `b as i32` would not.
        let signed = b as i8 as i32;
        hash = (hash + signed.wrapping_mul(multiplier)) % PIN_MODULUS;
        multiplier = multiplier.wrapping_mul(MULTIPLIER_STEP) % PIN_MODULUS;
    }
    // After the modulo, hash is in (-9973, 9973), so abs cannot overflow.
    format!("{:0width$}", hash.abs(), width = PIN_DIGITS)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Known answers from a different implementation. Every other property below could
    /// hold while the numbers were still wrong for a real peer.
    #[test]
    fn it_matches_foreign_known_answers() {
        let cases: &[(&[u8], &str)] = &[
            (&[], "0000"),
            (&[0x00], "0000"),
            (&[0x01], "0001"),
            // The sign-extension guard: unsigned bytes would give "0255".
            (&[0xFF], "0001"),
            (&[0xFF, 0xFF], "0032"),
            (&[0x01, 0x02], "0063"),
        ];
        for (input, want) in cases {
            assert_eq!(&derive(input), want, "auth_string {input:02x?}");
        }
    }

    /// Long inputs, where the intermediate hash and multiplier both wrap the modulus
    /// several times. These are what pin the truncated-remainder behaviour.
    #[test]
    fn it_matches_foreign_answers_for_multi_wrap_inputs() {
        assert_eq!(derive(&[0x7Fu8; 32]), "8857", "32 bytes of 0x7F");
        assert_eq!(derive(&[0xFFu8; 32]), "6509", "32 bytes of 0xFF");

        let incrementing: Vec<u8> = (0..32u8).collect();
        assert_eq!(derive(&incrementing), "5095", "0x00..0x1F");
    }

    /// The result is shown to a person next to another device's screen, so its shape is
    /// as load-bearing as its value: four digits, always, including leading zeros.
    #[test]
    fn it_is_always_four_digits() {
        for len in 0..40usize {
            let input: Vec<u8> = (0..len).map(|i| (i * 7 + 3) as u8).collect();
            let pin = derive(&input);
            assert_eq!(pin.len(), PIN_DIGITS, "wrong length for {len} bytes: {pin}");
            assert!(
                pin.bytes().all(|c| c.is_ascii_digit()),
                "non-digit in {pin}"
            );
        }
    }

    /// A real auth_string is 32 bytes of key material. Different sessions must not keep
    /// producing the same number, or comparing it proves nothing.
    #[test]
    fn different_auth_strings_generally_differ() {
        let a = derive(&[0x11u8; 32]);
        let b = derive(&[0x12u8; 32]);
        assert_ne!(a, b);
    }

    #[test]
    fn it_is_deterministic() {
        let input: Vec<u8> = (0..32u8).map(|i| i.wrapping_mul(37)).collect();
        assert_eq!(derive(&input), derive(&input));
    }

    /// The old derivation -- the first two bytes as a big-endian u16, mod 10000 -- was
    /// wrong, and wrong in a way that looked right: four digits, stable, different per
    /// session. It only failed against a real peer, where nobody could see both numbers
    /// at once. Kept as a test so it cannot come back by accident.
    #[test]
    fn it_is_not_the_first_two_bytes() {
        let auth = [0x12u8, 0x34, 0x56, 0x78, 0x9A];
        let naive = u16::from_be_bytes([auth[0], auth[1]]) % 10_000;
        assert_ne!(derive(&auth), format!("{naive:04}"));
    }
}

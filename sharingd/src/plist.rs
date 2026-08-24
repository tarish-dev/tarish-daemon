//! Just enough Apple binary plist to answer `/Discover`.
//!
//! AirDrop bodies are `bplist00`, and no plist crate exists in the AOSP tree. Only the
//! writer is needed and only for flat dictionaries of strings and byte blobs, so this
//! is deliberately the smallest thing that produces a valid document rather than a
//! general plist library.
//!
//! Layout: the 8-byte magic, then objects, then a table of their offsets, then a
//! 32-byte trailer describing the table. Object 0 is the root.

/// A value in the flat dictionary. Anything nested would need object graph handling
/// that `/Discover` does not require.
pub enum Value {
    Str(String),
    Data(Vec<u8>),
}

/// Encode `pairs` as a binary plist dictionary.
///
/// Key order is preserved as given. Apple's own encoder sorts keys, but readers do not
/// depend on it and preserving caller order keeps the output predictable to eyeball
/// against a capture.
pub fn dict(pairs: &[(&str, Value)]) -> Vec<u8> {
    // Object 0 is the dict; then every key, then every value. Two passes: build the
    // object bodies, recording where each one starts, then append the offset table.
    let n = pairs.len();
    let total_objects = 1 + n * 2;

    // How many bytes each object reference takes. One byte covers 255 objects, which a
    // /Discover body will never approach, but get it right rather than assume.
    let ref_size = byte_width(total_objects as u64);

    let mut out = Vec::with_capacity(256);
    out.extend_from_slice(b"bplist00");

    let mut offsets = Vec::with_capacity(total_objects);

    // --- object 0: the dictionary itself ---
    offsets.push(out.len());
    write_marker(&mut out, 0xD0, n);
    for i in 0..n {
        write_uint(&mut out, (1 + i) as u64, ref_size);          // key refs
    }
    for i in 0..n {
        write_uint(&mut out, (1 + n + i) as u64, ref_size);      // value refs
    }

    // --- keys, then values, in the order the refs above claim ---
    for (k, _) in pairs {
        offsets.push(out.len());
        write_string(&mut out, k);
    }
    for (_, v) in pairs {
        offsets.push(out.len());
        match v {
            Value::Str(s) => write_string(&mut out, s),
            Value::Data(b) => {
                write_marker(&mut out, 0x40, b.len());
                out.extend_from_slice(b);
            }
        }
    }

    // --- offset table ---
    let table_start = out.len();
    let offset_size = byte_width(table_start as u64);
    for off in &offsets {
        write_uint(&mut out, *off as u64, offset_size);
    }

    // --- 32-byte trailer ---
    out.extend_from_slice(&[0u8; 5]);       // unused
    out.push(0);                            // sort version
    out.push(offset_size);
    out.push(ref_size);
    out.extend_from_slice(&(total_objects as u64).to_be_bytes());
    out.extend_from_slice(&0u64.to_be_bytes());          // root object index
    out.extend_from_slice(&(table_start as u64).to_be_bytes());
    out
}

/// A marker byte carries its length in the low nibble when it fits, and otherwise
/// escapes to a following integer. Getting this wrong produces a document that parses
/// as truncated rather than as invalid, which is harder to spot.
fn write_marker(out: &mut Vec<u8>, kind: u8, len: usize) {
    if len < 0x0F {
        out.push(kind | len as u8);
    } else {
        out.push(kind | 0x0F);
        write_int_object(out, len as u64);
    }
}

/// An integer used as a length: marker 0x1n where 2^n is the byte count.
fn write_int_object(out: &mut Vec<u8>, v: u64) {
    let (marker, width) = if v <= u8::MAX as u64 {
        (0x10, 1)
    } else if v <= u16::MAX as u64 {
        (0x11, 2)
    } else {
        (0x12, 4)
    };
    out.push(marker);
    write_uint(out, v, width);
}

/// ASCII where possible, UTF-16BE otherwise.
///
/// The device name reaches this, and a name with any non-ASCII character encoded as
/// ASCII would be silently mangled on the peer's screen.
fn write_string(out: &mut Vec<u8>, s: &str) {
    if s.is_ascii() {
        write_marker(out, 0x50, s.len());
        out.extend_from_slice(s.as_bytes());
    } else {
        let units: Vec<u16> = s.encode_utf16().collect();
        write_marker(out, 0x60, units.len());
        for u in units {
            out.extend_from_slice(&u.to_be_bytes());
        }
    }
}

fn write_uint(out: &mut Vec<u8>, v: u64, width: u8) {
    let b = v.to_be_bytes();
    out.extend_from_slice(&b[8 - width as usize..]);
}

/// Smallest power-of-two byte width that holds `max`. Plist sizes are 1, 2, 4 or 8.
fn byte_width(max: u64) -> u8 {
    if max <= u8::MAX as u64 {
        1
    } else if max <= u16::MAX as u64 {
        2
    } else if max <= u32::MAX as u64 {
        4
    } else {
        8
    }
}

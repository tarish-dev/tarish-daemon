#[path = "../../tarish-daemon/sharingd/src/plist.rs"]
#[allow(dead_code)]
mod plist;

/// Build a bplist00 where object k is an array of `fan` references, all to object k+1,
/// and the last object is a short string. Total size is ~fan*levels*2 bytes, but a
/// resolver that follows every reference materialises fan^levels leaves.
fn bomb(fan: usize, levels: usize) -> Vec<u8> {
    let mut out = b"bplist00".to_vec();
    let mut offsets = Vec::new();
    for k in 0..levels {
        offsets.push(out.len());
        // array marker with escaped length (0xAF, then int object 0x11 = 2-byte int)
        out.push(0xAF);
        out.push(0x11);
        out.extend_from_slice(&(fan as u16).to_be_bytes());
        for _ in 0..fan {
            out.extend_from_slice(&((k + 1) as u16).to_be_bytes()); // ref_size = 2
        }
    }
    offsets.push(out.len());
    out.push(0x51); out.push(b'x'); // ascii string "x"
    let table_start = out.len();
    for o in &offsets {
        out.extend_from_slice(&(*o as u32).to_be_bytes()); // offset_size = 4
    }
    let mut trailer = [0u8; 32];
    trailer[6] = 4; // offset size
    trailer[7] = 2; // ref size
    trailer[8..16].copy_from_slice(&(offsets.len() as u64).to_be_bytes());
    trailer[16..24].copy_from_slice(&0u64.to_be_bytes());
    trailer[24..32].copy_from_slice(&(table_start as u64).to_be_bytes());
    out.extend_from_slice(&trailer);
    out
}

fn main() {
    let args: Vec<usize> = std::env::args().skip(1).map(|a| a.parse().unwrap()).collect();
    let (fan, levels) = (args[0], args[1]);
    let b = bomb(fan, levels);
    let t = std::time::Instant::now();
    let v = plist::parse(&b);
    println!("fan={fan} levels={levels} body={} bytes -> parsed={} in {:?} (leaves={})",
        b.len(), v.is_some(), t.elapsed(), (fan as u128).pow(levels as u32));
}

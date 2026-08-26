//! Quick Share endpoint identity: the service name, and the advertisement payload
//! that carries a device's name and type.
//!
//! Written from the protocol rather than from Bada's source. Bada is unlicensed --
//! see barq-app/docs/CREDITS.md -- so it is read here as a specification, the same
//! way OpenDrop was read for AirDrop. The constants below are protocol facts: byte
//! offsets, bit positions and a hash prefix, none of which are anyone's expression.

/// The string every Quick Share identifier is derived from.
pub const SERVICE_ID: &str = "NearbySharing";

/// mDNS service type, which is NOT a magic constant despite looking like one:
///
///     sha256("NearbySharing") = fc9f5ed42c8a5e9e94684076ef3bf938...
///     first 6 bytes, uppercase hex -> FC9F5ED42C8A
///
/// Derived at runtime by `service_type()` so the derivation stays visible and a
/// future service id change is one edit rather than a hunt for hex literals.
pub const SERVICE_TYPE: &str = "_FC9F5ED42C8A._tcp.local";

// Wire layout of the endpoint advertisement.
//
//   byte 0      version:3 | hidden:1 | device_type:3 | reserved:1
//   bytes 1..17 metadata, always 16 bytes (2 salt + 14 encrypted key)
//   if !hidden  1 byte name length, then that many bytes of UTF-8
//   then        TLV records: 1 byte type, 1 byte length, value
const HEADER_LEN: usize = 1;
const METADATA_LEN: usize = 16;
const VERSION_SHIFT: u8 = 5;
const VISIBILITY_SHIFT: u8 = 4;
const DEVICE_TYPE_SHIFT: u8 = 1;
const THREE_BIT: u8 = 0b111;

/// What the peer says it is. Only used to pick an icon, so an unknown value is not
/// an error -- a device type we have never heard of is still a device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceType {
    Unknown,
    Phone,
    Tablet,
    Laptop,
    Car,
    Foldable,
    Xr,
}

impl DeviceType {
    fn from_raw(raw: u8) -> Self {
        match raw {
            1 => Self::Phone,
            2 => Self::Tablet,
            3 => Self::Laptop,
            4 => Self::Car,
            5 => Self::Foldable,
            6 => Self::Xr,
            _ => Self::Unknown,
        }
    }

    fn raw(self) -> u8 {
        match self {
            Self::Unknown => 0,
            Self::Phone => 1,
            Self::Tablet => 2,
            Self::Laptop => 3,
            Self::Car => 4,
            Self::Foldable => 5,
            Self::Xr => 6,
        }
    }
}

#[derive(Debug, Clone)]
pub struct EndpointInfo {
    pub version: u8,
    /// Hidden means "advertise, but do not say who I am". The name is then absent
    /// from the wire entirely rather than blank, which is why `device_name` is an
    /// Option and not an empty string.
    pub hidden: bool,
    pub device_type: DeviceType,
    pub metadata: [u8; METADATA_LEN],
    pub device_name: Option<String>,
}

impl EndpointInfo {
    pub fn encode(&self) -> Vec<u8> {
        let name = if self.hidden {
            Vec::new()
        } else {
            self.device_name.clone().unwrap_or_default().into_bytes()
        };

        let mut out = Vec::with_capacity(HEADER_LEN + METADATA_LEN + 1 + name.len());
        out.push(
            ((self.version & THREE_BIT) << VERSION_SHIFT)
                | ((self.hidden as u8) << VISIBILITY_SHIFT)
                | ((self.device_type.raw() & THREE_BIT) << DEVICE_TYPE_SHIFT),
        );
        out.extend_from_slice(&self.metadata);
        if !self.hidden {
            // One length byte, so a name longer than 255 bytes cannot be expressed.
            // Truncate on a CHARACTER boundary -- cutting mid-codepoint would put
            // invalid UTF-8 on the wire and a peer would show mojibake or drop us.
            let mut n = name;
            if n.len() > 0xFF {
                let mut cut = 0xFF;
                while cut > 0 && (n[cut] & 0xC0) == 0x80 {
                    cut -= 1;
                }
                n.truncate(cut);
            }
            out.push(n.len() as u8);
            out.extend_from_slice(&n);
        }
        out
    }

    /// Returns None only when the buffer cannot hold a header and metadata. Anything
    /// past that is best-effort: a truncated name or a malformed TLV yields an
    /// endpoint without a name rather than nothing, because a peer we can see but
    /// cannot name is still worth showing.
    pub fn parse(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < HEADER_LEN + METADATA_LEN {
            return None;
        }
        let header = bytes[0];
        let hidden = (header >> VISIBILITY_SHIFT) & 1 == 1;

        let mut metadata = [0u8; METADATA_LEN];
        metadata.copy_from_slice(&bytes[HEADER_LEN..HEADER_LEN + METADATA_LEN]);

        let mut device_name = None;
        if !hidden {
            let off = HEADER_LEN + METADATA_LEN;
            if let Some(&len) = bytes.get(off) {
                let start = off + 1;
                let end = start + len as usize;
                if end <= bytes.len() {
                    device_name = Some(String::from_utf8_lossy(&bytes[start..end]).into_owned());
                }
            }
        }

        Some(Self {
            version: (header >> VERSION_SHIFT) & THREE_BIT,
            hidden,
            device_type: DeviceType::from_raw((header >> DEVICE_TYPE_SHIFT) & THREE_BIT),
            metadata,
            device_name,
        })
    }
}

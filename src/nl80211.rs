//! Ask the kernel which channel Wi-Fi is associated on, over nl80211.
//!
//! WHY THIS EXISTS
//!
//! `StartMoseyConfig` carries a `sta_channel_freq` field, and it is not decoration.
//! AWDL coexists with an infrastructure connection by TIME-SHARING one radio: the
//! announced channel sequence has 16 slots, and the slots hold the primary AWDL
//! channel, the secondary AWDL channel, AND THE CHANNEL OF THE AP. Stute et al.,
//! "One Billion Apples' Secret Sauce" (MobiCom 2018), Table 2 -- p and s are 44 and
//! 6, i is the AP. Without i the radio never goes back to the AP, and a single-radio
//! device loses its association rather than merely slowing down.
//!
//! So the STA frequency is an input the protocol is built around, and we were passing
//! zero. It was read from a property that only the app publishes, and the app is shut
//! for almost all of the device's life by design -- that is the whole point of the
//! radio gate. Measured on mustang: `sta_channel_freq=0` on every start, while the
//! phone was plainly associated at 5520 MHz.
//!
//! The AP's channel is NOT a valid AWDL channel and must not be put in the channel
//! list. Passing our AP's channel 104 there is rejected outright:
//!
//!     mosey_daemon_ffi: Error starting mosey: Invalid channel num: 104
//!
//! AWDL runs on the social channels (6, 44, 149) only. The AP channel travels in
//! `sta_channel_freq`, which is exactly the split the paper describes.

use std::io;
use std::mem;

const NETLINK_GENERIC: i32 = 16;
const NLM_F_REQUEST: u16 = 0x01;
const NLMSG_ERROR: u16 = 0x2;

// The controller family, which is the only id known ahead of time. Everything else
// has to be looked up through it, including nl80211's own id, which is assigned at
// runtime and is NOT stable across boots.
const GENL_ID_CTRL: u16 = 16;
const CTRL_CMD_GETFAMILY: u8 = 3;
const CTRL_ATTR_FAMILY_ID: u16 = 1;
const CTRL_ATTR_FAMILY_NAME: u16 = 2;

const NL80211_CMD_GET_INTERFACE: u8 = 5;
const NL80211_ATTR_IFINDEX: u16 = 3;
const NL80211_ATTR_WIPHY_FREQ: u16 = 38;

const NLMSG_HDR_LEN: usize = 16;
const GENL_HDR_LEN: usize = 4;

fn align4(n: usize) -> usize {
    (n + 3) & !3
}

fn put_attr(buf: &mut Vec<u8>, ty: u16, payload: &[u8]) {
    let len = 4 + payload.len();
    buf.extend_from_slice(&(len as u16).to_ne_bytes());
    buf.extend_from_slice(&ty.to_ne_bytes());
    buf.extend_from_slice(payload);
    buf.resize(align4(buf.len()), 0);
}

struct Fd(i32);
impl Drop for Fd {
    fn drop(&mut self) {
        // SAFETY: fd is owned and closed exactly once.
        unsafe { libc::close(self.0) };
    }
}

/// Walk the nlattrs in `buf` and return the payload of the first one of type `want`.
///
/// Attributes are length-prefixed and 4-byte aligned; a zero or short length would
/// make this spin, so it is treated as the end of the buffer rather than trusted.
fn find_attr(buf: &[u8], want: u16) -> Option<&[u8]> {
    let mut off = 0usize;
    while off + 4 <= buf.len() {
        let len = u16::from_ne_bytes([buf[off], buf[off + 1]]) as usize;
        let ty = u16::from_ne_bytes([buf[off + 2], buf[off + 3]]);
        if len < 4 || off + len > buf.len() {
            return None;
        }
        if ty == want {
            return Some(&buf[off + 4..off + len]);
        }
        off += align4(len);
    }
    None
}

/// One generic-netlink request, one response buffer back.
fn genl_request(family: u16, cmd: u8, body: &[u8]) -> io::Result<Vec<u8>> {
    // SAFETY: plain socket(2) with constant arguments.
    let fd = unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_DGRAM, NETLINK_GENERIC) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let fd = Fd(fd);

    let total = NLMSG_HDR_LEN + GENL_HDR_LEN + body.len();
    let mut msg = Vec::with_capacity(total);
    msg.extend_from_slice(&(total as u32).to_ne_bytes()); // nlmsg_len
    msg.extend_from_slice(&family.to_ne_bytes()); // nlmsg_type
    msg.extend_from_slice(&NLM_F_REQUEST.to_ne_bytes()); // nlmsg_flags
    msg.extend_from_slice(&1u32.to_ne_bytes()); // nlmsg_seq
    msg.extend_from_slice(&0u32.to_ne_bytes()); // nlmsg_pid
    msg.push(cmd); // genl cmd
    msg.push(1); // genl version
    msg.extend_from_slice(&0u16.to_ne_bytes()); // reserved
    msg.extend_from_slice(body);

    // SAFETY: sockaddr_nl is plain old data and all-zeros is a valid initial value.
    let mut kernel: libc::sockaddr_nl = unsafe { mem::zeroed() };
    kernel.nl_family = libc::AF_NETLINK as u16;

    // SAFETY: msg is a live buffer of the stated length; kernel is a valid sockaddr_nl.
    let sent = unsafe {
        libc::sendto(
            fd.0,
            msg.as_ptr() as *const libc::c_void,
            msg.len(),
            0,
            &kernel as *const libc::sockaddr_nl as *const libc::sockaddr,
            mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
        )
    };
    if sent < 0 {
        return Err(io::Error::last_os_error());
    }

    // Family info carries every multicast group and op, so this is not a small reply.
    let mut resp = vec![0u8; 8192];
    // SAFETY: resp is a live buffer of the stated length.
    let n = unsafe { libc::recv(fd.0, resp.as_mut_ptr() as *mut libc::c_void, resp.len(), 0) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    let n = n as usize;
    if n < NLMSG_HDR_LEN {
        return Err(io::Error::other("short netlink response"));
    }
    resp.truncate(n);

    let ty = u16::from_ne_bytes([resp[4], resp[5]]);
    if ty == NLMSG_ERROR {
        let e = i32::from_ne_bytes([
            resp[NLMSG_HDR_LEN],
            resp[NLMSG_HDR_LEN + 1],
            resp[NLMSG_HDR_LEN + 2],
            resp[NLMSG_HDR_LEN + 3],
        ]);
        return if e == 0 {
            Err(io::Error::other("netlink ack with no payload"))
        } else {
            Err(io::Error::from_raw_os_error(-e))
        };
    }
    Ok(resp)
}

/// nl80211's runtime-assigned family id.
fn nl80211_family() -> io::Result<u16> {
    let mut body = Vec::new();
    put_attr(&mut body, CTRL_ATTR_FAMILY_NAME, b"nl80211\0");
    let resp = genl_request(GENL_ID_CTRL, CTRL_CMD_GETFAMILY, &body)?;
    let attrs = &resp[NLMSG_HDR_LEN + GENL_HDR_LEN..];
    let id = find_attr(attrs, CTRL_ATTR_FAMILY_ID)
        .filter(|v| v.len() >= 2)
        .ok_or_else(|| io::Error::other("nl80211 family not present"))?;
    Ok(u16::from_ne_bytes([id[0], id[1]]))
}

/// The frequency `iface` is currently operating on, in MHz.
///
/// An interface that is up but not associated has no channel, so the attribute is
/// simply absent and this reports 0 -- which is the honest answer and the one the
/// caller already handles.
pub fn frequency_of(iface: &str) -> io::Result<u32> {
    let cname =
        std::ffi::CString::new(iface).map_err(|_| io::Error::other("bad interface name"))?;
    // SAFETY: cname is a valid NUL-terminated string.
    let idx = unsafe { libc::if_nametoindex(cname.as_ptr()) };
    if idx == 0 {
        return Err(io::Error::last_os_error());
    }

    let family = nl80211_family()?;
    let mut body = Vec::new();
    put_attr(&mut body, NL80211_ATTR_IFINDEX, &idx.to_ne_bytes());
    let resp = genl_request(family, NL80211_CMD_GET_INTERFACE, &body)?;

    let attrs = &resp[NLMSG_HDR_LEN + GENL_HDR_LEN..];
    match find_attr(attrs, NL80211_ATTR_WIPHY_FREQ) {
        Some(v) if v.len() >= 4 => Ok(u32::from_ne_bytes([v[0], v[1], v[2], v[3]])),
        _ => Ok(0),
    }
}

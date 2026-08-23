//! Adding the AWDL link-local route.
//!
//! An address on the interface is not enough. Android routes by **fwmark** and
//! gives a new interface its own routing table, which starts EMPTY — so
//! `connect()` returns `ENETUNREACH` despite a valid address and a reachable
//! neighbour sitting in the table. Nothing in the log says "you are missing a
//! route"; it just looks like the link does not work.
//!
//! Done with raw netlink rather than by running `ip`. Exec'ing it would need
//! `allow barqd system_file:file execute_no_trans`, which lets this daemon run
//! ANY system binary — far too broad a grant to buy one route. This is also why
//! barqd's SELinux domain grants no exec at all.
//!
//! Raw libc rather than the rtnetlink crate on purpose: this process holds
//! CAP_NET_ADMIN, so its dependency surface is worth keeping small, and
//! rtnetlink pulls in an async runtime for a single message.

use std::ffi::CString;
use std::io;
use std::mem;

const NETLINK_ROUTE: i32 = 0;
const RTM_NEWROUTE: u16 = 24;

const NLM_F_REQUEST: u16 = 0x01;
const NLM_F_ACK: u16 = 0x04;
const NLM_F_EXCL: u16 = 0x200;
const NLM_F_CREATE: u16 = 0x400;
const NLMSG_ERROR: u16 = 0x2;

const RTPROT_STATIC: u8 = 4;
const RT_SCOPE_LINK: u8 = 253;
const RTN_UNICAST: u8 = 1;
const RT_TABLE_UNSPEC: u8 = 0;

const RTA_DST: u16 = 1;
const RTA_OIF: u16 = 4;
const RTA_TABLE: u16 = 15;

#[repr(C)]
#[derive(Default)]
struct NlMsgHdr {
    len: u32,
    ty: u16,
    flags: u16,
    seq: u32,
    pid: u32,
}

#[repr(C)]
#[derive(Default)]
struct RtMsg {
    family: u8,
    dst_len: u8,
    src_len: u8,
    tos: u8,
    table: u8,
    protocol: u8,
    scope: u8,
    ty: u8,
    flags: u32,
}

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

/// Add `fe80::/64 dev <iface> table <ifindex>`.
///
/// Android names the per-network table after the interface, and its id is the
/// interface index. Returns Ok(()) if the route was added or already existed.
pub fn add_link_local(iface: &str) -> io::Result<()> {
    let cname = CString::new(iface).map_err(|_| io::Error::other("bad interface name"))?;
    // SAFETY: cname is a valid NUL-terminated string.
    let idx = unsafe { libc::if_nametoindex(cname.as_ptr()) };
    if idx == 0 {
        return Err(io::Error::last_os_error());
    }

    // SAFETY: plain socket(2) with constant arguments.
    let fd = unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_DGRAM, NETLINK_ROUTE) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    struct Fd(i32);
    impl Drop for Fd {
        fn drop(&mut self) {
            // SAFETY: fd is owned and closed exactly once.
            unsafe { libc::close(self.0) };
        }
    }
    let fd = Fd(fd);

    let rt = RtMsg {
        family: libc::AF_INET6 as u8,
        dst_len: 64,
        table: RT_TABLE_UNSPEC,
        protocol: RTPROT_STATIC,
        scope: RT_SCOPE_LINK,
        ty: RTN_UNICAST,
        ..Default::default()
    };

    let mut body = Vec::with_capacity(128);
    // SAFETY: RtMsg is repr(C) and plain old data.
    body.extend_from_slice(unsafe {
        std::slice::from_raw_parts(&rt as *const RtMsg as *const u8, mem::size_of::<RtMsg>())
    });
    body.resize(align4(body.len()), 0);

    let mut dst = [0u8; 16];
    dst[0] = 0xfe;
    dst[1] = 0x80;
    put_attr(&mut body, RTA_DST, &dst);
    put_attr(&mut body, RTA_OIF, &idx.to_ne_bytes());
    put_attr(&mut body, RTA_TABLE, &idx.to_ne_bytes());

    let hdr = NlMsgHdr {
        len: (mem::size_of::<NlMsgHdr>() + body.len()) as u32,
        ty: RTM_NEWROUTE,
        flags: NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL | NLM_F_ACK,
        seq: 1,
        pid: 0,
    };

    let mut msg = Vec::with_capacity(hdr.len as usize);
    // SAFETY: NlMsgHdr is repr(C) and plain old data.
    msg.extend_from_slice(unsafe {
        std::slice::from_raw_parts(&hdr as *const NlMsgHdr as *const u8, mem::size_of::<NlMsgHdr>())
    });
    msg.extend_from_slice(&body);

    let mut kernel: libc::sockaddr_nl = unsafe { mem::zeroed() };
    kernel.nl_family = libc::AF_NETLINK as u16;

    // SAFETY: msg is a live buffer of the stated length; kernel is a valid
    // sockaddr_nl of the stated size.
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

    let mut resp = [0u8; 512];
    // SAFETY: resp is a live buffer of the stated length.
    let n = unsafe {
        libc::recv(fd.0, resp.as_mut_ptr() as *mut libc::c_void, resp.len(), 0)
    };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    if (n as usize) < mem::size_of::<NlMsgHdr>() + 4 {
        return Ok(()); // no error payload came back; treat as success
    }

    let ty = u16::from_ne_bytes([resp[4], resp[5]]);
    if ty == NLMSG_ERROR {
        let off = mem::size_of::<NlMsgHdr>();
        let err = i32::from_ne_bytes([resp[off], resp[off + 1], resp[off + 2], resp[off + 3]]);
        match err {
            0 => Ok(()),
            e if -e == libc::EEXIST => Ok(()),   // already there is fine
            e => Err(io::Error::from_raw_os_error(-e)),
        }
    } else {
        Ok(())
    }
}

/// Table id for an interface, for logging.
pub fn table_id(iface: &str) -> u32 {
    CString::new(iface)
        .ok()
        // SAFETY: valid NUL-terminated string.
        .map(|c| unsafe { libc::if_nametoindex(c.as_ptr()) })
        .unwrap_or(0)
}

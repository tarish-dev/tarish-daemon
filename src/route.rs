//! Adding the AWDL link-local route.
//!
//! An address on the interface is not enough. Android routes by **fwmark** and
//! gives a new interface its own routing table, which starts EMPTY — so
//! `connect()` returns `ENETUNREACH` despite a valid address and a reachable
//! neighbour sitting in the table. Nothing in the log says "you are missing a
//! route"; it just looks like the link does not work.
//!
//! Done with raw netlink rather than by running `ip`. Exec'ing it would need
//! `allow tarishd system_file:file execute_no_trans`, which lets this daemon run
//! ANY system binary — far too broad a grant to buy one route. This is also why
//! tarishd's SELinux domain grants no exec at all.
//!
//! Raw libc rather than the rtnetlink crate on purpose: this process holds
//! CAP_NET_ADMIN, so its dependency surface is worth keeping small, and
//! rtnetlink pulls in an async runtime for a single message.

use std::ffi::CString;
use std::io;
use std::mem;

const NETLINK_ROUTE: i32 = 0;
const RTM_NEWROUTE: u16 = 24;
const RTM_NEWRULE: u16 = 32;
const RTM_DELRULE: u16 = 33;

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

// fib_rule attributes. FRA_TABLE shares its number with RTA_TABLE because both
// messages use the same attribute space.
const FRA_PRIORITY: u16 = 6;
const FRA_TABLE: u16 = 15;
const FRA_OIFNAME: u16 = 17;
const FRA_UID_RANGE: u16 = 20;
const FR_ACT_TO_TBL: u8 = 1;

/// Rule priority. Must sit below the catch-all `32000: from all unreachable`, which is
/// what every lookup fell through to while no rule pointed at our table -- AND below
/// Android's VPN lockdown block, which is the part that took a measurement to find.
///
/// This was 15000, which looks harmless and is not. Android's own priorities are:
///
///   10000  VPN_OVERRIDE_SYSTEM
///   11000  VPN_OVERRIDE_OIF
///   12000  VPN_OUTPUT_TO_LOCAL     <- Android's own "local traffic escapes the VPN"
///   13000  SECURE_VPN
///   14000  PROHIBIT_NON_VPN        <- the kill-switch
///   16000  EXPLICIT_NETWORK
///   17000  OUTPUT_INTERFACE
///
/// 15000 falls in the gap between the kill-switch and EXPLICIT_NETWORK, so with "block
/// connections without VPN" on and the VPN DOWN, the prohibit matched first and our rule
/// was never reached. Measured on blazer:
///
///   14000: from all fwmark 0x0/0x20000 iif lo uidrange 1-10206 prohibit   <- uid 7500 is here
///   15000: from all oif tlink0 uidrange 7500-7500 lookup 52               <- never consulted
///
///   $ ip -6 route get fe80::1 oif tlink0 uid 7500  -> Permission denied
///   $ ip -6 route get fe80::1 oif tlink0 uid 0     -> Network is unreachable
///
/// The daemon could still BIND and answer mDNS -- inbound is unaffected -- so AirDrop looked
/// half alive: "AirDrop server up", "answered 8 record(s)", and then every outbound attempt
/// failing with `/Discover failed: Permission denied (os error 13)`.
///
/// 13500: after SECURE_VPN, so a VPN that is actually up still claims traffic first, and
/// before PROHIBIT_NON_VPN so link-local AWDL survives the kill-switch.
///
/// WHY THIS IS NOT A LOCKDOWN BYPASS. The exemption is scoped three ways at once, and the
/// third is the one that matters: the rule matches only uid 7500, only when the output
/// interface is tlink0, and it resolves in table 52 -- which contains exactly one route:
///
///   fe80::/64 dev tlink0
///
/// So it cannot reach the internet, the LAN, or the VPN's subnet. It is a link-local escape
/// by construction, not by trust, which is the property to preserve if this is ever changed.
/// A uid-keyed exemption would be strictly worse: under lockdown it could reach anything.
const RULE_PRIORITY: u32 = 13500;

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
    let idx = index_of(iface)?;

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

    send_nl(RTM_NEWROUTE, &body)
}

/// The one uid allowed to route over the AWDL link.
///
/// Resolved BY NAME rather than hardcoded, because the number already lives in two
/// places — `config/tarish_aid.txt` here and the integrator's Connectivity patch, which
/// has to be kept in step with it. A third copy would be a third thing to forget, and
/// getting it wrong here fails silently in the safe-looking direction: a rule scoped to
/// the wrong uid still installs, and only the traffic stops.
///
/// Failing to resolve is fatal to the rule rather than falling back to "any uid". The
/// whole point is that nothing else reaches this interface, so a fallback that quietly
/// opened it up would be worse than no rule at all.
fn sharing_uid() -> io::Result<u32> {
    let name = CString::new("system_ext_tarish").map_err(|_| io::Error::other("bad uid name"))?;
    // SAFETY: name is a valid NUL-terminated string, and getpwnam returns a pointer
    // into static storage that we only read synchronously before returning a copy.
    let pw = unsafe { libc::getpwnam(name.as_ptr()) };
    if pw.is_null() {
        return Err(io::Error::other("system_ext_tarish is not a known user"));
    }
    // SAFETY: checked non-null above; passwd is plain old data.
    Ok(unsafe { (*pw).pw_uid })
}

/// `struct fib_rule_uid_range` from linux/fib_rules.h — two u32, inclusive.
#[repr(C)]
struct FibRuleUidRange {
    start: u32,
    end: u32,
}

/// Point traffic leaving `iface` at that interface's table.
///
/// A route in a table nothing consults is invisible. Android selects tables with
/// fib rules keyed on fwmark, and an interface it does not manage gets no rule at
/// all -- so `fe80::/64 dev mosey0 table 52` existed, was never looked up, and
/// every send fell through to `32000: from all unreachable`.
///
/// The symptom is badly misleading. Outbound gives "Network is unreachable",
/// which reads as a missing route rather than a missing rule; inbound is worse,
/// because SYNs arrive, our replies have nowhere to go, and it looks exactly like
/// nothing is listening on the port.
///
/// The rule is scoped to a single uid, so this is also the only thing standing
/// between any other process on the device and the AWDL link. See `sharing_uid`.
pub fn add_rule(iface: &str) -> io::Result<()> {
    let idx = index_of(iface)?;

    // Clear our own old rules first.
    //
    // The table number IS the interface index, and the interface is recreated with a
    // NEW index every time this daemon restarts. Adding without deleting leaves a rule
    // pointing at a table whose interface is gone -- and because both rules sit at the
    // same priority, the stale one matches FIRST and sends everything into an empty
    // table. The symptom is total: the link looks up, the address is there, and not a
    // single packet reaches a peer.
    //
    // Deleting by priority rather than by table clears whatever we left behind
    // previously, without needing to know what index it had.
    for _ in 0..8 {
        if del_rule().is_err() {
            break;   // nothing left at our priority
        }
    }

    // fib_rule_hdr has the same layout as rtmsg: the fields we call protocol,
    // scope and ty are res1, res2 and action there. Reusing the struct keeps one
    // definition rather than two identical ones.
    let rt = RtMsg {
        family: libc::AF_INET6 as u8,
        table: RT_TABLE_UNSPEC,     // carried in FRA_TABLE instead, which is u32
        ty: FR_ACT_TO_TBL,          // action
        ..Default::default()
    };

    let mut body = Vec::with_capacity(128);
    // SAFETY: RtMsg is repr(C) and plain old data.
    body.extend_from_slice(unsafe {
        std::slice::from_raw_parts(&rt as *const RtMsg as *const u8, mem::size_of::<RtMsg>())
    });
    body.resize(align4(body.len()), 0);

    // Match on the outgoing interface by NAME. Matching by index would need the
    // rule rewritten if mosey0 is torn down and recreated with a new index.
    let mut name = iface.as_bytes().to_vec();
    name.push(0);
    put_attr(&mut body, FRA_OIFNAME, &name);
    put_attr(&mut body, FRA_TABLE, &idx.to_ne_bytes());
    put_attr(&mut body, FRA_PRIORITY, &RULE_PRIORITY.to_ne_bytes());

    // SCOPE THE RULE TO ONE UID.
    //
    // Without this, any process that knows the peer's link-local address and the
    // interface scope id can route over the AWDL link. Nothing in Android stops it:
    // there is no netifcon labelling for interfaces (the platform policy contains no
    // netifcon statements at all), mosey0 is not a managed network so the local-network
    // gate never sees it, and SO_BINDTODEVICE is not required when a scope id will do.
    //
    // With the rule scoped, a different uid matches no rule for mosey0, falls through
    // to the unreachable default, and gets ENETUNREACH. No route, no traffic.
    //
    // This restricts ROUTING, not raw sockets: CAP_NET_RAW can still bind the interface
    // and inject. That is accepted -- anything holding it is already root-equivalent.
    let uid = sharing_uid()?;
    let range = FibRuleUidRange { start: uid, end: uid };
    // SAFETY: FibRuleUidRange is repr(C) and plain old data.
    let range_bytes = unsafe {
        std::slice::from_raw_parts(
            &range as *const FibRuleUidRange as *const u8,
            mem::size_of::<FibRuleUidRange>(),
        )
    };
    put_attr(&mut body, FRA_UID_RANGE, range_bytes);

    send_nl(RTM_NEWRULE, &body)
}

/// Take our fib rules back out, however many have accumulated.
///
/// The counterpart to `add_rule`'s opening sweep. Releasing the link without this
/// leaves a rule pointing at the table of an interface that no longer exists, and
/// because rules match by priority the stale one wins over the next one added.
pub fn remove_rule() -> io::Result<()> {
    let mut removed = 0;
    for _ in 0..8 {
        if del_rule().is_err() {
            break;   // nothing left at our priority
        }
        removed += 1;
    }
    if removed == 0 {
        return Err(io::Error::new(io::ErrorKind::NotFound, "no rule at our priority"));
    }
    Ok(())
}

/// Delete one rule at our priority. Errors once none remain, which is the stop signal.
fn del_rule() -> io::Result<()> {
    let rt = RtMsg {
        family: libc::AF_INET6 as u8,
        table: RT_TABLE_UNSPEC,
        ty: FR_ACT_TO_TBL,
        ..Default::default()
    };
    let mut body = Vec::with_capacity(64);
    // SAFETY: RtMsg is repr(C) and plain old data.
    body.extend_from_slice(unsafe {
        std::slice::from_raw_parts(&rt as *const RtMsg as *const u8, mem::size_of::<RtMsg>())
    });
    body.resize(align4(body.len()), 0);
    put_attr(&mut body, FRA_PRIORITY, &RULE_PRIORITY.to_ne_bytes());
    send_nl_flags(RTM_DELRULE, &body, NLM_F_REQUEST | NLM_F_ACK)
}

fn index_of(iface: &str) -> io::Result<u32> {
    let cname = CString::new(iface).map_err(|_| io::Error::other("bad interface name"))?;
    // SAFETY: cname is a valid NUL-terminated string.
    let idx = unsafe { libc::if_nametoindex(cname.as_ptr()) };
    if idx == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(idx)
}

/// Send one netlink request and interpret the ack.
fn send_nl(msg_ty: u16, body: &[u8]) -> io::Result<()> {
    send_nl_flags(msg_ty, body, NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL | NLM_F_ACK)
}

/// Same transport, explicit flags: a delete must not carry CREATE|EXCL.
fn send_nl_flags(msg_ty: u16, body: &[u8], flags: u16) -> io::Result<()> {
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

    let hdr = NlMsgHdr {
        len: (mem::size_of::<NlMsgHdr>() + body.len()) as u32,
        ty: msg_ty,
        flags,
        seq: 1,
        pid: 0,
    };

    let mut msg = Vec::with_capacity(hdr.len as usize);
    // SAFETY: NlMsgHdr is repr(C) and plain old data.
    msg.extend_from_slice(unsafe {
        std::slice::from_raw_parts(&hdr as *const NlMsgHdr as *const u8, mem::size_of::<NlMsgHdr>())
    });
    msg.extend_from_slice(body);

    // SAFETY: sockaddr_nl is plain old data and all-zeros is a valid value for it --
    // that is how the netlink address is meant to be initialised before the family
    // and pid fields are set below.
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
    let n = unsafe { libc::recv(fd.0, resp.as_mut_ptr() as *mut libc::c_void, resp.len(), 0) };
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
            e if -e == libc::EEXIST => Ok(()), // already there is fine, both calls are idempotent
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

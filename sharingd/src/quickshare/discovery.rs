//! Browse for Quick Share peers on the Wi-Fi LAN.
//!
//! IPv4, DELIBERATELY, and this is the one real difference from the AirDrop browser.
//! That one is IPv6-only because AWDL gives us nothing but a link-local address on
//! `mosey0`. Quick Share over a LAN runs on the network the phone has already joined,
//! where mDNS is IPv4 in practice -- so this binds `wlan0` and speaks 224.0.0.251.
//!
//! It follows that this path touches no AWDL at all: no `mosey0`, no radio mode, no
//! band selection, nothing that can take Wi-Fi down. That is the point of doing Quick
//! Share on hardware where AWDL and Wi-Fi cannot coexist.
//!
//! DNS message handling is reused wholesale from `dns` -- it is the same protocol,
//! and it is already proven against Apple responders.

use crate::dns;
use crate::quickshare::endpoint::EndpointInfo;
use crate::quickshare::{self, TXT_ENDPOINT_INFO};
use std::collections::HashMap;
use std::io;
use std::net::{Ipv4Addr, SocketAddrV4, UdpSocket};
use std::os::unix::io::AsRawFd;
use std::time::{Duration, Instant};

const MDNS_V4: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);
const MDNS_PORT: u16 = 5353;

#[derive(Debug, Clone)]
pub struct QsPeer {
    pub endpoint_id: String,
    pub instance: String,
    pub host: String,
    pub port: u16,
    pub addr: Option<Ipv4Addr>,
    pub name: Option<String>,
    pub last_seen: Instant,
}

pub struct QsBrowser {
    /// Receives: bound to INADDR_ANY:5353 and joined to the group, which is the only
    /// way to see multicast addressed to the group rather than to us.
    sock: UdpSocket,
    /// Sends: bound to the interface's own address.
    ///
    /// Two sockets because the two ends want opposite things. Sending from the
    /// INADDR_ANY socket is refused with EPERM on Android's managed networks -- the
    /// route resolves for our uid (checked with `ip route get ... uid 9999`, both
    /// with mark 0 and with the wlan0 netid), so it is not routing; it is that a
    /// socket with no local address has no network to be permitted on. Binding the
    /// interface address states which network we are on, without needing SO_MARK and
    /// therefore without CAP_NET_ADMIN, which this daemon must never hold.
    tx: UdpSocket,
    peers: HashMap<String, QsPeer>,
}

impl QsBrowser {
    pub fn new(iface: &str) -> io::Result<Self> {
        let ifindex = crate::mdns::ifindex_of(iface)?;
        let sock = bind_reuse_v4(MDNS_PORT).or_else(|e| {
            // The platform's own mdnsd may hold :5353. An ephemeral port still
            // receives the multicast we joined and can still query; it only stops us
            // answering. Discovery is what this phase needs, so that is enough.
            log::warn!("quickshare: could not bind :{MDNS_PORT} ({e}); ephemeral port");
            UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0))
        })?;
        join_multicast_v4(&sock, ifindex)?;
        // Choose the egress interface EXPLICITLY, or the send is refused outright.
        //
        // Android routes by fwmark and ends its rule list with "from all
        // unreachable". A socket on INADDR_ANY has no output interface, carries mark
        // 0, matches nothing above that line, and sendto() returns EPERM -- which
        // reads like a permissions problem and is really a routing one. The rule that
        // saves us is
        //
        //     17000: from all iif lo oif wlan0 lookup wlan0
        //
        // which has no uid range, so naming the interface is enough and no capability
        // is required. tarishsharingd holds none and must keep it that way.
        set_multicast_if_v4(&sock, ifindex)?;
        sock.set_read_timeout(Some(Duration::from_millis(500)))?;

        let local = ipv4_of(iface).ok_or_else(|| {
            io::Error::new(io::ErrorKind::AddrNotAvailable, format!("{iface} has no IPv4 address"))
        })?;
        let tx = UdpSocket::bind(SocketAddrV4::new(local, 0))?;
        set_multicast_if_v4(&tx, ifindex)?;

        Ok(Self { sock, tx, peers: HashMap::new() })
    }

    pub fn query(&self) -> io::Result<()> {
        let pkt = dns::query(quickshare::endpoint::SERVICE_TYPE);
        self.tx.send_to(&pkt, SocketAddrV4::new(MDNS_V4, MDNS_PORT))?;
        Ok(())
    }

    /// Read whatever has arrived and fold it into the peer table.
    pub fn poll(&mut self) {
        let mut buf = [0u8; 4096];
        // Bounded, so a chatty network cannot hold this thread forever.
        for _ in 0..32 {
            let n = match self.sock.recv_from(&mut buf) {
                Ok((n, _)) => n,
                Err(_) => return,
            };
            if let Some(msg) = dns::parse(&buf[..n]) {
                self.absorb(&buf[..n], &msg.records);
            }
        }
    }

    fn absorb(&mut self, packet: &[u8], records: &[dns::Record]) {
        for rec in records {
            match rec.rtype {
                dns::TYPE_PTR if rec.name == quickshare::endpoint::SERVICE_TYPE => {
                    let mut r = dns::Reader { buf: packet, pos: rec.rdata_at };
                    let Some(instance) = r.name() else { continue };
                    // An instance whose label does not decode to our service is not
                    // ours, whatever service it was published under.
                    let Some(id) = quickshare::endpoint_id_from_instance(&instance) else {
                        continue;
                    };
                    let endpoint_id = String::from_utf8_lossy(&id).into_owned();
                    self.peers.entry(instance.clone()).or_insert_with(|| {
                        log::info!("quickshare: peer discovered: {endpoint_id}");
                        QsPeer {
                            endpoint_id,
                            instance: instance.clone(),
                            host: String::new(),
                            port: 0,
                            addr: None,
                            name: None,
                            last_seen: Instant::now(),
                        }
                    }).last_seen = Instant::now();
                }
                dns::TYPE_SRV if rec.rdata.len() >= 6 => {
                    let port = u16::from_be_bytes([rec.rdata[4], rec.rdata[5]]);
                    let mut r = dns::Reader { buf: packet, pos: rec.rdata_at + 6 };
                    let host = r.name().unwrap_or_default();
                    if let Some(p) = self.peers.get_mut(&rec.name) {
                        p.port = port;
                        p.host = host;
                        p.last_seen = Instant::now();
                    }
                }
                dns::TYPE_TXT => {
                    if let Some(p) = self.peers.get_mut(&rec.name) {
                        if let Some(name) = name_from_txt(&rec.rdata) {
                            if p.name.as_deref() != Some(name.as_str()) {
                                log::info!(
                                    "quickshare: {} is {name:?}", p.endpoint_id
                                );
                            }
                            p.name = Some(name);
                        }
                        p.last_seen = Instant::now();
                    }
                }
                dns::TYPE_A if rec.rdata.len() == 4 => {
                    let a = Ipv4Addr::new(rec.rdata[0], rec.rdata[1], rec.rdata[2], rec.rdata[3]);
                    // A records name the HOST, not the instance, so match on it.
                    for p in self.peers.values_mut() {
                        if !p.host.is_empty() && p.host == rec.name {
                            p.addr = Some(a);
                            p.last_seen = Instant::now();
                        }
                    }
                }
                _ => {}
            }
        }
    }

    pub fn expire(&mut self, older_than: Duration) {
        let now = Instant::now();
        self.peers.retain(|_, p| now.duration_since(p.last_seen) < older_than);
    }

    pub fn peers(&self) -> Vec<QsPeer> {
        self.peers.values().cloned().collect()
    }
}

/// Pull the device name out of the TXT record's `n=` entry.
///
/// TXT rdata is a sequence of length-prefixed strings, and the value is base64 of the
/// endpoint info rather than a plain name -- so a peer with no parseable `n=` yields
/// None and stays nameless rather than being dropped.
fn name_from_txt(rdata: &[u8]) -> Option<String> {
    let mut i = 0;
    while i < rdata.len() {
        let len = rdata[i] as usize;
        i += 1;
        if i + len > rdata.len() {
            break;
        }
        let entry = &rdata[i..i + len];
        i += len;
        let Some(eq) = entry.iter().position(|&c| c == b'=') else { continue };
        if &entry[..eq] != TXT_ENDPOINT_INFO.as_bytes() {
            continue;
        }
        let raw = quickshare::base64_any_decode(&entry[eq + 1..])?;
        return EndpointInfo::parse(&raw)?.device_name;
    }
    None
}

fn bind_reuse_v4(port: u16) -> io::Result<UdpSocket> {
    // SAFETY: plain socket(2) with constant arguments.
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let on: libc::c_int = 1;
    for opt in [libc::SO_REUSEADDR, libc::SO_REUSEPORT] {
        // SAFETY: on is a live c_int of the stated size; fd is owned here.
        unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                opt,
                &on as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
        }
    }
    let mut a: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    a.sin_family = libc::AF_INET as u16;
    a.sin_port = port.to_be();
    // SAFETY: a is a correctly-sized sockaddr_in and fd is owned here.
    let rc = unsafe {
        libc::bind(
            fd,
            &a as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        let e = io::Error::last_os_error();
        // SAFETY: fd is owned and not yet handed to a UdpSocket.
        unsafe { libc::close(fd) };
        return Err(e);
    }
    // SAFETY: fd is a valid, bound UDP socket that nothing else owns.
    Ok(unsafe { <UdpSocket as std::os::unix::io::FromRawFd>::from_raw_fd(fd) })
}

/// The interface's IPv4 address, read from the kernel rather than assumed.
fn ipv4_of(iface: &str) -> Option<Ipv4Addr> {
    // SAFETY: a zeroed ifreq is valid, and the name is copied in bounded below.
    let mut req: libc::ifreq = unsafe { std::mem::zeroed() };
    let name = iface.as_bytes();
    if name.len() >= req.ifr_name.len() {
        return None;
    }
    for (i, b) in name.iter().enumerate() {
        req.ifr_name[i] = *b as libc::c_char;
    }
    // SAFETY: a UDP socket is a valid handle for SIOCGIFADDR, and req is correctly
    // sized. The fd is closed before returning.
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if fd < 0 {
        return None;
    }
    let rc = unsafe { libc::ioctl(fd, libc::SIOCGIFADDR as libc::c_int, &mut req) };
    // SAFETY: fd was created here and is not referenced afterwards.
    unsafe { libc::close(fd) };
    if rc != 0 {
        return None;
    }
    // SAFETY: SIOCGIFADDR fills ifr_addr as a sockaddr_in on success.
    let sa: libc::sockaddr_in = unsafe { std::mem::transmute_copy(&req.ifr_ifru) };
    Some(Ipv4Addr::from(u32::from_be(sa.sin_addr.s_addr)))
}

fn set_multicast_if_v4(sock: &UdpSocket, ifindex: u32) -> io::Result<()> {
    let mreq = libc::ip_mreqn {
        imr_multiaddr: libc::in_addr { s_addr: 0 },
        imr_address: libc::in_addr { s_addr: libc::INADDR_ANY.to_be() },
        imr_ifindex: ifindex as libc::c_int,
    };
    // SAFETY: mreq is a correctly-sized ip_mreqn and the fd is owned by sock.
    let rc = unsafe {
        libc::setsockopt(
            sock.as_raw_fd(),
            libc::IPPROTO_IP,
            libc::IP_MULTICAST_IF,
            &mreq as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::ip_mreqn>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn join_multicast_v4(sock: &UdpSocket, ifindex: u32) -> io::Result<()> {
    // ip_mreqn rather than ip_mreq: selecting the interface by INDEX is exact,
    // whereas by address it depends on which address the interface happens to hold
    // at this instant -- and on a phone that changes.
    let mreq = libc::ip_mreqn {
        imr_multiaddr: libc::in_addr { s_addr: u32::from_ne_bytes(MDNS_V4.octets()) },
        imr_address: libc::in_addr { s_addr: libc::INADDR_ANY.to_be() },
        imr_ifindex: ifindex as libc::c_int,
    };
    // SAFETY: mreq is a correctly-sized ip_mreqn and the fd is owned by sock.
    let rc = unsafe {
        libc::setsockopt(
            sock.as_raw_fd(),
            libc::IPPROTO_IP,
            libc::IP_ADD_MEMBERSHIP,
            &mreq as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::ip_mreqn>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

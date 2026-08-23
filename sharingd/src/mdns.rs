//! mDNS discovery on the AWDL link.
//!
//! AirDrop peers advertise `_airdrop._tcp.local` over mDNS on the AWDL
//! interface. This module joins the mDNS multicast group ON THAT INTERFACE
//! specifically — which is why Android's NsdManager is no use here even if a
//! native daemon could reach it: it gives no control over which interface a
//! service is browsed on, and browsing the Wi-Fi LAN instead of AWDL would find
//! nothing.
//!
//! Discovery only. Advertising comes next; browsing first because it can be
//! verified against a real Apple device without our own announcement having to
//! be correct.

use crate::dns;
use std::collections::HashMap;
use std::io;
use std::net::{Ipv6Addr, SocketAddrV6, UdpSocket};
use std::os::fd::AsRawFd;
use std::time::{Duration, Instant};

pub const AIRDROP_SERVICE: &str = "_airdrop._tcp.local";
const MDNS_PORT: u16 = 5353;
/// ff02::fb — the IPv6 mDNS link-local multicast group.
const MDNS_GROUP: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0x00fb);

#[derive(Clone, Debug)]
pub struct Peer {
    /// The mDNS instance name, e.g. `abc123def456._airdrop._tcp.local`.
    pub instance: String,
    /// Host from the SRV record, if seen.
    pub host: String,
    pub port: u16,
    pub addr: Option<Ipv6Addr>,
    pub last_seen: Instant,
}

impl Peer {
    /// Apple's instance names are 12 hex characters, which is an identifier and
    /// not a name a person would recognise. Until we parse the TXT record for
    /// something friendlier, show the identifier.
    pub fn short_id(&self) -> &str {
        self.instance.split('.').next().unwrap_or(&self.instance)
    }
}

pub struct Browser {
    sock: UdpSocket,
    peers: HashMap<String, Peer>,
    ifindex: u32,
}

impl Browser {
    /// Bind to the mDNS port and join the group **on `iface` only**.
    pub fn new(iface: &str) -> io::Result<Self> {
        let ifindex = ifindex_of(iface)?;

        let sock = UdpSocket::bind(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, MDNS_PORT, 0, 0))
            .or_else(|e| {
                // Port 5353 may already be held by the platform's mdnsd. Falling
                // back to an ephemeral port still receives multicast we joined,
                // and still lets us query; it only stops us being a responder.
                log::warn!("could not bind :{MDNS_PORT} ({e}); using an ephemeral port");
                UdpSocket::bind(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 0, 0, 0))
            })?;

        join_multicast(&sock, ifindex)?;
        sock.set_read_timeout(Some(Duration::from_millis(500)))?;

        Ok(Browser { sock, peers: HashMap::new(), ifindex })
    }

    /// Send a PTR query for AirDrop.
    pub fn query(&self) -> io::Result<()> {
        let pkt = dns::query(AIRDROP_SERVICE);
        let dst = SocketAddrV6::new(MDNS_GROUP, MDNS_PORT, 0, self.ifindex);
        self.sock.send_to(&pkt, dst)?;
        Ok(())
    }

    /// Read whatever has arrived and fold it into the peer table. Returns the
    /// number of packets processed.
    pub fn poll(&mut self) -> usize {
        let mut buf = [0u8; 4096];
        let mut n = 0;
        // Bounded so a chatty link cannot keep us in here indefinitely.
        for _ in 0..32 {
            match self.sock.recv_from(&mut buf) {
                Ok((len, _from)) => {
                    n += 1;
                    if let Some(records) = dns::parse(&buf[..len]) {
                        self.absorb(&buf[..len], &records);
                    }
                    // A packet we cannot parse is simply ignored. Peers on a
                    // shared link include devices we know nothing about.
                }
                Err(_) => break, // timeout or would-block
            }
        }
        n
    }

    fn absorb(&mut self, packet: &[u8], records: &[dns::Record]) {
        for rec in records {
            match rec.rtype {
                dns::TYPE_PTR if rec.name == AIRDROP_SERVICE => {
                    let mut r = dns::Reader { buf: packet, pos: rec.rdata_at };
                    if let Some(instance) = r.name() {
                        let e = self.peers.entry(instance.clone()).or_insert_with(|| {
                            log::info!("peer discovered: {}", short(&instance));
                            Peer {
                                instance: instance.clone(),
                                host: String::new(),
                                port: 0,
                                addr: None,
                                last_seen: Instant::now(),
                            }
                        });
                        e.last_seen = Instant::now();
                    }
                }
                dns::TYPE_SRV => {
                    // SRV rdata: priority(2) weight(2) port(2) target(name)
                    if rec.rdata.len() >= 6 {
                        let port = u16::from_be_bytes([rec.rdata[4], rec.rdata[5]]);
                        let mut r = dns::Reader { buf: packet, pos: rec.rdata_at + 6 };
                        let host = r.name().unwrap_or_default();
                        if let Some(p) = self.peers.get_mut(&rec.name) {
                            p.port = port;
                            p.host = host;
                            p.last_seen = Instant::now();
                        }
                    }
                }
                dns::TYPE_AAAA if rec.rdata.len() == 16 => {
                    let mut o = [0u8; 16];
                    o.copy_from_slice(&rec.rdata);
                    let addr = Ipv6Addr::from(o);
                    // The AAAA name is the host, not the instance, so match on it.
                    for p in self.peers.values_mut() {
                        if !p.host.is_empty() && p.host == rec.name {
                            p.addr = Some(addr);
                            p.last_seen = Instant::now();
                        }
                    }
                }
                _ => {}
            }
        }
    }

    /// Drop peers not heard from recently. mDNS TTLs are advisory; a peer that
    /// walks away simply stops announcing.
    pub fn expire(&mut self, older_than: Duration) {
        let now = Instant::now();
        self.peers.retain(|name, p| {
            let keep = now.duration_since(p.last_seen) < older_than;
            if !keep {
                log::info!("peer lost: {}", short(name));
            }
            keep
        });
    }

    pub fn peers(&self) -> Vec<Peer> {
        self.peers.values().cloned().collect()
    }
}

fn short(instance: &str) -> &str {
    instance.split('.').next().unwrap_or(instance)
}

fn ifindex_of(iface: &str) -> io::Result<u32> {
    let c = std::ffi::CString::new(iface).map_err(|_| io::Error::other("bad interface name"))?;
    // SAFETY: c is a valid NUL-terminated string.
    let idx = unsafe { libc::if_nametoindex(c.as_ptr()) };
    if idx == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(idx)
    }
}

/// Join ff02::fb on one interface. std has no IPv6 multicast join that takes an
/// interface index, so this is a setsockopt.
fn join_multicast(sock: &UdpSocket, ifindex: u32) -> io::Result<()> {
    let mreq = libc::ipv6_mreq {
        ipv6mr_multiaddr: libc::in6_addr { s6_addr: MDNS_GROUP.octets() },
        ipv6mr_interface: ifindex as _,
    };
    // SAFETY: mreq is a correctly-sized ipv6_mreq and the fd is owned by sock.
    let rc = unsafe {
        libc::setsockopt(
            sock.as_raw_fd(),
            libc::IPPROTO_IPV6,
            libc::IPV6_ADD_MEMBERSHIP,
            &mreq as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::ipv6_mreq>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }

    // Send multicast out of this interface too, not whatever the routing table
    // would otherwise pick.
    // SAFETY: ifindex is a u32 of the stated size.
    let rc = unsafe {
        libc::setsockopt(
            sock.as_raw_fd(),
            libc::IPPROTO_IPV6,
            libc::IPV6_MULTICAST_IF,
            &ifindex as *const _ as *const libc::c_void,
            std::mem::size_of::<u32>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

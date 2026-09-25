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
/// Port we claim in SRV. Nothing listens there yet; the protocol comes next.
/// Mosey uses high arbitrary ports (40985, 38005, 39763), so this is not fixed
/// by the protocol.
pub(crate) const AIRDROP_PORT: u16 = 8770;
/// DNS-SD service enumeration.
const SERVICE_ENUM: &str = "_services._dns-sd._udp.local";
/// The TXT a working Android peer sends. 489 = 0x1E9; bit meanings unknown.
const AIRDROP_FLAGS: &str = "flags=489";
/// Seconds. Short enough that a peer walking away disappears reasonably soon.
const TTL: u32 = 120;
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
    /// When this peer stops being valid, from the TTL IT told us.
    ///
    /// Discovery used to expire on `last_seen` alone against a fixed 45s, while querying
    /// every 4s. Apple's responder will not re-answer an identical question it has recently
    /// multicast (RFC 6762 response suppression), so most of those queries draw silence --
    /// and 45s later a peer that had advertised a 120s TTL was dropped as if it had walked
    /// away. Measured on hardware: the same Mac discovered and lost four times in fifteen
    /// minutes, which is what "AirDrop is not stable" looked like from the share sheet.
    ///
    /// The peer's own TTL is the right clock, so this holds it.
    pub expires_at: Instant,
    /// Questions this peer owes an answer to: unicast probes aimed at it, and multicast
    /// QU queries every responder must answer. Zeroed by any record it sends.
    ///
    /// THE TTL IS NOT A LIVENESS SIGNAL, and this is what replaces it for that job. iOS
    /// advertises AirDrop with a 4500 s TTL and sends a goodbye only on a graceful
    /// withdrawal; screen off, AirDrop off and walking away send nothing. So a peer that
    /// left stays valid by its own clock for seventy-five minutes, and the person taps a
    /// device that cannot answer. `LOST_UNANSWERED` of these in a row, with nothing heard
    /// for `LOST_AFTER`, is "gone" -- a few seconds, not an hour.
    pub unanswered: u32,
    /// When BLE said this peer stopped being receptive -- screen locked or AirDrop
    /// switched off, which look the same on the air. None while receptive, or while
    /// there is no BLE evidence either way. See `Browser::mark_unreceptive`.
    pub unreceptive_since: Option<Instant>,
}

/// Unanswered questions before a peer is presumed gone. Three, because a single frame
/// can miss an AWDL availability window, and two in a row is still a bad moment.
const LOST_UNANSWERED: u32 = 3;
/// And nothing heard from it for at least this long.
///
/// TWENTY SECONDS, NOT FOUR, AND THAT IS MEASURED. The first version used 4 s and evicted
/// a present iPhone: it answered at :52.4 and :55.5, then said nothing for 14 s while we
/// asked nine times, then answered again at :09.8 -- and we had dropped it at :00.1 as
/// "5 queries unanswered, nothing heard for 4.6s". Apple's responder does not answer every
/// repeated question, and whether it answers unicast probes at all on AWDL is not yet
/// settled (the answers we do get arrive with the multicast ones). So silence for a few
/// seconds is normal here and proves nothing. This bound is only for "gone" -- Bluetooth
/// off, walked away -- and even a minute is 75 times better than the 75-minute TTL. The
/// "screen off within a few seconds" the person sees comes from the BLE label and the
/// hide timer in getPeers, not from this.
///
/// SIXTY, NOT TWENTY -- second measurement, same day. An unlocked, receptive iPhone on
/// the desk answered a probe at :05.3 and then nothing for the next 20 s while asked
/// fifteen times; the 20 s rule dropped it at :41.06, which happened to coincide with
/// the operator switching its Bluetooth off, so the outcome looked right and the timer
/// had actually fired. A live idle iPhone is routinely silent for 20 s here. Sixty is a
/// bound on "gone" with no BLE evidence at all; with BLE running, the label hides the
/// peer in six seconds and this only clears the table later.
const LOST_AFTER: Duration = Duration::from_secs(60);

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
    iface: String,
    /// Our own instance name, e.g. "a1b2c3d4e5f6". Apple uses 12 hex characters
    /// and so do we, because peers display it and an unusual shape is a way to
    /// look wrong to something we cannot test against.
    instance: String,
    advertising: bool,
    /// How many browse queries we have sent. Drives the QU/QM mix in `query` — the first few
    /// of a session must not be suppressible, the rest can be the cheaper multicast form.
    queries_sent: u32,
    /// Whether we hold port 5353. A responder MUST: a peer sends its query to
    /// :5353 and will not see an answer from anywhere else.
    can_respond: bool,
}

impl Browser {
    /// Bind to the mDNS port and join the group **on `iface` only**.
    pub fn new(iface: &str) -> io::Result<Self> {
        let ifindex = ifindex_of(iface)?;

        // Bind with SO_REUSEPORT so a capture tool can listen on :5353 alongside
        // us. Without it, observing what this daemon receives means stopping it,
        // which changes the thing being observed.
        let sock = bind_reuse(MDNS_PORT)
            .or_else(|e| {
                // Port 5353 may already be held by the platform's mdnsd. Falling
                // back to an ephemeral port still receives multicast we joined,
                // and still lets us query; it only stops us being a responder.
                log::warn!("could not bind :{MDNS_PORT} ({e}); using an ephemeral port");
                UdpSocket::bind(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 0, 0, 0))
            })?;

        let can_respond = sock
            .local_addr()
            .map(|a| a.port() == MDNS_PORT)
            .unwrap_or(false);

        join_multicast(&sock, ifindex)?;
        sock.set_read_timeout(Some(Duration::from_millis(500)))?;

        Ok(Browser {
            sock,
            peers: HashMap::new(),
            ifindex,
            iface: iface.to_string(),
            instance: stable_instance(iface),
            advertising: false,
            queries_sent: 0,
            can_respond,
        })
    }

    /// Stop advertising, and tell peers so rather than letting them time us out.
    ///
    /// The previous version just went quiet, on the reasoning that a goodbye "claims
    /// records we are about to stop answering for". That was wrong on both counts: a
    /// goodbye claims nothing, it is the RFC 6762 §10.1 withdrawal, and going quiet
    /// does not remove us -- it leaves us listed for the rest of the TTL.
    ///
    /// With TTL at 120 s that is two minutes during which a Mac shows this phone,
    /// lets someone pick it, and gets the transfer refused. Screen off, app closed,
    /// still on the list. Being invisible has to be something we say, not something
    /// the other side eventually infers.
    pub fn stop_advertising(&mut self) -> io::Result<()> {
        if !self.advertising {
            return Ok(());
        }
        self.advertising = false;
        self.goodbye()
    }

    /// Withdraw our records: the same set, TTL 0.
    fn goodbye(&self) -> io::Result<()> {
        let pkt = dns::response(&self.records_with_ttl(0));
        // Repeated, because a withdrawal that is lost has no second chance -- the next
        // thing that would correct a peer's view is the TTL expiring, which is the
        // whole problem. Cheap: three small packets, once, on the way out.
        let mut last = Ok(());
        for i in 0..3 {
            if i > 0 {
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            last = self.send_multicast(&pkt);
        }
        last
    }

    pub fn instance(&self) -> &str {
        &self.instance
    }

    /// Forget the current AirDrop identity and mint a fresh random one, persisting it.
    ///
    /// The deliberate privacy escape hatch behind the app's "reset identity" control:
    /// it trades the cross-session continuity a stable identity buys (a peer keeps
    /// recognising this device) for unlinkability -- peers that had this device saved
    /// will no longer recognise it. Returns the new instance name.
    ///
    /// The caller MUST withdraw the old instance (`stop_advertising`) before this and
    /// re-announce after, or the old name lingers in a peer's cache for the record TTL
    /// -- a ghost, the very thing the stable identity exists to remove.
    pub fn reset_identity(&mut self) -> String {
        self.instance = mint_identity(&self.iface);
        self.instance.clone()
    }

    /// Start advertising this device as an AirDrop peer, and announce now.
    ///
    /// Announcing is not optional politeness: a peer that is already browsing
    /// has no reason to re-query, so without an unsolicited announcement we stay
    /// invisible until something else prompts it.
    pub fn advertise(&mut self) -> io::Result<()> {
        if !self.can_respond {
            return Err(io::Error::other(
                "not bound to :5353, so queries cannot be answered — something \
                 else holds the mDNS port",
            ));
        }
        self.advertising = true;
        self.announce()
    }

    /// Is this address one of ours?
    ///
    /// THE ONLY SELF-TEST THAT DOES NOT DRIFT. The instance name is derived from the
    /// interface MAC and snapshotted when the Browser is built -- and since the radio
    /// became on-demand, mosey0 is destroyed and recreated with a NEW MAC every time
    /// it is acquired. So a name-based check is comparing against whatever the MAC
    /// happened to be at construction, and anything of ours that arrives from either
    /// side of that boundary sails past it.
    ///
    /// An address is checked against /proc/net/if_inet6 at the moment of the question,
    /// so it cannot be stale. If a record points at an address that is currently ours,
    /// it is us, whatever it calls itself.
    ///
    /// The symptom when this is missed: the device lists itself, and tapping it makes
    /// the phone open an AirDrop connection to its own link-local address and prompt
    /// the person to accept a file from themselves.
    /// Is this service instance ours, by either the name we were built with or the
    /// one the interface would give us right now?
    ///
    /// Both, because the two disagree exactly when it matters. `self.instance` is
    /// fixed at construction; the second is recomputed from the interface's current
    /// MAC. Across a radio release and re-acquire the MAC changes, so an announcement
    /// we made on one side of that boundary does not match the name we hold on the
    /// other.
    fn is_self_instance(&self, instance: &str) -> bool {
        if instance == self.full_instance() {
            return true;
        }
        // Now that the identity is persisted (`stable_instance`), this recompute
        // equals `self.instance` and the check above already covers it -- but keep
        // it against the same source so it stays correct if persistence changes
        // under us mid-session. (Address-based `is_self_addr` remains the
        // drift-proof self-test.)
        let now = format!("{}.{}", stable_instance(&self.iface), AIRDROP_SERVICE);
        instance == now
    }

    fn is_self_addr(&self, a: Ipv6Addr) -> bool {
        self.our_addr() == Some(a)
    }

    fn our_addr(&self) -> Option<Ipv6Addr> {
        link_local_of(&self.iface)
    }

    fn host(&self) -> String {
        // Mosey uses Android_XXXXXXXX.local rather than the instance name, so a
        // peer sees a host distinct from the rotating service identity.
        format!("Android_{}.local", self.instance.get(..8).unwrap_or(&self.instance).to_uppercase())
    }

    fn full_instance(&self) -> String {
        format!("{}.{}", self.instance, AIRDROP_SERVICE)
    }

    /// The record set that describes us: what we are, where, and how to reach us.
    fn our_records(&self) -> Vec<Vec<u8>> {
        self.records_with_ttl(TTL)
    }

    /// The same set at an arbitrary TTL. Zero is a withdrawal; see `goodbye`.
    fn records_with_ttl(&self, ttl: u32) -> Vec<Vec<u8>> {
        let inst = self.full_instance();
        let host = self.host();
        let mut out = Vec::with_capacity(4);

        // Service enumeration: "this host offers _airdrop._tcp". Mosey sends it
        // and Tarish did not; a browser that enumerates services rather than
        // querying ours by name would never have seen us.
        out.push(dns::record(SERVICE_ENUM, dns::TYPE_PTR, ttl,
                             &dns::encode_name(AIRDROP_SERVICE), false));

        out.push(dns::record(AIRDROP_SERVICE, dns::TYPE_PTR, ttl,
                             &dns::encode_name(&inst), false));

        let mut srv = Vec::with_capacity(16);
        srv.extend_from_slice(&0u16.to_be_bytes());        // priority
        srv.extend_from_slice(&0u16.to_be_bytes());        // weight
        srv.extend_from_slice(&AIRDROP_PORT.to_be_bytes());
        srv.extend_from_slice(&dns::encode_name(&host));
        out.push(dns::record(&inst, dns::TYPE_SRV, ttl, &srv, true));

        // One key. Captured from Google's Mosey, which interoperates:
        //
        //   TXT 8ed4b330f476._airdrop._tcp.local -> flags=489
        //
        // An earlier version sent sn/at/sid/dnm here. Those belong to the Mac's
        // _appsvcprepair and _applicationservicepairing services and never
        // appear on _airdrop._tcp -- copying them onto this service was wrong.
        // 489 is 0x1E9; the bit meanings are not known.
        out.push(dns::record(&inst, dns::TYPE_TXT, ttl,
                             &dns::txt_rdata(&[AIRDROP_FLAGS]), true));

        if let Some(a) = self.our_addr() {
            out.push(dns::record(&host, dns::TYPE_AAAA, ttl, &a.octets(), true));
            // Reverse lookup, as Mosey publishes.
            out.push(dns::record(&reverse_name(&a), dns::TYPE_PTR, ttl,
                                 &dns::encode_name(&host), true));
        }

        // NSEC for both names we own. This is the correct reply to a query for a
        // type we do not have -- notably A on our host, which is exactly what an
        // Apple peer asked for and got silence.
        out.push(dns::record(&inst, dns::TYPE_NSEC, ttl,
                             &dns::nsec_rdata(&inst, &[dns::TYPE_TXT, dns::TYPE_SRV]), true));
        out.push(dns::record(&host, dns::TYPE_NSEC, ttl,
                             &dns::nsec_rdata(&host, &[dns::TYPE_AAAA]), true));
        out
    }

    fn send_multicast(&self, pkt: &[u8]) -> io::Result<()> {
        let dst = SocketAddrV6::new(MDNS_GROUP, MDNS_PORT, 0, self.ifindex);
        self.sock.send_to(pkt, dst)?;
        Ok(())
    }

    /// Unsolicited announcement of our records.
    pub fn announce(&self) -> io::Result<()> {
        if !self.advertising {
            return Ok(());
        }
        let recs = self.our_records();
        self.send_multicast(&dns::response(&recs))
    }

    /// Answer questions that are about us. Anything else is ignored rather than
    /// answered wrongly -- a responder that replies to names it does not own is
    /// worse than one that stays quiet.
    fn answer(&self, questions: &[dns::Question]) {
        if questions.is_empty() {
            return;
        }
        let inst = self.full_instance();
        let host = self.host();

        // Answer only what was actually asked about, and only for names we own.
        // A responder that replies to everything is worse than a quiet one: it
        // pollutes peers' caches with records it cannot back up.
        const QTYPE_ANY: u16 = 255;
        let mine = questions.iter().any(|q| {
            let ours = q.name == AIRDROP_SERVICE || q.name == inst || q.name == host;
            if !ours {
                return false;
            }
            match q.name.as_str() {
                // Service enumeration: PTR, or ANY.
                n if n == AIRDROP_SERVICE => {
                    q.qtype == dns::TYPE_PTR || q.qtype == QTYPE_ANY
                }
                // Our instance: SRV and TXT describe it.
                n if n == inst => {
                    q.qtype == dns::TYPE_SRV || q.qtype == dns::TYPE_TXT || q.qtype == QTYPE_ANY
                }
                // Our host: where to reach it.
                //
                // Answer type A as well as AAAA. Apple's stack asks for A even
                // on an IPv6-only link -- captured on the wire: after seeing our
                // PTR and SRV it sent "Q A c66a180ad90e.local" twice and nothing
                // else. We have no IPv4, so answering with our AAAA is the
                // useful reply; staying silent looks like a host that does not
                // exist, and the peer drops us.
                _ => q.qtype == dns::TYPE_AAAA
                    || q.qtype == dns::TYPE_A
                    || q.qtype == QTYPE_ANY,
            }
        });
        if !mine {
            return;
        }
        let asked: Vec<String> = questions
            .iter()
            .map(|q| format!("{}/{}", q.name, q.qtype))
            .collect();
        let recs = self.our_records();
        match self.send_multicast(&dns::response(&recs)) {
            Ok(()) => log::info!("answered {} record(s) to {:?}", recs.len(), asked),
            Err(e) => log::warn!("could not answer query {asked:?}: {e}"),
        }
    }

    /// Send a PTR query for AirDrop.
    ///
    /// MOSTLY QM, PERIODICALLY QU, and the mix is the point. A QM query is answered by
    /// multicast so every listener learns — but a responder that recently multicast the same
    /// record will not repeat it (Apple's does this), so a browser that only ever asks QM can
    /// sit in silence next to a peer that is plainly there. That is what made both a MacBook
    /// and an iPhone invisible until the operator switched to the receive screen and back:
    /// receiving makes us announce, the peers react, and their reaction was the only thing we
    /// ever heard.
    ///
    /// A QU question (RFC 6762 §5.4) must be answered directly and is not suppressed by a
    /// recent multicast. Sending every query as QU would work and would also make us the
    /// noisiest device on the link, and it throws away the shared-learning property for the
    /// common case of simply refreshing a peer we already know. So: QU for the first few
    /// queries of a browse, when we know nothing and need an answer we cannot be denied, and
    /// then one in every five to recover from a peer we have somehow missed.
    pub fn query(&mut self) -> io::Result<()> {
        self.queries_sent = self.queries_sent.saturating_add(1);
        let unicast = self.queries_sent <= 3 || self.queries_sent % 5 == 0;
        let pkt = dns::query_with(AIRDROP_SERVICE, unicast);
        let dst = SocketAddrV6::new(MDNS_GROUP, MDNS_PORT, 0, self.ifindex);
        self.sock.send_to(&pkt, dst)?;
        // A QU question must be answered by every responder that has the record, so
        // each known peer now owes one. A QM question is suppressible and counts for
        // nothing: silence after it is the expected case, not evidence.
        if unicast {
            for p in self.peers.values_mut() {
                p.unanswered = p.unanswered.saturating_add(1);
            }
        }
        Ok(())
    }

    /// Ask every peer we hold an address for, directly, whether it is still there.
    ///
    /// A unicast QU query to the peer's own link-local address on :5353 (RFC 6762 §5.5).
    /// The answer comes back unicast to this socket and is absorbed like any other
    /// record, which zeroes `unanswered`; no answer leaves the count where the question
    /// put it. This is the whole liveness mechanism -- a peer is kept by answering, not by
    /// the TTL it advertised.
    ///
    /// Returns how many peers were asked.
    pub fn probe(&mut self) -> usize {
        let pkt = dns::query_with(AIRDROP_SERVICE, true);
        let ifindex = self.ifindex;
        let mut asked = 0;
        for p in self.peers.values_mut() {
            let Some(addr) = p.addr else { continue };
            let dst = SocketAddrV6::new(addr, MDNS_PORT, 0, ifindex);
            match self.sock.send_to(&pkt, dst) {
                Ok(_) => {
                    p.unanswered = p.unanswered.saturating_add(1);
                    asked += 1;
                }
                Err(e) => log::debug!("probe of {} failed: {e}", short(&p.instance)),
            }
        }
        asked
    }

    /// Record what BLE says about the peers as a population.
    ///
    /// `true` means every listed peer is unreceptive right now: the advertisement count
    /// covers them all and none carries the receptive bit. `false` means either that
    /// something is receptive or that there is no evidence, and in both cases the label
    /// comes off -- a label that cannot be attributed is worse than none.
    ///
    /// A POPULATION, NOT A NAME. A BLE address is random and rotates, so it cannot be tied
    /// to an mDNS instance. With one iPhone in range this is exact; with two, one of which
    /// locks, the count says "one of them" and this says nothing. The daemon's probes then
    /// find the one that stops answering, if it does.
    pub fn mark_unreceptive(&mut self, unreceptive: bool) {
        let now = Instant::now();
        for p in self.peers.values_mut() {
            if unreceptive {
                if p.unreceptive_since.is_none() {
                    log::info!("peer {} is no longer receptive (screen off or AirDrop off)", short(&p.instance));
                    p.unreceptive_since = Some(now);
                }
            } else if p.unreceptive_since.take().is_some() {
                log::info!("peer {} is receptive again", short(&p.instance));
            }
        }
    }

    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }

    /// Restart the QU burst — call when a browse begins, so the first queries of a new
    /// session are the ones that cannot be suppressed.
    pub fn restart_query_burst(&mut self) {
        self.queries_sent = 0;
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
                    if let Some(msg) = dns::parse(&buf[..len]) {
                        if !msg.questions.is_empty() {
                            log::debug!(
                                "rx {} question(s): {:?}",
                                msg.questions.len(),
                                msg.questions.iter().map(|q| format!("{}/{}", q.name, q.qtype)).collect::<Vec<_>>()
                            );
                        }
                        self.absorb(&buf[..len], &msg.records);
                        if self.advertising {
                            self.answer(&msg.questions);
                        }
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
        // TEMPORARY DIAGNOSTIC (2026-09-24): peers are lost and rediscovered seconds apart,
        // and nothing in this module logs an arriving record, so the log cannot distinguish
        // "the announcement never came" from "it came and we dropped the peer anyway".
        // Remove once that is settled.
        if !records.is_empty() {
            let seen: Vec<String> = records
                .iter()
                .map(|r| format!("{}/{}/ttl={}", short(&r.name), r.rtype, r.ttl))
                .collect();
            log::info!("rx {} record(s): {:?}", records.len(), seen);
        }
        for rec in records {
            match rec.rtype {
                dns::TYPE_PTR if rec.name == AIRDROP_SERVICE => {
                    let mut r = dns::Reader { buf: packet, pos: rec.rdata_at };
                    if let Some(instance) = r.name() {
                        // Our own announcement comes back to us: the multicast
                        // socket loops sends back by default, and we are joined
                        // to the group we send to. Listing ourselves as a peer
                        // would put this device in its own share sheet -- and it
                        // did, on a device whose radio backend echoes more of what
                        // we transmit than the one this was written against.
                        if self.is_self_instance(&instance) {
                            continue;
                        }
                        let e = self.peers.entry(instance.clone()).or_insert_with(|| {
                            log::info!("peer discovered: {}", short(&instance));
                            Peer {
                                instance: instance.clone(),
                                host: String::new(),
                                port: 0,
                                addr: None,
                                last_seen: Instant::now(),
                                expires_at: Instant::now() + Self::ttl_of(rec),
                                unanswered: 0,
                                unreceptive_since: None,
                            }
                        });
                        e.last_seen = Instant::now();
                        e.unanswered = 0;
                        e.expires_at = Instant::now() + Self::ttl_of(rec);
                    }
                }
                // TXT carries only `flags`, which we do not use -- but it arrives in every
                // answer to a probe, so it counts as the peer being heard.
                dns::TYPE_TXT => {
                    if let Some(p) = self.peers.get_mut(&rec.name) {
                        p.last_seen = Instant::now();
                        p.unanswered = 0;
                        let t = Instant::now() + Self::ttl_of(rec);
                        p.expires_at = if rec.ttl == 0 { t } else { p.expires_at.max(t) };
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
                            p.unanswered = 0;
                            // `max` everywhere EXCEPT a withdrawal: a goodbye must shorten
                            // the lease, which is the one thing `max` cannot do.
                            let t = Instant::now() + Self::ttl_of(rec);
                            p.expires_at = if rec.ttl == 0 { t } else { p.expires_at.max(t) };
                        }
                    }
                }
                dns::TYPE_AAAA if rec.rdata.len() == 16 => {
                    let mut o = [0u8; 16];
                    o.copy_from_slice(&rec.rdata);
                    let addr = Ipv6Addr::from(o);

                    // Ours. Drop whatever entry has been collecting under that host
                    // rather than merely declining to fill in the address -- an entry
                    // with a name and a port and no address is still offered to the
                    // client, and is still us.
                    if self.is_self_addr(addr) {
                        self.peers.retain(|_, p| p.host != rec.name);
                        continue;
                    }

                    // The AAAA name is the host, not the instance, so match on it.
                    for p in self.peers.values_mut() {
                        if !p.host.is_empty() && p.host == rec.name {
                            p.addr = Some(addr);
                            p.last_seen = Instant::now();
                            p.unanswered = 0;
                            let t = Instant::now() + Self::ttl_of(rec);
                            p.expires_at = if rec.ttl == 0 { t } else { p.expires_at.max(t) };
                        }
                    }
                }
                _ => {}
            }
        }
    }

    /// How long a record is good for, clamped.
///
/// A peer choosing a huge TTL must not pin an entry forever once it has actually gone, and
/// one choosing zero (a goodbye, or a bug) must not make the entry vanish before the floor
/// in `expire` can apply. Bonjour uses 120s for these records, which sits inside this range.
fn ttl_of(rec: &dns::Record) -> Duration {
    // A GOODBYE IS NOT A SHORT LEASE. RFC 6762 §10.1: ttl=0 means the record is no longer
    // valid, and a receiver should delete it — recording one second rather than zero, so a
    // reordered packet still in flight cannot resurrect it.
    //
    // This used to clamp 0 up to MIN, and the callers apply it with `.max(...)`, so a peer
    // saying "I am leaving now" was read as "keep me another 30s" and usually as nothing at
    // all. The comment below was guarding against a BUGGY zero and threw away the legitimate
    // withdrawal with it. Departing peers are supposed to linger on our list for no longer
    // than anyone else's.
    if rec.ttl == 0 {
        return Duration::from_secs(1);
    }
    const MIN: u64 = 30;
    const MAX: u64 = 300;
    Duration::from_secs((rec.ttl as u64).clamp(MIN, MAX))
}

/// Forget every peer, so the next query rebuilds the table from scratch.
    ///
    /// For an explicit user refresh. Expiry alone is not enough: a peer whose records
    /// we still hold but which has become unreachable stays listed until its TTL runs
    /// out, and on a link that flaps -- frankel, where AWDL owns the radio and Wi-Fi
    /// scans contend with it -- that is exactly the state a user is looking at when
    /// they reach for refresh.
    pub fn forget_peers(&mut self) {
        self.peers.clear();
    }

    /// Drop peers whose own TTL has run out.
    ///
    /// `min_grace` is a FLOOR, not the timeout: a peer is kept until the later of its
    /// advertised expiry and `min_grace` after we last heard it. It used to be the whole
    /// rule, which meant discarding peers that had explicitly said they were valid for
    /// longer -- see `Peer::expires_at`. Keeping the floor still covers a peer that sends
    /// an absurdly short TTL.
    pub fn expire(&mut self, min_grace: Duration) {
        let now = Instant::now();
        self.peers.retain(|name, p| {
            let silent = now.duration_since(p.last_seen);
            // Asked repeatedly, heard nothing: gone, whatever its TTL says. This is the
            // rule that actually removes a departed iPhone; the TTL rule below is the
            // backstop for a peer we never managed to probe (no address yet).
            if p.unanswered >= LOST_UNANSWERED && silent >= LOST_AFTER {
                log::info!(
                    "peer lost: {} — {} queries unanswered, nothing heard for {:.1}s",
                    short(name), p.unanswered, silent.as_secs_f32()
                );
                return false;
            }
            let keep = now < p.expires_at || silent < min_grace;
            if !keep {
                log::info!("peer lost: {}", short(name));
            }
            keep
        });
    }

    pub fn peers(&self) -> Vec<Peer> {
        // Filtered again here, not only where records are absorbed. Everything above
        // is about catching a record as it arrives; this is about what leaves, and it
        // holds even if some future path adds an entry without going through absorb.
        // Cheap: one /proc read per call against a handful of peers.
        // Read our address ONCE, not once per peer: is_self_addr goes to
        // /proc/net/if_inet6 every call, and this runs on the discovery loop.
        let me = self.our_addr();
        self.peers
            .values()
            .filter(|p| p.addr.is_none() || p.addr != me)
            .cloned()
            .collect()
    }
}

/// `fe80::1` -> `1.0.0....8.E.F.ip6.arpa`, the reverse-lookup name.
fn reverse_name(a: &Ipv6Addr) -> String {
    let mut out = String::with_capacity(72);
    for b in a.octets().iter().rev() {
        out.push_str(&format!("{:X}.{:X}.", b & 0x0f, b >> 4));
    }
    out.push_str("ip6.arpa");
    out
}

fn short(instance: &str) -> &str {
    instance.split('.').next().unwrap_or(instance)
}

/// Where the deliberate, MAC-independent AirDrop identity is persisted.
///
/// `/data/misc/tarish` is our data dir (0700, `tarish_data_file`, owned by
/// `system_ext_tarish`); we already create files under it (`inbox/`), so this
/// needs no new SELinux policy.
const IDENTITY_PATH: &str = "/data/misc/tarish/identity";

/// A stable 12-hex AirDrop instance name, persisted across sessions.
///
/// The instance name is what an Apple peer keys its cache on. Deriving it from
/// the interface MAC (see `instance_name`) makes it change every time the radio
/// is acquired -- mosey0 is destroyed and recreated with a fresh random MAC on
/// demand, not just per reboot -- so every session a peer sees a brand-new
/// device and the previous ones linger as unreachable "ghost" tiles pointing at
/// a now-dead link-local address. The `is_self_instance` / cache-flush handling
/// keeps *us* consistent within a session, but nothing collapses the peer's view
/// across sessions.
///
/// The fix the old `instance_name` comment asked for: a deliberate identity, not
/// a side effect. Read the persisted value if well-formed; otherwise mint one
/// (6 random bytes, 12 hex) and persist it. Apple's own instance names are
/// arbitrary 12-hex and need not equal the AWDL MAC, so an invented value
/// interoperates fine while giving the peer a constant handle -- one tile per
/// device, whose AAAA we refresh (cache-flush) each session.
///
/// If persistence is unavailable (getrandom or the write fails), fall back to
/// the MAC-derived name: no worse than the pre-existing behaviour, never a
/// hard failure.
fn stable_instance(iface: &str) -> String {
    if let Ok(s) = std::fs::read_to_string(IDENTITY_PATH) {
        let s = s.trim();
        if s.len() == 12 && s.chars().all(|c| c.is_ascii_hexdigit()) {
            return s.to_lowercase();
        }
    }
    mint_identity(iface)
}

/// Mint a fresh random 12-hex identity and persist it, replacing any existing one.
///
/// Used both to create the identity on first run (via `stable_instance`) and to
/// deliberately rotate it (`Browser::reset_identity`). Falls back to the
/// MAC-derived name if getrandom fails, so it is never a hard failure.
fn mint_identity(iface: &str) -> String {
    let mut b = [0u8; 6];
    // SAFETY: getrandom(2) writing exactly b.len() bytes into a live buffer.
    let n = unsafe { libc::getrandom(b.as_mut_ptr() as *mut libc::c_void, b.len(), 0) };
    if n != b.len() as isize {
        log::error!("getrandom failed minting AirDrop identity — using MAC-derived name");
        return instance_name(iface);
    }
    let id: String = b.iter().map(|x| format!("{x:02x}")).collect();
    // Best-effort persist. A failure only means the id is not stable *yet* -- we
    // still return this session's id and retry next start; the pre-existing
    // (unstable) behaviour, not a regression.
    if let Err(e) = std::fs::write(IDENTITY_PATH, &id) {
        log::warn!("could not persist AirDrop identity to {IDENTITY_PATH}: {e} — id not stable yet");
    }
    id
}

/// A 12-hex-character instance name derived from the interface MAC, matching the
/// shape Apple uses. **Fallback only** now -- see `stable_instance`, which is
/// what the Browser is built with. Kept because it is the last resort when the
/// persisted identity cannot be read or minted.
fn instance_name(iface: &str) -> String {
    if let Ok(mac) = std::fs::read_to_string(format!("/sys/class/net/{iface}/address")) {
        let hex: String = mac.trim().split(':').collect();
        if hex.len() == 12 && hex.chars().all(|c| c.is_ascii_hexdigit()) {
            return hex.to_lowercase();
        }
    }
    // No MAC to derive from: better a fixed placeholder than a random name that
    // changes every restart and litters peers' caches.
    "000000000000".to_string()
}

/// The interface's IPv6 link-local address, for the AAAA record.
pub(crate) fn link_local_of(iface: &str) -> Option<Ipv6Addr> {
    let data = std::fs::read_to_string("/proc/net/if_inet6").ok()?;
    for line in data.lines() {
        let mut f = line.split_whitespace();
        let addr = f.next()?;
        let name = line.split_whitespace().last()?;
        if name != iface || addr.len() != 32 || !addr.starts_with("fe80") {
            continue;
        }
        let mut o = [0u8; 16];
        for i in 0..16 {
            o[i] = u8::from_str_radix(&addr[i * 2..i * 2 + 2], 16).ok()?;
        }
        return Some(Ipv6Addr::from(o));
    }
    None
}

/// Bind UDP with SO_REUSEADDR|SO_REUSEPORT, which std does not expose.
fn bind_reuse(port: u16) -> io::Result<UdpSocket> {
    // SAFETY: plain socket(2) with constant arguments.
    let fd = unsafe { libc::socket(libc::AF_INET6, libc::SOCK_DGRAM, 0) };
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
    let mut a: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
    a.sin6_family = libc::AF_INET6 as u16;
    a.sin6_port = port.to_be();
    // SAFETY: a is a correctly-sized sockaddr_in6.
    let rc = unsafe {
        libc::bind(
            fd,
            &a as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        let e = io::Error::last_os_error();
        // SAFETY: fd is owned and closed once.
        unsafe { libc::close(fd) };
        return Err(e);
    }
    // SAFETY: fd is a valid owned socket being handed to UdpSocket.
    Ok(unsafe { <UdpSocket as std::os::fd::FromRawFd>::from_raw_fd(fd) })
}

pub(crate) fn ifindex_of(iface: &str) -> io::Result<u32> {
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

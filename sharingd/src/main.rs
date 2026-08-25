//! barqsharingd — the unprivileged half of Barq.
//!
//! Everything that reads bytes from another device lives here: mDNS, the
//! AirDrop protocol, and the transfer itself. It runs as `nobody` with **no
//! capabilities**, in its own SELinux domain, so a bug in a parser is not a bug
//! in a process that can reconfigure the network.
//!
//! The privileged half is `barqd`: it holds the AWDL session and does nothing
//! else. See ../docs/ARCHITECTURE.md for why they are separate, and note the
//! property that motivates it — barqd is ~500 lines that will barely change and
//! can be audited exhaustively, while this daemon will churn for months.
//!
//! There is deliberately no IPC to barqd. Once the link is up, `mosey0` is an
//! ordinary interface: this process opens sockets on it like any other. barqd's
//! only job is to keep holding the handle, because the session dies with its
//! holder.
//!
//! Skeleton: publishes IBarqService and answers, but implements no protocol yet.

mod dns;
mod framed;
mod send;
mod httpd;
mod mdns;
mod plist;

use binder::{BinderFeatures, Interface, Result as BinderResult, Status, StatusCode, Strong};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use dev_barq::aidl::dev::barq::{
    BarqPeer::BarqPeer,
    BarqStatus::BarqStatus,
    IBarqCallback::IBarqCallback,
    IBarqService::{BnBarqService, IBarqService},
};

const SERVICE_NAME: &str = "dev.barq.IBarqService/default";

/// The AWDL interface barqd brings up. Presence of a link-local address on it is
/// how this process knows the transport is alive, without talking to barqd.
const IFACE: &str = "mosey0";

/// Peers found by the discovery thread. Shared rather than owned by the service
/// so discovery keeps running whether or not a client is bound — a device must
/// stay discoverable with the app closed.
type PeerTable = Arc<Mutex<Vec<mdns::Peer>>>;

/// Whether this device is advertising itself. Shared with the discovery thread,
/// which owns the socket. Daemon state on purpose: closing the client must not
/// make the device vanish.
type Discoverable = Arc<AtomicBool>;
type Callbacks = Arc<Mutex<Vec<Strong<dyn IBarqCallback>>>>;
/// Names learned from /Discover, keyed by the peer's LINK-LOCAL ADDRESS.
///
/// Kept outside the peer table because the browser republishes that table twice a
/// second and would wipe anything written into it.
///
/// Keyed by address rather than mDNS instance because **Apple rotates its instance
/// name**. Keyed by instance, every rotation threw the name away: the peer briefly had
/// no name, the client filters unnamed peers, and the device vanished from the list and
/// came back a second later. Rotation also leaves the old and new instances both
/// present for a moment, which is how the same laptop appeared twice. The address
/// survives rotation, so both symptoms go with it.
type PeerNames = Arc<Mutex<std::collections::HashMap<String, String>>>;
/// Set when a client asks for peers, so discovery can query at once instead of waiting
/// for its own timer.
///
/// Someone looking at a device list expects it to be live. Polling getPeers while the
/// browser only queried every ten seconds and held peers for ninety meant the list
/// showed devices that had already gone -- and a send to one of those fails with
/// "connection refused", because nothing is listening at the cached address any more.
type QueryNow = Arc<AtomicBool>;
pub(crate) type Transfers = Arc<TransferState>;

/// The one transfer that can be in flight, and whether the user has cancelled it.
///
/// Deliberately single-slot: AirDrop sends one archive per exchange, and a peer that
/// opens a second while the first is running would be answered on its own connection
/// anyway. Modelling a queue we cannot yet receive would be inventing behaviour.
#[derive(Default)]
pub(crate) struct TransferState {
    /// Id of the transfer in flight, 0 when idle. Ids never repeat within a boot, so a
    /// cancel arriving late for a finished transfer cannot stop the next one.
    current: std::sync::atomic::AtomicI64,
    cancelled: std::sync::atomic::AtomicI64,
    next: std::sync::atomic::AtomicI64,
}

impl TransferState {
    pub(crate) fn begin(&self) -> i64 {
        let id = self.next.fetch_add(1, Ordering::SeqCst) + 1;
        self.current.store(id, Ordering::SeqCst);
        id
    }

    pub(crate) fn current(&self) -> i64 {
        self.current.load(Ordering::SeqCst)
    }

    pub(crate) fn finish(&self, id: i64) {
        let _ = self.current.compare_exchange(id, 0, Ordering::SeqCst, Ordering::SeqCst);
    }

    /// Cancel by id rather than "whatever is running": a stale tap from a client that
    /// was showing the previous transfer must not kill the current one.
    pub(crate) fn cancel(&self, id: i64) {
        self.cancelled.store(id, Ordering::SeqCst);
    }

    pub(crate) fn is_cancelled(&self, id: i64) -> bool {
        id != 0 && self.cancelled.load(Ordering::SeqCst) == id
    }
}

/// Read an Android system property.
/// A human name for this device, sent to the peer as SenderComputerName.
///
/// This is the one place a person actually reads our identity, so it prefers something
/// they set over something the vendor did.
fn device_name() -> String {
    read_property("persist.barq.name")
        .or_else(|| read_property("ro.product.model"))
        .unwrap_or_else(|| "Barq".to_string())
}

/// Take an owned File from a descriptor the client passed over binder.
///
/// The parcel's descriptor is closed when the transaction returns, so it has to be
/// duplicated: the send runs on another thread and would otherwise read from a closed
/// fd, which presents as a truncated file rather than an error.
fn dup_file(pfd: &binder::ParcelFileDescriptor) -> std::io::Result<std::fs::File> {
    use std::os::fd::{AsRawFd, FromRawFd};
    // SAFETY: dup(2) on a descriptor the parcel currently owns; the result is a fresh
    // descriptor this process owns and hands straight to File.
    let raw = unsafe { libc::dup(pfd.as_raw_fd()) };
    if raw < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: raw is a valid descriptor we just created and do not use elsewhere.
    Ok(unsafe { std::fs::File::from_raw_fd(raw) })
}

fn read_property(name: &str) -> Option<String> {
    let cname = std::ffi::CString::new(name).ok()?;
    let mut buf = [0u8; 128];
    // SAFETY: cname is NUL-terminated and buf exceeds PROP_VALUE_MAX.
    let n = unsafe {
        libc::__system_property_get(cname.as_ptr(), buf.as_mut_ptr() as *mut libc::c_char)
    };
    if n <= 0 {
        return None;
    }
    std::str::from_utf8(&buf[..n as usize]).ok().map(|s| s.to_string())
}

struct BarqService {
    // Callbacks are held weakly in spirit: a client that is not running is the
    // normal case, so nothing here may assume one exists.
    callbacks: Callbacks,
    transfers: Transfers,
    names: PeerNames,
    query_now: QueryNow,
    /// Bumped by every setDiscoverable call so an older auto-off timer knows it has
    /// been superseded and must not switch visibility off under a newer request.
    visibility_generation: Arc<std::sync::atomic::AtomicU64>,
    discoverable: Discoverable,
    peers: PeerTable,
}

impl BarqService {
    fn new(peers: PeerTable, discoverable: Discoverable) -> Self {
        Self {
            callbacks: Arc::new(Mutex::new(Vec::new())),
            transfers: Arc::new(TransferState::default()),
            names: Arc::new(Mutex::new(std::collections::HashMap::new())),
            query_now: Arc::new(AtomicBool::new(false)),
            visibility_generation: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            discoverable,
            peers,
        }
    }

    /// Is the AWDL link up? Asked of the kernel rather than of barqd, so this
    /// process needs no privilege and no IPC to answer it.
    fn link_up(&self) -> bool {
        std::fs::read_to_string(format!("/sys/class/net/{IFACE}/operstate"))
            .map(|s| !s.trim().is_empty())
            .unwrap_or(false)
    }
}

impl Interface for BarqService {}

impl BarqService {
    /// Turn a peer id from the client back into something we can connect to.
    ///
    /// A peer is only sendable once its SRV and AAAA records have both been seen: the
    /// port comes from one and the address from the other, and mDNS delivers them in
    /// whatever order it likes.
    fn resolve(&self, peer_id: &str) -> Option<send::Target> {
        let peers = self.peers.lock().ok()?;
        let peer = peers.iter().find(|p| p.short_id() == peer_id || p.instance == peer_id)?;
        Some(send::Target {
            addr: peer.addr?,
            port: if peer.port != 0 { peer.port } else { return None },
            scope: mdns::ifindex_of(IFACE).ok()?,
        })
    }
}

impl IBarqService for BarqService {
    fn getStatus(&self) -> BinderResult<BarqStatus> {
        Ok(BarqStatus {
            linkUp: self.link_up(),
            discoverable: self.discoverable.load(Ordering::SeqCst),
            channel: 0,
            country: String::new(),
            peerCount: self.peers.lock().map(|p| p.len() as i32).unwrap_or(0),
        })
    }

    fn setDiscoverable(&self, discoverable: bool, duration_seconds: i32) -> BinderResult<()> {
        // Every call supersedes any pending auto-off, so a user who reopens the app
        // does not get switched off by a timer started the previous time.
        let gen = self
            .visibility_generation
            .fetch_add(1, Ordering::SeqCst)
            + 1;
        if discoverable && duration_seconds > 0 {
            let flag = self.discoverable.clone();
            let generation = self.visibility_generation.clone();
            let secs = duration_seconds as u64;
            std::thread::spawn(move || {
                std::thread::sleep(Duration::from_secs(secs));
                if generation.load(Ordering::SeqCst) == gen {
                    flag.store(false, Ordering::SeqCst);
                    log::info!("visibility expired after {secs}s");
                }
            });
        }
        // Discoverability is DAEMON state on purpose: closing the client must not
        // stop the device being reachable, or we are back to an app that has to
        // stay resident.
        self.discoverable.store(discoverable, Ordering::SeqCst);
        log::info!("discoverable={discoverable} duration={duration_seconds}s");
        Ok(())
    }

    fn getPeers(&self) -> BinderResult<Vec<BarqPeer>> {
        // Someone is looking, so make discovery work rather than serving whatever the
        // last ten-second sweep happened to leave behind.
        self.query_now.store(true, Ordering::SeqCst);
        let peers = self.peers.lock().map_err(|_| Status::from(StatusCode::UNKNOWN_ERROR))?;
        let names = self.names.lock().map_err(|_| Status::from(StatusCode::UNKNOWN_ERROR))?;
        // One entry per DEVICE, not per mDNS instance.
        //
        // Apple rotates its instance name, and for a few seconds after a rotation both
        // the old and the new instance are live -- which is how the same laptop showed
        // up twice. Collapsing on the resolved name and keeping the most recently seen
        // instance gives one row per device, and the newest instance is the one whose
        // address and port are still good.
        let mut newest: std::collections::HashMap<String, &mdns::Peer> =
            std::collections::HashMap::new();
        for p in peers.iter() {
            let key = p
                .addr
                .and_then(|a| names.get(&a.to_string()).cloned())
                .unwrap_or_else(|| p.instance.clone());
            newest
                .entry(key)
                .and_modify(|kept| {
                    if p.last_seen > kept.last_seen {
                        *kept = p;
                    }
                })
                .or_insert(p);
        }

        Ok(newest
            .values()
            .map(|p| BarqPeer {
                id: p.instance.clone(),
                // Apple advertises a 12-hex-character identifier, never a name -- its
                // TXT record carries only `flags`. The real name comes from asking the
                // peer over /Discover, which happens in the background; until that
                // answers, the identifier is what we honestly have.
                name: p
                    .addr
                    .and_then(|a| names.get(&a.to_string()).cloned())
                    .unwrap_or_else(|| p.short_id().to_string()),
                model: String::new(),
                rssi: 0,
            })
            .collect())
    }

    fn sendFiles(
        &self,
        peer_id: &str,
        files: &[binder::ParcelFileDescriptor],
        names: &[String],
    ) -> BinderResult<i64> {
        if files.len() != names.len() {
            log::warn!("sendFiles: {} descriptors but {} names", files.len(), names.len());
            return Err(Status::new_exception(binder::ExceptionCode::ILLEGAL_ARGUMENT, None));
        }
        let target = match self.resolve(peer_id) {
            Some(t) => t,
            None => {
                log::warn!("sendFiles: peer {peer_id:?} is not known");
                return Err(Status::new_exception(binder::ExceptionCode::ILLEGAL_ARGUMENT, None));
            }
        };

        // Descriptors are duplicated out of the binder parcel now: they belong to this
        // transaction and would be closed under the worker thread otherwise.
        let mut items = Vec::with_capacity(files.len());
        for (fd, name) in files.iter().zip(names) {
            let file = match dup_file(fd) {
                Ok(f) => f,
                Err(e) => {
                    log::warn!("sendFiles: could not take {name:?}: {e}");
                    return Err(Status::new_exception(binder::ExceptionCode::ILLEGAL_ARGUMENT, None));
                }
            };
            let size = file.metadata().map(|m| m.len()).unwrap_or(0);
            items.push(send::Item {
                file,
                // A name from a client still has no business steering a path on the
                // peer's disk, so it is reduced to a leaf like a received one.
                name: httpd::safe_leaf(name).unwrap_or_else(|| "file".to_string()),
                size,
            });
        }

        let id = self.transfers.begin();
        let transfers = self.transfers.clone();
        let peers_for_send = self.peers.clone();
        let peer_instance = peer_id.to_string();
        let callbacks = self.callbacks.clone();
        let name = device_name();
        let model = read_property("ro.product.model").unwrap_or_else(|| "Android".into());

        // Sending happens off the binder thread: a transfer runs for as long as it runs,
        // and holding a binder worker for that would block every other call into us.
        std::thread::spawn(move || {
            let announce = |f: &dyn Fn(&Strong<dyn IBarqCallback>) -> binder::Result<()>| {
                if let Ok(cbs) = callbacks.lock() {
                    for cb in cbs.iter() {
                        let _ = f(cb);
                    }
                }
            };
            announce(&|cb| cb.onTransferOffered(id, "", &[], 0));

            let result = send::send(
                &target,
                items,
                &name,
                &model,
                |done, total| {
                    if let Ok(cbs) = callbacks.lock() {
                        for cb in cbs.iter() {
                            let _ = cb.onTransferProgress(id, done as i64, total as i64);
                        }
                    }
                },
                || transfers.is_cancelled(id),
            );
            match result {
                Ok(()) => {
                    log::info!("send {id} complete");
                    announce(&|cb| cb.onTransferFinished(id, 0));
                }
                Err(e) => {
                    log::warn!("send {id} failed: {e}");
                    // A refused or reset connection means that peer is no longer there.
                    // Forgetting it now is better than leaving the picker offering a
                    // device that cannot be reached until the expiry timer notices.
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::ConnectionRefused
                            | std::io::ErrorKind::ConnectionReset
                            | std::io::ErrorKind::TimedOut
                    ) {
                        if let Ok(mut table) = peers_for_send.lock() {
                            table.retain(|p| p.instance != peer_instance);
                        }
                        log::info!("forgot unreachable peer {peer_instance}");
                    }
                    announce(&|cb| cb.onTransferFinished(id, -1));
                }
            }
            transfers.finish(id);
        });
        Ok(id)
    }

    fn respondToOffer(&self, _transfer_id: i64, _accept: bool) -> BinderResult<()> {
        Err(Status::from(StatusCode::NAME_NOT_FOUND))
    }

    fn cancelTransfer(&self, transfer_id: i64) -> BinderResult<()> {
        log::info!("cancelTransfer({transfer_id})");
        self.transfers.cancel(transfer_id);
        Ok(())
    }

    fn getReceivedFiles(&self) -> BinderResult<Vec<String>> {
        let files = httpd::received_files();
        log::info!("getReceivedFiles -> {} file(s)", files.len());
        Ok(files)
    }

    fn openReceivedFile(&self, name: &str) -> BinderResult<binder::ParcelFileDescriptor> {
        // The name is resolved against the inbox by the daemon, and only a leaf is
        // accepted: a client must not be able to steer this into an arbitrary path.
        httpd::open_received(name)
            .map(binder::ParcelFileDescriptor::new)
            .map_err(|e| {
                log::warn!("openReceivedFile({name:?}) refused: {e}");
                Status::new_exception(binder::ExceptionCode::ILLEGAL_ARGUMENT, None)
            })
    }

    fn deleteReceivedFile(&self, name: &str) -> BinderResult<()> {
        httpd::delete_received(name).map_err(|e| {
            log::warn!("deleteReceivedFile({name:?}) refused: {e}");
            Status::new_exception(binder::ExceptionCode::ILLEGAL_ARGUMENT, None)
        })
    }

    fn registerCallback(&self, cb: &Strong<dyn IBarqCallback>) -> BinderResult<()> {
        self.callbacks.lock().unwrap().push(cb.clone());
        log::info!("client registered");
        Ok(())
    }

    fn unregisterCallback(&self, cb: &Strong<dyn IBarqCallback>) -> BinderResult<()> {
        let mut cbs = self.callbacks.lock().unwrap();
        cbs.retain(|c| c.as_binder() != cb.as_binder());
        log::info!("client unregistered");
        Ok(())
    }
}

/// Browse for AirDrop peers on the AWDL interface, forever.
///
/// Runs whether or not a client is bound, because discoverability is daemon
/// state. Waits for the link rather than failing at start: barqd may still be
/// bringing it up, and a restart loop over a missing interface helps nobody.
/// Ask a peer what it is called, once, in the background.
///
/// AirDrop carries no name in mDNS, so this is the only way to show a person something
/// they recognise instead of twelve hex characters. Failures are expected and quiet: a
/// peer that is not discoverable to us simply will not answer, which is not a fault.
fn probe_name(names: PeerNames, instance: String, target: send::Target) {
    let key = target.addr.to_string();
    std::thread::spawn(move || match send::discover(&target) {
        Ok(Some(name)) => {
            log::info!("peer {instance} at {key} is {name:?}");
            if let Ok(mut cache) = names.lock() {
                cache.insert(key, name);
            }
        }
        Ok(None) => log::debug!("peer {instance} did not give a name"),
        Err(e) => log::debug!("peer {instance} /Discover failed: {e}"),
    });
}

fn start_discovery(
    peers: PeerTable,
    names: PeerNames,
    discoverable: Discoverable,
    query_now: QueryNow,
) {
    std::thread::spawn(move || {
        let mut browser = loop {
            match mdns::Browser::new(IFACE) {
                Ok(b) => {
                    log::info!("browsing {} on {IFACE}", mdns::AIRDROP_SERVICE);
                    break b;
                }
                Err(e) => {
                    log::info!("waiting for {IFACE} ({e})");
                    std::thread::sleep(Duration::from_secs(5));
                }
            }
        };

        // Asked once per peer per boot. Without this the loop would re-probe every
        // peer on every pass, which is a TLS connection each time.
        let mut probed: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut since_query = Duration::from_secs(99);
        let mut since_announce = Duration::ZERO;
        let mut was_advertising = false;
        loop {
            // Advertising follows the flag, so a client turning discoverability
            // on or off takes effect without restarting anything.
            // Any peer that has become reachable but is still nameless gets asked
            // once. Collected under the lock and probed outside it, because a probe
            // opens a TLS connection and holding the table through that would stall
            // every getPeers call for the duration.
            let mut to_probe = Vec::new();
            if let Ok(mut table) = peers.lock() {
                for p in table.iter_mut() {
                    if p.port != 0 && !probed.contains(&p.instance) {
                        if let Some(addr) = p.addr {
                            probed.insert(p.instance.clone());
                            to_probe.push((p.instance.clone(), addr, p.port));
                        }
                    }
                }
            }
            for (instance, addr, port) in to_probe {
                if let Ok(scope) = mdns::ifindex_of(IFACE) {
                    probe_name(names.clone(), instance, send::Target { addr, port, scope });
                }
            }

            let want = discoverable.load(Ordering::SeqCst);
            if want && !was_advertising {
                match browser.advertise() {
                    Ok(()) => {
                        log::info!("advertising as {}.{}", browser.instance(), mdns::AIRDROP_SERVICE);
                        was_advertising = true;
                        since_announce = Duration::ZERO;
                    }
                    Err(e) => log::warn!("cannot advertise: {e}"),
                }
            } else if !want && was_advertising {
                browser.stop_advertising();
                log::info!("no longer advertising");
                was_advertising = false;
            }

            // Re-announce periodically: a peer that started browsing after us has
            // no reason to query again, so silence means invisibility.
            if was_advertising && since_announce >= Duration::from_secs(20) {
                let _ = browser.announce();
                since_announce = Duration::ZERO;
            }

            // Re-query periodically; peers answer, and new ones announce anyway.
            // Query on our own timer, or immediately when a client is looking.
            let asked = query_now.swap(false, Ordering::SeqCst);
            if asked || since_query >= Duration::from_secs(4) {
                if let Err(e) = browser.query() {
                    log::warn!("query failed: {e}");
                }
                since_query = Duration::ZERO;
            }
            browser.poll();
            // Long enough to ride out a rotation and a missed announcement, short
            // enough that a device which has gone away stops being offered. Ninety
            // seconds was far too generous and left the list advertising peers that
            // would refuse a connection; twenty-five was tight enough that an ordinary
            // gap between announcements looked like the device had left.
            browser.expire(Duration::from_secs(45));

            if let Ok(mut shared) = peers.lock() {
                *shared = browser.peers();
            }
            std::thread::sleep(Duration::from_millis(500));
            since_query += Duration::from_millis(500);
            since_announce += Duration::from_millis(500);
        }
    });
}

/// Bring up the AirDrop HTTPS listener on the port our SRV record advertises.
///
/// Without this a peer that browses, resolves and reaches us gets connection-refused
/// and shows nothing -- being listed requires a real answer to POST /Discover, not a
/// correct mDNS record. Barq advertised 8770 with nothing bound to it for a long time.
///
/// mosey0 may not exist or may have no address yet when we start, since barqd brings
/// the link up independently. Retry rather than give up: failing here permanently
/// would mean a daemon that is running, looks healthy, and can never be discovered.
fn start_airdrop_server(discoverable: Discoverable, callbacks: Callbacks, transfers: Transfers) {
    std::thread::spawn(move || {
        let name = read_property("persist.barq.name")
            .or_else(|| read_property("ro.product.model"))
            .unwrap_or_else(|| "Barq".to_string());
        let model = read_property("ro.product.model").unwrap_or_else(|| "Android".to_string());

        loop {
            match httpd::Httpd::new(
                IFACE,
                mdns::AIRDROP_PORT,
                &name,
                &model,
                discoverable.clone(),
                callbacks.clone(),
                transfers.clone(),
            ) {
                Ok(server) => {
                    log::info!("AirDrop server up as \"{name}\"");
                    server.serve();
                    // serve() only returns if the listener itself died.
                    log::warn!("AirDrop server stopped — rebinding");
                }
                Err(e) => log::debug!("AirDrop server not up yet: {e}"),
            }
            std::thread::sleep(Duration::from_secs(5));
        }
    });
}

fn main() {
    android_logger::init_once(
        android_logger::Config::default()
            .with_tag("barqsharingd")
            .with_max_level(log::LevelFilter::Debug),
    );
    log::info!("starting");

    let peers: PeerTable = Arc::new(Mutex::new(Vec::new()));

    // Off by default. A device that advertises itself the moment it boots is a
    // privacy decision, not a default, and it belongs to the user through the
    // client. persist.barq.discoverable exists so the transport can be tested
    // before a client exists to turn it on.
    // Default OFF. Being discoverable is the user's decision, made by opening the app;
    // a device that advertises itself from boot is a privacy choice nobody made. The
    // property remains only so the transport can be exercised without a client.
    let initial = read_property("persist.barq.discoverable")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    if initial {
        log::warn!("persist.barq.discoverable is set — advertising without a client asking");
    }
    let discoverable: Discoverable = Arc::new(AtomicBool::new(initial));

    let service = BarqService::new(peers.clone(), discoverable.clone());
    start_discovery(
        peers,
        service.names.clone(),
        discoverable.clone(),
        service.query_now.clone(),
    );
    // The HTTP server refuses transfers while invisible and announces finished ones,
    // so it needs both the flag and the callback list the service owns.
    start_airdrop_server(
        discoverable,
        service.callbacks.clone(),
        service.transfers.clone(),
    );
    let binder = BnBarqService::new_binder(service, BinderFeatures::default());

    if let Err(e) = binder::add_service(SERVICE_NAME, binder.as_binder()) {
        log::error!("could not publish {SERVICE_NAME}: {e:?}");
        std::process::exit(1);
    }
    log::info!("published {SERVICE_NAME}");

    // One thread is plenty for a skeleton; the transfer work will want more.
    binder::ProcessState::join_thread_pool();
}

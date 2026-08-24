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

/// Read an Android system property.
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
        let peers = self.peers.lock().map_err(|_| Status::from(StatusCode::UNKNOWN_ERROR))?;
        Ok(peers
            .iter()
            .map(|p| BarqPeer {
                id: p.instance.clone(),
                // Apple advertises a 12-hex-character identifier, not a name. A
                // friendly name needs the TXT record or a connection, so show the
                // identifier rather than inventing something.
                name: p.short_id().to_string(),
                model: String::new(),
                rssi: 0,
            })
            .collect())
    }

    fn sendFiles(
        &self,
        _peer_id: &str,
        _files: &[binder::ParcelFileDescriptor],
        _names: &[String],
    ) -> BinderResult<i64> {
        Err(Status::new_exception(
            binder::ExceptionCode::UNSUPPORTED_OPERATION,
            Some(&std::ffi::CString::new("no transfer protocol yet").unwrap()),
        ))
    }

    fn respondToOffer(&self, _transfer_id: i64, _accept: bool) -> BinderResult<()> {
        Err(Status::from(StatusCode::NAME_NOT_FOUND))
    }

    fn cancelTransfer(&self, _transfer_id: i64) -> BinderResult<()> {
        Err(Status::from(StatusCode::NAME_NOT_FOUND))
    }

    fn getReceivedFiles(&self) -> BinderResult<Vec<String>> {
        Ok(httpd::received_files())
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
fn start_discovery(peers: PeerTable, discoverable: Discoverable) {
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

        let mut since_query = Duration::from_secs(99);
        let mut since_announce = Duration::ZERO;
        let mut was_advertising = false;
        loop {
            // Advertising follows the flag, so a client turning discoverability
            // on or off takes effect without restarting anything.
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
            if since_query >= Duration::from_secs(10) {
                if let Err(e) = browser.query() {
                    log::warn!("query failed: {e}");
                }
                since_query = Duration::ZERO;
            }
            browser.poll();
            browser.expire(Duration::from_secs(90));

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
fn start_airdrop_server(discoverable: Discoverable, callbacks: Callbacks) {
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

    start_discovery(peers.clone(), discoverable.clone());

    let service = BarqService::new(peers, discoverable.clone());
    // The HTTP server refuses transfers while invisible and announces finished ones,
    // so it needs both the flag and the callback list the service owns.
    start_airdrop_server(discoverable, service.callbacks.clone());
    let binder = BnBarqService::new_binder(service, BinderFeatures::default());

    if let Err(e) = binder::add_service(SERVICE_NAME, binder.as_binder()) {
        log::error!("could not publish {SERVICE_NAME}: {e:?}");
        std::process::exit(1);
    }
    log::info!("published {SERVICE_NAME}");

    // One thread is plenty for a skeleton; the transfer work will want more.
    binder::ProcessState::join_thread_pool();
}

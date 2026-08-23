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
mod mdns;

use binder::{BinderFeatures, Interface, Result as BinderResult, Status, StatusCode, Strong};
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

struct BarqService {
    // Callbacks are held weakly in spirit: a client that is not running is the
    // normal case, so nothing here may assume one exists.
    callbacks: std::sync::Mutex<Vec<Strong<dyn IBarqCallback>>>,
    discoverable: std::sync::atomic::AtomicBool,
    peers: PeerTable,
}

impl BarqService {
    fn new(peers: PeerTable) -> Self {
        Self {
            callbacks: std::sync::Mutex::new(Vec::new()),
            discoverable: std::sync::atomic::AtomicBool::new(false),
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
            discoverable: self.discoverable.load(std::sync::atomic::Ordering::SeqCst),
            channel: 0,
            country: String::new(),
            peerCount: self.peers.lock().map(|p| p.len() as i32).unwrap_or(0),
        })
    }

    fn setDiscoverable(&self, discoverable: bool, duration_seconds: i32) -> BinderResult<()> {
        // Discoverability is DAEMON state on purpose: closing the client must not
        // stop the device being reachable, or we are back to an app that has to
        // stay resident.
        self.discoverable
            .store(discoverable, std::sync::atomic::Ordering::SeqCst);
        log::info!("discoverable={discoverable} for {duration_seconds}s (not yet advertised)");
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
fn start_discovery(peers: PeerTable) {
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
        loop {
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
        }
    });
}

fn main() {
    android_logger::init_once(
        android_logger::Config::default()
            .with_tag("barqsharingd")
            .with_max_level(log::LevelFilter::Info),
    );
    log::info!("starting");

    let peers: PeerTable = Arc::new(Mutex::new(Vec::new()));
    start_discovery(peers.clone());

    let service = BarqService::new(peers);
    let binder = BnBarqService::new_binder(service, BinderFeatures::default());

    if let Err(e) = binder::add_service(SERVICE_NAME, binder.as_binder()) {
        log::error!("could not publish {SERVICE_NAME}: {e:?}");
        std::process::exit(1);
    }
    log::info!("published {SERVICE_NAME}");

    // One thread is plenty for a skeleton; the transfer work will want more.
    binder::ProcessState::join_thread_pool();
}

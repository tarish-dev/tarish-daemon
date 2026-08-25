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

/// The property barqd watches to decide whether to hold the AWDL radio.
/// Its default when absent is ON, so a policy denial here degrades to the old
/// battery cost rather than to a device that cannot share at all.
const WANT_PROP: &str = "barq.awdl.wanted";

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

// Transfer outcomes reported through IBarqCallback.onTransferFinished.
//
// Declined is deliberately distinct from failed. Someone pressing Decline on the other
// device is a normal answer, not an error, and telling a user "could not send" when the
// truth is "they said no" is both wrong and unhelpful -- it invites them to retry
// something that will be refused again.
const STATUS_OK: i32 = 0;
const STATUS_FAILED: i32 = -1;
const STATUS_DECLINED: i32 = -2;

/// The one transfer that can be in flight, and whether the user has cancelled it.
///
/// Deliberately single-slot: AirDrop sends one archive per exchange, and a peer that
/// opens a second while the first is running would be answered on its own connection
/// anyway. Modelling a queue we cannot yet receive would be inventing behaviour.
#[derive(Default)]
pub(crate) struct TransferState {
    /// The answer to the offer currently on screen, once a person gives one.
    ///
    /// One slot, not a map: AirDrop offers one transfer at a time, and a second offer
    /// arriving while the first is on screen replaces it rather than queueing. Keyed by
    /// id anyway, so a late answer to a transfer that has already timed out is
    /// discarded instead of accepting the next one on that person's behalf.
    decision: Mutex<Option<(i64, bool)>>,
    decided: std::sync::Condvar,
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

    /// Record a person's answer to an offer and wake whoever is waiting for it.
    pub(crate) fn answer(&self, id: i64, accept: bool) {
        if let Ok(mut d) = self.decision.lock() {
            *d = Some((id, accept));
        }
        self.decided.notify_all();
    }

    /// Block until someone answers offer `id`, or the wait runs out.
    ///
    /// `None` means nobody answered, and the caller must treat that as a refusal.
    /// Defaulting the other way would make the timeout a way to get a file onto the
    /// device by waiting -- the exact thing the prompt exists to prevent.
    pub(crate) fn await_answer(&self, id: i64, timeout: Duration) -> Option<bool> {
        let deadline = std::time::Instant::now() + timeout;
        let mut guard = self.decision.lock().ok()?;
        loop {
            if let Some((answered, accept)) = *guard {
                *guard = None;
                if answered == id {
                    return Some(accept);
                }
                // An answer to some earlier offer. Drop it rather than let it stand in
                // for this one.
            }
            let left = deadline.checked_duration_since(std::time::Instant::now())?;
            guard = self.decided.wait_timeout(guard, left).ok()?.0;
        }
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

// Set an Android system property.
//
// Declared here rather than taken from the libc crate so the call does not depend
// on which bionic symbols that crate happens to re-export for this target.
extern "C" {
    fn __system_property_set(name: *const libc::c_char, value: *const libc::c_char) -> libc::c_int;
}

fn write_property(name: &str, value: &str) -> bool {
    let (Ok(n), Ok(v)) = (std::ffi::CString::new(name), std::ffi::CString::new(value)) else {
        return false;
    };
    // SAFETY: both strings are NUL-terminated and outlive the call.
    unsafe { __system_property_set(n.as_ptr(), v.as_ptr()) == 0 }
}

/// Tell barqd whether the AWDL radio is wanted.
///
/// WHY A THREAD AND NOT A WRITE AT EACH CALL SITE
///
/// The foreground flag flaps. Opening a file picker produced eight onPause/onResume
/// pairs in five seconds on a real device, and tearing the radio down and back up on
/// each of those would be both slower and less reliable than leaving it up -- every
/// cycle recreates mosey0 with a new index and makes every socket bound to it stale.
/// So the decision is made in one place, on a timer, with a hold-off.
///
/// The three inputs are OR-ed because each is independently sufficient:
///
///   active        a client is in the foreground and may send or receive at any moment
///   transfer      bytes are moving; releasing the link here would kill it outright
///   discoverable  we are advertising, and advertising without a link is a lie
///
/// Rising edges apply immediately -- that is the latency a person actually feels,
/// staring at an empty device list. Falling edges wait out LINGER.
fn start_radio_gate(active: Arc<AtomicBool>, transfers: Transfers, discoverable: Discoverable) {
    // How long the radio stays up after nothing wants it any more.
    //
    // Long enough to ride out a file picker, a rotation, or a glance at another app
    // and come back to a live list; short enough that putting the phone in a pocket
    // stops costing anything within a minute.
    const LINGER: Duration = Duration::from_secs(30);

    std::thread::spawn(move || {
        let mut applied: Option<bool> = None;
        let mut idle_since: Option<std::time::Instant> = None;
        // The linger is for coming DOWN from busy. At boot nothing has asked for the
        // radio yet, and treating that as a falling edge would hold it up for thirty
        // seconds on every reboot for no one.
        let mut ever_busy = false;
        let mut next_try: Option<std::time::Instant> = None;
        let mut warned = false;
        let mut failures: u32 = 0;

        loop {
            let busy = active.load(Ordering::SeqCst)
                || transfers.current() != 0
                || discoverable.load(Ordering::SeqCst);

            let want = if busy {
                ever_busy = true;
                idle_since = None;
                true
            } else if !ever_busy {
                false
            } else {
                let since = *idle_since.get_or_insert_with(std::time::Instant::now);
                since.elapsed() < LINGER
            };

            if applied != Some(want) && next_try.map_or(true, |t| std::time::Instant::now() >= t) {
                if write_property(WANT_PROP, if want { "1" } else { "0" }) {
                    log::info!("radio {} ({WANT_PROP}={})",
                               if want { "wanted" } else { "released" },
                               if want { 1 } else { 0 });
                    applied = Some(want);
                    next_try = None;
                    warned = false;
                    failures = 0;
                } else {
                    // Keep trying, but slowly.
                    //
                    // An earlier version recorded the write as applied even when it
                    // failed, so one failure meant the gate never tried again for that
                    // state. That is wrong for anything transient -- property service
                    // not yet up, a policy reload -- and the cost of being wrong is the
                    // radio stuck in whatever state it was last in.
                    //
                    // Retrying on every pass instead would put a denial in the audit log
                    // twice a second when the cause is a missing rule, which is the
                    // common case and is not transient at all. Ten seconds is quiet
                    // enough for that and quick enough that nobody notices the other.
                    if !warned {
                        log::warn!(
                            "could not set {WANT_PROP} — check set_prop(barqsharingd, \
                             barq_awdl_prop); barqd will keep the radio up"
                        );
                        warned = true;
                    }
                    // Back off towards a minute. A missing rule is permanent until the
                    // next flash, and every attempt writes an AVC denial into the audit
                    // log -- at a flat ten seconds that is thousands of identical lines
                    // a day, which is how a log stops being worth reading.
                    failures = failures.saturating_add(1);
                    let wait = std::cmp::min(10 * u64::from(failures), 60);
                    next_try = Some(std::time::Instant::now() + Duration::from_secs(wait));
                }
            }

            std::thread::sleep(Duration::from_millis(500));
        }
    });
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
    /// Whether a client is in the foreground. Governs the radio, not visibility.
    active: Arc<AtomicBool>,
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
            active: Arc::new(AtomicBool::new(false)),
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

        // Never resolve to ourselves.
        //
        // The third and last of three independent guards, and the one that matches the
        // symptom exactly: this device discovered itself, and SENDING is what turned
        // that into a prompt asking the person to accept a file from themselves. The
        // browser should never have offered it and the server would now refuse it, but
        // this is the step that actually dials, so it checks too.
        if let Some(a) = peer.addr {
            if mdns::link_local_of(IFACE) == Some(a) {
                log::warn!("refusing to send to our own address {a} — ignoring peer {peer_id}");
                return None;
            }
        }

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

    fn setActive(&self, active: bool) -> BinderResult<()> {
        // Idempotent and deliberately quiet: this is called on every onResume and
        // onPause, which on a real device means several times a second while a file
        // picker is opening. The gate thread decides what to do about it.
        self.active.store(active, Ordering::SeqCst);
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
                    announce(&|cb| cb.onTransferFinished(id, STATUS_OK));
                }
                Err(e) => {
                    log::warn!("send {id} failed: {e}");
                    // A refusal is not a fault, and a client should be able to say so.
                    // PermissionDenied is what send() returns when /Ask answers with a
                    // non-200: the person on the other device pressed Decline.
                    let status = if e.kind() == std::io::ErrorKind::PermissionDenied {
                        STATUS_DECLINED
                    } else {
                        STATUS_FAILED
                    };
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
                    announce(&|cb| cb.onTransferFinished(id, status));
                }
            }
            transfers.finish(id);
        });
        Ok(id)
    }

    fn respondToOffer(&self, transfer_id: i64, accept: bool) -> BinderResult<()> {
        log::info!("respondToOffer({transfer_id}, accept={accept})");
        self.transfers.answer(transfer_id, accept);
        Ok(())
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
        // Which instance of the interface we are bound to. The table id IS the index,
        // and barqd recreates mosey0 with a new one every time it re-acquires the
        // radio, so this is the identity that matters -- not the name.
        let mut bound_idx = mdns::ifindex_of(IFACE).unwrap_or(0);
        let mut waiting_logged = false;
        let mut failures = 0u32;
        let mut since_query = Duration::from_secs(99);
        let mut since_announce = Duration::ZERO;
        let mut was_advertising = false;
        loop {
            // barqd holds AWDL only while something wants it, so mosey0 genuinely
            // disappears and comes back with a new index. Two things follow.
            //
            // With no interface there is nothing to browse: polling a dead socket at
            // 2 Hz and logging a failed query every four seconds would cost more than
            // releasing the radio ever saved, and would bury the log. Go idle instead.
            //
            // With a DIFFERENT interface, rebind immediately rather than waiting for
            // three failed queries to infer it. The failure counter is still there as
            // a backstop for sockets that die without the index changing, but it is no
            // longer how the common case is detected -- it used to take up to twelve
            // seconds, which is most of the time a person is willing to stare at an
            // empty list.
            let now_idx = mdns::ifindex_of(IFACE).unwrap_or(0);
            if now_idx == 0 {
                if bound_idx != 0 {
                    log::info!("{IFACE} is gone — discovery idle until it returns");
                    bound_idx = 0;
                    was_advertising = false;
                    if let Ok(mut shared) = peers.lock() {
                        shared.clear();   // nothing here is reachable any more
                    }
                }
                std::thread::sleep(Duration::from_secs(2));
                continue;
            }
            if now_idx != bound_idx {
                match mdns::Browser::new(IFACE) {
                    Ok(b) => {
                        log::info!("{IFACE} is up as index {now_idx} — bound");
                        browser = b;
                        bound_idx = now_idx;
                        failures = 0;
                        was_advertising = false;      // re-assert on the new socket
                        since_query = Duration::from_secs(99);
                        waiting_logged = false;
                    }
                    Err(e) => {
                        // Usually just the address not being assigned yet, a moment
                        // after the index appears. Say it once, then wait quietly.
                        if !waiting_logged {
                            log::info!("waiting for an address on {IFACE} ({e})");
                            waiting_logged = true;
                        }
                        std::thread::sleep(Duration::from_millis(500));
                        continue;
                    }
                }
            }
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
                // The goodbye is the part that actually removes us from a peer's list.
                // If it does not go out we stay listed for the record TTL, so a failure
                // here is worth saying rather than swallowing.
                match browser.stop_advertising() {
                    Ok(()) => log::info!("no longer advertising (withdrawn)"),
                    Err(e) => log::warn!(
                        "no longer advertising, but the goodbye failed ({e}) — peers \
                         will keep listing this device until the TTL expires"
                    ),
                }
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
                match browser.query() {
                    Ok(()) => failures = 0,
                    Err(e) => {
                        failures += 1;
                        log::warn!("query failed: {e} ({failures} in a row)");
                    }
                }
                since_query = Duration::ZERO;
            }

            // Rebind when the interface goes out from under us.
            //
            // barqd recreates mosey0 with a NEW interface index whenever it restarts,
            // and a socket bound to the old one is dead for good: every send returns
            // ENETUNREACH and this loop would log that forever while discovery quietly
            // returned nothing. Nothing else notices, because the daemon is up, the
            // interface exists, and the address looks fine -- it is simply a different
            // interface than the one we are bound to.
            if failures >= 3 {
                log::warn!("mDNS socket is stale — rebinding to {IFACE}");
                match mdns::Browser::new(IFACE) {
                    Ok(b) => {
                        browser = b;
                        bound_idx = mdns::ifindex_of(IFACE).unwrap_or(0);
                        failures = 0;
                        was_advertising = false;   // re-assert on the new socket
                        since_query = Duration::from_secs(99);
                        log::info!("rebound to {IFACE}");
                    }
                    Err(e) => log::warn!("rebind failed ({e}) — will retry"),
                }
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
            // Two very different waits behind one failure.
            //
            // If mosey0 exists, barqd has just brought it up and the address is
            // moments away -- retrying slowly here is dead time a person spends
            // looking at a device that cannot yet receive. If it does not exist, the
            // radio is released and nothing is coming; polling fast would be a wakeup
            // source for as long as the phone is in a pocket.
            let coming_up = mdns::ifindex_of(IFACE).is_ok();
            std::thread::sleep(if coming_up {
                Duration::from_millis(500)
            } else {
                Duration::from_secs(5)
            });
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
        discoverable.clone(),
        service.callbacks.clone(),
        service.transfers.clone(),
    );
    start_radio_gate(
        service.active.clone(),
        service.transfers.clone(),
        discoverable,
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

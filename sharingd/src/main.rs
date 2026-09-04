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
mod quickshare;
mod httpd;
mod mdns;
mod plist;

use binder::{BinderFeatures, Interface, Result as BinderResult, Status, StatusCode, Strong};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use dev_barq::aidl::dev::barq::{
    BarqPeer::BarqPeer,
    BarqPolicy::BarqPolicy,
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

/// The Wi-Fi frequency, published for barqd so it can choose the opposite band.
const STA_FREQ_PROP: &str = "barq.awdl.sta_freq";

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
pub(crate) fn device_name() -> String {
    read_property("persist.barq.name")
        .or_else(|| read_property("ro.product.model"))
        .unwrap_or_else(|| "Barq".to_string())
}

/// Persist the advertised name, or clear it back to the device-model default.
///
/// A `persist.` property survives reboot, which is what makes the name stick without
/// this daemon keeping a file of its own. The app cannot write it -- setting a persist
/// property needs a policy grant an app should not have -- so it comes through binder,
/// and so THIS is the only place a name is checked. An administrator's name arrives the
/// same way, through setPolicy, and gets the same treatment.
///
/// A NAME THAT IS NOT A NAME FALLS BACK TO THE DEVICE MODEL. Empty, blank, "   ", "...",
/// "---", a string of zero-width characters: all of them clear the property instead of
/// being advertised. The test is whether anything alphanumeric survives cleaning -- a
/// device that appears to a room of strangers as "..." is worse than one that appears as
/// its model, and there is no legitimate name made entirely of punctuation.
///
/// Cleaning, in order:
///   1. control and formatting characters removed -- a newline in an mDNS TXT record or
///      an AirDrop plist is at best ignored and at worst a parse failure on the peer
///   2. runs of whitespace collapsed to one space, so "A     B" does not advertise as
///      a name with a hole in it
///   3. trimmed
///   4. truncated on a CHARACTER boundary -- PROP_VALUE_MAX is 92 bytes and cutting
///      mid-UTF-8 would advertise invalid bytes
fn set_device_name(name: &str) {
    let cleaned = clean_name(name);
    if cleaned.is_empty() {
        write_property("persist.barq.name", "");
        log::info!("device name cleared — falling back to {:?}", device_name());
        return;
    }
    if write_property("persist.barq.name", &cleaned) {
        log::info!("device name set to {cleaned:?}");
    } else {
        log::warn!("could not write persist.barq.name");
    }
}

/// Reduce a name to something safe to advertise, or to empty if nothing is left.
fn clean_name(name: &str) -> String {
    // Strip anything that is not printable text. `char::is_control` covers C0 and C1;
    // the explicit range is the zero-width and bidirectional formatting block, which is
    // invisible and is exactly what someone reaches for to make a name that looks empty
    // to a reader and is not empty to a parser.
    let stripped: String = name
        .chars()
        .filter(|c| !c.is_control() && !matches!(*c, '\u{200B}'..='\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2060}'..='\u{206F}' | '\u{FEFF}'))
        .collect();

    // Collapse whitespace runs, then trim.
    let mut out = String::with_capacity(stripped.len());
    let mut in_space = false;
    for c in stripped.chars() {
        if c.is_whitespace() {
            in_space = true;
        } else {
            if in_space && !out.is_empty() {
                out.push(' ');
            }
            in_space = false;
            out.push(c);
        }
    }
    let out = out.trim().to_string();

    // Nothing alphanumeric means it is not a name. "..." and "---" land here.
    if !out.chars().any(char::is_alphanumeric) {
        return String::new();
    }

    // PROP_VALUE_MAX is 92 bytes; leave room and cut on a character boundary.
    let mut cut: &str = &out;
    while cut.len() > 90 {
        cut = &cut[..cut
            .char_indices()
            .last()
            .map(|(i, _)| i)
            .unwrap_or(0)];
    }
    cut.trim().to_string()
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

            // Compare against what the property ACTUALLY says, not only against our own
            // last write. Tracking just our own writes means that if the value is
            // changed by anything else -- or if a write we believed succeeded did not
            // land -- the gate sits there convinced it is already correct and never
            // corrects it. The radio then stays in whatever state that left, which on
            // a bench looks exactly like the gate being broken.
            let live = read_property(WANT_PROP).map(|v| v.trim() != "0");
            let needs_write = live != Some(want) || applied != Some(want);

            if needs_write && next_try.map_or(true, |t| std::time::Instant::now() >= t) {
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
    refresh_now: QueryNow,
    /// Bumped by every setDiscoverable call so an older auto-off timer knows it has
    /// been superseded and must not switch visibility off under a newer request.
    visibility_generation: Arc<std::sync::atomic::AtomicU64>,
    discoverable: Discoverable,
    /// Whether a client is in the foreground. Governs the radio, not visibility.
    active: Arc<AtomicBool>,
    /// Last Wi-Fi frequency the client reported, so we only write on a change.
    sta_freq: Arc<std::sync::atomic::AtomicI32>,
    peers: PeerTable,
    /// Quick Share peers the app has seen over BLE, keyed by endpoint id.
    ///
    /// Separate from `peers`, which is the AirDrop mDNS table. Two protocols, two
    /// discovery mechanisms, two tables -- merged only at getPeers, where each row
    /// carries the protocol that found it.
    ble_peers: Arc<Mutex<std::collections::HashMap<String, BlePeer>>>,
    /// What this device is permitted to do. Starts DENIED -- see setPolicy in the AIDL.
    policy: Arc<Mutex<BarqPolicy>>,
    /// Mirrors policy.requireConfirmation for the accept loop, which runs on the httpd
    /// threads and must not take the policy lock on every offer.
    auto_accept: Arc<AtomicBool>,
}

/// A Quick Share peer seen over BLE.
struct BlePeer {
    name: Option<String>,
    /// How to reach it with no network. None when the peer advertised no address.
    mac: Option<String>,
    seen: std::time::Instant,
}

/// How long a BLE peer stays listed after its last advertisement.
///
/// Peers advertise several times a second, so this is generous. It exists because BLE
/// gives no "gone" event: a device that walks away simply stops, and without an expiry
/// it would sit in the list forever and the first send to it would fail with no
/// explanation.
const BLE_PEER_TTL: Duration = Duration::from_secs(20);

/// BLUETOOTH, from the ConnectionRequest medium enum.
fn frames_medium_bluetooth() -> u64 {
    barq_protocol::frames::Medium::Bluetooth as u64
}

/// A coarse MIME type from a file name, for the introduction's file metadata.
///
/// Advisory: it picks the icon the peer shows and nothing else, so a wrong guess costs a
/// wrong icon rather than a failed transfer.
fn mime_of(name: &str) -> String {
    let ext = name.rsplit('.').next().unwrap_or("").to_ascii_lowercase();
    match ext.as_str() {
        "jpg" | "jpeg" => "image/jpeg",
        "png" => "image/png",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "heic" => "image/heic",
        "mp4" => "video/mp4",
        "mov" => "video/quicktime",
        "mp3" => "audio/mpeg",
        "pdf" => "application/pdf",
        "txt" => "text/plain",
        "apk" => "application/vnd.android.package-archive",
        _ => "application/octet-stream",
    }
    .to_string()
}

/// Reports progress to clients while a Quick Share send runs.
struct TransferProgress {
    id: i64,
    transfers: Transfers,
    callbacks: Callbacks,
}

impl quickshare::outbound::Progress for TransferProgress {
    fn progress(&self, done: u64, total: u64) {
        let cbs = match self.callbacks.lock() {
            Ok(c) => c,
            Err(_) => return,
        };
        for cb in cbs.iter() {
            let _ = cb.onTransferProgress(self.id, done as i64, total as i64);
        }
    }

    fn cancelled(&self) -> bool {
        self.transfers.is_cancelled(self.id)
    }
}

/// Deny everything. A daemon that has never heard from the app shares nothing.
fn denied_policy() -> BarqPolicy {
    BarqPolicy {
        airdrop: MODE_OFF,
        quickshare: MODE_OFF,
        requireConfirmation: true,
        deviceName: String::new(),
        airdropManaged: false,
        quickshareManaged: false,
        requireConfirmationManaged: false,
        deviceNameManaged: false,
    }
}

// Mirrors the constants in IBarqService.aidl. Kept as plain consts because the Rust
// backend does not expose interface constants in a form that can be matched on.
const PROTOCOL_AIRDROP: i32 = 0;
const PROTOCOL_QUICKSHARE: i32 = 1;

const MODE_OFF: i32 = 0;
const MODE_RECEIVE: i32 = 1;
const MODE_SEND: i32 = 2;
const MODE_BOTH: i32 = 3;

fn allows_receive(mode: i32) -> bool {
    mode == MODE_RECEIVE || mode == MODE_BOTH
}

fn allows_send(mode: i32) -> bool {
    mode == MODE_SEND || mode == MODE_BOTH
}

impl BarqService {
    fn new(peers: PeerTable, discoverable: Discoverable) -> Self {
        Self {
            callbacks: Arc::new(Mutex::new(Vec::new())),
            transfers: Arc::new(TransferState::default()),
            names: Arc::new(Mutex::new(std::collections::HashMap::new())),
            query_now: Arc::new(AtomicBool::new(false)),
            refresh_now: Arc::new(AtomicBool::new(false)),
            visibility_generation: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            discoverable,
            active: Arc::new(AtomicBool::new(false)),
            sta_freq: Arc::new(std::sync::atomic::AtomicI32::new(-1)),
            peers,
            ble_peers: Arc::new(Mutex::new(std::collections::HashMap::new())),
            policy: Arc::new(Mutex::new(denied_policy())),
            auto_accept: Arc::new(AtomicBool::new(false)),
        }
    }

    /// The AirDrop mode currently enforced. Denied if the lock is poisoned: a policy
    /// we cannot read is not a policy we may act on.
    fn airdrop_mode(&self) -> i32 {
        self.policy.lock().map(|p| p.airdrop).unwrap_or(MODE_OFF)
    }

    #[allow(dead_code)]
    fn quickshare_mode(&self) -> i32 {
        self.policy.lock().map(|p| p.quickshare).unwrap_or(MODE_OFF)
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
        // Policy gate for the whole RECEIVE direction.
        //
        // Visibility is the entire consent model on the receiving side -- httpd refuses
        // /Discover, /Ask and HEAD / whenever `visible()` is false -- so refusing to
        // become visible is sufficient, and there is no second place to forget. Turning
        // visibility OFF is always allowed: policy restricts sharing, never the ability
        // to stop.
        if discoverable && !allows_receive(self.airdrop_mode()) {
            log::warn!("setDiscoverable refused — policy does not permit AirDrop receive");
            return Err(Status::from(StatusCode::PERMISSION_DENIED));
        }
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

    fn setActive(&self, active: bool, sta_frequency_mhz: i32) -> BinderResult<()> {
        // Publish the Wi-Fi frequency for barqd BEFORE flipping the active flag, so
        // the gate can never ask for the radio while the band is still unknown --
        // barqd would then pick 5 GHz and take the association down, which is the
        // exact bug this exists to prevent.
        let f = if (2000..=7200).contains(&sta_frequency_mhz) { sta_frequency_mhz } else { 0 };
        if self.sta_freq.swap(f, Ordering::SeqCst) != f {
            if write_property(STA_FREQ_PROP, &f.to_string()) {
                log::info!("Wi-Fi is on {f} MHz");
            } else {
                log::warn!("could not publish {STA_FREQ_PROP} — barqd will guess the band");
            }
        }

        // Idempotent and deliberately quiet: this is called on every onResume and
        // onPause, which on a real device means several times a second while a file
        // picker is opening. The gate thread decides what to do about it.
        self.active.store(active, Ordering::SeqCst);
        Ok(())
    }

    fn setPolicy(&self, policy: &BarqPolicy) -> BinderResult<()> {
        log::info!(
            "policy: airdrop={} quickshare={} confirm={} name={:?} (managed: a={} q={} c={} n={})",
            policy.airdrop,
            policy.quickshare,
            policy.requireConfirmation,
            policy.deviceName,
            policy.airdropManaged,
            policy.quickshareManaged,
            policy.requireConfirmationManaged,
            policy.deviceNameManaged,
        );
        self.auto_accept
            .store(!policy.requireConfirmation, Ordering::SeqCst);

        // A name that is no longer permitted must stop being advertised, so apply it
        // here rather than only in setDeviceName -- an admin pinning a name should take
        // effect on the next policy push without the app having to notice and call a
        // second method.
        if !policy.deviceName.is_empty() {
            set_device_name(&policy.deviceName);
        }

        // Withdraw immediately if receiving is no longer allowed. Without this a device
        // that was already discoverable stays on the air until its timer expires, which
        // is exactly the window an administrator just closed.
        if !allows_receive(policy.airdrop) && self.discoverable.load(Ordering::SeqCst) {
            log::info!("policy withdrew AirDrop receive — going invisible now");
            self.discoverable.store(false, Ordering::SeqCst);
        }

        match self.policy.lock() {
            Ok(mut p) => *p = policy.clone(),
            Err(_) => return Err(Status::from(StatusCode::UNKNOWN_ERROR)),
        }
        Ok(())
    }

    fn getPolicy(&self) -> BinderResult<BarqPolicy> {
        let p = self
            .policy
            .lock()
            .map_err(|_| Status::from(StatusCode::UNKNOWN_ERROR))?;
        // Deref first: `p.clone()` would resolve to cloning the GUARD, not the policy.
        Ok((*p).clone())
    }

    fn setDeviceName(&self, name: &str) -> BinderResult<()> {
        if let Ok(p) = self.policy.lock() {
            // An administrator pinned the name. Refuse rather than accept-and-revert:
            // silently ignoring a write makes the settings screen look broken.
            if p.deviceNameManaged {
                log::warn!("setDeviceName refused — the name is managed");
                return Err(Status::from(StatusCode::PERMISSION_DENIED));
            }
        }
        set_device_name(name);
        Ok(())
    }

    fn getDeviceName(&self) -> BinderResult<String> {
        Ok(device_name())
    }

    fn reportBlePeer(&self, address: &str, rssi: i32, service_data: &[u8]) -> BinderResult<()> {
        let Some(a) = barq_protocol::ble::parse_advertisement(service_data) else {
            return Ok(()); // not an advertisement we understand; nothing to report
        };
        // A peer with no address is discoverable and not reachable, which is worse than
        // absent: it puts a device in the list that cannot be sent to. Unverified
        // advertisements -- the fast form, which carries no service-id hash -- are kept
        // only when they do carry an address, so the list stays actionable.
        if a.bluetooth_mac.is_none() && !a.verified {
            return Ok(());
        }

        let mut peers = self
            .ble_peers
            .lock()
            .map_err(|_| Status::from(StatusCode::UNKNOWN_ERROR))?;
        let now = std::time::Instant::now();
        peers.retain(|_, p| now.duration_since(p.seen) < BLE_PEER_TTL);

        let fresh = !peers.contains_key(&a.endpoint_id);
        if fresh {
            log::info!(
                "quickshare: BLE peer {} {:?} rssi={rssi} ble={address} bt={}",
                a.endpoint_id,
                a.device_name.as_deref().unwrap_or("<no name in the clear>"),
                a.bluetooth_mac.as_deref().unwrap_or("<not reachable>")
            );
        }
        peers.insert(
            a.endpoint_id,
            BlePeer {
                name: a.device_name,
                mac: a.bluetooth_mac,
                seen: now,
            },
        );
        Ok(())
    }

    fn sendFilesOnSocket(
        &self,
        peer_id: &str,
        socket: &binder::ParcelFileDescriptor,
        files: &[binder::ParcelFileDescriptor],
        names: &[String],
    ) -> BinderResult<i64> {
        if !allows_send(self.quickshare_mode()) {
            log::warn!("sendFilesOnSocket refused — policy does not permit Quick Share send");
            return Err(Status::from(StatusCode::PERMISSION_DENIED));
        }
        if files.len() != names.len() {
            log::warn!("sendFilesOnSocket: {} descriptors but {} names", files.len(), names.len());
            return Err(Status::from(StatusCode::BAD_VALUE));
        }

        // Duplicate everything before returning: the parcel closes its descriptors when
        // this transaction ends, and the transfer runs on another thread. Reading from a
        // closed fd presents as a truncated file rather than an error, which is the worst
        // way for this to fail.
        let sock = dup_file(socket).map_err(|e| {
            log::warn!("sendFilesOnSocket: could not dup the socket: {e}");
            Status::from(StatusCode::BAD_VALUE)
        })?;
        let mut out_files = Vec::with_capacity(files.len());
        for (f, n) in files.iter().zip(names) {
            let file = dup_file(f).map_err(|e| {
                log::warn!("sendFilesOnSocket: could not dup {n}: {e}");
                Status::from(StatusCode::BAD_VALUE)
            })?;
            let size = file.metadata().map(|m| m.len() as i64).unwrap_or(0);
            out_files.push(quickshare::outbound::OutFile {
                name: n.clone(),
                mime: mime_of(n),
                size,
                reader: Box::new(file),
            });
        }

        let id = self.transfers.begin();
        let device = device_name();
        let endpoint = quickshare::random_endpoint_id();
        let endpoint = quickshare::instance_name(&endpoint)
            .split('.')
            .next()
            .unwrap_or("BARQ")
            .to_string();
        let peer = peer_id.to_string();
        let transfers = self.transfers.clone();
        let callbacks = self.callbacks.clone();

        std::thread::spawn(move || {
            // Two handles on the same socket. `send` wants a reader and a writer, and a
            // socket is both -- but it must be ONE socket, not two, or the peer's replies
            // arrive on a descriptor nobody is reading.
            let reader = match sock.try_clone() {
                Ok(r) => r,
                Err(e) => {
                    log::warn!("quickshare: could not clone the socket: {e}");
                    transfers.finish(id);
                    return;
                }
            };
            let progress = TransferProgress {
                id,
                transfers: transfers.clone(),
                callbacks,
            };
            log::info!("quickshare: sending {} file(s) to {peer}", out_files.len());
            match quickshare::outbound::send(
                reader,
                sock,
                &device,
                &endpoint,
                // The mediums we are WILLING TO UPGRADE TO, which is not the same as
                // the one we connected over.
                //
                // This listed BLUETOOTH alone, reasoning that claiming a medium we
                // cannot carry would fail later. That reading was wrong: the field
                // advertises upgrade candidates, so listing only Bluetooth tells a stock
                // peer there is no way to get the file off Bluetooth at all -- and
                // nothing sends a file over Bluetooth alone, because it would crawl.
                // Windows completed the handshake, took the introduction, and then said
                // it could not complete the transfer.
                //
                // WIFI_LAN is advertised even though the upgrade itself is not
                // implemented yet. That is a deliberate, temporary asymmetry: it tells us
                // whether the peer responds by OFFERING an upgrade path, which is the one
                // piece of information needed to know what to build next. If it does, the
                // negotiation frames are already written and tested -- only the radio
                // side is missing.
                &[
                    frames_medium_bluetooth(),
                    barq_protocol::frames::Medium::WifiLan as u64,
                ],
                out_files,
                &progress,
            ) {
                Ok(true) => log::info!("quickshare: transfer {id} complete"),
                Ok(false) => log::info!("quickshare: transfer {id} was not accepted"),
                Err(e) => log::warn!("quickshare: transfer {id} failed: {e}"),
            }
            transfers.finish(id);
        });

        Ok(id)
    }

    fn refreshPeers(&self) -> BinderResult<()> {
        // Clear the published snapshot here, and let the discovery loop clear what it
        // owns -- its own table, the resolved-name cache and the probe record. Doing
        // only this half would look like it worked for one poll and then repopulate
        // from the browser's stale table.
        if let Ok(mut p) = self.peers.lock() {
            p.clear();
        }
        if let Ok(mut n) = self.names.lock() {
            n.clear();
        }
        self.refresh_now.store(true, Ordering::SeqCst);
        self.query_now.store(true, Ordering::SeqCst);
        log::info!("refreshPeers: dropped the peer table, re-browsing");
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

        // Deterministic order, because a HashMap has none.
        //
        // Rust seeds its hasher randomly, so `values()` yields a DIFFERENT order on
        // every call. The app polls this, rebuilds its tiles when the list changes, and
        // compares an order-sensitive signature to decide whether it changed -- so an
        // unstable order made every poll look like a change. The tiles were torn down
        // and rebuilt several times a second: peers visibly juggled, and a tile could be
        // replaced between a finger going down and the tap landing, sending to a device
        // the user had not aimed at.
        //
        // Sorted by display name, with the instance as tiebreak. Name rather than
        // instance because Apple ROTATES its instance name, so ordering on it would
        // reshuffle the list every rotation -- the exact thing being fixed. A name does
        // change once, when /Discover answers and the hex identifier is replaced by a
        // real name, and that reorder is correct: the row genuinely became something
        // else.
        let mut out: Vec<&mdns::Peer> = newest.values().copied().collect();
        out.sort_by(|a, b| {
            let name_of = |p: &mdns::Peer| {
                p.addr
                    .and_then(|x| names.get(&x.to_string()).cloned())
                    .unwrap_or_else(|| p.short_id().to_string())
            };
            name_of(a)
                .cmp(&name_of(b))
                .then_with(|| a.instance.cmp(&b.instance))
        });

        // Quick Share peers, from BLE, appended to the AirDrop ones.
        //
        // Two protocols in one list is the whole reason BarqPeer carries `protocol`: a
        // person picking a device is picking a protocol, and an Apple peer found over
        // AWDL cannot be reached the way an Android one over BLE can.
        let mut quickshare: Vec<BarqPeer> = Vec::new();
        if let Ok(mut ble) = self.ble_peers.lock() {
            let now = std::time::Instant::now();
            // Expire here as well as on report: a peer that walks away stops advertising,
            // and nothing else would ever notice it had gone.
            ble.retain(|_, p| now.duration_since(p.seen) < BLE_PEER_TTL);
            for (id, p) in ble.iter() {
                quickshare.push(BarqPeer {
                    id: id.clone(),
                    // A contacts-only peer publishes no name in the clear, and we have no
                    // certificate to decrypt one. The endpoint id is what we honestly
                    // have -- the same choice the AirDrop path makes before /Discover
                    // answers.
                    name: p.name.clone().unwrap_or_else(|| id.clone()),
                    model: String::new(),
                    rssi: 0,
                    protocol: PROTOCOL_QUICKSHARE,
                    bluetoothMac: p.mac.clone().unwrap_or_default(),
                });
            }
        }
        // Sorted for the same reason the AirDrop list is: an unstable order makes the
        // app rebuild its tiles and a device move under a finger mid-tap.
        quickshare.sort_by(|a, b| a.name.cmp(&b.name).then_with(|| a.id.cmp(&b.id)));

        Ok(out
            .into_iter()
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
                // AirDrop peers are reached over AWDL by link-local address, never
                // over Bluetooth.
                bluetoothMac: String::new(),
                // Everything getPeers returns today came from the AirDrop browser.
                // Quick Share discovery runs on wlan0 and is not folded into this
                // table yet; when it is, this is the field that keeps the two apart.
                protocol: PROTOCOL_AIRDROP,
            })
            .chain(quickshare)
            .collect())
    }

    fn sendFiles(
        &self,
        peer_id: &str,
        files: &[binder::ParcelFileDescriptor],
        names: &[String],
    ) -> BinderResult<i64> {
        // Policy gate for the SEND direction. Checked here rather than in the app
        // because this is the method that moves bytes: an app that hides its send
        // button is bypassed by calling this directly.
        if !allows_send(self.airdrop_mode()) {
            log::warn!("sendFiles refused — policy does not permit AirDrop send");
            return Err(Status::from(StatusCode::PERMISSION_DENIED));
        }
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
            // NO onTransferOffered HERE.
            //
            // This used to raise it with empty arguments, back when the callback meant
            // "a transfer has begun" and the client used it to put a progress bar up.
            // Adding the consent prompt changed what it MEANS -- it is now "someone
            // wants to send you a file, accept or decline" -- and this call was left
            // behind, so starting a send told the SENDER'S OWN app that an offer had
            // arrived. Tapping a peer raised an Accept/Decline card on the phone doing
            // the sending, with no name and no filenames because the arguments here are
            // empty.
            //
            // The client needs nothing from us to start a send: sendFiles returns the
            // transfer id, and progress arrives through onTransferProgress below.
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
    refresh_now: QueryNow,
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

            // An explicit refresh drops everything we think we know first, so the
            // query that follows rebuilds rather than tops up.
            if refresh_now.swap(false, Ordering::SeqCst) {
                browser.forget_peers();
                probed.clear();
                if let Ok(mut shared) = peers.lock() {
                    shared.clear();
                }
                log::info!("refresh: peer table cleared, re-browsing from scratch");
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
fn start_airdrop_server(
    discoverable: Discoverable,
    callbacks: Callbacks,
    transfers: Transfers,
    auto_accept: Arc<AtomicBool>,
) {
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
                auto_accept.clone(),
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

/// Browse for Quick Share peers on the Wi-Fi LAN.
///
/// Its own thread and its own socket, separate from the AWDL discovery loop: a
/// different interface and a different protocol, and a fault in one must not take the
/// other with it. Retries rather than giving up -- wlan0 may have no address yet at
/// boot, and a daemon that is running and permanently blind is worse than one that
/// keeps trying.
fn start_quickshare_discovery() {
    std::thread::spawn(|| {
        const IFACE: &str = "wlan0";
        // Instances already reported, so a peer is announced when it appears rather than
        // every half second for as long as it stays.
        let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
        loop {
            let mut browser = match quickshare::discovery::QsBrowser::new(IFACE) {
                Ok(b) => {
                    log::info!("quickshare: browsing on {IFACE}");
                    b
                }
                Err(e) => {
                    log::debug!("quickshare: {IFACE} not ready ({e})");
                    std::thread::sleep(Duration::from_secs(10));
                    continue;
                }
            };
            let mut since_query = Duration::from_secs(99);
            loop {
                if since_query >= Duration::from_secs(10) {
                    if let Err(e) = browser.query() {
                        // Back off before rebinding. Breaking straight out span the
                        // outer loop at full speed and filled the log with the same
                        // line at the same millisecond, which hides whatever the real
                        // cause is behind thousands of copies of the symptom.
                        log::warn!("quickshare: query failed ({e}) — rebinding in 10s");
                        std::thread::sleep(Duration::from_secs(10));
                        break;
                    }
                    since_query = Duration::ZERO;
                }
                browser.poll();
                browser.expire(Duration::from_secs(60));

                // Report what we found. Until now the browser maintained a peer table
                // that nothing ever read, so a working discovery and a broken one looked
                // identical from outside -- silence either way.
                //
                // Logged once per instance rather than per poll: the peer table is
                // refreshed every 500ms and the interesting event is a peer appearing,
                // not it continuing to exist.
                for p in browser.peers() {
                    if seen.insert(p.instance.clone()) {
                        log::info!(
                            "quickshare: peer {} \"{}\" at {}:{} ({})",
                            p.endpoint_id,
                            p.name.as_deref().unwrap_or("<no name>"),
                            p.addr.map(|a| a.to_string()).unwrap_or_else(|| p.host.clone()),
                            p.port,
                            p.instance,
                        );
                    }
                }

                std::thread::sleep(Duration::from_millis(500));
                since_query += Duration::from_millis(500);
            }
        }
    });
}

fn main() {
    android_logger::init_once(
        android_logger::Config::default()
            .with_tag("barqsharingd")
            .with_max_level(log::LevelFilter::Debug),
    );
    // Build marker. The AIDL surface has grown twice without the device appearing to
    // gain the new transactions, so the running code has to be identifiable from the log
    // rather than inferred from a file hash.
    log::info!("starting (aidl: policy+devicename, 17 transactions)");

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
        service.refresh_now.clone(),
    );
    // The HTTP server refuses transfers while invisible and announces finished ones,
    // so it needs both the flag and the callback list the service owns.
    start_airdrop_server(
        discoverable.clone(),
        service.callbacks.clone(),
        service.transfers.clone(),
        service.auto_accept.clone(),
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
    // Quick Share identity, logged once. Discovery is not wired yet; this proves the
    // derivation on real hardware rather than only in reasoning.
    log::info!("quickshare: {}", quickshare::describe_identity(&device_name()));
    start_quickshare_discovery();

    // One thread is plenty for a skeleton; the transfer work will want more.
    binder::ProcessState::join_thread_pool();
}

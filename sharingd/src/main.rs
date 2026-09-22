//! tarishsharingd — the unprivileged half of Tarish.
//!
//! Everything that reads bytes from another device lives here: mDNS, the
//! AirDrop protocol, and the transfer itself. It runs as `nobody` with **no
//! capabilities**, in its own SELinux domain, so a bug in a parser is not a bug
//! in a process that can reconfigure the network.
//!
//! The privileged half is `tarishd`: it holds the AWDL session and does nothing
//! else. See ../docs/ARCHITECTURE.md for why they are separate, and note the
//! property that motivates it — tarishd is ~500 lines that will barely change and
//! can be audited exhaustively, while this daemon will churn for months.
//!
//! There is deliberately no IPC to tarishd. Once the link is up, `mosey0` is an
//! ordinary interface: this process opens sockets on it like any other. tarishd's
//! only job is to keep holding the handle, because the session dies with its
//! holder.
//!
//! Skeleton: publishes ITarishService and answers, but implements no protocol yet.

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
use dev_tarish::aidl::dev::tarish::{
    TarishPeer::TarishPeer,
    TarishGroup::TarishGroup,
    TarishPolicy::TarishPolicy,
    TarishUpgrade::TarishUpgrade,
    TarishStatus::TarishStatus,
    ITarishCallback::ITarishCallback,
    ITarishService::{BnTarishService, ITarishService},
};

const SERVICE_NAME: &str = "dev.tarish.ITarishService/default";

/// This build's version, shown in the app's About screen (getDaemonVersion). The daemon is
/// Soong-built, not cargo, so it is a plain constant rather than CARGO_PKG_VERSION.
const TARISH_VERSION: &str = "0.3.0";

/// The AWDL stack (tlink) version, read from the shim's optional `mosey_version` symbol.
///
/// The shim is loaded by tarishd, not this process, so we dlopen it here purely to read the
/// string (RTLD_LAZY, nothing is started -- mosey_start_5 is never called). Resolved once
/// and cached. "unknown" when the loaded library does not export the symbol: an older pin,
/// or Google's own libmosey.
fn link_version() -> String {
    use std::ffi::{c_char, c_int, c_void, CStr, CString};
    use std::sync::OnceLock;
    static CACHE: OnceLock<String> = OnceLock::new();
    CACHE
        .get_or_init(|| {
            const RTLD_LAZY: c_int = 1;
            extern "C" {
                fn dlopen(filename: *const c_char, flag: c_int) -> *mut c_void;
                fn dlsym(handle: *mut c_void, symbol: *const c_char) -> *mut c_void;
            }
            let candidates = [
                "libmosey_daemon_ffi.so\0",
                "/system_ext/lib64/libmosey_daemon_ffi.so\0",
                "/vendor/lib64/libmosey_daemon_ffi.so\0",
            ];
            let sym = CString::new("mosey_version").unwrap();
            for path in candidates {
                // SAFETY: NUL-terminated literals; we only READ the static string the symbol
                // returns and never call any transport function.
                unsafe {
                    let h = dlopen(path.as_ptr() as *const c_char, RTLD_LAZY);
                    if h.is_null() {
                        continue;
                    }
                    let p = dlsym(h, sym.as_ptr());
                    if p.is_null() {
                        continue;
                    }
                    let f: unsafe extern "C" fn() -> *const c_char = std::mem::transmute(p);
                    let vp = f();
                    if !vp.is_null() {
                        if let Ok(s) = CStr::from_ptr(vp).to_str() {
                            return s.to_string();
                        }
                    }
                }
            }
            "unknown".to_string()
        })
        .clone()
}

/// The AWDL data interface. Configurable so the daemon runs over Google's `libmosey`
/// (`mosey0`) or over `tarish-link` (`tlink0`): `$TARISH_IFACE`, then
/// `persist.tarish.iface`, else the default. Resolved once.
///
/// Default is `tlink0` -- our tlink shim's interface. It MUST match the shim's own default
/// (tlink-shim `data_iface()` also defaults to `tlink0`), or on a clean device with
/// the property unset the shim brings up `tlink0` while this waits for a different name
/// forever. It was `mosey0` back when we ran over Google's libmosey; tlink replaced it.
fn iface() -> &'static str {
    use std::sync::OnceLock;
    static IFACE: OnceLock<String> = OnceLock::new();
    IFACE
        .get_or_init(|| {
            std::env::var("TARISH_IFACE")
                .ok()
                .or_else(|| read_property("persist.tarish.iface"))
                .unwrap_or_else(|| "tlink0".to_string())
        })
        .as_str()
}

/// The property tarishd watches to decide whether to hold the AWDL radio.
/// Its default when absent is ON, so a policy denial here degrades to the old
/// battery cost rather than to a device that cannot share at all.
const WANT_PROP: &str = "tarish.awdl.wanted";

/// The Wi-Fi frequency, published for tarishd so it can choose the opposite band.
const STA_FREQ_PROP: &str = "tarish.awdl.sta_freq";

/// Peers found by the discovery thread. Shared rather than owned by the service
/// so discovery keeps running whether or not a client is bound — a device must
/// stay discoverable with the app closed.
type PeerTable = Arc<Mutex<Vec<mdns::Peer>>>;

/// Whether this device is advertising itself. Shared with the discovery thread,
/// which owns the socket. Daemon state on purpose: closing the client must not
/// make the device vanish.
type Discoverable = Arc<AtomicBool>;
/// Quick Share peers found by mDNS on wlan0, with the address and port they published.
///
/// **This is a ROUTE, not just a listing.** Wi-Fi LAN is a bootstrap medium in this
/// protocol, not something a transfer upgrades to -- Bada's own registry says so: "Wi-Fi
/// LAN is the discovery medium today, so there is nothing to upgrade to", and its route
/// order is LAN before RFCOMM before L2CAP. A peer on our subnet is reached by connecting
/// to what it advertised, and everything else is for peers that are not.
///
/// The browser maintained this table and only logged it, so the daemon learned the peer
/// was at 192.168.0.99:56189 and then sent the file over Bluetooth at 200 KB/s.
type QsLanPeers = Arc<Mutex<Vec<quickshare::discovery::QsPeer>>>;
type Callbacks = Arc<Mutex<Vec<Strong<dyn ITarishCallback>>>>;
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

// Transfer outcomes reported through ITarishCallback.onTransferFinished.
//
// Declined is deliberately distinct from failed. Someone pressing Decline on the other
// device is a normal answer, not an error, and telling a user "could not send" when the
// truth is "they said no" is both wrong and unhelpful -- it invites them to retry
// something that will be refused again.
const STATUS_OK: i32 = 0;
const STATUS_FAILED: i32 = -1;
const STATUS_DECLINED: i32 = -2;
const STATUS_CANCELLED: i32 = -3; // must match TarishApp MainActivity.STATUS_CANCELLED

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
    /// The real confirmation PIN for the transfer being set up, and the transfer it
    /// belongs to. Never leaves this process.
    pin: Mutex<Option<(i64, String)>>,
    /// Set to a transfer id once someone typed its PIN correctly.
    pin_ok: Mutex<Option<i64>>,
    pin_confirmed: std::sync::Condvar,
    /// The socket a client has provided for a bandwidth upgrade, and which transfer
    /// asked for it.
    ///
    /// `Some((id, None))` is an explicit decline, which is a real answer and different
    /// from nobody having replied yet -- it lets the waiter stop immediately instead of
    /// sitting out a thirty-second timeout for a client that has already said no.
    upgrade_socket: Mutex<Option<(i64, Option<std::fs::File>)>>,
    upgrade_answered: std::sync::Condvar,
    /// The Wi-Fi Direct group a client has stood up for an inbound transfer.
    ///
    /// `Some((id, None))` is an explicit decline, distinct from nobody having answered yet:
    /// it lets the waiter stop at once rather than sitting out the whole timeout.
    group: Mutex<Option<(i64, Option<TarishGroup>)>>,
    /// The transfer a group request is outstanding for, or 0.
    ///
    /// AN ANSWER NOBODY ASKED FOR IS NOT AN ANSWER. Two app components can both respond to
    /// onGroupNeeded, and the second arrives after the upgrade has already happened. Stored
    /// unconditionally it sits in `group` as a stale answer, and the next await_group takes
    /// it instantly -- so the receiver stands up a SECOND listener on a new port and waits
    /// for a sender that joined the first one and is already streaming:
    ///
    ///     upgraded the inbound transfer to Wi-Fi Direct
    ///     hosting ... on 192.168.49.1:38617 for the sender   <- second listener
    ///     the sender never joined; staying put
    ///     inbound transfer failed: Connection reset by peer
    ///
    /// while the sender had sent the whole file in 0.3s over the first one.
    group_wanted: std::sync::atomic::AtomicI64,
    group_answered: std::sync::Condvar,
    /// Whether the transfer in flight actually rides the AWDL link.
    ///
    /// AirDrop does; Quick Share never does -- it runs over Bluetooth, Wi-Fi LAN or
    /// Wi-Fi Direct and has no use for mosey0. The radio gate needs to tell them
    /// apart, because on a BCM4383 device AWDL cannot coexist with Wi-Fi:
    /// bringing it up for a Quick Share transfer drops wlan0 and kills the
    /// very transfer that asked for it.
    needs_awdl: AtomicBool,
    /// Set while a client is standing up or using a Wi-Fi Direct group, so the radio gate
    /// takes AWDL DOWN for the duration.
    ///
    /// The chip runs ONE Wi-Fi peer-to-peer interface at a time: AWDL (`WL_IF_TYPE_ART`,
    /// from `wonder.ko`) OR a Wi-Fi Direct group, not both. So an off-network Quick Share
    /// transfer -- which needs a `P2P_GO`/`P2P_CLIENT` -- cannot form while AWDL holds the
    /// slot, and `WifiP2pManager.createGroup()/connect()` fails with `can't support new
    /// iface = WL_IF_TYPE_P2P_GO`. Releasing AWDL (`WANT_PROP=0` -> tarishd `mosey_stop`,
    /// which downs `wondertap0`+`wonder0` and frees the slot) is the only way to let the
    /// group form. This is stronger than `needs_awdl`: a Quick Share transfer never *needs*
    /// AWDL, but a foregrounded app keeps `active` true, which would otherwise hold AWDL up
    /// through the whole transfer. This overrides that, and applies immediately (no linger).
    /// Restored when the guard drops. AirDrop is unaffected -- it never uses Wi-Fi Direct.
    wifi_direct_active: AtomicBool,
    /// The id of an AirDrop transfer that is active OR pending-accept (0 = none), tracked
    /// SEPARATELY from `current` because the two protocols can race.
    ///
    /// THE RADIO SERVES ONE AT A TIME, AND AIRDROP HAS PRIORITY. `current` models a single
    /// transfer, so when a Quick Share receive calls `begin(false)` it OVERWRITES the id of an
    /// AirDrop offer that is still on screen waiting to be accepted -- and, before this,
    /// `arm_wifi_direct` then tore AWDL down under that pending offer, killing it. Both
    /// transfers failed. This field survives that overwrite (Quick Share's `begin` does not
    /// touch it), so the gate can keep AWDL up for a pending AirDrop and `arm_wifi_direct` can
    /// yield to it instead of stomping it. Set at AirDrop `/Ask` (`begin(true)`), cleared by
    /// the same transfer's `finish`. See docs/COEXISTENCE.md.
    airdrop_pending: std::sync::atomic::AtomicI64,
    /// When the current transfer last showed activity (claimed, or reported progress).
    ///
    /// The transfer slot is exclusive -- one transfer at a time across BOTH protocols -- so a
    /// transfer that ends without calling `finish` (a hung peer, a half-closed socket, a
    /// crash between `try_begin` and the transfer loop) would otherwise leave the slot claimed
    /// and block ALL sharing forever. This timestamp lets `try_begin` reclaim a slot that has
    /// shown no activity for `STALE_TRANSFER`, so a dead transfer self-heals. `None` when idle.
    last_activity: Mutex<Option<std::time::Instant>>,
}

/// A claimed transfer slot with no activity for this long is presumed dead and may be
/// reclaimed, so a hung or improperly-closed transfer cannot block sharing indefinitely.
/// Comfortably longer than the accept-prompt window (a pending offer shows no progress until
/// bytes flow), and a live transfer touches this on every progress report, so only a genuinely
/// stalled one is ever reclaimed.
const STALE_TRANSFER: Duration = Duration::from_secs(180);

impl TransferState {
    /// Claim the single transfer slot, EXCLUSIVELY. Returns the new transfer id, or `None` if
    /// a transfer is already in progress (either protocol) -- the caller must then refuse the
    /// request as busy rather than starting a second one.
    ///
    /// ONE TRANSFER AT A TIME, ACROSS BOTH PROTOCOLS. AirDrop and Quick Share share the device
    /// (the radio, the file store, the prompt), so a new request/accept checks here first and
    /// is turned away if anything is running. The one exception is a slot whose transfer has
    /// gone **stale** -- no activity for `STALE_TRANSFER`, i.e. it hung or closed improperly
    /// without calling `finish` -- which is reclaimed so a dead transfer cannot wedge sharing.
    pub(crate) fn try_begin(&self, needs_awdl: bool) -> Option<i64> {
        let cur = self.current.load(Ordering::SeqCst);
        if cur != 0 {
            if !self.is_stale() {
                return None; // busy with a live transfer
            }
            log::warn!(
                "transfer {cur} shows no activity for {}s — reclaiming the slot (presumed dead)",
                STALE_TRANSFER.as_secs()
            );
            self.finish(cur);
        }
        let id = self.next.fetch_add(1, Ordering::SeqCst) + 1;
        // Claim only if still free; another request may have taken it since the load above.
        if self
            .current
            .compare_exchange(0, id, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return None; // lost the race — someone else is now transferring
        }
        self.needs_awdl.store(needs_awdl, Ordering::SeqCst);
        // An AirDrop transfer also marks airdrop_pending so the radio gate keeps AWDL up for
        // it (and it reads as busy to the Quick Share side). Cleared by this transfer's finish.
        if needs_awdl {
            self.airdrop_pending.store(id, Ordering::SeqCst);
        }
        self.touch();
        Some(id)
    }

    /// Mark the current transfer as active now. Called on claim and on every progress report,
    /// so a live transfer is never seen as stale by [`try_begin`].
    pub(crate) fn touch(&self) {
        if let Ok(mut t) = self.last_activity.lock() {
            *t = Some(std::time::Instant::now());
        }
    }

    /// True if the claimed transfer has shown no activity for `STALE_TRANSFER` — hung, or
    /// closed without a `finish`. A `None` timestamp (idle) is not stale.
    fn is_stale(&self) -> bool {
        self.last_activity
            .lock()
            .ok()
            .and_then(|t| *t)
            .map(|t| t.elapsed() > STALE_TRANSFER)
            .unwrap_or(false)
    }

    /// True while a transfer that genuinely needs the AWDL link is in flight.
    pub(crate) fn current_needs_awdl(&self) -> bool {
        self.current.load(Ordering::SeqCst) != 0 && self.needs_awdl.load(Ordering::SeqCst)
    }

    /// True while an AirDrop transfer is active or waiting to be accepted. AirDrop owns the
    /// radio while this holds: the gate keeps AWDL up, and a Quick Share Wi-Fi Direct request
    /// yields to it (see `arm_wifi_direct`) rather than tearing AWDL down under it.
    pub(crate) fn airdrop_busy(&self) -> bool {
        self.airdrop_pending.load(Ordering::SeqCst) != 0
    }

    /// True while a Wi-Fi Direct transfer is holding AWDL down. The radio gate reads this
    /// and forces `WANT_PROP=0`, overriding foreground activity, so the chip's single P2P
    /// slot is free for the group.
    pub(crate) fn wifi_direct_active(&self) -> bool {
        self.wifi_direct_active.load(Ordering::SeqCst)
    }

    /// Take AWDL down for a Wi-Fi Direct transfer and block until the slot is actually free,
    /// so the client's `createGroup()`/`connect()` cannot race an ART interface that is still
    /// registered. Idempotent -- calling it again while already armed only re-confirms.
    ///
    /// The hold stays until [`finish`](Self::finish) clears it at transfer end (the single
    /// universal teardown point); the hold has to outlive this call because the group must
    /// stay up for the whole transfer, and restoring AWDL would tear the group down.
    ///
    /// The wait is two stages: first the radio gate must WRITE `WANT_PROP=0` (it polls every
    /// 500 ms), then tarishd must ACT on it -- `mosey_stop`, which downs `wondertap0`+
    /// `wonder0` so the driver `del_iface`s the ART monitor and frees the slot. We confirm
    /// the write by reading the property back, then allow a fixed settle for the teardown.
    /// Best-effort: if AWDL was never up (Quick Share with AirDrop off), the property is
    /// already "0" and this returns almost at once.
    /// Returns `true` if the radio was acquired for Wi-Fi Direct, `false` if AirDrop owns it
    /// and would not yield in time -- in which case the caller must NOT form a group (present
    /// the peer as busy) rather than tearing AWDL down under a live AirDrop transfer.
    pub(crate) fn arm_wifi_direct(&self) -> bool {
        if self.wifi_direct_active.load(Ordering::SeqCst) {
            // Already armed for this transfer (both join and a later re-ask can call in).
            return true;
        }
        // AIRDROP HAS PRIORITY FOR THE RADIO. If an AirDrop transfer is active or an offer is
        // on screen waiting to be accepted, do not take the radio out from under it. Wait a
        // little in case it finishes promptly; if it does not, refuse -- Quick Share then
        // presents the device as busy rather than killing both transfers (the exact failure
        // this arbitration exists to prevent). Symmetric guard: while we hold the radio, the
        // AirDrop `/Ask` path refuses new offers as busy.
        if self.airdrop_busy() {
            let give_up = std::time::Instant::now() + Duration::from_secs(15);
            while self.airdrop_busy() {
                if std::time::Instant::now() >= give_up {
                    log::info!(
                        "quickshare: AirDrop owns the radio; not taking it for Wi-Fi Direct \
                         (presenting busy)"
                    );
                    return false;
                }
                std::thread::sleep(Duration::from_millis(200));
            }
        }
        if self.wifi_direct_active.swap(true, Ordering::SeqCst) {
            // Someone armed it while we waited out AirDrop.
            return true;
        }
        // Re-check: an AirDrop offer that arrived in the instant between the wait and the swap
        // has priority, so yield the radio straight back to it.
        if self.airdrop_busy() {
            self.wifi_direct_active.store(false, Ordering::SeqCst);
            log::info!("quickshare: AirDrop claimed the radio first; yielding (presenting busy)");
            return false;
        }
        log::info!("quickshare: taking AWDL down for a Wi-Fi Direct transfer (freeing the P2P slot)");
        // Stage 1: wait for the gate to write WANT_PROP=0 (<=~500 ms once it runs).
        let deadline = std::time::Instant::now() + Duration::from_secs(3);
        while std::time::Instant::now() < deadline {
            if read_property(WANT_PROP).map(|v| v.trim() == "0").unwrap_or(true) {
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        // Stage 2: let tarishd poll and tear the ART interface down. tarishd polls every
        // 500 ms and mosey_stop's teardown is a couple of netlink round-trips; a second is
        // comfortably enough and is only paid on the off-network path (vs a 150 KB/s
        // Bluetooth fallback, which is what this avoids).
        std::thread::sleep(Duration::from_millis(1000));
        true
    }

    pub(crate) fn current(&self) -> i64 {
        self.current.load(Ordering::SeqCst)
    }

    pub(crate) fn finish(&self, id: i64) {
        let _ = self.current.compare_exchange(id, 0, Ordering::SeqCst, Ordering::SeqCst);
        // If this was the AirDrop transfer holding the radio, release the priority claim so a
        // waiting Quick Share can now take it. compare_exchange so a still-live AirDrop
        // transfer's claim is never cleared by some other transfer finishing.
        let _ = self
            .airdrop_pending
            .compare_exchange(id, 0, Ordering::SeqCst, Ordering::SeqCst);
        // A client that answered an upgrade request after we stopped waiting left a
        // descriptor parked in that slot. Nothing will ever read it, and it would sit open
        // until the next upgrade replaced it, so drop it with the transfer that asked.
        self.clear_upgrade(id);
        // Release any AWDL hold this transfer took for a Wi-Fi Direct group (see
        // `arm_wifi_direct`). This is the single universal transfer-end point, so AWDL comes
        // back however the transfer ended -- completed, cancelled, or failed. A no-op for a
        // transfer that never went off-network. The radio gate restores AWDL on its next
        // pass if activity/policy still want it.
        if self.wifi_direct_active.swap(false, Ordering::SeqCst) {
            log::info!("quickshare: released the AWDL hold for Wi-Fi Direct — radio may return");
        }
        // Clear the activity clock so the now-free slot is not seen as a stale claim.
        if let Ok(mut t) = self.last_activity.lock() {
            *t = None;
        }
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
    /// Park the real PIN for a transfer so `confirm_pin` can check against it.
    ///
    /// It lives here and nowhere else: not in the app, not in a callback argument, not
    /// in a log at info level. A sender that can see its own copy can confirm a transfer
    /// without looking at the other device, which is the whole thing the PIN prevents.
    pub(crate) fn set_pin(&self, id: i64, pin: &str) {
        if let Ok(mut p) = self.pin.lock() {
            *p = Some((id, pin.to_string()));
        }
    }

    /// Check what the user typed. True once, on a match.
    ///
    /// A mismatch is NOT fatal and does not clear anything: mistyping four digits is the
    /// ordinary case, and tearing the connection down would make the person start the
    /// whole transfer again.
    pub(crate) fn confirm_pin(&self, id: i64, typed: &str) -> bool {
        let matched = match self.pin.lock() {
            Ok(p) => match p.as_ref() {
                Some((parked, real)) => *parked == id && real == typed,
                None => false,
            },
            Err(_) => false,
        };
        if matched {
            if let Ok(mut c) = self.pin_ok.lock() {
                *c = Some(id);
            }
            self.pin_confirmed.notify_all();
        }
        matched
    }

    /// Block until the right digits arrive, the transfer is cancelled, or we give up.
    pub(crate) fn await_pin(&self, id: i64, timeout: Duration) -> bool {
        let deadline = std::time::Instant::now() + timeout;
        let mut guard = match self.pin_ok.lock() {
            Ok(g) => g,
            Err(_) => return false,
        };
        loop {
            if *guard == Some(id) {
                *guard = None;
                return true;
            }
            if self.is_cancelled(id) {
                return false;
            }
            let left = match deadline.checked_duration_since(std::time::Instant::now()) {
                Some(l) => l,
                None => return false,
            };
            // Woken periodically rather than only on notify, so a cancel while nobody is
            // typing is noticed instead of sitting here for the full timeout.
            guard = match self.pin_confirmed.wait_timeout(guard, left.min(Duration::from_millis(500))) {
                Ok(g) => g.0,
                Err(_) => return false,
            };
        }
    }

    /// Forget the parked PIN. Called when a transfer ends, however it ended.
    pub(crate) fn clear_pin(&self, id: i64) {
        if let Ok(mut p) = self.pin.lock() {
            if p.as_ref().map(|(parked, _)| *parked == id).unwrap_or(false) {
                *p = None;
            }
        }
        if let Ok(mut c) = self.pin_ok.lock() {
            if *c == Some(id) {
                *c = None;
            }
        }
    }

    /// A client's answer to onGroupNeeded. `None` declines.
    pub(crate) fn provide_group(&self, id: i64, group: Option<TarishGroup>) {
        // Only while a request is outstanding -- see the note on `group_wanted`.
        if self.group_wanted.load(Ordering::SeqCst) != id {
            log::debug!("quickshare: ignoring a group answer for {id}; nothing is waiting");
            return;
        }
        if let Ok(mut g) = self.group.lock() {
            *g = Some((id, group));
        }
        self.group_answered.notify_all();
    }

    /// Open a group request for `id`, so an answer will be accepted.
    pub(crate) fn want_group(&self, id: i64) {
        self.group_wanted.store(id, Ordering::SeqCst);
    }

    /// Close it, whatever the outcome.
    pub(crate) fn stop_wanting_group(&self) {
        self.group_wanted.store(0, Ordering::SeqCst);
    }

    /// Block until a client answers the group request for `id`, or we give up.
    pub(crate) fn await_group(&self, id: i64, timeout: Duration) -> Option<TarishGroup> {
        let deadline = std::time::Instant::now() + timeout;
        let mut guard = self.group.lock().ok()?;
        loop {
            if guard.as_ref().map(|(who, _)| *who == id).unwrap_or(false) {
                return guard.take().and_then(|(_, g)| g);
            }
            if self.is_cancelled(id) {
                return None;
            }
            let left = deadline.checked_duration_since(std::time::Instant::now())?;
            guard = self
                .group_answered
                .wait_timeout(guard, left.min(Duration::from_millis(500)))
                .ok()?
                .0;
        }
    }

    /// A client's answer to onUpgradeNeeded. `None` declines.
    pub(crate) fn provide_upgrade(&self, id: i64, sock: Option<std::fs::File>) {
        if let Ok(mut u) = self.upgrade_socket.lock() {
            *u = Some((id, sock));
        }
        self.upgrade_answered.notify_all();
    }

    /// Block until a client answers the upgrade request for `id`, or we give up.
    ///
    /// `None` covers every way of not getting a socket -- declined, cancelled, nobody
    /// bound, or the wait ran out -- because the caller does the same thing with all of
    /// them: carry on over the transport it already has.
    pub(crate) fn await_upgrade(&self, id: i64, timeout: Duration) -> Option<std::fs::File> {
        let deadline = std::time::Instant::now() + timeout;
        let mut guard = self.upgrade_socket.lock().ok()?;
        loop {
            // Take only an answer addressed to THIS transfer. A late reply for a previous
            // one is dropped here, which closes the fd it carried -- the right outcome for
            // a socket nothing is going to read.
            if guard.as_ref().map(|(who, _)| *who == id).unwrap_or(false) {
                return guard.take().and_then(|(_, sock)| sock);
            }
            if self.is_cancelled(id) {
                return None;
            }
            let left = deadline.checked_duration_since(std::time::Instant::now())?;
            guard = self
                .upgrade_answered
                .wait_timeout(guard, left.min(Duration::from_millis(500)))
                .ok()?
                .0;
        }
    }

    /// Drop any parked upgrade answer for `id`. Called when a transfer ends.
    pub(crate) fn clear_upgrade(&self, id: i64) {
        if let Ok(mut u) = self.upgrade_socket.lock() {
            if u.as_ref().map(|(who, _)| *who == id).unwrap_or(false) {
                *u = None;
            }
        }
    }

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
    read_property("persist.tarish.name")
        .or_else(|| read_property("ro.product.model"))
        .unwrap_or_else(|| "Tarish".to_string())
}

/// The model string sent to a peer as `ReceiverModelName` / `SenderModelName`.
///
/// **This is an identity claim, and peers act on it.** Apple's own share sheet picks an
/// icon from it, and it is the clearest signal we give that we are not an Apple device —
/// we say `Pixel 10 Pro` where an Apple peer says `iPhone` or `MacBookPro18,3`.
///
/// The override exists because whether that signal gates anything is an open question:
/// recent iOS shows a confirmation code before an AirDrop to a non-contact, but only ever
/// between two Apple devices, and nobody knows whether the gate is the model, the AWDL
/// version, or the absence of an Apple-signed identity. Being able to change this without
/// a rebuild is what makes that testable.
///
/// **The default is the truth, and it should stay that way.** A recipient reads this when
/// deciding whether to accept a transfer, so shipping a value that claims to be hardware
/// we are not is misrepresenting the device to someone making a trust decision. Use the
/// override for diagnosis, not for release.
pub(crate) fn device_model() -> String {
    read_property("persist.tarish.model")
        .or_else(|| read_property("ro.product.model"))
        .unwrap_or_else(|| "Android".to_string())
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
        write_property("persist.tarish.name", "");
        log::info!("device name cleared — falling back to {:?}", device_name());
        return;
    }
    if write_property("persist.tarish.name", &cleaned) {
        log::info!("device name set to {cleaned:?}");
    } else {
        log::warn!("could not write persist.tarish.name");
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

/// "XX:XX:XX:XX:XX:XX" to six bytes. None for anything else.
fn parse_mac(s: &str) -> Option<[u8; 6]> {
    let mut out = [0u8; 6];
    let mut n = 0;
    for part in s.split(':') {
        if n == 6 || part.len() != 2 {
            return None;
        }
        out[n] = u8::from_str_radix(part, 16).ok()?;
        n += 1;
    }
    (n == 6).then_some(out)
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

/// Tell tarishd whether the AWDL radio is wanted.
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
///   transfer      AirDrop bytes are moving; releasing the link would kill it outright
///   discoverable  we are advertising, and advertising without a link is a lie
///
/// Rising edges apply immediately -- that is the latency a person actually feels,
/// staring at an empty device list. Falling edges wait out LINGER.
///
/// ALL OF IT IS THEN AND-ED WITH THE AIRDROP POLICY, and that is not an optimisation.
/// AWDL serves AirDrop and nothing else: Quick Share runs over Bluetooth, Wi-Fi LAN or
/// Wi-Fi Direct and never touches mosey0. On a BCM4383 device the two cannot coexist
/// -- bringing AWDL up drops the Wi-Fi association -- so a device
/// with AirDrop switched off that lost its Wi-Fi the moment the app opened was losing it
/// for a link nothing was going to use. Worse, it took Quick Share's own Wi-Fi LAN
/// upgrade path down with it.
///
/// A policy withdrawal applies IMMEDIATELY rather than lingering. The linger exists to
/// ride out a flapping foreground flag; being told AirDrop is not permitted is not a
/// falling edge in activity, it is a prohibition.
fn start_radio_gate(
    active: Arc<AtomicBool>,
    transfers: Transfers,
    discoverable: Discoverable,
    policy: Arc<Mutex<TarishPolicy>>,
) {
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
        let mut permitted_last: Option<bool> = None;

        loop {
            // MODE_OFF on failure to read, matching airdrop_mode(): a poisoned lock must
            // not be the reason a radio comes up.
            let permitted = policy
                .lock()
                .map(|p| p.airdrop != MODE_OFF)
                .unwrap_or(false);
            if permitted_last != Some(permitted) {
                // Logged on change, because a radio that never comes up is otherwise
                // indistinguishable from a broken gate -- and this is now the most
                // likely reason for it.
                if permitted {
                    log::info!("AWDL permitted — AirDrop is enabled in policy");
                } else {
                    log::info!(
                        "AWDL not permitted — AirDrop is off in policy; the radio stays                          down and Wi-Fi is left alone"
                    );
                }
                permitted_last = Some(permitted);
            }

            let busy = active.load(Ordering::SeqCst)
                || transfers.current_needs_awdl()
                || transfers.airdrop_busy()
                || discoverable.load(Ordering::SeqCst);

            let want_by_activity = if busy {
                ever_busy = true;
                idle_since = None;
                true
            } else if !ever_busy {
                false
            } else {
                let since = *idle_since.get_or_insert_with(std::time::Instant::now);
                since.elapsed() < LINGER
            };
            // A Wi-Fi Direct transfer needs the chip's single P2P slot, which AWDL holds.
            // This overrides everything else -- including a foregrounded app keeping
            // `active` true -- and applies immediately, no linger: while a group is up, AWDL
            // MUST be down or the group cannot form. Restored the moment the hold drops.
            let yielded = transfers.wifi_direct_active();
            let want = permitted && want_by_activity && !yielded;

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
                            "could not set {WANT_PROP} — check set_prop(tarishsharingd, \
                             tarish_awdl_prop); tarishd will keep the radio up"
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

struct TarishService {
    // Callbacks are held weakly in spirit: a client that is not running is the
    // normal case, so nothing here may assume one exists.
    callbacks: Callbacks,
    transfers: Transfers,
    names: PeerNames,
    query_now: QueryNow,
    refresh_now: QueryNow,
    /// Set by resetIdentity(); the browser loop consumes it to withdraw the old
    /// AirDrop identity, mint a fresh one, and re-advertise. Same signalling shape
    /// as refresh_now -- a binder thread sets it, the loop swaps it.
    reset_identity: QueryNow,
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
    /// Quick Share peers reachable over the LAN, published by the mDNS browser.
    qs_lan: QsLanPeers,
    /// Who we say we are when receiving. Shared with the mDNS responder so both wires
    /// advertise the same endpoint id -- see QsIdentity.
    qs_ident: Arc<quickshare::discovery::QsIdentity>,
    /// What this device is permitted to do. Starts DENIED -- see setPolicy in the AIDL.
    policy: Arc<Mutex<TarishPolicy>>,
    /// Mirrors policy.requireConfirmation for the accept loop, which runs on the httpd
    /// threads and must not take the policy lock on every offer.
    auto_accept: Arc<AtomicBool>,
    /// Whether a sender must type the PIN before anything leaves this device.
    ///
    /// Held here rather than read from the policy at send time because the send runs on
    /// its own thread and the policy can change under it; this is the value that was in
    /// force when the transfer started.
    require_pin: Arc<AtomicBool>,
}

/// A Quick Share peer seen over BLE.
struct BlePeer {
    name: Option<String>,
    /// How to reach it with no network. None when the peer advertised no address.
    mac: Option<String>,
    /// The LE address the advertisement came from. An L2CAP channel is opened to this,
    /// not to `mac` -- and it rotates, so it is only as fresh as `seen`.
    ble_address: String,
    /// The peer's L2CAP PSM, 0 when it published none. Decides RFCOMM vs L2CAP.
    psm: u16,
    seen: std::time::Instant,
}

/// How long a BLE peer stays listed after its last advertisement.
///
/// Peers advertise several times a second, so this is generous. It exists because BLE
/// gives no "gone" event: a device that walks away simply stops, and without an expiry
/// it would sit in the list forever and the first send to it would fail with no
/// explanation.
const BLE_PEER_TTL: Duration = Duration::from_secs(20);

/// What we tell a peer we could upgrade to, when the socket arrived over Bluetooth.
///
/// **This field decides whether a stock Android receiver answers us at all**, and it has
/// now been wrong in two different directions against a real phone:
///
/// - BLUETOOTH alone: RFCOMM accepted, DISC 209 ms later, not one frame in between.
/// - BLUETOOTH + WIFI_LAN: the connection stays open and the peer never speaks.
///
/// The set below is the one Bada sends on a Bluetooth transport, and it is neither of
/// those: `supportedMediumsForCurrentTransport` filters WIFI_LAN out unless the current
/// transport IS Wi-Fi LAN, and leaves WIFI_DIRECT in. WIFI_DIRECT is the medium a stock
/// receiver actually upgrades to when there is no shared network, which is exactly the
/// case we are in. We decline the offer it then makes, and Bada's own failure policy for
/// an RFCOMM bootstrap is to stay on Bluetooth -- so claiming it costs a declined
/// negotiation, not a broken transfer.
///
/// `persist.tarish.qs_mediums` overrides it with a comma-separated list of raw enum values
/// (2 BLUETOOTH, 4 BLE, 5 WIFI_LAN, 6 WIFI_AWARE, 8 WIFI_DIRECT). That exists because
/// this is being settled against one real phone one attempt at a time, and a rebuild per
/// guess costs minutes and a reboot. It is read per transfer, so a `setprop` takes effect
/// on the next send.
fn quickshare_mediums() -> Vec<u64> {
    use tarish_protocol::frames::Medium;
    // BLUETOOTH *and* WIFI_LAN. Measured against a stock Pixel, one send per row:
    //
    //   [BLUETOOTH]                 RFCOMM accepted, closed 209 ms later
    //   [BLUETOOTH, WIFI_DIRECT]    closed 94 ms later
    //   [WIFI_LAN]                  closed ~100 ms later
    //   [BLUETOOTH, WIFI_LAN]       held open  <- only combination that gets past the gate
    //
    // So it is not "the mediums we could upgrade to" in any sense we can reason about
    // from the schema; the receiver wants both entries present and refuses the request
    // in under a fifth of a second otherwise. Do not simplify this to either one alone.
    //
    // WIFI_DIRECT IS NOT IN THE DEFAULT, and it may need to be. The upgrade request now
    // asks for Wi-Fi Direct, but a peer intersects that against what the CONNECTION
    // REQUEST claimed, so it may never offer a group while 8 is absent here. The row
    // above says [BLUETOOTH, WIFI_DIRECT] was refused in 94 ms -- but that was without
    // WIFI_LAN, and the pattern in this table is that the receiver wants the full set
    // rather than any one entry. Try `setprop persist.tarish.qs_mediums 2,5,8` before
    // concluding that Wi-Fi Direct does not work; it costs a send, not a rebuild.
    let default = vec![Medium::Bluetooth as u64, Medium::WifiLan as u64];
    let Some(raw) = read_property("persist.tarish.qs_mediums") else {
        return default;
    };
    if raw.trim().is_empty() {
        return default;
    }
    let parsed: Vec<u64> = raw
        .split(',')
        .filter_map(|f| f.trim().parse::<u64>().ok())
        .collect();
    if parsed.is_empty() {
        log::warn!("persist.tarish.qs_mediums={raw:?} parsed to nothing; using the default");
        return default;
    }
    log::info!("quickshare: advertising mediums {parsed:?} from persist.tarish.qs_mediums");
    parsed
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
    /// Snapshotted when the transfer began. See `TarishService::require_pin`.
    require_pin: bool,
}

impl TransferProgress {
    /// Tell the client the transfer ended, and how.
    ///
    /// **Not optional, and its absence is invisible from here.** Without it the daemon
    /// finishes the send, logs "transfer N complete", clears its slot -- and the app is
    /// still showing a full progress bar with a Cancel button, because nothing ever told
    /// it otherwise. The AirDrop path has announced this since it was written; the Quick
    /// Share send path was built alongside it and never did.
    fn finished(&self, status: i32) {
        let cbs = match self.callbacks.lock() {
            Ok(c) => c,
            Err(_) => return,
        };
        for cb in cbs.iter() {
            let _ = cb.onTransferFinished(self.id, status);
        }
    }
}

impl quickshare::outbound::Progress for TransferProgress {
    fn progress(&self, done: u64, total: u64) {
        // Keep the transfer slot alive: a transfer that is moving bytes is not stale, however
        // long it runs (see TransferState::try_begin / STALE_TRANSFER).
        self.transfers.touch();
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

    fn confirm_pin(&self, _pin: &str) -> bool {
        // PIN VERIFICATION INTENTIONALLY DISABLED — see docs/PIN-DISABLED.md.
        //
        // A typed PIN only ever applied to Quick Share, never to AirDrop, and it cannot work
        // against a stock Quick Share peer at all (there is no field to type it into), so it
        // made the two protocols inconsistent for no security we could point at: AirDrop is
        // safe with a plain accept prompt, and Quick Share should be too. Disabled until a
        // real purpose for it appears. The ask/park/await machinery below is kept, commented,
        // so it can be revived without reconstructing it.
        let _ = &self.require_pin; // field retained; see docs/PIN-DISABLED.md
        true
        // -- disabled --
        // if !self.require_pin {
        //     log::debug!("quickshare: PIN confirmation is off; sending without it");
        //     return true;
        // }
        // self.transfers.set_pin(self.id, pin);
        // {
        //     let cbs = match self.callbacks.lock() {
        //         Ok(c) => c,
        //         Err(_) => return false,
        //     };
        //     for cb in cbs.iter() {
        //         let _ = cb.onTransferPinRequired(self.id);
        //     }
        // }
        // let ok = self.transfers.await_pin(self.id, Duration::from_secs(120));
        // self.transfers.clear_pin(self.id);
        // ok
    }

    fn join_wifi(
        &self,
        req: &quickshare::outbound::WifiJoin,
    ) -> Option<std::net::TcpStream> {
        // Ask whoever is bound. No client means no radio, so there is nothing to wait for
        // -- return at once rather than parking the transfer for thirty seconds to
        // discover that. A transfer running with no client bound is ordinary: the send was
        // started from a share sheet and the person has since closed the app.
        let upgrade = TarishUpgrade {
            medium: req.medium as i32,
            ssid: req.ssid.to_string(),
            passphrase: req.passphrase.to_string(),
            gateway: req.gateway.to_string(),
            port: req.port as i32,
            frequency: req.frequency,
        };
        {
            let cbs = self.callbacks.lock().ok()?;
            if cbs.is_empty() {
                log::info!("quickshare: no client bound to join a network; staying put");
                return None;
            }
            // Joining a Wi-Fi Direct group is a P2P_CLIENT operation, which needs the chip's
            // single Wi-Fi P2P slot that AWDL holds. Take AWDL down and wait for the slot to
            // free BEFORE the client calls connect(), or the join fails against a live ART
            // interface. Held until finish() at transfer end. Wi-Fi LAN joins do not reach
            // here -- the peer is reached directly by its mDNS address, no group.
            // If AirDrop owns the radio and will not yield, do not join -- return None (we stay
            // on the current medium / the send does not upgrade) rather than stomping AirDrop.
            if req.medium == tarish_protocol::upgrade::Medium::WifiDirect
                && !self.transfers.arm_wifi_direct()
            {
                log::info!("quickshare: not joining a Wi-Fi Direct group -- AirDrop owns the radio");
                return None;
            }
            for cb in cbs.iter() {
                let _ = cb.onUpgradeNeeded(self.id, &upgrade);
            }
        }
        // Thirty seconds because forming or joining a Wi-Fi Direct group takes 4-8s on
        // the hardware measured, and first-time driver init is slower. Long enough not to
        // be the reason a working join is abandoned; short enough that a client which
        // never answers costs a slow transfer rather than a stalled one.
        let answered = self.transfers.await_upgrade(self.id, Duration::from_secs(30));
        self.transfers.clear_upgrade(self.id);
        let file = answered?;
        // The client promised a connected TCP socket. Converting rather than wrapping
        // gives us the socket options -- nodelay, read timeouts -- that the upgrade
        // handshake sets on it.
        //
        // SAFETY: the fd came over binder as a ParcelFileDescriptor and this owns it now;
        // `into_raw_fd` gives up File's ownership so it is not closed twice.
        use std::os::fd::{FromRawFd, IntoRawFd};
        let sock = unsafe { std::net::TcpStream::from_raw_fd(file.into_raw_fd()) };
        Some(sock)
    }
}

/// Deny everything. A daemon that has never heard from the app shares nothing.
fn denied_policy() -> TarishPolicy {
    TarishPolicy {
        airdrop: MODE_OFF,
        quickshare: MODE_OFF,
        requireConfirmation: true,
        deviceName: String::new(),
        airdropManaged: false,
        quickshareManaged: false,
        requireConfirmationManaged: false,
        deviceNameManaged: false,
        // The strict end of every switch, because this is what the daemon believes
        // before the app has ever spoken to it.
        requirePin: true,
        requirePinManaged: false,
    }
}

// Mirrors the constants in ITarishService.aidl. Kept as plain consts because the Rust
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

impl TarishService {
    fn new(peers: PeerTable, discoverable: Discoverable) -> Self {
        Self {
            callbacks: Arc::new(Mutex::new(Vec::new())),
            transfers: Arc::new(TransferState::default()),
            names: Arc::new(Mutex::new(std::collections::HashMap::new())),
            query_now: Arc::new(AtomicBool::new(false)),
            refresh_now: Arc::new(AtomicBool::new(false)),
            reset_identity: Arc::new(AtomicBool::new(false)),
            visibility_generation: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            discoverable,
            active: Arc::new(AtomicBool::new(false)),
            // NOT -1: that now MEANS something. -1 is the client saying the Wi-Fi
            // adapter is off, and this field is only written when the value changes --
            // so sharing the sentinel meant a daemon that started with Wi-Fi already
            // off saw no change, never published, and tarishd read an empty property
            // and fell back to "unknown". Observed on frankel: the client reported the
            // adapter off, tarish.awdl.sta_freq stayed empty, and AWDL chose 2.4 GHz.
            sta_freq: Arc::new(std::sync::atomic::AtomicI32::new(i32::MIN)),
            peers,
            ble_peers: Arc::new(Mutex::new(std::collections::HashMap::new())),
            qs_lan: Arc::new(Mutex::new(Vec::new())),
            qs_ident: Arc::new(quickshare::discovery::QsIdentity::new(&device_name())),
            policy: Arc::new(Mutex::new(denied_policy())),
            auto_accept: Arc::new(AtomicBool::new(false)),
            // Required until the app says otherwise.
            require_pin: Arc::new(AtomicBool::new(true)),
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

    /// Is the AWDL link up? Asked of the kernel rather than of tarishd, so this
    /// process needs no privilege and no IPC to answer it.
    fn link_up(&self) -> bool {
        let ifc = iface();
        std::fs::read_to_string(format!("/sys/class/net/{ifc}/operstate"))
            .map(|s| !s.trim().is_empty())
            .unwrap_or(false)
    }
}

impl Interface for TarishService {}

impl TarishService {
    /// Turn a peer id from the client back into something we can connect to.
    ///
    /// A peer is only sendable once its SRV and AAAA records have both been seen: the
    /// port comes from one and the address from the other, and mDNS delivers them in
    /// whatever order it likes.
    fn resolve(&self, peer_id: &str) -> Option<send::Target> {
        let ifc = iface();
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
            if mdns::link_local_of(ifc) == Some(a) {
                log::warn!("refusing to send to our own address {a} — ignoring peer {peer_id}");
                return None;
            }
        }

        Some(send::Target {
            addr: peer.addr?,
            port: if peer.port != 0 { peer.port } else { return None },
            scope: mdns::ifindex_of(ifc).ok()?,
        })
    }
}

impl ITarishService for TarishService {
    fn getStatus(&self) -> BinderResult<TarishStatus> {
        Ok(TarishStatus {
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
        // Publish the Wi-Fi frequency for tarishd BEFORE flipping the active flag, so
        // the gate can never ask for the radio while the band is still unknown --
        // tarishd would then pick 5 GHz and take the association down, which is the
        // exact bug this exists to prevent.
        // LOSING THE ASSOCIATION IS NOT LEARNING A NEW BAND.
        //
        // On a radio where AWDL and Wi-Fi cannot coexist (BCM4383), bringing AWDL up
        // destroys the very association this value is read from: wlan0 has no frequency,
        // the client reports 0, and tarishd then treats the band as unknown -- which it
        // is not. We knew it a second ago, and the association will return to the same
        // network on the same band when AWDL lets go.
        //
        // The cost of forgetting is not theoretical. channels_for() prefers 2.4 GHz when
        // the band is unknown and 5 GHz when the association is on 2.4, so a device that
        // forgot lands on 2.4 while a device that remembered sits on 5. Two devices, both
        // behaving exactly as designed, on opposite bands, with no overlapping
        // availability window -- and AirDrop between them simply never discovers
        // anything. Measured on blazer (sta_freq=2437, chose 5 GHz) against frankel
        // (sta_freq=0, chose 2.4 GHz).
        //
        // So a real frequency replaces a real frequency, and 0 is treated as "no news"
        // rather than as news. A genuine band change corrects this the moment the new
        // association reports its frequency.
        //
        // WI-FI BEING OFF IS THE ONE THING THAT DOES CLEAR THE MEMORY.
        //
        // Everything above is about an association that is coming back. A switched-off
        // adapter is not that: there is nothing to protect, nothing returning, and the
        // remembered band is now actively harmful -- it keeps AWDL out of 5 GHz to
        // avoid a network this device is not on. Measured on frankel with Wi-Fi off:
        // "Wi-Fi is on 5520 MHz -- putting AWDL in the other band, [6]", then
        // "not offering [[149, 44]]", and AirDrop ran on channel 6 at 0.87 MB/s.
        //
        // The client distinguishes the two because only it can: isWifiEnabled() is the
        // user's setting and stays true right through AWDL taking the radio, which is
        // exactly the case the memory exists for. A client too old to send -1 sends 0
        // and gets the old behaviour.
        let reported = if (2000..=7200).contains(&sta_frequency_mhz) {
            sta_frequency_mhz
        } else if sta_frequency_mhz < 0 {
            -1
        } else {
            0
        };
        let known = self.sta_freq.load(Ordering::SeqCst);
        // -1 is PUBLISHED, not folded into 0. tarishd prefers 2.4 GHz when the band is
        // unknown, to keep an adapter that is trying to associate from being locked out
        // of 5 GHz -- which is exactly the wrong instinct when the adapter is off, and
        // 2.4 GHz is where AirDrop measured 0.87 MB/s.
        let f = match reported {
            -1 => -1,
            0 if known > 0 => known,
            other => other,
        };
        if self.sta_freq.swap(f, Ordering::SeqCst) != f {
            if write_property(STA_FREQ_PROP, &f.to_string()) {
                if f > 0 {
                    log::info!("Wi-Fi is on {f} MHz");
                } else if f < 0 {
                    log::info!("Wi-Fi is off — AWDL can have the 5 GHz radio");
                } else {
                    log::info!("Wi-Fi band unknown — AWDL will keep clear of 5 GHz");
                }
            } else {
                log::warn!("could not publish {STA_FREQ_PROP} — tarishd will guess the band");
            }
        }

        // Idempotent and deliberately quiet: this is called on every onResume and
        // onPause, which on a real device means several times a second while a file
        // picker is opening. The gate thread decides what to do about it.
        self.active.store(active, Ordering::SeqCst);
        Ok(())
    }

    fn setPolicy(&self, policy: &TarishPolicy) -> BinderResult<()> {
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
        log::info!(
            "policy: requirePin={} (managed: {})",
            policy.requirePin,
            policy.requirePinManaged
        );
        self.auto_accept
            .store(!policy.requireConfirmation, Ordering::SeqCst);
        self.require_pin
            .store(policy.requirePin, Ordering::SeqCst);

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

    fn getPolicy(&self) -> BinderResult<TarishPolicy> {
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

    fn resetIdentity(&self) -> BinderResult<()> {
        // Signal the browser loop, which owns the Browser: it withdraws the old
        // instance, mints a fresh one, and re-advertises. Doing it here on the
        // binder thread would race the loop's exclusive access to the mDNS socket.
        self.reset_identity.store(true, Ordering::SeqCst);
        // Nudge a query too, so peers we know are refreshed against the new us.
        self.query_now.store(true, Ordering::SeqCst);
        log::info!("identity reset requested");
        Ok(())
    }

    fn getDaemonVersion(&self) -> BinderResult<String> {
        Ok(TARISH_VERSION.to_string())
    }

    fn getLinkVersion(&self) -> BinderResult<String> {
        Ok(link_version())
    }

    fn getQuickShareLanPeers(&self) -> BinderResult<Vec<String>> {
        let out = self
            .qs_lan
            .lock()
            .map(|t| {
                t.iter()
                    .map(|p| {
                        let addr = p
                            .addr
                            .map(|a| a.to_string())
                            .unwrap_or_else(|| p.host.clone());
                        format!(
                            "{}|{}|{}:{}",
                            p.endpoint_id,
                            p.name.as_deref().unwrap_or(""),
                            addr,
                            p.port
                        )
                    })
                    .collect()
            })
            .unwrap_or_default();
        Ok(out)
    }

    fn reportBlePeer(&self, address: &str, rssi: i32, service_data: &[u8]) -> BinderResult<()> {
        let Some(a) = tarish_protocol::ble::parse_advertisement(service_data) else {
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
        // ONE ROW PER PHYSICAL DEVICE, keyed on the only thing that does not rotate.
        //
        // A stock Android peer rotates its endpoint id, its BLE address AND its L2CAP
        // PSM together, every advertisement set. Keyed by endpoint id alone, one phone
        // becomes a new row every rotation and the stale ones linger for the whole TTL:
        // six rows called "K-N6", five of them holding an address that no longer exists.
        // Tapping one of those blocks in connect() until the socket gives up, which
        // looks like the transfer hanging at "starting".
        //
        // The BR/EDR MAC is stable across all of it, so an advertisement carrying one
        // replaces every earlier row for the same device. Peers with no MAC -- the fast
        // form -- keep the old behaviour, since there is nothing better to key on.
        if let Some(mac) = a.bluetooth_mac.as_deref() {
            peers.retain(|id, p| id == &a.endpoint_id || p.mac.as_deref() != Some(mac));
        }
        peers.insert(
            a.endpoint_id,
            BlePeer {
                name: a.device_name,
                mac: a.bluetooth_mac,
                // The LE address this advertisement arrived from, kept because an L2CAP
                // channel is opened to it and not to the BR/EDR MAC. It rotates, so the
                // newest advertisement always wins -- which is what this insert does.
                ble_address: address.to_string(),
                psm: a.psm.unwrap_or(0),
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
        self.send_common(peer_id, socket, files, names, false)
    }

    fn sendFilesOnL2capSocket(
        &self,
        peer_id: &str,
        socket: &binder::ParcelFileDescriptor,
        files: &[binder::ParcelFileDescriptor],
        names: &[String],
    ) -> BinderResult<i64> {
        self.send_common(peer_id, socket, files, names, true)
    }

    fn confirmTransferPin(&self, _transfer_id: i64, _pin: &str) -> BinderResult<bool> {
        // PIN VERIFICATION INTENTIONALLY DISABLED — see docs/PIN-DISABLED.md. No PIN is ever
        // parked now, so there is nothing to check; accept unconditionally. The AIDL method
        // stays (it is part of the interface) and the app no longer calls it. Original check:
        //   let ok = self.transfers.confirm_pin(transfer_id, pin.trim());
        //   if !ok { log::info!("quickshare: PIN rejected for transfer {transfer_id}"); }
        //   Ok(ok)
        Ok(true)
    }

    fn sendFilesOnLan(
        &self,
        peer_id: &str,
        files: &[binder::ParcelFileDescriptor],
        names: &[String],
    ) -> BinderResult<i64> {
        self.send_on_lan(peer_id, files, names)
    }

    fn quickShareAdvertisement(&self, bluetooth_mac: &str) -> BinderResult<Vec<u8>> {
        // Do not advertise Quick Share at all when policy forbids receiving it. Otherwise the app
        // publishes a BLE endpoint + RFCOMM listener, a sender (e.g. a Pixel) discovers us as a
        // Quick Share target, connects, and only THEN gets refused at receiveOnSocket — which reads
        // as "failed" on the sender, and for a peer that also speaks AirDrop it stops there rather
        // than ever trying AirDrop. An empty advertisement makes QuickShareReceiver.start() bail
        // before it listens or advertises, so a disabled Quick Share is genuinely invisible.
        if !allows_receive(self.quickshare_mode()) {
            log::info!("quickShareAdvertisement: Quick Share receive is off — not advertising");
            return Ok(Vec::new());
        }
        let Some(mac) = parse_mac(bluetooth_mac) else {
            log::warn!("quickShareAdvertisement: {bluetooth_mac:?} is not a Bluetooth address");
            return Ok(Vec::new());
        };
        // No PSM: we listen on RFCOMM, not L2CAP.
        //
        // THIS FIELD DECIDES WHICH SOCKET THE PEER OPENS, and it is not a preference. A peer
        // that sees a PSM opens an L2CAP channel and REFUSES RFCOMM -- accepted and closed
        // inside 200 ms, no frame either way, which reads as a device that is asleep. So this
        // stays None until an L2CAP listener actually exists.
        let advert = tarish_protocol::ble::build_advertisement(
            &self.qs_ident.id_str(),
            &self.qs_ident.endpoint_info,
            Some(mac),
            self.qs_ident.device_token,
            None,
        );
        match advert {
            Some(bytes) => {
                log::info!(
                    "quickshare: advertisement for {} over BLE ({} bytes, RFCOMM at {bluetooth_mac})",
                    self.qs_ident.id_str(),
                    bytes.len()
                );
                Ok(bytes)
            }
            None => {
                log::warn!("quickShareAdvertisement: could not build one");
                Ok(Vec::new())
            }
        }
    }

    fn receiveOnSocket(&self, socket: &binder::ParcelFileDescriptor) -> BinderResult<i64> {
        if !allows_receive(self.quickshare_mode()) {
            log::warn!("receiveOnSocket refused — policy does not permit Quick Share receive");
            return Err(Status::from(StatusCode::PERMISSION_DENIED));
        }
        // Duplicated for the same reason every other descriptor here is: the parcel's copy
        // closes when this transaction returns, and the thread that reads it runs after.
        let sock = match dup_file(socket) {
            Ok(f) => f,
            Err(e) => {
                log::warn!("receiveOnSocket: could not take the socket ({e})");
                return Ok(0);
            }
        };
        let reader = match sock.try_clone() {
            Ok(r) => r,
            Err(e) => {
                log::warn!("receiveOnSocket: could not clone the socket ({e})");
                return Ok(0);
            }
        };

        // One transfer at a time across both protocols: refuse if anything is running.
        let Some(id) = self.transfers.try_begin(false) else {
            log::info!("receiveOnSocket refused — busy with another transfer");
            return Ok(0);
        };
        let transfers = self.transfers.clone();
        let callbacks = self.callbacks.clone();
        let auto_accept = self.auto_accept.clone();
        std::thread::spawn(move || {
            let host = QsHost {
                id,
                // The peer names itself in its ConnectionRequest, which serve() reads. There
                // is no address to report here: a Bluetooth peer arrives on a socket the app
                // accepted and the daemon never sees who dialled.
                peer: "a nearby device".to_string(),
                transfers: transfers.clone(),
                callbacks: callbacks.clone(),
                auto_accept,
                created: std::sync::Mutex::new(Vec::new()),
            };
            log::info!("quickshare: inbound Bluetooth connection (transfer {id})");
            let outcome = quickshare::connection::serve(
                Box::new(reader),
                Box::new(sock),
                tarish_protocol::upgrade::Medium::Bluetooth,
                &host,
                &transfers,
                &callbacks,
            );
            use quickshare::connection::ServeOutcome;
            let status = match &outcome {
                // NOT "over Bluetooth": the transport may have been swapped underneath by
                // then. Bluetooth is where the connection STARTED, and a line claiming a
                // 5 GHz Wi-Fi Direct transfer arrived over Bluetooth is the kind of log that
                // sends someone looking in the wrong place later.
                Ok(ServeOutcome::Received(names)) if !names.is_empty() => {
                    log::info!("quickshare: received {} file(s) from a Bluetooth connection", names.len());
                    STATUS_OK
                }
                Ok(ServeOutcome::Received(_)) => {
                    log::info!("quickshare: nothing received");
                    STATUS_DECLINED
                }
                Ok(ServeOutcome::Cancelled) => {
                    log::info!("quickshare: inbound Bluetooth transfer {id} cancelled — partial discarded");
                    STATUS_CANCELLED
                }
                Err(e) => {
                    log::warn!("quickshare: inbound transfer {id} failed: {e}");
                    STATUS_FAILED
                }
            };
            if let Ok(cbs) = callbacks.lock() {
                for cb in cbs.iter() {
                    let _ = cb.onTransferFinished(id, status);
                }
            }
            transfers.finish(id);
        });
        Ok(id)
    }

    fn provideWifiDirectGroup(&self, transfer_id: i64, group: &TarishGroup) -> BinderResult<()> {
        // An empty ssid is a decline, not a malformed answer: no Wi-Fi Direct, a driver
        // that would not form a group, or a client that would rather not.
        if group.ssid.is_empty() {
            log::info!("quickshare: client declined to host a group for transfer {transfer_id}");
            self.transfers.provide_group(transfer_id, None);
        } else {
            log::info!(
                "quickshare: client is hosting {:?} at {} for transfer {transfer_id}",
                group.ssid,
                group.goAddress
            );
            // Field by field: the generated parcelable does not derive Clone, and
            // `group.clone()` on a &T silently clones the REFERENCE instead of the value.
            self.transfers.provide_group(
                transfer_id,
                Some(TarishGroup {
                    ssid: group.ssid.clone(),
                    passphrase: group.passphrase.clone(),
                    goAddress: group.goAddress.clone(),
                    frequency: group.frequency,
                }),
            );
        }
        Ok(())
    }

    fn provideUpgradeSocket(
        &self,
        transfer_id: i64,
        socket: Option<&binder::ParcelFileDescriptor>,
    ) -> BinderResult<()> {
        let Some(pfd) = socket else {
            log::info!("quickshare: client declined the upgrade for transfer {transfer_id}");
            self.transfers.provide_upgrade(transfer_id, None);
            return Ok(());
        };
        // Duplicated for the same reason every other descriptor here is: the parcel's copy
        // is closed when this transaction returns, and the transfer thread that will read
        // it runs long after that.
        match dup_file(pfd) {
            Ok(f) => {
                log::info!("quickshare: client joined the network for transfer {transfer_id}");
                self.transfers.provide_upgrade(transfer_id, Some(f));
            }
            Err(e) => {
                // Report it as a decline rather than an error. The transfer is waiting for
                // an answer and will otherwise sit out its whole timeout for a descriptor
                // that is never going to arrive.
                log::warn!("quickshare: could not take the upgrade socket ({e}); declining");
                self.transfers.provide_upgrade(transfer_id, None);
            }
        }
        Ok(())
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

    fn getPeers(&self) -> BinderResult<Vec<TarishPeer>> {
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
        // Two protocols in one list is the whole reason TarishPeer carries `protocol`: a
        // person picking a device is picking a protocol, and an Apple peer found over
        // AWDL cannot be reached the way an Android one over BLE can.
        let mut quickshare: Vec<TarishPeer> = Vec::new();
        if let Ok(mut ble) = self.ble_peers.lock() {
            let now = std::time::Instant::now();
            // Expire here as well as on report: a peer that walks away stops advertising,
            // and nothing else would ever notice it had gone.
            ble.retain(|_, p| now.duration_since(p.seen) < BLE_PEER_TTL);
            for (id, p) in ble.iter() {
                quickshare.push(TarishPeer {
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
                    bleAddress: p.ble_address.clone(),
                    psm: p.psm as i32,
                });
            }
        }
        // Sorted for the same reason the AirDrop list is: an unstable order makes the
        // app rebuild its tiles and a device move under a finger mid-tap.
        quickshare.sort_by(|a, b| a.name.cmp(&b.name).then_with(|| a.id.cmp(&b.id)));

        Ok(out
            .into_iter()
            .map(|p| TarishPeer {
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
                // AirDrop never uses either of these; they exist for the Quick Share
                // rows above, where they decide which socket the app opens.
                bleAddress: String::new(),
                psm: 0,
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

        // One transfer at a time across both protocols: refuse the send if anything is running.
        let Some(id) = self.transfers.try_begin(true) else {
            log::warn!("sendFiles refused — busy with another transfer");
            return Err(Status::from(StatusCode::WOULD_BLOCK));
        };
        let transfers = self.transfers.clone();
        let peers_for_send = self.peers.clone();
        let peer_instance = peer_id.to_string();
        let callbacks = self.callbacks.clone();
        let name = device_name();
        let model = device_model();

        // Sending happens off the binder thread: a transfer runs for as long as it runs,
        // and holding a binder worker for that would block every other call into us.
        std::thread::spawn(move || {
            let announce = |f: &dyn Fn(&Strong<dyn ITarishCallback>) -> binder::Result<()>| {
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

    fn registerCallback(&self, cb: &Strong<dyn ITarishCallback>) -> BinderResult<()> {
        let mut cbs = self.callbacks.lock().unwrap();
        // DEDUP. Registering is not idempotent by nature: `connect()` in the client
        // re-registers the SAME callback on every (re)connect. Left unchecked the list grew a
        // copy per reconnect, and EVERY oneway callback fanned out to all of them --
        // onGroupNeeded in particular made the app spin up one Wi-Fi Direct Channel per copy,
        // and the receiver was killed for "too many Binders sent to uid 1000" mid-transfer.
        // Refuse duplicates so a live client counts once. (A client that dies leaves a dead
        // proxy, which is harmless: a oneway to it just fails and it can never trigger work in
        // an app that is gone; unregisterCallback and the next matching register cover it.)
        if cbs.iter().any(|c| c.as_binder() == cb.as_binder()) {
            log::debug!("client already registered; not adding a duplicate");
        } else {
            cbs.push(cb.clone());
            log::info!("client registered ({} total)", cbs.len());
        }
        Ok(())
    }

    fn unregisterCallback(&self, cb: &Strong<dyn ITarishCallback>) -> BinderResult<()> {
        let mut cbs = self.callbacks.lock().unwrap();
        cbs.retain(|c| c.as_binder() != cb.as_binder());
        log::info!("client unregistered");
        Ok(())
    }
}

/// Browse for AirDrop peers on the AWDL interface, forever.
///
/// Runs whether or not a client is bound, because discoverability is daemon
/// state. Waits for the link rather than failing at start: tarishd may still be
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
    reset_identity: QueryNow,
) {
        let ifc = iface();
    std::thread::spawn(move || {
        let mut browser = loop {
            match mdns::Browser::new(ifc) {
                Ok(b) => {
                    log::info!("browsing {} on {ifc}", mdns::AIRDROP_SERVICE);
                    break b;
                }
                Err(e) => {
                    log::info!("waiting for {ifc} ({e})");
                    std::thread::sleep(Duration::from_secs(5));
                }
            }
        };

        // Asked once per peer per boot. Without this the loop would re-probe every
        // peer on every pass, which is a TLS connection each time.
        let mut probed: std::collections::HashSet<String> = std::collections::HashSet::new();
        // Which instance of the interface we are bound to. The table id IS the index,
        // and tarishd recreates mosey0 with a new one every time it re-acquires the
        // radio, so this is the identity that matters -- not the name.
        let mut bound_idx = mdns::ifindex_of(ifc).unwrap_or(0);
        // The address we bound the responder against. The index is not enough: tarishd
        // re-acquires the radio and tlink0's link-local is reassigned (every off-network
        // Quick Share teardown/restore does this), and the address often lands a moment
        // AFTER the index appears. Either way the responder ends up receiving queries but
        // answering into a socket bound to an address that is gone — rx is logged, no
        // "answered" — which reads as invisible on the sender. Track it and rebind on change.
        let mut bound_addr = mdns::link_local_of(ifc);
        let mut waiting_logged = false;
        let mut failures = 0u32;
        let mut since_query = Duration::from_secs(99);
        let mut since_announce = Duration::ZERO;
        let mut was_advertising = false;
        loop {
            // tarishd holds AWDL only while something wants it, so mosey0 genuinely
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
            let now_idx = mdns::ifindex_of(ifc).unwrap_or(0);
            if now_idx == 0 {
                if bound_idx != 0 {
                    log::info!("{ifc} is gone — discovery idle until it returns");
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
                match mdns::Browser::new(ifc) {
                    Ok(b) => {
                        log::info!("{ifc} is up as index {now_idx} — bound");
                        browser = b;
                        bound_idx = now_idx;
                        bound_addr = mdns::link_local_of(ifc);
                        failures = 0;
                        was_advertising = false;      // re-assert on the new socket
                        since_query = Duration::from_secs(99);
                        waiting_logged = false;
                    }
                    Err(e) => {
                        // Usually just the address not being assigned yet, a moment
                        // after the index appears. Say it once, then wait quietly.
                        if !waiting_logged {
                            log::info!("waiting for an address on {ifc} ({e})");
                            waiting_logged = true;
                        }
                        std::thread::sleep(Duration::from_millis(500));
                        continue;
                    }
                }
            }
            // Rebind when the link-local changed but the index did not — the address
            // arriving after the index, a reassignment on radio re-acquire, or a socket
            // gone deaf after a Wi-Fi reset. Without this the responder keeps a socket bound
            // to an address that is gone: it still receives queries (rx logged) but its
            // answers go nowhere, so the device is invisible until something else forces a
            // rebind. Re-asserting advertising on the fresh socket restores visibility.
            let now_addr = mdns::link_local_of(ifc);
            if now_addr.is_some() && now_addr != bound_addr {
                match mdns::Browser::new(ifc) {
                    Ok(b) => {
                        log::info!("{ifc} link-local changed to {now_addr:?} — rebound");
                        browser = b;
                        bound_addr = now_addr;
                        was_advertising = false; // re-advertise + re-announce on the new socket
                    }
                    Err(e) => log::debug!("{ifc} address changed but rebind not ready ({e})"),
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
                if let Ok(scope) = mdns::ifindex_of(ifc) {
                    probe_name(names.clone(), instance, send::Target { addr, port, scope });
                }
            }

            // A requested identity reset: withdraw the OLD instance first (so a peer
            // drops it rather than keeping it as a ghost pointing at a name we will no
            // longer answer for), then mint the new one. Clearing was_advertising makes
            // the block just below re-advertise under the new identity this same pass.
            if reset_identity.swap(false, Ordering::SeqCst) {
                if was_advertising {
                    let _ = browser.stop_advertising();
                }
                let new_id = browser.reset_identity();
                was_advertising = false;
                log::info!("identity reset — now {new_id}.{}", mdns::AIRDROP_SERVICE);
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

            // Re-announce frequently: a peer that started browsing after us has no reason to
            // query again, so silence means invisibility — and worse, an Apple sender waits for
            // a fresh announce to refresh our address before it sends the offer, so a slow cadence
            // shows up directly as tap->prompt latency (finding 124: ~3-5s vs libmosey ~1s, which
            // announces in reactive bursts). 20s was far too slow for that; 1s keeps a current
            // record in front of the sender at all times. The loop ticks every 500ms, so this is
            // one extra small multicast every ~1s while visible — cheap.
            if was_advertising && since_announce >= Duration::from_secs(1) {
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
            // tarishd recreates mosey0 with a NEW interface index whenever it restarts,
            // and a socket bound to the old one is dead for good: every send returns
            // ENETUNREACH and this loop would log that forever while discovery quietly
            // returned nothing. Nothing else notices, because the daemon is up, the
            // interface exists, and the address looks fine -- it is simply a different
            // interface than the one we are bound to.
            if failures >= 3 {
                log::warn!("mDNS socket is stale — rebinding to {ifc}");
                match mdns::Browser::new(ifc) {
                    Ok(b) => {
                        browser = b;
                        bound_idx = mdns::ifindex_of(ifc).unwrap_or(0);
                        failures = 0;
                        was_advertising = false;   // re-assert on the new socket
                        since_query = Duration::from_secs(99);
                        log::info!("rebound to {ifc}");
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
/// correct mDNS record. Tarish advertised 8770 with nothing bound to it for a long time.
///
/// mosey0 may not exist or may have no address yet when we start, since tarishd brings
/// the link up independently. Retry rather than give up: failing here permanently
/// would mean a daemon that is running, looks healthy, and can never be discovered.
fn start_airdrop_server(
    discoverable: Discoverable,
    callbacks: Callbacks,
    transfers: Transfers,
    auto_accept: Arc<AtomicBool>,
) {
        let ifc = iface();
    std::thread::spawn(move || {
        let name = read_property("persist.tarish.name")
            .or_else(|| read_property("ro.product.model"))
            .unwrap_or_else(|| "Tarish".to_string());
        let model = device_model();

        loop {
            match httpd::Httpd::new(
                ifc,
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
                    std::sync::Arc::new(server).serve();
                    // serve() only returns if the listener itself died.
                    log::warn!("AirDrop server stopped — rebinding");
                }
                Err(e) => log::debug!("AirDrop server not up yet: {e}"),
            }
            // Two very different waits behind one failure.
            //
            // If mosey0 exists, tarishd has just brought it up and the address is
            // moments away -- retrying slowly here is dead time a person spends
            // looking at a device that cannot yet receive. If it does not exist, the
            // radio is released and nothing is coming; polling fast would be a wakeup
            // source for as long as the phone is in a pocket.
            let coming_up = mdns::ifindex_of(ifc).is_ok();
            std::thread::sleep(if coming_up {
                Duration::from_millis(500)
            } else {
                Duration::from_secs(5)
            });
        }
    });
}

/// Accept Quick Share transfers over the LAN.
///
/// The receiving counterpart to send_on_lan, and the same reasoning: a peer on our subnet
/// reaches us by connecting to an address we advertised, so the daemon listens and runs the
/// protocol. No radio is involved, so the app is not needed here -- unlike off-network
/// receiving, which will need it to accept a Bluetooth connection.
///
/// `serve()` has existed since the protocol work and had never been called. Everything it
/// needs already existed too: the callback list for the prompt, the transfer slot for the
/// answer, and httpd's inbox for the files.
fn start_quickshare_server(
    transfers: Transfers,
    callbacks: Callbacks,
    auto_accept: Arc<AtomicBool>,
    policy: Arc<Mutex<TarishPolicy>>,
    port: Arc<std::sync::atomic::AtomicU16>,
) {
    std::thread::spawn(move || {
        loop {
            // PORT 0: let the kernel choose, then publish what it chose. A fixed port would
            // collide with whatever else is on the device and fail at bind for a reason no
            // one would look for -- and the peer learns the port from mDNS anyway, so there
            // is nothing to gain by picking one.
            let listener = match std::net::TcpListener::bind(("0.0.0.0", 0)) {
                Ok(l) => l,
                Err(e) => {
                    log::warn!("quickshare: could not listen ({e}); retrying in 10s");
                    std::thread::sleep(Duration::from_secs(10));
                    continue;
                }
            };
            let bound = match listener.local_addr() {
                Ok(a) => a.port(),
                Err(e) => {
                    log::warn!("quickshare: listener has no address ({e})");
                    std::thread::sleep(Duration::from_secs(10));
                    continue;
                }
            };
            // Published BEFORE the accept loop, so the responder never advertises a port
            // nothing is listening on.
            port.store(bound, Ordering::SeqCst);
            log::info!("quickshare: accepting transfers on port {bound}");

            for conn in listener.incoming() {
                let sock = match conn {
                    Ok(s) => s,
                    Err(e) => {
                        log::warn!("quickshare: accept failed ({e}); rebinding");
                        break;
                    }
                };
                // POLICY IS CHECKED PER CONNECTION, not once at start-up. An administrator
                // who turns receiving off should close the door on the next peer to knock,
                // not at the next reboot -- and the daemon starts denied, so a listener
                // running before any policy arrives must refuse everything.
                let mode = policy.lock().map(|p| p.quickshare).unwrap_or(MODE_OFF);
                if !allows_receive(mode) {
                    log::info!("quickshare: refusing a connection — policy does not permit receive");
                    continue;
                }

                let peer = sock
                    .peer_addr()
                    .map(|a| a.ip().to_string())
                    .unwrap_or_else(|_| "a nearby device".to_string());
                let transfers = transfers.clone();
                let callbacks = callbacks.clone();
                let auto_accept = auto_accept.clone();
                // One thread per connection. A peer that stalls mid-transfer must not stop
                // the next one being answered.
                std::thread::spawn(move || {
                    let reader = match sock.try_clone() {
                        Ok(r) => r,
                        Err(e) => {
                            log::warn!("quickshare: could not clone an inbound socket: {e}");
                            return;
                        }
                    };
                    // Same reason as every other socket here: a peer that stops reading
                    // must cost this transfer, not the thread forever.
                    let _ = sock.set_write_timeout(Some(Duration::from_secs(20)));
                    // One transfer at a time across both protocols: if anything is running,
                    // drop this connection rather than serving a second transfer at once.
                    let Some(id) = transfers.try_begin(false) else {
                        log::info!("quickshare: refusing an inbound LAN connection — busy");
                        return;
                    };
                    let host = QsHost {
                        id,
                        peer: peer.clone(),
                        transfers: transfers.clone(),
                        callbacks: callbacks.clone(),
                        auto_accept,
                        created: std::sync::Mutex::new(Vec::new()),
                    };
                    log::info!("quickshare: inbound connection from {peer} (transfer {id})");
                    let outcome = quickshare::connection::serve(
                        Box::new(reader),
                        Box::new(sock),
                        tarish_protocol::upgrade::Medium::WifiLan,
                        &host,
                        &transfers,
                        &callbacks,
                    );
                    // TELL THE CLIENT IT ENDED. Without this the app sits at a full
                    // progress bar forever: the bytes arrived, the file is in the inbox, and
                    // nothing ever said the transfer was over. serve() has no notion of
                    // this -- the send path had the same hole and it presents identically,
                    // as a transfer "stuck at completion".
                    use quickshare::connection::ServeOutcome;
                    let status = match &outcome {
                        Ok(ServeOutcome::Received(names)) if !names.is_empty() => {
                            log::info!("quickshare: received {} file(s) from {peer}", names.len());
                            STATUS_OK
                        }
                        // Nothing arrived. A person declining is the ordinary reason, and it
                        // is an answer rather than a fault.
                        Ok(ServeOutcome::Received(_)) => {
                            log::info!("quickshare: nothing received from {peer}");
                            STATUS_DECLINED
                        }
                        // Cancelled mid-stream. serve() already discarded the partial, so
                        // there is nothing in the inbox for the app to collect.
                        Ok(ServeOutcome::Cancelled) => {
                            log::info!("quickshare: transfer {id} cancelled by {peer} — partial discarded");
                            STATUS_CANCELLED
                        }
                        Err(e) => {
                            // A peer that opens a connection and closes it without a word is
                            // probing, not failing -- Windows does it either side of a real
                            // transfer. Not worth a warning.
                            if e.kind() == std::io::ErrorKind::UnexpectedEof {
                                log::debug!("quickshare: {peer} connected and said nothing");
                            } else {
                                log::warn!("quickshare: inbound transfer {id} failed: {e}");
                            }
                            STATUS_FAILED
                        }
                    };
                    if let Ok(cbs) = callbacks.lock() {
                        for cb in cbs.iter() {
                            let _ = cb.onTransferFinished(id, status);
                        }
                    }
                    transfers.finish(id);
                });
            }
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
fn start_quickshare_discovery(
    lan: QsLanPeers,
    port: Arc<std::sync::atomic::AtomicU16>,
    ident: Arc<quickshare::discovery::QsIdentity>,
) {
    std::thread::spawn(move || {
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
            // ADVERTISE FROM THE SAME LOOP AS BROWSING. Both want wlan0 with an address,
            // both have to be torn down and rebuilt when it goes away, and doing that in two
            // places means two chances to get the interface state wrong.
            //
            // None when there is no port yet -- the listener publishes it once it is bound,
            // and advertising a port nothing is listening on is worse than not advertising:
            // a sender finds us, connects, and fails.
            let mut responder: Option<quickshare::discovery::QsResponder> = None;
            let mut since_announce = Duration::from_secs(99);
            let mut since_query = Duration::from_secs(99);
            loop {
                let bound = port.load(Ordering::SeqCst);
                if responder.is_none() && bound != 0 {
                    match quickshare::discovery::QsResponder::new(IFACE, &ident, bound) {
                        Ok(r) => {
                            log::info!(
                                "quickshare: advertising as \"{}\" ({}) on port {bound}",
                                device_name(),
                                ident.id_str()
                            );
                            responder = Some(r);
                        }
                        Err(e) => log::debug!("quickshare: cannot advertise yet ({e})"),
                    }
                }
                if let Some(r) = responder.as_mut() {
                    r.poll();
                    // Re-announced periodically, not only on start-up: a sender already
                    // browsing will not re-query because we appeared, so a receiver that
                    // waits to be asked stays invisible until the peer's next scan.
                    if since_announce >= Duration::from_secs(30) {
                        if let Err(e) = r.announce() {
                            log::debug!("quickshare: announce failed ({e})");
                        }
                        since_announce = Duration::ZERO;
                    }
                }

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
                let found = browser.peers();
                // Publish before logging. This is what sendFilesOnLan reads, and a table
                // that is only ever logged is the bug this replaces.
                if let Ok(mut t) = lan.lock() {
                    *t = found.clone();
                }
                for p in found {
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
                since_announce += Duration::from_millis(500);
            }
        }
    });
}

fn main() {
    android_logger::init_once(
        android_logger::Config::default()
            .with_tag("tarishsharingd")
            .with_max_level(log::LevelFilter::Debug),
    );
    // Build marker. The AIDL surface has grown twice without the device appearing to
    // gain the new transactions, so the running code has to be identifiable from the log
    // rather than inferred from a file hash.
    log::info!("starting (aidl: policy+devicename, 17 transactions)");

    let peers: PeerTable = Arc::new(Mutex::new(Vec::new()));

    // Off by default. A device that advertises itself the moment it boots is a
    // privacy decision, not a default, and it belongs to the user through the
    // client. persist.tarish.discoverable exists so the transport can be tested
    // before a client exists to turn it on.
    // Default OFF. Being discoverable is the user's decision, made by opening the app;
    // a device that advertises itself from boot is a privacy choice nobody made. The
    // property remains only so the transport can be exercised without a client.
    let initial = read_property("persist.tarish.discoverable")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    if initial {
        log::warn!("persist.tarish.discoverable is set — advertising without a client asking");
    }
    let discoverable: Discoverable = Arc::new(AtomicBool::new(initial));

    let service = TarishService::new(peers.clone(), discoverable.clone());
    start_discovery(
        peers,
        service.names.clone(),
        discoverable.clone(),
        service.query_now.clone(),
        service.refresh_now.clone(),
        service.reset_identity.clone(),
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
        service.policy.clone(),
    );
    // Cloned BEFORE the service moves into the binder. The discovery thread is started
    // after the service is published on purpose -- nothing should browse for peers until
    // there is somewhere to report them -- so the handle has to be taken while it can be.
    let qs_lan = service.qs_lan.clone();
    let qs_ident = service.qs_ident.clone();
    // The port the Quick Share listener actually bound, for the responder to advertise.
    // Zero until it is up, which is how the responder knows not to announce yet.
    let qs_port = Arc::new(std::sync::atomic::AtomicU16::new(0));
    start_quickshare_server(
        service.transfers.clone(),
        service.callbacks.clone(),
        service.auto_accept.clone(),
        service.policy.clone(),
        qs_port.clone(),
    );
    let binder = BnTarishService::new_binder(service, BinderFeatures::default());

    if let Err(e) = binder::add_service(SERVICE_NAME, binder.as_binder()) {
        log::error!("could not publish {SERVICE_NAME}: {e:?}");
        std::process::exit(1);
    }
    log::info!("published {SERVICE_NAME}");
    // Quick Share identity, logged once. Discovery is not wired yet; this proves the
    // derivation on real hardware rather than only in reasoning.
    log::info!("quickshare: {}", quickshare::describe_identity(&device_name()));
    start_quickshare_discovery(qs_lan, qs_port, qs_ident);

    // One thread is plenty for a skeleton; the transfer work will want more.
    binder::ProcessState::join_thread_pool();
}

impl TarishService {
    /// Drive a Quick Share send over a socket the app already connected.
    ///
    /// `multiplexed` says which kind of socket it is, and the app knows because the
    /// peer's advertisement told it: an L2CAP channel carries a virtual socket that has
    /// to be opened first, an RFCOMM one is a plain stream. Getting it wrong is not
    /// subtle -- multiplex frames on RFCOMM are unparseable to the peer, and raw frames
    /// on L2CAP are ignored entirely.
    fn send_common(
        &self,
        peer_id: &str,
        socket: &binder::ParcelFileDescriptor,
        files: &[binder::ParcelFileDescriptor],
        names: &[String],
        multiplexed: bool,
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

        // One transfer at a time across both protocols: refuse the send if anything is running.
        let Some(id) = self.transfers.try_begin(false) else {
            log::warn!("sendFilesOnSocket refused — busy with another transfer");
            return Err(Status::from(StatusCode::WOULD_BLOCK));
        };
        let device = device_name();
        // FOUR CHARACTERS. Not the mDNS instance label.
        //
        // This ran the id through `instance_name`, which base64url-encodes a ten-byte
        // structure -- version byte, id, service hash, reserved -- and produced a
        // fourteen-character string. That is the right value for an mDNS record and the
        // wrong one for this field, which wants the bare endpoint id.
        //
        // Windows tolerated it. A stock Pixel does not, and does not merely refuse:
        //
        //   FATAL EXCEPTION: highpool[467]
        //   Process: com.google.android.gms.persistent
        //   java.lang.IllegalArgumentException: ConnectionsDevice's endpoint id must be
        //   assigned with length 4.
        //
        // It takes down com.google.android.gms.persistent, which is why the peer went
        // from talking to us to silently dropping the channel -- the service handling it
        // had died. Their crash, our malformed field.
        let endpoint = String::from_utf8_lossy(&quickshare::random_endpoint_id()).into_owned();
        let peer = peer_id.to_string();
        let transfers = self.transfers.clone();
        let callbacks = self.callbacks.clone();
        // Read ONCE, here, not inside the transfer. A policy push halfway through a send
        // should not change whether that send was allowed to skip its confirmation.
        let require_pin = self.require_pin.load(Ordering::SeqCst);

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
                require_pin,
            };
            log::info!("quickshare: sending {} file(s) to {peer}", out_files.len());
            // The virtual socket, opened before anything above it says a word.
            // The mediums we are WILLING TO UPGRADE TO, which is not the same as the
            // one we connected over. See `quickshare_mediums`, which records what each
            // wrong answer did to a real Android phone.
            let mediums = quickshare_mediums();

            // On L2CAP the peer will not speak until a virtual socket has been asked for
            // and accepted, so that handshake happens here, before the protocol above it
            // writes anything. On RFCOMM there is nothing to open: it is already a
            // stream. Both arms hand `send` a reader and a writer and it never learns
            // which it got.
            let outcome = if multiplexed {
                // THREE handles on one socket: read, write, and a third the reader uses
                // to acknowledge packets. Acknowledging is part of receiving, so the
                // read side has to be able to write, and giving it its own handle avoids
                // locking the send path behind it.
                let acks = match sock.try_clone() {
                    Ok(a) => a,
                    Err(e) => {
                        log::warn!("quickshare: could not clone the socket for acks: {e}");
                        progress.finished(STATUS_FAILED);
                        transfers.finish(id);
                        return;
                    }
                };
                match quickshare::mux::open(reader, sock, acks) {
                    Ok((r, w)) => quickshare::outbound::send(
                        Box::new(r),
                        Box::new(w),
                        &device,
                        &endpoint,
                        tarish_protocol::upgrade::Medium::Bluetooth,
                        &mediums,
                        out_files,
                        &progress,
                    ),
                    Err(e) => Err(e),
                }
            } else {
                quickshare::outbound::send(
                    Box::new(reader),
                    Box::new(sock),
                    &device,
                    &endpoint,
                    tarish_protocol::upgrade::Medium::Bluetooth,
                    &mediums,
                    out_files,
                    &progress,
                )
            };
            report_outcome(id, outcome, &progress);
            transfers.finish(id);
        });

        Ok(id)
    }

    /// Send to a Quick Share peer over the LAN, dialling the address it advertised.
    ///
    /// THE FAST PATH, AND THE ONE THAT WAS MISSING. Wi-Fi LAN is a bootstrap medium here,
    /// not an upgrade target: a peer on our subnet publishes an address over mDNS and is
    /// reached by connecting to it. The daemon had that address -- it logged
    /// "peer MTOI at 192.168.0.99:56189" -- and then sent the file over Bluetooth at
    /// 200 KB/s, because the browser's table was never published anywhere that could use
    /// it. Chasing a WIFI_LAN bandwidth upgrade instead was a dead end: a stock peer never
    /// offers one, and Bada's own registry says why -- "Wi-Fi LAN is the discovery medium
    /// today, so there is nothing to upgrade to".
    fn send_on_lan(
        &self,
        peer_id: &str,
        files: &[binder::ParcelFileDescriptor],
        names: &[String],
    ) -> BinderResult<i64> {
        if !allows_send(self.quickshare_mode()) {
            log::warn!("sendFilesOnLan refused — policy does not permit Quick Share send");
            return Err(Status::from(StatusCode::PERMISSION_DENIED));
        }
        if files.len() != names.len() {
            return Err(Status::from(StatusCode::BAD_VALUE));
        }

        // Matched on endpoint id, which is what the app holds. The same four characters
        // key the BLE table, so a peer seen both ways resolves to one device.
        let route = {
            let table = self
                .qs_lan
                .lock()
                .map_err(|_| Status::from(StatusCode::UNKNOWN_ERROR))?;
            table
                .iter()
                .find(|p| p.endpoint_id == peer_id)
                .and_then(|p| p.addr.map(|a| (a, p.port)))
        };
        // Not an error. A peer discovered only over BLE has no LAN route, and the caller
        // is expected to fall back to Bluetooth -- so say so quietly and return 0.
        let Some((addr, port)) = route else {
            log::info!("quickshare: no LAN route to {peer_id}; the caller should use Bluetooth");
            return Ok(0);
        };
        if port == 0 {
            log::info!("quickshare: {peer_id} published no port yet; not a LAN route");
            return Ok(0);
        }

        let target = std::net::SocketAddr::new(std::net::IpAddr::V4(addr), port);
        // Bounded, and short. A peer that advertised an address it is not listening on
        // must cost a moment before we fall back, not the whole transfer.
        let sock = match std::net::TcpStream::connect_timeout(&target, Duration::from_secs(5)) {
            Ok(s) => s,
            Err(e) => {
                log::info!("quickshare: could not reach {peer_id} at {target} ({e}); use Bluetooth");
                return Ok(0);
            }
        };
        // Small request/response frames dominate the handshake; Nagle would add a round
        // trip to each for no benefit on a link this fast.
        let _ = sock.set_nodelay(true);
        // Same reason as the upgraded socket: a peer that accepts and then stops reading
        // would park this transfer's thread in sk_stream_wait_memory for good, and a
        // transfer that never ends never reports an outcome and never frees anything.
        let _ = sock.set_write_timeout(Some(Duration::from_secs(20)));
        log::info!("quickshare: connected to {peer_id} at {target} over the LAN");

        let mut out_files = Vec::with_capacity(files.len());
        for (f, n) in files.iter().zip(names) {
            let file = dup_file(f).map_err(|e| {
                log::warn!("sendFilesOnLan: could not dup {n}: {e}");
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

        // One transfer at a time across both protocols: refuse the send if anything is running.
        let Some(id) = self.transfers.try_begin(false) else {
            log::warn!("sendFilesOnLan refused — busy with another transfer");
            return Err(Status::from(StatusCode::WOULD_BLOCK));
        };
        let device = device_name();
        let endpoint = String::from_utf8_lossy(&quickshare::random_endpoint_id()).into_owned();
        let peer = peer_id.to_string();
        let transfers = self.transfers.clone();
        let callbacks = self.callbacks.clone();
        let require_pin = self.require_pin.load(Ordering::SeqCst);

        std::thread::spawn(move || {
            let reader = match sock.try_clone() {
                Ok(r) => r,
                Err(e) => {
                    log::warn!("quickshare: could not clone the LAN socket: {e}");
                    transfers.finish(id);
                    return;
                }
            };
            let progress = TransferProgress {
                id,
                transfers: transfers.clone(),
                callbacks,
                require_pin,
            };
            log::info!(
                "quickshare: sending {} file(s) to {peer} over the LAN",
                out_files.len()
            );
            // WIFI_LAN ALONE, and not quickshare_mediums(). That function answers a
            // different question -- what we could upgrade a BLUETOOTH bootstrap to -- and
            // its measured table is about what a receiver accepts over Bluetooth. Bada
            // does the same: a LAN transport advertises setOf(WIFI_LAN) and nothing else,
            // because there is no faster medium to move to from here.
            let mediums = [tarish_protocol::frames::Medium::WifiLan as u64];
            let outcome = quickshare::outbound::send(
                Box::new(reader),
                Box::new(sock),
                &device,
                &endpoint,
                tarish_protocol::upgrade::Medium::WifiLan,
                &mediums,
                out_files,
                &progress,
            );
            report_outcome(id, outcome, &progress);
            transfers.finish(id);
        });

        Ok(id)
    }
}

/// Receives a Quick Share transfer: prompts a person, writes the files, reports progress.
///
/// The counterpart to TransferProgress on the send side, and deliberately built on the
/// SAME pieces AirDrop receiving already uses -- the callback list for the prompt, the
/// transfer slot for the answer, and `httpd`'s inbox for the files. So `getReceivedFiles`,
/// `openReceivedFile` and `deleteReceivedFile` work for Quick Share with no new AIDL and no
/// change in the app: a received file is a received file, whichever protocol brought it.
struct QsHost {
    id: i64,
    peer: String,
    transfers: Transfers,
    callbacks: Callbacks,
    auto_accept: Arc<AtomicBool>,
    // The actual on-disk paths this connection created (non_clobbering returns a String).
    // Tracked because non_clobbering() may rename a file, so the destination is not
    // derivable from the peer's name -- and discard() on a mid-transfer cancel has to
    // delete exactly what was opened.
    created: std::sync::Mutex<Vec<String>>,
}

impl quickshare::connection::Host for QsHost {
    fn id(&self) -> i64 {
        self.id
    }


    fn ask(&self, transfer_id: i64, from: &str, files: &[tarish_protocol::sharing::FileMetadata]) -> bool {
        let names: Vec<String> = files.iter().map(|f| f.name.clone()).collect();
        let total: i64 = files.iter().map(|f| f.size.max(0)).sum();

        // Turned off deliberately, by the person or by their organisation. Nothing to ask.
        if self.auto_accept.load(Ordering::SeqCst) {
            log::info!(
                "quickshare: accepting {} file(s) from {from} without asking",
                names.len()
            );
            return true;
        }

        {
            let Ok(cbs) = self.callbacks.lock() else {
                return false;
            };
            // NO CLIENT, NO TRANSFER. An offer nobody can see must not be accepted on the
            // person's behalf -- this writes files to their device. Refusing is the safe
            // answer and it is the same one the AirDrop path gives.
            if cbs.is_empty() {
                log::info!("quickshare: offer from {from} refused — no client to ask");
                return false;
            }
            for cb in cbs.iter() {
                let _ = cb.onTransferOffered(
                    self.id,
                    &self.peer,
                    &names,
                    total,
                    PROTOCOL_QUICKSHARE,
                );
            }
        }
        // A person has to pick the phone up and read it. Shorter than the sender's own
        // patience would make us the reason it failed.
        // WAIT ON THE ID THE CLIENT WAS TOLD, not this connection's own id. They are two
        // different slots -- main.rs mints one for QsHost and connection.rs mints another
        // for the offer it announces -- and await_answer drops any answer whose id does
        // not match, on purpose. So respondToOffer() could never satisfy this wait and
        // every incoming Quick Share transfer ended "timed out unanswered — refused",
        // with the sender reporting a clean send and the receiver keeping nothing.
        match self.transfers.await_answer(transfer_id, Duration::from_secs(60)) {
            Some(accepted) => {
                log::info!("quickshare: offer from {from} {}", if accepted { "accepted" } else { "declined" });
                accepted
            }
            // Nobody answered. A silent timeout is a refusal: accepting because a prompt
            // went unanswered is the one outcome a person cannot undo.
            None => {
                log::info!("quickshare: offer from {from} timed out unanswered — refused");
                false
            }
        }
    }

    fn create(&self, name: &str) -> std::io::Result<Box<dyn std::io::Write + Send>> {
        // The name came off the wire and is hostile until proven otherwise. safe_leaf
        // strips any path structure; non_clobbering then refuses to overwrite, so a peer
        // cannot replace a file it sent earlier -- or one AirDrop put there.
        let leaf = httpd::safe_leaf(name).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("refusing the peer's file name {name:?}"),
            )
        })?;
        let dest = httpd::non_clobbering(httpd::INBOX, &leaf);
        let f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&dest)?;
        // Remember the real path so a cancel can delete exactly this file, whatever
        // non_clobbering named it.
        if let Ok(mut v) = self.created.lock() {
            v.push(dest.clone());
        }
        log::info!("quickshare: writing {leaf} to the inbox");
        Ok(Box::new(f))
    }

    fn discard(&self) {
        // A cancelled transfer streamed a partial straight to the inbox. Remove every file
        // this connection opened so the app never collects a truncated one.
        if let Ok(mut v) = self.created.lock() {
            for p in v.drain(..) {
                if let Err(e) = std::fs::remove_file(&p) {
                    log::warn!("quickshare: could not discard partial {p:?}: {e}");
                }
            }
        }
    }

    fn progress(&self, done: u64, total: u64) {
        // Keep the transfer slot alive while bytes move (see try_begin / STALE_TRANSFER).
        self.transfers.touch();
        let Ok(cbs) = self.callbacks.lock() else {
            return;
        };
        for cb in cbs.iter() {
            let _ = cb.onTransferProgress(self.id, done as i64, total as i64);
        }
    }

    fn cancelled(&self) -> bool {
        self.transfers.is_cancelled(self.id)
    }

    fn host_group(&self) -> Option<quickshare::connection::WifiGroup> {
        // ASKED REPEATEDLY, NOT ONCE.
        //
        // onGroupNeeded is oneway, so it reaches whoever is registered at the instant it is
        // sent and nobody else. On an INBOUND transfer the component that answers it --
        // TransferService -- is started by the app just after it responds to the offer, and
        // the daemon fires this the moment ask() returns. The callback lost that race every
        // time: the question went out before anyone was listening, and the transfer then sat
        // out the whole timeout waiting for an answer to a question nobody heard.
        //
        // Re-asking is the fix rather than a longer wait, because waiting cannot help once
        // the frame has been sent to nobody. Cheap: one oneway call every two seconds, and it
        // stops the moment an answer lands.
        // Hosting a Wi-Fi Direct group is a P2P_GO operation, which needs the chip's single
        // Wi-Fi P2P slot that AWDL holds. Take AWDL down and wait for the slot to free before
        // the client calls createGroup(), or the group cannot form against a live ART
        // interface. Held until finish() at transfer end so the group survives the transfer.
        // If AirDrop owns the radio and will not yield, do NOT host -- return None so the
        // transfer stays on its current medium (the peer sees us busy) rather than tearing
        // AWDL down under a live AirDrop transfer.
        if !self.transfers.arm_wifi_direct() {
            log::info!("quickshare: not hosting a Wi-Fi Direct group -- AirDrop owns the radio");
            return None;
        }
        let deadline = std::time::Instant::now() + GROUP_WAIT;
        let mut asked_anyone = false;
        while std::time::Instant::now() < deadline {
            // Open the request BEFORE asking: an answer that races back before the flag
            // is set would be discarded as unsolicited.
            self.transfers.want_group(self.id);
            {
                let Ok(cbs) = self.callbacks.lock() else {
                    self.transfers.stop_wanting_group();
                    return None;
                };
                for cb in cbs.iter() {
                    let _ = cb.onGroupNeeded(self.id);
                    asked_anyone = true;
                }
            }
            if let Some(g) = self.transfers.await_group(self.id, GROUP_ASK_INTERVAL) {
                self.transfers.stop_wanting_group();
                return Some(quickshare::connection::WifiGroup {
                    ssid: g.ssid,
                    passphrase: g.passphrase,
                    go_address: g.goAddress,
                    frequency: g.frequency,
                });
            }
        }
        self.transfers.stop_wanting_group();
        if asked_anyone {
            log::info!("quickshare: no client answered the group request; staying put");
        } else {
            log::info!("quickshare: no client bound to host a group; staying put");
        }
        None
    }
}

/// How long an inbound transfer waits for a client to stand up a Wi-Fi Direct group.
///
/// Forming one is 4-8s on real hardware and slower on a cold driver, and the sender is
/// waiting on our acceptance throughout -- so this is a real pause, paid once, against a
/// transfer that would otherwise run at a hundredth of the speed.
const GROUP_WAIT: Duration = Duration::from_secs(30);

/// How often to repeat the request while waiting. See host_group.
const GROUP_ASK_INTERVAL: Duration = Duration::from_secs(2);

/// Report how a Quick Share send ended, once, in one place.
///
/// Declined is not a failure: someone on the other device said no, and reporting that as
/// "could not send" invites a retry that will be refused again.
fn report_outcome(id: i64, outcome: std::io::Result<bool>, progress: &TransferProgress) {
    match outcome {
        Ok(true) => {
            log::info!("quickshare: transfer {id} complete");
            progress.finished(STATUS_OK);
        }
        // A cancel of our own is NOT the peer declining, and saying so put "the other
        // device turned it down" on screen after the user pressed Cancel themselves.
        // Both end the transfer the same way; only one is somebody else's decision.
        Ok(false) if progress.transfers.is_cancelled(id) => {
            log::info!("quickshare: transfer {id} cancelled");
            progress.finished(STATUS_FAILED);
        }
        Ok(false) => {
            log::info!("quickshare: transfer {id} was not accepted");
            progress.finished(STATUS_DECLINED);
        }
        Err(e) => {
            log::warn!("quickshare: transfer {id} failed: {e}");
            progress.finished(STATUS_FAILED);
        }
    }
}

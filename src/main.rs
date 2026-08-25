//! barqd — Barq AWDL transport daemon.
//!
//! Holds the AWDL link up so nothing above it has to. This is the privileged
//! half of Barq: it runs as `system` with CAP_NET_ADMIN and CAP_NET_RAW, drives
//! the vendor library, and **parses nothing from the network**. Everything that
//! reads remote input — mDNS, TLS, HTTP, Apple plists, cpio — lives in the
//! unprivileged `barqsharingd`, so a bug in a parser is not a bug in a process
//! holding those capabilities. See docs/ARCHITECTURE.md.
//!
//! Why a daemon at all: an Android app that wants to keep running must hold a
//! foreground service and therefore a permanent notification. A native daemon
//! started by init has no such obligation, so the client app can be an ordinary
//! app that is closed most of the time.

mod mosey;
mod route;

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

const IFACE: &str = "mosey0";

/// AWDL channel. 149 is what the vendor stack uses on this hardware; 5745 MHz.
const CHANNELS: &[u8] = &[149];

/// Serialised `StartMoseyConfig`: field 1 = is_dbs_supported, field 6 =
/// rate_adaptation. These four bytes are what the vendor daemon itself passes.
const CONFIG: &[u8] = &[0x08, 0x01, 0x30, 0x01];

const MAX_MDNS: u32 = 0x7fff_ffff;

/// Whether anything actually wants the radio. Written by barqsharingd, read here.
///
/// A property rather than binder or an init service control, for two reasons.
///
/// Binder would put an IPC parser inside the process that holds CAP_NET_ADMIN,
/// which is the one thing this daemon is structured to avoid. A property read is
/// a shared-memory load of a single boolean -- no parsing, no attack surface.
///
/// `ctl.start`/`ctl.stop` would work and would NOT leak privilege (init applies
/// the .rc's user, capabilities and seclabel regardless of who asked), but it
/// would hand an unprivileged caller the ability to start and stop a privileged
/// process. That is a new authority, and a battery optimisation is not worth
/// creating one. barqd stays init-started, exactly once, at boot.
const WANT_PROP: &str = "barq.awdl.wanted";

/// How often to look at it. This is a shared-memory read, not a syscall, so the
/// cost is far below the noise floor -- the session itself was measured at 6.5%
/// of a core, and this is not measurable next to it.
const POLL: Duration = Duration::from_millis(500);

static RUNNING: AtomicBool = AtomicBool::new(true);

extern "C" fn on_signal(_sig: libc::c_int) {
    RUNNING.store(false, Ordering::SeqCst);
}

fn install_signal_handlers() {
    // Cast through a function POINTER, not straight from the function item:
    // `on_signal as sighandler_t` is "direct cast of function item into an
    // integer", which current rustc rejects.
    let handler = on_signal as extern "C" fn(libc::c_int) as libc::sighandler_t;
    // SAFETY: on_signal only touches an AtomicBool, which is async-signal-safe.
    unsafe {
        libc::signal(libc::SIGTERM, handler);
        libc::signal(libc::SIGINT, handler);
    }
}

/// Country code for the regulatory domain, read from the system property the
/// platform already maintains so barqd does not invent its own notion of where
/// the device is. The vendor library rejects anything that is not two letters.
///
/// Read through libc rather than a helper crate: this process holds
/// CAP_NET_ADMIN, so every dependency is part of its threat model, and one
/// property read does not justify one.
fn read_property(name: &str) -> Option<String> {
    let cname = std::ffi::CString::new(name).ok()?;
    // PROP_VALUE_MAX is 92; 128 is comfortably clear of it.
    let mut buf = [0u8; 128];
    // SAFETY: cname is NUL-terminated and buf is PROP_VALUE_MAX-sized or larger,
    // which is the contract __system_property_get requires.
    let n = unsafe {
        libc::__system_property_get(cname.as_ptr(), buf.as_mut_ptr() as *mut libc::c_char)
    };
    if n <= 0 {
        return None;
    }
    let s = std::str::from_utf8(&buf[..n as usize]).ok()?;
    Some(s.to_string())
}

/// Regulatory country, in priority order.
///
/// WHERE THIS ACTUALLY COMES FROM
///
/// An earlier version read only the three Wi-Fi sources and concluded "no country"
/// whenever they were empty, with a message blaming Wi-Fi never having associated.
/// That was wrong, and it cost a device: on a phone with a SIM and no Wi-Fi ever
/// connected, the platform knew the country perfectly well --
///
///     Wifi Country Code = QA
///     mCountryCodeFromDriverQA   SupportedChannelListIn5g[149, 153, 157, 161]
///
/// -- while `persist.vendor.wifi.country` was empty and `ro.boot.wificountrycode`
/// was "00". Channel 149 was permitted the whole time. It worked on the development
/// phone only because that one had associated to an AP at some point, which persists
/// the country; a phone that never had would never come up, and the log would send
/// you looking at Wi-Fi.
///
/// The SIM is authoritative when Wi-Fi has not persisted anything, and it is where
/// the platform's own WifiCountryCode looks too.
///
///   1. `persist.barq.country`            explicit operator override
///   2. `persist.vendor.wifi.country`     what the Wi-Fi stack persisted, if anything
///   3. `gsm.operator.iso-country`        the network the SIM is registered on
///   4. `gsm.sim.operator.iso-country`    the SIM's home country
///   5. `ro.boot.wificountrycode`         boot default, usually "00" -- last on purpose
///
/// Returns None only when nothing knows. "00" is never accepted: the vendor library
/// takes it, logs a bring-up that looks fine, and then returns NULL.
fn country_code() -> Option<String> {
    for prop in [
        "persist.barq.country",
        "persist.vendor.wifi.country",
        "gsm.operator.iso-country",
        "gsm.sim.operator.iso-country",
        "ro.boot.wificountrycode",
    ] {
        let Some(raw) = read_property(prop) else { continue };

        // Multi-SIM devices publish one value per slot, comma separated, so a
        // single-SIM phone reads "qa," -- which fails a length check on the whole
        // string and is exactly how this was missed.
        let v = raw.split(',').next().unwrap_or("").trim().to_uppercase();

        if v.len() == 2 && v.chars().all(|c| c.is_ascii_alphabetic()) {
            log::info!("country {v} (from {prop})");
            return Some(v);
        }
        if v == "00" {
            log::debug!("{prop}=00 — the world regulatory domain, no country set");
        }
    }
    None
}

/// Whether anything actually wants the radio right now.
///
/// Defaults to ON when the property is absent, and the failure mode is why. If
/// barqsharingd never writes it -- a policy denial, a crash, an older build --
/// defaulting off would mean AWDL never comes up and Barq is silently dead.
/// Defaulting on means the worst case is the battery cost we had before this
/// existed, with sharing still working. Fail towards working.
fn wants_radio() -> bool {
    match read_property(WANT_PROP) {
        Some(v) => v.trim() != "0",
        None => true,
    }
}

/// A live AWDL link: the vendor session, plus the routing that makes the
/// interface usable from userspace.
///
/// Bundled into one value so acquiring and releasing cannot drift apart. The
/// previous arrangement did all of this once in `main` and never undid it,
/// which was correct only because the process never let go.
struct Link {
    /// Held and never read. Dropping it is the entire point: mosey_stop runs from
    /// Session's Drop, which is what takes the radio and the interface down.
    _session: mosey::Session,
}

impl Link {
    fn acquire() -> Result<Self, String> {
        // Read the country at ACQUIRE time, not at start-up. It comes from the SIM
        // or from an AP, so at boot there may not be one yet -- barqd used to
        // exit(1) in that case and rely on init to retry. Asking when we actually
        // need it removes that race entirely.
        let country = country_code().ok_or_else(|| {
            format!(
                "no regulatory country from any source: persist.barq.country, \
                 persist.vendor.wifi.country, gsm.operator.iso-country, \
                 gsm.sim.operator.iso-country, ro.boot.wificountrycode. With no SIM and \
                 no Wi-Fi association there is nothing to read. Channel {} is not \
                 permitted in the world domain, so the radio will refuse to come up. \
                 Set one explicitly: setprop persist.barq.country <CC>",
                CHANNELS[0]
            )
        })?;

        let session = mosey::Session::start(
            CHANNELS,
            &country,
            MAX_MDNS,
            mosey::OpMode::Netlink,
            CONFIG,
        )?;

        log::info!(
            "AWDL session up, handle={:p}, channel={}, country={}",
            session.handle(),
            CHANNELS[0],
            country
        );

        // The interface appears a moment after the call returns.
        std::thread::sleep(Duration::from_secs(2));
        match route::add_link_local(IFACE) {
            Ok(()) => log::info!(
                "route: fe80::/64 dev {IFACE} table {}",
                route::table_id(IFACE)
            ),
            Err(e) => log::warn!(
                "link-local route not added ({e}) — sockets on {IFACE} will get ENETUNREACH"
            ),
        }

        // A route in a table nothing consults does nothing. Android picks tables with
        // fib rules keyed on fwmark, and gets no rule for an interface it does not
        // manage -- so the route above sat in table N, was never looked up, and every
        // lookup fell through to "32000: from all unreachable".
        match route::add_rule(IFACE) {
            Ok(()) => log::info!("rule: oif {IFACE} lookup {}", route::table_id(IFACE)),
            Err(e) => log::warn!(
                "routing rule not added ({e}) — the route on {IFACE} exists but nothing \
                 will consult it, so the device stays unreachable"
            ),
        }

        Ok(Link { _session: session })
    }
}

impl Drop for Link {
    fn drop(&mut self) {
        // Take the rule out first, while the interface is still there. The routes
        // themselves go with the interface, but a fib rule does not: it is keyed by
        // priority and would otherwise pile up one per acquire.
        match route::remove_rule() {
            Ok(()) => log::info!("rule removed"),
            Err(e) => log::warn!("could not remove routing rule: {e}"),
        }
        log::info!("releasing AWDL session");
        // `session` drops here, which calls mosey_stop and takes the interface down.
    }
}

fn main() {
    android_logger::init_once(
        android_logger::Config::default()
            .with_tag("barqd")
            .with_max_level(log::LevelFilter::Info),
    );

    install_signal_handlers();
    log::info!("starting; radio follows {WANT_PROP}");

    // The session is held only while something wants it. Holding it from boot cost
    // 6.5% of a core continuously with no client bound and the screen off -- the
    // vendor library runs its own threads inside this process, so an idle AWDL link
    // is not free the way an idle socket is.
    //
    // What this daemon does NOT do is stop and restart itself. It stays init-started,
    // once, at boot, keeping its capabilities for its whole life; only the session
    // comes and goes. See WANT_PROP.
    let mut link: Option<Link> = None;
    let mut last_want: Option<bool> = None;
    let mut retry_at = std::time::Instant::now();
    let mut last_error = String::new();

    while RUNNING.load(Ordering::SeqCst) {
        let want = wants_radio();
        if last_want != Some(want) {
            log::info!("{WANT_PROP}={}", if want { 1 } else { 0 });
            last_want = Some(want);
            retry_at = std::time::Instant::now();   // a fresh request retries at once
        }

        match (want, link.is_some()) {
            (true, false) if std::time::Instant::now() >= retry_at => {
                match Link::acquire() {
                    Ok(l) => {
                        link = Some(l);
                        last_error.clear();
                    }
                    Err(e) => {
                        // Say it once per distinct cause. Retrying every 500ms and
                        // logging each time would bury everything else in the buffer.
                        if e != last_error {
                            log::error!("{e}");
                            last_error = e;
                        }
                        retry_at = std::time::Instant::now() + Duration::from_secs(5);
                    }
                }
            }
            (false, true) => link = None,   // Drop does the work
            _ => {}
        }

        std::thread::sleep(POLL);
    }

    log::info!("shutting down");
    drop(link);
}

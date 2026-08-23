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

const IFACE: &str = "mosey0";

/// AWDL channel. 149 is what the vendor stack uses on this hardware; 5745 MHz.
const CHANNELS: &[u8] = &[149];

/// Serialised `StartMoseyConfig`: field 1 = is_dbs_supported, field 6 =
/// rate_adaptation. These four bytes are what the vendor daemon itself passes.
const CONFIG: &[u8] = &[0x08, 0x01, 0x30, 0x01];

const MAX_MDNS: u32 = 0x7fff_ffff;

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

/// Regulatory country, in priority order:
///
///   1. `persist.barq.country` — explicit operator override
///   2. `ro.boot.wificountrycode`, `persist.vendor.wifi.country` — the platform's
///
/// Returns None when the platform has no country, rather than silently
/// substituting the world domain. See the warning in `main`: "00" is accepted by
/// the vendor library and then fails to bring the radio up, which is a genuinely
/// confusing way to find out.
fn country_code() -> Option<String> {
    for prop in [
        "persist.barq.country",
        "ro.boot.wificountrycode",
        "persist.vendor.wifi.country",
    ] {
        if let Some(v) = read_property(prop) {
            let v = v.trim().to_uppercase();
            if v.len() == 2 && v.chars().all(|c| c.is_ascii_alphabetic()) {
                log::info!("country {v} (from {prop})");
                return Some(v);
            }
            if v == "00" {
                log::warn!("{prop}=00 — the world regulatory domain, no country set");
            }
        }
    }
    None
}

fn main() {
    android_logger::init_once(
        android_logger::Config::default()
            .with_tag("barqd")
            .with_max_level(log::LevelFilter::Info),
    );

    install_signal_handlers();
    log::info!("starting");

    // A device with no regulatory country cannot legally use channel 149, and the
    // failure is silent: the vendor library ACCEPTS "00", logs a bring-up that
    // looks fine, and then returns NULL. Say so before that happens.
    let country = match country_code() {
        Some(c) => c,
        None => {
            log::error!(
                "no regulatory country. The platform reports none, which usually \
                 means Wi-Fi has never associated — the country normally comes \
                 from the AP. Channel {} is not permitted in the world domain, so \
                 the radio will refuse to come up.",
                CHANNELS[0]
            );
            log::error!("set one explicitly:  setprop persist.barq.country <CC>");
            std::process::exit(1);
        }
    };

    let session = match mosey::Session::start(
        CHANNELS,
        &country,
        MAX_MDNS,
        mosey::OpMode::Netlink,
        CONFIG,
    ) {
        Ok(s) => s,
        Err(e) => {
            log::error!("{e}");
            std::process::exit(1);
        }
    };

    log::info!(
        "AWDL session up, handle={:p}, channel={}, country={}",
        session.handle(),
        CHANNELS[0],
        country
    );

    // The interface appears a moment after the call returns.
    std::thread::sleep(std::time::Duration::from_secs(2));
    match route::add_link_local(IFACE) {
        Ok(()) => log::info!(
            "route: fe80::/64 dev {IFACE} table {}",
            route::table_id(IFACE)
        ),
        Err(e) => log::warn!(
            "link-local route not added ({e}) — sockets on {IFACE} will get ENETUNREACH"
        ),
    }

    // The session lives exactly as long as this process. Exiting tears down the
    // interface and the device stops being discoverable, so hold here and let
    // Drop stop it cleanly on SIGTERM.
    while RUNNING.load(Ordering::SeqCst) {
        // SAFETY: pause(2) with no arguments.
        unsafe { libc::pause() };
    }

    log::info!("shutting down");
    drop(session);
}

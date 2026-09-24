//! tarishd — Tarish AWDL transport daemon.
//!
//! Holds the AWDL link up so nothing above it has to. This is the privileged
//! half of Tarish: it runs as `system` with CAP_NET_ADMIN and CAP_NET_RAW, drives
//! the vendor library, and **parses nothing from the network**. Everything that
//! reads remote input — mDNS, TLS, HTTP, Apple plists, cpio — lives in the
//! unprivileged `tarishsharingd`, so a bug in a parser is not a bug in a process
//! holding those capabilities. See docs/ARCHITECTURE.md.
//!
//! Why a daemon at all: an Android app that wants to keep running must hold a
//! foreground service and therefore a permanent notification. A native daemon
//! started by init has no such obligation, so the client app can be an ordinary
//! app that is closed most of the time.

mod mosey;
mod nl80211;
mod route;

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

/// The AWDL data interface. Configurable so the daemon can run over Google's `libmosey`
/// (`mosey0`) or over `tarish-link` (`tlink0`): `$TARISH_IFACE`, then
/// `persist.tarish.iface`, else the default. Resolved once.
///
/// Default is `tlink0` -- our tlink shim's interface. It MUST match the shim's own default
/// (tlink-shim `data_iface()` also defaults to `tlink0`), or on a clean device with
/// the property unset the shim brings up `tlink0` while this waits for a different name
/// forever. It was `mosey0` back when we ran over Google's libmosey; tlink replaced it.
/// Has the AWDL link died underneath us?
///
/// THE DAEMON MUST NOT TRUST ITS OWN `link` VARIABLE. Turning Wi-Fi off and on reloads the
/// wonder driver, which takes `wondertap0` down and leaves `tlink0` behind as a stale
/// interface. `link` is still `Some`, so the poll loop's `(want, link.is_some())` match reads
/// `(true, true)` and does nothing — forever. Observed 2026-09-24 on blazer: wondertap0 DOWN,
/// tarish.awdl.wanted=1 ignored, and `ctl.restart tarishd` fixing it instantly, which is what
/// proved the radio was never the problem.
///
/// CHECKS wondertap0, NOT tlink0. tlink0 survives the teardown looking perfectly healthy —
/// it is the interface whose presence means least. wondertap0 is the one the driver owns.
///
/// Reads /sys/class/net, which this domain can already read (see the radiotap0 survey) and
/// which needs no netlink socket, so a wedged netlink path cannot hide a dead link.
///
/// ABSENT AND DOWN ARE BOTH DEAD. A missing file means the driver removed the interface; a
/// down operstate means it is there and not running. Neither can carry AWDL.
fn awdl_link_is_dead() -> bool {
    match std::fs::read_to_string("/sys/class/net/wondertap0/operstate") {
        Ok(v) => {
            let v = v.trim();
            v == "down" || v == "notpresent"
        }
        Err(_) => true, // gone entirely
    }
}

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
/// The infrastructure interface whose channel AWDL has to schedule around.
const STA_IFACE: &str = "wlan0";

/// AWDL channels to try, in order of preference.
///
/// Not one constant, because one constant is wrong somewhere. 149 (5745 MHz,
/// U-NII-3) is what the vendor stack uses here and what Apple prefers, but it is not
/// permitted for Wi-Fi in much of the EU. 44 (5220 MHz, U-NII-2A) is the other 5 GHz
/// channel Apple uses, and 6 (2.4 GHz) is the social channel every region allows.
///
/// The regulatory decision is NOT ours to compute: the vendor library is given the
/// country and refuses a channel it may not use. So offer candidates and let it
/// choose -- the one it accepts is by definition the one that is legal and supported
/// here, which is a better answer than any table we could maintain.
/// AWDL social channels by band. Apple uses 6 on 2.4 GHz, 44 and 149 on 5 GHz.
const CHANNELS_24: &[u8] = &[6];
const CHANNELS_5: &[u8] = &[149, 44];

/// Pick AWDL's channel in the OPPOSITE band from the Wi-Fi association.
///
/// THIS IS THE WHOLE COEXISTENCE STORY, AND IT IS NOT ABOUT CHANNEL HOPPING.
///
/// `is_dbs_supported=true`: the chip runs 2.4 GHz and 5 GHz simultaneously. What it
/// cannot do is sit on two different 5 GHz channels. Measured on mustang with Wi-Fi
/// associated at 5700 MHz, all three with channel_hopping=true:
///
///     channels=[6,44,149]   -> used 6     Wi-Fi COMPLETED, stable
///     channels=[149,44,6]   -> used 149   Wi-Fi DISCONNECTED within 3s
///     channels=[149]        -> used 149   Wi-Fi DISCONNECTED within 3s
///
/// So the library takes the FIRST channel in the list and channel_hopping changes
/// nothing here. Two earlier hypotheses died on that bench: that hopping would let
/// the radio interleave, and that telling the scheduler `sta_channel_freq` would be
/// enough -- the library decoded 5520 correctly and the association still dropped.
///
/// With no association we prefer 2.4 GHz, NOT 5 GHz -- see the comment on the `0`
/// arm below. The list is still tried in order and the vendor library refuses a
/// channel it may not use, so regulatory domains remain its decision, not ours.
fn channels_for(sta_freq_mhz: i32) -> Vec<&'static [u8]> {
    match sta_freq_mhz {
        // PREFER 5 GHz (ch149) WHENEVER THERE IS NO 5 GHz ASSOCIATION TO PROTECT.
        //
        // Finding 120: on ch149 the AWDL link is ~3.4 MB/s and discovers reliably; on ch6 it is
        // ~138 KB/s and flaky. Both symptoms the test team reported (slow transfers, unstable
        // discovery) were this channel choice, not the daemon. So default to 5 GHz.
        //
        // The one case we still keep on 2.4 GHz is a LIVE 5 GHz Wi-Fi association (`f >= 5000`):
        // this chip is DBS (2.4 + ONE 5 GHz channel), so AWDL on a *different* 5 GHz channel kills
        // that association (measured). That guard stays.
        //
        // The old code also kept the `0` (adapter on, not associated) case on 2.4, to avoid AWDL
        // locking Wi-Fi out of associating on 5 GHz. That trade is no longer worth it: AWDL is
        // on-demand (up only during an active AirDrop session, released when idle), so Wi-Fi can
        // associate on 5 GHz whenever AirDrop is not in use, and during an active transfer the
        // ch149 speed/discovery win beats a background join. So `0` now prefers 5 GHz too.
        f if f < 0 => vec![CHANNELS_5, CHANNELS_24],     // Wi-Fi off -> the good band (5 GHz)
        0 => vec![CHANNELS_5, CHANNELS_24],              // no association -> 5 GHz too (finding 120)
        f if f >= 5000 => vec![CHANNELS_24, CHANNELS_5], // live 5 GHz assoc -> AWDL on 2.4 (DBS guard)
        _ => vec![CHANNELS_5, CHANNELS_24],              // Wi-Fi on 2.4 -> AWDL on 5
    }
}

/// Would AWDL on these channels land in the same band as the association?
///
/// The split matches channels_for() exactly and deliberately: if the two disagreed,
/// one of them would pick a candidate the other considers fatal.
///
/// 6 GHz COUNTS WITH 5, AND THIS IS NOW MEASURED rather than assumed. On mustang
/// (BCM4390, the chip that coexists at all), associated at 6215 MHz:
///
///     AWDL on channel 6   (2.4 GHz)  -> both alive, 45s soak
///     AWDL on channel 149 (5 GHz)    -> Wi-Fi gone in under 20s, still gone at 60s
///
/// So 6 GHz is not a third independent band here: it shares a radio chain with 5 GHz,
/// and `is_dbs_supported` means 2.4 plus ONE of the upper bands, not all three. A 6 GHz
/// association therefore has to be protected from 5 GHz AWDL exactly as a 5 GHz one is,
/// which is what this grouping does.
fn same_band_as_sta(channels: &[u8], sta_freq_mhz: i32) -> bool {
    if sta_freq_mhz <= 0 {
        return false;
    }
    let sta_is_24 = sta_freq_mhz < 5000;
    channels.iter().all(|&c| (c <= 14) == sta_is_24)
}

/// Serialised `StartMoseyConfig`: field 1 = is_dbs_supported, field 6 =
/// rate_adaptation. These four bytes are what the vendor daemon itself passes.
/// Serialised `StartMoseyConfig`. The library logs how it decoded this:
///
///     is_dbs_supported, sta_channel_freq, daemon_amsdu, driver_ampdu,
///     channel_hopping, rate_adaptation, maxAmsduSizeMode
///
/// so the protobuf field numbers are 1..7 in that order. We set field 1
/// (is_dbs_supported) and field 6 (rate_adaptation), which is what the vendor
/// daemon passes, plus field 2 when we know it -- see `mosey_config`.
const CFG_DBS_SUPPORTED: [u8; 2] = [0x08, 0x01];      // field 1, varint 1
const CFG_RATE_ADAPTATION: [u8; 2] = [0x30, 0x01];    // field 6, varint 1
const CFG_STA_FREQ_TAG: u8 = 0x10;                    // field 2, varint

/// Build the config, telling the AWDL scheduler which channel Wi-Fi is using.
///
/// WHY THIS MATTERS MORE THAN IT LOOKS
///
/// We were passing sta_channel_freq = 0, i.e. "no idea". One radio cannot sit on
/// two 5 GHz channels at once, so with the STA channel unknown the stack parks AWDL
/// on its own channel and the Wi-Fi association dies. Measured on mustang, Wi-Fi
/// associated at 5520 MHz and AWDL asked for 149 (5745 MHz):
///
///     AWDL off    COMPLETED @ 5520MHz, steady
///     AWDL up     DISCONNECTED, Frequency -1MHz, within 3 seconds
///                 WifiScanningService: Scan failed - unspecified reason, repeating
///
/// Stock does not do this, which is the point: Google's daemon knows the STA channel
/// and can interleave its availability windows with it. Told the same thing, the
/// library can schedule around the association instead of standing on it.
fn mosey_config(sta_freq_mhz: i32) -> Vec<u8> {
    let mut v = Vec::with_capacity(8);
    v.extend_from_slice(&CFG_DBS_SUPPORTED);
    if sta_freq_mhz > 0 {
        v.push(CFG_STA_FREQ_TAG);
        let mut n = sta_freq_mhz as u32;
        while n >= 0x80 {
            v.push((n as u8 & 0x7f) | 0x80);
            n >>= 7;
        }
        v.push(n as u8);
    }
    v.extend_from_slice(&CFG_RATE_ADAPTATION);
    v
}

/// The frequency Wi-Fi is currently associated on, in MHz, or 0 if unknown.
///
/// This is not just an input to our own band choice. It is `sta_channel_freq` in
/// StartMoseyConfig, which is how AWDL schedules slots on the AP's channel -- see
/// nl80211.rs for the protocol reference. Reporting 0 means the radio never goes
/// back to the AP.
///
/// It used to come only from a property that tarishsharingd publishes on behalf of the
/// client, which meant it was 0 whenever the app was closed -- i.e. nearly always,
/// since closing it is what the radio gate is for. Measured on mustang: every single
/// start logged `sta_channel_freq=0` while the phone sat associated at 5520 MHz, and
/// the band-avoidance branch never once executed.
///
/// 0 is still the honest answer when there is genuinely no association.
/// Raw override for the whole StartMoseyConfig, as hex.
///
/// Exists to characterise coexistence without a build per hypothesis. Each
/// build-push-test cycle is minutes; each hypothesis about a vendor blob's config is
/// cheap and usually wrong, so the two should not be coupled. Unset in normal use.
///
///     setprop persist.tarish.mosey_config 0801109 02b28013001
fn config_override() -> Option<Vec<u8>> {
    let hex = read_property("persist.tarish.mosey_config")?;
    let hex: String = hex.chars().filter(|c| !c.is_whitespace()).collect();
    if hex.is_empty() || hex.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(hex.len() / 2);
    for i in (0..hex.len()).step_by(2) {
        out.push(u8::from_str_radix(&hex[i..i + 2], 16).ok()?);
    }
    log::warn!("using persist.tarish.mosey_config override: {hex}");
    Some(out)
}

/// Override for which channels to offer, e.g. `6` or `44,149`.
///
/// Same reason as the config override: the channel is a coexistence variable and
/// should be testable without a rebuild. Empty means pick by band.
fn channel_override() -> Option<Vec<u8>> {
    let v = read_property("persist.tarish.channels")?;
    let list: Vec<u8> = v
        .split(',')
        .filter_map(|c| c.trim().parse::<u8>().ok())
        .collect();
    if list.is_empty() {
        return None;
    }
    log::warn!("using persist.tarish.channels override: {list:?}");
    Some(list)
}

fn sta_frequency() -> i32 {
    // tarish.awdl.sta_freq is what tarishsharingd publishes from the client, which is the
    // only component that can see the Wi-Fi state at all -- tarishd and tarishsharingd are
    // native daemons with no framework access, and nothing exposes the association
    // frequency as a readable file. persist.tarish.sta_freq stays as a manual override
    // for bench work.
    // An explicit bench override wins, so a frequency can be forced without a build.
    if let Some(f) = read_property("persist.tarish.sta_freq")
        .and_then(|v| v.trim().parse::<u32>().ok())
        .filter(|f| (2000..=7200).contains(f))
    {
        log::warn!("using persist.tarish.sta_freq override: {f} MHz");
        return f as i32;
    }

    // Then ask the kernel directly. This is the path that actually runs: the property
    // below is published by tarishsharingd from the client, and the client is closed for
    // almost all of the device's life by design.
    match nl80211::frequency_of(STA_IFACE) {
        Ok(f) if (2000..=7200).contains(&f) => return f as i32,
        Ok(_) => {}  // up but not associated -- no channel to avoid, 0 is correct
        Err(e) => log::warn!("nl80211 could not report {STA_IFACE} frequency: {e}"),
    }

    // -1 IS A REAL ANSWER HERE, NOT A PARSE FAILURE.
    //
    // The client publishes -1 when the Wi-Fi adapter is switched off, which the kernel
    // query above cannot distinguish from "the interface is missing for some other
    // reason" -- with Wi-Fi off, wlan0 is simply gone and nl80211 errors. Folding it
    // into 0 loses the one case where 5 GHz is free, so it is kept.
    read_property("tarish.awdl.sta_freq")
        .and_then(|v| v.trim().parse::<i32>().ok())
        .map(|f| if (2000..=7200).contains(&f) { f } else if f < 0 { -1 } else { 0 })
        .unwrap_or(0)
}

const MAX_MDNS: u32 = 0x7fff_ffff;

/// Whether anything actually wants the radio. Written by tarishsharingd, read here.
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
/// creating one. tarishd stays init-started, exactly once, at boot.
const WANT_PROP: &str = "tarish.awdl.wanted";

/// Whether the lockdown exemption is currently earned.
///
/// Set by tarishsharingd when the app reports an authenticated window, cleared when it
/// closes. Read here, and the only thing it changes is the PRIORITY of the fib rule: above
/// Android's kill-switch while true, below it while false. See route.rs for why that is the
/// whole of the privilege.
///
/// Same reasoning as WANT_PROP for using a property: this daemon holds CAP_NET_ADMIN and a
/// property read is a shared-memory load of one boolean, with no parser to attack. It lives
/// under the `tarish.awdl.` prefix, which property_contexts already labels, so it needs no
/// new SELinux type -- and tarishsharingd already has set_prop on that type while tarishd
/// has only get_prop, which is the direction this needs.
///
/// FAIL-CLOSED BY CONSTRUCTION: anything other than "1" is false, so a missing property, an
/// unreadable one, a crashed tarishsharingd or a stale value all mean NOT exempt. The
/// failure mode of this feature is losing the exemption, never keeping it.
const EXEMPT_PROP: &str = "tarish.awdl.exempt";
/// Whether a VPN kill-switch is really in force. Published by tarishd because only tarishd
/// can see it, and read by tarishsharingd to answer the app's isLockdownActive().
///
/// Under the `tarish.awdl.` prefix ON PURPOSE: that prefix is already labelled
/// tarish_awdl_prop, so this key needs no new property_contexts entry. An exact rule for a
/// new key would leave it on default_prop, where set_prop on our own type is still denied --
/// and that failure is silent. See the property_contexts comment.
const LOCKDOWN_PROP: &str = "tarish.awdl.lockdown";

/// How often to re-check the kill-switch. A netlink dump is far heavier than a property read,
/// so this is seconds rather than the 500ms poll -- and lockdown state changes when a person
/// changes a setting, not on a timescale that needs watching closely.
const LOCKDOWN_EVERY: Duration = Duration::from_secs(5);

/// Is the exemption earned right now?
fn exemption_earned() -> bool {
    read_property(EXEMPT_PROP).as_deref() == Some("1")
}

/// The longest this daemon will hold the exemption, whatever the property says.
///
/// A SECOND CAP, IN THE PROCESS THAT OWNS THE RULE, and the point is that it trusts nothing.
/// tarishsharingd already caps the window and clears the property at its own startup, but
/// both of those depend on tarishsharingd being alive to do them. Kill it mid-window — OOM,
/// a panic, `kill -9` — and the property keeps saying "1" with nobody left to change it,
/// while THIS process is the one actually holding the rule above the kill-switch.
///
/// So the rule is demoted after this long regardless, and re-promoted only if the property
/// is still set AND has been re-asserted since. Slightly longer than the client's 600s so a
/// healthy window is never cut short by clock skew between the two.
const EXEMPT_MAX: Duration = Duration::from_secs(660);

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
/// platform already maintains so tarishd does not invent its own notion of where
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

// Declared by hand rather than taken from libc: __system_property_get IS re-exported for
// this target and __system_property_set is not, so relying on the crate would make the build
// depend on which bionic symbols it happens to re-export. sharingd declares it the same way.
extern "C" {
    fn __system_property_set(name: *const libc::c_char, value: *const libc::c_char) -> libc::c_int;
}

/// Publish a property. tarishd only ever read them until it had to report lockdown state.
fn write_property(name: &str, value: &str) -> bool {
    let (Ok(n), Ok(v)) = (
        std::ffi::CString::new(name),
        std::ffi::CString::new(value),
    ) else {
        return false;
    };
    // SAFETY: both strings are NUL-terminated and outlive the call.
    unsafe { __system_property_set(n.as_ptr(), v.as_ptr()) == 0 }
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
///   1. `persist.tarish.country`            explicit manual override
///   2. `persist.vendor.wifi.country`     what the Wi-Fi stack persisted, if anything
///   3. `gsm.operator.iso-country`        the network the SIM is registered on
///   4. `gsm.sim.operator.iso-country`    the SIM's home country
///   5. `ro.boot.wificountrycode`         boot default, usually "00" -- last on purpose
///
/// Returns None only when nothing knows. "00" is never accepted: the vendor library
/// takes it, logs a bring-up that looks fine, and then returns NULL.
fn country_code() -> Option<String> {
    for prop in [
        "persist.tarish.country",
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
/// tarishsharingd never writes it -- a policy denial, a crash, an older build --
/// defaulting off would mean AWDL never comes up and Tarish is silently dead.
/// Defaulting on means the worst case is the battery cost we had before this
/// existed, with sharing still working. Fail towards working.
fn wants_radio() -> bool {
    match read_property(WANT_PROP) {
        Some(v) => v.trim() != "0",
        None => true,
    }
}

/// Which radio shape this device exposes.
///
/// The vendor library supports two, and they are not interchangeable:
///
///   Netlink   wants a wiphy named `wonder`, and creates `wonder0` from it
///   Radiotap  rides a PRE-EXISTING `radiotap0` interface
///
/// Which one a device gives you is a vendor decision, not a setting. mustang
/// (Pixel 10 Pro XL) presents the `wonder` wiphy; frankel (Pixel 10) presents
/// `radiotap0` and no `wonder` wiphy at all, with `wonder.ko` loaded but its
/// `physical_name` parameter empty. Hardcoding Netlink meant frankel failed with
///
///     Error starting mosey: init_driver
///     Caused by: Could not find wiphy <wonder>
///
/// while the country, the policy and the channel were all correct -- which reads
/// like a transport fault and is really a wrong-mode fault.
///
/// So look at what is actually there rather than assuming, and keep the other as a
/// fallback: this is a closed library on vendor hardware, and the next device may
/// present a third arrangement we have not seen.
fn radio_modes() -> Vec<mosey::OpMode> {
    // Asked of /sys/class/net, which this domain can already read, and NOT of
    // /sys/class/ieee80211, which it cannot:
    //
    //     avc: denied { read } name="ieee80211" scontext=u:r:tarishd:s0
    //          tcontext=u:object_r:sysfs:s0 tclass=dir
    //
    // Granting that would mean read of generic sysfs for one hint that only decides
    // which order to try two options in. The fallback already covers being wrong, so
    // the cheaper signal is the better one -- a device presenting radiotap0 wants the
    // Radiotap path, and anything else gets Netlink first.
    let has_radiotap = std::path::Path::new("/sys/class/net/radiotap0").exists();
    log::info!("radio survey: radiotap0={has_radiotap}");

    // An ordering, not a decision. Both are always tried, because this is a hint and
    // the vendor library is the authority.
    if has_radiotap {
        vec![mosey::OpMode::Radiotap, mosey::OpMode::Netlink]
    } else {
        vec![mosey::OpMode::Netlink, mosey::OpMode::Radiotap]
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
        // or from an AP, so at boot there may not be one yet -- tarishd used to
        // exit(1) in that case and rely on init to retry. Asking when we actually
        // need it removes that race entirely.
        let country = country_code().ok_or_else(|| {
            "no regulatory country from any source: persist.tarish.country, \
             persist.vendor.wifi.country, gsm.operator.iso-country, \
             gsm.sim.operator.iso-country, ro.boot.wificountrycode. With no SIM and no \
             Wi-Fi association there is nothing to read, and no channel is permitted in \
             the world domain. Set one explicitly: setprop persist.tarish.country <CC>"
                .to_string()
        })?;

        // Try each shape until one takes. A failure here is the library telling us the
        // device is not arranged the way we guessed, which is information, not an error
        // worth giving up on.
        // Try each shape and channel until one takes. A refusal here is the library
        // telling us the device is not arranged the way we guessed, or that the
        // regulatory domain forbids that channel -- both are information, not errors
        // worth giving up on.
        //
        // Mode is the outer loop because it is a property of the hardware and does not
        // change; channel is inner because it is a regulatory question the library
        // answers differently in different countries.
        let sta = sta_frequency();
        if sta > 0 {
            log::info!(
                "Wi-Fi is on {sta} MHz — putting AWDL in the other band, {:?}",
                channels_for(sta).first().unwrap_or(&CHANNELS_5)
            );
        } else if sta < 0 {
            log::info!(
                "Wi-Fi is off — the radio is ours, trying {:?} first",
                channels_for(sta).first().unwrap_or(&CHANNELS_5)
            );
        } else {
            log::info!(
                "no Wi-Fi association — nothing to avoid, trying {:?} first",
                channels_for(0).first().unwrap_or(&CHANNELS_24)
            );
        }
        let config = config_override().unwrap_or_else(|| mosey_config(sta));
        let forced = channel_override();

        let mut session = None;
        let mut chosen = None;
        let mut last = String::new();
        // WHAT WE WILL NOT DO IS TAKE THE STA'S BAND.
        //
        // channels_for() puts the opposite band first, but it is a PREFERENCE: when the
        // first candidate is refused the loop used to walk straight into the band the
        // phone is associated on, and this chip cannot hold two channels there. Measured:
        // AWDL on 149 against a 5520 MHz STA kills the association, and it still kills it
        // with sta_channel_freq set and with channel_hopping forced true. So the fallback
        // was not a degraded mode, it was a Wi-Fi outage.
        //
        // Losing AWDL is recoverable and visible -- the user retries the share. Losing
        // Wi-Fi on a phone is neither. Refuse instead.
        //
        // An explicit channel override still wins: it exists for bench work, and the
        // whole point is to be able to ask for the arrangement that breaks.
        let offered: Vec<&[u8]> = match &forced {
            Some(c) => vec![c.as_slice()],
            None => {
                let (keep, refused): (Vec<&[u8]>, Vec<&[u8]>) = channels_for(sta)
                    .into_iter()
                    .partition(|c| !same_band_as_sta(c, sta));
                if !refused.is_empty() {
                    log::info!(
                        "not offering {refused:?} — same band as the {sta} MHz association; \
                         losing AWDL beats losing Wi-Fi"
                    );
                }
                keep
            }
        };

        'search: for mode in radio_modes() {
            for channels in offered.iter().copied() {
                match mosey::Session::start(channels, &country, MAX_MDNS, mode, &config) {
                    Ok(s) => {
                        session = Some(s);
                        chosen = Some((mode, channels));
                        break 'search;
                    }
                    Err(e) => {
                        // NOT debug. Refusing the preferred channel is how a phone
                        // loses Wi-Fi: the next candidate is the other band, which on
                        // a 5 GHz STA is the STA's own band, and DBS cannot hold two
                        // 5 GHz channels. The fallback used to be silent, so the only
                        // trace was `channel=149` in the success line.
                        log::warn!("{mode:?} + channel {channels:?} refused: {e}");
                        last = e;
                    }
                }
            }
        }

        let session = session.ok_or_else(|| {
            format!(
                "no combination of radio mode and channel was accepted in {country}. \
                 Tried {:?} against channels {:?}{}. Last error: {last}",
                radio_modes(),
                offered,
                if sta > 0 {
                    format!(" (the {sta} MHz band was withheld to protect the association)")
                } else {
                    String::new()
                }
            )
        })?;
        let (mode, channels) = chosen.expect("set with session");

        log::info!(
            "AWDL session up, handle={:p}, mode={mode:?}, channel={}, country={country}",
            session.handle(),
            channels[0],
        );

        // The interface appears a moment after the call returns.
        std::thread::sleep(Duration::from_secs(2));
        let ifc = iface();
        match route::add_link_local(ifc) {
            Ok(()) => log::info!(
                "route: fe80::/64 dev {ifc} table {}",
                route::table_id(ifc)
            ),
            Err(e) => log::warn!(
                "link-local route not added ({e}) — sockets on {ifc} will get ENETUNREACH"
            ),
        }

        // A route in a table nothing consults does nothing. Android picks tables with
        // fib rules keyed on fwmark, and gets no rule for an interface it does not
        // manage -- so the route above sat in table N, was never looked up, and every
        // lookup fell through to "32000: from all unreachable".
        let exempt = exemption_earned();
        match route::add_rule(ifc, exempt) {
            Ok(()) => log::info!(
                "rule: oif {ifc} lookup {} ({})",
                route::table_id(ifc),
                if exempt { "ABOVE the VPN kill-switch — authenticated window open" }
                else { "below the VPN kill-switch — no authenticated window" }
            ),
            Err(e) => log::warn!(
                "routing rule not added ({e}) — the route on {ifc} exists but nothing \
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

/// Log verbosity, from `persist.tarish.loglevel` (error|warn|info|debug|trace).
///
/// Hardcoding Info meant the one line explaining a Wi-Fi-killing channel fallback was
/// compiled out on every shipped device, and recovering it needed a rebuild and a
/// reflash. Info stays the default; this only makes the level answerable in the field.
fn log_level() -> log::LevelFilter {
    match read_property("persist.tarish.loglevel")
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        "error" => log::LevelFilter::Error,
        "warn" => log::LevelFilter::Warn,
        "debug" => log::LevelFilter::Debug,
        "trace" => log::LevelFilter::Trace,
        _ => log::LevelFilter::Info,
    }
}

fn main() {
    android_logger::init_once(
        android_logger::Config::default()
            .with_tag("tarishd")
            .with_max_level(log_level()),
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

    let mut last_exempt: Option<bool> = None;
    let mut exempt_since: Option<std::time::Instant> = None;
    let mut exempt_capped = false;
    let mut last_lockdown: Option<bool> = None;
    let mut lockdown_checked_at: Option<std::time::Instant> = None;
    while RUNNING.load(Ordering::SeqCst) {
        // Publish whether a kill-switch is actually in force. The app asks
        // tarishsharingd, which reads this; neither of them can see it directly.
        if lockdown_checked_at.map_or(true, |t| t.elapsed() >= LOCKDOWN_EVERY) {
            lockdown_checked_at = Some(std::time::Instant::now());
            let now_locked = route::lockdown_active();
            if last_lockdown != Some(now_locked) {
                if !write_property(LOCKDOWN_PROP, if now_locked { "1" } else { "0" }) {
                    log::error!(
                        "could not publish {LOCKDOWN_PROP} — the app cannot tell whether a \
                         kill-switch is active and will assume one is. Check \
                         set_prop(tarishd, tarish_awdl_prop)"
                    );
                }
                log::info!(
                    "{LOCKDOWN_PROP}={} — a VPN kill-switch is {}",
                    if now_locked { 1 } else { 0 },
                    if now_locked { "in force" } else { "NOT in force" }
                );
                last_lockdown = Some(now_locked);
            }
        }

        let want = wants_radio();
        if last_want != Some(want) {
            log::info!("{WANT_PROP}={}", if want { 1 } else { 0 });
            last_want = Some(want);
            retry_at = std::time::Instant::now();   // a fresh request retries at once
        }

        // THE AUTHENTICATED WINDOW CAN OPEN AND CLOSE WHILE THE LINK IS UP, so the rule has
        // to follow it and not just be chosen once at acquire(). Without this the exemption
        // would last as long as the AWDL session, which is the property the feature exists
        // to remove -- and worse, it would be decided by whatever the state happened to be
        // at the moment AirDrop was switched on.
        //
        // Re-adding is how the priority changes: add_rule sweeps BOTH priorities first, so
        // this demotes as cleanly as it promotes and never leaves a rule at the old one.
        // Only while a link exists; with no interface there is nothing to point at.
        let mut exempt = exemption_earned();

        // Enforce our own ceiling before acting on the property.
        //
        // `exempt_since` is reset only on a TRANSITION into the exempt state, so a property
        // stuck at "1" cannot keep renewing it: the timer runs from when the window opened,
        // not from when we last looked. Once expired we hold the demotion until the property
        // goes false and true again, which is what re-authenticating does.
        if exempt {
            match exempt_since {
                None => exempt_since = Some(std::time::Instant::now()),
                Some(t) if t.elapsed() > EXEMPT_MAX => {
                    if !exempt_capped {
                        log::error!(
                            "{EXEMPT_PROP} has been set for {}s — past our own {}s ceiling. \
                             Demoting the rule and holding it down until the window is \
                             re-opened. tarishsharingd may have died mid-window.",
                            t.elapsed().as_secs(),
                            EXEMPT_MAX.as_secs()
                        );
                        exempt_capped = true;
                    }
                    exempt = false;
                }
                Some(_) => {}
            }
        } else {
            exempt_since = None;
            exempt_capped = false;
        }

        if last_exempt != Some(exempt) {
            if link.is_some() {
                let ifc = iface();
                match route::add_rule(ifc, exempt) {
                    Ok(()) => log::info!(
                        "{EXEMPT_PROP}={} — rule moved {} the VPN kill-switch",
                        if exempt { 1 } else { 0 },
                        if exempt { "ABOVE" } else { "below" }
                    ),
                    // Losing the promotion is safe; losing the demotion is not, so say so
                    // loudly rather than leaving a stale exemption in place unremarked.
                    Err(e) => log::error!(
                        "could not move the routing rule for {EXEMPT_PROP}={} ({e}) — \
                         the exemption may still be in force",
                        if exempt { 1 } else { 0 }
                    ),
                }
            }
            last_exempt = Some(exempt);
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
            // WE BELIEVE WE HAVE A LINK AND THE INTERFACE SAYS OTHERWISE.
            //
            // Drop it so the arm above re-acquires on the next tick. Dropping calls
            // mosey_stop, which is the right thing even for an interface that is already
            // gone: it releases the handle so the next start gets a fresh one, and the
            // interface index changes on every restart anyway (BUILD-NOTES 35), so reusing
            // any of the old state would be wrong.
            //
            // Not rate-limited by retry_at: acquire() failing sets that itself, so a radio
            // that is genuinely unavailable still backs off to 5s rather than spinning.
            (true, true) if awdl_link_is_dead() => {
                log::warn!(
                    "AWDL link died underneath us — wondertap0 is down or gone, most likely a \
                     Wi-Fi association change reloading the driver. Releasing and re-acquiring."
                );
                link = None;
            }
            _ => {}
        }

        std::thread::sleep(POLL);
    }

    log::info!("shutting down");
    drop(link);
}

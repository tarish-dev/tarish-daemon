//! FFI to the vendor AWDL library.
//!
//! This is the only place in barqd that talks to `libmosey_daemon_ffi.so`, and
//! the only place a vendor ABI change can break us. Everything unsafe about the
//! transport lives here so the rest of the daemon can be ordinary safe Rust.
//!
//! The ABI is documented in `docs/MOSEY-FFI.md`. It was recovered by observation,
//! not published, so treat it as versioned and unstable: `mosey_start_5`'s `_5`
//! is a version marker, not an arity, which means a vendor bump can rename it.
//! We therefore resolve by exact name and fail loudly rather than degrade.

use std::ffi::{c_char, c_int, c_void, CStr, CString};
use std::ptr;

/// Where the library might be. barqd does not own it and does not care which of
/// these it finds — shipping and pinning it is the integrator's job. The bare
/// soname comes first so the dynamic linker's own search applies.
const CANDIDATES: &[&str] = &[
    "libmosey_daemon_ffi.so",
    "/system_ext/lib64/libmosey_daemon_ffi.so",
    "/vendor/lib64/libmosey_daemon_ffi.so",
    "/system/lib64/libmosey_daemon_ffi.so",
];
const LIB_ENV: &str = "BARQ_MOSEY_LIB";

const RTLD_NOW: c_int = 2;

extern "C" {
    fn dlopen(filename: *const c_char, flag: c_int) -> *mut c_void;
    fn dlsym(handle: *mut c_void, symbol: *const c_char) -> *mut c_void;
    fn dlerror() -> *const c_char;
}

type Start5 = unsafe extern "C" fn(
    channels: *const u8,
    n_channels: u64,
    max_mdns: u32,
    country: *const c_char,
    op_mode: u32,
    config: *const u8,
    config_len: u64,
) -> *mut c_void;

type Stop = unsafe extern "C" fn(*mut c_void) -> *mut c_void;

/// Radio backend. Selects the whole backend, not a mode within one.
///
/// Which of these a device offers is a vendor decision. Both are real and both are
/// in use across the Pixel 10 family, so neither is "the wrong one" -- an earlier
/// comment here called Radiotap "not what we want", which was true of the phone in
/// front of us at the time and false of the next one.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum OpMode {
    /// `Preexisting { iface_name: "radiotap0" }`, ArtIoctl.
    Radiotap = 1,
    /// `AsNeeded { iface_name: "wonder0", wiphy_name: "wonder" }`, Netlink.
    Netlink = 2,
}

/// A live AWDL session.
///
/// The session lives exactly as long as this value: the vendor library tears the
/// interface down when its holder goes away. That is why barqd's whole job is to
/// hold one, and why a client app must never be the holder.
pub struct Session {
    handle: *mut c_void,
    stop: Option<Stop>,
    _lib: *mut c_void,
}

// SAFETY: the handle is only ever touched from the thread that made it, or on
// shutdown. barqd creates, holds and drops a Session entirely on its main thread --
// the acquire/release loop never moves one across threads -- so this impl is not
// actually exercised today. It exists so a Session can be owned by a struct that
// something else wants to move.
unsafe impl Send for Session {}

fn last_dlerror() -> String {
    // SAFETY: dlerror returns a NUL-terminated string or NULL.
    unsafe {
        let e = dlerror();
        if e.is_null() {
            "unknown error".to_string()
        } else {
            CStr::from_ptr(e).to_string_lossy().into_owned()
        }
    }
}

impl Session {
    /// Bring AWDL up. `config` is a serialised `StartMoseyConfig` protobuf;
    /// `08 01 30 01` (is_dbs_supported, rate_adaptation) is what the vendor
    /// daemon itself passes and is enough.
    pub fn start(
        channels: &[u8],
        country: &str,
        max_mdns: u32,
        op_mode: OpMode,
        config: &[u8],
    ) -> Result<Self, String> {
        if country.len() != 2 {
            return Err(format!("country must be exactly 2 letters, got {country:?}"));
        }

        let (lib, loaded) = Self::open_lib()?;
        log::info!("loaded {loaded}");

        // SAFETY: lib is a live handle from dlopen; the names are the exact
        // exported symbols documented in docs/MOSEY-FFI.md.
        let (start5, stop) = unsafe {
            let name = CString::new("mosey_start_5").unwrap();
            let p = dlsym(lib, name.as_ptr());
            if p.is_null() {
                return Err(format!(
                    "mosey_start_5 not found in {loaded} — ABI changed? \
                     The _5 suffix is a version marker, so a vendor bump can rename it."
                ));
            }
            let start5: Start5 = std::mem::transmute(p);

            let name = CString::new("mosey_stop").unwrap();
            let p = dlsym(lib, name.as_ptr());
            let stop: Option<Stop> = if p.is_null() {
                None
            } else {
                Some(std::mem::transmute(p))
            };
            (start5, stop)
        };

        let cc = CString::new(country).map_err(|e| e.to_string())?;

        // SAFETY: every pointer below outlives the call, and the lengths match
        // the slices they describe.
        let handle = unsafe {
            start5(
                channels.as_ptr(),
                channels.len() as u64,
                max_mdns,
                cc.as_ptr(),
                op_mode as u32,
                config.as_ptr(),
                config.len() as u64,
            )
        };

        if handle.is_null() {
            return Err(
                "mosey_start_5 returned NULL — read logcat for `mosey_daemon`, it \
                 reports how it parsed every argument and names its own complaint"
                    .to_string(),
            );
        }

        Ok(Session { handle, stop, _lib: lib })
    }

    fn open_lib() -> Result<(*mut c_void, String), String> {
        let mut tried: Vec<String> = Vec::new();

        if let Ok(p) = std::env::var(LIB_ENV) {
            if !p.is_empty() {
                let c = CString::new(p.clone()).map_err(|e| e.to_string())?;
                // SAFETY: c is a valid NUL-terminated path.
                let h = unsafe { dlopen(c.as_ptr(), RTLD_NOW) };
                if !h.is_null() {
                    return Ok((h, p));
                }
                return Err(format!("{LIB_ENV}={p}: {}", last_dlerror()));
            }
        }

        for cand in CANDIDATES {
            let c = CString::new(*cand).map_err(|e| e.to_string())?;
            // SAFETY: c is a valid NUL-terminated path.
            let h = unsafe { dlopen(c.as_ptr(), RTLD_NOW) };
            if !h.is_null() {
                return Ok((h, (*cand).to_string()));
            }
            tried.push((*cand).to_string());
        }

        Err(format!(
            "no AWDL library found (tried {}). Set {LIB_ENV} to override. \
             barqd requires libmosey_daemon_ffi.so to be present — shipping it is \
             the integrator's job, not this daemon's.",
            tried.join(", ")
        ))
    }

    pub fn handle(&self) -> *mut c_void {
        self.handle
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        if let Some(stop) = self.stop {
            if !self.handle.is_null() {
                log::info!("stopping AWDL session");
                // SAFETY: handle came from mosey_start_5 and is stopped once.
                unsafe { stop(self.handle) };
                self.handle = ptr::null_mut();
            }
        }
    }
}

# Tarish — current architecture

**Authoritative as of 2026-09-22.** If any other document disagrees with this one about what
ships, this one is right; the other is historical. Supersedes the scattered `libmosey`-era
descriptions across the repos.

## Production data path

```
Tarish app  (UI, consent, BLE, Wi-Fi Direct, share sheet, MDM policy)
    │  binder
    ▼
tarishsharingd  (uid 7500 system_ext_tarish, NO Linux caps)
    │            AirDrop HTTP/TLS/plist/cpio, mDNS, Quick Share/UKEY2/secure channel,
    │            file staging — all attacker-facing parsing lives here
    ▼
tarishd  (uid system, CAP_NET_ADMIN + CAP_NET_RAW; parses NO high-level input)
    │  dlopen libmosey_daemon_ffi.so  (5 FFI symbols: mosey_start_5/stop/update/dump/reset)
    ▼
tlink-shim   (our shim, exports that soname/ABI — REPLACES Google's libmosey)
    ▼
tlink-session / tlink-hal   (AWDL election, sync, availability windows, channels, IPv6)
    ▼
wonder.ko    (Google's SoftMAC shim, vendor_dlkm, driven over netlink — NOT reimplemented)
    ▼
Broadcom radio + firmware   (the one closed layer)
```

## What actually ships today (the libmosey → tlink switch)

**Production replaces Google's `libmosey` with our own `tlink`.** Both provide the identical
`libmosey_daemon_ffi.so` soname and the five FFI symbols `tarishd` dlopens, so the whole AWDL
userspace is swapped by overwriting one `.so`. `wonder.ko` (the silicon-tied kernel MAC
module) stays in place either way — it is not reimplemented.

- **libmosey** = Google's closed blob. Still pinned in the integration repo (`vendor/mosey/`)
  as a fallback and for ABI reference.
- **tlink** = our open Rust stack (`vendor/tlink/`), installed *over* the libmosey path. It
  creates the `tlink0` interface. This is the prod default.

Any document that says "tarishd drives AWDL through libmosey" or "GrapheneOS requires
`libmosey_daemon_ffi.so`" is describing the ABI contract, not the implementation: the file at
that path is now tlink's shim. The **app README's** "current AWDL layer = libmosey" line is
**historical** and being corrected.

## Privilege / trust boundary (the core security decision)

- **tarishd** holds the network capabilities but parses no peer-controlled high-level input.
- **tarishsharingd** parses everything hostile (CPIO, TLS, plists, UKEY2, …) but holds **no**
  Linux capabilities and runs as its own uid.
- **The app** owns only framework operations (BLE, Wi-Fi Direct, consent UI, storage) and is
  the sole consumer of the daemon's binder API.
- **Consent is enforced in the daemon**, not the UI: an offer must be *accepted* before any
  upload is allowed, so a compromised UI cannot bypass the receive prompt.

## Known-open items (do not describe these as finished)

- **Off-network Quick Share stays on Bluetooth** when AirDrop/AWDL is active: `wonder.ko`'s
  interface holds the chip's single P2P slot, so a Wi-Fi Direct group can't form alongside it.
  Same-Wi-Fi transfers use the LAN (fast) automatically.
- **AWDL is single-channel (ch149) in prod**, which misses peers on other social channels
  (e.g. some iPhones). Multi-channel scheduling (like stock mosey) is in progress.
- **The `platform_app` binder grant is being narrowed** to a signature-scoped app domain.
- **tarishd's SELinux policy** is being re-derived from tlink's actual syscalls (it was
  inherited from Google's `mosey_server`).

## Repositories

| Repo | Role | Public? |
|---|---|---|
| `tarish-app` | Android client (UI, BLE, Wi-Fi Direct, consent, MDM) | yes |
| `tarish-daemon` | `tarishd`, `tarishsharingd`, `tarishctl`, AIDL, protocol lib | yes |
| `tarish-link` | tlink — the independent AWDL stack + shim | yes |
| `grapheneos` (integration) | build scripts, pins, patches, SELinux wiring | private |

The integration repo is intentionally private; a reproducible build recipe can be published
without it.

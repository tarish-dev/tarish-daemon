# Tarish — current architecture

**Authoritative as of 2026-09-24.** If any other document disagrees with this one about what
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

## VPN kill-switch and the authenticated window — PARTIALLY SHIPPED

Sharing works under an always-on VPN in lockdown mode, which stock Quick Share does not do.
That is a deliberate exemption in a control enterprises rely on, so it is scoped and
measured rather than argued. **Authoritative account, including the threat model:**
grapheneos `docs/VPN-LOCKDOWN.md`.

What ships and is verified on hardware: an `ip rule` for `tlink0` above Android's
`PROHIBIT_NON_VPN`, scoped to uid 7500, to a table holding exactly `fe80::/64 dev tlink0`
and no IPv4. It cannot reach the internet, the LAN or the VPN's subnet.

**The authenticated window is now verified on hardware** (blazer, build `2026092412`,
2026-09-24): the app locks in its own right, the rule moves 15500 -> 13500 while a window is
open, the keep-unlocked heartbeat runs, and the lock appears and disappears with a real VPN
kill-switch — tested off→on, on→off, and with the VPN uninstalled entirely.

Whether a kill-switch is in force is decided by **tarishd**, not the app: an `RTM_GETRULE`
netlink dump matching `FR_ACT_PROHIBIT`, published as `tarish.awdl.lockdown`. The app cannot
determine it, and a settings read cannot be scoped by SELinux — see grapheneos
`docs/VPN-LOCKDOWN.md` for why that matters.

Still **not measured**, and should not be described as proven: the specific three-missed-beat
boundary, binder-death withdrawal against a *stuck* rather than exited app, and tarishd's
660s ceiling (it needs an 11-minute window to observe).

Two platform patches exist and their status is easy to get backwards: `0001` (local-network
access for uid 7500) is **required**; `0002` (BPF lockdown exemption) is a **no-op**, because
uid 7500 never carries `LOCKDOWN_VPN_MATCH`.

## Known-open items (do not describe these as finished)

- **Off-network Quick Share now upgrades to Wi-Fi Direct** — this used to say it stayed on
  Bluetooth. `wonder.ko`'s interface does hold the chip's single P2P slot, but tlink takes
  the AWDL interface down for the Wi-Fi Direct leg and puts it back, which frees the slot.
  Observed on hardware 2026-09-24: `taking AWDL down for a Wi-Fi Direct transfer (freeing
  the P2P slot)`, followed by `upgraded the inbound transfer to Wi-Fi Direct`. Same-Wi-Fi
  transfers still use the LAN automatically.
- **AWDL is single-channel (ch149) in prod**, which misses peers on other social channels
  (e.g. some iPhones). Multi-channel scheduling (like stock mosey) is in progress.
- **tlink AirDrop is proven for the core path (bring-up, election, sync, discovery, receive);
  send throughput is still being hardened.** tlink ships as the AWDL userspace (the shim
  replaces libmosey), but it is not yet at full libmosey parity — Google's `libmosey` remains
  the same-ABI drop-in fallback. Do not describe tlink AirDrop *send* as finished.
- ~~**The `platform_app` binder grant is being narrowed**~~ — **DONE 2026-09-24**, security
  review #28. The app has its own `tarish_app` domain, keyed in `seapp_contexts` on package
  name AND platform signature. The five grants that named `platform_app` moved onto it.
  Verified enforcing on hardware, with `tarishctl` refused from an unprivileged shell as the
  proof the lock holds.
- ~~**tarishd's SELinux policy is being re-derived**~~ — **DONE 2026-09-24**, and by
  measurement rather than reasoning. `auditallow` was placed on every questionable grant, one
  build shipped, and `gos-selinux.sh --granted` read back what was actually exercised.
  `tarishsharingd` lost `rawip_socket`, `icmp_socket` and `netlink_route_socket` — entire
  classes — and `tarishd` lost `listen`/`accept` on classes where those operations do not
  exist, plus `map`, `watch`/`watch_reads`, `nlmsg_readpriv` and all of
  `netlink_netfilter_socket`. Zero denials under enforcing.

  `map` is the instructive one for anyone auditing inherited policy: the rule carried a
  comment citing a real failure when it was removed, and that failure belonged to **Google's
  libmosey**. We run tlink. The permission set had outlived the binary it was written for.

## Repositories

| Repo | Role | Public? |
|---|---|---|
| `tarish-app` | Android client (UI, BLE, Wi-Fi Direct, consent, MDM) | yes |
| `tarish-daemon` | `tarishd`, `tarishsharingd`, `tarishctl`, AIDL, protocol lib | yes |
| `tarish-link` | tlink — the independent AWDL stack + shim | yes |
| `grapheneos` (integration) | build scripts, pins, patches, SELinux wiring | private |

The integration repo is intentionally private; a reproducible build recipe can be published
without it.

# Tarish

**AirDrop and Quick Share on Android, with no Google Play Services — sandboxed or
otherwise — and no Google account.**

Send a file to a MacBook from a phone that has never spoken to Google. The Mac shows a real
device name and a normal AirDrop prompt; the phone shows a normal share sheet. Send to a
Windows laptop or another Android phone and Quick Share does the same. Nothing signs in,
nothing checks in, and no Google application is installed.

Two repositories:

| | |
|---|---|
| **tarish-daemon** (this one) | the transports, the protocols, the SELinux policy, integration |
| [**tarish-app**](https://github.com/tarish-dev/tarish-app) | the share sheet, the prompts, and the radio work only the framework can do |

---

## Status

Verified on hardware, under SELinux **enforcing**, on a build with **zero Google
applications installed**.

| | AirDrop (Apple) | Quick Share (Android / Windows) |
|---|---|---|
| discovery | ✅ AWDL + mDNS | ✅ mDNS on Wi-Fi, BLE off-network |
| send | ✅ | ✅ |
| receive | ✅ | ✅ |
| shared network | ✅ | ✅ 22 MB/s measured |
| off-network | ✅ AWDL is its own link | ✅ Wi-Fi Direct 10.5 MB/s; Bluetooth ~150 KB/s bootstrap |
| both protocols at once | ✅ verified concurrently, no degradation |

Interoperability is tested against **real peers, not only against ourselves**: macOS and
iOS for AirDrop, Windows 11 and stock Android for Quick Share. That distinction has caught
bugs that no amount of self-testing would — see *Testing* below.

---

## Why, when sandboxed Play Services exists

GrapheneOS's sandboxed Play Services is excellent, and it is not an answer to this.

**It cannot do AirDrop at all.** AirDrop needs Google's `mosey` stack running with platform
privileges. Getting it working that way — the route this project took first — required
*privileged* Play Services, not the sandboxed kind, plus a successful check-in to Google's
servers to receive a feature flag. That is a long way from "install an app".

**And for many people the objection is not the sandbox, it is the code.** Sandboxed Play
Services is still Google's code on your device. Plenty of people who choose a
de-Googled OS do not want it there in any form, at any privilege level. That is a
legitimate position and it should not cost you file sharing with the people around you.

---

## The layers, per protocol

Being precise about what is ours and what is the vendor's matters more than the line count.

### AirDrop

| layer | whose | notes |
|---|---|---|
| radio and MAC — `wonder.ko` | **vendor** | Google/Broadcom kernel module, already in the stock image. **Zero AWDL protocol strings in it** |
| AWDL protocol — `libmosey_daemon_ffi.so` | **vendor** | election, sync, peer discovery. 51 protocol strings. This is the piece an OWL-style reimplementation would replace |
| IP on `mosey0` | ours | including the routing that Android's fwmark model requires |
| mDNS, TLS, HTTP, Apple's plist dialect, cpio | **ours** | `tarishsharingd` |
| share sheet, prompts, consent | **ours** | the app |

Both vendor blobs **already ship in the Pixel vendor image** and run on a build with no
Google packages, so using them adds nothing to the device that was not already there.
Replacing them is a separate, not-yet-started track.

### Quick Share

Entirely ours, top to bottom — there is no vendor component.

| layer | where |
|---|---|
| BLE advertise and scan | **app** (framework Bluetooth is unreachable from a native daemon) |
| mDNS discovery on `wlan0` | daemon |
| Bluetooth RFCOMM / L2CAP socket | **app**, handed to the daemon as an fd |
| Wi-Fi Direct group | **app** (`WifiP2pManager` is framework API), socket handed over |
| UKEY2 handshake, D2D keys, SecureMessage | daemon — `libtarish_protocol` |
| secure channel, sequence numbers, replay refusal | daemon |
| offline frames, payload reassembly, sharing FSM | daemon |
| bandwidth upgrade negotiation | daemon decides, app provides the radio |

`libtarish_protocol` is deliberately **Android-free** so it is testable on a build host.
202 tests, including one that runs a whole share between two peers in-process: handshake,
key derivation, encrypted channel, introduction, acceptance, a file in chunks, reassembled
and compared byte for byte.

---

## Decisions worth explaining

These are the ones that look odd until you know why.

### `tarishsharingd` runs as its own uid, and that costs a framework patch

The daemon is uid **7500 `system_ext_tarish`**, declared in `config/tarish_aid.txt`.

The split is a privilege boundary. `tarishd` holds the AWDL link and needs
`CAP_NET_ADMIN`; `tarishsharingd` parses input from strangers and holds **no capabilities
at all**. Everything that touches a remote byte lives in the process that can do the least.

The AID alone is not enough to reach `wlan0`. Since Android B, only uid 0 and uid 1000 may
touch the local network; every other uid needs a bit in a BPF map that `PermissionMonitor`
derives from **packages** — so a native daemon can never earn it, and mDNS `sendto()` fails
with `EPERM`. The grant is a one-line framework patch
(`patches/packages_modules_Connectivity/`) that hardcodes 7500 and grants exactly
`PERMISSION_BIT_ACCESS_LOCAL_NETWORK` and nothing else.

This only ever affected Quick Share. AirDrop rides `mosey0`, which is not a managed network
and is not gated — which is why the daemon did mDNS correctly for a long time before this
surfaced. The failure is silent: the daemon starts, advertises, and never sends. The
installer refuses to proceed if the patch and `tarish_aid.txt` disagree about the number.

**Three alternatives were considered and rejected:** running as `system` (defeats the
privilege split), running as a package uid (a native daemon has no package), and
`CAP_NET_RAW` (does not bypass the BPF gate).

### Always-on VPN lockdown

Android's *Block connections without VPN* is a good setting and enterprises rightly turn it
on. It also breaks every peer-to-peer transfer that works by IP — AirDrop, Quick Share and
Tarish alike — because the traffic is on a link-local address that is not the VPN, so it is
dropped, and nothing tells the person why.

The position taken here: **honour it, do not bypass it.** Under lockdown the device should
say plainly that sharing is disabled by policy, rather than appearing broken. Design in
`docs/POLICY.md`. The exemption question — whether uid 7500 already sits inside the BPF
program's `is_system_uid` exemption, which is wider than the local-network gate's — is
measured, not assumed.

### The AWDL band is negotiated, not guessed

The chip does 2.4 and 5 GHz simultaneously but **cannot hold two 5 GHz channels**, so AWDL
must occupy the opposite band from Wi-Fi. Getting it wrong drops the Wi-Fi association in
about three seconds. The app reports the association frequency to the daemon whenever it
changes; unknown means the daemon guesses, and a guess is wrong about half the time.

### Wi-Fi LAN is a bootstrap, never an upgrade target

A peer on the same subnet publishes an address over mDNS and is reached by connecting to
it. That is already the fast path. A stock peer will never answer an upgrade request for
`WIFI_LAN`, and it is not malfunctioning when it stays silent. The bandwidth upgrade exists
for peers with **no** shared network, and it means Wi-Fi Direct.

### The advertiser hosts the upgrade network; the discoverer joins

Not sender and receiver. A stock sender never asks for an upgrade, and an advertiser
refuses to join one. So when we send we ask and the peer hosts; when we receive we offer,
unprompted.

---

## Devices

Tarish needs `wonder.ko` **bound to the Wi-Fi driver**, and that depends on the Wi-Fi chip,
not the model or the SoC. Every Pixel 10 image ships both `bcmdhd4383.ko` and
`bcmdhd4390.ko` and loads whichever matches the silicon, so the model name tells you
nothing. Check the device:

```bash
adb shell 'lsmod | grep bcmdhd'          # 4390 = good, 4383 = no wondertap
adb shell 'ls /sys/class/ieee80211/'     # a `wonder` wiphy is the real test
```

| device | model | chip | AirDrop | Quick Share |
|---|---|---|---|---|
| `blazer` | Pixel 10 Pro | BCM4390 | ✅ AWDL and Wi-Fi coexist | ✅ |
| `mustang` | Pixel 10 Pro XL | BCM4390 | ✅ AWDL and Wi-Fi coexist | ✅ |
| `frankel` | Pixel 10 | BCM4383 | ⚠️ works, but takes the radio — see below | ✅ |
| `rango` | Pixel 10 Pro Fold | unverified | unverified | expected to work |
| `stallion` | Pixel 10a | no `wonder.ko` at all | ❌ impossible | ✅ |

**On BCM4383 (Pixel 10) the radio is exclusive.** There is no `wondertap`, so AWDL falls
back to a radiotap path that takes the physical radio: Wi-Fi drops within about ten seconds
of AirDrop becoming active, and comes back on its own **10-24 seconds after AirDrop is
switched off**. Measured over repeated cycles, with the association on 5520 MHz and the
band correctly reported to the daemon — so this is the silicon, not a band-selection
mistake, and no software change reaches it.

That is a tradeoff rather than a trap: *sharing and Wi-Fi at the same time* is not
available on this chip, but nothing needs a reboot and nothing stays broken. Quick Share
needs no AWDL and is unaffected throughout — so on exactly the hardware where AirDrop is
awkward, the other half is untouched.

**The Pixel 10a can never do AirDrop.** Its image ships no `wonder.ko`. It still ships
`mosey_server` and the Mosey app, so finding those proves nothing. Quick Share works.

---

## Integration

Everything a platform integrator needs is in **[docs/INTEGRATING.md](docs/INTEGRATING.md)**:
what the platform must provide, the SELinux policy and why trimming it costs cycles, the
routing trap, the regulatory-country requirement, and the failures that look like success.

The short version:

```make
PRODUCT_PACKAGES += tarishd tarishsharingd
```

plus `sepolicy/*.te` and its four context files, the AID in `TARGET_FS_CONFIG_GEN`, and the
local-network patch. `docs/GRAPHENEOS.md` covers that build specifically.

**LineageOS is the next target.** Nothing here is GrapheneOS-specific by design — the
daemon asks the platform for an AWDL library and a kernel module and does not care where
they came from, which is exactly why the vendor pin lives with the integrator rather than
in this repo.

**If you maintain GrapheneOS or LineageOS and want this in the image, please open an
issue.** It is built to be adopted: no Google dependency, no network callbacks, an
unprivileged parser process, policy that an administrator can pin, and a licence that
imposes nothing.

---

## Testing

Two devices, driven from a script, no screen taps:

```bash
tarishctl peers                     # what this device can see
tarishctl send <peer-id> <file>     # start a transfer
tarishctl accept <transfer-id>      # answer an offer
tarishctl policy pin off            # for transport tests
```

`tarishctl` is **userdebug and eng only**, enforced in the makefile and again in SELinux
policy — it can start a transfer and accept an incoming one, which is not something a shell
on a production device should be able to do.

**Test against both vendors, always.** Passing against one proves very little:

- Windows sends no confirming `Response` and cannot host Wi-Fi Direct at all
- macOS accepts a gzip container that Apple itself never sends
- a stock Pixel does both, and is stricter about frame shapes

And test **two Tarish devices against each other**, which is a different thing again: a
third-party peer runs its own half of the protocol, so it papers over any place where our
two halves disagree. Several real bugs were only ever visible device-to-device — a
container mismatch where our sender gzipped and our receiver did not decompress, and an id
mismatch that made accepting an incoming transfer impossible.

---

## Acknowledgement

Thanks to **[Bada](https://github.com/kyujin-cho/Bada)**, an open Quick Share
implementation for Android. **No code from it is used here** — this is a fresh
implementation in a different language and process model — but it worked out several
protocol details independently and documented why they matter, and that saved real time.
Where a constant exists because Bada found it first, the comment beside it says so.

Also to the **openheimer / OWL** research on AWDL, and to **opendrop**, for establishing
what AirDrop looks like on the wire.

## Licence

Apache 2.0. See [LICENCE](LICENSE).

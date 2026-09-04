# Barq

**AirDrop and Quick Share on Android, with no Google Play Services — sandboxed or
otherwise — and no Google account.**

Send a file to a MacBook from a GrapheneOS phone that has never spoken to Google. The Mac
shows a real device name and a normal AirDrop prompt; the phone shows a normal share
sheet. Nothing signs in, nothing checks in, and no Google application is installed.

That is working today, both directions, under SELinux enforcing. Quick Share — the
Android and Windows side — is in progress: its protocol is complete and tested, and
discovery finds real devices over BLE with no network at all.

## Why, when sandboxed Play Services exists

GrapheneOS's sandboxed Play Services is excellent, and it is not an answer to this.

**It cannot do AirDrop at all.** AirDrop needs Google's `mosey` stack running with
platform privileges. Getting it working the other way — the route this project took
first — required *privileged* Google Play Services, not the sandboxed kind, plus a
successful check-in to Google's servers to receive the feature flag that enables it. That
is a long way from "install an app".

**And for many people the objection is not the sandbox, it is the code.** A sandboxed
Play Services is still Google's code running on your device. Plenty of people who choose
GrapheneOS do not want it there in any form, at any privilege level. That is a legitimate
position and it should not cost you file sharing with the people around you.

Barq needs no Play Services, no Google account, no check-in, and no network path to
Google. It works on a build with zero Google applications installed.

## What is ours, and what comes from the vendor image

Being precise about this matters more than the line count, so here is the whole stack.

**AirDrop** leans on two Google binaries for the radio, and nothing above it:

| Layer | Whose |
|---|---|
| Radio and MAC — `wonder.ko` | **vendor** (Google/Broadcom kernel module) |
| AWDL protocol — election, sync, peers, action frames — `libmosey_daemon_ffi.so` | **vendor** (Google userspace blob) |
| Lifecycle, privilege split, the AWDL interface, routing | **ours** |
| mDNS `_airdrop._tcp` — advertise, browse, resolve | **ours** |
| TLS listener and the HTTPS server | **ours** |
| The AirDrop protocol — `/Discover`, `/Ask`, `/Upload`, Apple plists | **ours** |
| cpio extraction, the inbox, the consent prompt | **ours** |
| BLE beacon, share sheet, UI | **ours** |

Both blobs already ship in the vendor image of supported Pixels. Barq does not install
them, and a phone running Barq has nothing on it that a stock phone does not — they are
radio drivers, not Play Services. Replacing them with an open AWDL implementation is
possible, and is why the FFI is isolated behind a single file, but it is not what Barq
does today.

**Quick Share uses no vendor blobs at all.** Every layer is ours:

| Layer | |
|---|---|
| BLE discovery — wake-up pulse and endpoint advertisement | ours |
| UKEY2 handshake — commitment, P-256 ECDH, key confirmation | ours |
| D2D key derivation, SecureMessage envelope | ours |
| Secure channel — traffic keys, sequence numbers, replay refusal | ours |
| Length-prefixed framing, Nearby Connections offline frames | ours |
| Payload reassembly, with its bounds checks | ours |
| Nearby Sharing frames — introduction, response, paired key | ours |
| Ordering state machines, bandwidth upgrade | ours |
| Bluetooth transport, socket handling | ours |

That half is **6,600 lines of Rust with 163 tests**, including one that runs a whole
share between two peers inside a single process: handshake, key derivation, encrypted
channel, introduction, acceptance, and a file in chunks, reassembled and compared byte
for byte.

Some of it could not be captured off the air and had to be derived — the RFCOMM service
UUID a peer listens on never appears in a packet, and the BLE advertisement's field
layout is documented nowhere public. Where a value came from someone else's work, the
comment beside it says whose.

## Status

**Bidirectional AirDrop with a Mac, on a GrapheneOS build with no Google
applications installed, under SELinux enforcing.** Files go both ways, the peer
shows a real device name, and an incoming transfer has to be accepted by a person.

```
init.svc.barqd        = running     u:r:barqd:s0        user system
init.svc.barqsharingd = running     u:r:barqsharingd:s0 user system_ext_barq

barqd:        AWDL session up, handle=0xc00c19599c6bc80, channel=149, country=QA
barqd:        rule: oif mosey0 lookup 54
barqsharingd: AirDrop server up as "Pixel 10 Pro XL"
barqsharingd: advertising as 7249a325a6b8._airdrop._tcp.local
barqsharingd: peer 4d1a2c9f8e70 at fe80::… is "K-MBProM5"

notifications ........ 0
```

| | state |
|---|---|
| AWDL bring-up, routing, peers | working |
| mDNS browse + advertise, with withdrawal | working |
| TLS, `/Discover`, `/Ask`, `/Upload` | working |
| receive from a Mac, cpio + AppleDouble extraction | working |
| send to a Mac, gzip payload, decline reported | working |
| per-transfer accept/decline prompt | working |
| radio held only while something wants it | working |
| AWDL + Wi-Fi at the same time | **chip-dependent** — see below |
| contacts-only AirDrop | **not implemented, not planned** — it needs a real Apple contact certificate, which expires. Everyone-mode only. |

### AWDL and Wi-Fi share one radio

Barq puts AWDL in the **opposite band** from the Wi-Fi association: 2.4 GHz when Wi-Fi
is on 5 GHz and vice versa. The frequency comes from the client through `setActive`,
because both daemons are native and neither can see the Wi-Fi state.

That is sufficient on **BCM4390** (Pixel 10 Pro XL), where `wondertap` exists,
`wonder.ko` binds, and AWDL runs on its own wiphy. Verified with both live for 90
seconds continuously.

It is **not** sufficient on **BCM4383** (Pixel 10), which has no `wondertap`. Barq
falls back to driving `radiotap0`, a monitor interface that takes the physical radio
with it whatever channel is requested — AWDL works, discovery and transfers work, and
Wi-Fi drops and does not return until the device reboots.

Check the chip, not the model. Every Pixel 10 image ships both drivers:

```bash
adb shell 'lsmod | grep bcmdhd'        # 4390 = concurrent, 4383 = exclusive
adb shell 'ls /sys/class/ieee80211/'   # a `wonder` wiphy is the real test
```

Whether this is inherent to the chip or an artefact of hardcoding
`is_dbs_supported=true` is the open question — see docs/TODO.md.

### The radio is held on demand

`barqd` does not hold AWDL from boot any more. An idle session costs **6.5% of a
core continuously** — `libmosey` runs its own threads inside whichever process
holds the handle — so the session follows `barq.awdl.wanted`, which
`barqsharingd` sets from *a client is on screen, or a transfer is running, or we
are advertising*. Released, `barqd` costs 0.05%.

`barqd` itself is still started once by `init` at boot and never restarted; only
the session comes and goes. See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for
why it is a property and not `ctl.start` or binder.

### Quick Share

The second protocol, for Android and Windows peers, is in progress. The **protocol is
complete and tested** — `libbarq_protocol` is 6,600 lines of Rust with 157 tests,
including one that runs a whole share between two peers in a single process: UKEY2
handshake, key derivation, encrypted channel, introduction, acceptance, and a file in
chunks, reassembled and compared byte for byte.

Discovery over BLE works against real devices: a Windows machine running Quick Share is
found by name with no network involved at all.

What is not finished is the transport plumbing — an mDNS responder for the same-network
case, and the Wi-Fi Direct half of the no-network case. See
[docs/TODO.md](docs/TODO.md).

## Clients

The daemon owns the client contract, in `aidl/dev/barq/`:

```
IBarqService.aidl    getStatus, setDiscoverable, setActive, getPeers, sendFiles,
                     respondToOffer, cancelTransfer, getReceivedFiles,
                     openReceivedFile, deleteReceivedFile,
                     register/unregisterCallback, refreshPeers,
                     setPolicy, getPolicy, setDeviceName, getDeviceName,
                     reportBlePeer
IBarqCallback.aidl   onPeerFound/Lost, onTransferOffered/Progress/Finished
```

It lives here rather than in the client because the daemon is the server: it
defines the protocol and a client is written against it. [Barq
app](https://github.com/bodaay/barq-app) consumes these files directly instead of
keeping its own copy,
so the two cannot drift apart silently.

Two rules the contract encodes deliberately:

- **Discoverability is daemon state, not app state.** It survives a client that is
  merely rebinding. It does not survive the radio being released — see
  `setActive`, which is a separate signal on purpose, because a client that is
  *sending* is not discoverable and needs the link more than ever.
- **Every callback is `oneway`.** The daemon must never block on a UI process
  that may be slow, frozen, or about to be killed. A client that is not running
  is the normal case, not an error.

## How it works

```
app  --binder-->  barqsharingd  --property-->  barqd  --dlopen-->  libmosey
     setActive()                 barq.awdl.wanted

init  --(sys.boot_completed)-->  barqd        (once, and never restarted)
                                   |  wait for barq.awdl.wanted
                                   |
                                   |  on 1:  mosey_start_5(channels, country, config, ...)
                                   |             -> wonder.ko over nl80211
                                   |             -> mosey0 appears with a link-local address
                                   |         RTM_NEWROUTE  fe80::/64 dev mosey0 table <ifindex>
                                   |         RTM_NEWRULE   oif mosey0 lookup <ifindex>
                                   |
                                   |  on 0:  RTM_DELRULE, then mosey_stop(handle)
                                   |
                                   +-- SIGTERM --> mosey_stop(handle)

init  --(sys.boot_completed)-->  barqsharingd (no capabilities)
                                   |  publish dev.barq.IBarqService
                                   |  mDNS browse/advertise on mosey0
                                   |  TLS listener on [fe80::…%mosey0]:8770
                                   +  rebind both whenever mosey0 is replaced
```

Two details that are not obvious and cost real time to find:

**The session lives exactly as long as the process holding the handle.** Exit and
`mosey0` disappears. `barqd` therefore does nothing but hold it — which is also
why the client app must never be the holder.

**It can be stopped and started again in one process.** `mosey_start_5` after
`mosey_stop` works: new handle, new interface index, new link-local address, ~360 ms
plus a 2 s settle. This was tested before anything was built on it, because
`libmosey` is a closed blob and the whole on-demand design depends on it.

**Every cycle changes the interface index, and the table id IS the index.** So the
fib rule is deleted before it is added and removed on release, and anything holding
a socket on `mosey0` has to notice and rebind. Note that a blocking `accept()` on a
socket bound to an address that no longer exists never returns *and never errors*.

**An address is not enough.** Android routes by fwmark and gives a new interface
its own routing table, which starts *empty* — `connect()` returns
`ENETUNREACH` despite a valid address and a reachable neighbour. `barqd` adds the
link-local route itself, over netlink rather than by running `ip`, so the daemon
never needs permission to execute anything.

## Layout

```
src/main.rs              barqd — the privileged half: session lifecycle, routing
src/mosey.rs             the vendor FFI, isolated to one file
src/route.rs             netlink: the link-local route and the fib rule
sharingd/src/            barqsharingd — mDNS, TLS, HTTP, plist, cpio, transfers
aidl/dev/barq/           the client contract (AIDL)
init/barq.rc             init service: user system, group system inet, NET_ADMIN NET_RAW
Android.bp               rust_binary x2, system_ext
sepolicy/barqd.te        SELinux domain, privileged half
sepolicy/barqsharingd.te SELinux domain, no capabilities
sepolicy/barq.te         types shared between the two
sepolicy/file_contexts   labels both binaries
sepolicy/service_contexts labels the binder service name
sepolicy/property_contexts labels barq.awdl.wanted
docs/ARCHITECTURE.md     the two-process split and the Rust decision
docs/MOSEY-FFI.md        the vendor ABI barqd calls, and how it was recovered
docs/INTEGRATING.md      what a platform must provide, and the traps
```

## Building

Barq is built by the platform build, not standalone — it is a system daemon and
wants the platform toolchain, labelling and signing. Drop it into an AOSP-derived
tree and add it to a product:

```make
PRODUCT_PACKAGES += barqd barqsharingd
```

then install `sepolicy/` into the tree's private policy. The GrapheneOS buildfarm
does this with `scripts/gos-barq.sh`.

All of `sepolicy/` must be installed, not just the `.te` files — `file_contexts`
labels the executables, `service_contexts` labels the binder service name, and
`property_contexts` labels `barq.awdl.wanted`. Each missing one fails differently
and none of them fails loudly. In particular, `sepolicy/barqd.te` must be
installed **with** `sepolicy/file_contexts`. Without
the label the domain exists but nothing ever runs in it — the build succeeds,
policy contains `barqd`, and `init` silently runs the daemon in its own domain
instead. That failure looks correct from every angle except the one that matters.

## Requirements

- `libmosey_daemon_ffi.so` present and loadable. barqd tries the plain soname
  first, then the usual paths, and honours `BARQ_MOSEY_LIB` as an override.
  **Shipping and pinning that library is the integrator's job** — barqd is
  distribution-agnostic and only requires that one is there.
- `wonder.ko` bound to the Wi-Fi driver. On Pixel 10 that is every model except
  the 10a (`bcmdhd4383` has no `wondertap` support).
- A build you can add SELinux policy to.

Integration details, and the failures worth knowing about in advance, are in
**[docs/INTEGRATING.md](docs/INTEGRATING.md)** — including why
`sepolicy/file_contexts` must be installed alongside the `.te`, and why trimming
the policy costs a build cycle each time.

## Name

بَرْق — *barq*, Arabic for lightning; historically the word for telegraph.

## Running it on GrapheneOS

Barq is built to be integrated into an OS image, not sideloaded: it is two `init`
services with their own SELinux domains and a dedicated AID, none of which an APK can
give itself. [docs/GRAPHENEOS.md](docs/GRAPHENEOS.md) is the full procedure — what to
copy, what to wire into the build, the one framework patch that is required and why, and
how to verify each step landed.

It is written for GrapheneOS because that is where it was developed, but nothing in it is
GrapheneOS-specific. The same steps apply to AOSP or to any build you control.

## Credits

**[Bada](https://github.com/kyujin-cho/Bada)** is a working Quick Share implementation
for Android, in Kotlin, under Apache 2.0. `libbarq_protocol` is a Rust port of the
protocol layers of its `core-protocol` module. The code here is rewritten — different
language, different process model — but the protocol knowledge is Bada's, and several
constants in this implementation exist because Bada found them first and wrote down why
they matter. Where a value came from Bada, the comment beside it says so.

**[OpenDrop](https://github.com/seemoo-lab/opendrop)** and the AWDL research from the
Secure Mobile Networking Lab at TU Darmstadt are what made the AirDrop side tractable.

## License

Apache License 2.0 — see [LICENSE](LICENSE) and [NOTICE](NOTICE).

Apache 2.0 rather than MIT deliberately: this is a clean-room implementation of two
proprietary protocols, and Apache's patent grant matters more here than the shorter
licence text does. It is also Bada's licence and AOSP's, so nothing downstream has to
reason about compatibility.

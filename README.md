# Barq

**`barqd`** — an AWDL transport daemon for Android.

Barq brings up and holds an [AWDL](https://en.wikipedia.org/wiki/Apple_Wireless_Direct_Link)
link — the Wi-Fi peer-to-peer layer Apple devices use for AirDrop — as a native
system daemon, and hands the rest of the system a working IPv6 interface with
discovered peers on it.

It exists so that a sharing *app* does not have to. On Android, third-party code
that wants to keep running must hold a foreground service and therefore a
permanent visible notification. A native daemon started by `init` has no such
obligation: no foreground-service rule, no Doze, no app-standby, no notification.
Barq takes the transport so the UI can be an ordinary app that is not running most
of the time.

This is the same split Apple and Google both ship. Google's is `mosey_server`
(native, `system`, `NET_ADMIN|NET_RAW`, invisible) plus a client app; Apple's is
`sharingd`. Barq is the equivalent piece for a build that has neither.

## Status

Working, and narrow. On a GrapheneOS build for Pixel 10 with **no Google
applications installed**:

```
init.svc.barqd = running        pid = 3520
context = u:r:barqd:s0          user = system
barqd: AWDL session up, handle=0xf00cfac6a13e980, channel=149
barqd: route: fe80::/64 dev mosey0 table 52
mosey0  fe80::857:88ff:fe44:9fe9/64

AVC denials .......... 0
notifications ........ 0
```

Peer discovery, master election and availability-window synchronisation all run;
a macOS peer is discovered, elected master and installed in the kernel neighbour
table.

**What Barq does not do yet:** mDNS (`_airdrop._tcp.local`), the AirDrop protocol
itself, and the IPC implementation. It is the transport and nothing above it.

## Clients

The daemon owns the client contract, in `aidl/dev/barq/`:

```
IBarqService.aidl    getStatus, setDiscoverable, getPeers, sendFiles,
                     respondToOffer, cancelTransfer, register/unregisterCallback
IBarqCallback.aidl   onPeerFound/Lost, onTransferOffered/Progress/Finished
```

It lives here rather than in the client because the daemon is the server: it
defines the protocol and a client is written against it. [Barq
app](../barq-app) consumes these files directly instead of keeping its own copy,
so the two cannot drift apart silently.

Two rules the contract encodes deliberately:

- **Discoverability is daemon state, not app state.** Closing the client must not
  stop the device being reachable.
- **Every callback is `oneway`.** The daemon must never block on a UI process
  that may be slow, frozen, or about to be killed. A client that is not running
  is the normal case, not an error.

## What is actually Barq, and what is not

Barq is ~400 lines. It would be misleading to call it an AWDL implementation.

| Layer | Provided by | Whose |
|---|---|---|
| Radio / MAC | `wonder.ko` | vendor kernel module (Google/Broadcom) |
| AWDL protocol — election, sync, peers, action frames | `libmosey_daemon_ffi.so` | vendor userspace blob (Google) |
| **Lifecycle, privileges, routing, integration** | **`barqd`** | **this repo** |

Both blobs already ship in the vendor image for supported devices, so Barq adds
nothing to a phone that is not already on it — but the AWDL protocol itself is
Google's, loaded through a five-function C ABI. Barq is a *host* for it with its
own lifecycle and privilege model.

Replacing that layer with an open implementation (e.g. OWL) is possible and is
the reason the FFI is isolated behind one file, but it is not what Barq does
today.

## How it works

```
init  --(sys.boot_completed)-->  barqd
                                   |  dlopen libmosey_daemon_ffi.so
                                   |  mosey_start_5(channels, country, config, ...)
                                   |      -> wonder.ko over nl80211
                                   |      -> mosey0 appears with a link-local address
                                   |  RTM_NEWROUTE  fe80::/64 dev mosey0 table <ifindex>
                                   |  hold the session handle
                                   +-- SIGTERM --> mosey_stop(handle)
```

Two details that are not obvious and cost real time to find:

**The session lives exactly as long as the process holding the handle.** Exit and
`mosey0` disappears. `barqd` therefore does nothing but hold it.

**An address is not enough.** Android routes by fwmark and gives a new interface
its own routing table, which starts *empty* — `connect()` returns
`ENETUNREACH` despite a valid address and a reachable neighbour. `barqd` adds the
link-local route itself, over netlink rather than by running `ip`, so the daemon
never needs permission to execute anything.

## Layout

```
src/barqd.c              the daemon
aidl/dev/barq/           the client contract (AIDL)
init/barq.rc             init service: user system, group system inet, NET_ADMIN NET_RAW
Android.bp               cc_binary, system_ext
sepolicy/barqd.te        SELinux domain
sepolicy/file_contexts   labels /system_ext/bin/barqd
docs/MOSEY-FFI.md        the vendor ABI barqd calls, and how it was recovered
```

## Building

Barq is built by the platform build, not standalone — it is a system daemon and
wants the platform toolchain, labelling and signing. Drop it into an AOSP-derived
tree and add it to a product:

```make
PRODUCT_PACKAGES += barqd
```

then install `sepolicy/` into the tree's private policy. The GrapheneOS buildfarm
does this with `scripts/gos-barq.sh`.

`sepolicy/barqd.te` must be installed **with** `sepolicy/file_contexts`. Without
the label the domain exists but nothing ever runs in it — the build succeeds,
policy contains `barqd`, and `init` silently runs the daemon in its own domain
instead. That failure looks correct from every angle except the one that matters.

## Requirements

- A device whose vendor image ships `wonder.ko` and `libmosey_daemon_ffi.so`.
  On Pixel 10 that is every model except the 10a, whose Wi-Fi driver
  (`bcmdhd4383`) has no `wondertap` support at all.
- `userdebug` or a build you can add SELinux policy to.

## Name

بَرْق — *barq*, Arabic for lightning; historically the word for telegraph.

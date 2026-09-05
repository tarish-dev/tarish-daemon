# The shape this should be

Not a plan of work. A decision record: where the privilege boundary belongs, why the
current one is in the wrong place, and the two questions still open.

Nothing here is built. `docs/ARCHITECTURE.md` describes what exists today.

## Where we are

| | privilege | does | parses hostile input |
|---|---|---|---|
| `barqd` | `system`, `CAP_NET_ADMIN`, `CAP_NET_RAW` | libmosey FFI, nl80211, brings up `mosey0`, routes and fib rules | no, by design |
| `barqsharingd` | uid 7500, no capabilities | AirDrop mDNS/TLS/HTTP/plist/cpio; Quick Share protocol; writes received files | everything |
| `BarqApp` | **platform certificate, privileged** | BLE, Bluetooth sockets, UI, prompts | some |

The first two are a deliberate split and a good one: capabilities in the process that
parses nothing, parsing in the process that holds nothing.

**The app being privileged was never decided.** It holds a platform certificate for one
reason: `android.os.ServiceManager.getService()` is the only way an APK can reach a native
binder service, it is a hidden API, and hidden-API access comes with the platform
signature. Once signed that way every other privilege is free, so `BLUETOOTH_PRIVILEGED`
and `NETWORK_SETTINGS` were added without anything pushing back. `BLUETOOTH_PRIVILEGED` has
no call site at all.

That is the failure this document exists to correct: not a wrong decision, an absent one.

## Where it belongs

**The boundary is the radio, not the protocol.** Only AWDL needs a capability. Everything
above it is ordinary networking and framework API.

    barqd            privileged, in the OS image, three jobs and no more
    Barq (APK)       ordinary unprivileged app; Rust core over JNI

`barqd` reduces to:

1. start and stop the AWDL session — libmosey FFI, nl80211 vendor commands
2. bring up `mosey0`, install `fe80::/64` in its table and the **uid-scoped fib rule**,
   for the uid it reads from `SO_PEERCRED` on the control socket -- nothing hardcoded
3. report the interface index and link-local address, because the index changes every
   session and anything caching it breaks

It parses nothing, writes nothing, and knows no protocol.

Everything else is the app: mDNS, TLS, HTTP, plists, cpio, received files, BLE, Bluetooth
sockets, both protocol stacks, the UI.

**Quick Share then needs no OS support whatsoever.** No daemon, no image, no privilege, no
signature — a plain APK on any Android. Only AirDrop needs `barqd`, because only AWDL needs
`CAP_NET_ADMIN`. That is a far better story than "requires a custom ROM", and it is what
Bada already demonstrates: an ordinary app doing this protocol with no platform help.

## What disappears

| gone | why it ever existed |
|---|---|
| the app's platform certificate and privapp entry | one hidden-API lookup |
| `BLUETOOTH_PRIVILEGED` | nothing. No call site |
| `NETWORK_SETTINGS` | turning Wi-Fi on as a convenience |
| AID 7500, `barq_aid.txt`, `TARGET_FS_CONFIG_GEN` | a daemon must run as SOME uid and `nobody` is shared. Not a property we wanted |
| `/data/misc/barq/inbox`, its init mkdir and chmod | somewhere 0700 to stage files |
| the binder hop that copies files out, and most of `FileCollector` | crossing from uid 7500 to the app |
| `patches/packages_modules_Connectivity/*` | **a native daemon can never earn local-network access** -- the BPF bit is derived from installed packages. An app has one |
| the AID/patch consistency check in `gos-barq.sh` | keeping 7500 agreeing in two places |

The received-file path today is `daemon → /data/misc/barq/inbox (0700) → binder → app →
Downloads/Barq → MediaStore`. In the target it is: the app writes where it received. Two
hops and a private directory removed, and it fixes something already wrong -- a received
file currently sits somewhere no file manager can open until the app is foregrounded.

## The core stays Rust

`libbarq_protocol` is 193 tests and deliberately Android-free, which is why it is testable
on the build host with no device. **That is the asset**, and a rewrite in Kotlin would
reproduce the code and discard the evidence: the PIN derivation pinned against foreign
vectors, per-packet versus cumulative acknowledgements, the `0xFF -> "0001"` sign-extension
guard, LEGACY-mode framing, two real BLE captures. Every one of those tests exists because
it was got wrong first.

So: JNI, not a rewrite. `rust_ffi_shared` in-tree, or `cargo-ndk` with prebuilt `.so` per
ABI when the APK has to build outside the platform tree -- which it must, if MDM is to
install it. Four hazards, all known: `catch_unwind` at every entry point so no panic
crosses into the JVM; `AttachCurrentThread` for callbacks from Rust threads; a `GlobalRef`
for the callback object; `JNIEnv` is per-thread and never shared.

Keep the surface narrow -- roughly `send(fd, files, callbacks)`,
`serve(fd, callbacks)`, `confirm_pin`, `cancel`. Sockets, discovery and UI are already
Java and stay there.

## Two open questions

**1. Parsing moves into the app's uid.** Today a parser bug gets uid 7500: `inet`, its own
directory, and whatever descriptors were handed in. After the move the same bug is in a
process that can read the files the user selected, drive Bluetooth and BLE, and command
`barqd`. Rust makes that class of bug much less likely; the blast radius still widens.

Getting the isolation back means keeping a protocol process -- which is `barqsharingd`
again, app-owned rather than init-owned. `android:process` gives a separate process but the
same uid, so it is not a real boundary. **This is a trade to make deliberately, not by
omission.**

**2. AirDrop's boundary pins the signing key.** `barqd` exposes a Unix socket, which is
public API on the app side (`LocalSocket`) and needs no privilege to use. But *which* app
may command the radio? The workable answer is SELinux: give the app its own domain via
`seapp_contexts` keyed on package and signature, with the certificate in the image's
`mac_permissions.xml`.

So MDM can install the APK, but only a build signed with the key the image trusts can use
AirDrop. Quick Share, needing nothing, stays open to any build. A constraint rather than a
blocker, and arguably correct.

**And one consequence worth stating plainly:** listening while backgrounded needs a
foreground service, so being discoverable costs a visible notification. `barqd`'s own
header cites avoiding that as a reason for being a daemon. Since discovery and
discoverability are already foreground-only by decision, most of that advantage is already
spent -- and a notification that appears exactly when the device is discoverable is
arguably right for a privacy tool.

## Order, when it happens

1. Drop `BLUETOOTH_PRIVILEGED`. No call site; costs nothing to prove.
2. Move Quick Share into the app over JNI. It needs no privilege and no `barqd`, so it
   proves the JNI boundary and the build with nothing else at risk.
3. Move AirDrop's protocol layer, and shrink `barqd` to the three jobs above.
4. Drop the platform certificate, the privapp entry, AID 7500, the inbox and the framework
   patch -- all of which are unreachable until 3 is done.

Step 2 is the one that stands alone and is worth doing on its own merits.

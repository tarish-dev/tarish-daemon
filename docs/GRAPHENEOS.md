# Integrating Tarish into GrapheneOS

Written for GrapheneOS because that is where Tarish was developed, but nothing here is
GrapheneOS-specific — the same steps apply to AOSP or any build you control.

Tarish is **not** an app you can sideload. It is two `init` services with their own SELinux
domains, a dedicated Android ID, and one framework patch. None of that can be granted by
an APK, which is the whole reason the daemon exists: it holds the transport so the UI does
not have to be a permanently-running foreground service.

## What you are adding

| | |
|---|---|
| `tarishd` | holds the AWDL link. `CAP_NET_ADMIN`, `CAP_NET_RAW`, uid `system` |
| `tarishsharingd` | parses everything a stranger sends. **No capabilities**, uid 7500 |
| SELinux policy | two domains, plus file/service/property contexts |
| AID 7500 | `system_ext_tarish`, so the daemon owns its own files |
| one framework patch | `packages/modules/Connectivity` — see step 5 |

The split is the security design: the process holding `CAP_NET_ADMIN` never parses remote
input, and the process parsing remote input holds nothing. See
[ARCHITECTURE.md](ARCHITECTURE.md).

## Before you start

- A build tree you can modify and rebuild.
- A device you can flash. **A `user` build will not work for development** — you cannot
  read the daemon's logs or push a rebuilt binary. Use `userdebug`.
- The AWDL half additionally needs a Pixel with Google's `wonder.ko` and
  `libmosey_daemon_ffi.so` in its vendor image. Quick Share does **not** — it is plain
  Wi-Fi and works on any device.

---

## 1. Copy the source in

```bash
cp -r tarish-daemon /path/to/aosp/vendor/tarish
```

Anywhere works; `vendor/tarish` is used throughout this document and in the SELinux
policy's own comments.

## 2. Build the packages

Create `vendor/tarish/tarish.mk`:

```make
PRODUCT_PACKAGES += \
    tarishd \
    tarishsharingd
```

and inherit it from your device makefile:

```make
$(call inherit-product, vendor/tarish/tarish.mk)
```

On a Pixel with adevtool, the device makefile is
`vendor/google_devices/<device>/<device>.mk` — **which is generated**. Anything you add
there is destroyed by the next `adevtool generate-all`, so re-apply after every vendor
extraction. This is the most common way an integration silently reverts.

## 3. Declare the AID

`tarishsharingd` runs as uid 7500. Without this it runs as `nobody`, which is **shared** —
so `/data/misc/tarish` becomes readable by anything else running as `nobody`, defeating the
point of isolating it.

Add to your `BoardConfig.mk` or a device `.mk`:

```make
TARGET_FS_CONFIG_GEN += vendor/tarish/config/tarish_aid.txt
```

7500 sits inside `AID_SYSTEM_EXT_RESERVED` (7500–7999) and both daemons ship in
`system_ext`, so this is the range the platform reserved for exactly this.

## 4. Install the SELinux policy

Copy `vendor/tarish/sepolicy/` into your build's private policy directory and reference it:

```make
PRODUCT_PRIVATE_SEPOLICY_DIRS += vendor/tarish/sepolicy
```

**Copy all of it, not just the `.te` files.** Four context files come with the policy and
each fails differently and silently:

| file | without it |
|---|---|
| `file_contexts` | the domain exists but nothing ever runs in it |
| `service_contexts` | the daemon cannot publish its binder service |
| `property_contexts` | its properties get the default label and `set_prop` on its own type is still denied |
| `seapp_contexts` | the app side cannot reach it |

Do **not** put the policy in `vendor/google_devices/<device>/sepolicy/` on a Pixel. That
directory is adevtool output and is regenerated; the policy will vanish.

## 5. Apply the framework patch — this one is not optional

```bash
cd packages/modules/Connectivity
git apply /path/to/vendor/tarish/patches/packages_modules_Connectivity/*.patch
```

**Why it is required.** Since Android B, local network access is gated by a BPF map.
`is_local_network_access_blocked()` exempts only uid 0 and uid 1000; every other uid needs
`PERMISSION_BIT_ACCESS_LOCAL_NETWORK` in `sUidPermissionChunkMap`, which
`PermissionMonitor` derives from **installed packages**. A native daemon has no package,
so it can never earn the bit. Every mDNS `sendto()` then fails with `EPERM` — the daemon
starts, advertises, looks entirely healthy, and never sends a packet.

**`repo sync` silently discards this patch.** Re-apply after every sync and verify with
`git apply --check` rather than assuming.

The patch hardcodes 7500 and so does `config/tarish_aid.txt`. Change one and you must change
the other; they cannot disagree quietly.

See [../patches/README.md](../patches/README.md) for the full reasoning.

## 6. Build and flash

```bash
source build/envsetup.sh
lunch <device>-cur-userdebug
m
```

---

## Verifying it, step by step

Do these in order. Each one fails in a way that looks like the next one's problem.

**The services started, in the right domains and as the right users:**

```
$ adb shell 'getprop init.svc.tarishd; getprop init.svc.tarishsharingd'
running
running

$ adb shell 'ps -A -o USER,NAME | grep tarish'
system            tarishd
system_ext_tarish   tarishsharingd
```

If `tarishsharingd` runs as `nobody`, step 3 did not take. If a service is absent, check
`logcat` for an SELinux denial on `execute_no_trans` — that is step 4.

**The binder service is published:**

```
$ adb shell service list | grep tarish
dev.tarish.ITarishService/default: [dev.tarish.ITarishService]
```

Absent means `service_contexts` is missing.

**The framework patch is live:**

```
$ adb shell dumpsys connectivity | grep 7500
7500  PERMISSION_ACCESS_LOCAL_NETWORK  PERMISSION_INTERNET
```

Absent means step 5 did not apply, or `repo sync` removed it. The daemon will run
perfectly and never send an mDNS packet.

**No denials:**

```
$ adb logcat -b all -d | grep -i "avc:.*denied" | grep tarish
```

Should be empty.

---

## Things that look like failure and are not

- **`tarishd` idles with no AWDL session.** Correct. The radio is only held while a client
  is on screen or a transfer is running — otherwise it costs battery for nothing.
- **`mosey0` does not exist yet.** It appears when the session starts, and gets a **new
  interface index every time**. Anything caching that index will break.
- **The peer list is empty on a network with client isolation.** Most hotel and guest
  Wi-Fi blocks multicast, so mDNS discovery cannot work. This is the network, not the
  build — BLE discovery is unaffected.

## What this does not give you

The daemon is the transport and the protocol. **It has no user interface.** Discovering a
peer, showing a transfer prompt, and BLE advertising all need an app, because a native
daemon cannot reach framework Bluetooth or draw anything. See
[tarish-app](https://github.com/tarish-dev/tarish-app).

Tarish also does not replace `wonder.ko` or `libmosey_daemon_ffi.so` for AirDrop — those are
Google's, already in the Pixel vendor image, and Tarish drives them rather than
reimplementing them. Quick Share has no such dependency.

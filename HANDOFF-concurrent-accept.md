# Handoff: build & verify the concurrent-accept fix (branch `httpd-concurrent-accept`)

**Goal:** build `tarishsharingd` from this branch, deploy it, and confirm it fixes the
discovery/throughput instability — the single-threaded httpd accept loop that churns
connections (SYN/RST storm) and blocks live transfers for seconds. Prod users on the
libmosey transport report the same discovery unreliability, so this is a prod fix, not a
dev-only one.

Full diagnosis: `tarish-link/docs/FINDINGS.md` findings 109 and 110.

## What changed (commit 82d94cc)

- `sharingd/src/httpd.rs`: `serve()` now takes `Arc<Self>` and spawns **one thread per
  accepted connection** (`serve_one`), instead of accepting → fully serving → then
  accepting the next. Shared state is all `Arc` (`SslAcceptor` is `Send+Sync`;
  `Discoverable`/`Callbacks`/`Transfers` are `Arc<…>`), and every handler is `&self`.
  Falls back to inline serving if a thread can't spawn.
- `sharingd/src/main.rs`: wraps the server in `Arc::new(server).serve()`.

**Untested** — it only compiles under Soong (Android `binder`), which needs the build host.

## Build (on the build host — a LOGIN shell, per CLAUDE.md)

The build host is `ubuntu@192.168.200.252`, source at `/srv/src/grapheneos`. `bf-run`/env are
only on PATH in a login shell, so wrap remote commands in `bash -lc "…"`.

1. Get this branch into the tree. `scripts/gos-tarish.sh` copies the checkout into
   `vendor/tarish/` and wires it, so make the build host's `tarish-daemon` checkout be on
   `httpd-concurrent-accept` (fetch/checkout there, or set `TARISH_SRC`), then:
   ```bash
   ssh ubuntu@192.168.200.252 'bash -lc "cd ~/grapheneos && ./scripts/gos-tarish.sh --install"'
   ```
2. Targeted module build (far faster than a full image):
   ```bash
   ssh ubuntu@192.168.200.252 'bash -lc "cd /srv/src/grapheneos && source build/envsetup.sh && lunch <device>-cur-user && m tarishsharingd"'
   ```
   The binary lands under `$OUT_DIR` (…/system_ext/bin/tarishsharingd).

## Deploy to the device (workstation with the phone)

```bash
scp ubuntu@192.168.200.252:/srv/build/grapheneos/.../system_ext/bin/tarishsharingd /tmp/tarishsharingd
adb push /tmp/tarishsharingd /data/local/tmp/tarishsharingd
adb shell su 0 mount -o rw,remount /system_ext
adb shell su 0 cp /data/local/tmp/tarishsharingd /system_ext/bin/tarishsharingd
adb shell su 0 restorecon /system_ext/bin/tarishsharingd
adb shell su 0 setprop ctl.restart tarishsharingd   # (or ctl.restart tarishd to bounce the stack)
```

## Verify (measure over SEVERAL runs — the metric has ~4× run-to-run variance, finding 110)

1. **Discovery:** reboot an iPhone (clears its cache), set AirDrop to **Everyone**, open the
   share sheet. It should render "Pixel 10 Pro" promptly and repeatably, not "declined first
   time / works second." Test on both iPhones.
2. **Connection churn gone:** capture `tlink0` TCP during a receive and count SYN/RST:
   ```bash
   adb shell su 0 tcpdump -i tlink0 -nn -S "tcp port 8770"
   ```
   The ~95-SYN / ~33-RST storm should be gone (a handful of clean connections instead).
3. **Throughput/stalls:** send the same file 3–5× and look at the inbound gaps. Before, the
   4.5 MB MP4 took 17–64 s with multi-second stalls; expect fewer/shorter stalls and lower
   variance. Compare against stock libmosey (`/data/local/tmp/libmosey_stock.so`) as the
   baseline, same file, same direction.

Works on **both** transports (this fix is above the radio): test with our shim
(`/data/local/tmp/shim.so` → `/system_ext/lib64/libmosey_daemon_ffi.so`) and with stock
libmosey. The Pi (`pi@192.168.0.232`, ALFA `wlx00c0cab0604c`, monitor on ch6) is the
independent on-air witness.

## If it helps, then revisit (in this order)

1. **immediate-ACK is already in** `tarish-link` (c1976b9) — keep it.
2. Only after churn is fixed, re-evaluate **ACK redundancy** (`ACK_REPEAT` knob in
   `tlink-session`, currently a no-op) with a proper multi-run A/B — it was inconclusive and
   possibly contention-negative while churn dominated (finding 110).

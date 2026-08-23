# Architecture

Two decisions taken 2026-08-23, before the code grew, because both are expensive
to reverse afterwards.

## Two processes, split by privilege

```
barqd                                  barqsharingd
  privileged                             unprivileged
  user system                            user barq
  CAP_NET_ADMIN, CAP_NET_RAW             no capabilities
  own SELinux domain                     own SELinux domain

  holds the AWDL session                 mDNS on mosey0
  drives wonder.ko via libmosey          AirDrop protocol: TLS, HTTP, plist, cpio
  adds the link-local route              the actual file transfer
                                         publishes IBarqService to the app
```

**Why split.** Everything in the right-hand column parses input from a remote
device over the air. That is the classic remote-code-execution surface, and the
left-hand column holds `CAP_NET_ADMIN` and `CAP_NET_RAW`. Putting them in one
process means a bug in a cpio header is a compromise of a privileged process.

The privileged half is small, stable, and parses nothing from the network — it
calls a vendor library and adds a route. Keeping it that way is the point.

The client app talks to `barqsharingd`, not to `barqd`. The app never needs the
privileged process, and `barqd` publishes no binder service — which is why its
SELinux domain deliberately grants no `servicemanager` access.

**The names are deliberately not `barqd`/`barqsd`.** One-letter-apart daemon
names are easy to misread in a log or a `ps` listing, which is exactly when you
are least able to afford it.

## Rust, not C

`barqd` began as ~200 lines of C — a `dlopen` shim, which C is fine for. The
sharing daemon will be thousands of lines of parsing untrusted network input:
Apple property lists, cpio archives, HTTP framing, TLS records.

That is the wrong place for a memory-unsafe language, on an OS whose entire
premise is hardening. `mosey_server` — the daemon this replaces — is itself
Rust, which is a reasonable signal about the right tool.

Confirmed available in an AOSP-derived tree:

| | |
|---|---|
| Rust builds | `rust_binary` modules build and install today (`mmd` is one) |
| crates | 603 vendored in `external/rust/android-crates-io`, incl. `rustls`, `ring`, `tokio`, `serde`, `libc`, `anyhow`, `android_logger` |
| AIDL | has a Rust backend; `libbinder_rs` is in the tree |
| TLS | `rustls` + `ring`, so no BoringSSL FFI needed |

Not available: `plist`, `quick-xml`. Apple's AirDrop uses **binary** plists, which
we would parse ourselves regardless.

**The FFI stays unsafe and stays small.** `libmosey_daemon_ffi.so` is a C ABI, so
calling it needs `unsafe`. That is confined to one module in `barqd`, which is
also the only place a vendor ABI change can break us.

## What this means for the current C daemon

`barqd` as it exists — C, working, holding AWDL at boot with zero denials — is a
**prototype of the privileged half**. It stays until the Rust port replaces it,
because a working daemon beats a planned one. It is not the shape we are keeping.

## Order of work

1. Port `barqd` to Rust. Small, self-contained, proves the Rust build and the
   FFI boundary in the tree.
2. `barqsharingd` skeleton: its own user, SELinux domain, and the `IBarqService`
   implementation. No protocol yet.
3. mDNS on `mosey0`, so peers become discoverable.
4. The AirDrop protocol.

Each step is testable on hardware before the next, which is how the transport got
built and is the reason it works.

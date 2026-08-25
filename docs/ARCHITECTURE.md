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


## The radio is held on demand

`barqd` no longer holds the AWDL session from boot to shutdown. It holds it while
something wants it, and `barq.awdl.wanted` is how it is told.

```
app  --binder-->  barqsharingd  --property-->  barqd  --dlopen-->  libmosey
     setActive()                barq.awdl.wanted        mosey_start_5 / mosey_stop
```

An idle session costs 6.5% of a core continuously — libmosey runs its own threads inside
whichever process holds the handle — so this is worth doing. Released, `barqd` costs
0.05%.

**The gate is not visibility.** A client that is sending is not discoverable and needs the
link; a client bouncing through a file picker toggles the foreground several times a
second. So the daemon ORs three inputs and applies its own hold-off:

| input | why it is sufficient on its own |
|---|---|
| `setActive` | a client is on screen and may send or receive at any moment |
| transfer in flight | bytes are moving; releasing here kills the transfer |
| `discoverable` | we are advertising, and advertising without a link is a lie |

Rising edges apply at once. Falling edges wait out a 30-second linger.

**`barqd` is never restarted to do this.** It stays init-started, once, at boot, and keeps
its capabilities for its whole life; only the session comes and goes. `ctl.start`/
`ctl.stop` would not have leaked privilege — init applies the `.rc`, not the caller's
context — but it would have given an unprivileged domain the power to start and stop a
privileged process, and that is not a trade worth making for battery life. A property is
read-only from `barqd`'s side and carries one boolean, which is the smallest channel that
does the job.

**It fails towards working.** With the property absent, `barqd` holds the radio up. A
missing `set_prop` rule therefore costs battery rather than breaking the transport.

### What this means for anything bound to `mosey0`

The interface now genuinely disappears and returns **with a new index and a new
link-local address**. Anything holding a socket on it must notice and rebind. Both places
that do are in `barqsharingd`:

- the mDNS browser compares the index every pass
- the HTTPS listener uses a non-blocking accept and compares address and index, because
  a blocking `accept()` on a dead address never returns and never errors

## Receiving asks first

`POST /Ask` used to answer `200` unconditionally: while the app was open, any device in
range could put a file on this one with no prompt. Visibility was the entire consent
model.

It now raises `onTransferOffered` with the sender's name and the file names, and blocks
for up to 45 seconds waiting for `respondToOffer`. **No answer is a refusal** — otherwise
waiting out the timeout would itself be a way onto the device. A decline answers `401`,
which is what an Apple receiver sends and what our own sender already reports as
"Declined".

`POST /Upload` is refused outright when no offer has been accepted. `/Ask` and `/Upload`
normally share a connection, but nothing stops a peer opening a fresh one and posting
straight to `/Upload`, which would walk right past the prompt.


## Being invisible is something we say

Three things have to agree, or the device stays on a peer's list after it has stopped
being able to receive anything:

| | when not discoverable |
|---|---|
| mDNS | records **withdrawn** with a TTL-0 goodbye, not merely unanswered |
| `HEAD /`, `POST /Discover` | 401 — an invisible device does not identify itself |
| `POST /Ask` | 401 |

Withdrawing without gating `/Discover` is not enough: a peer with a cached record asks
directly and is told the device's name, which is all it needs to keep drawing the row.
Gating without withdrawing is not enough either — the row stays for the record TTL, and
picking it fails.

`POST /Upload` is deliberately **not** in that table. It is authorised by an accepted
offer, not by current visibility, so a transfer someone agreed to cannot fail partway
through because a visibility timer lapsed.

# tarish-daemon

The transports for **[Tarish](https://github.com/tarish-dev/tarish-app)** — AirDrop and Quick
Share on Android with no Google Play Services and no Google account.

> ### 📖 Documentation lives in the app repository
>
> **[github.com/tarish-dev/tarish-app](https://github.com/tarish-dev/tarish-app)** is the home of the
> project. What Tarish is, why it exists, which devices it works on, how to integrate it into
> GrapheneOS or LineageOS, the protocol notes, the policy model and the open issues are all
> documented there, for both halves.
>
> This repository is the code.

---

## What is in here

| | |
|---|---|
| `src/`, `tarishd` | holds the AWDL link up. Needs `CAP_NET_ADMIN`; runs from boot so the link outlives any UI |
| `sharingd/` | `tarishsharingd`: mDNS, TLS, the AirDrop protocol, the Quick Share transports. Runs as its own unprivileged uid and parses input from strangers, so it holds nothing else |
| `protocol/` | `libtarish_protocol`: UKEY2, D2D keys, SecureMessage, the secure channel, offline frames and the sharing state machines. **Android-free on purpose**, so it is testable on a build host — 202 tests |
| `tarishctl/` | a shell client for the daemon, **userdebug and eng only**. Two devices driven from a script, no screen taps |
| `aidl/` | the IPC contract. It lives with the daemon because the daemon is the server; the app consumes these files rather than copying them |
| `sepolicy/` | the SELinux domains, and the four context files that each fail differently and none loudly |
| `config/`, `init/` | the AID and the init scripts |
| `patches/` | the framework patch that lets an unprivileged uid reach the local network |

## Building

Inside a platform tree:

```make
PRODUCT_PACKAGES += tarishd tarishsharingd
```

The protocol library builds and tests off-device:

```bash
atest tarish_protocol_test
```

Everything else — the AID wiring, the policy install, the framework patch, the vendor pin,
and how to verify each stage separately — is in
**[the integration guide](https://github.com/tarish-dev/tarish-app/blob/main/docs/GRAPHENEOS.md)**.

## The vendor pin is the integrator's job, not this repository's

`tarishsharingd` requires `libmosey_daemon_ffi.so` to be present and does not care where it
came from: it tries the soname, then the usual paths, then `TARISH_MOSEY_LIB`. Shipping and
pinning that blob belongs to whoever is building the OS.

Keeping it out of here is what lets the daemon run on LineageOS, or plain AOSP, without
carrying one integrator's vendor decisions.

## Licence

Apache 2.0. See [LICENSE](LICENSE).

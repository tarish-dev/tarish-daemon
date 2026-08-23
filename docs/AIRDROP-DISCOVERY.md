# How macOS actually discovers AirDrop peers

Captured off the wire between a MacBook Pro and this phone over AWDL, 2026-08-23.
Raw capture: [apple-airdrop-discovery-capture.txt](apple-airdrop-discovery-capture.txt).

## The finding

**`_airdrop._tcp.local` is not how modern macOS finds peers.** Advertising it and
answering correctly is not enough, and that is exactly what Barq did for several
build cycles while a Mac sat three feet away and never listed it.

Attributing every packet in a 260-packet capture to its sender:

```
19  phone   Q  _airdrop._tcp.local                        <- us, browsing
 1  Mac     Q  _airdrop._tcp.local                        <- asked ONCE
 3  Mac     Q  _applicationServicePairing._tcp.local
 3  Mac     Q  _appSvcPrePair._tcp.local
185 Mac     A  k-mbprom5._appsvcprepair._tcp.local
184 Mac     A  k-mbprom5._applicationservicepairing._tcp.local
```

The Mac asked about `_airdrop._tcp` **once** in fifteen minutes. Everything else
it did — hundreds of records — was two other services.

## What the Mac advertises

```
_services._dns-sd._udp.local  PTR -> _applicationservicepairing._tcp.local
_services._dns-sd._udp.local  PTR -> _appsvcprepair._tcp.local

k-mbprom5._appsvcprepair._tcp.local
    SRV -> 84717908-3422-48b5-b2be-53f0c066c0df.local:55573
    TXT    sn=com.apple.sharingd.AirDrop
           at=c35650444485
           sid=D593F104-38F3-4121-A0B4-4F166E5DC402
           dnm=K-MBProM5
           _dc=1

k-mbprom5._applicationservicepairing._tcp.local
    SRV -> 84717908-3422-48b5-b2be-53f0c066c0df.local:55574
    TXT    (same, WITHOUT dnm)
```

**AirDrop is named inside the TXT, not by the service type.**
`sn=com.apple.sharingd.AirDrop` is what marks these records as AirDrop; the
service itself is a generic Apple "application service pairing" mechanism that
presumably carries other services too.

## Field notes

| Field | Observed | Notes |
|---|---|---|
| `sn` | `com.apple.sharingd.AirDrop` | the service identity — this is the AirDrop marker |
| `at` | `c35650444485`, earlier `004eb9b20bd5` | 12 hex, **changes between sessions** |
| `sid` | a UUID, different each session | session identifier |
| `dnm` | `K-MBProM5` | the displayed device name. Present on `_appsvcprepair` only |
| `_dc` | `1` | unknown |

Instance name is the device name lowercased (`K-MBProM5` -> `k-mbprom5`), not an
opaque id. The **host** is a UUID, and it also changes per session.

Two ports, adjacent and ephemeral-looking: `55573` for pre-pair, `55574` for
pairing. They differ between captures, so they are assigned, not fixed.

## What this means for Barq

Advertising `_airdrop._tcp.local` alone cannot work. To be listed we must
advertise both pairing services with `sn=com.apple.sharingd.AirDrop`, plus the
`_services._dns-sd._udp.local` pointers, and answer for a UUID-shaped host.

Still unknown, and not answered by this capture:

- what `at` and `_dc` mean, and whether a peer validates them
- what protocol runs on the pre-pair and pairing ports
- whether BLE is required before any of this is honoured. The Mac transmits
  nothing on AWDL when idle, so something wakes it, and BLE is the documented
  trigger

## How this was captured

macOS **gates AWDL multicast reception** — a plain socket joined to `ff02::fb`
on `awdl0` receives nothing, while the same code on `en0` works. Only
mDNSResponder with the P2P flag sees AWDL traffic. Sending is not gated.

So the phone is the only usable vantage point: `tools/mdnsdump.c` runs there and
sees everything. Two earlier conclusions drawn from a Mac-side listener were
wrong because of this, and the listener had not been self-tested.

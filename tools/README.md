# tools

## `announce.py`

Send an mDNS announcement for `_airdrop._tcp.local` out of a chosen interface.

```bash
./announce.py awdl0 beefcafe1234
```

**Why this exists.** Testing discovery against a real Apple device means having
AirDrop actually open on it — macOS only advertises while the AirDrop window or
share sheet is up, so "no peers found" is ambiguous between *our bug* and
*nothing was advertising*. This removes that ambiguity: it emits the same
PTR + SRV + AAAA shape a real peer does, on demand, from any machine with an
AWDL interface.

Used to verify barqsharingd's browser end to end:

```
Mac awdl0  --[ff02::fb]-->  phone mosey0
barqsharingd::mdns: peer discovered: beefcafe1234
```

It is a **test** tool, not a Barq component: it does not implement AirDrop and
the service it announces answers nothing.

# Open work

Ordered by what unblocks the most. Kept here rather than in a chat log so it survives.

## Blocking: what makes a peer start browsing `_airdrop._tcp`

Our mDNS advertisement is verified byte-for-byte identical in shape to Google's Mosey,
and in every capture so far the only device asking for `_airdrop._tcp` has been us. BLE
advertising is now live and correct, and it did not by itself change that.

Two device-side tests, neither yet run, that separate "our beacon is wrong" from "the
test setup was never valid":

- [ ] **Confirm the Mac is set to "Everyone", not "Contacts Only".** Barq's beacon
      carries zeroed identifier hashes — an honest "no identity". A Contacts-Only
      receiver is *supposed* to ignore that, so on that setting the result is expected
      and proves nothing.
- [ ] **Capture with the Mac actually SENDING** — share sheet open on a file, not the
      AirDrop receive window. Every capture so far has had the Mac in receive mode,
      where it waits to be found rather than looking. The sender is the side that
      browses `_airdrop._tcp`.

Then, if both are clean and it still does not appear:

- [ ] **Trace `mosey_update`.** Barq calls only `mosey_start_5` and `mosey_stop`.
      Google's daemon also calls `mosey_update(handle, ptr, 1, 0)`, and the pointer's
      contents were never identified. It is the leading candidate for populating the
      AWDL service-response TLVs that Mosey's state dump reports.
      `gos-ffi-trace.sh` already knows how to read its real arguments.

## Protocol, once discovery works

- [ ] HTTPS layer: `POST /Discover`, `/Ask`, `/Upload`, Apple binary plist bodies
- [ ] TLS: certificate handling for "everyone" versus contacts-only — the real unknown
- [ ] cpio reader/writer for the payload archive
- [ ] Act on a received BLE beacon rather than holding AWDL continuously, which costs
      more power than Apple spends

## App

- [ ] Share-sheet target, transfer UI, Quick Settings tile
- [ ] Retire Bada: `gos-app.sh` and `gos-bada.sh` are marked stopgaps

## Rig

- [ ] Monitor-mode 5 GHz adapter + BLE, OWL as a controllable peer.
      See [REVERSE-ENGINEERING.md](REVERSE-ENGINEERING.md).

# PIN verification is intentionally disabled

**Decision (2026-09-22): the typed-PIN confirmation is turned off, on purpose, until a real
purpose for it is established.** The code is commented out rather than deleted so it can be
revived without reconstructing it.

## Why

The PIN was a Quick Share **send-side** feature: the receiver showed a code, the person read
it to the sender, and the sender typed it before any bytes left. In practice it did not earn
its place:

- **AirDrop never had it and is fine.** AirDrop confirms with a plain accept prompt on the
  receiving device and nothing else. If that is acceptable for AirDrop, the same plain accept
  is acceptable for Quick Share — requiring more from one protocol than the other was
  inconsistent for no security we could point at.
- **It cannot work against a stock Quick Share peer at all.** A stock Android sender has no
  field to type our PIN into (Quick Share uses an automatic visual code-match, not a typed
  entry). Observed on hardware: the receiver showed a PIN, the stock sender had nowhere to
  enter it, and it added friction with no interop. See the memory note
  `pin-breaks-stock-quickshare`.
- **We only receive on the Receive screen**, behind an explicit accept — so the consent step
  the PIN was meant to strengthen is already present.

So the PIN made the two protocols inconsistent and blocked stock interop while protecting
nothing the accept prompt did not already cover. It is disabled until a concrete threat model
shows what it would add.

## What was disabled (commented, not deleted)

Daemon (`tarish-daemon`):

- `sharingd/src/main.rs` — `TransferProgress::confirm_pin` returns `true` without asking
  (the set/notify/await block is commented). `confirmTransferPin` (AIDL, must stay) is a
  no-op returning `Ok(true)`. The `TransferState` PIN plumbing (`set_pin` / `await_pin` /
  `confirm_pin` / `clear_pin` and the `pin` / `pin_ok` fields) is now unused; it is kept for
  revival.
- `sharingd/src/quickshare/connection.rs` — the session PIN is no longer derived
  (`tarish_protocol::pin::derive`) and `onTransferPinDisplay` is no longer called.
- `require_pin` / `TarishPolicy.requirePin` remain in the interface but no longer gate
  anything.

App (`tarish-app`):

- `SettingsActivity.java` — the "Require PIN to send" toggle and its caption are hidden.
- `MainActivity.java` — `onTransferPinRequired` and `onTransferPinDisplay` are no-ops; the
  accept path no longer shows a receiver code. `askForPin` / `showReceiverPin` and the PIN
  dialog fields remain, unused.

## To revive

Uncomment the blocks marked `PIN VERIFICATION INTENTIONALLY DISABLED` in the files above and
restore the `requirePin` toggle. The derivation on both ends must stay identical
(`tarish_protocol::pin::derive` over the same `auth_string`) or a correct-looking PIN
verifies nothing — the trap that cost a build cycle before.

# Vendored crates

Third-party Rust crates copied here **unmodified** from crates.io.

## Why inside Barq rather than external/rust/

Barq is meant to build outside the GrapheneOS tree — on LineageOS, or plain AOSP, as
though someone else wrote it. A dependency placed in `external/rust/` would make that
untrue: every consumer would have to know to put our dependencies there first.

`gos-barq.sh` copies this whole checkout into `vendor/barq/`, so anything here comes
along on its own with no change on the consumer side.

The one deliberate exception to vendoring is **`libmosey_daemon_ffi.so`**, which is
pinned in the *grapheneos* repo instead. It is hardware-specific — Google's AWDL
userspace for Pixel — and carrying it here would tie a portable daemon to one vendor's
phone.

## Module naming

Soong module names carry a `_barq` suffix so they cannot collide if AOSP later carries
the same crate. `crate_name` stays the real name, so import paths are unchanged and the
sources need no edits.

## What is here

| crate | version | licence | why |
|---|---|---|---|
| `cpio-archive` | 0.10.0 | MPL-2.0 | AirDrop payloads are cpio **odc** (magic `070707`) |
| `is_executable` | 1.0.6 | MIT/Apache-2.0 | cpio-archive dependency (writer path) |
| `simple-file-manifest` | 0.11.0 | MIT/Apache-2.0 | cpio-archive dependency (writer path) |

`chrono` and `thiserror` are cpio-archive's other dependencies and already exist in the
AOSP tree, so they are not vendored.

### On cpio-archive specifically

Apple sends **odc**, not `newc` — confirmed from a working implementation that had to
reverse-engineer it. Most cpio crates implement `newc` only. This one implements both,
its `OdcReader<T: Read>` is **streaming** rather than buffering the archive in memory,
and it comes from `indygreg/apple-platform-rs`, written for Apple platform tooling.

The writer is kept rather than stripped, even though only the reader is needed today.
Removing it would drop two dependencies but would make our copy diverge from upstream,
turning future updates into re-copy-plus-re-patch — and the send direction will want a
writer anyway.

## Updating

Re-download from crates.io and replace the directory, keeping `Android.bp`. Do not edit
the sources: local changes here are invisible at review time and are lost on the next
update.

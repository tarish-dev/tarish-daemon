# Security review, September 2026 — findings and where each one stands

An external four-pass review of Tarish. Recorded here verbatim in substance, with the
status of each item kept current. **The status column is the authoritative part**; the
review itself is a snapshot and several items moved within hours of it being written.

Numbering follows the review so the two can be read side by side.

---

## Fixed and verified by the reviewer

| # | Finding | Note |
|---|---|---|
| 1 | Plist reference-amplification bomb | object budget added; a 726-byte bomb refused in 10 ms at 5.5 MB instead of 3.9 GB. **Partial — see 11** |
| 2 | Upload DoS half | compressed, decompressed and member-count caps; failed archives deleted |
| 3 | Any platform-signed app could drive the daemon | closed by the `tarish_app` domain, keyed on package **and** signature |
| 4 | Concurrent payload cap | 32 in flight, held across 8M fuzz iterations |
| 5 | Silent AWDL death on panic | `catch_unwind` in the session thread |
| 6 | Unbounded `adopters` map | capped at 256 MACs |
| 7 | Filenames with bidi/control characters | refused, not sanitized; Quick Share shares the check. **Storage side only — see 15** |
| 8 | Regulatory default no longer assumes Qatar | falls back to "00". **Enforcement unverified — see 12** |
| 9 | `forbid(unsafe_code)` on tlink and tlink-session | |
| 10 | Three stale beacon tests | 20M mutated frames, zero panics; 203 protocol tests passed at the time |

## Fixed after the review was written

| # | Finding | Fix |
|---|---|---|
| **18** | `net_domain` on sharingd — blanket grant on the process that parses hostile input | **DONE 2026-09-24.** Replaced with a measured set. Lost `rawip_socket`, `icmp_socket` and `netlink_route_socket` — entire classes. Method and evidence in `sepolicy/tarishsharingd.te` |
| **19** | tarishd's inherited mosey_server policy | **DONE 2026-09-24.** Lost `listen`/`accept` on `packet_socket` and `netlink_generic_socket` (operations that do not exist for those classes), `watch`/`watch_reads` on `/dev/tun`, `nlmsg_readpriv`, `nlmsg_getneigh`, and `netlink_netfilter_socket` entirely |
| **17** | ECDH secret normalization | **DONE 2026-09-24.** `shared_secret` now hashes the padded 32 bytes. Google hashes the padded form on both its C++ (`EVP_PKEY_derive`) and Java (`KeyAgreement.generateSecret`) paths. See below |
| **16** | LAN upgrade connects to any address a peer supplies | **DONE 2026-09-24.** Scope check: RFC1918 and unique-local only; loopback, unspecified, multicast, broadcast, link-local, documentation and global all refused, with v4-mapped v6 re-checked |
| **11** | The plist budget counts objects, not bytes | **DONE 2026-09-24.** Leaf bytes now charged, with the allowance proportional to the input (8x `buf.len()`, floor 256 KiB) rather than flat, so a small hostile body gets a small allowance |
| **15** | Consent shows unsanitized names | **DONE 2026-09-24.** The char rule is factored out of `safe_leaf` as `display_safe()` and applied at the offer boundary, to the file names **and** the sender name. An offer carrying an unsafe name is refused before anyone is asked |

### On 18 and 19 — how the trim was derived

Not by reasoning. `auditallow` was added to every questionable grant, one build was shipped,
and `scripts/gos-selinux.sh --granted` read back what was actually exercised across AirDrop
send, AirDrop receive, Quick Share off-network receive over Bluetooth, a Quick Share receive
that upgraded to Wi-Fi Direct, and four AWDL bring-up/teardown cycles. Everything that never
appeared was removed.

Three things that make the method usable, all learned the hard way:

- The kernel caps audit at **50 messages/second** with a 64-deep backlog. One AWDL bring-up
  produced 300 `create udp_socket` and 180 `setopt packet_socket` grants and dropped 31
  records. A dropped record makes a USED permission look unused, so `--clear` now lifts the
  rate limit and `--granted` refuses a run that lost any.
- An unprivileged shell **cannot read dmesg at all** (`klogctl: Permission denied`), and adb
  hides it. The first run reported "no loss" while structurally unable to see the counter.
- Enumerating what a macro grants by grepping for `allow ... netdomain` **misses macro
  invocations**. `unix_socket_connect(netdomain, fwmarkd, netd)` contains no `allow`, so the
  fwmark grant was dropped and only reappeared as a denial on hardware. Enumerate a macro by
  what it expands to.

`dnsproxyd` was deliberately **not** restored: this daemon reaches peers by address, never by
name, and a process that parses hostile input and cannot make a DNS query is a better shape.

### On 17 — why the reviewer was right and the code's own comment was wrong

The module header asserted that UKEY2 hashes a magnitude with leading zeros stripped. It does
not. The mistake looks inherited from `securemessage.proto`'s comment that x and y travel as
big-endian two's complement — which is true, and still honoured in the public-key codec, but
governs the **public key fields**, not the ECDH output.

It survived every test because when the X coordinate has no leading zero byte — 255 times in
256 — `magnitude(x)` and `x` are the same bytes. Only the 1-in-256 case diverged, and a rare
handshake failure reads as a flaky peer. Bada strips too and this code was ported from it, so
"Bada interoperates" was never independent evidence.

**Still unconfirmed against a real peer.** That needs a captured handshake whose shared X
begins with `0x00`, a 1-in-256 capture. Until such a vector is in `QUICKSHARE-VECTORS.md`
this rests on Google's source rather than an observed exchange.

---

## Open — high

| # | Finding | Next step |
|---|---|---|
| 12 | **The regulatory fix rests on an unverified assumption.** `Wonder::capabilities()` returns a hardcoded `[44, 149]` regardless of domain, and `bring_up` never consults it, so nothing in tlink refuses a forbidden channel on the shipping path | one on-device experiment: set a domain where 149 is no-IR and see whether bring-up fails |
| 13 | **Offer-versus-delivery integrity (AirDrop).** Extraction does not check delivered names, count or sizes against the accepted offer | deferred deliberately. The Quick Share path already refuses unannounced payloads and is the model to copy |

## Open — medium

| # | Finding | Note |
|---|---|---|
| 14 | **Disabling the PIN removed the only MITM check on UKEY2.** The handshake is otherwise unauthenticated Diffie-Hellman | the problem was typed entry, not the mechanism. Display-and-compare should interoperate, since the derivation matches Apple's and Bada's vectors. **Needs an operator decision** |

## Open — low and housekeeping

| # | Finding |
|---|---|
| 20 | Upload caps of 8 GiB exceed most phones' free space — cap against `statvfs` free space minus a reserve |
| 21 | Orphaned files on a tripped extraction guard — earlier members stay in the inbox with no announce |
| 22 | The VPN routing exemption's safety is entirely the contents of tlink0's table — assert that at insert time rather than maintaining it by care. **Blocked on a design decision:** asserting it means parsing an `RTM_GETROUTE` dump, which needs `nlmsg_read` — a permission removed from tarishd on 2026-09-24 because nothing used it. So the choice is a netlink dump parser in the privileged daemon plus a re-grant, versus the status quo. `gos-lockdown.sh` already asserts the same invariant continuously; what is missing is runtime enforcement, not detection |
| 23 | Two clock-tracking tests in `follow.rs` still red — deferred knowingly |
| 24 | Check the published pcaps for third-party device names before launch |
| 25 | Wi-Fi Direct join is protocol-inherent; confirm teardown on every error path |

---

## Reviewed and found clean

The AWDL parsers (20M mutated frames), the UKEY2 server handshake, key validation,
MAC-then-decrypt with constant-time comparison, sequence enforcement, Quick Share framing
bounds, path traversal handling, and the SELinux reasoning throughout.

## Not reviewed

The Java app beyond the filename path, the Quick Share connection and upload state machines
in depth, the vendored cpio crate, `HANDOFF-concurrent-accept.md`, and tarishd's own route
and property handling.

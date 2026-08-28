# Open work

Ordered by what unblocks the most. Kept here rather than in a chat log so it survives.

**This file leads with what is still open.** It used to lead with "nothing listens on
the port we advertise", which was true when written and had been fixed for a long time
by the time anyone read it again — so the first thing a reader met was a blocker that
did not exist, and the live work was two hundred lines down.

## Open

### AWDL and Wi-Fi cannot run together on BCM4383, and the fallback hides it

**Second priority, after VPN lockdown.**

The coexistence work landed and is verified on BCM**4390** (mustang): AWDL goes in the
opposite band from the Wi-Fi association and both run indefinitely. On BCM**4383**
(frankel) the same code picks the right band and Wi-Fi dies anyway, does not recover
when AWDL stops, survives a Wi-Fi toggle, and needs a reboot. Full measurements in the
integrator's BUILD-NOTES 40.

The difference is `wondertap`. 4390 exposes it, so `wonder.ko` binds and the Netlink
path drives a real `wonder` wiphy. 4383 does not, so barqd falls back to driving
`radiotap0` — a monitor interface, which takes the physical radio with it whatever
channel is requested.

**Is `is_dbs_supported` a lie on 4383?** We hardcode it true for every device:

```rust
const CFG_DBS_SUPPORTED: [u8; 2] = [0x08, 0x01];
```

If that chip cannot do dual-band simultaneous, the library believes it can hold both,
does not time-slice, and stands on the STA — exactly what is observed. One byte tests
it (`08 01` -> `08 00`). **Run this first**; if it is the answer, the flag should be
derived from the chip rather than assumed, the same way the STA frequency now is.

**The fallback should not fail this way.** It exists so a device without a `wonder`
wiphy still works, and it does — discovery and transfers are fine on frankel. But
costing the user their network until they reboot is not graceful degradation. Options,
in order of preference:

  1. If the DBS theory holds, fix the config and keep the fallback.
  2. Otherwise refuse the radiotap path **while Wi-Fi is associated**, and say so in
     the app — the same treatment as "AirDrop radio is not running".
  3. Only as a last resort, refuse radiotap entirely, which costs 4383 devices AWDL
     altogether.

**Testing this needs the override properties to work on a user build.** They are
gated behind properties a shell cannot set there, which is why the one-byte test has
not been run. Gate the overrides on `ro.debuggable` and it becomes seconds instead of
a signed build per hypothesis — that plumbing already paid for itself once, finding
the channel answer in two minutes rather than three build cycles.

**UPDATE — measured on a userdebug frankel, and it narrows the problem sharply.**

frankel does not have the Netlink AWDL path at all, and now we know why at module
level rather than by inference:

```
wonder.physical_name = wondertap0     (module parameter, read-only)
interfaces present:    wlan0, wlan1, aware_nmi0     <- no wondertap0
/sys/class/ieee80211:  phy0 only                    <- no AWDL wiphy
driver:                bcmdhd4383
```

`wonder.ko` loads, asks for an interface `bcmdhd4383` never creates, and registers
nothing. So AWDL there is radiotap-only, which takes the whole radio — matching OWL's
own documented limitation exactly.

**The config surface is exhausted.** `channel_hopping=true` IS honoured by the library
— captured decode, no longer an assumption — and the association still dies same-band
with `sta_channel_freq` correctly set. There is nothing left in StartMoseyConfig to
try. So the one-byte `is_dbs_supported` test below is worth less than it looked: this
is not a scheduler that needs better inputs, it is a radio path with no scheduler.

**Google ships the same bug.** Quick Share's AirDrop support on Pixel 10, 10 Pro and
10 Pro XL was widely reported (Nov 2025) to drop Wi-Fi the moment the share sheet
opens, with the network list going empty and connectivity returning when it closes.
Google closed the issue tracker report without a fix. That is our symptom, with their
implementation, on the same hardware — so this is a property of the platform rather
than of our stack, and "match stock behaviour" is not an available answer.

What is still worth doing here is making the radiotap fallback REFUSE rather than
wedge Wi-Fi, so the failure is a share that does not happen instead of a phone that
loses its network. The band refusal already does this for same-band on 4390; the
radiotap path needs the equivalent.


### Always-on VPN lockdown breaks peer-to-peer, and should not just fail silently

**Priority: first.** Operator requirement.

Android's *Block connections without VPN* (always-on VPN lockdown) is a good setting
and enterprises rightly turn it on. It also breaks every peer-to-peer transfer that
works by IP — AirDrop, Quick Share and Barq alike — because the traffic is on a
link-local address that is not the VPN, so it is dropped. Nothing tells the person
why. The device simply stops being able to send or receive, and the app looks broken.

**Behaviour we want**

1. **Detect** that lockdown is on. Barq is platform-signed and privileged, so the
   hidden setting is readable; that is a starting point, not a design.
2. **Under lockdown, every transfer is individually authorised by the person** —
   biometric or device PIN, per send and per receive. Not a setting, not a
   remembered choice, not a session: the enterprise turned this on deliberately, and
   the only defensible way to make a hole in it is a human opening it once, knowingly,
   for one transfer.
3. **Open the path for that transfer only, then close it again.** Fail closed: if
   barqd or barqsharingd dies mid-transfer, or the app is killed, the exemption must
   not outlive it. An exemption that survives a crash is precisely the hole the
   setting exists to prevent.
4. **No device credential, no transfer.** If there is no PIN and no enrolled
   biometric there is nothing to authorise with, so under lockdown Barq refuses to
   send or receive at all. Refusing is the correct answer here, not a fallback.
5. **Say so in the app.** Barq behaves differently under lockdown and the UI should
   state that plainly — the same reasoning as the "AirDrop radio is not running"
   card: an app that silently does less is indistinguishable from one that is broken.

**Measured: Google's own implementation fails the same way**

Tested by the operator on the previous build, with privileged GMS and Play Store
installed: with *Block connections without VPN* on, **AirDrop through Google's own
stack does not work either**. Same setting, same outcome.

Three things follow, and they matter more than the original framing:

1. **This is not a Barq deficiency.** The whole peer-to-peer class is blocked, and a
   privileged, system-integrated, Google-signed implementation is blocked with it.
   Anyone hitting this on stock Android hits it too.
2. **There is no app-level workaround to copy.** Google, with a privileged app and
   every platform integration available to them, did not solve it — so we should not
   expect to find a supported API that quietly exempts us. If one existed, theirs
   would use it.
3. **The fix is therefore a platform change, and we can make one.** Barq ships inside
   an OS we build. Google's app could not modify netd, the bpf rules or
   ConnectivityService; we can. That is a real advantage and it cuts both ways: we
   would be putting a hole in a security control *in our own OS*, for our own app,
   which is exactly why the per-transfer human authorisation above is a requirement
   and not a nicety. A platform exemption with no human in the loop is a backdoor
   with our name on it.

**Still to measure**

- The test above used Google's stack, which runs as a privileged *app* uid.
  `barqsharingd` is a native daemon with its own uid, and lockdown is applied over uid
  ranges. It is possible the daemon is already outside them and only the app-side
  traffic was blocked — that would change what needs building. **Answer this first.**
- Which layer actually drops the packet: the bpf owner match, an iptables rule, or
  routing. The narrowest place to make a scoped, temporary exception is whichever one
  it is, and guessing wrong means weakening more than necessary.
- Which mechanism actually opens the path, and can it be scoped to one socket rather
  than one uid? A per-uid exemption for the transfer window is much wider than it
  sounds — everything that daemon does is exempt for that period.
- Does the person get one prompt per transfer, or one per file? Per transfer.
- What does the *sender* see when the receiver is under lockdown and declines to
  authorise? It has to be distinguishable from an ordinary decline, or the sender
  retries into a wall.

**What must not be done**: a persistent exemption, a "remember this device" option,
or anything that survives a reboot. If the answer is not "a human authorised this
specific transfer, just now", the transfer does not happen.

- **Channel 149 is hardcoded, and it is not legal everywhere.** `CHANNELS = &[149]`
  (5745 MHz, U-NII-3). Permitted in Qatar, the US and much of Asia; largely **not**
  permitted for Wi-Fi in the EU. The country is now read correctly and follows the
  device, but in a region where 149 is barred the vendor library will refuse to bring
  the radio up and Barq will fail closed with a correct country in the log -- which
  will read as a different bug than it is.

  Apple picks per region (2.4 GHz ch 6, or 5 GHz 44/149), so the fix is a channel
  table keyed on the regulatory domain rather than a constant. Until then the honest
  statement is: Barq works where channel 149 is permitted.

- **Drop `android_logger` from the privileged half — before any production build.**

  `barqd`'s own header states the rule: *"every dependency is part of its threat
  model, and one property read does not justify one."* It then links a full regex
  engine for log filtering. Confirmed in its runtime maps:

  ```
  libregex  libregex_automata  libregex_syntax  libaho_corasick  libmemchr  libenv_filter
  ```

  AOSP builds `libandroid_logger` with the `regex` feature and `libenv_filter`
  baked in, and ships no regex-free variant, so this arrives whether or not it is
  wanted. `barqd` never uses filter strings — it sets a tag and a max level — so
  the whole engine is dead weight in the one process holding `CAP_NET_ADMIN` and
  `CAP_NET_RAW`.

  Fix is ~20 lines calling `__android_log_write` through libc, leaving `barqd`
  linking only libc and the `log` facade. **Deliberately deferred:** convenient
  logging is worth more than the dependency while the daemon is still being
  developed, and swapping the logger mid-development trades a real debugging aid
  for a theoretical gain. Do it when hardening for a release build, and re-check
  the maps afterwards rather than assuming.

- **Two `unsafe` sites without a `SAFETY:` tag** — `unsafe impl Send for Session`
  (which has an untagged justification above it) and a `mem::zeroed()` on a
  `sockaddr_nl`. Both benign; tagged now, noted here because the audit that finds
  them should find zero next time.

- **Offer sizes.** `onTransferOffered` reports `totalBytes = 0`. Apple's `/Ask` carries
  file names and UTIs but no sizes, so the prompt cannot say how big the transfer is
  without inventing a number. Worth checking whether `Items` carries one on some senders.
- **One transfer at a time.** `serve()` handles connections inline, so an offer waiting on
  a person blocks the accept loop for up to 45 s. Correct for AirDrop, which does one
  transfer at a time, but it means a second peer probing during a prompt is ignored rather
  than refused.
- **Single-client `setActive`.** The foreground flag is one boolean, not per-client, so
  two clients would fight over it. There is one client today and the AIDL is ours.

## Still to understand

Research questions, not blocked work. Neither has been answered.

### Understand before implementing: how a peer lists a dual-protocol device ONCE

**Observed**, on two Android phones that both support AirDrop and Quick Share: the
receiver lists the sender **once**, not twice. Something correlates the two
advertisements, and we do not know what.

This has to be understood **before** the Quick Share migration starts, because Barq
will be exactly such a device -- speaking AirDrop to Apple peers and Quick Share to
Android ones -- and getting it wrong means every Android peer sees us twice.

What is established: the two identities share **nothing** at protocol level.

| | AirDrop | Quick Share |
|---|---|---|
| mDNS | `_airdrop._tcp.local` | `_FC9F5ED42C8A._tcp.local` |
| instance | 12 hex, rotating | 4-char endpoint id |
| BLE | Apple mfg data `0x004C` | Google service UUID `0xFE2C` |
| name in discovery | **none** -- TXT is only `flags=` | in endpoint info |

AirDrop's TXT carries no device name at all; the name arrives later as
`ReceiverComputerName` in the `/Discover` response. So a browser cannot even compare
names until after a TLS connection. Correlation therefore cannot be happening at the
mDNS layer.

**Leading hypothesis: both advertisements come from the same BLE adapter**, so a
scanner groups them by source address before either protocol is involved. That would
explain dedup with no shared identifier anywhere above the link layer.

**The experiment**, using what already exists: `BarqBleService` logs the source address
of every AirDrop beacon it sees. Add a second scan filter for `0xFE2C` and log the same
way, then watch the two phones that actually exhibit the behaviour. If both payloads
appear from one address at any given moment, the hypothesis holds.

**The caveat that could kill it:** Android uses resolvable private addresses that
rotate. If the two payloads rotate *together* the grouping still works; if they rotate
independently, address correlation cannot be the mechanism and something else is.

Deliberately **not** implemented yet. Fixing before understanding would bake in a guess,
and the last several wire-format guesses in this project were wrong while every
measurement was right.

### Understand before implementing: does AirDrop signal device state?

Reported from using iOS: AirDrop appears to carry a state indicating the screen has been
turned off. Not yet located in any wire format we hold, and **not** recorded in
GoOpenDrop -- its `ReceivedBLEBeacon.DataReceived` captures the beacon payload and
nothing ever decodes it.

Two places it could live, and we do not know which:

- **The undecoded `flags` bits.** `flags` is a capability bitmap, not a constant:
  GoOpenDrop sends `136` = `0x88` (`SUPPORTS_MIXED_TYPES | SUPPORTS_DISCOVER_MAYBE`),
  and we measured Mosey sending `489` = `0x1E9`, which is those two bits plus bits
  0, 5, 6 and 8. Four undecoded bits, and device state is a plausible occupant.
- **The eight zero bytes in the BLE beacon.** Our AirDrop advertisement carries

  ```
  05 12 | 00 00 00 00 00 00 00 00 | 01 | aa aa pp pp ee ee ee ee | 00
        ^^^^^^^^^^^^^^^^^^^^^^^^^ never explained
  ```

  copied verbatim from a measured capture, which was the right call. But eight bytes of
  always-zero is unusual in an otherwise dense format, and status flags that happen to
  be zero in the captured state would look exactly like this.

Apple also broadcasts a separate **NearbyInfo** message (type `0x10`) alongside
AirDrop's `0x05`, which is a third candidate.

**The experiment**, cheap and using what exists: `BarqBleService` already scans Apple
beacons and logs the sender address. Log the full manufacturer payload instead, then
lock and unlock an iPhone while it advertises and diff the bytes. The same method
decoded the framed cpio container in one capture.

**Why it matters beyond curiosity:** if Apple already models "device present but screen
off", then Barq's app-open visibility rule maps onto something the protocol expects
rather than being our own invention, and a peer could show us accurately instead of
listing a device that will refuse.

### App

- [ ] Share-sheet target, transfer UI, Quick Settings tile
- [ ] Retire Bada: `gos-app.sh` and `gos-bada.sh` are marked stopgaps

### Rig

- [ ] Monitor-mode 5 GHz adapter + BLE, OWL as a controllable peer.
      See [REVERSE-ENGINEERING.md](REVERSE-ENGINEERING.md).

## Done

### barqsharingd could not send on wlan0 — SOLVED, and not by the uid alone

The daemon advertised AirDrop happily and every Quick Share mDNS query died with
EPERM at `sendto`, while `socket`, `bind` and `IP_MULTICAST_IF` all succeeded.

The old entry here concluded "the uid is the variable, PROVEN", on the evidence that
identical code sent as uid 1000 and failed as 9999. That was a true measurement and
an incomplete diagnosis, and acting on it alone would not have fixed anything: a
dedicated AID at 7500 failed *identically*.

The actual gate is `is_local_network_access_blocked()` in Connectivity's
`bpf/progs/netd.c`. Since Android B it exempts only uid 0 and uid 1000; every other
uid needs `PERMISSION_BIT_ACCESS_LOCAL_NETWORK` in `sUidPermissionChunkMap`, which
`PermissionMonitor` derives from PACKAGES. A native daemon has no package, so it can
never earn the bit however it is numbered. The older kernel rule exempted everything
below uid 10000, which would have covered 9999 and 7500 both — so this is a rule that
recently got narrower, not one we had misread.

Two parts, both shipped:

- the daemon runs as its own AID, `system_ext_barq` (7500), declared through
  `TARGET_FS_CONFIG_GEN`. This buys isolation and legibility, not network access.
- the integrator grants the bit:
  `grapheneos/patches/packages_modules_Connectivity/0001-grant-barq-daemon-local-network-access.patch`

Why this never affected AirDrop, which had been doing mDNS for weeks: the access map
is keyed by INTERFACE, and `mosey0` is not a managed network. The gate is wlan0-only.

Full mechanism and the three rejected alternatives: grapheneos BUILD-NOTES 41.


- **Per-transfer consent.** `/Ask` blocked on `respondToOffer` rather than answering 200
  unconditionally. No answer within 45 s is a refusal, and `/Upload` is refused outright
  without an accepted offer so a peer cannot skip the prompt by opening a new connection.
- **On-demand AWDL.** The radio is held only while a client is on screen, a transfer is
  running, or the device is advertising. See ARCHITECTURE.md.

### The original blocking list — all of it shipped

Kept because the reasoning is the record of how the protocol was worked out, and
because the mis-framing in it is worth remembering: mDNS and BLE were repeatedly
blamed for "discovery not working" when the actual cause was that nothing was bound to
the advertised port, so no peer could ever finish resolving us.

### Blocking: nothing listens on the port we advertise

Our SRV says `Android_XXXXXXXX.local:8770` and **nothing is bound to 8770**. Checked on
the device: no listening socket in either daemon.

This is not a detail below discovery, it is a prerequisite *for* discovery finishing.
A sender does not list a peer because it answered mDNS. It resolves the SRV, opens
**TLS** to that port and sends `POST /Discover`; the device appears in the AirDrop
window only if that returns a valid response. So even a peer that browses, resolves and
reaches us gets connection-refused and shows nothing.

Which means the mDNS and BLE work, both of which are correct, could not have produced a
visible device on their own. That was mis-framed for several cycles as "discovery is the
blocker".

- [ ] Bind a TLS listener on the advertised port
- [ ] `POST /Discover` returning a valid Apple binary plist
- [x] Certificate story — **settled, and it is not an unknown.** A self-signed
      certificate is sufficient; the peer does not validate ours. Contacts mode is
      deliberately out of scope: it needs an Apple validation record extracted from a
      real device that expires yearly, for identity that means little between two
      platforms with no trust relationship anyway.
- [ ] Minimal binary plist writer — no plist crate exists in the AOSP tree, and the
      `/Discover` and `/Ask` bodies are flat dicts of strings and data blobs
- [ ] TLS via `libopenssl` (BoringSSL-backed, already in the tree). No HTTP crate
      exists either, but the surface is four routes and hand-writing it matches how
      barqsharingd already hand-parses DNS.

Only once something answers on that port does the question below become testable at all.

### Then: what makes a peer start browsing `_airdrop._tcp`

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

### Protocol, once discovery works

- [ ] HTTPS layer: `POST /Discover`, `/Ask`, `/Upload`, Apple binary plist bodies
- [ ] TLS: certificate handling for "everyone" versus contacts-only — the real unknown
- [ ] cpio reader/writer for the payload archive
- [ ] Act on a received BLE beacon rather than holding AWDL continuously, which costs
      more power than Apple spends

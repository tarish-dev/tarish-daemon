# Policy: MDM control, and behaviour under VPN lockdown

Two related pieces of control, agreed 2026-09-01, neither implemented yet.

- **What an administrator may turn on and off**, per protocol and per direction.
- **What happens when "Block connections without VPN" is enabled**, which is the harder
  half and the one with a security argument attached.

They connect at one point: the administrator decides whether Barq may operate under
lockdown at all.

---

## 1. MDM control

### Use the platform mechanism, not a vendor one

Android **managed configurations** (app restrictions) are part of AOSP, so every MDM —
Intune, Workspace ONE, SOTI, MobileIron, Jamf — can set them, because they are all
calling the same platform API. One implementation covers all of them.

```
res/xml/app_restrictions.xml          the typed schema
AndroidManifest: <meta-data android:name="android.content.APP_RESTRICTIONS" .../>
RestrictionsManager.getApplicationRestrictions()   read
ACTION_APPLICATION_RESTRICTIONS_CHANGED            react without a restart
```

They are set by a device owner or profile owner. On a device with nothing enrolled
there is no DPC, nothing sets them, and the defaults apply — which is the correct
outcome, not a gap.

### The keys

Per protocol and per direction, expressed as *choice* rather than pairs of booleans:
choice fields render as a single dropdown in an admin console, whereas two booleans
per protocol invite the nonsensical combination and double the surface.

| key | type | default |
|---|---|---|
| `airdrop` | off \| receive_only \| send_only \| both | both |
| `quickshare` | off \| receive_only \| send_only \| both | both |
| `require_confirmation` | bool | **true** |
| `vpn_lockdown_sessions` | bool | **false** |
| `lockdown_idle_seconds` | int | 300 |
| `lockdown_stall_seconds` | int | 30 |
| `lockdown_max_seconds` | int | 1800 |

`require_confirmation` defaults true and an administrator turning it *off* is turning
off the per-transfer accept prompt. That is theirs to decide, but the default is the
safe one.

### Enforcement belongs in the daemon, not the UI

A hidden button is not a policy control. `barqsharingd` is what advertises, browses,
accepts connections and writes files, so policy has to reach it and it has to be the
thing that refuses. An app that merely hides the affordance is bypassed by killing the
app or connecting to the daemon directly.

The daemon cannot read managed configuration itself — it is native, uid 7500, with no
framework access, for the same reason it cannot do BLE. So:

```
MDM -> DPC -> app (RestrictionsManager) -> AIDL -> barqsharingd enforces
```

and the daemon **defaults to denied**, opening only on being told. A daemon that has
never heard from the app shares nothing.

Note this is the opposite of the radio gate, where an unset `barq.awdl.wanted` means
radio-ON. That default is right there — a missing property should not silently disable
sharing — and wrong here, where a missing policy must not silently permit it. Do not
copy the pattern across.

---

## 2. VPN lockdown

### What lockdown actually does

Not destination-based. It is a per-uid rule enforced in eBPF on the cgroup egress hook
(`packages/modules/Connectivity/bpf/progs/netd.c`), and on ingress the rule is
literally "drop unless it arrived on `lo`". Older releases did the same with iptables
owner-uid matches. Traffic either left through the tunnel or it did not.

Two details from reading that program matter more than the general shape:

**Multicast is dropped before the system-uid escape.**

```c
if ((uidRules & LOCKDOWN_VPN_MATCH) && is_multicast(skb, kver)) {
    return DROP;
}

if (is_system_uid(uid)) return PASS;
```

mDNS is multicast, for AirDrop and Quick Share alike. So under lockdown *discovery*
dies first, and independently of everything below.

**The exempt sets of the two gates in this file are different**, which is a trap:

| gate | exempt set | uid 7500 |
|---|---|---|
| local network access | `is_system_or_root` — uid 0 and 1000 only | **caught** |
| VPN lockdown | `is_system_uid` — uid < 10000 | **exempt** |

So the same uid choice that cost us a Connectivity patch for local-network access may
hand us lockdown exemption for nothing. Assuming symmetry between two gates in one file
would be wrong in both directions.

### THE MEASUREMENT THAT DECIDES THE DESIGN

**Does uid 7500 ever carry `LOCKDOWN_VPN_MATCH`?** That is computed Java-side in
`Vpn.java`, which works out the uid ranges a VPN applies to. If native system uids are
never included, the multicast rule never fires for us and lockdown does not reach Barq.

Enable always-on VPN with lockdown, then read `dumpsys connectivity trafficcontroller`
and look for 7500. Everything below depends on the answer.

### If we are exempt, that is a hole to close, not a gift

A person enabling "Block connections without VPN" believes traffic is blocked. A daemon
that keeps sending because its uid happens to be under 10000 is an unintended hole — we
did not open it, but benefiting from it silently is not defensible.

So the design is not "how do we bypass lockdown". It is **honour lockdown ourselves,
and depart from it only with authentication**. That inverts the problem usefully:

- no framework patch, because we are not opening anything
- fail-closed for free, because the default is our own refusal

If it turns out we are *not* exempt, this becomes a genuine exemption mechanism and a
second Connectivity patch — one whose purpose is a hole in a security control the user
chose, which is categorically different from the local-network grant and deserves a
separate argument before anyone writes it.

### The session model

Per-transfer authentication does not fit, because **discovery is continuous**. It is
not an event to authorise; it is a state. So authentication opens a bounded session
covering discovery and any transfers inside it.

```
DISABLED ──authenticate──> ACTIVE(lease)
   ▲                            │
   ├── T_idle expired ──────────┤
   ├── T_max expired ───────────┤   regardless of activity
   ├── app died ────────────────┤
   └── daemon restarted ────────┘   lease is in memory, never persisted
```

**Three timers, and the third is not optional:**

- `T_idle` (300s) — counts down when nothing is transferring.
- `T_stall` (30s) — during a transfer, no progress for this long and it stops counting
  as a transfer; the idle clock resumes.
- `T_max` (1800s) — absolute ceiling **regardless of progress**.

`T_max` exists because a stall timer alone does not close the hole. A peer sending one
byte every 29 seconds never stalls and would hold the session open forever, so
"in transfer" would be an unbounded extension primitive. `T_max` bounds it absolutely.

**The clock lives in the daemon**, not the app — the app can be frozen, killed or lied
to, and the enforcement point must own the timing. Use `CLOCK_BOOTTIME`: wall time
would let a clock change extend a session, and `CLOCK_MONOTONIC` stops across suspend,
which would let one survive a night in a pocket.

**DISABLED means silent**, not "visible but refusing": no advertising, no browsing, no
accepting connections. Under lockdown Barq is not on the air at all until a human opens
it. Easier to reason about and easier to verify.

**The cost, which the app must state rather than let people discover:** under lockdown
you cannot receive spontaneously. A sender finds nothing unless you have already opened
a window. That is correct — an always-available receive path is precisely the standing
hole the setting exists to prevent — but it is a visible behaviour change.

Authentication is `BiometricPrompt` with device-credential fallback, so face,
fingerprint and PIN all work and the platform decides which is acceptable. The app
prompts, because the daemon has no UI; the daemon enforces, because the app can be
bypassed.

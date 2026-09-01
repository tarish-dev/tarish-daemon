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

**The exempt sets of the two gates in this file are different**, which is a trap in
both directions:

| gate | exempt set | uid 7500 |
|---|---|---|
| local network access | `is_system_or_root` — uid 0 and 1000 only | **caught** |
| VPN lockdown, unicast | `is_system_uid` — uid < 10000 | **exempt** |
| VPN lockdown, multicast | none — checked before the exemption | **caught** |

Reading only the first two rows is how this document came to claim, wrongly, that we
escape lockdown. The multicast check runs above the exemption, so the exemption is real
and irrelevant for discovery. See the next section.

### ANSWERED: 7500 IS in scope, and only multicast is blocked

Read from source rather than measured, because it is unambiguous. `Vpn.java` builds
the lockdown block list from the whole per-user range and carves out only uid 0:

```java
// The UID range of the first user (0-99999) would block the IPSec traffic, which comes
// directly from the kernel and is marked as uid=0. So we adjust the range to allow it
// through (b/69873852).
rangesThatShouldBeBlocked.add(new UidRangeParcel(1, range.getUpper()));
```

So uids **1..99999** carry `LOCKDOWN_VPN_MATCH`, and 7500 is one of them. An earlier
draft of this document claimed we were probably exempt because `is_system_uid` covers
uid < 10000. That was wrong: the exemption exists, but the multicast check runs FIRST.

| traffic from uid 7500 under lockdown | outcome |
|---|---|
| multicast — mDNS, so AirDrop AND Quick Share discovery | **DROPPED** |
| unicast — an established transfer | **PASSES** via `is_system_uid` |

**Discovery dies; transfers survive.** That is the whole problem, and it is much
narrower than "Barq does not work under lockdown".

So the exemption we would need is not "let Barq talk" but **"let uid 7500 send mDNS
multicast while a session is open"**. Unicast needs nothing. That is a far smaller
thing to argue for, and it lines up exactly with the session model, since discovery is
what a session exists to enable.

Still worth confirming on hardware once a VPN app is installed — enable lockdown, read
`dumpsys connectivity trafficcontroller`, and check that 7500 appears with the lockdown
bit. Source says it must; measuring costs two minutes and this file has been wrong once.

### The measurement, for the record

Enable always-on VPN with lockdown, then read `dumpsys connectivity trafficcontroller`
and confirm 7500 carries the lockdown bit. Needs a VPN app installed; mustang has only
`com.android.vpndialogs`, which is not one.

### This is a real hole, and it deserves its own argument

Since we ARE in scope, this is not "close a gap we inherited" — it is opening one that
the platform deliberately closed, in a security control the user or their administrator
switched on. That is categorically different from the local-network grant, which gave
us a capability the platform already gives to packages and merely withholds from
uid-only daemons.

Nobody should write that patch until the narrow version is argued on its merits:
multicast only, only while an authenticated session is open, revoked on every path that
ends a session. Anything wider is not defensible.

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

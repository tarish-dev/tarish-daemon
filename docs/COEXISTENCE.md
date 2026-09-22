# AirDrop + Quick Share radio coexistence

How Tarish shares one Wi-Fi radio between AWDL (AirDrop) and Wi-Fi Direct (Quick Share).
Established from measuring both our stack and Google's stock stack on the same hardware
(Pixel 10 Pro/XL, BCM4390). This is the design; the open code items are at the end.

## The hardware fact

The chip runs **one** Wi-Fi peer-to-peer interface at a time — AWDL (`WL_IF_TYPE_ART`, from
`wonder.ko`) **or** a Wi-Fi Direct group (`P2P_GO`), not both. The driver refuses the second
with `can't support new iface = WL_IF_TYPE_P2P_GO`. This is true on **stock Google too**: while
mustang was receiving AirDrop over AWDL, an Oppo's Quick Share showed it as "screen off"
(unavailable). So the goal is **not** simultaneity — it is clean time-sharing.

Bluetooth (BLE) is a **separate radio** and coexists freely.

## What coexists, and what doesn't

- **Discovery coexists.** AirDrop advertises over AWDL (+ a BLE wake beacon); Quick Share
  advertises over BLE (+ wlan0 mDNS on-network). `STA + AWDL + BLE` is an allowed combination,
  so a device is discoverable on **both** AirDrop and Quick Share at rest. Keep it that way.
- **Only the transfer contends**, and only for the Wi-Fi P2P slot — which only Quick Share's
  **off-network** path needs.

## Transfer-time decision (branch on the selected peer + path)

| Selected peer / path | Radio it needs | AWDL action |
|---|---|---|
| **Apple (AirDrop)** | AWDL (already up) | none — rides AWDL; present Quick Share as busy meanwhile |
| **Quick Share, same Wi-Fi (LAN)** | wlan0 STA (no P2P slot) | **none** — no conflict, both stay live; this is the fast, common case |
| **Quick Share, off-network** | Wi-Fi Direct (P2P slot) | **tear AWDL down** for the transfer, restore after |

So AWDL is only shut off for the **off-network Quick Share** case. Everything else coexists.

## Off-network Quick Share sequence (the only teardown case)

1. Fully release the P2P slot: **`mosey_stop` is not enough** — it drops `tlink0` but leaves
   `wondertap0` (the `WL_IF_TYPE_ART` monitor iface) registered, so `createGroup` still fails.
   **The trigger is bringing `wondertap0` + `wonder0` DOWN** (validated on blazer): the driver
   then `del_iface`s wondertap0 and idles the monitor (`dhd_monitor_stop`), releasing the ART
   role. **No `rmmod` needed** — a plain `ip link set … down` (inverse of tlink's start trigger).
   Implementation: a tlink HAL `stop()` that downs `wondertap0`+`wonder0`, called from the
   shim's `mosey_stop`; restore goes through the daemon's normal start (a bare `ip link up`
   does not resume the session cleanly).
2. Form/join the Wi-Fi Direct group; run the transfer (wlan0-speed).
3. Restore AWDL, and do what stock does on resume:
   - **send an mDNS goodbye** for the previous AWDL identity (the MAC rotates each session, so
     without this the peer briefly shows two of the device);
   - **kick a targeted Wi-Fi scan** on the STA channel to shorten Wi-Fi recovery;
   - keep the AirDrop **name** stable across restarts so the device stays recognisable.

## Arbitration: one owner at a time, AirDrop has priority

The radio serves **one** peer-to-peer protocol at a time, so when both want it at once, one
must yield — it must not be taken out from under the other. This was found the hard way
(2026-09-22): with an **iPhone AirDrop offer on screen waiting to be accepted**, a Quick Share
request arrived from another Android and **both transfers failed**. Two causes:

1. `arm_wifi_direct` tore AWDL down unconditionally — killing the pending AirDrop offer's radio.
2. `TransferState` models **one** transfer (`current`), so the Quick Share `begin()` overwrote
   the AirDrop offer's id; the radio gate then no longer saw AirDrop as busy.

The rule now (operator's choice): **exactly one transfer at a time, across BOTH protocols** —
including same-network (Wi-Fi LAN) Quick Share, which has no radio conflict but is still
serialised for predictability (the device, the prompt and the file store are shared too).

- **Exclusive claim.** `TransferState::try_begin` claims the single `current` slot with a
  compare-exchange from 0. Every transfer entry point — AirDrop `/Ask`, Quick Share inbound
  (Bluetooth and LAN), and all three send paths — calls it and, on `None` (something already
  running), **refuses busy**: AirDrop answers `/Ask` with `401` (peer shows "Declined"), an
  inbound Quick Share connection is dropped, and a send returns `WOULD_BLOCK`.
- **AirDrop still keeps the radio while it holds the slot.** `airdrop_pending` (set for an
  AirDrop claim) keeps the radio gate holding AWDL up, and `arm_wifi_direct` yields to it —
  belt-and-suspenders now that the slot is exclusive.
- **Reliable release, including hangs and improper closes.** An exclusive slot is only safe if
  it is *always* released, or a dead transfer would wedge all sharing. Every path calls
  `finish` (which frees the slot and clears the radio holds), and as a backstop each transfer
  stamps a `last_activity` time — on claim and on every progress report — so `try_begin`
  **reclaims a slot that has shown no activity for `STALE_TRANSFER` (180 s)**: a hung peer, a
  half-closed socket, or a crash between claim and the transfer loop self-heals within that
  window instead of blocking forever. A live transfer touches the clock constantly, so only a
  genuinely stalled one is ever reclaimed; the window is longer than the accept-prompt wait so
  a pending offer is not mistaken for dead.

So exactly one transfer runs at a time; any new request or accept while one is in flight is
turned away busy, and the slot is guaranteed to free even if a transfer dies uncleanly.

## Graceful signalling

While one protocol owns the radio, present the device to the other as **busy/unavailable**
(stock's "screen off"), rather than hanging or crawling on Bluetooth. Per-transfer this is
implemented (see Arbitration above); doing it at **discovery** level too — hiding one
advertiser while the other transfers — is still open.

## Multi-channel AWDL (so every iPhone peers, not just the ch149 cluster)

Apple's cluster runs a **channel schedule**, captured from stock mosey on hardware:
`master_chan` = ch6 **or** ch149 (follows the master); a 16-slot `channel_seq` with the bulk
channel in most slots and **ch6 fixed at slot 8** as a cross-band rendezvous. Stock mosey
**follows** this schedule rather than pinning one channel. Our tlink pins ch149, so it misses
peers whose master is on ch6 (e.g. an iPhone mini). tlink must parse the master's `channel_seq`
+ `sync_params` and hop to match. Evidence:
`../grapheneos/awdl/captures/stock-mosey-channel-seq-2026092201.txt`.

## What is implemented (2026-09-22)

The AWDL teardown/restore around an off-network Quick Share Wi-Fi Direct transfer is in place:

- **tlink** (`tlink-shim` `mosey_stop`): after the session thread joins, downs `wondertap0`
  then `wonder0` over rtnetlink (`tlink-hal::wonder::set_iface_down`). The driver `del_iface`s
  the ART monitor and `dhd_monitor_stop`s, releasing the P2P slot. `mosey_start_5` recreates
  both, so restore is the daemon's normal start path.
- **sharingd** (`TransferState`): a `wifi_direct_active` override. The radio gate forces
  `WANT_PROP=0` while it is set — overriding a foregrounded app's `active` input, immediately,
  no linger — so tarishd `mosey_stop`s and frees the slot. `arm_wifi_direct()` sets it and
  blocks until the slot is actually free (confirms the gate wrote `WANT_PROP=0`, then a settle
  for the teardown) before the client forms/joins the group. Armed in `host_group`
  (receive/`P2P_GO`) and `join_wifi` for `WifiDirect` (send/`P2P_CLIENT`); released centrally
  in `finish()` so AWDL returns however the transfer ended. AirDrop and Wi-Fi LAN Quick Share
  never arm it.

## Open code items

1. **tlink multi-channel scheduling** — follow the peer `channel_seq`; keep the ch6 rendezvous
   slot. (task #20; the highest functional win — fixes iPhone-mini interop.)
2. **Resume niceties** — on AWDL restore after a Wi-Fi Direct transfer, send an mDNS goodbye
   for the previous AWDL identity (the MAC rotates each session, so a peer can briefly show two
   of the device) and kick a targeted STA-channel scan. The identity name is already kept
   stable across restarts.
3. **Busy/unavailable signalling** to the idle protocol while the radio is owned.

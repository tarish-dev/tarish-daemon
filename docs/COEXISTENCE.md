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

1. Fully release the P2P slot: **`mosey_stop` is not enough** — `wonder.ko`'s `wondertap0`
   (the ART iface) persists and keeps the slot. The slot only frees when the wonder interface
   is actually torn down (module unload, or a wonder/shim-level teardown).
2. Form/join the Wi-Fi Direct group; run the transfer (wlan0-speed).
3. Restore AWDL, and do what stock does on resume:
   - **send an mDNS goodbye** for the previous AWDL identity (the MAC rotates each session, so
     without this the peer briefly shows two of the device);
   - **kick a targeted Wi-Fi scan** on the STA channel to shorten Wi-Fi recovery;
   - keep the AirDrop **name** stable across restarts so the device stays recognisable.

## Graceful signalling

While one protocol owns the radio, present the device to the other as **busy/unavailable**
(stock's "screen off"), rather than hanging or crawling on Bluetooth.

## Multi-channel AWDL (so every iPhone peers, not just the ch149 cluster)

Apple's cluster runs a **channel schedule**, captured from stock mosey on hardware:
`master_chan` = ch6 **or** ch149 (follows the master); a 16-slot `channel_seq` with the bulk
channel in most slots and **ch6 fixed at slot 8** as a cross-band rendezvous. Stock mosey
**follows** this schedule rather than pinning one channel. Our tlink pins ch149, so it misses
peers whose master is on ch6 (e.g. an iPhone mini). tlink must parse the master's `channel_seq`
+ `sync_params` and hop to match. Evidence:
`../grapheneos/awdl/captures/stock-mosey-channel-seq-2026092201.txt`.

## Open code items

1. **tlink multi-channel scheduling** — follow the peer `channel_seq`; keep the ch6 rendezvous
   slot. (task #20; the highest functional win — fixes iPhone-mini interop.)
2. **wonder.ko teardown/restore** around an off-network Quick Share Wi-Fi Direct transfer, with
   the goodbye + targeted-scan recovery above.
3. **Busy/unavailable signalling** to the idle protocol while the radio is owned.

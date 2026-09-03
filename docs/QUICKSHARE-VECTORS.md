# Quick Share — captured vectors from a real peer

Captured from **Windows Quick Share** (Google's Quick Share app for Windows) advertising on
the LAN, 2026-08-28. These are real bytes off a real implementation, not synthesised from
a reading of the protocol, which is what makes them worth keeping: a test that passes
against our own encoder proves only that we are self-consistent.

Captured with nothing more than the host's own resolver, no code of ours involved:

```
dns-sd -B _FC9F5ED42C8A._tcp .
dns-sd -L I0dTWlL8n14AAA _FC9F5ED42C8A._tcp local
```

## The advertisement

```
service   _FC9F5ED42C8A._tcp.local
instance  I0dTWlL8n14AAA
host      K-Desktop5090.local:54703
TXT       n=BgGJXkvVBh_HZPOTA1LoUvoNSy1EZXNrdG9wNTA5MA
```

The service type confirms `sha256("NearbySharing")[0..6]` = `FC9F5ED42C8A`, which we derive
in `quickshare::SERVICE_ID_HASH_PREFIX`.

## Instance name

base64url, 10 bytes, and structurally identical to ours:

```
windows  I0dTWlL8n14AAA  ->  23 | 47 53 5A 52 | FC 9F 5E | 00 00     endpoint_id "GSZR"
ours     I0VyTHf8n14AAA  ->  23 | 45 72 4C 77 | FC 9F 5E | 00 00     endpoint_id "ErLw"
                             ^^   ^^^^^^^^^^^   ^^^^^^^^   ^^^^^
                             PCP  endpoint id   svc hash   reserved
```

Only the random endpoint id differs, which is what should differ. PCP is `0x23` on both.

## EndpointInfo (the `n=` TXT value)

31 bytes:

```
06 01 89 5E 4B D5 06 1F C7 64 F3 93 03 52 E8 52 FA 0D 4B 2D 44 65 73 6B 74 6F 70 35 30 39 30
^^ |------------------ 16 byte metadata -----------------| ^^ |------- "K-Desktop5090" -------|
header                                                     len
```

Header byte `0x06` = `0000 0110`:

| field | bits | value |
|---|---|---|
| version | 7..5 | 0 |
| hidden | 4 | 0 |
| device_type | 3..1 | **3** (laptop) |
| reserved | 0 | 0 |

`device_type=3` for a Windows desktop is a useful data point: the field describes a form
factor, and Windows reports laptop rather than a desktop-specific value.

The name is length-prefixed UTF-8 with no terminator and no trailing bytes, which matches
`quickshare::endpoint`.

## What this already settles

- the service type, the instance encoding and the EndpointInfo layout are right
- **LAN discovery is real.** Quick Share advertises over mDNS on the local network, so it
  is not a BLE-only discovery protocol with mDNS as a mere connection medium. That was an
  open question and it is now answered by observation.
- a peer is reachable at a plain TCP port (`54703` here) taken from the SRV record, which
  is where the Nearby Connections framing begins

## What it does NOT settle

- whether a peer will *accept* a connection that arrives without any prior BLE contact.
  Discovery working over mDNS does not by itself prove the connection path does.
- anything above the transport: UKEY2, the connection frames and the sharing FSM are all
  still unverified against a real implementation.
- the 16 metadata bytes are opaque here. They are not decoded, and nothing in our code
  depends on their content yet.

## Re-capturing

The instance name and port change per session, so these exact values are a snapshot. The
structure is what is being asserted, not the bytes. Re-run the two `dns-sd` commands above
against any Windows or Android peer with Quick Share visible to everyone.

## BLE endpoint advertisements, captured 2026-09-03

Taken on mustang with an unfiltered BLE scan (`persist.barq.ble_debug 1`), in a room with
a Windows machine running Quick Share and an Android device actively sharing.

**The headline result is a negative one.** Over several minutes there were **zero**
`0xFE2C` FastInitiation pulses and hundreds of `0xFEF3` advertisements. Discovery happens
on `0xFEF3`; the `0xFE2C` pulse is a sender waking an idle receiver, not the mechanism by
which peers are found. `protocol/src/ble.rs` said otherwise until this capture.

Three advertisements, from two devices with randomised addresses:

```
4a17233932584d1132b3480eb85b8b562fcefb2077e73494e5f264    endpoint "92XM"
4a172357444b4811320f75aa376a6c91683c1583cf24accd3c2536    endpoint "WDKH"
4a172342524a361132e88e4a78a8c8399b84fcc5a2404ee85f2d94    endpoint "BRJ6"
```

Structure, agreed by all three:

| offset | bytes | meaning |
|---|---|---|
| 0 | `4a` | version and flags; bit 1 set marks a fast advertisement |
| 1–2 | `17 23` | constant in every sample; **meaning not established**. `0x17` = 23 = length − 4 |
| 3–6 | varies | endpoint id, four printable ASCII characters |
| 7 | `11` | endpoint-info length, 17 |
| 8–24 | varies | endpoint info: flags byte, 2-byte salt, 14-byte encrypted metadata key |
| 25–26 | varies | two trailing bytes, **purpose unknown** |

The endpoint-info length being exactly 17 across three samples from two devices is what
makes the reading credible: 1 + 2 + 14 is Quick Share's own endpoint-info shape.

Decrypting the device name from the metadata key needs a contact certificate rooted in a
Google account. Barq has none and wants none, so the field is carried and not
interpreted — the name arrives later over the connection, as it does for AirDrop.

For contrast, the idle background advertisements on the same service are 17 bytes and a
different shape, and must not be read as peers:

```
5120001111020000232000557834460000
512210001002040803200082db0adb0000
5128000010024020231000158513940000    (K-PROART, the Windows machine, while idle)
```

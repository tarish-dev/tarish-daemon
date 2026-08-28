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

# The AirDrop protocol layer

## Status

Not implemented in Barq. **Already solved in GoOpenDrop**, whose server and client both
implement the full exchange against real Apple devices. What follows is what that
establishes, so Barq implements from a working description instead of rediscovering it.

Reimplemented, not reused, at the author's request — see [CREDITS](CREDITS.md) in the
app repo. The value taken is the description.

## The listener

HTTPS on the **AWDL interface's IPv6 link-local address, with the scope ID**:

```
[fe80::xxxx:xxxx:xxxx:xxxx%mosey0]:PORT
```

Binding to the scoped address matters. A link-local address is ambiguous without its
interface, and the port must be the one the SRV record advertises. Barq currently
advertises `8770` with **nothing bound to it**, which is why no peer could ever list us
regardless of discovery.

## TLS — the question I wrongly called unknown

- The server presents an ordinary **self-signed certificate**. There is no need to
  produce an Apple-issued one for the receiving side.
- The client sets `InsecureSkipVerify` and does **not** validate the peer's certificate.
- Apple's root CA is carried (`certs/apple_root_ca.pem`) to validate Apple's *client*
  certificates where that matters, along with a separate **validation record**.

So "what will Everyone mode accept from an unknown peer" has an answer: a self-signed
certificate is enough. This was recorded as the major open unknown and as the main
justification for a capture rig. It was neither — the answer already existed.

## Scope: "everyone" only — contacts mode is deliberately not implemented

Operator's decision, and it removes the single worst dependency in the protocol.

Contacts-only AirDrop proves identity with an Apple-issued **validation record** and
client certificate. Those cannot be generated; they have to be **extracted from a real
Apple device**, and they **expire annually**. Building on them would mean a device that
silently stops working a year later and can only be fixed by having an Apple device to
hand.

The trust it buys is also largely notional here. This is a transfer between two
platforms that have no trust relationship in the first place; a certificate chain that
proves "this is an Apple ID in your contacts" does not make the peer trustworthy, it
only makes it *identified*.

Concretely, this means:

- `ReceiverRecordData` is **omitted** from the `/Discover` response
- no client certificate is presented or required
- `certs/apple_root_ca.pem` is not needed — we validate nobody
- we are listed as an unknown device, which is correct and honest

## The `/Discover` response

A binary plist:

| Key | Value |
|---|---|
| `ReceiverComputerName` | the name shown in the sender's AirDrop UI |
| `ReceiverModelName` | device model string |
| `ReceiverMediaCapabilities` | the JSON bytes `{"Version":1}` |
| `ReceiverRecordData` | Apple validation record — **omitted**, see above |

This settles where the display name comes from: it is **here**, in the protocol, not in
mDNS. Consistent with Mosey publishing no name anywhere in its records, and with the
TXT carrying only `flags`.

`/Ask` answers with `ReceiverModelName` and `ReceiverComputerName`.

## The TXT `flags` field has meaning

GoOpenDrop advertises `flags=136` and documents it as
`SUPPORTS_DISCOVER_MAYBE (0x80) | SUPPORTS_MIXED_TYPES (0x08)`, crediting opendrop for
the decoding.

We measured Google's Mosey advertising `flags=489` = `0x1E9`, which includes both of
those bits and four more. Two independent implementations therefore use different
values and both interoperate, so this is a capability bitmap and not a magic constant —
which is worth knowing, because it means a wrong value degrades features rather than
breaking discovery outright.

Barq sends `489` because that is what was measured from a working Android
implementation on the same hardware. The remaining bits are not decoded here and are
not guessed at.

## HTTP quirks that are not optional

Two things the handlers force explicitly, which read as noise and are not:

- **HTTP/1.1, not HTTP/2.** The server pins `ProtoMajor=1, ProtoMinor=1` per request and
  the client disables HTTP/2 by passing an empty `TLSNextProto` map. Go would otherwise
  negotiate h2 over TLS and Apple's stack does not expect it.
- **`Connection: close` on every response.** Each exchange is its own connection.

A `HEAD /` returning `200` with `Content-Length: 0` is also implemented — Apple probes
it, and failing that probe is enough to be dropped.

## Endpoints

| Method | Path | Purpose |
|---|---|---|
| `HEAD` | `/` | liveness probe |
| `POST` | `/Discover` | "who are you" — decides whether we appear in the sender's UI |
| `POST` | `/Ask` | "may I send you this" — the accept/decline prompt |
| `POST` | `/Upload` | the payload itself |

Bodies are **Apple binary plists**, served as `application/octet-stream`. Unauthorised
requests get `401` with `Content-Length: 0`.

`/Discover` can be answered with a **precomputed fixed response** — GoOpenDrop serves a
constant byte slice. Being listed does not require dynamic logic, which makes it a very
cheap first milestone.

## Payload

The uploaded bundle is a **cpio archive**, so a cpio reader is required to receive and a
writer to send. GoOpenDrop implements both in `awdl/cpio/`.

## What this means for Barq's order of work

1. Bind TLS on the advertised port with a self-signed certificate
2. `HEAD /` and a fixed `/Discover` response — enough to be listed
3. `/Ask`, then `/Upload` plus cpio
4. Only then revisit discovery, which is cheap to test once something answers

Discovery was treated as the blocker for several cycles. The listener was the more
fundamental gap and the cheaper thing to check.

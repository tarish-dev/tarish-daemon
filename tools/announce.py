#!/usr/bin/env python3
"""Send an mDNS announcement for _airdrop._tcp.local out of a chosen interface.

Tests tarishsharingd's browser without depending on macOS actually having AirDrop
open: this is the same PTR/SRV/AAAA shape a real peer announces.
"""
import socket, struct, sys, time

IFACE = sys.argv[1] if len(sys.argv) > 1 else "awdl0"
INSTANCE = sys.argv[2] if len(sys.argv) > 2 else "beefcafe1234"
PORT = 8770

def name(n):
    out = b""
    for label in n.split("."):
        out += bytes([len(label)]) + label.encode()
    return out + b"\x00"

svc = "_airdrop._tcp.local"
inst = f"{INSTANCE}.{svc}"
host = f"{INSTANCE}.local"

idx = socket.if_nametoindex(IFACE)

# link-local address of that interface, for the AAAA record
addr6 = None
for fam, _, _, _, sa in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET6):
    pass
import subprocess, re
out = subprocess.run(["ifconfig", IFACE], capture_output=True, text=True).stdout
m = re.search(r"inet6 (fe80::[0-9a-f:]+)%", out)
addr6 = m.group(1) if m else "fe80::1"

hdr = struct.pack("!HHHHHH", 0, 0x8400, 0, 3, 0, 0)   # response, 3 answers

# PTR: _airdrop._tcp.local -> instance
ptr_rd = name(inst)
ptr = name(svc) + struct.pack("!HHIH", 12, 0x8001, 120, len(ptr_rd)) + ptr_rd

# SRV: instance -> host:port
srv_rd = struct.pack("!HHH", 0, 0, PORT) + name(host)
srv = name(inst) + struct.pack("!HHIH", 33, 0x8001, 120, len(srv_rd)) + srv_rd

# AAAA: host -> link-local
aaaa_rd = socket.inet_pton(socket.AF_INET6, addr6)
aaaa = name(host) + struct.pack("!HHIH", 28, 0x8001, 120, len(aaaa_rd)) + aaaa_rd

pkt = hdr + ptr + srv + aaaa

s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_IF, struct.pack("I", idx))
s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_HOPS, 255)
dst = ("ff02::fb", 5353, 0, idx)

print(f"announcing {inst} -> {host}:{PORT} [{addr6}] out {IFACE} (idx {idx})")
for i in range(8):
    s.sendto(pkt, dst)
    time.sleep(1.5)
print("done")

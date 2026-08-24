#!/usr/bin/env bash
# attribute.sh — summarise an mdnsdump capture, split into US and PEER.
#
#   tools/attribute.sh <capture.txt> [serial]
#
# WHY THIS EXISTS
#
# Twice now a capture has been read as "a peer is asking for AirDrop" when every
# packet was our own. mDNS multicast loops back, so our questions arrive at our own
# socket and look exactly like a peer's.
#
# The second time was worse than the first: the address was hard-coded from an
# earlier session, and mosey0's link-local address CHANGES on reboot. So the stale
# constant labelled our own traffic PEER, which is the most misleading possible
# failure -- it manufactures the result you were hoping for.
#
# Therefore: this reads our address from the device, live, every run. Never pass it
# in, never remember it.
set -uo pipefail
CAP="${1:?usage: attribute.sh <capture.txt> [serial]}"
ADB=(adb); [ $# -ge 2 ] && ADB=(adb -s "$2")

OURS="$("${ADB[@]}" shell "ip -6 addr show mosey0 2>/dev/null | grep -oE 'fe80::[0-9a-f:]+'" 2>/dev/null | tr -d '\r')"
[ -n "$OURS" ] || { echo "cannot read mosey0 address — is the device attached and mosey0 up?" >&2; exit 1; }
echo "ours (live): $OURS"

awk -v ours="$OURS" '
    /bytes from/ { match($0, /from [0-9a-f:]+/); src = substr($0, RSTART+5, RLENGTH-5); next }
    /^[[:space:]]*Q[[:space:]]/ {
        if (src == "") next
        who = (src == ours) ? "US" : "PEER"
        name = $3
        key = who " " src " " name
        count[key]++
    }
    END {
        for (k in count) printf "%-4s %s x%d\n", "", k, count[k]
    }
' "$CAP" | sort -k2 | sed 's/^ *//'

echo
n=$(awk -v ours="$OURS" '
    /bytes from/ { match($0, /from [0-9a-f:]+/); src = substr($0, RSTART+5, RLENGTH-5); next }
    /^[[:space:]]*Q[[:space:]]/ { if (src != ours && $3 ~ /_airdrop/) c++ }
    END { print c+0 }' "$CAP")
echo "peers asking for _airdrop._tcp: $n"
[ "$n" -eq 0 ] && echo "  -> nothing is looking for us; discovery has not been triggered"

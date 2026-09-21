# Patches against the platform

One patch, and it is not optional.

## `packages_modules_Connectivity` — local network access for the sharing daemon

`tarishsharingd` runs as its own AID (7500, `system_ext_tarish`) so that the process parsing
input from strangers owns nothing else on the device. That decision has one consequence
the platform does not let you fix from outside it.

Since Android B, reaching the local network is gated by a BPF map.
`is_local_network_access_blocked()` in `bpf/progs/netd.c` exempts **only uid 0 and uid
1000**; every other uid must carry `PERMISSION_BIT_ACCESS_LOCAL_NETWORK` in
`sUidPermissionChunkMap`. `PermissionMonitor` builds that map from **installed packages**.

A native daemon has no package. So it can never earn the bit, and every mDNS
`sendto(224.0.0.251:5353)` fails with `EPERM`. The daemon starts, advertises, looks
healthy, and silently never sends.

The patch adds the uid to the map in `PermissionMonitor`'s existing callback. One bit,
for one uid. Notably **not** `NO_INTERNET`, which leaves the uid's internet access exactly
as it was.

It is applied at the policy layer rather than in the BPF program on purpose: `dumpsys
connectivity` then shows the grant, so it is visible to anyone auditing the device rather
than buried in a kernel map.

**The patch hardcodes 7500 and so does `config/tarish_aid.txt`.** If you change one, change
the other. They cannot disagree quietly — the daemon would start and never send.

### Applying it

```bash
cd packages/modules/Connectivity
git apply /path/to/tarish-daemon/patches/packages_modules_Connectivity/*.patch
```

`repo sync` resets projects to their manifest revision and will silently discard it, so
re-apply after every sync. Check with `git apply --check` before assuming it is still
there.

### Why AirDrop did not need this

AirDrop rides `tlink0`, which is not a *managed network* and is not gated at all. Quick
Share rides `wlan0`, which is. The daemon did mDNS correctly for weeks before this
surfaced, because only one of the two protocols crosses that gate.

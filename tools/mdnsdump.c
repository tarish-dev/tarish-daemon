// mdnsdump — print every mDNS record seen on one interface.
//
// Runs on the device, where AWDL multicast is actually receivable. macOS gates
// reception on awdl0, so the phone is the only vantage point that can see what
// an Apple peer really puts on the wire.
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <net/if.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

static const char *tname(unsigned t) {
    switch (t) { case 1: return "A"; case 12: return "PTR"; case 16: return "TXT";
                 case 28: return "AAAA"; case 33: return "SRV"; case 47: return "NSEC";
                 default: return "?"; }
}

// Returns bytes consumed at `pos`; writes the name into out.
static int rdname(const unsigned char *b, int len, int pos, char *out, int outsz) {
    int start = pos, jumps = 0, adv = -1, o = 0;
    out[0] = 0;
    while (pos >= 0 && pos < len) {
        int l = b[pos];
        if ((l & 0xC0) == 0xC0) {
            if (pos + 1 >= len) return -1;
            if (adv < 0) adv = pos + 2 - start;
            pos = ((l & 0x3F) << 8) | b[pos + 1];
            if (++jumps > 16) return -1;
            continue;
        }
        if (l == 0) { if (adv < 0) adv = pos + 1 - start; break; }
        pos++;
        if (pos + l > len || o + l + 2 > outsz) return -1;
        if (o) out[o++] = '.';
        memcpy(out + o, b + pos, l); o += l; out[o] = 0;
        pos += l;
    }
    return adv < 0 ? -1 : adv;
}

int main(int argc, char **argv) {
    const char *iface = argc > 1 ? argv[1] : "mosey0";
    int secs = argc > 2 ? atoi(argv[2]) : 30;

    unsigned idx = if_nametoindex(iface);
    if (!idx) { printf("no such interface: %s\n", iface); return 1; }

    int s = socket(AF_INET6, SOCK_DGRAM, 0);
    int on = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &on, sizeof on);
#ifdef SO_REUSEPORT
    setsockopt(s, SOL_SOCKET, SO_REUSEPORT, &on, sizeof on);
#endif
    struct sockaddr_in6 a = {0};
    a.sin6_family = AF_INET6; a.sin6_port = htons(5353);
    if (bind(s, (struct sockaddr *)&a, sizeof a) < 0) { perror("bind"); return 1; }

    struct ipv6_mreq mreq = {0};
    inet_pton(AF_INET6, "ff02::fb", &mreq.ipv6mr_multiaddr);
    mreq.ipv6mr_interface = idx;
    if (setsockopt(s, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP, &mreq, sizeof mreq) < 0) {
        perror("join"); return 1;
    }
    struct timeval tv = { .tv_sec = 1 };
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);

    printf("dumping mDNS on %s (idx %u) for %ds\n", iface, idx, secs);
    time_t end = time(NULL) + secs;
    unsigned char buf[4096];
    char nm[300];
    int pkts = 0;

    while (time(NULL) < end) {
        struct sockaddr_in6 from; socklen_t fl = sizeof from;
        int n = recvfrom(s, buf, sizeof buf, 0, (struct sockaddr *)&from, &fl);
        if (n < 12) continue;
        pkts++;
        char src[64];
        inet_ntop(AF_INET6, &from.sin6_addr, src, sizeof src);
        int qd = (buf[4] << 8) | buf[5], an = (buf[6] << 8) | buf[7];
        int ns = (buf[8] << 8) | buf[9], ar = (buf[10] << 8) | buf[11];
        printf("--- %d bytes from %s  qd=%d an=%d ns=%d ar=%d\n", n, src, qd, an, ns, ar);

        int pos = 12, ok = 1;
        for (int i = 0; i < qd && ok; i++) {
            int c = rdname(buf, n, pos, nm, sizeof nm);
            if (c < 0) { ok = 0; break; }
            pos += c;
            if (pos + 4 > n) { ok = 0; break; }
            unsigned qt = (buf[pos] << 8) | buf[pos + 1];
            printf("    Q  %-6s %s\n", tname(qt), nm);
            pos += 4;
        }
        for (int i = 0; i < an + ns + ar && ok; i++) {
            int c = rdname(buf, n, pos, nm, sizeof nm);
            if (c < 0) break;
            pos += c;
            if (pos + 10 > n) break;
            unsigned rt = (buf[pos] << 8) | buf[pos + 1];
            int rl = (buf[pos + 8] << 8) | buf[pos + 9];
            pos += 10;
            if (pos + rl > n) break;
            printf("    A  %-6s %s", tname(rt), nm);
            if (rt == 12) { char t[300]; if (rdname(buf, n, pos, t, sizeof t) > 0) printf(" -> %s", t); }
            else if (rt == 33 && rl >= 6) {
                char t[300]; rdname(buf, n, pos + 6, t, sizeof t);
                printf(" -> %s:%d", t, (buf[pos + 4] << 8) | buf[pos + 5]);
            } else if (rt == 28 && rl == 16) {
                char ip[64]; inet_ntop(AF_INET6, buf + pos, ip, sizeof ip); printf(" -> %s", ip);
            } else if (rt == 16) {
                printf(" -> ");
                for (int k = 0; k < rl && k < 120;) {
                    int sl = buf[pos + k]; k++;
                    if (sl <= 0 || k + sl > rl) break;
                    printf("[%.*s]", sl, buf + pos + k);
                    k += sl;
                }
            }
            printf("\n");
            pos += rl;
        }
    }
    printf("done — %d packet(s)\n", pkts);
    return 0;
}

// barqd — Barq AWDL transport daemon.
//
// Holds the AWDL link up so nothing above it has to care. This is the piece
// that lets Bada be only a UI: a native daemon has no foreground-service rule,
// so there is no permanent notification, and no doze or app-standby rules apply
// to it at all.
//
// It is the same shape Google uses: mosey_server is a native daemon running as
// `system` with NET_ADMIN|NET_RAW and no notification anywhere, while MoseyApp
// is just the client. We are not inventing an architecture, we are matching a
// working one.
//
// WHAT IT DOES
//
//   1. dlopen /system_ext/lib64/libmosey_daemon_ffi.so
//   2. mosey_start_5(...) with the signature recovered in docs/MOSEY-ABI.md
//   3. add the IPv6 link-local route Android does NOT add for us
//   4. stay alive holding the handle -- the session dies with its holder
//   5. mosey_stop(handle) on SIGTERM, so a restart is clean
//
// WHAT IT DOES NOT DO YET
//
//   mDNS, the AirDrop protocol, and any IPC for Bada. Transport only.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <dlfcn.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <android/log.h>

#define TAG  "barqd"
#define LIB  "/system_ext/lib64/libmosey_daemon_ffi.so"
#define IFACE "mosey0"

#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN,  TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

typedef void *(*start5_fn)(const uint8_t *, uint64_t, uint32_t,
                           const char *, uint32_t, const uint8_t *, uint64_t);
typedef void *(*stop_fn)(void *);

static volatile sig_atomic_t running = 1;
static void on_signal(int s) { (void)s; running = 0; }

// Android routes by fwmark, and the per-network table for a freshly created
// interface starts EMPTY -- an address alone gives ENETUNREACH on connect().
// The route must go in the table Android names after the interface.
//
// Done over netlink rather than by exec'ing `ip`. Forking a shell utility would
// need `allow barqd system_file:file execute_no_trans`, which lets this daemon
// execute ANY system binary -- far too broad a grant to buy one route, and it
// showed up as exactly that denial. RTM_NEWROUTE costs about sixty lines and
// needs no new permission beyond the netlink_route_socket we already hold.
static int add_link_local_route(void) {
    int fd = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);
    if (fd < 0) { LOGE("netlink socket: %s", strerror(errno)); return -1; }

    unsigned idx = if_nametoindex(IFACE);
    if (!idx) { LOGE("if_nametoindex(%s): %s", IFACE, strerror(errno)); close(fd); return -1; }

    // Android names the per-network route table after the interface; the numeric
    // id is what the kernel wants. Interface index doubles as the table id for
    // these per-network tables on Android.
    struct {
        struct nlmsghdr  nh;
        struct rtmsg     rt;
        char             buf[256];
    } req;
    memset(&req, 0, sizeof req);

    req.nh.nlmsg_len   = NLMSG_LENGTH(sizeof(struct rtmsg));
    req.nh.nlmsg_type  = RTM_NEWROUTE;
    req.nh.nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL | NLM_F_ACK;

    req.rt.rtm_family   = AF_INET6;
    req.rt.rtm_dst_len  = 64;                 // fe80::/64
    req.rt.rtm_table    = RT_TABLE_UNSPEC;    // real id goes in RTA_TABLE below
    req.rt.rtm_protocol = RTPROT_STATIC;
    req.rt.rtm_scope    = RT_SCOPE_LINK;
    req.rt.rtm_type     = RTN_UNICAST;

    struct in6_addr dst;
    memset(&dst, 0, sizeof dst);
    dst.s6_addr[0] = 0xfe; dst.s6_addr[1] = 0x80;

    struct rtattr *rta;
    size_t off = NLMSG_ALIGN(req.nh.nlmsg_len);
    #define ADD_ATTR(type, ptr, len) do {                                   \
        rta = (struct rtattr *)((char *)&req + off);                        \
        rta->rta_type = (type);                                             \
        rta->rta_len  = RTA_LENGTH(len);                                    \
        memcpy(RTA_DATA(rta), (ptr), (len));                                \
        off += RTA_ALIGN(rta->rta_len);                                     \
    } while (0)

    ADD_ATTR(RTA_DST, &dst, sizeof dst);
    ADD_ATTR(RTA_OIF, &idx, sizeof idx);
    uint32_t table = idx;
    ADD_ATTR(RTA_TABLE, &table, sizeof table);
    #undef ADD_ATTR

    req.nh.nlmsg_len = off;

    struct sockaddr_nl kernel;
    memset(&kernel, 0, sizeof kernel);
    kernel.nl_family = AF_NETLINK;

    if (sendto(fd, &req, req.nh.nlmsg_len, 0,
               (struct sockaddr *)&kernel, sizeof kernel) < 0) {
        LOGE("RTM_NEWROUTE send: %s", strerror(errno)); close(fd); return -1;
    }

    char resp[512];
    ssize_t n = recv(fd, resp, sizeof resp, 0);
    close(fd);
    if (n < 0) { LOGW("no netlink ack: %s", strerror(errno)); return -1; }

    struct nlmsghdr *rh = (struct nlmsghdr *)resp;
    if (rh->nlmsg_type == NLMSG_ERROR) {
        struct nlmsgerr *e = (struct nlmsgerr *)NLMSG_DATA(rh);
        if (e->error == 0)        { LOGI("route: fe80::/64 dev %s table %u", IFACE, idx); return 0; }
        if (e->error == -EEXIST)  { LOGI("route already present"); return 0; }
        LOGE("RTM_NEWROUTE: %s", strerror(-e->error));
        return -1;
    }
    LOGI("route: fe80::/64 dev %s table %u", IFACE, idx);
    return 0;
}

int main(void) {
    signal(SIGTERM, on_signal);
    signal(SIGINT,  on_signal);

    LOGI("starting");

    void *h = dlopen(LIB, RTLD_NOW);
    if (!h) { LOGE("dlopen %s: %s", LIB, dlerror()); return 1; }

    start5_fn start5 = (start5_fn)dlsym(h, "mosey_start_5");
    stop_fn   stop   = (stop_fn)  dlsym(h, "mosey_stop");
    if (!start5) { LOGE("mosey_start_5 not found -- vendor image ABI changed?"); return 1; }

    // Values confirmed against 13 live calls plus a working invocation.
    // StartMoseyConfig: field 1 = is_dbs_supported, field 6 = rate_adaptation.
    const uint8_t channels[] = { 149 };
    const uint8_t config[]   = { 0x08, 0x01, 0x30, 0x01 };
    const char   *country    = "QA";
    const uint32_t OP_NETLINK = 2;   // 1 = radiotap/ArtIoctl, 2 = wonder0/netlink
    const uint32_t MAX_MDNS   = 0x7fffffff;

    void *session = start5(channels, sizeof channels, MAX_MDNS,
                           country, OP_NETLINK, config, sizeof config);
    if (!session) {
        LOGE("mosey_start_5 returned NULL -- check logcat for mosey_daemon, "
             "it reports how it parsed every argument");
        return 1;
    }
    LOGI("AWDL session up, handle=%p, channel=%u", session, channels[0]);

    sleep(2);                 // let the interface appear before routing it
    if (add_link_local_route() != 0)
        LOGW("link-local route not added — sockets on %s will get ENETUNREACH", IFACE);

    // The session lives exactly as long as this process. Exiting tears down
    // mosey0 and the device stops being discoverable, so hold here.
    while (running) pause();

    LOGI("stopping");
    if (stop) stop(session);
    dlclose(h);
    return 0;
}

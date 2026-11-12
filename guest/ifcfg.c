// Freestanding arm64 test of the interface Android is shown for the network, doing
// what netd and IpClient do with eth1. Run with ZEROEMU_NET=1.

typedef unsigned long u64;
typedef long i64;
typedef unsigned int u32;
typedef unsigned short u16;
typedef unsigned char u8;

#define NR_ioctl 29
#define NR_openat 56
#define NR_close 57
#define NR_read 63
#define NR_write 64
#define NR_exit_group 94
#define NR_setresuid 147
#define NR_socket 198
#define NR_bind 200
#define NR_connect 203
#define NR_sendto 206
#define NR_recvfrom 207
#define NR_setsockopt 208

static i64 sys6(i64 n, i64 a, i64 b, i64 c, i64 d, i64 e, i64 f) {
    register i64 x8 __asm__("x8") = n;
    register i64 x0 __asm__("x0") = a;
    register i64 x1 __asm__("x1") = b;
    register i64 x2 __asm__("x2") = c;
    register i64 x3 __asm__("x3") = d;
    register i64 x4 __asm__("x4") = e;
    register i64 x5 __asm__("x5") = f;
    __asm__ volatile("svc #0" : "+r"(x0) : "r"(x8), "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5) : "memory");
    return x0;
}
#define sys(n, ...) sys6_(n, __VA_ARGS__, 0, 0, 0, 0, 0, 0)
#define sys6_(n, a, b, c, d, e, f, ...) sys6(n, (i64)(a), (i64)(b), (i64)(c), (i64)(d), (i64)(e), (i64)(f))

void *memset(void *d, int c, u64 n) { char *p = d; while (n--) *p++ = (char)c; return d; }
void *memcpy(void *d, const void *s, u64 n) { char *p = d; const char *q = s; while (n--) *p++ = *q++; return d; }
static u64 slen(const char *s) { u64 n = 0; while (s[n]) n++; return n; }
static int same(const void *a, const void *b, u64 n) { const char *p = a, *q = b; while (n--) if (*p++ != *q++) return 0; return 1; }
static void puts_(const char *s) { sys(NR_write, 1, s, slen(s)); }

static int failures;
static void check(int cond, const char *name) {
    puts_(cond ? "ok   " : "FAIL ");
    puts_(name);
    puts_("\n");
    if (!cond) failures++;
}

#define EPERM 1
#define ENETUNREACH 101
#define EAGAIN 11
#define EADDRNOTAVAIL 99
#define AF_INET 2
#define AF_NETLINK 16
#define SOCK_DGRAM 2
#define SOCK_RAW 3
#define MSG_DONTWAIT 0x40
#define RTM_NEWLINK 16
#define RTM_GETLINK 18
#define RTM_NEWADDR 20
#define RTM_DELADDR 21
#define RTM_GETADDR 22
#define NLMSG_ERROR 2
#define NLMSG_DONE 3
#define NLM_F_REQUEST 1
#define NLM_F_ACK 4
#define NLM_F_DUMP 0x300
#define IFA_ADDRESS 1
#define IFA_LOCAL 2
#define IFA_BROADCAST 4
#define IFA_LABEL 3
#define IFA_FLAGS 8
#define IFLA_ADDRESS 1
#define IFF_UP 1
#define IFF_RUNNING 0x40
#define IFF_LOWER_UP 0x10000
#define SIOCGIFFLAGS 0x8913
#define SIOCSIFFLAGS 0x8914
#define SIOCGIFADDR 0x8915
#define SIOCSIFADDR 0x8916
#define SIOCGIFNETMASK 0x891b
#define SIOCGIFHWADDR 0x8927
#define SIOCGIFINDEX 0x8933
#define SIOCGIFCONF 0x8912
#define SIOCETHTOOL 0x8946

struct nlmsghdr { u32 len; u16 type, flags; u32 seq, pid; };
struct ifreq { char name[16]; union { struct { u16 family, port; u8 addr[4]; u8 pad[8]; } in; int value; u16 flags; struct { u16 family; u8 mac[6]; } hw; u8 raw[24]; } u; };
struct sockaddr_nl { u16 family, pad; u32 pid, groups; };

static const u8 IP[4] = { 10, 0, 2, 15 };
static u8 rbuf[8192];

static void name(struct ifreq *r) {
    memset(r, 0, sizeof *r);
    memcpy(r->name, "eth1", 5);
}

// The attribute `type` of an rtnetlink message past `hdr` bytes of fixed header, or null.
static u8 *rta(u8 *msg, u64 hdr, u16 type, int *len) {
    struct nlmsghdr *h = (void *)msg;
    u64 off = sizeof *h + hdr;
    while (off + 4 <= h->len) {
        u16 alen = *(u16 *)(msg + off), kind = *(u16 *)(msg + off + 2);
        if (alen < 4) return 0;
        if (kind == type) {
            if (len) *len = alen - 4;
            return msg + off + 4;
        }
        off += (alen + 3) & ~3u;
    }
    return 0;
}

static void request(int fd, u16 type, u16 flags, const void *body, u64 n) {
    static u8 m[256];
    struct nlmsghdr *h = (void *)m;
    memset(m, 0, sizeof m);
    h->len = sizeof *h + n;
    h->type = type;
    h->flags = flags;
    h->seq = 7;
    memcpy(m + sizeof *h, body, n);
    struct sockaddr_nl to = { AF_NETLINK };
    sys(NR_sendto, fd, m, h->len, 0, &to, sizeof to);
}

static i64 ack(int fd) {
    i64 n = sys(NR_recvfrom, fd, rbuf, sizeof rbuf, MSG_DONTWAIT, 0, 0);
    struct nlmsghdr *h = (void *)rbuf;
    if (n < 20 || h->type != NLMSG_ERROR) return -1000;
    return *(int *)(rbuf + sizeof *h);
}

// RTM_NEWADDR as ifc_add_address sends it: IFA_LOCAL and IFA_BROADCAST, nothing else.
static void address(int fd, u16 type, const u8 *ip, int prefix, int index) {
    u8 b[40] = { AF_INET, (u8)prefix, 0, 0 };
    *(int *)(b + 4) = index;
    *(u16 *)(b + 8) = 8;
    *(u16 *)(b + 10) = IFA_LOCAL;
    memcpy(b + 12, ip, 4);
    *(u16 *)(b + 16) = 8;
    *(u16 *)(b + 18) = IFA_BROADCAST;
    memcpy(b + 20, ip, 4);
    request(fd, type, NLM_F_REQUEST | NLM_F_ACK, b, 24);
}

static int read_file(const char *path, char *out, u64 n) {
    int fd = (int)sys(NR_openat, -100, path, 0, 0);
    if (fd < 0) return -1;
    i64 got = sys(NR_read, fd, out, n);
    sys(NR_close, fd);
    return (int)got;
}

int cmain(void) {
    int s = (int)sys(NR_socket, AF_INET, SOCK_DGRAM, 0);
    struct ifreq r;

    // ---- it's there, up, and has no address
    name(&r);
    check(sys(NR_ioctl, s, SIOCGIFINDEX, &r) == 0 && r.u.value == 2, "eth1 exists, index 2");
    name(&r);
    check(sys(NR_ioctl, s, SIOCGIFFLAGS, &r) == 0 && (r.u.flags & (IFF_UP | IFF_RUNNING)) == (IFF_UP | IFF_RUNNING), "up and running");
    name(&r);
    check(sys(NR_ioctl, s, SIOCGIFHWADDR, &r) == 0 && r.u.hw.family == 1 && r.u.hw.mac[0] == 0x52 && r.u.hw.mac[5] == 0x56, "with an Ethernet address");
    name(&r);
    check(sys(NR_ioctl, s, SIOCGIFADDR, &r) == -EADDRNOTAVAIL, "and no IP address");
    name(&r);
    check(sys(NR_ioctl, s, SIOCETHTOOL, &r) == -95, "no driver to ask: EOPNOTSUPP");

    char file[64];
    check(read_file("/sys/class/net/eth1/address", file, 64) == 18 && same(file, "52:54:00:12:34:56", 17), "sysfs has its address");
    check(read_file("/proc/sys/net/ipv6/conf/eth1/disable_ipv6", file, 64) > 0, "and its sysctls exist");
    check(read_file("/proc/sys/net/ipv4/neigh/eth1/ucast_solicit", file, 64) > 0, "including neighbour ones");

    // ---- a dump as EthernetTracker sends it: a one-byte rtgenmsg
    int rt = (int)sys(NR_socket, AF_NETLINK, SOCK_RAW, 0);
    struct sockaddr_nl me = { AF_NETLINK, 0, 0, 1 << 4 | 1 }; // groups 5 and 1
    check(sys(NR_bind, rt, &me, sizeof me) == 0, "a socket on the address and link groups");
    u8 gen[1] = { 0 };
    request(rt, RTM_GETLINK, NLM_F_REQUEST | NLM_F_DUMP, gen, 1);
    int seen_eth = 0;
    for (;;) {
        i64 n = sys(NR_recvfrom, rt, rbuf, sizeof rbuf, MSG_DONTWAIT, 0, 0);
        struct nlmsghdr *h = (void *)rbuf;
        if (n <= 0 || h->type == NLMSG_DONE) break;
        int index = *(int *)(rbuf + sizeof *h + 4);
        unsigned flags = *(unsigned *)(rbuf + sizeof *h + 8);
        if (index == 2) {
            int alen = 0;
            u8 *mac = rta(rbuf, 16, IFLA_ADDRESS, &alen);
            seen_eth = alen == 6 && mac && mac[0] == 0x52 && (flags & IFF_LOWER_UP) != 0;
        }
    }
    check(seen_eth, "the link dump has it, with its address, link up");

    // ---- netd clears it
    name(&r);
    r.u.in.family = AF_INET;
    check(sys(NR_ioctl, s, SIOCSIFADDR, &r) == 0, "SIOCSIFADDR 0 clears nothing and succeeds");
    u8 zero[4] = { 0 };
    address(rt, RTM_NEWADDR, zero, 0, 2);
    check(ack(rt) == 0, "and 0.0.0.0/0, which netd sends as well, is acknowledged");
    name(&r);
    check(sys(NR_ioctl, s, SIOCGIFADDR, &r) == -EADDRNOTAVAIL, "and isn't an address");

    // ---- IpClient configures it
    address(rt, RTM_DELADDR, IP, 24, 2);
    check(ack(rt) == -EADDRNOTAVAIL, "deleting what isn't there: EADDRNOTAVAIL");
    address(rt, RTM_NEWADDR, IP, 24, 2);
    i64 n = sys(NR_recvfrom, rt, rbuf, sizeof rbuf, MSG_DONTWAIT, 0, 0);
    struct nlmsghdr *h = (void *)rbuf;
    int alen = 0;
    int announced = n > 0 && h->type == RTM_NEWADDR && rbuf[sizeof *h] == AF_INET && rbuf[sizeof *h + 1] == 24 && *(int *)(rbuf + sizeof *h + 4) == 2;
    check(announced, "the address is announced on its group");
    u8 *a = rta(rbuf, 8, IFA_ADDRESS, &alen);
    check(a && alen == 4 && same(a, IP, 4), "with IFA_ADDRESS, or IpClient drops it");
    check(rta(rbuf, 8, IFA_FLAGS, 0) != 0, "and IFA_FLAGS, likewise");
    check(rta(rbuf, 8, IFA_LOCAL, 0) && rta(rbuf, 8, IFA_LABEL, 0), "and the rest");
    check(ack(rt) == 0, "and acknowledged");

    name(&r);
    check(sys(NR_ioctl, s, SIOCGIFADDR, &r) == 0 && same(r.u.in.addr, IP, 4), "SIOCGIFADDR has it");
    name(&r);
    u8 mask[4] = { 255, 255, 255, 0 };
    check(sys(NR_ioctl, s, SIOCGIFNETMASK, &r) == 0 && same(r.u.in.addr, mask, 4), "and SIOCGIFNETMASK the prefix");
    u8 conf[80] = { 0 };
    struct { int len; int pad; void *buf; } ifc = { sizeof conf, 0, conf };
    check(sys(NR_ioctl, s, SIOCGIFCONF, &ifc) == 0 && ifc.len == 80 && same(conf + 40, "eth1", 4) && same(conf + 60, IP, 4), "and SIOCGIFCONF lists it after lo");

    u8 family[1] = { AF_INET };
    request(rt, RTM_GETADDR, NLM_F_REQUEST | NLM_F_DUMP, family, 1);
    int in_dump = 0;
    for (;;) {
        n = sys(NR_recvfrom, rt, rbuf, sizeof rbuf, MSG_DONTWAIT, 0, 0);
        if (n <= 0 || h->type == NLMSG_DONE) break;
        if (*(int *)(rbuf + sizeof *h + 4) == 2) in_dump = 1;
    }
    check(in_dump, "the address dump has it");

    // ---- flags, as NetlinkUtils.setInterfaceFlags
    u8 link[16] = { 0 };
    *(int *)(link + 4) = 2;
    *(unsigned *)(link + 8) = 0;
    *(unsigned *)(link + 12) = IFF_UP;
    request(rt, RTM_NEWLINK, NLM_F_REQUEST | NLM_F_ACK, link, 16);
    n = sys(NR_recvfrom, rt, rbuf, sizeof rbuf, MSG_DONTWAIT, 0, 0);
    check(n > 0 && h->type == RTM_NEWLINK && (*(unsigned *)(rbuf + sizeof *h + 8) & IFF_UP) == 0, "taking it down is announced on the link group");
    check(ack(rt) == 0, "and acknowledged");
    *(unsigned *)(link + 8) = IFF_UP;
    request(rt, RTM_NEWLINK, NLM_F_REQUEST | NLM_F_ACK, link, 16);
    n = sys(NR_recvfrom, rt, rbuf, sizeof rbuf, MSG_DONTWAIT, 0, 0);
    check(n > 0 && h->type == RTM_NEWLINK && (*(unsigned *)(rbuf + sizeof *h + 8) & IFF_UP) != 0, "so is bringing it up");
    check(ack(rt) == 0, "and acknowledged");

    // ---- and goes
    address(rt, RTM_DELADDR, IP, 24, 2);
    n = sys(NR_recvfrom, rt, rbuf, sizeof rbuf, MSG_DONTWAIT, 0, 0);
    check(n > 0 && h->type == RTM_DELADDR, "removing it is announced");
    check(ack(rt) == 0, "and acknowledged");
    name(&r);
    check(sys(NR_ioctl, s, SIOCGIFADDR, &r) == -EADDRNOTAVAIL, "it's gone");

    // ---- more than one address, and which one a delete means
    u8 second[4] = { 10, 0, 2, 16 }, other[4] = { 192, 0, 2, 1 };
    address(rt, RTM_NEWADDR, IP, 24, 2);
    sys(NR_recvfrom, rt, rbuf, sizeof rbuf, MSG_DONTWAIT, 0, 0);
    check(ack(rt) == 0, "the address again");
    address(rt, RTM_NEWADDR, second, 24, 2);
    n = sys(NR_recvfrom, rt, rbuf, sizeof rbuf, MSG_DONTWAIT, 0, 0);
    check(n > 0 && h->type == RTM_NEWADDR, "a second is announced, with no word of removing the first");
    check(ack(rt) == 0, "and acknowledged");
    name(&r);
    check(sys(NR_ioctl, s, SIOCGIFADDR, &r) == 0 && same(r.u.in.addr, IP, 4), "the first stays primary");
    address(rt, RTM_DELADDR, other, 32, 2);
    check(ack(rt) == -EADDRNOTAVAIL, "deleting one it doesn't have: EADDRNOTAVAIL");
    name(&r);
    check(sys(NR_ioctl, s, SIOCGIFADDR, &r) == 0 && same(r.u.in.addr, IP, 4), "and nothing's gone");
    address(rt, RTM_DELADDR, second, 24, 2);
    n = sys(NR_recvfrom, rt, rbuf, sizeof rbuf, MSG_DONTWAIT, 0, 0);
    u8 *gone = rta(rbuf, 8, IFA_LOCAL, 0);
    check(n > 0 && h->type == RTM_DELADDR && gone && same(gone, second, 4), "the second goes, and that's what's announced");
    check(ack(rt) == 0, "and acknowledged");
    name(&r);
    check(sys(NR_ioctl, s, SIOCGIFADDR, &r) == 0 && same(r.u.in.addr, IP, 4), "the first is still there");

    // ---- flags set the old way are announced too
    name(&r);
    sys(NR_ioctl, s, SIOCGIFFLAGS, &r);
    r.u.flags = (u16)(r.u.flags & ~IFF_UP);
    check(sys(NR_ioctl, s, SIOCSIFFLAGS, &r) == 0, "SIOCSIFFLAGS: down");
    n = sys(NR_recvfrom, rt, rbuf, sizeof rbuf, MSG_DONTWAIT, 0, 0);
    check(n > 0 && h->type == RTM_NEWLINK && (*(unsigned *)(rbuf + sizeof *h + 8) & IFF_RUNNING) == 0, "announced, no longer running");
    struct { u16 family; u16 port; u8 addr[4]; u8 pad[8]; } far = { AF_INET, 0x3500, { 8, 8, 8, 8 }, { 0 } };
    int probe = (int)sys(NR_socket, AF_INET, SOCK_DGRAM, 0);
    check(sys(NR_connect, probe, &far, sizeof far) == -ENETUNREACH, "and an interface that's down has no route");
    name(&r);
    sys(NR_ioctl, s, SIOCGIFFLAGS, &r);
    r.u.flags = (u16)(r.u.flags | IFF_UP);
    sys(NR_ioctl, s, SIOCSIFFLAGS, &r);
    n = sys(NR_recvfrom, rt, rbuf, sizeof rbuf, MSG_DONTWAIT, 0, 0);
    check(n > 0 && h->type == RTM_NEWLINK && (*(unsigned *)(rbuf + sizeof *h + 8) & IFF_RUNNING) != 0, "up again, running again");
    check(sys(NR_connect, probe, &far, sizeof far) == 0, "with its route");

    // ---- a TUN device's name is a directory under /sys
    {
        int tun = (int)sys(NR_openat, -100, "/dev/tun", 2, 0);
        struct ifreq tr;
        memset(&tr, 0, sizeof tr);
        memcpy(tr.name, "..", 3);
        tr.u.flags = 1; // IFF_TUN
        if (tun >= 0) check(sys(NR_ioctl, tun, 0x400454ca /* TUNSETIFF */, &tr) == -22, "a TUN device can't be called ..");
    }

    // ---- none of that without the capability
    check(sys(NR_setresuid, 10100, 10100, 10100) == 0, "become an app");
    name(&r);
    r.u.in.family = AF_INET;
    check(sys(NR_ioctl, s, SIOCSIFADDR, &r) == -EPERM, "SIOCSIFADDR: EPERM");
    name(&r);
    check(sys(NR_ioctl, s, SIOCSIFFLAGS, &r) == -EPERM, "SIOCSIFFLAGS: EPERM");
    name(&r);
    check(sys(NR_ioctl, s, SIOCGIFADDR, &r) == 0 && same(r.u.in.addr, IP, 4), "asking is fine, and the address is still there");
    int app = (int)sys(NR_socket, AF_NETLINK, SOCK_RAW, 0);
    struct sockaddr_nl none = { AF_NETLINK };
    sys(NR_bind, app, &none, sizeof none);
    address(app, RTM_DELADDR, IP, 24, 2);
    check(ack(app) == -EPERM, "RTM_DELADDR: EPERM");
    address(app, RTM_NEWADDR, second, 24, 2);
    check(ack(app) == -EPERM, "RTM_NEWADDR: EPERM");
    u8 link2[16] = { 0 };
    *(int *)(link2 + 4) = 2;
    *(unsigned *)(link2 + 12) = IFF_UP;
    request(app, RTM_NEWLINK, NLM_F_REQUEST | NLM_F_ACK, link2, 16);
    check(ack(app) == -EPERM, "RTM_NEWLINK: EPERM");
    u8 fam[1] = { AF_INET };
    request(app, RTM_GETADDR, NLM_F_REQUEST | NLM_F_DUMP, fam, 1);
    n = sys(NR_recvfrom, app, rbuf, sizeof rbuf, MSG_DONTWAIT, 0, 0);
    check(n > 0 && h->type != NLMSG_ERROR, "a dump is for anyone");
    struct sockaddr_nl group = { AF_NETLINK, 0, 0, 1 << 4 };
    u8 forged[32] = { 0 };
    check(sys(NR_sendto, app, forged, sizeof forged, 0, &group, sizeof group) == -EPERM, "forging a group's news: EPERM");
    check(sys(NR_socket, AF_INET, SOCK_RAW, 255) == -EPERM, "a raw socket: EPERM");
    int big_buf = 1 << 30;
    check(sys(NR_setsockopt, s, 1 /* SOL_SOCKET */, 33 /* SO_RCVBUFFORCE */, &big_buf, 4) == -EPERM, "SO_RCVBUFFORCE: EPERM");

    puts_(failures ? "SOME CHECKS FAILED\n" : "all checks passed\n");
    return failures;
}

void __attribute__((noreturn)) cstart(void) {
    sys(NR_exit_group, cmain());
    __builtin_unreachable();
}

__asm__(".global _start\n_start:\n bl cstart\n");

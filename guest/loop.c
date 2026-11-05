// Freestanding arm64 test of sockets on the device reaching each other: no host socket,
// no network needed. Written to pass on real Linux too.

typedef unsigned long u64;
typedef long i64;
typedef unsigned int u32;
typedef unsigned short u16;
typedef unsigned char u8;

#define NR_close 57
#define NR_read 63
#define NR_write 64
#define NR_ppoll 73
#define NR_exit_group 94
#define NR_socket 198
#define NR_bind 200
#define NR_listen 201
#define NR_accept 202
#define NR_connect 203
#define NR_getsockname 204
#define NR_getpeername 205
#define NR_sendto 206
#define NR_recvfrom 207
#define NR_setsockopt 208
#define NR_getsockopt 209
#define NR_shutdown 210
#define NR_sendmsg 211
#define NR_recvmsg 212
#define NR_accept4 242
#define NR_recvmmsg 243
#define NR_getrlimit 163
#define NR_setrlimit 164
#define NR_sendmmsg 269

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
static void putn(i64 v) {
    char b[24]; int i = 23; b[i] = 0;
    int neg = v < 0; u64 u = neg ? (u64)-v : (u64)v;
    do { b[--i] = (char)('0' + u % 10); u /= 10; } while (u);
    if (neg) b[--i] = '-';
    puts_(b + i);
}
static int failures;
static void check(int cond, const char *name) {
    puts_(cond ? "ok   " : "FAIL ");
    puts_(name);
    puts_("\n");
    if (!cond) failures++;
}
static void expect(i64 got, i64 want, const char *name) {
    check(got == want, name);
    if (got != want) { puts_("     got "); putn(got); puts_(", wanted "); putn(want); puts_("\n"); }
}

#define EAGAIN 11
#define EINVAL 22
#define EPIPE 32
#define EADDRINUSE 98
#define ECONNRESET 104
#define EISCONN 106
#define ENOTCONN 107
#define ECONNREFUSED 111
#define AF_INET 2
#define AF_INET6 10
#define SOCK_STREAM 1
#define SOCK_DGRAM 2
#define SOCK_NONBLOCK 04000
#define SOL_IP 0
#define SOL_SOCKET 1
#define SOL_IPV6 41
#define SO_REUSEADDR 2
#define SO_ERROR 4
#define SO_ACCEPTCONN 30
#define SO_TIMESTAMP 29
#define IP_TTL 2
#define IP_PKTINFO 8
#define IP_RECVTTL 12
#define IPV6_V6ONLY 26
#define MSG_DONTWAIT 0x40
#define MSG_NOSIGNAL 0x4000
#define MSG_TRUNC 0x20
#define MSG_CTRUNC 0x8
#define MSG_WAITALL 0x100
#define MSG_WAITFORONE 0x10000
#define POLLIN 1
#define POLLOUT 4
#define POLLERR 8
#define POLLHUP 0x10
#define POLLRDHUP 0x2000

struct in4 { u16 family; u16 port; u8 addr[4]; u8 pad[8]; };
struct in6 { u16 family; u16 port; u32 flow; u8 addr[16]; u32 scope; };
struct pollfd { int fd; short events, revents; };
struct iovec { void *base; u64 len; };
struct msghdr { void *name; u32 namelen; struct iovec *iov; u64 iovlen; void *control; u64 controllen; u32 flags; };
struct mmsghdr { struct msghdr hdr; u32 len; };
struct cmsg { u64 len; int level, type; u8 data[]; };

static u16 be(u16 v) { return (u16)(v << 8 | v >> 8); }
static struct in4 v4(u8 a, u8 b, u8 c, u8 d, u16 port) { struct in4 s = { AF_INET, be(port), { a, b, c, d }, { 0 } }; return s; }
static int wait_for(int fd, int events, i64 ms) {
    struct pollfd p = { fd, (short)events, 0 };
    struct { i64 s, ns; } t = { ms / 1000, (ms % 1000) * 1000000 };
    i64 r = sys(NR_ppoll, &p, 1, &t, 0, 8);
    return r < 0 ? (int)r : p.revents;
}
static int intopt(int fd, int level, int name) {
    int v = -12345, len = sizeof v;
    i64 r = sys(NR_getsockopt, fd, level, name, &v, &len);
    return r < 0 ? (int)r : v;
}
static int listener(u16 port) {
    int fd = (int)sys(NR_socket, AF_INET, SOCK_STREAM, 0);
    struct in4 at = v4(127, 0, 0, 1, port);
    sys(NR_bind, fd, &at, sizeof at);
    sys(NR_listen, fd, 8);
    return fd;
}
static int connected(u16 port) {
    int fd = (int)sys(NR_socket, AF_INET, SOCK_STREAM, 0);
    struct in4 to = v4(127, 0, 0, 1, port);
    i64 r = sys(NR_connect, fd, &to, sizeof to);
    if (r != 0) { puts_("     could not connect: "); putn(r); puts_("\n"); }
    return fd;
}

static u8 big[1 << 20], back[1 << 20];
static u8 pattern(u64 at) { return (u8)((at * 2654435761u) >> 24); }

int cmain(void) {
    char buf[256];

    // ---- connecting and accepting
    int l = listener(41000);
    check(intopt(l, SOL_SOCKET, SO_ACCEPTCONN) == 1, "SO_ACCEPTCONN");
    expect(wait_for(l, POLLIN, 0), 0, "nothing waiting: poll says so");
    int nb = (int)sys(NR_socket, AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    struct in4 at = v4(127, 0, 0, 1, 41000);
    sys(NR_bind, nb, &at, 0);
    int c = connected(41000);
    check(c >= 0, "a connect to a listener on this device");
    check(wait_for(c, POLLOUT, 0) & POLLOUT, "it's up at once");
    check(wait_for(l, POLLIN, 1000) & POLLIN, "the listener polls readable");
    struct in4 peer, me;
    int len = sizeof peer;
    int s = (int)sys(NR_accept4, l, &peer, &len, SOCK_NONBLOCK);
    check(s >= 0 && len == 16 && peer.family == AF_INET, "accept4 names the peer");
    u8 lo[4] = { 127, 0, 0, 1 };
    check(same(peer.addr, lo, 4) && peer.port != 0, "as 127.0.0.1, with a port");
    int mlen = sizeof me;
    check(sys(NR_getsockname, c, &me, &mlen) == 0 && me.port == peer.port && same(me.addr, lo, 4), "which is the client's own name");
    mlen = sizeof me;
    check(sys(NR_getsockname, s, &me, &mlen) == 0 && me.port == be(41000), "the accepted socket is named by the port connected to");
    mlen = sizeof me;
    check(sys(NR_getpeername, c, &me, &mlen) == 0 && me.port == be(41000) && same(me.addr, lo, 4), "and that's the client's peer");
    expect(wait_for(l, POLLIN, 0), 0, "taken: the listener has nothing again");
    expect(sys(NR_accept4, nb, 0, 0, 0), -EINVAL, "accept on a socket not listening: EINVAL");
    expect(sys(NR_connect, c, &at, sizeof at), -EISCONN, "connected already: EISCONN");

    // ---- talking
    expect(sys(NR_recvfrom, s, buf, 8, 0, 0, 0), -EAGAIN, "the accepted socket was asked to be non-blocking");
    expect(sys(NR_write, c, "hello", 5), 5, "write");
    check(wait_for(s, POLLIN, 1000) & POLLIN, "the other end polls readable");
    expect(sys(NR_recvfrom, s, buf, 8, 2 /* MSG_PEEK */, 0, 0), 5, "peek");
    expect(sys(NR_read, s, buf, 8), 5, "read");
    check(same(buf, "hello", 5), "the right bytes");
    expect(sys(NR_write, s, "world", 5), 5, "and back");
    expect(sys(NR_recvfrom, c, buf, 5, MSG_WAITALL, 0, 0), 5, "read, blocking");
    check(same(buf, "world", 5), "right");

    // ---- full, and through a lot of it
    int cn = (int)sys(NR_socket, AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    expect(sys(NR_connect, cn, &at, sizeof at), 0, "a non-blocking connect here: at once");
    int sn = (int)sys(NR_accept4, l, 0, 0, SOCK_NONBLOCK);
    u64 sent = 0, got = 0;
    int bad = 0, stalls = 0;
    const u64 TEN_MB = 10 << 20;
    while (got < TEN_MB && stalls < 50) {
        i64 w = 0, r = 0;
        if (sent < TEN_MB) {
            u64 n = TEN_MB - sent;
            if (n > sizeof big) n = sizeof big;
            for (u64 i = 0; i < n; i++) big[i] = pattern(sent + i);
            w = sys(NR_write, cn, big, n);
            if (w > 0) sent += (u64)w;
            else if (w != -EAGAIN) { bad = 1; break; }
        }
        r = sys(NR_read, sn, back, sizeof back);
        if (r > 0) {
            for (i64 i = 0; i < r; i++) if (back[i] != pattern(got + (u64)i)) bad = 1;
            got += (u64)r;
        } else if (r != -EAGAIN) { bad = 1; break; }
        stalls = (w <= 0 && r <= 0) ? stalls + 1 : 0;
    }
    check(!bad && got == TEN_MB, "10 MB from one to the other, every byte right, with the queue full on the way");

    // Full: writes stop, and poll says when there's room.
    i64 total = 0, w;
    while ((w = sys(NR_write, cn, big, sizeof big)) > 0) total += w;
    check(total > 0 && w == -EAGAIN, "nobody reading: EAGAIN when full");
    expect(wait_for(cn, POLLOUT, 0), 0, "and not writable");
    while (sys(NR_read, sn, back, sizeof back) > 0) {}
    check(wait_for(cn, POLLOUT, 1000) & POLLOUT, "read it all: writable");
    sys(NR_close, cn);
    sys(NR_close, sn);

    // ---- endings
    expect(sys(NR_shutdown, c, 1), 0, "shutdown(SHUT_WR)");
    int rev = wait_for(s, POLLIN | POLLRDHUP, 1000);
    check((rev & POLLIN) && (rev & POLLRDHUP) && !(rev & POLLHUP), "the other end: RDHUP, and not HUP");
    expect(sys(NR_read, s, buf, 8), 0, "the end of the stream");
    expect(sys(NR_write, s, "more", 4), 4, "it can still send");
    expect(sys(NR_read, c, buf, 8), 4, "and that's heard");
    expect(sys(NR_sendto, c, "x", 1, MSG_NOSIGNAL, 0, 0), -EPIPE, "the side that shut can't: EPIPE");
    sys(NR_close, s);
    expect(sys(NR_read, c, buf, 8), 0, "the other end closes: the end for this one too");
    sys(NR_close, c);

    c = connected(41000);
    s = (int)sys(NR_accept4, l, 0, 0, 0);
    sys(NR_close, s);
    check(wait_for(c, POLLIN, 1000) & POLLIN, "closed: readable");
    expect(sys(NR_read, c, buf, 8), 0, "the end of the stream");
    expect(sys(NR_sendto, c, "x", 1, MSG_NOSIGNAL, 0, 0), 1, "the first send after that goes through");
    expect(sys(NR_sendto, c, "x", 1, MSG_NOSIGNAL, 0, 0), -EPIPE, "the next: EPIPE");
    sys(NR_close, c);

    c = connected(41000);
    s = (int)sys(NR_accept4, l, 0, 0, 0);
    sys(NR_write, c, "unread", 6);
    sys(NR_close, s);
    rev = wait_for(c, POLLIN, 1000);
    check(rev & POLLERR, "closed with bytes unread: an error");
    expect(sys(NR_read, c, buf, 8), -ECONNRESET, "ECONNRESET");
    expect(sys(NR_read, c, buf, 8), 0, "once, then the end");
    sys(NR_close, c);

    // Never accepted.
    c = connected(41000);
    sys(NR_close, l);
    rev = wait_for(c, POLLIN, 1000);
    expect(sys(NR_read, c, buf, 8), -ECONNRESET, "the listener goes with a connection waiting: ECONNRESET");
    sys(NR_close, c);
    int after = (int)sys(NR_socket, AF_INET, SOCK_STREAM, 0);
    struct in4 gone = v4(127, 0, 0, 1, 41000);
    expect(sys(NR_connect, after, &gone, sizeof gone), -ECONNREFUSED, "and after that: ECONNREFUSED");
    sys(NR_close, after);

    // ---- who's reachable how
    int wild = (int)sys(NR_socket, AF_INET6, SOCK_STREAM, 0);
    struct in6 any6 = { AF_INET6, be(41001), 0, { 0 }, 0 };
    sys(NR_bind, wild, &any6, sizeof any6);
    expect(sys(NR_listen, wild, 4), 0, "a dual-stack wildcard listener");
    c = connected(41001);
    check(c >= 0, "reached by IPv4");
    struct in6 p6;
    len = sizeof p6;
    s = (int)sys(NR_accept, wild, &p6, &len);
    u8 mapped_lo[16] = { 0,0,0,0,0,0,0,0,0,0,0xff,0xff,127,0,0,1 };
    check(s >= 0 && len == 28 && p6.family == AF_INET6 && same(p6.addr, mapped_lo, 16), "whose name it's given as ::ffff:127.0.0.1");
    sys(NR_close, s);
    sys(NR_close, c);
    int c6 = (int)sys(NR_socket, AF_INET6, SOCK_STREAM, 0);
    struct in6 lo6 = { AF_INET6, be(41001), 0, { 0 }, 0 };
    lo6.addr[15] = 1;
    expect(sys(NR_connect, c6, &lo6, sizeof lo6), 0, "and by ::1");
    len = sizeof p6;
    s = (int)sys(NR_accept, wild, &p6, &len);
    check(s >= 0 && same(p6.addr, lo6.addr, 16), "named ::1");
    sys(NR_close, s);
    sys(NR_close, c6);
    sys(NR_close, wild);

    int only6 = (int)sys(NR_socket, AF_INET6, SOCK_STREAM, 0);
    int on = 1;
    sys(NR_setsockopt, only6, SOL_IPV6, IPV6_V6ONLY, &on, 4);
    struct in6 any7 = { AF_INET6, be(41002), 0, { 0 }, 0 };
    sys(NR_bind, only6, &any7, sizeof any7);
    sys(NR_listen, only6, 4);
    int v4c = (int)sys(NR_socket, AF_INET, SOCK_STREAM, 0);
    struct in4 to7 = v4(127, 0, 0, 1, 41002);
    expect(sys(NR_connect, v4c, &to7, sizeof to7), -ECONNREFUSED, "IPV6_V6ONLY: no IPv4");
    sys(NR_close, v4c);
    sys(NR_close, only6);

    int spec = listener(41003);
    int wrong = (int)sys(NR_socket, AF_INET, SOCK_STREAM, 0);
    struct in4 other_lo = v4(127, 0, 0, 2, 41003);
    expect(sys(NR_connect, wrong, &other_lo, sizeof other_lo), -ECONNREFUSED, "a listener on one address isn't on another");
    sys(NR_close, wrong);
    sys(NR_close, spec);

    int any4 = (int)sys(NR_socket, AF_INET, SOCK_STREAM, 0);
    struct in4 w4 = v4(0, 0, 0, 0, 41004);
    sys(NR_bind, any4, &w4, sizeof w4);
    sys(NR_listen, any4, 4);
    int zero = (int)sys(NR_socket, AF_INET, SOCK_STREAM, 0);
    expect(sys(NR_connect, zero, &w4, sizeof w4), 0, "connecting to 0.0.0.0 means this machine");
    mlen = sizeof me;
    check(sys(NR_getsockname, zero, &me, &mlen) == 0 && same(me.addr, lo, 4), "from loopback");
    sys(NR_close, zero);
    sys(NR_close, any4);

    // ---- changing its mind, a listener: this used to hang for ever on its own lock
    {
        int ul = listener(41005);
        int waiting = connected(41005);
        struct { u16 family; u8 pad[14]; } unspec = { 0, { 0 } };
        expect(sys(NR_connect, ul, &unspec, sizeof unspec), 0, "connect(AF_UNSPEC) on a listener");
        expect(sys(NR_accept4, ul, 0, 0, 0), -EINVAL, "it isn't one now");
        check(wait_for(waiting, POLLIN, 1000) & POLLIN, "whoever was waiting hears");
        expect(sys(NR_read, waiting, buf, 8), -ECONNRESET, "that it's been reset");
        struct in4 self_to = v4(127, 0, 0, 1, 41005);
        expect(sys(NR_connect, ul, &self_to, sizeof self_to), -ECONNREFUSED, "connecting it to its own port: refused, and returns");
        int nobody = (int)sys(NR_socket, AF_INET, SOCK_STREAM, 0);
        expect(sys(NR_connect, nobody, &self_to, sizeof self_to), -ECONNREFUSED, "so does anyone else");
        int taker = (int)sys(NR_socket, AF_INET, SOCK_STREAM, 0);
        int yes = 1;
        sys(NR_setsockopt, taker, SOL_SOCKET, SO_REUSEADDR, &yes, 4);
        sys(NR_setsockopt, ul, SOL_SOCKET, SO_REUSEADDR, &yes, 4);
        sys(NR_close, waiting);
        sys(NR_close, nobody);
        sys(NR_close, taker);
        sys(NR_close, ul);
    }

    // ---- no descriptor for it: the connection stays queued
    {
        int al = listener(41006);
        int client = connected(41006);
        struct { u64 cur, max; } low, old;
        sys(NR_getrlimit, 7, &old);
        low.cur = 0; low.max = old.max;
        sys(NR_setrlimit, 7, &low);
        expect(sys(NR_accept4, al, 0, 0, 0), -24 /* EMFILE */, "at the limit: EMFILE");
        sys(NR_setrlimit, 7, &old);
        int taken = (int)sys(NR_accept4, al, 0, 0, 0);
        check(taken >= 0, "with room again, it's still there");
        expect(sys(NR_write, client, "kept", 4), 4, "and still connected");
        expect(sys(NR_read, taken, buf, 8), 4, "both ways");
        sys(NR_close, taken);
        sys(NR_close, client);
        sys(NR_close, al);
    }

    // The kernel picks a port for a listener with none.
    int auto_l = (int)sys(NR_socket, AF_INET, SOCK_STREAM, 0);
    sys(NR_listen, auto_l, 4);
    mlen = sizeof me;
    check(sys(NR_getsockname, auto_l, &me, &mlen) == 0 && me.port != 0, "listen with no bind gets a port");
    sys(NR_close, auto_l);

    // ---- datagrams
    int a = (int)sys(NR_socket, AF_INET, SOCK_DGRAM, 0), b = (int)sys(NR_socket, AF_INET, SOCK_DGRAM, 0);
    struct in4 ua = v4(127, 0, 0, 1, 41010), ub = v4(127, 0, 0, 1, 41011);
    sys(NR_bind, a, &ua, sizeof ua);
    expect(sys(NR_sendto, b, "one", 3, 0, &ua, sizeof ua), 3, "a datagram to a socket on this device");
    check(wait_for(a, POLLIN, 1000) & POLLIN, "it polls readable");
    len = sizeof peer;
    expect(sys(NR_recvfrom, a, buf, 8, 0, &peer, &len), 3, "one arrives");
    check(same(buf, "one", 3) && same(peer.addr, lo, 4) && peer.port != 0, "from loopback, and an automatic port");
    mlen = sizeof me;
    sys(NR_getsockname, b, &me, &mlen);
    check(me.port == peer.port, "the sender's own");
    expect(sys(NR_sendto, a, "reply", 5, 0, &peer, sizeof peer), 5, "reply to where it came from");
    expect(sys(NR_recvfrom, b, buf, 8, 0, 0, 0), 5, "heard");
    check(same(buf, "reply", 5), "right");
    sys(NR_sendto, b, "two", 3, 0, &ua, sizeof ua);
    sys(NR_sendto, b, "three", 5, 0, &ua, sizeof ua);
    expect(sys(NR_recvfrom, a, buf, 8, 0, 0, 0), 3, "datagrams stay separate");
    expect(sys(NR_recvfrom, a, buf, 8, 0, 0, 0), 5, "the second");
    sys(NR_sendto, b, "a long one", 10, 0, &ua, sizeof ua);
    expect(sys(NR_recvfrom, a, buf, 4, 0, 0, 0), 4, "cut to the room");
    expect(sys(NR_recvfrom, a, buf, 8, MSG_DONTWAIT, 0, 0), -EAGAIN, "and the rest is gone");

    struct in4 unused = v4(127, 0, 0, 1, 41019);
    expect(sys(NR_sendto, b, "x", 1, 0, &unused, sizeof unused), 1, "unconnected, to nobody: it goes");
    expect(sys(NR_sendto, b, "x", 1, 0, &unused, sizeof unused), 1, "and no complaint");
    int cu = (int)sys(NR_socket, AF_INET, SOCK_DGRAM, 0);
    sys(NR_connect, cu, &unused, sizeof unused);
    expect(sys(NR_write, cu, "x", 1), 1, "connected, to nobody: it goes");
    expect(sys(NR_recvfrom, cu, buf, 8, MSG_DONTWAIT, 0, 0), -ECONNREFUSED, "and the next call hears");
    expect(sys(NR_recvfrom, cu, buf, 8, MSG_DONTWAIT, 0, 0), -EAGAIN, "once");
    sys(NR_close, cu);

    // Connected to 0.0.0.0 means this machine, and that's who answers.
    {
        int server_u = (int)sys(NR_socket, AF_INET, SOCK_DGRAM, 0);
        struct in4 at_u = v4(127, 0, 0, 1, 41013), any_u = v4(0, 0, 0, 0, 41013);
        sys(NR_bind, server_u, &at_u, sizeof at_u);
        int client_u = (int)sys(NR_socket, AF_INET, SOCK_DGRAM, 0);
        expect(sys(NR_connect, client_u, &any_u, sizeof any_u), 0, "connect a datagram socket to 0.0.0.0");
        mlen = sizeof me;
        check(sys(NR_getpeername, client_u, &me, &mlen) == 0 && same(me.addr, lo, 4), "its peer is loopback");
        expect(sys(NR_write, client_u, "q", 1), 1, "send");
        len = sizeof peer;
        expect(sys(NR_recvfrom, server_u, buf, 8, MSG_DONTWAIT, &peer, &len), 1, "heard");
        sys(NR_sendto, server_u, "a", 1, 0, &peer, sizeof peer);
        expect(sys(NR_recvfrom, client_u, buf, 8, MSG_DONTWAIT, 0, 0), 1, "and the answer isn't thrown away");
        sys(NR_close, server_u);
        sys(NR_close, client_u);
    }

    // A socket connected to the sender is who hears it, even with another on the port.
    {
        int yes = 1;
        struct in4 shared = v4(127, 0, 0, 1, 41014), sender_at = v4(127, 0, 0, 1, 41015);
        int general = (int)sys(NR_socket, AF_INET, SOCK_DGRAM, 0), to_sender = (int)sys(NR_socket, AF_INET, SOCK_DGRAM, 0), sender = (int)sys(NR_socket, AF_INET, SOCK_DGRAM, 0);
        sys(NR_setsockopt, general, SOL_SOCKET, SO_REUSEADDR, &yes, 4);
        sys(NR_setsockopt, to_sender, SOL_SOCKET, SO_REUSEADDR, &yes, 4);
        sys(NR_bind, general, &shared, sizeof shared);
        sys(NR_bind, to_sender, &shared, sizeof shared);
        sys(NR_bind, sender, &sender_at, sizeof sender_at);
        sys(NR_connect, to_sender, &sender_at, sizeof sender_at);
        sys(NR_sendto, sender, "m", 1, 0, &shared, sizeof shared);
        expect(sys(NR_recvfrom, to_sender, buf, 8, MSG_DONTWAIT, 0, 0), 1, "a connected socket hears its peer");
        expect(sys(NR_recvfrom, general, buf, 8, MSG_DONTWAIT, 0, 0), -EAGAIN, "and the other on that port doesn't");
        sys(NR_close, general);
        sys(NR_close, to_sender);
        sys(NR_close, sender);
    }

    // Naming the peer is the same as sending without a name.
    {
        int cu2 = (int)sys(NR_socket, AF_INET, SOCK_DGRAM, 0);
        struct in4 nobody2 = v4(127, 0, 0, 1, 41018);
        sys(NR_connect, cu2, &nobody2, sizeof nobody2);
        expect(sys(NR_sendto, cu2, "x", 1, 0, &nobody2, sizeof nobody2), 1, "sendto its own peer");
        expect(sys(NR_recvfrom, cu2, buf, 8, MSG_DONTWAIT, 0, 0), -ECONNREFUSED, "is told nobody's there too");
        // Failing to connect changes nothing.
        struct in6 wrong_family = { AF_INET6, be(9), 0, { 0 }, 0 };
        expect(sys(NR_connect, cu2, &wrong_family, sizeof wrong_family), -97 /* EAFNOSUPPORT */, "a failed connect");
        mlen = sizeof me;
        check(sys(NR_getpeername, cu2, &me, &mlen) == 0 && me.port == be(41018), "leaves the peer it had");
        sys(NR_close, cu2);
    }

    // Lots of nothing can't fill the world: each datagram costs something on a queue.
    {
        int deaf = (int)sys(NR_socket, AF_INET, SOCK_DGRAM, 0), noisy = (int)sys(NR_socket, AF_INET, SOCK_DGRAM, 0);
        struct in4 deaf_at = v4(127, 0, 0, 1, 41016);
        sys(NR_bind, deaf, &deaf_at, sizeof deaf_at);
        for (int i = 0; i < 4000; i++) sys(NR_sendto, noisy, "", 0, 0, &deaf_at, sizeof deaf_at);
        int count = 0;
        while (sys(NR_recvfrom, deaf, buf, 8, MSG_DONTWAIT, 0, 0) == 0) count++;
        check(count > 100 && count < 4000, "empty datagrams still fill a queue, and some were dropped");
        int big_rcv = 2000, small = (int)sys(NR_socket, AF_INET, SOCK_DGRAM, 0);
        struct in4 small_at = v4(127, 0, 0, 1, 41017);
        sys(NR_bind, small, &small_at, sizeof small_at);
        sys(NR_setsockopt, small, SOL_SOCKET, 8 /* SO_RCVBUF */, &big_rcv, 4);
        expect(sys(NR_sendto, noisy, big, 30000, 0, &small_at, sizeof small_at), 30000, "a datagram bigger than the buffer");
        expect(sys(NR_recvfrom, small, big, 30000, MSG_DONTWAIT, 0, 0), 30000, "still arrives on an empty queue");
        sys(NR_close, deaf);
        sys(NR_close, noisy);
        sys(NR_close, small);
    }

    // A connected socket hears only its peer, and isn't found by others.
    int picky = (int)sys(NR_socket, AF_INET, SOCK_DGRAM, 0);
    struct in4 up = v4(127, 0, 0, 1, 41012);
    sys(NR_bind, picky, &up, sizeof up);
    sys(NR_connect, picky, &ua, sizeof ua);
    int third = (int)sys(NR_socket, AF_INET, SOCK_DGRAM, 0);
    sys(NR_sendto, third, "no", 2, 0, &up, sizeof up);
    expect(sys(NR_recvfrom, picky, buf, 8, MSG_DONTWAIT, 0, 0), -EAGAIN, "a connected socket doesn't hear strangers");
    sys(NR_sendto, a, "yes", 3, 0, &up, sizeof up);
    expect(sys(NR_recvfrom, picky, buf, 8, MSG_DONTWAIT, 0, 0), 3, "only its peer");
    sys(NR_close, picky);
    sys(NR_close, third);

    // ---- many at once
    {
        char d1[8] = "first", d2[8] = "second";
        struct iovec i1 = { d1, 5 }, i2 = { d2, 6 };
        struct mmsghdr out[2];
        memset(out, 0, sizeof out);
        out[0].hdr.name = &ua; out[0].hdr.namelen = sizeof ua; out[0].hdr.iov = &i1; out[0].hdr.iovlen = 1;
        out[1].hdr.name = &ua; out[1].hdr.namelen = sizeof ua; out[1].hdr.iov = &i2; out[1].hdr.iovlen = 1;
        expect(sys(NR_sendmmsg, b, out, 2, 0), 2, "sendmmsg: two");
        check(out[0].len == 5 && out[1].len == 6, "each with its length");

        char r1[8], r2[8], r3[8];
        struct iovec o1 = { r1, 8 }, o2 = { r2, 8 }, o3 = { r3, 8 };
        struct in4 n1, n2, n3;
        struct mmsghdr in[3];
        memset(in, 0, sizeof in);
        in[0].hdr.name = &n1; in[0].hdr.namelen = sizeof n1; in[0].hdr.iov = &o1; in[0].hdr.iovlen = 1;
        in[1].hdr.name = &n2; in[1].hdr.namelen = sizeof n2; in[1].hdr.iov = &o2; in[1].hdr.iovlen = 1;
        in[2].hdr.name = &n3; in[2].hdr.namelen = sizeof n3; in[2].hdr.iov = &o3; in[2].hdr.iovlen = 1;
        expect(sys(NR_recvmmsg, a, in, 3, MSG_WAITFORONE, 0), 2, "recvmmsg: what's there, without waiting for the third");
        check(in[0].len == 5 && same(r1, "first", 5) && in[1].len == 6 && same(r2, "second", 6), "in order and whole");
        check(in[0].hdr.namelen == 16 && n1.port != 0, "with their sources");
        expect(sys(NR_recvmmsg, a, in, 3, MSG_DONTWAIT, 0), -EAGAIN, "nothing there: EAGAIN");
    }

    // ---- control messages
    {
        int ttl = 1;
        expect(sys(NR_setsockopt, a, SOL_IP, IP_RECVTTL, &ttl, 4), 0, "IP_RECVTTL");
        expect(sys(NR_setsockopt, a, SOL_IP, IP_PKTINFO, &ttl, 4), 0, "IP_PKTINFO");
        expect(sys(NR_setsockopt, a, SOL_SOCKET, SO_TIMESTAMP, &ttl, 4), 0, "SO_TIMESTAMP");
        sys(NR_sendto, b, "ctl", 3, 0, &ua, sizeof ua);
        char data[8];
        u64 control[32];
        struct iovec io = { data, 8 };
        struct msghdr m = { 0, 0, &io, 1, control, sizeof control, 0 };
        expect(sys(NR_recvmsg, a, &m, 0), 3, "recvmsg");
        int seen_ttl = 0, seen_info = 0, seen_time = 0;
        u64 off = 0;
        while (off + 16 <= m.controllen) {
            struct cmsg *cm = (struct cmsg *)((char *)control + off);
            if (cm->level == SOL_IP && cm->type == IP_TTL && cm->len == 20 && *(int *)cm->data > 0) seen_ttl = 1;
            if (cm->level == SOL_IP && cm->type == IP_PKTINFO && cm->len == 28 && same(cm->data + 8, lo, 4)) seen_info = 1;
            if (cm->level == SOL_SOCKET && cm->type == SO_TIMESTAMP && cm->len == 32 && *(i64 *)cm->data > 0) seen_time = 1;
            off += (cm->len + 7) & ~7ul;
        }
        check(seen_ttl, "the TTL");
        check(seen_info, "the address it came to");
        check(seen_time, "the time");
        sys(NR_sendto, b, "ctl", 3, 0, &ua, sizeof ua);
        struct msghdr small = { 0, 0, &io, 1, control, 16, 0 };
        expect(sys(NR_recvmsg, a, &small, 0), 3, "with no room for them");
        check(small.flags & MSG_CTRUNC, "MSG_CTRUNC");
        expect(small.controllen, 16, "with what room there was: a header");

        // Exactly enough for the one asked for: no complaint, padding or no padding.
        int offs = 0;
        sys(NR_setsockopt, a, SOL_IP, IP_PKTINFO, &offs, 4);
        sys(NR_setsockopt, a, SOL_SOCKET, SO_TIMESTAMP, &offs, 4);
        sys(NR_sendto, b, "ctl", 3, 0, &ua, sizeof ua);
        struct msghdr exact = { 0, 0, &io, 1, control, 20, 0 };
        expect(sys(NR_recvmsg, a, &exact, 0), 3, "room for a TTL and no padding");
        check(!(exact.flags & MSG_CTRUNC), "that's enough");
        expect(exact.controllen, 20, "and it says how much");
        sys(NR_sendto, b, "ctl", 3, 0, &ua, sizeof ua);
        struct msghdr cut = { 0, 0, &io, 1, control, 17, 0 };
        expect(sys(NR_recvmsg, a, &cut, 0), 3, "room for only part of it");
        check(cut.flags & MSG_CTRUNC, "says so");
        expect(((struct cmsg *)control)->len, 17, "and its length is what's there");
    }
    sys(NR_close, a);
    sys(NR_close, b);

    puts_(failures ? "SOME CHECKS FAILED\n" : "all checks passed\n");
    return failures;
}

void __attribute__((noreturn)) cstart(void) {
    sys(NR_exit_group, cmain());
    __builtin_unreachable();
}

__asm__(".global _start\n_start:\n bl cstart\n");

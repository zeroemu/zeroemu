// Freestanding arm64 test of sockets with a network behind them: the name server, and
// TCP to servers on the host through 10.0.2.2. Run by scripts/test-tcp.py with
// DROIDRT_NET=1, which starts the servers and passes their ports:
//   tcp echo silent closes resets refused sink pieces adb-server half-resets udp-echo

typedef unsigned long u64;
typedef long i64;
typedef unsigned int u32;
typedef unsigned short u16;
typedef unsigned char u8;

#define NR_ioctl 29
#define NR_close 57
#define NR_read 63
#define NR_write 64
#define NR_epoll_create1 20
#define NR_epoll_ctl 21
#define NR_epoll_pwait 22
#define NR_ppoll 73
#define NR_exit_group 94
#define NR_setitimer 103
#define NR_rt_sigaction 134
#define NR_socket 198
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
#define NR_recvmmsg 243
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
// As check, saying what it got when that wasn't it.
static void expect(i64 got, i64 want, const char *name) {
    check(got == want, name);
    if (got != want) { puts_("     got "); putn(got); puts_(", wanted "); putn(want); puts_("\n"); }
}

#define EINTR 4
#define EAGAIN 11
#define EACCES 13
#define EPIPE 32
#define EAFNOSUPPORT 97
#define ENETUNREACH 101
#define ECONNRESET 104
#define EISCONN 106
#define ENOTCONN 107
#define ETIMEDOUT 110
#define ECONNREFUSED 111
#define EHOSTUNREACH 113
#define EALREADY 114
#define EINPROGRESS 115
#define ECONNABORTED 103

#define AF_INET 2
#define AF_INET6 10
#define SOCK_STREAM 1
#define SOCK_DGRAM 2
#define SOCK_NONBLOCK 04000
#define SOL_SOCKET 1
#define SOL_TCP 6
#define SO_ERROR 4
#define SO_LINGER 13
#define SO_RCVTIMEO 20
#define SO_SNDTIMEO 21
#define TCP_NODELAY 1
#define TCP_INFO 11
#define MSG_PEEK 2
#define MSG_TRUNC 0x20
#define MSG_DONTWAIT 0x40
#define MSG_WAITALL 0x100
#define MSG_NOSIGNAL 0x4000
#define POLLIN 1
#define POLLOUT 4
#define POLLERR 8
#define POLLHUP 0x10
#define POLLRDHUP 0x2000
#define SIOCSIFADDR 0x8916
#define FIONREAD 0x541b
#define SIOCOUTQ 0x5411
#define SIGALRM 14
#define SIGPIPE 13

struct in4 { u16 family; u16 port; u8 addr[4]; u8 pad[8]; };
struct in6 { u16 family; u16 port; u32 flow; u8 addr[16]; u32 scope; };
struct pollfd { int fd; short events, revents; };
struct iovec { void *base; u64 len; };
struct msghdr { void *name; u32 namelen; struct iovec *iov; u64 iovlen; void *control; u64 controllen; u32 flags; };
struct sigaction_k { void *handler; u64 flags; void *restorer; u64 mask; };
struct itimerval { i64 interval_s, interval_us, value_s, value_us; };

static u16 be(u16 v) { return (u16)(v << 8 | v >> 8); }
static struct in4 v4(u8 a, u8 b, u8 c, u8 d, u16 port) { struct in4 s = { AF_INET, be(port), { a, b, c, d }, { 0 } }; return s; }
static struct in4 host(u16 port) { return v4(10, 0, 2, 2, port); }
static int sock_error(int fd) {
    int v = -1, len = 4;
    sys(NR_getsockopt, fd, SOL_SOCKET, SO_ERROR, &v, &len);
    return v;
}
static int wait_for(int fd, int events, i64 ms) {
    struct pollfd p = { fd, (short)events, 0 };
    struct { i64 s, ns; } t = { ms / 1000, (ms % 1000) * 1000000 };
    i64 r = sys(NR_ppoll, &p, 1, &t, 0, 8);
    return r < 0 ? (int)r : p.revents;
}
static int connected(u16 port) {
    int fd = (int)sys(NR_socket, AF_INET, SOCK_STREAM, 0);
    struct in4 to = host(port);
    i64 r = sys(NR_connect, fd, &to, sizeof to);
    if (r != 0) { puts_("     could not connect: "); putn(r); puts_("\n"); }
    return fd;
}

static volatile int alarmed, piped;
static void on_alarm(int sig) { (void)sig; alarmed = 1; }
static void on_pipe(int sig) { (void)sig; piped++; }
static void alarm_soon(void) {
    struct sigaction_k act = { (void *)on_alarm, 0, 0, 0 };
    sys(NR_rt_sigaction, SIGALRM, &act, 0, 8);
    struct itimerval it = { 0, 0, 0, 50000 };
    alarmed = 0;
    sys(NR_setitimer, 0, &it, 0);
}

// A DNS query for a name of one or two labels, in `out`. Its length.
static u64 query(u8 *out, u16 id, const char *name, u16 qtype) {
    u8 *p = out;
    *p++ = (u8)(id >> 8); *p++ = (u8)id; *p++ = 1; *p++ = 0;
    *p++ = 0; *p++ = 1; *p++ = 0; *p++ = 0; *p++ = 0; *p++ = 0; *p++ = 0; *p++ = 1;
    const char *s = name;
    for (;;) {
        u64 n = 0;
        while (s[n] && s[n] != '.') n++;
        *p++ = (u8)n;
        memcpy(p, s, n);
        p += n;
        if (!s[n]) break;
        s += n + 1;
    }
    *p++ = 0; *p++ = (u8)(qtype >> 8); *p++ = (u8)qtype; *p++ = 0; *p++ = 1;
    // an OPT record, as netd adds
    const u8 opt[] = { 0, 0, 41, 2, 0, 0, 0, 0, 0, 0, 0 };
    memcpy(p, opt, sizeof opt);
    return (u64)(p - out) + sizeof opt;
}

static u8 big[1 << 20];
static u8 back[1 << 20];
#define TEN_MB (10 << 20)

static u8 pattern(u64 at) { return (u8)((at * 2654435761u) >> 24); }

// Sends 10 MB and reads them back at once, with poll, as a real program does.
static void through_echo(u16 port) {
    int fd = (int)sys(NR_socket, AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    struct in4 to = host(port);
    sys(NR_connect, fd, &to, sizeof to);
    wait_for(fd, POLLOUT, 5000);
    u64 sent = 0, got = 0;
    int bad = 0, shut = 0, again = 0;
    while (got < TEN_MB) {
        int ev = POLLIN | (sent < TEN_MB ? POLLOUT : 0);
        int r = wait_for(fd, ev, 20000);
        if (r <= 0) { puts_("     timed out\n"); bad = 1; break; }
        if ((r & POLLOUT) && sent < TEN_MB) {
            u64 n = TEN_MB - sent;
            if (n > sizeof big) n = sizeof big;
            for (u64 i = 0; i < n; i++) big[i] = pattern(sent + i);
            i64 w = sys(NR_sendto, fd, big, n, 0, 0, 0);
            if (w > 0) sent += (u64)w;
            else if (w == -EAGAIN) again++;
            else { puts_("     send: "); putn(w); puts_("\n"); bad = 1; break; }
            if (sent == TEN_MB && !shut) { sys(NR_shutdown, fd, 1); shut = 1; }
        }
        if (r & POLLIN) {
            i64 n = sys(NR_recvfrom, fd, back, sizeof back, 0, 0, 0);
            if (n <= 0) { puts_("     recv: "); putn(n); puts_("\n"); bad = 1; break; }
            for (i64 i = 0; i < n; i++) if (back[i] != pattern(got + (u64)i)) bad = 1;
            got += (u64)n;
        }
    }
    check(!bad && got == TEN_MB, "10 MB each way at once, every byte right");
    check(sys(NR_recvfrom, fd, back, 16, MSG_DONTWAIT, 0, 0) == 0 || wait_for(fd, POLLIN, 5000) >= 0, "half-closed, and the echo closed after");
    check(sys(NR_recvfrom, fd, back, 16, 0, 0, 0) == 0, "the end of the stream");
    sys(NR_close, fd);
}

int cmain(int argc, char **argv) {
    u16 ports[11];
    if (argc < 12) { puts_("usage: tcp echo silent closes resets refused sink pieces adb-server half-resets udp-echo udp-echo2\n"); return 1; }
    for (int i = 0; i < 11; i++) {
        u32 v = 0;
        for (char *c = argv[i + 1]; *c; c++) v = v * 10 + (u32)(*c - '0');
        ports[i] = (u16)v;
    }
    u16 echo = ports[0], silent = ports[1], closes = ports[2], resets = ports[3], refused = ports[4], sink = ports[5], pieces = ports[6], adb_server = ports[7], half_resets = ports[8], udp_echo = ports[9], udp_echo2 = ports[10];
    char buf[256];
    u8 hip_of_udp[4] = { 10, 0, 2, 2 };
    i64 r = 0;
    struct in4 test_net = v4(192, 0, 2, 1, 80);

    // ---- what the resolver does, once there's an address
    int sf = (int)sys(NR_socket, AF_INET, SOCK_DGRAM, 0);
    struct in4 far = v4(8, 8, 8, 8, 0);
    expect(sys(NR_connect, sf, &far, sizeof far), -ENETUNREACH, "before there's an address: ENETUNREACH");
    struct { char name[16]; struct in4 addr; u8 pad[8]; } ifr;
    memset(&ifr, 0, sizeof ifr);
    memcpy(ifr.name, "eth1", 5);
    ifr.addr = v4(10, 0, 2, 15, 0);
    expect(sys(NR_ioctl, sf, SIOCSIFADDR, &ifr), 0, "eth1 gets its address");
    expect(sys(NR_connect, sf, &far, sizeof far), 0, "8.8.8.8 port 0 connects now: nothing goes out");
    struct in4 me;
    int len = sizeof me;
    u8 ip[4] = { 10, 0, 2, 15 };
    check(sys(NR_getsockname, sf, &me, &len) == 0 && same(me.addr, ip, 4) && me.port != 0, "from 10.0.2.15, and a port");
    struct in6 g6 = { AF_INET6, be(53), 0, { 0x20 }, 0 };
    int s6 = (int)sys(NR_socket, AF_INET6, SOCK_DGRAM, 0);
    expect(sys(NR_connect, s6, &g6, sizeof g6), -ENETUNREACH, "2000:: stays unreachable: no IPv6, so no AAAA lookups");
    struct in4 neighbour = v4(10, 0, 2, 9, 80);
    int sn = (int)sys(NR_socket, AF_INET, SOCK_STREAM, 0);
    expect(sys(NR_connect, sn, &neighbour, sizeof neighbour), -EHOSTUNREACH, "a neighbour nobody answers for: EHOSTUNREACH");

    // ---- the name server
    int dns = (int)sys(NR_socket, AF_INET, SOCK_DGRAM, 0);
    struct in4 server = v4(10, 0, 2, 3, 53);
    expect(sys(NR_connect, dns, &server, sizeof server), 0, "connect to the name server");
    u8 q[300], a[600];
    u64 n = query(q, 0x1234, "LocalHost", 1);
    expect(sys(NR_write, dns, q, n), (i64)n, "ask it");
    check(wait_for(dns, POLLIN, 5000) & POLLIN, "poll sees the answer");
    struct in4 from;
    len = sizeof from;
    r = sys(NR_recvfrom, dns, a, sizeof a, 0, &from, &len);
    u8 sip[4] = { 10, 0, 2, 3 };
    check(r > 12 && len == 16 && same(from.addr, sip, 4) && from.port == be(53), "the answer comes from exactly 10.0.2.3:53");
    check(a[0] == 0x12 && a[1] == 0x34 && (a[2] & 0x80), "with the ID");
    check(same(a + 12, q + 12, n - 12 - 11), "the question, its case as asked");
    check((a[3] & 15) == 0 && a[6] == 0 && a[7] == 1 && same(a + r - 4, "\x7f\0\0\1", 4), "localhost is 127.0.0.1");

    n = query(q, 0x1235, "localhost", 28);
    sys(NR_write, dns, q, n);
    wait_for(dns, POLLIN, 5000);
    r = sys(NR_read, dns, a, sizeof a);
    check(r > 12 && a[1] == 0x35 && (a[3] & 15) == 0 && a[7] == 0, "AAAA: no error, no answers");

    n = query(q, 0x1236, "nothing-here-at-all.invalid", 1);
    sys(NR_write, dns, q, n);
    check(wait_for(dns, POLLIN, 20000) & POLLIN, "a name that isn't: an answer anyway");
    r = sys(NR_read, dns, a, sizeof a);
    check(r > 12 && a[1] == 0x36 && (a[3] & 15) == 2, "SERVFAIL");
    expect(sys(NR_recvfrom, dns, a, sizeof a, MSG_DONTWAIT, 0, 0), -EAGAIN, "and nothing more");

    int dns2 = (int)sys(NR_socket, AF_INET, SOCK_DGRAM, 0);
    n = query(q, 0x1237, "localhost", 1);
    expect(sys(NR_sendto, dns2, q, n, 0, &server, sizeof server), (i64)n, "unconnected too");
    wait_for(dns2, POLLIN, 5000);
    u8 tiny[8];
    struct iovec iv = { tiny, sizeof tiny };
    struct in4 mfrom;
    struct msghdr m = { &mfrom, sizeof mfrom, &iv, 1, 0, 0, 0 };
    r = sys(NR_recvmsg, dns2, &m, MSG_PEEK);
    check(r == 8 && (m.flags & MSG_TRUNC) && m.namelen == 16 && mfrom.port == be(53), "recvmsg: cut short and saying so, with the source");
    r = sys(NR_recvfrom, dns2, a, 8, MSG_TRUNC, 0, 0);
    check(r > 12, "MSG_TRUNC gives a datagram's real size");
    expect(sys(NR_recvfrom, dns2, a, sizeof a, MSG_DONTWAIT, 0, 0), -EAGAIN, "and it was gone after that");

    int closed = (int)sys(NR_socket, AF_INET, SOCK_DGRAM, 0);
    struct in4 other_port = v4(10, 0, 2, 3, 54);
    sys(NR_connect, closed, &other_port, sizeof other_port);
    expect(sys(NR_write, closed, "x", 1), 1, "connected to a port nothing's on: the send goes");
    check(wait_for(closed, POLLERR, 100) & POLLERR, "poll shows an error");
    expect(sys(NR_recvfrom, closed, a, 8, 0, 0, 0), -ECONNREFUSED, "and the next call gets ECONNREFUSED");
    expect(sys(NR_write, closed, "x", 1), 1, "once");
    expect(sys(NR_write, closed, "x", 1), -ECONNREFUSED, "the one after, on a send too");

    // ---- datagrams to the host and back
    {
        struct in4 echo_to = host(udp_echo), echo_from;
        int u = (int)sys(NR_socket, AF_INET, SOCK_DGRAM, 0);
        expect(sys(NR_sendto, u, "marco", 5, 0, &echo_to, sizeof echo_to), 5, "a datagram to the host");
        check(wait_for(u, POLLIN, 5000) & POLLIN, "the echo arrives");
        int alen = sizeof echo_from;
        expect(sys(NR_recvfrom, u, buf, 16, 0, &echo_from, &alen), 5, "whole");
        check(same(buf, "marco", 5), "right");
        check(alen == 16 && same(echo_from.addr, hip_of_udp, 4) && echo_from.port == be(udp_echo), "from 10.0.2.2, not the host's own view");
        sys(NR_sendto, u, "one", 3, 0, &echo_to, sizeof echo_to);
        wait_for(u, POLLIN, 5000);
        sys(NR_sendto, u, "three", 5, 0, &echo_to, sizeof echo_to);
        expect(sys(NR_recvfrom, u, buf, 16, 0, 0, 0), 3, "datagrams stay separate");
        wait_for(u, POLLIN, 5000);
        expect(sys(NR_recvfrom, u, buf, 16, 0, 0, 0), 5, "the second");
        sys(NR_sendto, u, "a long one", 10, 0, &echo_to, sizeof echo_to);
        wait_for(u, POLLIN, 5000);
        expect(sys(NR_recvfrom, u, buf, 2, MSG_TRUNC, 0, 0), 10, "MSG_TRUNC: the real length of what was cut");

        // sendmmsg and recvmmsg, as Chromium's QUIC uses
        char first[8] = "first", second[8] = "second", r1[8], r2[8];
        struct iovec i1 = { first, 5 }, i2 = { second, 6 }, o1 = { r1, 8 }, o2 = { r2, 8 };
        struct mmsghdr { struct msghdr hdr; u32 len; } out[2], in[2];
        memset(out, 0, sizeof out);
        memset(in, 0, sizeof in);
        out[0].hdr.name = &echo_to; out[0].hdr.namelen = sizeof echo_to; out[0].hdr.iov = &i1; out[0].hdr.iovlen = 1;
        out[1].hdr.name = &echo_to; out[1].hdr.namelen = sizeof echo_to; out[1].hdr.iov = &i2; out[1].hdr.iovlen = 1;
        expect(sys(NR_sendmmsg, u, out, 2, 0), 2, "sendmmsg to the host");
        in[0].hdr.iov = &o1; in[0].hdr.iovlen = 1;
        in[1].hdr.iov = &o2; in[1].hdr.iovlen = 1;
        i64 got_m = 0;
        for (int i = 0; i < 50 && got_m < 2; i++) {
            wait_for(u, POLLIN, 100);
            i64 m = sys(NR_recvmmsg, u, (char *)in + got_m * (i64)sizeof in[0], 2 - got_m, MSG_DONTWAIT, 0);
            if (m > 0) got_m += m;
        }
        expect(got_m, 2, "recvmmsg: both echoes");
        check(in[0].len == 5 && same(r1, "first", 5) && in[1].len == 6 && same(r2, "second", 6), "in order and whole");
        sys(NR_close, u);

        // Naming an address on a connected socket: it goes, and only its peer is heard.
        {
            struct in4 to_echo = host(udp_echo), elsewhere = host(udp_echo2);
            int nu = (int)sys(NR_socket, AF_INET, SOCK_DGRAM, 0);
            expect(sys(NR_connect, nu, &to_echo, sizeof to_echo), 0, "connect");
            expect(sys(NR_write, nu, "one", 3), 3, "write, which connects the host socket");
            wait_for(nu, POLLIN, 5000);
            expect(sys(NR_read, nu, buf, 16), 3, "the echo");
            expect(sys(NR_sendto, nu, "two", 3, 0, &to_echo, sizeof to_echo), 3, "sendto naming the peer works");
            wait_for(nu, POLLIN, 5000);
            expect(sys(NR_read, nu, buf, 16), 3, "and it's heard");
            expect(sys(NR_sendto, nu, "off", 3, 0, &elsewhere, sizeof elsewhere), 3, "sendto naming someone else goes too");
            expect(wait_for(nu, POLLIN, 200), 0, "and their answer isn't for a socket connected elsewhere");
            sys(NR_close, nu);

            // The port the world sees doesn't change when a socket connects.
            struct in4 seen1, seen2;
            int pu = (int)sys(NR_socket, AF_INET, SOCK_DGRAM, 0);
            sys(NR_sendto, pu, "port", 4, 0, &to_echo, sizeof to_echo);
            wait_for(pu, POLLIN, 5000);
            sys(NR_read, pu, buf, 16);
            int plen = sizeof seen1;
            sys(NR_getsockname, pu, &seen1, &plen);
            expect(sys(NR_connect, pu, &to_echo, sizeof to_echo), 0, "connect after sending");
            sys(NR_write, pu, "again", 5);
            check(wait_for(pu, POLLIN, 5000) & POLLIN, "an answer through the same socket");
            expect(sys(NR_read, pu, buf, 16), 5, "right");
            plen = sizeof seen2;
            sys(NR_getsockname, pu, &seen2, &plen);
            check(seen1.port == seen2.port, "with the same port");
            // A reply on its way when it connects still arrives.
            sys(NR_sendto, pu, "late", 4, 0, &to_echo, sizeof to_echo);
            expect(sys(NR_connect, pu, &to_echo, sizeof to_echo), 0, "connect while an answer's on its way");
            check(wait_for(pu, POLLIN, 5000) & POLLIN, "it still comes");
            sys(NR_close, pu);
        }

        // Connected: the host hears a closed port, and the next call hears of it.
        int cu = (int)sys(NR_socket, AF_INET, SOCK_DGRAM, 0);
        expect(sys(NR_connect, cu, &echo_to, sizeof echo_to), 0, "connect to the host's echo");
        expect(sys(NR_write, cu, "polo", 4), 4, "write");
        wait_for(cu, POLLIN, 5000);
        expect(sys(NR_read, cu, buf, 16), 4, "read");
        check(same(buf, "polo", 4), "right");
        struct in4 closed_to = host(refused);
        expect(sys(NR_connect, cu, &closed_to, sizeof closed_to), 0, "reconnect, to a port nobody's on");
        expect(sys(NR_write, cu, "x", 1), 1, "the send goes");
        check(wait_for(cu, POLLERR | POLLIN, 5000) & POLLERR, "poll shows an error when the host hears of it");
        expect(sys(NR_recvfrom, cu, buf, 8, MSG_DONTWAIT, 0, 0), -ECONNREFUSED, "ECONNREFUSED");
        struct { u16 family; u8 pad[14]; } unspec_u = { 0, { 0 } };
        expect(sys(NR_connect, cu, &unspec_u, sizeof unspec_u), 0, "AF_UNSPEC");
        expect(sys(NR_sendto, cu, "back", 4, 0, &echo_to, sizeof echo_to), 4, "and it can send anywhere again");
        wait_for(cu, POLLIN, 5000);
        expect(sys(NR_recvfrom, cu, buf, 16, 0, 0, 0), 4, "and hear back");
        sys(NR_close, cu);

        // Too big for this host to send, if it's that kind of host; never a crash.
        int bigu = (int)sys(NR_socket, AF_INET, SOCK_DGRAM, 0);
        r = sys(NR_sendto, bigu, big, 65000, 0, &echo_to, sizeof echo_to);
        check(r == 65000 || r == -90 /* EMSGSIZE */, "a very large datagram goes, or is refused as too large");
        expect(sys(NR_sendto, bigu, big, 65600, 0, &echo_to, sizeof echo_to), -90, "past the limit: EMSGSIZE");
        sys(NR_close, bigu);
    }

    // ---- connecting, non-blocking, as IoBridge does
    int fd = (int)sys(NR_socket, AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    struct in4 to = host(echo);
    i64 first = sys(NR_connect, fd, &to, sizeof to);
    expect(first, -EINPROGRESS, "a non-blocking connect: EINPROGRESS");
    check((wait_for(fd, POLLOUT | POLLIN, 5000) & POLLOUT) != 0, "poll: writable when it's up");
    expect(sock_error(fd), 0, "SO_ERROR: none");
    expect(sys(NR_connect, fd, &to, sizeof to), 0, "connect again: 0");
    expect(sys(NR_connect, fd, &to, sizeof to), -EISCONN, "and then EISCONN");
    struct in4 peer;
    len = sizeof peer;
    u8 hip[4] = { 10, 0, 2, 2 };
    check(sys(NR_getpeername, fd, &peer, &len) == 0 && same(peer.addr, hip, 4) && peer.port == be(echo), "its peer is 10.0.2.2, never the host's own view");
    len = sizeof me;
    check(sys(NR_getsockname, fd, &me, &len) == 0 && same(me.addr, ip, 4) && me.port != 0, "and it's 10.0.2.15");
    expect(sys(NR_recvfrom, fd, buf, 16, 0, 0, 0), -EAGAIN, "nothing to read: EAGAIN");
    expect(sys(NR_write, fd, "ping", 4), 4, "write");
    check(wait_for(fd, POLLIN, 5000) & POLLIN, "poll: readable when the echo comes");
    int avail = 0;
    expect(sys(NR_ioctl, fd, FIONREAD, &avail), 0, "FIONREAD");
    expect(avail, 4, "says how much");
    expect(sys(NR_recvfrom, fd, buf, 16, MSG_PEEK, 0, 0), 4, "MSG_PEEK");
    expect(sys(NR_recvfrom, fd, buf + 4, 16, MSG_PEEK | MSG_DONTWAIT, 0, 0), 4, "still there");
    expect(sys(NR_read, fd, buf + 8, 16), 4, "read");
    check(same(buf, "ping", 4) && same(buf + 4, "ping", 4) && same(buf + 8, "ping", 4), "the right bytes each time");
    int opt = 1;
    expect(sys(NR_setsockopt, fd, SOL_TCP, TCP_NODELAY, &opt, 4), 0, "TCP_NODELAY on a live connection");
    u8 info[232];
    len = sizeof info;
    check(sys(NR_getsockopt, fd, SOL_TCP, TCP_INFO, info, &len) == 0 && info[0] == 1, "TCP_INFO: established");

    // Scattered, both ways.
    struct iovec out[2] = { { "scat", 4 }, { "ter!", 4 } };
    struct msghdr ms = { 0, 0, out, 2, 0, 0, 0 };
    expect(sys(NR_sendmsg, fd, &ms, 0), 8, "sendmsg, two pieces");
    wait_for(fd, POLLIN, 5000);
    char a1[3], a2[5];
    struct iovec in[2] = { { a1, 3 }, { a2, 5 } };
    struct msghdr mr = { buf, 32, in, 2, 0, 16, 77 };
    expect(sys(NR_recvmsg, fd, &mr, MSG_WAITALL), 8, "recvmsg, two pieces");
    check(same(a1, "sca", 3) && same(a2, "tter!", 5) && mr.flags == 0 && mr.namelen == 0 && mr.controllen == 0, "right, with no name, control or flags left over");
    sys(NR_close, fd);

    // A shared blocking connect.
    fd = (int)sys(NR_socket, AF_INET, SOCK_STREAM, 0);
    expect(sys(NR_connect, fd, &to, sizeof to), 0, "a blocking connect");
    sys(NR_close, fd);

    // ---- refused
    fd = (int)sys(NR_socket, AF_INET, SOCK_STREAM, 0);
    to = host(refused);
    expect(sys(NR_connect, fd, &to, sizeof to), -ECONNREFUSED, "blocking, refused: ECONNREFUSED");
    expect(sock_error(fd), 0, "the error isn't left over");
    len = sizeof peer;
    expect(sys(NR_getpeername, fd, &peer, &len), -ENOTCONN, "no peer");
    to = host(echo);
    expect(sys(NR_connect, fd, &to, sizeof to), 0, "the socket can try again, somewhere else");
    sys(NR_close, fd);

    fd = (int)sys(NR_socket, AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    to = host(refused);
    r = sys(NR_connect, fd, &to, sizeof to);
    expect(r, -EINPROGRESS, "non-blocking, refused: EINPROGRESS first");
    int rev = wait_for(fd, POLLOUT | POLLIN, 5000);
    check((rev & (POLLERR | POLLHUP)) == (POLLERR | POLLHUP), "poll: an error, and hung up");
    expect(sock_error(fd), ECONNREFUSED, "SO_ERROR: ECONNREFUSED");
    expect(sock_error(fd), 0, "reading it clears it");
    expect(sys(NR_connect, fd, &to, sizeof to), -ECONNABORTED, "connect, with nothing left to report: ECONNABORTED");
    sys(NR_close, fd);

    fd = (int)sys(NR_socket, AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    sys(NR_connect, fd, &to, sizeof to);
    wait_for(fd, POLLOUT, 5000);
    expect(sys(NR_connect, fd, &to, sizeof to), -ECONNREFUSED, "or connect again and it reports it");
    sys(NR_close, fd);

    // ---- the usual adb server port, whatever this process was told
    fd = (int)sys(NR_socket, AF_INET, SOCK_STREAM, 0);
    to = host(5037);
    expect(sys(NR_connect, fd, &to, sizeof to), -ECONNREFUSED, "port 5037: refused without asking");
    sys(NR_close, fd);

    // ---- what apps mustn't get at
    fd = (int)sys(NR_socket, AF_INET, SOCK_STREAM, 0);
    to = host(adb_server);
    expect(sys(NR_connect, fd, &to, sizeof to), -ECONNREFUSED, "the adb server, though it's there: refused");
    sys(NR_close, fd);
    fd = (int)sys(NR_socket, AF_INET, SOCK_STREAM, 0);
    to = host(5555);
    expect(sys(NR_connect, fd, &to, sizeof to), -ECONNREFUSED, "a device's own port: refused");
    sys(NR_close, fd);
    fd = (int)sys(NR_socket, AF_INET, SOCK_STREAM, 0);
    struct in4 here = v4(10, 0, 2, 15, 1);
    expect(sys(NR_connect, fd, &here, sizeof here), -ECONNREFUSED, "its own address is itself, with nobody listening");
    sys(NR_close, fd);
    fd = (int)sys(NR_socket, AF_INET, SOCK_STREAM, 0);
    struct in4 refused_dns = v4(10, 0, 2, 3, 53);
    expect(sys(NR_connect, fd, &refused_dns, sizeof refused_dns), -ECONNREFUSED, "the name server over TCP: refused");
    sys(NR_close, fd);

    // ---- waiting, and being interrupted
    fd = connected(silent);
    struct { i64 s, us; } tv = { 0, 30000 };
    expect(sys(NR_setsockopt, fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv), 0, "SO_RCVTIMEO");
    expect(sys(NR_recvfrom, fd, buf, 16, 0, 0, 0), -EAGAIN, "a recv with a timeout: EAGAIN");
    struct { i64 s, us; } none = { 0, 0 };
    sys(NR_setsockopt, fd, SOL_SOCKET, SO_RCVTIMEO, &none, sizeof none);
    alarm_soon();
    expect(sys(NR_recvfrom, fd, buf, 16, 0, 0, 0), -EINTR, "a blocking recv ends on a signal");
    check(alarmed, "the signal, that is");
    expect(sys(NR_recvfrom, fd, buf, 16, MSG_DONTWAIT, 0, 0), -EAGAIN, "MSG_DONTWAIT");
    expect(wait_for(fd, POLLIN, 20), 0, "nothing to read: poll times out");
    check(wait_for(fd, POLLOUT, 20) & POLLOUT, "and it's writable");
    // Fill it: the server isn't reading, and every queue on the way has a limit.
    expect(sys(NR_setsockopt, fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv), 0, "SO_SNDTIMEO");
    i64 total = 0;
    for (int i = 0; i < 200; i++) {
        r = sys(NR_sendto, fd, big, sizeof big, 0, 0, 0);
        if (r <= 0) break;
        total += r;
    }
    check(total > 0 && r == -EAGAIN, "sending to someone not reading stops, with a timeout: EAGAIN");
    int outq = 0;
    check(sys(NR_ioctl, fd, SIOCOUTQ, &outq) == 0 && outq > 0, "SIOCOUTQ: there's some unsent");
    expect(wait_for(fd, POLLOUT, 20), 0, "and it's no longer writable");
    sys(NR_close, fd);

    // A connect nothing answers for, if the host's network has no opinion.
    fd = (int)sys(NR_socket, AF_INET, SOCK_STREAM, 0);
    alarm_soon();
    r = sys(NR_connect, fd, &test_net, sizeof test_net);
    check(r == -EINTR || r == -ENETUNREACH || r == -EHOSTUNREACH || r == -ETIMEDOUT || r == -EACCES, "a blocking connect ends on a signal, or the host says no");
    if (r == -EINTR) {
        struct { i64 s, us; } brief = { 0, 20000 };
        sys(NR_setsockopt, fd, SOL_SOCKET, SO_SNDTIMEO, &brief, sizeof brief);
        expect(sys(NR_connect, fd, &test_net, sizeof test_net), -EALREADY, "connect again, with a timeout: EALREADY, it's still going");
    }
    sys(NR_close, fd);

    // ---- the other side finishes
    fd = connected(closes);
    check(wait_for(fd, POLLIN, 5000) & POLLIN, "the server wrote, and closed");
    expect(sys(NR_read, fd, buf, 16), 3, "its bytes come first");
    check(same(buf, "bye", 3), "right ones");
    rev = wait_for(fd, POLLIN | POLLOUT | POLLRDHUP, 5000);
    check((rev & POLLRDHUP) && (rev & POLLOUT) && !(rev & POLLHUP), "at the end: RDHUP and writable, not HUP: this side can still send");
    expect(sys(NR_read, fd, buf, 16), 0, "then the end");
    expect(sys(NR_read, fd, buf, 16), 0, "and it stays that way");
    expect(sys(NR_shutdown, fd, 1), 0, "shut this side too");
    rev = wait_for(fd, POLLIN | POLLOUT, 5000);
    check(rev & POLLHUP, "now it's hung up");
    struct sigaction_k pipe_act = { (void *)on_pipe, 0, 0, 0 };
    sys(NR_rt_sigaction, SIGPIPE, &pipe_act, 0, 8);
    piped = 0;
    expect(sys(NR_sendto, fd, "x", 1, MSG_NOSIGNAL, 0, 0), -EPIPE, "send after shutdown: EPIPE");
    expect(piped, 0, "without a signal, as asked");
    expect(sys(NR_write, fd, "x", 1), -EPIPE, "write too");
    expect(piped, 1, "with one");
    sys(NR_close, fd);

    fd = connected(resets);
    rev = wait_for(fd, POLLIN, 5000);
    check(rev & (POLLIN | POLLHUP), "a reset wakes poll");
    r = sys(NR_recvfrom, fd, buf, 16, 0, 0, 0);
    expect(r, -ECONNRESET, "recv: ECONNRESET");
    expect(sys(NR_recvfrom, fd, buf, 16, 0, 0, 0), 0, "once, then the end");
    expect(sys(NR_sendto, fd, "x", 1, MSG_NOSIGNAL, 0, 0), -EPIPE, "send: EPIPE");
    len = sizeof peer;
    expect(sys(NR_getpeername, fd, &peer, &len), -ENOTCONN, "and it has no peer any more");
    sys(NR_close, fd);

    // ---- MSG_WAITALL across pieces
    fd = connected(pieces);
    expect(sys(NR_recvfrom, fd, big, 1500, MSG_PEEK | MSG_WAITALL, 0, 0), 1500, "MSG_PEEK with MSG_WAITALL waits for it all too");
    expect(sys(NR_recvfrom, fd, big, 2000, MSG_WAITALL, 0, 0), 2000, "MSG_WAITALL waits through two sends");
    expect(sys(NR_recvfrom, fd, big, 100, MSG_WAITALL, 0, 0), 0, "and returns what there is at the end");
    expect(sys(NR_recvfrom, fd, big, 100, MSG_PEEK | MSG_WAITALL, 0, 0), 0, "as does a peek");
    sys(NR_close, fd);

    // ---- an error isn't lost on a call that had something to return
    fd = connected(half_resets);
    expect(sys(NR_recvfrom, fd, big, 200, MSG_WAITALL, 0, 0), 100, "MSG_WAITALL: what arrived before the reset");
    expect(sys(NR_recvfrom, fd, big, 200, 0, 0, 0), -ECONNRESET, "and the next call hears of it");
    expect(sys(NR_recvfrom, fd, big, 200, 0, 0, 0), 0, "then the end");
    sys(NR_close, fd);

    // ---- both ways shut: hung up, though the peer's still there
    fd = connected(silent);
    expect(wait_for(fd, 0, 0), 0, "a live connection: no POLLHUP");
    sys(NR_shutdown, fd, 2);
    check(wait_for(fd, 0, 1000) & POLLHUP, "shutdown both ways: POLLHUP at once");
    sys(NR_close, fd);

    // ---- no bytes at all
    fd = connected(silent);
    expect(sys(NR_read, fd, big, 0), 0, "read of no bytes returns at once, with nothing to read");
    sys(NR_close, fd);

    // ---- urgent data doesn't exist here, but sendUrgentData mustn't fail
    fd = connected(echo);
    expect(sys(NR_sendto, fd, "ab", 2, 1 /* MSG_OOB */, 0, 0), 2, "MSG_OOB: both bytes taken");
    expect(sys(NR_recvfrom, fd, buf, 1, MSG_WAITALL, 0, 0), 1, "the first goes through");
    check(buf[0] == 'a', "the ordinary one");
    expect(wait_for(fd, POLLIN, 100), 0, "and the urgent one isn't mixed in with the rest");
    sys(NR_close, fd);

    // ---- changing its mind
    fd = connected(echo);
    struct { u16 family; u8 pad[14]; } unspec = { 0, { 0 } };
    expect(sys(NR_connect, fd, &unspec, sizeof unspec), 0, "connect(AF_UNSPEC) ends a connection");
    expect(sock_error(fd), ECONNRESET, "leaving ECONNRESET to find");
    len = sizeof peer;
    expect(sys(NR_getpeername, fd, &peer, &len), -ENOTCONN, "no peer");
    to = host(echo);
    expect(sys(NR_connect, fd, &to, sizeof to), 0, "the socket can connect again");
    expect(sys(NR_write, fd, "ok", 2), 2, "and works");
    expect(sys(NR_recvfrom, fd, buf, 2, MSG_WAITALL, 0, 0), 2, "both ways");
    sys(NR_close, fd);

    // A connect that's still going, if the host's network lets one be: shut down.
    fd = (int)sys(NR_socket, AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    r = sys(NR_connect, fd, &test_net, sizeof test_net);
    if (r == -EINPROGRESS && wait_for(fd, POLLOUT | POLLIN, 0) == 0) {
        expect(sys(NR_shutdown, fd, 2), 0, "shutdown of a connect in progress");
        check((wait_for(fd, POLLOUT, 0) & (POLLERR | POLLHUP)) == (POLLERR | POLLHUP), "poll says it's over, with an error");
        expect(sock_error(fd), ECONNRESET, "which is ECONNRESET");
        to = host(echo);
        expect(sys(NR_connect, fd, &to, sizeof to), -EINPROGRESS, "the socket can start again");
        check(wait_for(fd, POLLOUT, 5000) & POLLOUT, "and connect");
        expect(sock_error(fd), 0, "with nothing left over");
    }
    sys(NR_close, fd);

    // ---- edge-triggered: each arrival is news, even with some still unread
    {
        struct { u32 events; u32 pad; u64 data; } ev = { POLLIN | 1u << 31, 0, 5 }, out_ev[2];
        int ep = (int)sys(NR_epoll_create1, 0);
        fd = connected(echo);
        expect(sys(NR_epoll_ctl, ep, 1, fd, &ev), 0, "EPOLLET on a connection");
        expect(sys(NR_epoll_pwait, ep, out_ev, 2, 0, 0, 8), 0, "nothing yet");
        sys(NR_write, fd, "abcd", 4);
        expect(sys(NR_epoll_pwait, ep, out_ev, 2, 5000, 0, 8), 1, "the echo arrives: an edge");
        expect(sys(NR_recvfrom, fd, buf, 1, 0, 0, 0), 1, "take a little of it");
        expect(sys(NR_epoll_pwait, ep, out_ev, 2, 0, 0, 8), 0, "no news");
        sys(NR_write, fd, "efgh", 4);
        expect(sys(NR_epoll_pwait, ep, out_ev, 2, 5000, 0, 8), 1, "more arrives, on top of what's unread: another edge");
        sys(NR_close, fd);
        sys(NR_close, ep);
    }

    // ---- a closing socket's bytes still arrive: the script counts them
    fd = connected(sink);
    for (u64 i = 0; i < 1 << 20; i++) big[i] = pattern(i);
    u64 at = 0;
    while (at < 1 << 20) {
        r = sys(NR_write, fd, big + at, (1 << 20) - at);
        if (r <= 0) break;
        at += (u64)r;
    }
    expect((i64)at, 1 << 20, "1 MiB queued for the sink");
    sys(NR_close, fd);

    // ---- SO_LINGER at zero: no goodbye. Nothing should hang.
    fd = connected(silent);
    struct { int on, secs; } linger = { 1, 0 };
    expect(sys(NR_setsockopt, fd, SOL_SOCKET, SO_LINGER, &linger, sizeof linger), 0, "SO_LINGER {1, 0}");
    sys(NR_write, fd, "gone", 4);
    sys(NR_close, fd);

    // ---- AF_INET6, which every Java socket is
    fd = (int)sys(NR_socket, AF_INET6, SOCK_STREAM, 0);
    struct in6 mapped = { AF_INET6, be(echo), 0, { 0,0,0,0,0,0,0,0,0,0,0xff,0xff,10,0,2,2 }, 0 };
    expect(sys(NR_connect, fd, &mapped, sizeof mapped), 0, "a v4-mapped address on AF_INET6");
    struct in6 p6;
    len = sizeof p6;
    check(sys(NR_getpeername, fd, &p6, &len) == 0 && len == 28 && p6.family == AF_INET6 && same(p6.addr, mapped.addr, 16) && p6.port == be(echo), "the peer stays ::ffff:10.0.2.2");
    u8 m15[16] = { 0,0,0,0,0,0,0,0,0,0,0xff,0xff,10,0,2,15 };
    len = sizeof p6;
    check(sys(NR_getsockname, fd, &p6, &len) == 0 && same(p6.addr, m15, 16) && p6.port != 0, "and it's ::ffff:10.0.2.15");
    expect(sys(NR_write, fd, "six!", 4), 4, "write");
    expect(sys(NR_recvfrom, fd, buf, 4, MSG_WAITALL, 0, 0), 4, "and back");
    check(same(buf, "six!", 4), "right");
    sys(NR_close, fd);
    int only = (int)sys(NR_socket, AF_INET, SOCK_STREAM, 0);
    expect(sys(NR_connect, only, &mapped, sizeof mapped), -EAFNOSUPPORT, "the same address to AF_INET: EAFNOSUPPORT, and libcore falls back");
    sys(NR_close, only);

    through_echo(echo);

    (void)EALREADY;
    puts_(failures ? "SOME CHECKS FAILED\n" : "all checks passed\n");
    return failures;
}

void __attribute__((noreturn)) cstart(u64 *sp) {
    sys(NR_exit_group, cmain((int)sp[0], (char **)(sp + 1)));
    __builtin_unreachable();
}

__asm__(".global _start\n_start:\n mov x0, sp\n bl cstart\n");

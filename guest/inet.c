// Freestanding arm64 test of AF_INET sockets' blocking calls: with nothing that can
// arrive yet, they must sleep rather than return, or a server's accept loop spins.

typedef unsigned long u64;
typedef long i64;
typedef unsigned int u32;
typedef unsigned short u16;

#define NR_ioctl 29
#define NR_close 57
#define NR_read 63
#define NR_write 64
#define NR_ppoll 73
#define NR_exit_group 94
#define NR_setitimer 103
#define NR_rt_sigaction 134
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
#define NR_shutdown 210
#define NR_accept4 242

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
static void puts_(const char *s) { sys(NR_write, 1, s, slen(s)); }

static int failures;
static void check(int cond, const char *name) {
    puts_(cond ? "ok   " : "FAIL ");
    puts_(name);
    puts_("\n");
    if (!cond) failures++;
}

#define EINTR 4
#define EAGAIN 11
#define EINVAL 22
#define EPIPE 32
#define EADDRINUSE 98
#define ENOTCONN 107
#define SOCK_STREAM 1
#define SOCK_NONBLOCK 04000
#define MSG_DONTWAIT 0x40
#define SIGALRM 14
#define SIGPIPE 13

struct sigaction_k { void *handler; u64 flags; void *restorer; u64 mask; };
struct itimerval { i64 interval_s, interval_us, value_s, value_us; };
static volatile int alarmed;
static void on_alarm(int sig) { (void)sig; alarmed = 1; }

// An alarm in 50 ms whose handler has no SA_RESTART, so it ends a blocking call.
static void alarm_soon(void) {
    struct sigaction_k act = { (void *)on_alarm, 0, 0, 0 };
    sys(NR_rt_sigaction, SIGALRM, &act, 0, 8);
    struct itimerval it = { 0, 0, 0, 50000 };
    alarmed = 0;
    sys(NR_setitimer, 0, &it, 0);
}

void __attribute__((noreturn)) cstart(void);
__asm__(".global _start\n_start:\n bl cstart\n");

#define AF_INET 2
#define AF_INET6 10
#define SOCK_DGRAM 2
#define SOCK_RAW 3
#define SOL_IP 0
#define SOL_SOCKET 1
#define SOL_TCP 6
#define SOL_UDP 17
#define SOL_IPV6 41
#define SO_REUSEADDR 2
#define SO_TYPE 3
#define SO_ERROR 4
#define SO_BROADCAST 6
#define SO_SNDBUF 7
#define SO_RCVBUF 8
#define SO_RCVTIMEO 20
#define SO_MARK 36
#define SO_PROTOCOL 38
#define SO_DOMAIN 39
#define SO_COOKIE 57
#define IP_TTL 2
#define IPV6_UNICAST_HOPS 16
#define IPV6_V6ONLY 26
#define IPV6_TCLASS 67
#define TCP_NODELAY 1
#define TCP_ULP 31
#define UDP_GRO 104
#define POLLIN 1
#define POLLOUT 4
#define POLLHUP 0x10
#define POLLRDHUP 0x2000
#define MSG_NOSIGNAL 0x4000
#define EACCES 13
#define EAFNOSUPPORT 97
#define EDESTADDRREQ 89
#define EADDRNOTAVAIL 99
#define ENETUNREACH 101
#define ECONNREFUSED 111
#define ENOPROTOOPT 92
#define EPROTONOSUPPORT 93
#define ESOCKTNOSUPPORT 94
#define EISCONN 106
#define EOPNOTSUPP 95
#define NR_fchown 55
#define NR_fcntl 25
#define NR_memfd_create 279
#define NR_getsockopt 209

typedef unsigned char u8;
struct in4 { u16 family; u16 port; u8 addr[4]; u8 pad[8]; };
struct in6 { u16 family; u16 port; u32 flow; u8 addr[16]; u32 scope; };
struct pollfd { int fd; short events, revents; };

static u16 be(u16 v) { return (u16)(v << 8 | v >> 8); }
static struct in4 v4(u8 a, u8 b, u8 c, u8 d, u16 port) { struct in4 s = { AF_INET, be(port), { a, b, c, d }, { 0 } }; return s; }
static int same(const void *a, const void *b, u64 n) { const char *p = a, *q = b; while (n--) if (*p++ != *q++) return 0; return 1; }
static int intopt(int fd, int level, int name) {
    int v = -12345, len = sizeof v;
    i64 r = sys(NR_getsockopt, fd, level, name, &v, &len);
    return r < 0 ? (int)r : v;
}
static int ready(int fd) {
    struct pollfd p = { fd, POLLIN | POLLOUT | POLLRDHUP, 0 };
    struct { i64 s, ns; } zero = { 0, 0 };
    sys(NR_ppoll, &p, 1, &zero, 0, 8);
    return p.revents;
}
static volatile int piped;
static void on_pipe(int sig) { (void)sig; piped++; }

int cmain(void) {
    char buf[64];
    int fd = (int)sys(NR_socket, AF_INET, SOCK_STREAM, 0);
    check(fd >= 0, "an AF_INET stream socket");
    check(sys(NR_accept4, fd, 0, 0, 0) == -EINVAL, "accept before listen: EINVAL");
    check(ready(fd) == (POLLOUT | POLLHUP), "a new stream socket polls writable and hung up");
    check(sys(NR_listen, fd, 5) == 0, "listen");
    check(ready(fd) == 0, "a listener with nothing waiting polls as nothing");
    check(sys(NR_recvfrom, fd, buf, 16, 0, 0, 0) == -ENOTCONN, "recv on a listener: ENOTCONN");

    int nb = (int)sys(NR_socket, AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    sys(NR_listen, nb, 5);
    check(sys(NR_accept4, nb, 0, 0, 0) == -EAGAIN, "a non-blocking accept: EAGAIN");

    alarm_soon();
    check(sys(NR_accept4, fd, 0, 0, 0) == -EINTR && alarmed, "a blocking accept sleeps until a signal: EINTR");

    int u = (int)sys(NR_socket, AF_INET, SOCK_DGRAM, 0);
    check(u >= 0 && ready(u) == POLLOUT, "a new datagram socket polls writable only");
    check(sys(NR_recvfrom, u, buf, 16, MSG_DONTWAIT, 0, 0) == -EAGAIN, "MSG_DONTWAIT on a blocking datagram socket: EAGAIN");
    alarm_soon();
    check(sys(NR_recvfrom, u, buf, 16, 0, 0, 0) == -EINTR && alarmed, "a blocking recv sleeps until a signal");
    struct { i64 s, us; } tv = { 0, 20000 };
    check(sys(NR_setsockopt, u, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv) == 0, "SO_RCVTIMEO");
    check(sys(NR_recvfrom, u, buf, 16, 0, 0, 0) == -EAGAIN, "a blocking recv with a timeout: EAGAIN");

    // ---- bionic's fdopen won't take "r+" without this, and getaddrinfo needs that
    int unix_fd = (int)sys(NR_socket, 1, SOCK_STREAM, 0);
    check(sys(NR_fcntl, u, 3, 0) == 2, "F_GETFL on a socket: O_RDWR");
    check(sys(NR_fcntl, unix_fd, 3, 0) == 2, "on a Unix socket too, which is what it's for");
    int blocking_not = (int)sys(NR_socket, AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    check(sys(NR_fcntl, blocking_not, 3, 0) == (2 | SOCK_NONBLOCK), "with O_NONBLOCK alongside");
    int mem = (int)sys(NR_memfd_create, "x", 0);
    check(sys(NR_fcntl, mem, 3, 0) == 2, "and any file open for both");

    // ---- which sockets there are
    check(sys(NR_socket, AF_INET, SOCK_STREAM, 17) == -EPROTONOSUPPORT, "a stream socket for UDP: EPROTONOSUPPORT");
    check(sys(NR_socket, AF_INET, 5, 0) == -ESOCKTNOSUPPORT, "SOCK_SEQPACKET: ESOCKTNOSUPPORT");
    check(intopt(fd, SOL_SOCKET, SO_PROTOCOL) == 6, "SO_PROTOCOL is the real one when 0 was asked for: TCP");
    check(intopt(u, SOL_SOCKET, SO_PROTOCOL) == 17, "and UDP, which netd compares");
    check(intopt(u, SOL_SOCKET, SO_TYPE) == SOCK_DGRAM && intopt(u, SOL_SOCKET, SO_DOMAIN) == AF_INET, "SO_TYPE and SO_DOMAIN");
    int ping = (int)sys(NR_socket, AF_INET, SOCK_DGRAM, 1);
    check(ping >= 0, "a ping socket");
    check(sys(NR_socket, AF_INET6, SOCK_DGRAM, 1) == -EPROTONOSUPPORT, "ICMPv4 on AF_INET6: EPROTONOSUPPORT");
    int raw = (int)sys(NR_socket, AF_INET, SOCK_RAW, 255);
    check(raw >= 0 && ready(raw) == POLLOUT, "a raw socket, as netd's iptables has");

    // ---- what the resolver does, with no address on any interface yet
    int r4 = (int)sys(NR_socket, AF_INET, SOCK_DGRAM, 0);
    u64 mark = 0x12345;
    check(sys(NR_setsockopt, r4, SOL_SOCKET, SO_MARK, &mark, 4) == 0 && intopt(r4, SOL_SOCKET, SO_MARK) == 0x12345, "SO_MARK reads back");
    check(sys(NR_fchown, r4, 10100, -1) == 0, "fchown of a socket, or every lookup fails");
    check(sys(NR_fchown, fd, 10100, 10100) == 0, "any socket");
    struct in4 google = v4(8, 8, 8, 8, 0);
    check(sys(NR_connect, r4, &google, sizeof google) == -ENETUNREACH, "no address: 8.8.8.8 is ENETUNREACH");
    struct in6 g6 = { AF_INET6, 0, 0, { 0x20 }, 0 };
    int r6 = (int)sys(NR_socket, AF_INET6, SOCK_DGRAM, 0);
    check(sys(NR_connect, r6, &g6, sizeof g6) == -ENETUNREACH, "and 2000:: is ENETUNREACH");
    struct in4 lo0 = v4(127, 0, 0, 1, 0);
    check(sys(NR_connect, r4, &lo0, sizeof lo0) == 0, "loopback, port 0, is fine");
    struct in4 name;
    int len = sizeof name;
    check(sys(NR_getsockname, r4, &name, &len) == 0 && len == 16 && name.addr[0] == 127 && name.port != 0, "and now has a source address and a port");
    check(sys(NR_getpeername, r4, &name, &len) == 0 && name.addr[0] == 127, "and a peer");
    struct { u16 family; u8 pad[14]; } unspec = { 0, { 0 } };
    check(sys(NR_connect, r4, &unspec, sizeof unspec) == 0, "AF_UNSPEC ends that");
    len = sizeof name;
    check(sys(NR_getpeername, r4, &name, &len) == -ENOTCONN, "no peer now");

    // ---- names
    int fresh = (int)sys(NR_socket, AF_INET6, SOCK_DGRAM, 0);
    struct in6 six;
    len = sizeof six;
    check(sys(NR_getsockname, fresh, &six, &len) == 0 && len == 28 && six.family == AF_INET6 && six.port == 0, "an unbound name: the family and zeros");
    len = 4;
    memset(buf, 0x55, sizeof buf);
    check(sys(NR_getsockname, fresh, buf, &len) == 0 && len == 28 && buf[3] == 0 && (unsigned char)buf[4] == 0x55, "cut to the room, with its real length");

    // ---- families, which libcore's fallback depends on
    struct in6 any6 = { AF_INET6, be(9), 0, { 0 }, 0 };
    any6.addr[15] = 1;
    int t4 = (int)sys(NR_socket, AF_INET, SOCK_STREAM, 0);
    check(sys(NR_connect, t4, &any6, sizeof any6) == -EAFNOSUPPORT, "an AF_INET socket given IPv6: EAFNOSUPPORT");
    check(sys(NR_bind, t4, &any6, sizeof any6) == -EAFNOSUPPORT, "binding too");
    struct in4 short4 = v4(127, 0, 0, 1, 9);
    check(sys(NR_connect, t4, &short4, 8) == -EINVAL, "too short an address: EINVAL");
    int t6 = (int)sys(NR_socket, AF_INET6, SOCK_STREAM, 0);
    check(sys(NR_connect, t6, &short4, sizeof short4) == -EAFNOSUPPORT, "a stream on AF_INET6 given AF_INET: EAFNOSUPPORT");
    int u6 = (int)sys(NR_socket, AF_INET6, SOCK_DGRAM, 0);
    check(sys(NR_connect, u6, &short4, sizeof short4) == 0, "a datagram socket takes it");
    int on = 1;
    int only = (int)sys(NR_socket, AF_INET6, SOCK_DGRAM, 0);
    check(sys(NR_setsockopt, only, SOL_IPV6, IPV6_V6ONLY, &on, 4) == 0, "IPV6_V6ONLY");
    check(sys(NR_connect, only, &short4, sizeof short4) == -EAFNOSUPPORT, "and then doesn't");
    struct in6 mapped = { AF_INET6, be(9), 0, { 0,0,0,0,0,0,0,0,0,0,0xff,0xff,127,0,0,1 }, 0 };
    check(sys(NR_connect, only, &mapped, sizeof mapped) == -ENETUNREACH, "nor a v4-mapped address: ENETUNREACH");

    // ---- ports, the guest's own
    int b1 = (int)sys(NR_socket, AF_INET, SOCK_DGRAM, 0), b2 = (int)sys(NR_socket, AF_INET, SOCK_DGRAM, 0);
    struct in4 port = v4(127, 0, 0, 1, 40123);
    check(sys(NR_bind, b1, &port, sizeof port) == 0, "bind");
    check(sys(NR_bind, b1, &port, sizeof port) == -EINVAL, "twice: EINVAL");
    check(sys(NR_bind, b2, &port, sizeof port) == -EADDRINUSE, "taken: EADDRINUSE");
    struct in4 wild = v4(0, 0, 0, 0, 40123);
    check(sys(NR_bind, b2, &wild, sizeof wild) == -EADDRINUSE, "the wildcard overlaps it");
    struct in4 other = v4(127, 0, 0, 2, 40123);
    check(sys(NR_bind, b2, &other, sizeof other) == 0, "another address doesn't");
    int b3 = (int)sys(NR_socket, AF_INET6, SOCK_DGRAM, 0);
    struct in6 w6 = { AF_INET6, be(40123), 0, { 0 }, 0 };
    check(sys(NR_bind, b3, &w6, sizeof w6) == -EADDRINUSE, "nor does a dual-stack wildcard");
    int t1 = (int)sys(NR_socket, AF_INET, SOCK_STREAM, 0);
    check(sys(NR_bind, t1, &port, sizeof port) == 0, "TCP ports are separate");
    sys(NR_close, b1);
    int b4 = (int)sys(NR_socket, AF_INET, SOCK_DGRAM, 0);
    check(sys(NR_bind, b4, &port, sizeof port) == 0, "closing frees a port");
    int r1 = (int)sys(NR_socket, AF_INET, SOCK_STREAM, 0), r2 = (int)sys(NR_socket, AF_INET, SOCK_STREAM, 0);
    struct in4 rport = v4(0, 0, 0, 0, 40124);
    sys(NR_setsockopt, r1, SOL_SOCKET, SO_REUSEADDR, &on, 4);
    sys(NR_setsockopt, r2, SOL_SOCKET, SO_REUSEADDR, &on, 4);
    check(sys(NR_bind, r1, &rport, sizeof rport) == 0 && sys(NR_bind, r2, &rport, sizeof rport) == 0, "SO_REUSEADDR on both shares a port");
    check(sys(NR_listen, r1, 1) == 0, "and one can listen");
    check(sys(NR_listen, r2, 1) == -EADDRINUSE, "but only one");
    int r3 = (int)sys(NR_socket, AF_INET, SOCK_STREAM, 0);
    sys(NR_setsockopt, r3, SOL_SOCKET, SO_REUSEADDR, &on, 4);
    check(sys(NR_bind, r3, &rport, sizeof rport) == -EADDRINUSE, "nor can another bind then");
    struct in4 foreign = v4(192, 0, 2, 1, 0);
    int b5 = (int)sys(NR_socket, AF_INET, SOCK_DGRAM, 0);
    check(sys(NR_bind, b5, &foreign, sizeof foreign) == -EADDRNOTAVAIL, "an address that isn't ours: EADDRNOTAVAIL");
    check(sys(NR_listen, u, 1) == -EOPNOTSUPP, "listen on a datagram socket: EOPNOTSUPP");

    // ---- options: anything can be set, and a few are refused for the caller's sake
    check(intopt(u, SOL_IP, IP_TTL) == 64, "IP_TTL by default");
    check(intopt(u6, SOL_IPV6, IPV6_UNICAST_HOPS) == 64, "IPV6_UNICAST_HOPS");
    check(intopt(u6, SOL_IPV6, IPV6_V6ONLY) == 0, "IPV6_V6ONLY, which Chromium's QUIC setup needs to read");
    check(intopt(u6, SOL_IPV6, IPV6_TCLASS) == 0, "IPV6_TCLASS");
    check(intopt(u, SOL_IPV6, IPV6_TCLASS) == -ENOPROTOOPT, "IPv6 options on AF_INET: ENOPROTOOPT");
    check(intopt(u6, SOL_IP, IP_TTL) == 64, "and IP options on AF_INET6 are fine");
    int ttl = 7, big = 100000;
    check(sys(NR_setsockopt, u, SOL_IP, IP_TTL, &ttl, 4) == 0 && intopt(u, SOL_IP, IP_TTL) == 7, "IP_TTL reads back");
    check(sys(NR_setsockopt, u, SOL_SOCKET, SO_RCVBUF, &big, 4) == 0 && intopt(u, SOL_SOCKET, SO_RCVBUF) == 200000, "SO_RCVBUF reads back doubled");
    big = 100000000;
    check(sys(NR_setsockopt, u, SOL_SOCKET, SO_SNDBUF, &big, 4) == 0 && intopt(u, SOL_SOCKET, SO_SNDBUF) == 524288, "SO_SNDBUF up to its limit");
    check(sys(NR_setsockopt, u, SOL_UDP, UDP_GRO, &on, 4) == -ENOPROTOOPT, "UDP_GRO: refused, so Chromium goes without");
    check(sys(NR_setsockopt, fd, SOL_TCP, TCP_ULP, "tls", 4) == -ENOPROTOOPT, "TCP_ULP: refused");
    check(sys(NR_setsockopt, fd, SOL_TCP, TCP_NODELAY, &on, 4) == 0 && intopt(fd, SOL_TCP, TCP_NODELAY) == 1, "TCP_NODELAY");
    check(sys(NR_setsockopt, u, SOL_TCP, TCP_NODELAY, &on, 4) == -ENOPROTOOPT, "not on a datagram socket");
    check(sys(NR_setsockopt, u, SOL_IP, 200, &ttl, 4) == 0 && intopt(u, SOL_IP, 200) == 7, "an option nobody's heard of is kept");
    check(intopt(u, SOL_IP, 201) == -ENOPROTOOPT, "and one never set can't be read");
    u64 c1 = 0, c2 = 0;
    int clen = 8;
    check(sys(NR_getsockopt, u, SOL_SOCKET, SO_COOKIE, &c1, &clen) == 0 && sys(NR_getsockopt, fd, SOL_SOCKET, SO_COOKIE, &c2, &clen) == 0 && c1 && c1 != c2, "SO_COOKIE differs by socket");

    // ---- a stream with no connection
    int s = (int)sys(NR_socket, AF_INET, SOCK_STREAM, 0);
    check(sys(NR_recvfrom, s, buf, 16, 0, 0, 0) == -ENOTCONN, "recv with no connection: ENOTCONN");
    check(sys(NR_read, s, buf, 16) == -ENOTCONN, "read too");
    check(sys(NR_getpeername, s, &name, &len) == -ENOTCONN, "no peer");
    check(sys(NR_shutdown, s, 3) == -EINVAL, "shutdown(3): EINVAL");
    check(sys(NR_shutdown, s, 1) == -ENOTCONN, "shutdown: ENOTCONN");
    struct sigaction_k pipe_act = { (void *)on_pipe, 0, 0, 0 };
    sys(NR_rt_sigaction, SIGPIPE, &pipe_act, 0, 8);
    int s2 = (int)sys(NR_socket, AF_INET, SOCK_STREAM, 0);
    check(sys(NR_sendto, s2, "x", 1, MSG_NOSIGNAL, 0, 0) == -EPIPE && piped == 0, "send: EPIPE, and no signal if asked");
    check(sys(NR_sendto, s2, "x", 1, 0, 0, 0) == -EPIPE && piped == 1, "SIGPIPE if not");
    check(sys(NR_write, s2, "x", 1) == -EPIPE && piped == 2, "write as well");
    struct in4 here = v4(127, 0, 0, 1, 40999);
    check(sys(NR_connect, s2, &here, sizeof here) == -ECONNREFUSED, "connecting to nobody on this device: ECONNREFUSED");
    check(sys(NR_connect, s2, &here, sizeof here) == -ECONNREFUSED, "and again, it's still unconnected");
    check(intopt(s2, SOL_SOCKET, SO_ERROR) == 0, "the error isn't left to read too");

    // ---- a datagram socket with nowhere to send
    int d = (int)sys(NR_socket, AF_INET, SOCK_DGRAM, 0);
    check(sys(NR_sendto, d, "x", 1, 0, 0, 0) == -EDESTADDRREQ, "send with no destination: EDESTADDRREQ");
    check(sys(NR_write, d, "x", 1) == -EDESTADDRREQ, "write too");
    struct in4 zero_port = v4(127, 0, 0, 1, 0);
    check(sys(NR_sendto, d, "x", 1, 0, &zero_port, sizeof zero_port) == -EINVAL, "to port 0: EINVAL");
    struct in4 lo9 = v4(127, 0, 0, 1, 9);
    check(sys(NR_sendto, d, "hi", 2, 0, &lo9, sizeof lo9) == 2, "to loopback: it goes");
    len = sizeof name;
    check(sys(NR_getsockname, d, &name, &len) == 0 && name.port != 0 && name.addr[0] == 0, "and that gave it a port, but no address");
    struct in4 group = v4(224, 0, 0, 251, 5353);
    check(sys(NR_sendto, d, "hi", 2, 0, &group, sizeof group) == 2, "a multicast group: it goes, to nobody");
    struct in4 bcast = v4(255, 255, 255, 255, 9);
    check(sys(NR_sendto, d, "hi", 2, 0, &bcast, sizeof bcast) == -EACCES, "broadcast without asking: EACCES");
    sys(NR_setsockopt, d, SOL_SOCKET, SO_BROADCAST, &on, 4);
    check(sys(NR_sendto, d, "hi", 2, 0, &bcast, sizeof bcast) == 2, "with SO_BROADCAST it goes");
    check(sys(NR_sendto, d, "hi", 2, 0, &google, sizeof google) == -EINVAL, "port 0 again");
    google.port = be(53);
    check(sys(NR_sendto, d, "hi", 2, 0, &google, sizeof google) == -ENETUNREACH, "the rest of the world: ENETUNREACH");
    (void)same; (void)EISCONN;

    puts_(failures ? "SOME CHECKS FAILED\n" : "all checks passed\n");
    return failures;
}

void __attribute__((noreturn)) cstart(void) {
    sys(NR_exit_group, cmain());
    __builtin_unreachable();
}

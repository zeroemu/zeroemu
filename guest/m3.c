// Freestanding arm64 test of droidrt's IPC layer (no libc): eventfd, epoll,
// timerfd, signalfd, and AF_UNIX sockets (socketpair, named stream servers,
// seqpacket, datagrams, SCM_RIGHTS, SCM_CREDENTIALS, SO_PEERCRED). Exits with
// the failure count.

typedef unsigned long u64;
typedef long i64;
typedef unsigned int u32;

#define NR_eventfd2 19
#define NR_epoll_create1 20
#define NR_epoll_ctl 21
#define NR_epoll_pwait 22
#define NR_close 57
#define NR_pipe2 59
#define NR_read 63
#define NR_write 64
#define NR_mmap 222
#define NR_ppoll 73
#define NR_signalfd4 74
#define NR_timerfd_create 85
#define NR_timerfd_settime 86
#define NR_exit_group 94
#define NR_kill 129
#define NR_rt_sigprocmask 135
#define NR_getpid 172
#define NR_socket 198
#define NR_socketpair 199
#define NR_bind 200
#define NR_listen 201
#define NR_accept 202
#define NR_connect 203
#define NR_sendto 206
#define NR_recvfrom 207
#define NR_setsockopt 208
#define NR_getsockopt 209
#define NR_sendmsg 211
#define NR_recvmsg 212
#define NR_clone 220
#define NR_wait4 260

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
static int seq(const char *a, const char *b, u64 n) { while (n--) if (*a++ != *b++) return 0; return 1; }
static void puts_(const char *s) { sys(NR_write, 1, s, slen(s)); }

static int failures;
static void check(int cond, const char *name) {
    puts_(cond ? "ok   " : "FAIL ");
    puts_(name);
    puts_("\n");
    if (!cond) failures++;
}

static i64 fork_(void) { return sys(NR_clone, 17 /* SIGCHLD */, 0, 0, 0, 0); }
static int wait_status(i64 pid) { int st = -1; sys(NR_wait4, pid, &st, 0, 0); return st; }

struct epoll_event { u32 events; u32 pad; u64 data; }; // arm64: not packed
struct iovec { void *base; u64 len; };
struct msghdr { void *name; u32 namelen; u32 pad; struct iovec *iov; u64 iovlen; void *control; u64 controllen; int flags; int pad2; };
struct sockaddr_un { unsigned short family; char path[108]; };

#define EAGAIN 11
#define SOCK_STREAM 1
#define SOCK_DGRAM 2
#define SOCK_SEQPACKET 5

static u64 abstract_addr(struct sockaddr_un *a, const char *name) {
    memset(a, 0, sizeof *a);
    a->family = 1;
    u64 n = slen(name);
    memcpy(a->path + 1, name, n); // leading NUL: abstract namespace
    return 2 + 1 + n;
}

int cmain(void) {
    // ---- eventfd ----
    int efd = (int)sys(NR_eventfd2, 3, 0);
    u64 v = 0;
    check(sys(NR_read, efd, &v, 8) == 8 && v == 3, "eventfd read returns the counter");
    v = 5;
    sys(NR_write, efd, &v, 8);
    int sem = (int)sys(NR_eventfd2, 2, 1 /* EFD_SEMAPHORE */ | 04000 /* NONBLOCK */);
    u64 a1 = 0, a2 = 0, a3 = 0;
    sys(NR_read, sem, &a1, 8);
    sys(NR_read, sem, &a2, 8);
    check(a1 == 1 && a2 == 1 && sys(NR_read, sem, &a3, 8) == -EAGAIN, "eventfd semaphore + nonblock EAGAIN");

    // ---- epoll over a pipe and an eventfd ----
    int p[2];
    sys(NR_pipe2, p, 0);
    int ep = (int)sys(NR_epoll_create1, 0);
    struct epoll_event e1 = { 1 /* EPOLLIN */, 0, 111 }, e2 = { 1, 0, 222 }, out[4];
    sys(NR_epoll_ctl, ep, 1, p[0], &e1);
    sys(NR_epoll_ctl, ep, 1, efd, &e2);
    i64 n = sys(NR_epoll_pwait, ep, out, 4, 0, 0, 8);
    check(n == 1 && out[0].data == 222, "epoll: only the non-empty eventfd is ready");
    sys(NR_read, efd, &v, 8);
    sys(NR_write, p[1], "x", 1);
    n = sys(NR_epoll_pwait, ep, out, 4, 1000, 0, 8);
    check(n == 1 && out[0].data == 111, "epoll wakes for the pipe");
    char c;
    sys(NR_read, p[0], &c, 1);
    check(sys(NR_epoll_pwait, ep, out, 4, 30, 0, 8) == 0, "epoll times out when nothing is ready");

    // ---- timerfd, also through epoll ----
    int tfd = (int)sys(NR_timerfd_create, 1 /* MONOTONIC */, 0);
    u64 its[4] = { 0, 20000000, 0, 20000000 }; // every 20 ms, first at 20 ms
    sys(NR_timerfd_settime, tfd, 0, its, 0);
    struct epoll_event e3 = { 1, 0, 333 };
    sys(NR_epoll_ctl, ep, 1, tfd, &e3);
    n = sys(NR_epoll_pwait, ep, out, 4, 1000, 0, 8);
    u64 expirations = 0;
    sys(NR_read, tfd, &expirations, 8);
    check(n == 1 && out[0].data == 333 && expirations >= 1, "timerfd fires and wakes epoll");

    // ---- signalfd ----
    u64 usr1 = 1ul << (10 - 1);
    sys(NR_rt_sigprocmask, 0 /* BLOCK */, &usr1, 0, 8);
    int sfd = (int)sys(NR_signalfd4, -1, &usr1, 8, 0);
    sys(NR_kill, sys(NR_getpid, 0), 10);
    unsigned char info[128];
    check(sys(NR_read, sfd, info, 128) == 128 && *(u32 *)info == 10, "signalfd reads a blocked SIGUSR1");

    // ---- socketpair: data and EOF ----
    int sv[2];
    check(sys(NR_socketpair, 1, SOCK_STREAM, 0, sv) == 0, "socketpair");
    sys(NR_write, sv[0], "hello", 5);
    char buf[64];
    check(sys(NR_read, sv[1], buf, 64) == 5 && seq(buf, "hello", 5), "socketpair carries bytes");
    sys(NR_close, sv[0]);
    check(sys(NR_read, sv[1], buf, 64) == 0, "peer close gives EOF");

    // ---- SCM_RIGHTS: send a pipe's write end to a child ----
    int pp[2], ss[2];
    sys(NR_pipe2, pp, 0);
    sys(NR_socketpair, 1, SOCK_STREAM, 0, ss);
    i64 pid = fork_();
    if (pid == 0) {
        union { char buf[64]; u64 align; } ctl;
        char d;
        struct iovec iov = { &d, 1 };
        struct msghdr m = { 0, 0, 0, &iov, 1, ctl.buf, sizeof ctl.buf, 0, 0 };
        if (sys(NR_recvmsg, ss[1], &m, 0) != 1) sys(NR_exit_group, 1);
        int got = *(int *)(ctl.buf + 16);
        sys(NR_write, got, "via passed fd", 13);
        sys(NR_exit_group, 0);
    }
    {
        union { char buf[24]; u64 align; } ctl;
        memset(&ctl, 0, sizeof ctl);
        *(u64 *)ctl.buf = 20;          // cmsg_len
        *(int *)(ctl.buf + 8) = 1;     // SOL_SOCKET
        *(int *)(ctl.buf + 12) = 1;    // SCM_RIGHTS
        *(int *)(ctl.buf + 16) = pp[1];
        struct iovec iov = { "F", 1 };
        struct msghdr m = { 0, 0, 0, &iov, 1, ctl.buf, 24, 0, 0 };
        sys(NR_sendmsg, ss[0], &m, 0);
        sys(NR_close, pp[1]);
        n = sys(NR_read, pp[0], buf, 64);
        check(wait_status(pid) == 0 && n == 13 && seq(buf, "via passed fd", 13), "SCM_RIGHTS passes a pipe to another process");
    }

    // ---- named stream server in a child; SO_PEERCRED ----
    struct sockaddr_un addr;
    u64 alen = abstract_addr(&addr, "droidrt-test");
    int srv = (int)sys(NR_socket, 1, SOCK_STREAM, 0);
    check(sys(NR_bind, srv, &addr, alen) == 0 && sys(NR_listen, srv, 8) == 0, "bind + listen on an abstract name");
    pid = fork_();
    if (pid == 0) {
        int cl = (int)sys(NR_socket, 1, SOCK_STREAM, 0);
        if (sys(NR_connect, cl, &addr, alen) != 0) sys(NR_exit_group, 1);
        sys(NR_write, cl, "ping", 4);
        char r[8];
        i64 k = sys(NR_read, cl, r, 8);
        sys(NR_exit_group, k == 4 && seq(r, "pong", 4) ? 0 : 2);
    }
    int conn = (int)sys(NR_accept, srv, 0, 0);
    n = sys(NR_read, conn, buf, 64);
    sys(NR_write, conn, "pong", 4);
    u32 cred[3] = { 0 }, clen = 12;
    sys(NR_getsockopt, conn, 1, 17 /* SO_PEERCRED */, cred, &clen);
    check(n == 4 && seq(buf, "ping", 4) && wait_status(pid) == 0, "accept + request/response across processes");
    check(cred[0] == (u32)pid, "SO_PEERCRED names the client process");
    struct sockaddr_un taken;
    u64 tlen = abstract_addr(&taken, "droidrt-test");
    int dup_srv = (int)sys(NR_socket, 1, SOCK_STREAM, 0);
    check(sys(NR_bind, dup_srv, &taken, tlen) == -98, "a bound name is in use (EADDRINUSE)");

    // ---- seqpacket keeps message boundaries ----
    int sq[2];
    sys(NR_socketpair, 1, SOCK_SEQPACKET, 0, sq);
    sys(NR_write, sq[0], "one", 3);
    sys(NR_write, sq[0], "two!", 4);
    i64 r1 = sys(NR_read, sq[1], buf, 64);
    i64 r2 = sys(NR_read, sq[1], buf + 10, 64);
    check(r1 == 3 && r2 == 4 && seq(buf + 10, "two!", 4), "seqpacket preserves message boundaries");

    // ---- datagrams with SCM_CREDENTIALS (how logd identifies writers) ----
    struct sockaddr_un daddr;
    u64 dlen = abstract_addr(&daddr, "droidrt-logdw");
    int dsrv = (int)sys(NR_socket, 1, SOCK_DGRAM, 0);
    sys(NR_bind, dsrv, &daddr, dlen);
    int on = 1;
    sys(NR_setsockopt, dsrv, 1, 16 /* SO_PASSCRED */, &on, 4);
    int dcl = (int)sys(NR_socket, 1, SOCK_DGRAM, 0);
    sys(NR_sendto, dcl, "log line", 8, 0, &daddr, dlen);
    {
        union { char buf[64]; u64 align; } ctl;
        struct iovec iov = { buf, 64 };
        struct msghdr m = { 0, 0, 0, &iov, 1, ctl.buf, sizeof ctl.buf, 0, 0 };
        n = sys(NR_recvmsg, dsrv, &m, 0);
        int is_cred = m.controllen >= 28 && *(int *)(ctl.buf + 12) == 2;
        u32 sender = *(u32 *)(ctl.buf + 16);
        check(n == 8 && seq(buf, "log line", 8) && is_cred && sender == (u32)sys(NR_getpid, 0), "dgram + SCM_CREDENTIALS");
    }

    // ---- ppoll on a socket ----
    int pq[2];
    sys(NR_socketpair, 1, SOCK_STREAM, 0, pq);
    struct { int fd; short events, revents; } pfd = { pq[1], 1, 0 };
    u64 tmo[2] = { 0, 30000000 };
    i64 none = sys(NR_ppoll, &pfd, 1, tmo, 0, 8);
    sys(NR_write, pq[0], "z", 1);
    i64 one = sys(NR_ppoll, &pfd, 1, tmo, 0, 8);
    check(none == 0 && one == 1 && (pfd.revents & 1), "ppoll: timeout, then readable");

    // ART flushes caches over its read-only JIT code view: cache
    // maintenance on a page never touched faults as a read, not a write.
    char *code = (char *)sys(NR_mmap, 0, 4096, 5 /* PROT_READ|PROT_EXEC */, 0x22, -1, 0);
    __asm__ volatile("dc cvau, %0\n dsb ish\n ic ivau, %0\n dsb ish\n isb" : : "r"(code + 0x3c0) : "memory");
    check((i64)code > 0, "cache maintenance on read-only code does not fault");

    puts_(failures ? "SOME CHECKS FAILED\n" : "all checks passed\n");
    return failures;
}

void __attribute__((noreturn)) cstart(void) {
    sys(NR_exit_group, cmain());
    __builtin_unreachable();
}

__asm__(".global _start\n_start:\n bl cstart\n");

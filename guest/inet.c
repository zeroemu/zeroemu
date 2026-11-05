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
#define SOL_SOCKET 1
#define SO_RCVTIMEO 20

int cmain(void) {
    char buf[16];
    int fd = (int)sys(NR_socket, AF_INET, SOCK_STREAM, 0);
    check(fd >= 0, "an AF_INET stream socket");
    check(sys(NR_accept4, fd, 0, 0, 0) == -EINVAL, "accept before listen: EINVAL");
    check(sys(NR_listen, fd, 5) == 0, "listen");

    int nb = (int)sys(NR_socket, AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    sys(NR_listen, nb, 5);
    check(sys(NR_accept4, nb, 0, 0, 0) == -EAGAIN, "a non-blocking accept: EAGAIN");
    check(sys(NR_recvfrom, nb, buf, 16, 0, 0, 0) == -EAGAIN, "a non-blocking recv: EAGAIN");
    check(sys(NR_recvfrom, fd, buf, 16, MSG_DONTWAIT, 0, 0) == -EAGAIN, "MSG_DONTWAIT on a blocking socket: EAGAIN");

    alarm_soon();
    check(sys(NR_accept4, fd, 0, 0, 0) == -EINTR && alarmed, "a blocking accept sleeps until a signal: EINTR");
    alarm_soon();
    check(sys(NR_recvfrom, fd, buf, 16, 0, 0, 0) == -EINTR && alarmed, "a blocking recv too");

    struct { i64 s, us; } tv = { 0, 20000 };
    check(sys(NR_setsockopt, fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv) == 0, "SO_RCVTIMEO");
    check(sys(NR_recvfrom, fd, buf, 16, 0, 0, 0) == -EAGAIN, "a blocking recv with a timeout: EAGAIN");

    puts_(failures ? "SOME CHECKS FAILED\n" : "all checks passed\n");
    return failures;
}

void __attribute__((noreturn)) cstart(void) {
    sys(NR_exit_group, cmain());
    __builtin_unreachable();
}

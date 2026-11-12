// Freestanding arm64 test of a guest vsock listener, driven by scripts/test-net.py
// over a host TCP port: an echo, as adbd's transport would use it. Run as
//   zeroemu --adb-port <port> target/guest/vsock_aarch64

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

#define AF_VSOCK 40
#define CID_ANY 0xffffffffu
#define PORT 5555
#define POLLIN 1

struct sockaddr_vm { u16 family, reserved; u32 port, cid; char pad[4]; };

static i64 write_all(int fd, const char *p, u64 n) {
    u64 done = 0;
    while (done < n) {
        i64 w = sys(NR_write, fd, p + done, n - done);
        if (w <= 0) return w;
        done += w;
    }
    return done;
}

static char buf[64 * 1024];

int cmain(void) {
    struct sigaction_k ignore = { (void *)1 /* SIG_IGN */, 0, 0, 0 };
    sys(NR_rt_sigaction, SIGPIPE, &ignore, 0, 8);

    int fd = (int)sys(NR_socket, AF_VSOCK, SOCK_STREAM, 0);
    check(fd >= 0, "an AF_VSOCK stream socket");
    check(sys(NR_accept4, fd, 0, 0, 0) == -EINVAL, "accept before listen: EINVAL");
    struct sockaddr_vm a = { AF_VSOCK, 0, PORT, CID_ANY };
    check(sys(NR_bind, fd, &a, sizeof a) == 0, "bind any cid");
    int other = (int)sys(NR_socket, AF_VSOCK, SOCK_STREAM, 0);
    check(sys(NR_bind, other, &a, sizeof a) == -EADDRINUSE, "the same port twice: EADDRINUSE");
    sys(NR_close, other);
    check(sys(NR_listen, fd, 5) == 0, "listen");

    // The host connected before this listened, and has been kept waiting.
    u32 len = sizeof a;
    struct sockaddr_vm peer = { 0 };
    int c = (int)sys(NR_accept4, fd, &peer, &len, 0);
    check(c >= 0, "accepts the host's connection");
    check(peer.family == AF_VSOCK && peer.cid == 2 && len == 16, "the client is the host, CID 2");
    struct sockaddr_vm me = { 0 };
    len = sizeof me;
    check(sys(NR_getsockname, c, &me, &len) == 0 && me.family == AF_VSOCK && me.cid != 1 && me.cid != peer.cid && me.port == PORT, "its own address differs, as adbd insists");

    // Echo to the end. A slow reader on the host holds this back, not memory.
    u64 total = 0;
    for (;;) {
        i64 n = sys(NR_read, c, buf, sizeof buf);
        if (n <= 0) {
            check(n == 0, "the end of the stream reads as 0");
            break;
        }
        total += n;
        if (write_all(c, buf, n) != n) {
            check(0, "writing the echo");
            break;
        }
    }
    check(total == 4 * 1024 * 1024, "4 MiB came through");
    check(sys(NR_read, c, buf, 16) == 0, "and stays at the end");
    check(sys(NR_shutdown, c, 1) == 0, "shutdown for writing");
    check(sys(NR_write, c, "x", 1) == -EPIPE, "a write afterwards: EPIPE");
    sys(NR_close, c);

    // A second connection: this end goes first.
    c = (int)sys(NR_accept4, fd, 0, 0, 0);
    check(c >= 0, "a second connection");
    alarm_soon();
    check(sys(NR_read, c, buf, 16) == -EINTR && alarmed, "a blocking read sleeps until a signal");
    check(sys(NR_read, c, buf, 16) == 5 && buf[0] == 'h', "reads what the host sent next");
    check(write_all(c, "bye", 3) == 3, "writes");
    sys(NR_close, c);

    puts_(failures ? "SOME CHECKS FAILED\n" : "all checks passed\n");
    return failures;
}

void __attribute__((noreturn)) cstart(void) {
    sys(NR_exit_group, cmain());
    __builtin_unreachable();
}

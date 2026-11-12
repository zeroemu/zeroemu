// Freestanding arm64 test of zeroemu's msync, mlock family, mincore, sendfile,
// copy_file_range and the quota and module stubs.

typedef unsigned long u64;
typedef long i64;
typedef unsigned int u32;

#define NR_openat 56
#define NR_quotactl 60
#define NR_close 57
#define NR_lseek 62
#define NR_read 63
#define NR_write 64
#define NR_sendfile 71
#define NR_exit_group 94
#define NR_eventfd2 19
#define NR_timerfd_create 85
#define NR_timerfd_settime 86
#define NR_signalfd4 74
#define NR_rt_sigprocmask 135
#define NR_gettid 178
#define NR_tkill 130
#define NR_epoll_create1 20
#define NR_epoll_ctl 21
#define NR_epoll_pwait 22
#define NR_socket 198
#define NR_connect 203
#define NR_munmap 215
#define NR_mmap 222
#define NR_msync 227
#define NR_mlock 228
#define NR_munlock 229
#define NR_mlockall 230
#define NR_mincore 232
#define NR_memfd_create 279
#define NR_splice 76
#define NR_pipe2 59
#define NR_ppoll 73
#define NR_mlock2 284
#define NR_copy_file_range 285

#define EINVAL 22
#define ENOMEM 12
#define ESRCH 3

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
#define sys(...) sys6_(__VA_ARGS__, 0, 0, 0, 0, 0, 0)
#define sys6_(n, a, b, c, d, e, f, ...) sys6(n, (i64)(a), (i64)(b), (i64)(c), (i64)(d), (i64)(e), (i64)(f))

void *memset(void *d, int c, u64 n) { char *p = d; while (n--) *p++ = (char)c; return d; }
static u64 slen(const char *s) { u64 n = 0; while (s[n]) n++; return n; }
static void puts_(const char *s) { sys(NR_write, 1, s, slen(s)); }
static int same(const char *a, const char *b, u64 n) { while (n--) if (*a++ != *b++) return 0; return 1; }

static int failures;
static void check(int cond, const char *name) {
    puts_(cond ? "ok   " : "FAIL ");
    puts_(name);
    puts_("\n");
    if (!cond) failures++;
}

int cmain(void) {
    char *m = (char *)sys(NR_mmap, 0, 16384, 3, 0x22, -1, 0);
    sys(NR_munmap, m + 8192, 4096); // a hole in the middle

    check(sys(NR_msync, m + 1, 4096, 4) == -EINVAL, "msync: unaligned EINVAL");
    check(sys(NR_msync, m, 4096, 4 | 1) == -EINVAL, "msync: MS_SYNC with MS_ASYNC EINVAL");
    check(sys(NR_msync, m, 4096, 8) == -EINVAL, "msync: unknown flag EINVAL");
    check(sys(NR_msync, m, 16384, 4) == -ENOMEM, "msync: a hole ENOMEM");
    check(sys(NR_msync, m, 8192, 4) == 0, "msync: mapped memory");

    check(sys(NR_mlock, m, 8192) == 0 && sys(NR_munlock, m, 8192) == 0, "mlock and munlock");
    check(sys(NR_mlock, m, 16384) == -ENOMEM, "mlock: a hole ENOMEM");
    check(sys(NR_mlock2, m, 4096, 1) == 0 && sys(NR_mlock2, m, 4096, 2) == -EINVAL, "mlock2: MLOCK_ONFAULT only");
    check(sys(NR_mlockall, 1) == 0 && sys(NR_mlockall, 0) == -EINVAL && sys(NR_mlockall, 4) == -EINVAL, "mlockall flags");

    static unsigned char vec[4];
    m[4096] = 1;
    check(sys(NR_mincore, m, 8192, vec) == 0 && (vec[0] & 1) == 0 && (vec[1] & 1) == 1, "mincore: touched page in, untouched out");
    check(sys(NR_mincore, m, 16384, vec) == -ENOMEM, "mincore: a hole ENOMEM");
    check(sys(NR_mincore, m + 1, 4096, vec) == -EINVAL, "mincore: unaligned EINVAL");

    int in = (int)sys(NR_memfd_create, "in", 0), out = (int)sys(NR_memfd_create, "out", 0);
    sys(NR_write, in, "hello world", 11);
    sys(NR_lseek, in, 0, 0);
    check(sys(NR_sendfile, out, in, 0, 5) == 5 && sys(NR_lseek, in, 0, 1) == 5, "sendfile: no offset moves the input");
    i64 off = 6;
    check(sys(NR_sendfile, out, in, &off, 5) == 5 && off == 11 && sys(NR_lseek, in, 0, 1) == 5, "sendfile: an offset is updated instead");
    i64 eof = 11;
    check(sys(NR_sendfile, out, in, &eof, 5) == 0, "sendfile: end of file is 0");
    static char buf[16];
    sys(NR_lseek, out, 0, 0);
    check(sys(NR_read, out, buf, 16) == 10 && same(buf, "helloworld", 10), "the bytes arrived");

    int to = (int)sys(NR_memfd_create, "to", 0);
    i64 a = 6, b = 2;
    sys(NR_write, to, "xx", 2);
    check(sys(NR_copy_file_range, in, &a, to, &b, 5, 0) == 5 && a == 11 && b == 7, "copy_file_range: both offsets advance");
    check(sys(NR_copy_file_range, in, &a, to, &b, 5, 1) == -EINVAL, "copy_file_range: flags EINVAL");

    check(sys(NR_quotactl, 0, "/dev/x", 0, 0) == -ESRCH, "quotactl: quotas off");

    // netd's synchronizeKernelRCU opens and closes one of these.
    int key = (int)sys(NR_socket, 15 /* AF_KEY */, 3 /* SOCK_RAW */ | 02000000, 2 /* PF_KEY_V2 */);
    check(key >= 0 && sys(NR_close, key) == 0, "AF_KEY socket");

    // lmkd watches a PSI trigger: EPOLLPRI, and it must not fire on its own.
    int psi = (int)sys(NR_openat, -100, "/proc/pressure/memory", 2 /* O_RDWR */, 0);
    static const char trigger[] = "some 70000 1000000";
    check(psi >= 0 && sys(NR_write, psi, trigger, sizeof trigger) == sizeof trigger, "write a PSI trigger");
    int ep = (int)sys(NR_epoll_create1, 0);
    u64 ev[2] = {2 /* EPOLLPRI */, 7};
    check(sys(NR_epoll_ctl, ep, 1, psi, ev) == 0, "epoll watches the PSI file");
    check(sys(NR_epoll_pwait, ep, ev, 1, 0, 0, 8) == 0, "an idle trigger does not fire");

    // The clipboard monitor blocks reading the host: no EOF.
    int cb = (int)sys(NR_socket, 40 /* AF_VSOCK */, 1 | 04000 /* SOCK_STREAM | SOCK_NONBLOCK */, 0);
    unsigned vm[4] = {40, 5000, 2, 0};
    check(sys(NR_connect, cb, vm, 16) == 0, "connect to the host pipe");
    check(sys(NR_write, cb, "pipe:clipboard", 15) == 15, "open the clipboard pipe");
    unsigned empty = 0;
    check(sys(NR_write, cb, &empty, 4) == 4, "and send it a message");
    check(sys(NR_read, cb, buf, 4) == -11, "it stays open, with nothing to read");

    // splice: Android copies into install sessions with it.
    {
        int sp[2];
        char sbuf[16];
        sys(NR_pipe2, sp, 0);
        int m = (int)sys(NR_memfd_create, "splice", 0);
        int m2 = (int)sys(NR_memfd_create, "splice2", 0);
        sys(NR_write, sp[1], "hello pipe", 10);
        check(sys(NR_splice, sp[0], 0, m, 0, 5, 0) == 5, "splice from a pipe to a file");
        check(sys(NR_lseek, m, 0, 1) == 5, "moves the file's position");
        sys(NR_lseek, m, 0, 0);
        check(sys(NR_read, m, sbuf, 16) == 5 && sbuf[0] == 'h' && sbuf[4] == 'o', "the bytes arrive");
        check(sys(NR_read, sp[0], sbuf, 5) == 5 && sbuf[1] == 'p', "and the rest stay in the pipe");
        u64 where = 1;
        check(sys(NR_splice, m, &where, sp[1], 0, 3, 0) == 3 && where == 4, "from a file at an offset to a pipe, advancing it");
        check(sys(NR_read, sp[0], sbuf, 3) == 3 && sbuf[0] == 'e' && sbuf[2] == 'l', "those bytes");
        check(sys(NR_splice, m, 0, m2, 0, 3, 0) == -22, "with no pipe at either end: EINVAL");
        check(sys(NR_splice, sp[0], &where, m, 0, 3, 0) == -29, "an offset on a pipe: ESPIPE");
        sys(NR_close, sp[1]);
        check(sys(NR_splice, sp[0], 0, m, 0, 3, 0) == 0, "from a pipe with no writers: 0");
        sys(NR_close, sp[0]);
        sys(NR_close, m);
        sys(NR_close, m2);
    }

    // ---- edge-triggered epoll, as mio and Tokio use it
    {
        struct { u32 events; u32 pad; u64 data; } in = { 1u | 1u << 31, 0, 77 }, out[2];
        int e = (int)sys(NR_epoll_create1, 0);
        int efd = (int)sys(NR_eventfd2, 0, 0);
        u64 one = 1;
        check(sys(NR_epoll_ctl, e, 1, efd, &in) == 0, "EPOLLET on an eventfd");
        check(sys(NR_epoll_pwait, e, out, 2, 0, 0, 8) == 0, "not ready: no report");
        sys(NR_write, efd, &one, 8);
        check(sys(NR_epoll_pwait, e, out, 2, 0, 0, 8) == 1 && out[0].data == 77, "a write: one report");
        check(sys(NR_epoll_pwait, e, out, 2, 0, 0, 8) == 0, "still readable, and nothing new: no report, or mio spins");
        check(sys(NR_epoll_pwait, e, out, 2, 20, 0, 8) == 0, "nor does waiting bring one");
        sys(NR_write, efd, &one, 8);
        check(sys(NR_epoll_pwait, e, out, 2, 0, 0, 8) == 1, "never read, another write: another report");
        check(sys(NR_epoll_pwait, e, out, 2, 0, 0, 8) == 0, "and only one");
        check(sys(NR_epoll_ctl, e, 3, efd, &in) == 0 && sys(NR_epoll_pwait, e, out, 2, 0, 0, 8) == 1, "EPOLL_CTL_MOD reports what's ready again");

        int pe = (int)sys(NR_epoll_create1, 0);
        int pfd[2];
        sys(NR_pipe2, pfd, 0);
        char b[8];
        struct { u32 events; u32 pad; u64 data; } pin = { 1u | 1u << 31, 0, 88 };
        sys(NR_epoll_ctl, pe, 1, pfd[0], &pin);
        sys(NR_write, pfd[1], "x", 1);
        check(sys(NR_epoll_pwait, pe, out, 2, 0, 0, 8) == 1, "a pipe: reported");
        sys(NR_read, pfd[0], b, 8);
        sys(NR_write, pfd[1], "y", 1);
        check(sys(NR_epoll_pwait, pe, out, 2, 0, 0, 8) == 1, "read to empty and filled between waits: reported, though it looks unchanged");
        check(sys(NR_epoll_pwait, pe, out, 2, 0, 0, 8) == 0, "once");
        struct { int fd; short ev, rev; } pollep = { pe, 1, 0 };
        struct { i64 s, ns; } zero = { 0, 0 };
        check(sys(NR_ppoll, &pollep, 1, &zero, 0, 8) == 0, "polling the epoll itself agrees");
        sys(NR_write, pfd[1], "z", 1);
        check(sys(NR_ppoll, &pollep, 1, &zero, 0, 8) == 1, "until there's news");
        check(sys(NR_epoll_pwait, pe, out, 2, 0, 0, 8) == 1, "which polling didn't use up");

        // A timer: one edge per expiry, read or not, and through a nested epoll too.
        int te = (int)sys(NR_epoll_create1, 0), tfd = (int)sys(NR_timerfd_create, 1, 0);
        struct { u32 events; u32 pad; u64 data; } tin = { 1u | 1u << 31, 0, 11 };
        sys(NR_epoll_ctl, te, 1, tfd, &tin);
        struct { i64 is, ins, vs, vns; } every = { 0, 20000000, 0, 20000000 };
        sys(NR_timerfd_settime, tfd, 0, &every, 0);
        check(sys(NR_epoll_pwait, te, out, 2, 2000, 0, 8) == 1, "a periodic timer under EPOLLET: an edge");
        check(sys(NR_epoll_pwait, te, out, 2, 0, 0, 8) == 0, "unread and not yet due again: no report, not a spin");
        check(sys(NR_epoll_pwait, te, out, 2, 2000, 0, 8) == 1, "the next expiry, unread: another");
        int outer = (int)sys(NR_epoll_create1, 0);
        struct { u32 events; u32 pad; u64 data; } oin = { 1u | 1u << 31, 0, 12 };
        sys(NR_epoll_ctl, outer, 1, te, &oin);
        check(sys(NR_epoll_pwait, outer, out, 2, 2000, 0, 8) == 1, "through a nested epoll: an edge");
        check(sys(NR_epoll_pwait, te, out, 2, 2000, 0, 8) == 1, "drain the inner one");
        check(sys(NR_epoll_pwait, outer, out, 2, 2000, 0, 8) == 1, "and the next expiry reaches the outer");
        struct { i64 is, ins, vs, vns; } never = { 0, 0, 0, 0 };
        sys(NR_timerfd_settime, tfd, 0, &never, 0);

        // A signal for this one thread, waiting on a signalfd.
        u64 usr1 = 1ul << 9;
        sys(NR_rt_sigprocmask, 0, &usr1, 0, 8);
        int sfd = (int)sys(NR_signalfd4, -1, &usr1, 8, 0);
        int se = (int)sys(NR_epoll_create1, 0);
        struct { u32 events; u32 pad; u64 data; } sin = { 1u | 1u << 31, 0, 13 };
        sys(NR_epoll_ctl, se, 1, sfd, &sin);
        check(sys(NR_epoll_pwait, se, out, 2, 0, 0, 8) == 0, "a signalfd under EPOLLET: nothing yet");
        i64 me = sys(NR_gettid, 0);
        sys(NR_tkill, me, 10);
        check(sys(NR_epoll_pwait, se, out, 2, 0, 0, 8) == 1, "a signal to this thread: an edge");
        char sinfo[128];
        sys(NR_read, sfd, sinfo, 128);
        sys(NR_tkill, me, 10);
        check(sys(NR_epoll_pwait, se, out, 2, 0, 0, 8) == 1, "another, after reading the first: another");
        sys(NR_read, sfd, sinfo, 128);
        sys(NR_rt_sigprocmask, 1, &usr1, 0, 8);

        struct { u32 events; u32 pad; u64 data; } lvl = { 1, 0, 99 };
        int le = (int)sys(NR_epoll_create1, 0);
        sys(NR_epoll_ctl, le, 1, pfd[0], &lvl);
        check(sys(NR_epoll_pwait, le, out, 2, 0, 0, 8) == 1 && sys(NR_epoll_pwait, le, out, 2, 0, 0, 8) == 1, "without EPOLLET: every time");
    }

    puts_(failures ? "SOME CHECKS FAILED\n" : "all checks passed\n");
    return failures;
}

void __attribute__((noreturn)) cstart(void) {
    sys(NR_exit_group, cmain());
    __builtin_unreachable();
}

__asm__(".global _start\n_start:\n bl cstart\n");

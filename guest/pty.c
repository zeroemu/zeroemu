// Freestanding arm64 test of droidrt's pseudo-terminals (no libc): what
// bionic's posix_openpt/grantpt/unlockpt/ptsname and logwrap do with
// /dev/ptmx, the slave's output processing, termios and window size, and
// the hangup a master sees once its slaves close.

typedef unsigned long u64;
typedef long i64;
typedef unsigned int u32;

#define NR_ioctl 29
#define NR_openat 56
#define NR_close 57
#define NR_read 63
#define NR_write 64
#define NR_ppoll 73
#define NR_newfstatat 79
#define NR_exit_group 94

#define EIO 5
#define EAGAIN 11
#define ENOTTY 25
#define O_RDWR 2
#define O_NONBLOCK 04000
#define O_CLOEXEC 02000000

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

static void utoa(u32 v, char *out) {
    char t[12];
    int n = 0;
    do { t[n++] = (char)('0' + v % 10); v /= 10; } while (v);
    while (n) *out++ = t[--n];
    *out = 0;
}

int cmain(void) {
    int m = (int)sys(NR_openat, -100, "/dev/ptmx", O_RDWR | O_CLOEXEC, 0);
    check(m >= 0, "open /dev/ptmx");
    u32 n = 99;
    check(sys(NR_ioctl, m, 0x80045430 /* TIOCGPTN */, &n) == 0 && n < 4096, "TIOCGPTN");
    char path[32] = "/dev/pts/";
    utoa(n, path + 9);
    u64 st[16];
    check(sys(NR_newfstatat, -100, path, st, 0) == 0 && (st[2] & 0170000) == 020000, "the slave node exists");
    check(sys(NR_openat, -100, path, O_RDWR, 0) == -EIO, "the slave is locked until unlockpt");
    u32 zero = 0;
    check(sys(NR_ioctl, m, 0x40045431 /* TIOCSPTLCK */, &zero) == 0, "unlockpt");
    int s = (int)sys(NR_openat, -100, path, O_RDWR, 0);
    check(s >= 0, "open the slave");

    u32 tio[9];
    check(sys(NR_ioctl, s, 0x5401 /* TCGETS */, tio) == 0 && (tio[1] & 5) == 5 && (tio[3] & 2), "the slave's termios: OPOST|ONLCR, ICANON");
    check(sys(NR_ioctl, m, 0x5401, tio) == 0, "TCGETS on the master");

    char b[64];
    sys(NR_write, s, "out\n", 4);
    check(sys(NR_read, m, b, sizeof b) == 5 && seq(b, "out\r\n", 5), "slave output: \\n becomes \\r\\n");
    sys(NR_write, m, "in\n", 3);
    check(sys(NR_read, s, b, sizeof b) == 3 && seq(b, "in\n", 3), "master writes reach the slave");

    u32 ws[2] = { 24 | 80u << 16, 0 }, got[2] = { 0, 0 };
    check(sys(NR_ioctl, m, 0x5414 /* TIOCSWINSZ */, ws) == 0 && sys(NR_ioctl, s, 0x5413, got) == 0 && got[0] == ws[0], "window size");

    int p = (int)sys(NR_ioctl, m, 0x5441 /* TIOCGPTPEER */, O_RDWR | O_NONBLOCK);
    check(p >= 0 && sys(NR_read, p, b, 1) == -EAGAIN, "TIOCGPTPEER opens a (nonblocking) slave");
    check(sys(NR_ioctl, 0x7fff, 0x5401, tio) < 0 && sys(NR_ioctl, m, 0x40045431, 0) != -ENOTTY, "bad fds fail; pty ioctls are known");

    sys(NR_close, p);
    sys(NR_close, s);
    struct { int fd; short ev, rev; } pfd = { m, 1, 0 };
    u64 ts[2] = { 0, 0 };
    check(sys(NR_ppoll, &pfd, 1, ts, 0, 8) == 1 && (pfd.rev & 0x10), "POLLHUP once every slave is closed");
    check(sys(NR_read, m, b, sizeof b) == -EIO, "then a master read is EIO");
    sys(NR_close, m);
    check(sys(NR_newfstatat, -100, path, st, 0) < 0, "closing the master removes /dev/pts/<n>");

    if (failures) {
        puts_("SOME CHECKS FAILED\n");
        return failures;
    }
    puts_("all checks passed\n");
    return 0;
}

void __attribute__((noreturn)) cstart(void) {
    sys(NR_exit_group, cmain());
    __builtin_unreachable();
}

__asm__(".global _start\n_start:\n bl cstart\n");

// Freestanding arm64 test of zeroemu's /dev/tun and interface ioctls, as
// Android's Thread network service uses them: create "thread-wpan", set its
// MTU and bring it up through an inet socket, see it in /sys/class/net, and
// see it go away when the device closes.

typedef unsigned long u64;
typedef long i64;
typedef unsigned int u32;

#define NR_ioctl 29
#define NR_openat 56
#define NR_close 57
#define NR_read 63
#define NR_write 64
#define NR_exit_group 94
#define NR_socket 198

#define ENODEV 19
#define TUNSETIFF 0x400454ca
#define SIOCGIFFLAGS 0x8913
#define SIOCSIFFLAGS 0x8914
#define SIOCGIFMTU 0x8921
#define SIOCSIFMTU 0x8922
#define SIOCGIFINDEX 0x8933

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
static int streq(const char *a, const char *b) { while (*a && *a == *b) a++, b++; return *a == *b; }
static void copy(char *d, const char *s) { while ((*d++ = *s++)) {} }

static int failures;
static void check(int cond, const char *name) {
    puts_(cond ? "ok   " : "FAIL ");
    puts_(name);
    puts_("\n");
    if (!cond) failures++;
}

static char req[40];
static void named(const char *n) { memset(req, 0, sizeof req); copy(req, n); }

int cmain(void) {
    int tun = (int)sys(NR_openat, -100, "/dev/tun", 02 | 04000 /* O_RDWR|O_NONBLOCK */, 0);
    check(tun >= 0, "open /dev/tun");
    named("thread-wpan");
    *(unsigned short *)(req + 16) = 0x1 | 0x1000 | 0x8000; // IFF_TUN | IFF_NO_PI | IFF_TUN_EXCL
    check(sys(NR_ioctl, tun, TUNSETIFF, req) == 0 && streq(req, "thread-wpan"), "TUNSETIFF thread-wpan");

    int s = (int)sys(NR_socket, 10 /* AF_INET6 */, 2 /* SOCK_DGRAM */, 0);
    named("thread-wpan");
    check(sys(NR_ioctl, s, SIOCGIFINDEX, req) == 0 && *(int *)(req + 16) >= 2, "the new interface has an index");
    named("thread-wpan");
    *(int *)(req + 16) = 1280;
    check(sys(NR_ioctl, s, SIOCSIFMTU, req) == 0, "set its MTU");
    named("thread-wpan");
    check(sys(NR_ioctl, s, SIOCGIFMTU, req) == 0 && *(int *)(req + 16) == 1280, "and read it back");
    named("thread-wpan");
    *(short *)(req + 16) = 1; // IFF_UP
    sys(NR_ioctl, s, SIOCSIFFLAGS, req);
    named("thread-wpan");
    check(sys(NR_ioctl, s, SIOCGIFFLAGS, req) == 0 && (*(short *)(req + 16) & 1), "bring it up");

    static char buf[64];
    int m = (int)sys(NR_openat, -100, "/sys/class/net/thread-wpan/mtu", 0, 0);
    i64 n = m >= 0 ? sys(NR_read, m, buf, sizeof buf - 1) : -1;
    check(n == 5 && buf[0] == '1' && buf[3] == '0', "/sys/class/net/thread-wpan/mtu says 1280");
    check(sys(NR_read, tun, buf, sizeof buf) == -11, "no packets: EAGAIN");

    sys(NR_close, tun);
    named("thread-wpan");
    check(sys(NR_ioctl, s, SIOCGIFINDEX, req) == -ENODEV, "closing the device removes the interface");

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

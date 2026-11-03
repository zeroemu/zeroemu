// Freestanding Linux smoke test for droidrt (no libc). Builds for arm64 and
// x86_64; exercises the initial stack, memory syscalls, time, randomness,
// FP/SIMD, and exit codes. Prints "ok <name>" per check, exits with the
// number of failures.

typedef unsigned long u64;
typedef long i64;

#if defined(__aarch64__)
#define NR_write 64
#define NR_writev 66
#define NR_exit_group 94
#define NR_uname 160
#define NR_brk 214
#define NR_mmap 222
#define NR_clock_gettime 113
#define NR_getrandom 278
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
#elif defined(__x86_64__)
#define NR_write 1
#define NR_writev 20
#define NR_exit_group 231
#define NR_uname 63
#define NR_brk 12
#define NR_mmap 9
#define NR_clock_gettime 228
#define NR_getrandom 318
static i64 sys6(i64 n, i64 a, i64 b, i64 c, i64 d, i64 e, i64 f) {
    register i64 r10 __asm__("r10") = d;
    register i64 r8 __asm__("r8") = e;
    register i64 r9 __asm__("r9") = f;
    __asm__ volatile("syscall" : "+a"(n) : "D"(a), "S"(b), "d"(c), "r"(r10), "r"(r8), "r"(r9) : "rcx", "r11", "memory");
    return n;
}
#endif

static u64 slen(const char *s) { u64 n = 0; while (s[n]) n++; return n; }
static int seq(const char *a, const char *b) { while (*a && *a == *b) a++, b++; return *a == *b; }
static void puts_(const char *s) { sys6(NR_write, 1, (i64)s, slen(s), 0, 0, 0); }

static int failures;
static void check(int cond, const char *name) {
    puts_(cond ? "ok   " : "FAIL ");
    puts_(name);
    puts_("\n");
    if (!cond) failures++;
}

struct iovec { const void *base; u64 len; };
struct timespec { i64 sec; i64 nsec; };
struct utsname { char f[6][65]; };

// The compiler may emit calls to these even in freestanding code.
void *memset(void *d, int c, u64 n) { char *p = d; while (n--) *p++ = (char)c; return d; }
void *memcpy(void *d, const void *s, u64 n) { char *p = d; const char *q = s; while (n--) *p++ = *q++; return d; }

__attribute__((noinline)) static double fp_work(double x) {
    double acc = 0;
    for (int i = 1; i <= 10; i++) acc += x / i;
    return acc;
}

int cmain(u64 *sp) {
    u64 argc = sp[0];
    char **argv = (char **)(sp + 1);
    char **envp = argv + argc + 1;
    u64 *auxv = (u64 *)envp;
    while (*auxv) auxv++;
    auxv++;
    u64 pagesz = 0, random = 0;
    for (u64 *a = auxv; a[0]; a += 2) {
        if (a[0] == 6) pagesz = a[1];
        if (a[0] == 25) random = a[1];
    }

    check(argc == 3 && seq(argv[1], "alpha") && seq(argv[2], "beta"), "argv");
    check(pagesz == 4096, "auxv AT_PAGESZ");
    check(random != 0, "auxv AT_RANDOM");

    struct iovec iov[2] = {{"ok   writev ", 12}, {"(two iovecs)\n", 13}};
    check(sys6(NR_writev, 1, (i64)iov, 2, 0, 0, 0) == 25, "writev return value");

    u64 cur = sys6(NR_brk, 0, 0, 0, 0, 0, 0);
    u64 grown = sys6(NR_brk, cur + 65536, 0, 0, 0, 0, 0);
    int brk_ok = grown == cur + 65536;
    if (brk_ok) { char *p = (char *)cur; p[0] = 1; p[65535] = 2; brk_ok = p[0] + p[65535] == 3; }
    check(brk_ok, "brk grow + touch");

    // mmap(NULL, 1 MiB, RW, PRIVATE|ANONYMOUS)
    i64 m = sys6(NR_mmap, 0, 1 << 20, 3, 0x22, -1, 0);
    int mmap_ok = m > 0;
    if (mmap_ok) { u64 *p = (u64 *)m; mmap_ok = p[1000] == 0; p[1000] = 42; mmap_ok &= p[1000] == 42; }
    check(mmap_ok, "mmap anonymous");

    struct utsname u;
    check(sys6(NR_uname, (i64)&u, 0, 0, 0, 0, 0) == 0 && seq(u.f[0], "Linux"), "uname");

    struct timespec t1, t2;
    sys6(NR_clock_gettime, 1, (i64)&t1, 0, 0, 0, 0);
    for (volatile int i = 0; i < 1000000; i++) {}
    sys6(NR_clock_gettime, 1, (i64)&t2, 0, 0, 0, 0);
    check(t2.sec > t1.sec || (t2.sec == t1.sec && t2.nsec > t1.nsec), "CLOCK_MONOTONIC advances");

    unsigned char rnd[32] = {0};
    int nonzero = 0;
    check(sys6(NR_getrandom, (i64)rnd, 32, 0, 0, 0, 0) == 32, "getrandom");
    for (int i = 0; i < 32; i++) nonzero |= rnd[i];
    check(nonzero, "getrandom fills buffer");

    double r = fp_work(2.0);
    check(r > 5.85 && r < 5.86, "FP/SIMD arithmetic");

    puts_(failures ? "SOME CHECKS FAILED\n" : "all checks passed\n");
    return failures;
}

void __attribute__((noreturn)) cstart(u64 *sp) {
    sys6(NR_exit_group, cmain(sp), 0, 0, 0, 0, 0);
    __builtin_unreachable();
}

// Entry: hand the kernel-provided stack pointer to C.
#if defined(__aarch64__)
__asm__(".global _start\n_start:\n mov x0, sp\n bl cstart\n");
#elif defined(__x86_64__)
__asm__(".global _start\n_start:\n mov %rsp, %rdi\n and $-16, %rsp\n call cstart\n");
#endif

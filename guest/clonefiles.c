// Freestanding arm64 test of descriptor tables across clone: a thread cloned
// without CLONE_FILES has its own copy (bionic's crash handler closes every fd
// in such a thread), one with CLONE_FILES shares the caller's, and a fork from
// a private-table thread copies that table.
typedef unsigned long u64;
typedef long i64;
#define NR_write 64
#define NR_close 57
#define NR_pipe2 59
#define NR_fcntl 25
#define NR_futex 98
#define NR_mmap 222
#define NR_clone 220
#define NR_exit_group 94
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
#define sys(...) sys6_(__VA_ARGS__, 0, 0, 0, 0, 0, 0)
#define sys6_(n, a, b, c, d, e, f, ...) sys6(n, (i64)(a), (i64)(b), (i64)(c), (i64)(d), (i64)(e), (i64)(f))
void *memset(void *d, int c, u64 n) { char *p = d; while (n--) *p++ = (char)c; return d; }
static u64 slen(const char *s) { u64 n = 0; while (s[n]) n++; return n; }
static void puts_(const char *s) { sys(NR_write, 1, s, slen(s)); }
static void putn(i64 v) { char b[24]; int i = 23; b[i] = 0; int neg = v < 0; if (neg) v = -v; do { b[--i] = '0' + v % 10; v /= 10; } while (v); if (neg) b[--i] = '-'; puts_(&b[i]); }
static int failures;
static void check(int cond, const char *name) { puts_(cond ? "ok   " : "FAIL "); puts_(name); puts_("\n"); if (!cond) failures++; }

// debuggerd's pseudothread flags: CLONE_THREAD|CLONE_SIGHAND|CLONE_VM|CLONE_CHILD_SETTID|CLONE_CHILD_CLEARTID
#define PSEUDO_FLAGS (0x10000 | 0x800 | 0x100 | 0x1000000 | 0x200000)
static i64 spawn(u64 flags, void *stack_top, void (*fn)(void *), void *arg, int *ctid) {
    register i64 x0 __asm__("x0") = flags;
    register i64 x1 __asm__("x1") = (i64)stack_top;
    register i64 x2 __asm__("x2") = 0;
    register i64 x3 __asm__("x3") = 0;
    register i64 x4 __asm__("x4") = (i64)ctid;
    register i64 x8 __asm__("x8") = NR_clone;
    register void *x19 __asm__("x19") = (void *)fn;
    register void *x20 __asm__("x20") = arg;
    __asm__ volatile("svc #0\n" "cbnz x0, 1f\n" "mov x0, x20\n" "blr x19\n" "mov x0, #0\n" "mov x8, #93\n" "svc #0\n" "1:\n"
        : "+r"(x0) : "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x8), "r"(x19), "r"(x20) : "memory", "x30");
    return x0;
}
#define CLONE_FILES 0x400
static volatile int child_newfd = -100;
static int shared_fd = -1;
static void closer(void *arg) {
    (void)arg;
    sys(NR_close, shared_fd);
}
static volatile int private_read = -1;
static volatile i64 forked_sees_private = -100, forked_sees_parent = -100;
static int parent_only_fd = -1;
static void forker(void *arg) {
    (void)arg;
    int p[2];
    sys(NR_pipe2, p, 0);
    private_read = p[0];
    sys(NR_close, parent_only_fd);
    i64 pid = sys(220 /* clone */, 17 /* SIGCHLD */, 0, 0, 0, 0);
    if (pid == 0) {
        // Exit status: 1 if the thread's own pipe is here, 2 if the closed fd stayed closed.
        int code = (sys(NR_fcntl, p[0], 1) >= 0 ? 1 : 0) | (sys(NR_fcntl, parent_only_fd, 1) < 0 ? 2 : 0);
        sys(93, code);
    }
    int st = 0;
    sys(NR_wait4, pid, &st, 0, 0);
    forked_sees_private = (st >> 8) & 1;
    forked_sees_parent = (st >> 8) & 2;
}
static void pseudothread(void *arg) {
    (void)arg;
    for (int i = 0; i < 1024; i++) if (i != 1) sys(NR_close, i);
    int p[2];
    sys(NR_pipe2, p, 0x80000);
    child_newfd = p[0];
}
static volatile int ctid;
static char stack[65536] __attribute__((aligned(16)));
void _start(void) {
    int p[2];
    check(sys(NR_pipe2, p, 0x80000) == 0, "pipe2");
    puts_("parent pipe fds "); putn(p[0]); puts_(" "); putn(p[1]); puts_("\n");
    ctid = -1;
    i64 tid = spawn(PSEUDO_FLAGS, stack + sizeof stack, pseudothread, 0, (int *)&ctid);
    check(tid > 0, "clone(CLONE_THREAD|CLONE_VM|CLONE_SIGHAND, no CLONE_FILES)");
    while (ctid != 0) sys(NR_futex, &ctid, 0, ctid, 0);
    puts_("pseudothread's first fd after closing 0..1023: "); putn(child_newfd); puts_(" (Linux: 0)\n");
    check(child_newfd == 0, "pseudothread got fd 0");
    i64 r = sys(NR_fcntl, p[0], 1 /*F_GETFD*/);
    puts_("parent fcntl(F_GETFD) on its pipe fd after pseudothread exit: "); putn(r); puts_("\n");
    check(r >= 0, "parent's fds survive a no-CLONE_FILES thread closing them");
    r = sys(NR_fcntl, 1, 1);
    check(r >= 0, "parent's stdout survives");

    // pthread-style: CLONE_FILES shares the table.
    int q[2];
    sys(NR_pipe2, q, 0);
    shared_fd = q[0];
    ctid = -1;
    spawn(PSEUDO_FLAGS | CLONE_FILES, stack + sizeof stack, closer, 0, (int *)&ctid);
    while (ctid != 0) sys(NR_futex, &ctid, 0, ctid, 0);
    check(sys(NR_fcntl, q[0], 1) == -9, "with CLONE_FILES a thread's close is the caller's");

    ctid = -1;
    sys(NR_pipe2, q, 0);
    parent_only_fd = q[0];
    spawn(PSEUDO_FLAGS, stack + sizeof stack, forker, 0, (int *)&ctid);
    while (ctid != 0) sys(NR_futex, &ctid, 0, ctid, 0);
    check(forked_sees_private == 1, "fork from a private-table thread copies that table");
    check(forked_sees_parent == 2, "and not the process's");
    check(sys(NR_fcntl, q[0], 1) >= 0, "the thread's close left the process's fd open");

    puts_(failures ? "SOME CHECKS FAILED\n" : "all checks passed\n");
    sys(NR_exit_group, failures);
}

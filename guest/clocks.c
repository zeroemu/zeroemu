// Freestanding arm64 test of the guest's clocks: the virtual counter (CNTVCT_EL0)
// against CLOCK_MONOTONIC on every vCPU.

typedef unsigned long u64;
typedef long i64;
typedef unsigned int u32;
typedef unsigned short u16;
typedef unsigned char u8;

#define NR_write 64
#define NR_exit 93
#define NR_exit_group 94
#define NR_futex 98
#define NR_clock_gettime 113
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
#define sys(...) sys6_(__VA_ARGS__, 0, 0, 0, 0, 0, 0)
#define sys6_(n, a, b, c, d, e, f, ...) sys6(n, (i64)(a), (i64)(b), (i64)(c), (i64)(d), (i64)(e), (i64)(f))

void *memset(void *d, int c, u64 n) { char *p = d; while (n--) *p++ = (char)c; return d; }
void *memcpy(void *d, const void *s, u64 n) { char *p = d; const char *q = s; while (n--) *p++ = *q++; return d; }
static u64 slen(const char *s) { u64 n = 0; while (s[n]) n++; return n; }
static void puts_(const char *s) { sys(NR_write, 1, s, slen(s)); }
static void putn(u64 v) {
    char b[24];
    int i = 23;
    b[i] = 0;
    do b[--i] = '0' + v % 10; while (v /= 10);
    puts_(b + i);
}

static int failures;
static void check(int cond, const char *name) {
    puts_(cond ? "ok   " : "FAIL ");
    puts_(name);
    puts_("\n");
    if (!cond) failures++;
}

struct timespec { i64 sec, nsec; };
static u64 ns_of(struct timespec t) { return (u64)t.sec * 1000000000 + (u64)t.nsec; }
static u64 svc_ns(int id) {
    struct timespec t;
    sys(NR_clock_gettime, id, &t);
    return ns_of(t);
}

// The virtual counter, read as Linux's vDSO reads it, and in nanoseconds: exactly
// floor(t * 1e9 / frequency), as zeroemu converts the host's ticks.
static u64 cntvct(void) {
    u64 v;
    __asm__ volatile("isb\n mrs %0, cntvct_el0" : "=r"(v) :: "memory");
    return v;
}
static u64 cntfrq(void) {
    u64 v;
    __asm__ volatile("mrs %0, cntfrq_el0" : "=r"(v));
    return v;
}
static u64 counter_ns(u64 t) {
    u64 f = cntfrq();
    return t / f * 1000000000 + t % f * 1000000000 / f;
}

// CNTVCT_EL0 between two CLOCK_MONOTONIC syscalls, and a syscall between two
// counter reads: true if the counter is CLOCK_MONOTONIC to the nanosecond.
static int counter_is_monotonic(int rounds) {
    for (int i = 0; i < rounds; i++) {
        u64 a = svc_ns(1);
        u64 c = counter_ns(cntvct());
        u64 b = svc_ns(1);
        u64 c2 = counter_ns(cntvct());
        if (!(a <= c && c <= b && b <= c2)) {
            puts_("  counter ");
            putn(c);
            puts_(" between ");
            putn(a);
            puts_(" and ");
            putn(b);
            puts_("\n");
            return 0;
        }
    }
    return 1;
}

// A thread of our own, on a vCPU of its own.
#define CLONE_THREAD_FLAGS (0x100 | 0x200 | 0x400 | 0x800 | 0x10000 | 0x40000 | 0x200000)
static i64 spawn(void *stack_top, void (*fn)(void *), void *arg, int *ctid) {
    register i64 x0 __asm__("x0") = CLONE_THREAD_FLAGS;
    register i64 x1 __asm__("x1") = (i64)stack_top;
    register i64 x2 __asm__("x2") = 0;
    register i64 x3 __asm__("x3") = 0;
    register i64 x4 __asm__("x4") = (i64)ctid;
    register i64 x8 __asm__("x8") = NR_clone;
    register void *x19 __asm__("x19") = (void *)fn;
    register void *x20 __asm__("x20") = arg;
    __asm__ volatile(
        "svc #0\n"
        "cbnz x0, 1f\n"
        "mov x0, x20\n"
        "blr x19\n"
        "mov x0, #0\n"
        "mov x8, #93\n"
        "svc #0\n"
        "1:\n"
        : "+r"(x0)
        : "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x8), "r"(x19), "r"(x20)
        : "memory", "x30");
    return x0;
}
static void join(int *ctid) {
    while (__atomic_load_n(ctid, __ATOMIC_ACQUIRE) != 0) sys(NR_futex, ctid, 0 /* WAIT */, *ctid, 0);
}

#define THREADS 4
static char stacks[THREADS][65536] __attribute__((aligned(16)));
static int tids[THREADS];
static volatile int thread_ok[THREADS];
static void counter_thread(void *arg) {
    u64 i = (u64)arg;
    thread_ok[i] = counter_is_monotonic(2000);
}

// One thread reads the counter and hands the value over; the other, on another
// vCPU, must not then read an earlier one.
static u64 handed;
static volatile int handover_bad;
static void handover_thread(void *arg) {
    (void)arg;
    for (int i = 0; i < 20000; i++) {
        u64 v;
        while ((v = __atomic_load_n(&handed, __ATOMIC_ACQUIRE)) == 0) {}
        if (cntvct() < v) handover_bad = 1;
        __atomic_store_n(&handed, 0, __ATOMIC_RELEASE);
    }
}

static int run(u64 *sp) {
    (void)sp;

    // The virtual counter: CLOCK_MONOTONIC on every vCPU, from its first read.
    check(cntfrq() != 0, "CNTFRQ_EL0 is readable at EL0");
    puts_("info counter frequency ");
    putn(cntfrq());
    puts_(" Hz\n");
    check(counter_is_monotonic(2000), "CNTVCT_EL0 is CLOCK_MONOTONIC to the nanosecond");
    for (int i = 0; i < THREADS; i++) {
        tids[i] = 1;
        spawn(stacks[i] + sizeof stacks[i], counter_thread, (void *)(u64)i, &tids[i]);
    }
    int all = 1;
    for (int i = 0; i < THREADS; i++) {
        join(&tids[i]);
        all &= thread_ok[i];
    }
    check(all, "the same on vCPUs made later, by other threads");
    tids[0] = 1;
    spawn(stacks[0] + sizeof stacks[0], handover_thread, 0, &tids[0]);
    for (int i = 0; i < 20000; i++) {
        while (__atomic_load_n(&handed, __ATOMIC_ACQUIRE) != 0) {}
        __atomic_store_n(&handed, cntvct(), __ATOMIC_RELEASE);
    }
    join(&tids[0]);
    check(!handover_bad, "a value handed to another vCPU is never ahead of its counter");
    i64 pid = sys(NR_clone, 17 /* SIGCHLD */, 0, 0, 0, 0);
    if (pid == 0) sys(NR_exit_group, counter_is_monotonic(2000) ? 0 : 1);
    int st = -1;
    sys(NR_wait4, pid, &st, 0, 0);
    check(st == 0, "and in a forked child");

    puts_(failures ? "SOME CHECKS FAILED\n" : "all checks passed\n");
    return failures;
}

void __attribute__((noreturn)) cstart(u64 *sp) {
    sys(NR_exit_group, run(sp));
    __builtin_unreachable();
}

__asm__(".global _start\n_start:\n mov x0, sp\n bl cstart\n");

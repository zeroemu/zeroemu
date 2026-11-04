// Freestanding arm64 test: more guest threads than the hypervisor has vCPUs.
// 200 threads block in futex waits at once and all wake; then 100 threads
// spin in user code at once, which only ends if spinning threads give their
// vCPUs to the ones still waiting for one.

typedef unsigned long u64;
typedef long i64;

#define NR_futex 98
#define NR_mmap 222
#define NR_write 64
#define NR_exit_group 94
#define NR_clone 220
#define NR_gettid 178

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

static int failures;
static void check(int cond, const char *name) {
    puts_(cond ? "ok   " : "FAIL ");
    puts_(name);
    puts_("\n");
    if (!cond) failures++;
}

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

static void join(volatile int *ctid) {
    while (*ctid != 0) sys(NR_futex, ctid, 0, *ctid, 0);
}

#define STACK 16384
#define N_BLOCK 200
#define N_SPIN 100

static volatile int gate;
static volatile int arrived, done_count;
static int tids[N_BLOCK];

static void blocker(void *arg) {
    (void)arg;
    __atomic_fetch_add(&arrived, 1, __ATOMIC_SEQ_CST);
    while (__atomic_load_n(&gate, __ATOMIC_ACQUIRE) == 0) sys(NR_futex, &gate, 128 /* WAIT|PRIVATE */, 0, 0);
    __atomic_fetch_add(&done_count, 1, __ATOMIC_SEQ_CST);
}

static volatile int spinning, release_spin;

static void spinner(void *arg) {
    (void)arg;
    __atomic_fetch_add(&spinning, 1, __ATOMIC_SEQ_CST);
    // Pure user-mode spin until every spinner has started at least once.
    while (__atomic_load_n(&release_spin, __ATOMIC_ACQUIRE) == 0) {
        if (__atomic_load_n(&spinning, __ATOMIC_ACQUIRE) == N_SPIN) __atomic_store_n(&release_spin, 1, __ATOMIC_RELEASE);
    }
}

// A priority-inheritance mutex, as bionic and libc++ use it: the word holds
// the owner's tid; contended paths go through FUTEX_LOCK_PI / UNLOCK_PI.
#define N_PI 8
#define PI_ROUNDS 2000
static volatile unsigned pi_word;
static long pi_counter;

static void pi_lock(unsigned tid) {
    unsigned zero = 0;
    if (__atomic_compare_exchange_n(&pi_word, &zero, tid, 0, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED)) return;
    while (sys(NR_futex, &pi_word, 6 | 128 /* LOCK_PI|PRIVATE */, 0, 0) != 0) {}
}

static void pi_unlock(unsigned tid) {
    unsigned mine = tid;
    if (__atomic_compare_exchange_n(&pi_word, &mine, 0, 0, __ATOMIC_RELEASE, __ATOMIC_RELAXED)) return;
    sys(NR_futex, &pi_word, 7 | 128 /* UNLOCK_PI|PRIVATE */, 0, 0);
}

static void pi_worker(void *arg) {
    (void)arg;
    unsigned tid = (unsigned)sys(NR_gettid, 0);
    for (int i = 0; i < PI_ROUNDS; i++) {
        pi_lock(tid);
        long c = pi_counter;
        for (volatile int k = 0; k < 20; k++) {}
        pi_counter = c + 1;
        pi_unlock(tid);
    }
}

static volatile int pi_held, pi_release;

static void pi_holder(void *arg) {
    (void)arg;
    unsigned tid = (unsigned)sys(NR_gettid, 0);
    pi_lock(tid);
    __atomic_store_n(&pi_held, 1, __ATOMIC_RELEASE);
    while (__atomic_load_n(&pi_release, __ATOMIC_ACQUIRE) == 0) {}
    pi_unlock(tid);
}

int cmain(void) {
    char *stacks = (char *)sys(NR_mmap, 0, (u64)STACK * N_BLOCK, 3, 0x22, -1, 0);
    check((i64)stacks > 0, "stacks mapped");
    int started = 0;
    for (int i = 0; i < N_BLOCK; i++) {
        tids[i] = 1;
        if (spawn(stacks + (u64)STACK * (i + 1), blocker, 0, &tids[i]) > 0) started++;
    }
    check(started == N_BLOCK, "200 threads created");
    while (__atomic_load_n(&arrived, __ATOMIC_ACQUIRE) < N_BLOCK) sys(NR_futex, &arrived, 128, -1, 0); // a short sleep (EAGAIN)
    __atomic_store_n(&gate, 1, __ATOMIC_RELEASE);
    sys(NR_futex, &gate, 129 /* WAKE|PRIVATE */, 0x7fffffff);
    for (int i = 0; i < N_BLOCK; i++) join(&tids[i]);
    check(done_count == N_BLOCK, "all 200 blocked threads woke and finished");

    started = 0;
    for (int i = 0; i < N_SPIN; i++) {
        tids[i] = 1;
        if (spawn(stacks + (u64)STACK * (i + 1), spinner, 0, &tids[i]) > 0) started++;
    }
    for (int i = 0; i < N_SPIN; i++) join(&tids[i]);
    check(started == N_SPIN && spinning == N_SPIN, "100 threads spinning at once all ran");

    unsigned me = (unsigned)sys(NR_gettid, 0);
    pi_lock(me);
    check(sys(NR_futex, &pi_word, 6 | 128, 0, 0) == -35, "PI lock: relocking your own lock is EDEADLK");
    pi_unlock(me);
    for (int i = 0; i < N_PI; i++) {
        tids[i] = 1;
        spawn(stacks + (u64)STACK * (i + 1), pi_worker, 0, &tids[i]);
    }
    for (int i = 0; i < N_PI; i++) join(&tids[i]);
    check(pi_counter == N_PI * PI_ROUNDS && pi_word == 0, "PI mutex: 8 threads contend, none lost, lock free after");
    tids[0] = 1;
    spawn(stacks + STACK, pi_holder, 0, &tids[0]);
    while (__atomic_load_n(&pi_held, __ATOMIC_ACQUIRE) == 0) {}
    check(sys(NR_futex, &pi_word, 8 | 128 /* TRYLOCK_PI */, 0, 0) == -11, "PI trylock on a held lock is EAGAIN");
    check(sys(NR_futex, &pi_word, 7 | 128, 0, 0) == -1, "PI unlock by a non-owner is EPERM");
    __atomic_store_n(&pi_release, 1, __ATOMIC_RELEASE);
    join(&tids[0]);

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

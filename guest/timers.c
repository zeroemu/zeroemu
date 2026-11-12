// Freestanding arm64 test of zeroemu's POSIX timers and interval timers:
// expiry signals with their siginfo, periodic timers and overruns, thread
// targets, deletion, and what fork and exec do to them.

typedef unsigned long u64;
typedef long i64;

#define NR_getitimer 102
#define NR_setitimer 103
#define NR_nanosleep 101
#define NR_timer_create 107
#define NR_timer_gettime 108
#define NR_timer_getoverrun 109
#define NR_timer_settime 110
#define NR_timer_delete 111
#define NR_rt_sigaction 134
#define NR_rt_sigprocmask 135
#define NR_rt_sigpending 136
#define NR_rt_sigtimedwait 137
#define NR_tgkill 131
#define NR_getpid 172
#define NR_gettid 178
#define NR_clone 220
#define NR_execve 221
#define NR_mmap 222
#define NR_wait4 260
#define NR_write 64
#define NR_exit 93
#define NR_exit_group 94
#define NR_futex 98

#define EINVAL 22
#define EINTR 4
#define EAGAIN 11
#define EOPNOTSUPP 95
#define SIGRT 40
#define SIGALRM 14
#define SI_TIMER (-2)
#define SI_TKILL (-6)
#define SI_KERNEL 0x80

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

static void sleep_ms(long ms) {
    i64 ts[2] = {ms / 1000, (ms % 1000) * 1000000};
    sys(NR_nanosleep, ts, 0);
}

struct sigaction_k { void *handler; u64 flags; void *restorer; u64 mask; };
struct sigevent_k { u64 value; int signo; int notify; int tid; int pad[11]; };
struct its { i64 int_s, int_ns, val_s, val_ns; };

static u64 bit(int sig) { return 1ul << (sig - 1); }

static volatile int hits, last_code, last_id, last_alarm_code;
static volatile u64 last_value;
static void on_rt(int sig, char *info, void *uc) {
    (void)sig, (void)uc;
    hits++;
    last_code = *(int *)(info + 8);
    last_id = *(int *)(info + 16);
    last_value = *(u64 *)(info + 24);
}
static volatile int alarms;
static void on_alarm(int sig, char *info, void *uc) {
    (void)sig, (void)uc;
    alarms++;
    last_alarm_code = *(int *)(info + 8);
}

static void install(int sig, void (*fn)(int, char *, void *)) {
    struct sigaction_k act = {(void *)fn, 4 /* SA_SIGINFO */, 0, 0};
    sys(NR_rt_sigaction, sig, &act, 0, 8);
}

static void block(u64 mask) { sys(NR_rt_sigprocmask, 0, &mask, 0, 8); }
static void unblock(u64 mask) { sys(NR_rt_sigprocmask, 1, &mask, 0, 8); }

// A thread that waits for its timer as bionic's SIGEV_THREAD thread does.
static char stack[65536] __attribute__((aligned(16)));
static int helper_tid_word;
static volatile int helper_tid, helper_ok, helper_seen_tkill;
static void helper(void *arg) {
    (void)arg;
    helper_tid = (int)sys(NR_gettid);
    u64 set = bit(SIGRT);
    char info[128];
    i64 ts[2] = {5, 0};
    i64 got = sys(NR_rt_sigtimedwait, &set, info, ts, 8);
    helper_ok = got == SIGRT && *(int *)(info + 8) == SI_TIMER && *(u64 *)(info + 24) == 0x77;
    got = sys(NR_rt_sigtimedwait, &set, info, ts, 8);
    helper_seen_tkill = got == SIGRT && *(int *)(info + 8) == SI_TKILL;
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

static int wait_status(i64 pid) {
    int st = 0;
    sys(NR_wait4, pid, &st, 0, 0);
    return st;
}

static int run(void) {
    int id = -1, id2 = -1;

    // Creating and deleting.
    check(sys(NR_timer_create, 1, 0, &id) == 0 && id >= 0, "timer_create with no sigevent");
    check(sys(NR_timer_create, 4, 0, &id2) == -EOPNOTSUPP, "no timers on CLOCK_MONOTONIC_RAW");
    check(sys(NR_timer_create, 99, 0, &id2) == -EINVAL, "an unknown clock is EINVAL");
    struct sigevent_k bad = {0, 200, 0, 0, {0}};
    check(sys(NR_timer_create, 1, &bad, &id2) == -EINVAL, "an impossible signal is EINVAL");
    struct sigevent_k badtid = {0, SIGRT, 4, 999999, {0}};
    check(sys(NR_timer_create, 1, &badtid, &id2) == -EINVAL, "a thread outside the process is EINVAL");
    check(sys(NR_timer_delete, id) == 0, "timer_delete");
    check(sys(NR_timer_delete, id) == -EINVAL, "deleting it twice is EINVAL");
    struct its t = {0, 0, 0, 1000000};
    check(sys(NR_timer_settime, 12345, 0, &t, 0) == -EINVAL, "timer_settime on an unknown id is EINVAL");
    struct its badt = {0, 0, 0, 1000000000};
    sys(NR_timer_create, 1, 0, &id);
    check(sys(NR_timer_settime, id, 0, &badt, 0) == -EINVAL, "nanoseconds of a whole second are EINVAL");
    sys(NR_timer_delete, id);

    // One shot, with the handler seeing si_code, si_tid and si_value.
    install(SIGRT, on_rt);
    struct sigevent_k ev = {0x1234, SIGRT, 0, 0, {0}};
    check(sys(NR_timer_create, 1, &ev, &id) == 0, "timer_create SIGEV_SIGNAL");
    t = (struct its){0, 0, 0, 10000000};
    check(sys(NR_timer_settime, id, 0, &t, 0) == 0, "arm for 10 ms");
    i64 ts[2] = {5, 0};
    i64 slept = sys(NR_nanosleep, ts, 0);
    check(slept == -EINTR && hits == 1, "the signal interrupts a sleep");
    check(last_code == SI_TIMER && last_id == id && last_value == 0x1234, "siginfo: SI_TIMER, the id, the value");
    struct its now = {1, 1, 1, 1};
    check(sys(NR_timer_gettime, id, &now) == 0 && now.val_s == 0 && now.val_ns == 0, "spent: gettime reads zero");

    // Absolute time in the past fires at once.
    hits = 0;
    t = (struct its){0, 0, 0, 1};
    sys(NR_timer_settime, id, 1 /* TIMER_ABSTIME */, &t, 0);
    sleep_ms(20);
    check(hits == 1, "an absolute time in the past fires at once");

    // Periodic, then disarmed: old value comes back; nothing more arrives.
    hits = 0;
    t = (struct its){0, 5000000, 0, 5000000};
    sys(NR_timer_settime, id, 0, &t, 0);
    for (int i = 0; i < 40 && hits < 4; i++) sleep_ms(5);
    check(hits >= 4, "a periodic timer keeps firing");
    sys(NR_timer_gettime, id, &now);
    check(now.int_ns == 5000000, "gettime reports the interval");
    struct its off = {0, 0, 0, 0}, old = {0, 0, 0, 0};
    sys(NR_timer_settime, id, 0, &off, &old);
    check(old.int_ns == 5000000, "disarming returns the old setting");
    sleep_ms(10);
    int settled = hits;
    sleep_ms(30);
    check(hits == settled, "a disarmed timer is silent");

    // Blocked: expiries pile up as overruns.
    block(bit(SIGRT));
    t = (struct its){0, 2000000, 0, 2000000};
    sys(NR_timer_settime, id, 0, &t, 0);
    sleep_ms(30);
    u64 set = bit(SIGRT);
    char info[128];
    check(sys(NR_rt_sigtimedwait, &set, info, ts, 8) == SIGRT && *(int *)(info + 8) == SI_TIMER, "a blocked expiry is pending");
    // The next one, sent once the first was taken, counts what piled up.
    check(sys(NR_rt_sigtimedwait, &set, info, ts, 8) == SIGRT && *(int *)(info + 20) >= 1, "the next expiry reports overruns in si_overrun");
    check(sys(NR_timer_getoverrun, id) >= 1, "and timer_getoverrun agrees");
    sys(NR_timer_settime, id, 0, &off, 0);
    sleep_ms(10);
    i64 nowait[2] = {0, 0};
    sys(NR_rt_sigtimedwait, &set, info, nowait, 8); // anything that slipped in

    // Deleting takes its pending signal with it.
    t = (struct its){0, 0, 0, 1000000};
    sys(NR_timer_settime, id, 0, &t, 0);
    sleep_ms(10);
    u64 pending = 0;
    sys(NR_rt_sigpending, &pending, 8);
    check((pending & bit(SIGRT)) != 0, "the expiry waits while blocked");
    sys(NR_timer_delete, id);
    pending = 0;
    sys(NR_rt_sigpending, &pending, 8);
    check((pending & bit(SIGRT)) == 0, "timer_delete drops the waiting signal");

    // SIGEV_THREAD_ID, the way bionic's SIGEV_THREAD runs; then tgkill to end it.
    helper_tid_word = 1;
    spawn(stack + sizeof stack, helper, 0, &helper_tid_word);
    while (!helper_tid) sleep_ms(1);
    struct sigevent_k te = {0x77, SIGRT, 4, helper_tid, {0}};
    check(sys(NR_timer_create, 1, &te, &id) == 0, "timer_create SIGEV_THREAD_ID");
    t = (struct its){0, 0, 0, 2000000};
    sys(NR_timer_settime, id, 0, &t, 0);
    while (!helper_ok && helper_tid_word) sleep_ms(1);
    check(helper_ok, "the named thread takes it, si_code SI_TIMER");
    sys(NR_timer_delete, id);
    sys(NR_tgkill, sys(NR_getpid), helper_tid, SIGRT);
    while (helper_tid_word) sys(NR_futex, &helper_tid_word, 0, helper_tid_word, 0);
    check(helper_seen_tkill, "tgkill reaches it with si_code SI_TKILL");
    unblock(bit(SIGRT));

    // setitimer.
    install(SIGALRM, on_alarm);
    i64 iv[4] = {0, 5000, 0, 5000};
    check(sys(NR_setitimer, 0, iv, 0) == 0, "setitimer ITIMER_REAL");
    for (int i = 0; i < 40 && alarms < 2; i++) sleep_ms(5);
    check(alarms >= 2 && last_alarm_code == SI_KERNEL, "SIGALRM repeats, si_code SI_KERNEL");
    i64 cur[4] = {9, 9, 9, 9};
    check(sys(NR_getitimer, 0, cur) == 0 && cur[1] == 5000, "getitimer reads the interval");
    i64 zero[4] = {0, 0, 0, 0}, before[4] = {0, 0, 0, 0};
    check(sys(NR_setitimer, 0, zero, before) == 0 && before[1] == 5000, "setitimer returns the old value");
    sleep_ms(10);
    int quiet = alarms;
    sleep_ms(20);
    check(alarms == quiet, "and zero stops it");
    i64 badv[4] = {0, 1000000, 0, 0};
    check(sys(NR_setitimer, 0, badv, 0) == -EINVAL, "a whole second of microseconds is EINVAL");
    check(sys(NR_setitimer, 9, zero, 0) == -EINVAL, "an unknown itimer is EINVAL");
    i64 prof[4] = {1, 0, 2, 0};
    check(sys(NR_setitimer, 2, prof, 0) == 0 && sys(NR_getitimer, 2, cur) == 0 && cur[0] == 1 && cur[2] == 2, "ITIMER_PROF stores its value");
    sys(NR_setitimer, 2, zero, 0);

    // fork: the child has no timers. exec: POSIX timers are gone.
    struct sigevent_k fe = {1, SIGRT, 0, 0, {0}};
    sys(NR_timer_create, 1, &fe, &id);
    i64 pid = sys(NR_clone, 17, 0, 0, 0, 0);
    if (pid == 0) {
        struct its q;
        sys(NR_exit, sys(NR_timer_gettime, id, &q) == -EINVAL ? 0 : 1);
    }
    check(wait_status(pid) == 0, "fork does not inherit timers");
    sys(NR_timer_delete, id);

    pid = sys(NR_clone, 17, 0, 0, 0, 0);
    if (pid == 0) {
        int kid = -1;
        sys(NR_timer_create, 1, &fe, &kid);
        t = (struct its){0, 5000000, 0, 5000000};
        sys(NR_timer_settime, kid, 0, &t, 0);
        const char *argv[] = {"sleep", "0.1", 0};
        const char *envp[] = {0};
        i64 e = sys(NR_execve, "/system/bin/sleep", argv, envp);
        sys(NR_exit, e == -2 /* ENOENT: no system image */ ? 77 : 99);
    }
    int st = wait_status(pid);
    if ((st >> 8) == 77) {
        puts_("skip exec drops POSIX timers: no system image\n");
    } else {
        check(st == 0, "exec drops POSIX timers");
    }

    puts_(failures ? "SOME CHECKS FAILED\n" : "all checks passed\n");
    return failures;
}

void __attribute__((noreturn)) cstart(void) {
    sys(NR_exit_group, run());
    __builtin_unreachable();
}

__asm__(".global _start\n_start:\n bl cstart\n");

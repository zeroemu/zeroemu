// Freestanding arm64 test of things zeroemu once got wrong where ordinary programs
// could tell: each check is what Linux does.
typedef unsigned long u64;
typedef long i64;
typedef unsigned int u32;

#define NR_ioctl 29
#define NR_symlinkat 36
#define NR_ftruncate 46
#define NR_openat 56
#define NR_close 57
#define NR_pipe2 59
#define NR_getdents64 61
#define NR_read 63
#define NR_write 64
#define NR_pread64 67
#define NR_newfstatat 79
#define NR_fstat 80
#define NR_utimensat 88
#define NR_exit 93
#define NR_exit_group 94
#define NR_futex 98
#define NR_nanosleep 101
#define NR_setitimer 103
#define NR_kill 129
#define NR_tkill 130
#define NR_rt_sigaction 134
#define NR_rt_sigprocmask 135
#define NR_setresuid 147
#define NR_setresgid 149
#define NR_getpid 172
#define NR_gettid 178
#define NR_munmap 215
#define NR_madvise 233
#define NR_mremap 216
#define NR_clone 220
#define NR_mmap 222
#define NR_mprotect 226
#define NR_mincore 232
#define NR_madvise 233
#define NR_wait4 260
#define NR_socketpair 199

#define BINDER_WRITE_READ 0xc0306201
#define BINDER_SET_CONTEXT_MGR 0x40046207
#define BC_TRANSACTION_SG 0x40486311
#define BC_ENTER_LOOPER 0x630c
#define BR_FAILED_REPLY 0x7211
#define BR_REPLY 0x80407203
#define TYPE_PTR 0x70742a85

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
static int seq(const char *a, const char *b, u64 n) { while (n--) if (*a++ != *b++) return 0; return 1; }
static int streq(const char *a, const char *b) { while (*a && *a == *b) a++, b++; return *a == *b; }
static void nap_ms(i64 ms) { i64 ts[2] = {ms / 1000, (ms % 1000) * 1000000}; sys(NR_nanosleep, ts, 0); }

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
        "svc #0\n" "cbnz x0, 1f\n" "mov x0, x20\n" "blr x19\n" "mov x0, #0\n" "mov x8, #93\n" "svc #0\n" "1:\n"
        : "+r"(x0) : "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x8), "r"(x19), "r"(x20) : "memory", "x30");
    return x0;
}

static i64 fork_(void) { return sys(NR_clone, 17 /* SIGCHLD */, 0, 0, 0, 0); }
// Wait up to `ms` for child; returns wait status, or -1 if it had to be killed.
static i64 reap(i64 pid, i64 ms) {
    int st = 0;
    for (i64 t = 0; t < ms; t += 20) {
        if (sys(NR_wait4, pid, &st, 1 /* WNOHANG */, 0) == pid) return st;
        nap_ms(20);
    }
    sys(NR_kill, pid, 9);
    sys(NR_wait4, pid, &st, 0, 0);
    return -1;
}

static volatile int handled;
static void handler(int s) { (void)s; handled++; }

// Spins in user code, with no syscall, until a signal's handler says to stop.
static volatile int spin_tid, spin_stop, spin_done;
static void spin_handler(int s) { (void)s; spin_stop = 1; }
static void spin_on(void *arg) {
    (void)arg;
    spin_tid = (int)sys(NR_gettid);
    while (!spin_stop) {}
    spin_done = 1;
}

// Round after round, lets in with sigprocmask a SIGUSR1 that the main thread sends to
// the whole process at about the same time, while no other thread lets it in. Then
// it spins in user code until the handler has run: Linux delivers it on the way back
// from sigprocmask, or wakes this thread for it (complete_signal, kernel/signal.c).
// A round where it is still waiting after that long counts as missed.
#define RACE_ROUNDS 2000
static volatile int race_round, race_done, race_seen, race_missed;
static void race_handler(int s) { (void)s; race_seen++; }
static void race_on(void *arg) {
    (void)arg;
    u64 usr1 = 1UL << 9;
    for (int i = 1; i <= RACE_ROUNDS; i++) {
        while (race_round != i) {
            if (race_round < 0) return;
        }
        // A different moment each round, against the main thread's kill.
        for (int n = (i * 37) % 2000; n > 0; n--) __asm__ volatile("" ::: "memory");
        sys(NR_rt_sigprocmask, 1 /* SIG_UNBLOCK */, &usr1, 0, 8);
        for (long n = 0; race_seen != i && n < 50000000; n++) {}
        if (race_seen != i) {
            race_missed++;
            sys(NR_getpid); // takes it on the way back
        }
        sys(NR_rt_sigprocmask, 0 /* SIG_BLOCK */, &usr1, 0, 8);
        race_done = i;
    }
}

// Reads a page in user code, with no syscall, until it is told the page was dropped.
// Then whether it reads the zeros MADV_DONTNEED left (1) or the old value (2).
static volatile int *watched;
static volatile int watch_started, watch_dropped, watch_result;
static void watch(void *arg) {
    (void)arg;
    watch_started = 1;
    for (;;) {
        int dropped = watch_dropped;
        __asm__ volatile("dmb ish" ::: "memory");
        int v = *watched;
        if (dropped) {
            watch_result = v == 0 ? 1 : 2;
            return;
        }
    }
}

// The condition flags after a syscall (gettid) or a page fault (a write to `p`), set
// to `in` just before.
static u64 flags_through_syscall(u64 in) {
    u64 out;
    __asm__ volatile("msr nzcv, %1\n" "mov x8, #178\n" "svc #0\n" "mrs %0, nzcv\n" : "=&r"(out) : "r"(in) : "x0", "x8", "memory", "cc");
    return out;
}
static u64 flags_through_fault(u64 in, volatile char *p) {
    u64 out;
    __asm__ volatile("msr nzcv, %1\n" "strb wzr, [%2]\n" "mrs %0, nzcv\n" : "=&r"(out) : "r"(in), "r"(p) : "memory", "cc");
    return out;
}

static int fa, fb;
static volatile i64 w1_ret = 99, w2_ret = 99;
static void waiter1(void *arg) { (void)arg; i64 ts[2] = {0, 300000000}; w1_ret = sys(NR_futex, &fa, 0 /* WAIT */, 0, ts); }
static void waiter2(void *arg) { (void)arg; i64 ts[2] = {3, 0}; w2_ret = sys(NR_futex, &fb, 0 /* WAIT */, 0, ts); }
static int fc;
static volatile i64 w3_ret = 99;
static void waiter3(void *arg) { (void)arg; w3_ret = sys(NR_futex, &fc, 9 /* WAIT_BITSET */, 0, 0, 0, 1); }
// Waits for a value the word never holds, over and over: each FUTEX_WAIT is EAGAIN.
static volatile int rq_word = 1, rq_dst, rq_stop;
static void rq_noise(void *arg) { (void)arg; while (!rq_stop) sys(NR_futex, &rq_word, 128 /* WAIT_PRIVATE */, 0); }
static volatile int wz, pi_word;
static volatile i64 wz_ret = 99, pi_ret = 99;
static void wz_waiter(void *arg) { (void)arg; i64 ts[2] = {2, 0}; wz_ret = sys(NR_futex, &wz, 128 /* WAIT_PRIVATE */, 0, ts); }
static void pi_waiter(void *arg) {
    (void)arg;
    pi_ret = sys(NR_futex, &pi_word, 6 | 128 /* LOCK_PI_PRIVATE */, 0, 0);
    if (pi_ret == 0) sys(NR_futex, &pi_word, 7 | 128 /* UNLOCK_PI_PRIVATE */);
}
static char stacks[6][16384] __attribute__((aligned(16)));
static int ctid[6];
// Waits up to a second for the threads spawned with these ctids, set nonzero first, to
// exit: CLONE_CHILD_CLEARTID zeroes each.
static int gone(int from, int to) {
    for (int ms = 0; ms < 1000; ms += 5) {
        int left = 0;
        for (int n = from; n < to; n++) left |= ctid[n];
        if (!left) return 1;
        nap_ms(5);
    }
    return 0;
}

// MADV_DONTNEED of `pages` pages, one of which another thread is reading in user code:
// once madvise returns, that thread no longer reads the old page. Linux's
// flush_tlb_page and flush_tlb_range (arch/arm64/include/asm/tlbflush.h) reach every
// CPU and wait for them.
static void dropped_everywhere(u64 pages, int n, const char *name) {
    char *m = (char *)sys(NR_mmap, 0, 4 * 4096, 3, 0x22, -1, 0);
    watched = (volatile int *)(m + 4096);
    *watched = 1;
    watch_started = watch_dropped = watch_result = 0;
    spawn(stacks[n] + 16384, watch, 0, &ctid[n]);
    for (int i = 0; i < 200 && !watch_started; i++) nap_ms(5);
    nap_ms(20); // reading it through its TLB by now
    sys(NR_madvise, (u64)watched, pages * 4096, 4 /* MADV_DONTNEED */);
    watch_dropped = 1;
    for (int i = 0; i < 200 && !watch_result; i++) nap_ms(5);
    check(watch_result == 1, name);
}

struct bwr { u64 wsize, wcons, wbuf, rsize, rcons, rbuf; };
// binder_buffer_object: a scatter-gather buffer, and where in its parent its address goes.
struct ptr_obj { u32 type, flags; u64 buffer, length, parent, parent_offset; };
static volatile u64 canary[2] = {0x1122334455667788, 0x1122334455667788};

static i64 bw(int fd, void *w, u64 wn, void *r, u64 rn, u64 *got) {
    struct bwr b = { wn, 0, (u64)w, rn, 0, (u64)r };
    i64 ret = sys(NR_ioctl, fd, BINDER_WRITE_READ, &b);
    if (got) *got = b.rcons;
    return ret;
}

// The d_type getdents64 gave `name`, or -1.
static int dtype_of(char *buf, i64 n, const char *name) {
    for (i64 off = 0; off < n; off += *(unsigned short *)(buf + off + 16)) {
        if (streq(buf + off + 19, name)) return *(unsigned char *)(buf + off + 18);
    }
    return -1;
}

// `pre`, `v` in decimal and `post`, in `out`.
static char *num_path(char *out, const char *pre, i64 v, const char *post) {
    char digits[20], *p = out;
    int nd = 0;
    while (*pre) *p++ = *pre++;
    do digits[nd++] = (char)('0' + v % 10); while ((v /= 10) > 0);
    while (nd) *p++ = digits[--nd];
    while (*post) *p++ = *post++;
    *p = 0;
    return out;
}

// A number in a /proc file: after `tag` if there is one, or else the `nth` field
// (from 0) of its first line.
static char pbuf[4096] __attribute__((aligned(4096)));
static i64 proc_num(const char *path, const char *tag, int nth) {
    i64 fd = sys(NR_openat, -100, path, 0, 0);
    i64 n = fd < 0 ? -1 : sys(NR_read, fd, pbuf, sizeof pbuf - 1);
    sys(NR_close, fd);
    if (n <= 0) return -1;
    pbuf[n] = 0;
    char *p = pbuf;
    if (tag) {
        for (u64 len = slen(tag); *p && !(*p == *tag && seq(p, tag, len)); p++) {}
        if (!*p) return -1;
        p += slen(tag);
    } else {
        for (; nth > 0 && *p; p++) if (*p == ' ') nth--;
    }
    while (*p == ' ' || *p == '\t') p++;
    i64 v = 0;
    for (; *p >= '0' && *p <= '9'; p++) v = v * 10 + (*p - '0');
    return v;
}
static i64 resident(void) { return proc_num("/proc/self/statm", 0, 1); }

// Whether `want` is among the commands the driver returns next.
static u32 rbuf[256];
static int saw(int fd, u32 want) {
    for (int tries = 0; tries < 20; tries++) {
        u64 got = 0;
        if (bw(fd, 0, 0, rbuf, sizeof rbuf, &got) < 0) return 0;
        char *p = (char *)rbuf, *end = p + got;
        while (p < end) {
            u32 cmd = *(u32 *)p;
            if (cmd == want) return 1;
            if (cmd == BR_REPLY || cmd == BR_FAILED_REPLY) return 0;
            p += 4 + ((cmd >> 16) & 0x3fff);
        }
    }
    return 0;
}

int cmain(void) {
    // --- FIONREAD on a pipe
    int p[2]; sys(NR_pipe2, p, 0); sys(NR_write, p[1], "hello", 5);
    int avail = -1;
    check(sys(NR_ioctl, p[0], 0x541b, &avail) == 0 && avail == 5, "FIONREAD on a pipe says what is waiting");

    // --- a unix stream takes what fits, and says how much is waiting
    int sv[2];
    sys(NR_socketpair, 1, 1 | 04000 /* SOCK_STREAM | SOCK_NONBLOCK */, 0, sv);
    static char big[200000];
    i64 first = sys(NR_write, sv[0], big, sizeof big);
    i64 second = sys(NR_write, sv[0], big, 100000);
    check(first == (i64)sizeof big && second > 0 && second < 100000, "a nonblocking stream write takes the part there is room for");
    avail = -1;
    check(sys(NR_ioctl, sv[1], 0x541b, &avail) == 0 && avail == first + second, "FIONREAD on a unix socket");
    sys(NR_close, sv[0]); sys(NR_close, sv[1]);

    // --- mtime follows a write
    i64 fd = sys(NR_openat, -100, "/tmp/f", 0102 /* O_RDWR|O_CREAT */, 0600);
    i64 times[4] = {1000, 0, 1000, 0};
    sys(NR_utimensat, fd, 0, times, 0);
    char st[128]; sys(NR_fstat, fd, st);
    int set = *(i64 *)(st + 88) == 1000;
    sys(NR_write, fd, "hello", 5);
    sys(NR_fstat, fd, st);
    check(set && *(i64 *)(st + 88) > 1700000000, "a write moves a file's mtime to now");
    sys(NR_close, fd);
    i64 dir = sys(NR_openat, -100, "/tmp", 0, 0);
    sys(NR_utimensat, dir, 0, times, 0);
    sys(NR_fstat, dir, st);
    set = *(i64 *)(st + 88) == 1000;
    sys(NR_close, sys(NR_openat, -100, "/tmp/g", 0102, 0600));
    sys(NR_fstat, dir, st);
    check(set && *(i64 *)(st + 88) > 1700000000, "making a file moves its directory's mtime");

    // --- O_NOFOLLOW on a symlink
    sys(NR_symlinkat, "/tmp/f", -100, "/tmp/l");
    check(sys(NR_openat, -100, "/tmp/l", 0100000 /* O_NOFOLLOW (arm64) */, 0) == -40, "open(symlink, O_NOFOLLOW) is ELOOP");
    check(sys(NR_openat, -100, "/tmp/l", 0, 0) >= 0, "and without it the link is followed");

    // --- lengths that can't be
    check(sys(NR_mmap, 0, -1L, 1, 0x22, -1, 0) == -12, "mmap of (size_t)-1 bytes is ENOMEM");
    i64 m = sys(NR_mmap, 0, 4 * 4096, 3, 0x22, -1, 0);
    i64 pid = fork_();
    if (pid == 0) sys(NR_exit_group, sys(NR_mremap, m, -1L, 4096, 0, 0) == -14 ? 0 : 3);
    check(reap(pid, 3000) == 0, "mremap with an old length of (size_t)-1 is EFAULT, and unmaps nothing");

    // --- prefaulting maps pages without touching them
    unsigned char vec[4];
    i64 pm = sys(NR_mmap, 0, 4 * 4096, 3, 0x22, -1, 0);
    check(sys(NR_madvise, pm + 4096, 2 * 4096, 23 /* MADV_POPULATE_WRITE */) == 0 && sys(NR_mincore, pm, 4 * 4096, vec) == 0
          && !vec[0] && vec[1] && vec[2] && !vec[3], "MADV_POPULATE_WRITE maps the pages it is given, and only those");
    i64 pp = sys(NR_mmap, 0, 2 * 4096, 3, 0x8022 /* MAP_POPULATE */, -1, 0);
    check(sys(NR_mincore, pp, 2 * 4096, vec) == 0 && vec[0] && vec[1], "MAP_POPULATE maps the pages at once");
    i64 pn = sys(NR_mmap, 0, 2 * 4096, 3, 0x18022 /* MAP_POPULATE | MAP_NONBLOCK */, -1, 0);
    check(sys(NR_mincore, pn, 2 * 4096, vec) == 0 && !vec[0] && !vec[1], "MAP_NONBLOCK cancels MAP_POPULATE");
    // Linux reads these in too (FOLL_FORCE in populate_vma_page_range, mm/gup.c), but
    // MADV_POPULATE_READ wants PROT_READ.
    i64 px = sys(NR_mmap, 0, 2 * 4096, 4 /* PROT_EXEC */, 0x8022 /* MAP_POPULATE */, -1, 0);
    check(sys(NR_mincore, px, 2 * 4096, vec) == 0 && vec[0] && vec[1], "MAP_POPULATE maps an execute-only mapping");
    i64 pw = sys(NR_mmap, 0, 2 * 4096, 2 /* PROT_WRITE */, 0x8021 /* MAP_POPULATE | MAP_SHARED */, -1, 0);
    check(sys(NR_mincore, pw, 2 * 4096, vec) == 0 && vec[0] && vec[1], "MAP_POPULATE maps a shared write-only mapping");
    check(sys(NR_madvise, px, 4096, 22) == -22 && sys(NR_madvise, pw, 4096, 22) == -22, "MADV_POPULATE_READ of either is EINVAL");
    sys(NR_mprotect, pm, 4096, 0);
    check(sys(NR_madvise, pm, 4096, 22 /* MADV_POPULATE_READ */) == -22, "MADV_POPULATE_READ of PROT_NONE is EINVAL");
    sys(NR_munmap, pm + 3 * 4096, 4096);
    check(sys(NR_madvise, pm + 2 * 4096, 2 * 4096, 22) == -12, "MADV_POPULATE_READ over a hole is ENOMEM");

    // --- nanosleep's remaining time
    i64 act[4] = {(i64)handler, 0, 0, 0};
    sys(NR_rt_sigaction, 14 /* SIGALRM */, act, 0, 8);
    i64 itv[4] = {0, 0, 0, 100000}; // one shot, 100 ms
    sys(NR_setitimer, 0, itv, 0);
    i64 req[2] = {1, 0}, rem[2] = {777, 777};
    i64 r = sys(NR_nanosleep, req, rem);
    check(r == -4 && rem[0] == 0 && rem[1] > 500000000 && rem[1] < 1000000000, "an interrupted nanosleep says how long was left");

    // --- a handler installed with a junk sa_restorer and no SA_RESTORER flag
    pid = fork_();
    if (pid == 0) {
        i64 a2[4] = {(i64)handler, 0, 0x7654321000, 0};
        sys(NR_rt_sigaction, 10 /* SIGUSR1 */, a2, 0, 8);
        sys(NR_tkill, sys(NR_gettid), 10);
        sys(NR_exit_group, handled ? 0 : 3);
    }
    check(reap(pid, 3000) == 0, "sa_restorer is ignored without SA_RESTORER");

    // --- a blocked signal runs its handler as soon as it is unblocked: Linux delivers it
    // on the way back from sigprocmask, before the next instruction
    handled = 0;
    i64 usr1[4] = {(i64)handler, 0, 0, 0};
    sys(NR_rt_sigaction, 10 /* SIGUSR1 */, usr1, 0, 8);
    u64 block = 1UL << 9, old = 0;
    sys(NR_rt_sigprocmask, 0 /* SIG_BLOCK */, &block, &old, 8);
    sys(NR_tkill, sys(NR_gettid), 10);
    int before = handled;
    sys(NR_rt_sigprocmask, 2 /* SIG_SETMASK */, &old, 0, 8);
    int after = handled;
    check(before == 0 && after == 1, "a pending signal runs once unblocked, before sigprocmask returns");

    // --- a signal reaches a thread that spins in user code and never makes a syscall
    i64 usr2[4] = {(i64)spin_handler, 0, 0, 0};
    sys(NR_rt_sigaction, 12 /* SIGUSR2 */, usr2, 0, 8);
    spawn(stacks[2] + 16384, spin_on, 0, &ctid[2]);
    for (int i = 0; i < 200 && !spin_tid; i++) nap_ms(5);
    nap_ms(20); // well into its loop
    sys(NR_tkill, spin_tid, 12);
    for (int i = 0; i < 200 && !spin_done; i++) nap_ms(5);
    check(spin_done, "a signal interrupts a thread spinning in user code");

    // --- a signal sent to the process reaches the one thread that lets it in, even as
    // it does so: Linux changes a mask, and picks a thread for a process's signal by
    // its mask, under the same lock (kernel/signal.c)
    i64 race_act[4] = {(i64)race_handler, 0, 0, 0};
    sys(NR_rt_sigaction, 10 /* SIGUSR1 */, race_act, 0, 8);
    u64 race_old = 0;
    sys(NR_rt_sigprocmask, 0 /* SIG_BLOCK */, &block, &race_old, 8); // the new thread's too
    spawn(stacks[5] + 16384, race_on, 0, &ctid[5]);
    i64 self_pid = sys(NR_getpid);
    for (int i = 1; i <= RACE_ROUNDS && race_missed < 4; i++) {
        race_round = i;
        sys(NR_kill, self_pid, 10);
        while (race_done != i) {}
    }
    race_round = -1;
    sys(NR_rt_sigprocmask, 2 /* SIG_SETMASK */, &race_old, 0, 8);
    check(race_missed == 0 && race_seen == RACE_ROUNDS, "a process's signal reaches the thread letting it in as it is sent");

    // --- the condition flags come back from a syscall and a page fault as they went in:
    // Linux's kernel_exit puts back the PSTATE the exception saved (arch/arm64/kernel/entry.S)
    char *fresh = (char *)sys(NR_mmap, 0, 16 * 4096, 3, 0x22, -1, 0);
    int flags_kept = 1;
    for (u64 f = 0; f < 16; f++) {
        flags_kept &= flags_through_syscall(f << 28) == f << 28;
        flags_kept &= flags_through_fault(f << 28, fresh + f * 4096) == f << 28;
    }
    check(flags_kept, "the condition flags survive a syscall and a page fault");

    // --- pages dropped are gone for every thread when madvise returns
    dropped_everywhere(1, 3, "another thread stops reading a page MADV_DONTNEED dropped");
    dropped_everywhere(2, 4, "and one of two pages");

    // --- an exclusive load across a 16-byte boundary
    pid = fork_();
    if (pid == 0) {
        static char buf[32] __attribute__((aligned(16)));
        register char *x0 __asm__("x0") = buf + 14;
        __asm__ volatile("ldxr w1, [x0]\n clrex" : : "r"(x0) : "x1", "memory");
        sys(NR_exit_group, 0);
    }
    i64 status = reap(pid, 3000);
    // Some CPUs allow it; none may spin on it.
    check(status == 0 || (status & 0x7f) == 7, "a misaligned exclusive load is SIGBUS, not a loop");

    // --- FUTEX_REQUEUE, then the requeued waiter times out
    spawn(stacks[0] + 16384, waiter1, 0, &ctid[0]);
    nap_ms(60);
    i64 moved = sys(NR_futex, &fa, 3 /* REQUEUE */, 0, 1, &fb);
    nap_ms(400); // waiter 1 has timed out by now
    spawn(stacks[1] + 16384, waiter2, 0, &ctid[1]);
    nap_ms(100);
    i64 woke = sys(NR_futex, &fb, 1 /* WAKE */, 1);
    nap_ms(300);
    // FUTEX_REQUEUE returns the waiters it woke and moved (futex_requeue in kernel/futex/requeue.c).
    check(moved == 1, "FUTEX_REQUEUE counts the waiter it moved");
    check(w1_ret == -110 && woke == 1 && w2_ret == 0, "a requeued waiter that timed out doesn't take a later wake");
    sys(NR_futex, &fb, 1, 10);
    nap_ms(50);

    // --- FUTEX_WAKE_BITSET wakes only the waiters it shares a bit with
    spawn(stacks[0] + 16384, waiter3, 0, &ctid[0]);
    nap_ms(60);
    i64 none = sys(NR_futex, &fc, 10 /* WAKE_BITSET */, 1, 0, 0, 2);
    i64 one = sys(NR_futex, &fc, 10, 1, 0, 0, 3);
    nap_ms(100);
    check(none == 0 && one == 1 && w3_ret == 0, "FUTEX_WAKE_BITSET wakes only waiters with a bit in common");
    sys(NR_futex, &fc, 1, 10);
    nap_ms(50);

    // --- FUTEX_REQUEUE moves only waiters that sleep. Linux queues a FUTEX_WAIT only
    // once the word holds its value (futex_wait_setup in kernel/futex/waitwake.c), so
    // the requeue below never moves the noise threads' waits, and the wake behind it
    // finds nobody. ART signals a condition variable this way: a stale wait moved in a
    // sleeper's place loses the sleeper's wakeup.
    for (int n = 0; n < 3; n++) {
        ctid[n] = -1;
        spawn(stacks[n] + 16384, rq_noise, 0, &ctid[n]);
    }
    nap_ms(20);
    i64 rq_moved = 0, rq_woke = 0;
    for (int i = 0; i < 20000; i++) {
        rq_moved += sys(NR_futex, &rq_word, 3 | 128 /* REQUEUE_PRIVATE */, 0, 1, &rq_dst);
        rq_woke += sys(NR_futex, &rq_dst, 1 | 128 /* WAKE_PRIVATE */, 0x7fffffff);
    }
    rq_stop = 1;
    check(gone(0, 3) && rq_moved == 0 && rq_woke == 0, "FUTEX_REQUEUE never moves a FUTEX_WAIT whose value was stale");

    // --- futex arguments Linux refuses or reads its own way (kernel/futex/core.c,
    // waitwake.c, requeue.c, syscalls.c)
    check(sys(NR_futex, (u64)&rq_word + 1, 1 | 128, 1) == -22 && sys(NR_futex, &rq_word, 3 | 128, 0, 1, (u64)&rq_dst + 2) == -22,
          "a futex word that isn't aligned is EINVAL");
    check(sys(NR_futex, &rq_word, 10 | 128 /* WAKE_BITSET */, 1, 0, 0, 0) == -22, "FUTEX_WAKE_BITSET with no bits is EINVAL");
    check(sys(NR_futex, &rq_word, 3 | 128, -1, 1, &rq_dst) == -22 && sys(NR_futex, &rq_word, 3 | 128, 0, 0xffffffffL, &rq_dst) == -22
          && sys(NR_futex, &rq_word, 3 | 128, 0, 0x100000000L, &rq_dst) == 0, "FUTEX_REQUEUE's counts are ints, the second in the timeout's low half");
    ctid[0] = -1;
    spawn(stacks[0] + 16384, wz_waiter, 0, &ctid[0]);
    nap_ms(60);
    i64 wz_rt = sys(NR_futex, &wz, 1 | 128 | 256 /* CLOCK_REALTIME */, 1);
    nap_ms(20);
    i64 wz_still = wz_ret;
    check(wz_rt == -38 && wz_still == 99, "FUTEX_CLOCK_REALTIME on FUTEX_WAKE is ENOSYS, and wakes nobody");
    i64 wz_woke = sys(NR_futex, &wz, 1 | 128, 0);
    check(gone(0, 1) && wz_woke == 1 && wz_ret == 0, "FUTEX_WAKE of 0 wakes one, as on Linux");
    check(sys(NR_futex, &rq_word, 0 | 128 | 256, 0 /* not its value */, 0) == -38 && sys(NR_futex, &rq_word, 3 | 128 | 256, 0, 1, &rq_dst) == -38
          && sys(NR_futex, &rq_word, 9 | 128 | 256, 0, 0, 0, -1) == -11,
          "FUTEX_CLOCK_REALTIME is ENOSYS but on the calls whose clock the caller picks");
    i64 bad_ts[2] = {0, 2000000000};
    check(sys(NR_futex, &rq_word, 0 | 128 | 256, 0, 8 /* not mapped */) == -14 && sys(NR_futex, &rq_word, 0 | 128 | 256, 0, bad_ts) == -22,
          "and the timeout is read before that, as on Linux");
    check(sys(NR_futex, &rq_word, 1 | 128 | 0x200, 1) == -38, "a futex op with a bit Linux doesn't know is ENOSYS");
    // A word whose page isn't in yet: futex_wait faults the page in without its bucket
    // locked, then reads the word again.
    char *cold = (char *)sys(NR_mmap, 0, 2 * 4096, 3, 0x22, -1, 0);
    char *noprot = (char *)sys(NR_mmap, 0, 4096, 0, 0x22, -1, 0);
    i64 cf = sys(NR_openat, -100, "/tmp/futex-word", 0102 /* O_RDWR|O_CREAT */, 0600);
    int fw = 0x12345678;
    sys(NR_write, cf, &fw, 4);
    char *fm = (char *)sys(NR_mmap, 0, 4096, 1, 2 /* MAP_PRIVATE */, cf, 0);
    i64 ten_ms[2] = {0, 10000000};
    check(sys(NR_futex, cold, 128, 1, 0) == -11 && sys(NR_futex, cold + 4096, 128, 0, ten_ms) == -110
          && sys(NR_futex, fm, 128, 0x12345678, ten_ms) == -110 && sys(NR_futex, noprot, 128, 0, 0) == -14,
          "FUTEX_WAIT reads a word whose page isn't in yet, and EFAULT where it can't be read");
    sys(NR_close, cf);
    check(sys(NR_futex, &pi_word, 6 | 128, 0, 0) == 0, "FUTEX_LOCK_PI takes a free lock");
    ctid[0] = -1;
    spawn(stacks[0] + 16384, pi_waiter, 0, &ctid[0]);
    nap_ms(60);
    i64 pi_requeued = sys(NR_futex, &pi_word, 3 | 128, 1, 1, &rq_dst);
    i64 pi_waiting = pi_ret;
    sys(NR_futex, &pi_word, 7 | 128 /* UNLOCK_PI */);
    check(pi_requeued == -22 && pi_waiting == 99 && gone(0, 1) && pi_ret == 0 && pi_word == 0,
          "FUTEX_REQUEUE leaves a PI lock's waiter alone (EINVAL), and it gets the lock at unlock");

    // --- binder: a buffer's pointer goes inside its parent, not wherever the sender says
    int mgr = (int)sys(NR_openat, -100, "/dev/binder", 02000002, 0);
    u64 area = (u64)sys(NR_mmap, 0, 128 * 1024, 1, 2, mgr, 0);
    sys(NR_ioctl, mgr, BINDER_SET_CONTEXT_MGR, 0);
    u32 enter = BC_ENTER_LOOPER;
    bw(mgr, &enter, 4, 0, 0, 0);
    pid = fork_();
    if (pid == 0) {
        int b = (int)sys(NR_openat, -100, "/dev/binder", 02000002, 0);
        sys(NR_mmap, 0, 128 * 1024, 1, 2, b, 0);
        static char parent_buf[16], child_buf[16];
        // The manager's first buffer starts its area: two objects, two offsets, then the
        // parent's bytes.
        u64 parent_at = area + 80 + 16;
        struct ptr_obj objs[2] = {
            { TYPE_PTR, 0, (u64)parent_buf, 16, 0, 0 },
            { TYPE_PTR, 1 /* HAS_PARENT */, (u64)child_buf, 16, 0, (u64)&canary[0] - parent_at },
        };
        u64 offs[2] = { 0, 40 };
        struct { u32 cmd; u64 target, cookie; u32 code, flags; int pid; u32 euid; u64 data_size, offsets_size, buffer, offsets, buffers_size; } __attribute__((packed)) w;
        memset(&w, 0, sizeof w);
        w.cmd = BC_TRANSACTION_SG;
        w.code = 1;
        w.data_size = sizeof objs;
        w.offsets_size = sizeof offs;
        w.buffer = (u64)objs;
        w.offsets = (u64)offs;
        w.buffers_size = 32;
        bw(b, &w, sizeof w, 0, 0, 0);
        sys(NR_exit_group, saw(b, BR_FAILED_REPLY) ? 0 : 3);
    }
    status = reap(pid, 3000);
    check(status == 0 && canary[0] == 0x1122334455667788, "binder refuses a fixup outside its parent buffer");

    // --- /proc: what stat and readdir say of a file, which they find out without making it
    char pst[128];
    check(sys(NR_newfstatat, -100, "/proc/self/status", pst, 0) == 0 && *(u32 *)(pst + 16) == 0100444 && *(i64 *)(pst + 48) == 0,
          "/proc/self/status is a read-only regular file of size 0");
    check(sys(NR_newfstatat, -100, "/proc/self/oom_score_adj", pst, 0) == 0 && *(u32 *)(pst + 16) == 0100644, "/proc/self/oom_score_adj is writable");
    check(sys(NR_newfstatat, -100, "/proc/self/fd", pst, 0) == 0 && (*(u32 *)(pst + 16) & 0170000) == 040000, "/proc/self/fd is a directory");
    check(sys(NR_newfstatat, -100, "/proc/999999/status", pst, 0) == -2, "a process that isn't there has no status");
    static char dents[8192];
    i64 pd = sys(NR_openat, -100, "/proc/self", 0, 0);
    i64 dn = sys(NR_getdents64, pd, dents, sizeof dents);
    check(dtype_of(dents, dn, "status") == 8 && dtype_of(dents, dn, "fd") == 4 && dtype_of(dents, dn, "exe") == 10 && dtype_of(dents, dn, "task") == 4,
          "readdir of /proc/self gives each entry's type");
    sys(NR_close, pd);
    check(sys(NR_newfstatat, -100, "/proc/self/nonesuch", pst, 0) == -2 && sys(NR_newfstatat, -100, "/proc/nonesuch", pst, 0) == -2, "names /proc doesn't have aren't there");
    check(sys(NR_newfstatat, -100, "/proc/thread-self/stat", pst, 0) == 0 &&
          sys(NR_newfstatat, -100, "/proc/sys/kernel", pst, 0) == 0 && sys(NR_newfstatat, -100, "/proc/pressure/memory", pst, 0) == 0 &&
          sys(NR_newfstatat, -100, "/proc/meminfo", pst, 0) == 0, "a thread's directory, /proc/sys, /proc/pressure and /proc/meminfo are found");
    char path[64];
    i64 me = sys(NR_gettid);
    check(sys(NR_newfstatat, -100, num_path(path, "/proc/self/task/", me, "/stat"), pst, 0) == 0 &&
          sys(NR_newfstatat, -100, num_path(path, "/proc/self/task/0", me, "/stat"), pst, 0) == -2 &&
          sys(NR_newfstatat, -100, "/proc/self/task/999999", pst, 0) == -2, "a thread's directory is found by its number, as readdir spells it");
    i64 nfd = sys(NR_openat, -100, "/proc/self/stat", 0, 0);
    check(sys(NR_newfstatat, -100, num_path(path, "/proc/self/fd/", nfd, ""), pst, 0x100 /* AT_SYMLINK_NOFOLLOW */) == 0 && (*(u32 *)(pst + 16) & 0170000) == 0120000 &&
          sys(NR_close, nfd) == 0 && sys(NR_newfstatat, -100, path, pst, 0x100) == -2, "an open fd is a link in /proc/self/fd, and a closed one isn't there");
    pid = fork_();
    if (pid == 0) sys(NR_exit_group, 0);
    // A zombie keeps its directory until it is reaped.
    char *zpath = num_path(path, "/proc/", pid, "/stat");
    nap_ms(100);
    i64 zst = sys(NR_newfstatat, -100, zpath, pst, 0);
    check(reap(pid, 3000) == 0 && zst == 0 && sys(NR_newfstatat, -100, zpath, pst, 0) == -2, "a zombie's /proc directory is there until it is reaped");

    // --- RSS: pages counted as they come and go, as Linux's mm counters count them
    memset(pbuf, 0, sizeof pbuf);
    i64 r0 = resident();
    char *mem = (char *)sys(NR_mmap, 0, 64 * 4096, 3, 0x22, -1, 0);
    for (int i = 0; i < 64; i++) mem[i * 4096] = 1;
    i64 r1 = resident();
    sys(NR_madvise, mem, 16 * 4096, 4 /* MADV_DONTNEED */);
    i64 r2 = resident();
    char *grown = (char *)sys(NR_mremap, mem, 64 * 4096, 4096 * 4096, 1 /* MREMAP_MAYMOVE */);
    i64 r3 = resident();
    check(r1 - r0 == 64 && r1 - r2 == 16 && r3 == r2, "statm's resident pages follow touching, MADV_DONTNEED and mremap");
    check(proc_num("/proc/self/status", "VmRSS:", 0) == r3 * 4 && proc_num("/proc/self/stat", 0, 23) == r3, "status's VmRSS and stat's rss say the same");
    pid = fork_();
    if (pid == 0) {
        i64 c0 = resident();
        char *more = (char *)sys(NR_mmap, 0, 8 * 4096, 3, 0x22, -1, 0);
        for (int i = 0; i < 8; i++) more[i * 4096] = 1;
        sys(NR_exit_group, c0 > 48 && resident() - c0 == 8 ? 0 : 3);
    }
    check(reap(pid, 3000) == 0, "a forked child has the pages it shares, and counts its own");
    sys(NR_munmap, grown, 4096 * 4096);
    check(resident() == r0, "munmap gives them back");

    puts_(failures ? "SOME CHECKS FAILED\n" : "all checks passed\n");
    return failures;
}

void cstart(void) { sys(NR_exit_group, cmain()); }
__asm__(".global _start\n_start:\n bl cstart\n");

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
#define NR_read 63
#define NR_write 64
#define NR_pread64 67
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
#define NR_setresuid 147
#define NR_setresgid 149
#define NR_gettid 178
#define NR_munmap 215
#define NR_mremap 216
#define NR_clone 220
#define NR_mmap 222
#define NR_mprotect 226
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

static int fa, fb;
static volatile i64 w1_ret = 99, w2_ret = 99;
static void waiter1(void *arg) { (void)arg; i64 ts[2] = {0, 300000000}; w1_ret = sys(NR_futex, &fa, 0 /* WAIT */, 0, ts); }
static void waiter2(void *arg) { (void)arg; i64 ts[2] = {3, 0}; w2_ret = sys(NR_futex, &fb, 0 /* WAIT */, 0, ts); }
static char stacks[2][16384] __attribute__((aligned(16)));
static int ctid[2];

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
    sys(NR_futex, &fa, 3 /* REQUEUE */, 0, 1, &fb);
    nap_ms(400); // waiter 1 has timed out by now
    spawn(stacks[1] + 16384, waiter2, 0, &ctid[1]);
    nap_ms(100);
    i64 woke = sys(NR_futex, &fb, 1 /* WAKE */, 1);
    nap_ms(300);
    check(w1_ret == -110 && woke == 1 && w2_ret == 0, "a requeued waiter that timed out doesn't take a later wake");
    sys(NR_futex, &fb, 1, 10);
    nap_ms(50);

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

    puts_(failures ? "SOME CHECKS FAILED\n" : "all checks passed\n");
    return failures;
}

void cstart(void) { sys(NR_exit_group, cmain()); }
__asm__(".global _start\n_start:\n bl cstart\n");

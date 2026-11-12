// Freestanding arm64 test of zeroemu's copy-on-write fork: parent and child
// see their own writes only, including writes the kernel makes for them and
// after mprotect; a big fork is cheap; and threads writing one page while
// another thread forks lose nothing.

typedef unsigned long u64;
typedef long i64;
typedef unsigned int u32;

#define NR_pipe2 59
#define NR_read 63
#define NR_write 64
#define NR_exit 93
#define NR_exit_group 94
#define NR_futex 98
#define NR_clock_gettime 113
#define NR_munmap 215
#define NR_clone 220
#define NR_mmap 222
#define NR_mprotect 226
#define NR_madvise 233
#define NR_mremap 216
#define NR_memfd_create 279
#define NR_ftruncate 46
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
static void putn(i64 v) {
    char b[24];
    int i = 23;
    b[i] = 0;
    do { b[--i] = '0' + v % 10; v /= 10; } while (v);
    puts_(&b[i]);
}

static int failures;
static void check(int cond, const char *name) {
    puts_(cond ? "ok   " : "FAIL ");
    puts_(name);
    puts_("\n");
    if (!cond) failures++;
}

static i64 fork_(void) { return sys(NR_clone, 17 /* SIGCHLD */, 0, 0, 0, 0); }
static int wait_status(i64 pid) {
    int st = 0;
    sys(NR_wait4, pid, &st, 0, 0);
    return (st >> 8) & 0xff;
}
static i64 now_ms(void) {
    i64 ts[2];
    sys(NR_clock_gettime, 1, ts);
    return ts[0] * 1000 + ts[1] / 1000000;
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

// Two threads write their own word of one page; each checks its last write
// is still there. Forks in the main thread must not lose any.
#define FORKS 300
static volatile int stop_writers, lost;
static volatile u64 *shared_page;
static void writer(void *arg) {
    long i = (long)arg;
    u64 c = 0;
    while (!__atomic_load_n(&stop_writers, __ATOMIC_ACQUIRE)) {
        shared_page[i * 8] = ++c;
        for (volatile int k = 0; k < 20; k++) {}
        if (shared_page[i * 8] != c) {
            __atomic_fetch_add(&lost, 1, __ATOMIC_SEQ_CST);
            c = shared_page[i * 8];
        }
    }
}

// The kernel writes for this thread: clock_gettime into the same page. The
// copy that makes must not lose what the other two threads store meanwhile.
static void kernel_writer(void *arg) {
    (void)arg;
    while (!__atomic_load_n(&stop_writers, __ATOMIC_ACQUIRE)) {
        sys(NR_clock_gettime, 1, shared_page + 64);
    }
}

static char stacks[3][65536] __attribute__((aligned(16)));
static int tids[3];

int cmain(void) {
    char *m = (char *)sys(NR_mmap, 0, 1 << 20, 3, 0x22, -1, 0);
    m[0] = 'a';
    m[4096] = 'b';
    i64 pid = fork_();
    if (pid == 0) {
        int bad = m[0] != 'a' || m[4096] != 'b';
        m[0] = 'c'; // ours alone
        bad |= m[0] != 'c';
        sys(NR_exit, bad);
    }
    check(wait_status(pid) == 0 && m[0] == 'a', "a child's write stays in the child");

    pid = fork_();
    if (pid == 0) {
        for (volatile int i = 0; i < 2000000; i++) {}
        sys(NR_exit, m[4096] != 'b');
    }
    m[4096] = 'd';
    check(wait_status(pid) == 0, "a parent's write stays out of the child");

    // The kernel writes through its own view of guest memory: read() into a shared page.
    int p[2];
    sys(NR_pipe2, p, 0);
    pid = fork_();
    if (pid == 0) {
        sys(NR_write, p[1], "z", 1);
        sys(NR_read, p[0], m + 8192, 1);
        sys(NR_exit, m[8192] != 'z');
    }
    int kernel_ok = wait_status(pid) == 0;
    check(kernel_ok && m[8192] == 0, "a page never touched stays clean for the parent");
    m[12288] = 'p';
    pid = fork_();
    if (pid == 0) {
        sys(NR_write, p[1], "z", 1);
        sys(NR_read, p[0], m + 12288, 1);
        sys(NR_exit, m[12288] != 'z');
    }
    check(wait_status(pid) == 0 && m[12288] == 'p', "read() into a shared page writes the reader's copy");

    // mprotect must not make a shared frame writable.
    m[16384] = 'x';
    sys(NR_mprotect, m + 16384, 4096, 1 /* PROT_READ */);
    pid = fork_();
    if (pid == 0) {
        sys(NR_mprotect, m + 16384, 4096, 3);
        m[16384] = 'y';
        sys(NR_exit, m[16384] != 'y');
    }
    check(wait_status(pid) == 0 && m[16384] == 'x', "mprotect then write in the child leaves the parent's page");
    sys(NR_mprotect, m + 16384, 4096, 3);
    m[16384] = 'w';
    check(m[16384] == 'w', "the parent writes it too, now the child is gone");

    pid = fork_();
    if (pid == 0) {
        sys(NR_munmap, m, 1 << 20);
        sys(NR_exit, 0);
    }
    check(wait_status(pid) == 0 && m[4096] == 'd', "a child's munmap leaves the parent's pages");

    // A big fork should cost page-table work, not a copy of the memory.
    u64 big = 512ul << 20;
    char *b = (char *)sys(NR_mmap, 0, big, 3, 0x22, -1, 0);
    for (u64 i = 0; i < big; i += 4096) b[i] = (char)(i >> 12);
    i64 t0 = now_ms();
    pid = fork_();
    if (pid == 0) sys(NR_exit, b[4096 * 7] != 7);
    i64 forked = now_ms() - t0;
    check(wait_status(pid) == 0, "a fork of 512 MiB of touched memory works");
    puts_("     fork took ms: "), putn(forked), puts_("\n");
    int sum_ok = 1;
    for (u64 i = 0; i < big; i += 4096) sum_ok &= b[i] == (char)(i >> 12);
    check(sum_ok, "and the parent's pages are intact");
    sys(NR_munmap, b, big);

    shared_page = (volatile u64 *)sys(NR_mmap, 0, 4096, 3, 0x22, -1, 0);
    for (long i = 0; i < 2; i++) {
        tids[i] = 1;
        spawn(stacks[i] + sizeof stacks[i], writer, (void *)i, &tids[i]);
    }
    tids[2] = 1;
    spawn(stacks[2] + sizeof stacks[2], kernel_writer, 0, &tids[2]);
    for (int i = 0; i < FORKS; i++) {
        pid = fork_();
        if (pid == 0) sys(NR_exit, 0);
        wait_status(pid);
    }
    __atomic_store_n(&stop_writers, 1, __ATOMIC_RELEASE);
    for (int i = 0; i < 3; i++) {
        while (tids[i] != 0) sys(NR_futex, &tids[i], 0, tids[i], 0);
    }
    check(lost == 0, "threads writing one page, one through the kernel, lose nothing across 300 forks");
    if (lost) puts_("     lost writes: "), putn(lost), puts_("\n");

    // A write-only private page stays readable through fork, as arm64 has it.
    char *wo = (char *)sys(NR_mmap, 0, 4096, 2 /* PROT_WRITE */, 0x22, -1, 0);
    wo[0] = 'w';
    pid = fork_();
    if (pid == 0) sys(NR_exit, wo[0] != 'w');
    check(wait_status(pid) == 0, "a write-only page reads back after fork");

    // What fork does with a mapping.
    char *df = (char *)sys(NR_mmap, 0, 8192, 3, 0x22, -1, 0);
    df[0] = 'd';
    df[4096] = 'k';
    check(sys(NR_madvise, df, 4096, 10 /* MADV_DONTFORK */) == 0, "MADV_DONTFORK");
    pid = fork_();
    if (pid == 0) {
        // The page is gone: mapping there exactly must work, and it starts empty.
        char *again = (char *)sys(NR_mmap, df, 4096, 3, 0x22 | 0x100000 /* MAP_FIXED_NOREPLACE */, -1, 0);
        sys(NR_exit, !(again == df && again[0] == 0 && df[4096] == 'k'));
    }
    check(wait_status(pid) == 0, "the child lacks a DONTFORK page and keeps the next one");
    char *wipe = (char *)sys(NR_mmap, 0, 4096, 3, 0x22, -1, 0);
    wipe[0] = 'w';
    check(sys(NR_madvise, wipe, 4096, 18 /* MADV_WIPEONFORK */) == 0, "MADV_WIPEONFORK");
    pid = fork_();
    if (pid == 0) sys(NR_exit, wipe[0] != 0);
    check(wait_status(pid) == 0 && wipe[0] == 'w', "the child reads zeros, the parent its data");

    // mremap: moving a touched shared mapping must not free frames its object owns.
    int shm = (int)sys(NR_memfd_create, "m", 0);
    sys(NR_ftruncate, shm, 8192);
    char *sm = (char *)sys(NR_mmap, 0, 8192, 3, 0x01 /* MAP_SHARED */, shm, 0);
    sm[0] = 's';
    sm[4096] = 't';
    char *dst = (char *)sys(NR_mmap, 0, 8192, 3, 0x22, -1, 0);
    char *moved = (char *)sys(NR_mremap, sm, 8192, 4096, 1 | 2 /* MAYMOVE|FIXED */, dst);
    check(moved == dst && moved[0] == 's', "shrink a shared mapping to a fixed address");
    char *other = (char *)sys(NR_mmap, 0, 4096, 3, 0x01, shm, 4096);
    for (int i = 0; i < 64; i++) ((volatile char *)sys(NR_mmap, 0, 4096, 3, 0x22, -1, 0))[0] = 'x';
    check(other[0] == 't', "the page it left behind still belongs to the object");

    char *pv = (char *)sys(NR_mmap, 0, 8192, 3, 0x22, -1, 0);
    check(sys(NR_mremap, pv, 4096, 4096, 1 | 2, 0x7fc0000000) == -22, "mremap into the kernel window: EINVAL");
    check(sys(NR_mremap, pv + 4096, 4096, 8192, 1 | 2, pv) == -22, "mremap onto itself: EINVAL");
    check(sys(NR_mremap, pv, 0, 4096, 1) == -22, "mremap of zero bytes of private memory: EINVAL");

    puts_(failures ? "SOME CHECKS FAILED\n" : "all checks passed\n");
    return failures;
}

void __attribute__((noreturn)) cstart(void) {
    sys(NR_exit_group, cmain());
    __builtin_unreachable();
}

__asm__(".global _start\n_start:\n bl cstart\n");

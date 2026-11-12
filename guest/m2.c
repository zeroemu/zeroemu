// Freestanding test of zeroemu's M2 kernel (no libc), built for arm64 and
// x86_64: threads via raw clone + futex, fork/pipe/wait4, mprotect faults
// delivered to a SIGSEGV handler (which fixes the page and returns through
// rt_sigreturn), munmap, mremap, and a huge PROT_NONE reservation. Exits
// with the failure count.

typedef unsigned long u64;
typedef long i64;

#if defined(__aarch64__)
#define NR_futex 98
#define NR_write 64
#define NR_exit 93
#define NR_exit_group 94
#define NR_rt_sigaction 134
#define NR_munmap 215
#define NR_mremap 216
#define NR_clone 220
#define NR_mmap 222
#define NR_mprotect 226
#define NR_wait4 260
#define NR_pipe2 59
#define NR_read 63
#define NR_close 57
#define NR_rt_sigprocmask 135
#define NR_rt_sigtimedwait 137
#define NR_getpid 172
#define NR_kill 129

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
#define NR_read 0
#define NR_write 1
#define NR_close 3
#define NR_mmap 9
#define NR_mprotect 10
#define NR_munmap 11
#define NR_rt_sigaction 13
#define NR_mremap 25
#define NR_clone 56
#define NR_exit 60
#define NR_wait4 61
#define NR_futex 202
#define NR_exit_group 231
#define NR_pipe2 293
#define NR_rt_sigprocmask 14
#define NR_rt_sigtimedwait 128
#define NR_getpid 39
#define NR_kill 62

static i64 sys6(i64 n, i64 a, i64 b, i64 c, i64 d, i64 e, i64 f) {
    register i64 r10 __asm__("r10") = d;
    register i64 r8 __asm__("r8") = e;
    register i64 r9 __asm__("r9") = f;
    __asm__ volatile("syscall" : "+a"(n) : "D"(a), "S"(b), "d"(c), "r"(r10), "r"(r8), "r"(r9) : "rcx", "r11", "memory");
    return n;
}
#else
#error unsupported guest arch
#endif
#define sys(n, ...) sys6_(n, __VA_ARGS__, 0, 0, 0, 0, 0, 0)
#define sys6_(n, a, b, c, d, e, f, ...) sys6(n, (i64)(a), (i64)(b), (i64)(c), (i64)(d), (i64)(e), (i64)(f))

void *memset(void *d, int c, u64 n) { char *p = d; while (n--) *p++ = (char)c; return d; }
void *memcpy(void *d, const void *s, u64 n) { char *p = d; const char *q = s; while (n--) *p++ = *q++; return d; }
static u64 slen(const char *s) { u64 n = 0; while (s[n]) n++; return n; }
static void puts_(const char *s) { sys(NR_write, 1, s, slen(s)); }

static int failures;
static void check(int cond, const char *name) {
    puts_(cond ? "ok   " : "FAIL ");
    puts_(name);
    puts_("\n");
    if (!cond) failures++;
}

#define PROT_RW 3
#define MAP_PRIV_ANON 0x22
static void *map(u64 len, int prot) { return (void *)sys(NR_mmap, 0, len, prot, MAP_PRIV_ANON, -1, 0); }

// ---- threads ----

#define CLONE_THREAD_FLAGS (0x100 | 0x200 | 0x400 | 0x800 | 0x10000 | 0x40000 | 0x200000) // VM FS FILES SIGHAND THREAD SYSVSEM CHILD_CLEARTID

// Starts fn(arg) on a new thread with its own stack; the child exits the
// thread when fn returns. *ctid is cleared and futex-woken at thread exit.
static i64 spawn(void *stack_top, void (*fn)(void *), void *arg, int *ctid) {
#if defined(__aarch64__)
    register i64 x0 __asm__("x0") = CLONE_THREAD_FLAGS;
    register i64 x1 __asm__("x1") = (i64)stack_top;
    register i64 x2 __asm__("x2") = 0;
    register i64 x3 __asm__("x3") = 0; // tls
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
        "mov x8, #93\n" // exit: just this thread
        "svc #0\n"
        "1:\n"
        : "+r"(x0)
        : "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x8), "r"(x19), "r"(x20)
        : "memory", "x30");
    return x0;
#elif defined(__x86_64__)
    // x86_64 clone args: flags, stack, parent_tid, child_tid, tls.
    register i64 rax __asm__("rax") = NR_clone;
    register i64 rdi __asm__("rdi") = CLONE_THREAD_FLAGS;
    register i64 rsi __asm__("rsi") = (i64)stack_top;
    register i64 rdx __asm__("rdx") = 0;
    register i64 r10 __asm__("r10") = (i64)ctid;
    register i64 r8 __asm__("r8") = 0;
    register void *rbx __asm__("rbx") = (void *)fn;
    register void *r12 __asm__("r12") = arg;
    __asm__ volatile(
        "syscall\n"
        "test %%rax, %%rax\n"
        "jnz 1f\n"
        "movq %%r12, %%rdi\n"
        "call *%%rbx\n"
        "xorl %%edi, %%edi\n"
        "movl $60, %%eax\n" // exit: just this thread
        "syscall\n"
        "1:\n"
        : "+r"(rax)
        : "r"(rdi), "r"(rsi), "r"(rdx), "r"(r10), "r"(r8), "r"(rbx), "r"(r12)
        : "memory", "rcx", "r11", "cc");
    return rax;
#endif
}

static volatile u64 counter;
static volatile int lock_word; // 0 free, 1 locked, 2 locked with waiters
static volatile u64 locked_counter;

static void lock(void) {
    int c = 0;
    if (__atomic_compare_exchange_n(&lock_word, &c, 1, 0, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED)) return;
    if (c != 2) c = __atomic_exchange_n(&lock_word, 2, __ATOMIC_ACQUIRE);
    while (c != 0) {
        sys(NR_futex, &lock_word, 128 /* WAIT|PRIVATE */, 2, 0);
        c = __atomic_exchange_n(&lock_word, 2, __ATOMIC_ACQUIRE);
    }
}
static void unlock(void) {
    if (__atomic_fetch_sub(&lock_word, 1, __ATOMIC_RELEASE) != 1) {
        lock_word = 0;
        sys(NR_futex, &lock_word, 129 /* WAKE|PRIVATE */, 1);
    }
}

static void worker(void *arg) {
    (void)arg;
    for (int i = 0; i < 100000; i++) __atomic_fetch_add(&counter, 1, __ATOMIC_RELAXED);
    for (int i = 0; i < 20000; i++) { lock(); locked_counter++; unlock(); }
}

static void join(volatile int *ctid) {
    while (*ctid != 0) sys(NR_futex, ctid, 0 /* WAIT, shared */, *ctid, 0);
}

// ---- signals ----

struct sigaction_k { void *handler; u64 flags; void *restorer; u64 mask; };
static char *fault_page;
static volatile u64 fault_addr;
static volatile int faults;

static void on_segv(int sig, void *info, void *uc) {
    (void)sig; (void)uc;
    fault_addr = *(u64 *)((char *)info + 16); // si_addr
    faults++;
    sys(NR_mprotect, fault_page, 4096, PROT_RW); // fix it; the store is retried
}

int cmain(i64 *sp) {
    // Threads + atomics + futex mutex + CLONE_CHILD_CLEARTID join.
    int tids[4];
    for (int i = 0; i < 4; i++) {
        char *stack = map(256 << 10, PROT_RW);
        tids[i] = 1;
        tids[i] = (int)spawn(stack + (256 << 10), worker, 0, &tids[i]) > 0 ? tids[i] : -1;
    }
    for (int i = 0; i < 4; i++) if (tids[i] > 0) join(&tids[i]);
    check(counter == 400000, "4 threads x 100000 atomic increments");
    check(locked_counter == 80000, "futex mutex under contention");

    // fork + pipe + wait4 exit status.
    int fds[2];
    check(sys(NR_pipe2, fds, 0) == 0, "pipe2");
    i64 pid = sys(NR_clone, 17 /* SIGCHLD */, 0, 0, 0, 0);
    if (pid == 0) {
        sys(NR_close, fds[0]);
        sys(NR_write, fds[1], "from child", 10);
        sys(NR_exit_group, 42);
    }
    sys(NR_close, fds[1]);
    char buf[32] = {0};
    i64 n = sys(NR_read, fds[0], buf, sizeof buf);
    int status = 0;
    i64 w = sys(NR_wait4, pid, &status, 0, 0);
    check(n == 10 && buf[0] == 'f' && buf[9] == 'd', "child wrote through pipe");
    check(w == pid && status == (42 << 8), "wait4 reports exit status 42");
    check(sys(NR_read, fds[0], buf, 1) == 0, "pipe EOF after child exit");

    // A forked child's memory is a copy.
    static volatile int shared_var = 1;
    pid = sys(NR_clone, 17, 0, 0, 0, 0);
    if (pid == 0) { shared_var = 99; sys(NR_exit_group, shared_var == 99 ? 0 : 1); }
    sys(NR_wait4, pid, &status, 0, 0);
    check(status == 0 && shared_var == 1, "fork copies memory (child write invisible)");

    // mprotect + SIGSEGV handler + rt_sigreturn (via the kernel trampoline).
    struct sigaction_k act = { (void *)on_segv, 4 /* SA_SIGINFO */, 0, 0 };
    check(sys(NR_rt_sigaction, 11, &act, 0, 8) == 0, "rt_sigaction(SIGSEGV)");
    fault_page = map(4096, PROT_RW);
    fault_page[0] = 1;
    sys(NR_mprotect, fault_page, 4096, 1 /* PROT_READ */);
    fault_page[100] = 7; // faults, handler unprotects, store retried
    check(faults == 1 && fault_addr == (u64)(fault_page + 100) && fault_page[100] == 7, "fault -> handler -> sigreturn -> retry");

    // munmap then a fixed remap reads back zero.
    char *p = map(8192, PROT_RW);
    p[0] = 55; p[4096] = 66;
    sys(NR_munmap, p, 8192);
    char *q = (char *)sys(NR_mmap, p, 8192, PROT_RW, MAP_PRIV_ANON | 0x10 /* FIXED */, -1, 0);
    check(q == p && q[0] == 0 && q[4096] == 0, "munmap discards contents");

    // mremap grows and moves while keeping data.
    char *r = map(8192, PROT_RW);
    for (int i = 0; i < 8192; i++) r[i] = (char)(i * 7);
    char *r2 = (char *)sys(NR_mremap, r, 8192, 1 << 20, 1 /* MAYMOVE */, 0);
    int same = r2 != (char *)-1;
    for (int i = 0; same && i < 8192; i++) same = r2[i] == (char)(i * 7);
    check(same && r2[(1 << 20) - 1] == 0, "mremap keeps data, new tail zeroed");

    // A 64 GiB reservation costs nothing until touched.
    char *big = (char *)sys(NR_mmap, 0, 64ul << 30, 0, MAP_PRIV_ANON | 0x4000, -1, 0);
    int ok = (i64)big > 0 && sys(NR_mprotect, big + (32ul << 30), 4096, PROT_RW) == 0;
    if (ok) big[32ul << 30] = 1;
    check(ok && big[32ul << 30] == 1, "64 GiB PROT_NONE reservation, one page used");

    // bionic's atexit array: mprotect one page read-only and back, which
    // splits the mapping, then grow it with mremap. Linux rejoins the
    // mapping, so the source is a single mapping again.
    char *ax = (char *)sys(NR_mmap, 0, 8192, PROT_RW, MAP_PRIV_ANON, -1, 0);
    ax[0] = 5;
    sys(NR_mprotect, ax + 4096, 4096, 1 /* PROT_READ */);
    sys(NR_mprotect, ax, 8192, PROT_RW);
    char *ax2 = (char *)sys(NR_mremap, ax, 8192, 16384, 1 /* MREMAP_MAYMOVE */, 0);
    check((i64)ax2 > 0 && ax2[0] == 5, "mremap after mprotect splits and rejoins");

    // sigwaitinfo: a blocked signal is taken without its handler running.
    u64 usr1 = 1ul << (10 - 1), old = 0;
    sys(NR_rt_sigprocmask, 0 /* SIG_BLOCK */, &usr1, &old, 8);
    sys(NR_kill, sys(NR_getpid, 0), 10);
    int info[32];
    i64 got = sys(NR_rt_sigtimedwait, &usr1, info, 0, 8);
    check(got == 10 && info[0] == 10, "sigtimedwait takes a blocked signal with its siginfo");
    i64 ts[2] = {0, 10 * 1000 * 1000};
    check(sys(NR_rt_sigtimedwait, &usr1, 0, ts, 8) == -11, "sigtimedwait times out with EAGAIN");
    sys(NR_rt_sigprocmask, 2 /* SIG_SETMASK */, &old, 0, 8);

    // Linux lays the argv then envp strings out contiguously, ascending.
    i64 argc = sp[0];
    char **argv = (char **)(sp + 1), **envp = argv + argc + 1;
    int ascending = argc > 0;
    for (char **a = argv; ascending && *a; a++) {
        char *next = a[1] ? a[1] : envp[0];
        if (next && next != *a + slen(*a) + 1) ascending = 0;
    }
    check(ascending, "argv and envp strings are contiguous and ascending");

    puts_(failures ? "SOME CHECKS FAILED\n" : "all checks passed\n");
    return failures;
}

void __attribute__((noreturn)) cstart(i64 *sp) {
    sys(NR_exit_group, cmain(sp));
    __builtin_unreachable();
}

#if defined(__aarch64__)
__asm__(".global _start\n_start:\n mov x0, sp\n bl cstart\n");
#elif defined(__x86_64__)
__asm__(".global _start\n_start:\n mov %rsp, %rdi\n call cstart\n");
#endif

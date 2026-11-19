// Freestanding arm64 test of the guest's clocks: the virtual counter (CNTVCT_EL0)
// against CLOCK_MONOTONIC on every vCPU, the other clocks against it, and the vDSO,
// found through AT_SYSINFO_EHDR as bionic finds it, against the syscalls, and
// signal handlers returning through it. And getcpu, which sched_getcpu makes.

typedef unsigned long u64;
typedef long i64;
typedef unsigned int u32;
typedef unsigned short u16;
typedef unsigned char u8;

#define NR_openat 56
#define NR_close 57
#define NR_read 63
#define NR_write 64
#define NR_exit 93
#define NR_exit_group 94
#define NR_futex 98
#define NR_clock_gettime 113
#define NR_clock_getres 114
#define NR_sched_getaffinity 123
#define NR_getcpu 168
#define NR_gettimeofday 169
#define NR_tgkill 131
#define NR_rt_sigaction 134
#define NR_getpid 172
#define NR_gettid 178
#define NR_clone 220
#define NR_wait4 260

#define EFAULT 14
#define EINVAL 22

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
static int seq(const char *a, const char *b) { while (*a && *a == *b) a++, b++; return *a == *b; }
static void puts_(const char *s) { sys(NR_write, 1, s, slen(s)); }
static void putn(u64 v) {
    char b[24];
    int i = 23;
    b[i] = 0;
    do b[--i] = '0' + v % 10; while (v /= 10);
    puts_(b + i);
}

static int contains(const char *h, u64 n, const char *needle) {
    u64 m = slen(needle);
    for (u64 i = 0; i + m <= n; i++) {
        u64 j = 0;
        while (j < m && h[i + j] == needle[j]) j++;
        if (j == m) return 1;
    }
    return 0;
}

static int failures;
static void check(int cond, const char *name) {
    puts_(cond ? "ok   " : "FAIL ");
    puts_(name);
    puts_("\n");
    if (!cond) failures++;
}

struct timespec { i64 sec, nsec; };
struct timeval { i64 sec, usec; };
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

// The vDSO, looked up the way bionic's __libc_init_vdso does: symbols counted from
// the SHT_DYNSYM section header, the tables from PT_DYNAMIC, the load bias from
// PT_LOAD. Then the versions, as glibc and musl check them.
typedef int (*clock_gettime_fn)(int, struct timespec *);
typedef int (*gettimeofday_fn)(struct timeval *, void *);
typedef int (*clock_getres_fn)(int, struct timespec *);
static clock_gettime_fn vdso_gettime;
static gettimeofday_fn vdso_gettimeofday;
static clock_getres_fn vdso_getres;
static u64 vdso_sigreturn;
static int versioned;

struct ehdr { u8 ident[16]; u16 type, machine; u32 version; u64 entry, phoff, shoff; u32 flags; u16 ehsize, phentsize, phnum, shentsize, shnum, shstrndx; };
struct phdr { u32 type, flags; u64 offset, vaddr, paddr, filesz, memsz, align; };
struct shdr { u32 name, type; u64 flags, addr, offset, size; u32 link, info; u64 addralign, entsize; };
struct sym { u32 name; u8 info, other; u16 shndx; u64 value, size; };
struct dyn { i64 tag; u64 val; };
struct verdef { u16 version, flags, ndx, cnt; u32 hash, aux, next; };
struct verdaux { u32 name, next; };

static int find_vdso(u64 base) {
    struct ehdr *e = (struct ehdr *)base;
    if (!(e->ident[0] == 0x7f && e->ident[1] == 'E' && e->type == 3 && e->machine == 183)) return 0;
    u64 count = 0;
    struct shdr *sh = (struct shdr *)(base + e->shoff);
    for (int i = 0; i < e->shnum; i++)
        if (sh[i].type == 11 /* SHT_DYNSYM */) count = sh[i].size / sizeof(struct sym);
    u64 bias = 0;
    struct dyn *dyn = 0;
    struct phdr *ph = (struct phdr *)(base + e->phoff);
    for (int i = 0; i < e->phnum; i++) {
        if (ph[i].type == 2) dyn = (struct dyn *)(base + ph[i].offset);
        if (ph[i].type == 1) bias = base + ph[i].offset - ph[i].vaddr;
    }
    if (!count || !bias || !dyn) return 0;
    const char *strtab = 0;
    struct sym *symtab = 0;
    u16 *versym = 0;
    struct verdef *verdef = 0;
    for (struct dyn *d = dyn; d->tag; d++) {
        if (d->tag == 5) strtab = (const char *)(bias + d->val);
        if (d->tag == 6) symtab = (struct sym *)(bias + d->val);
        if (d->tag == 0x6ffffff0) versym = (u16 *)(bias + d->val);
        if (d->tag == 0x6ffffffc) verdef = (struct verdef *)(bias + d->val);
    }
    if (!strtab || !symtab) return 0;
    // The index of version LINUX_2.6.39.
    int want = -1;
    for (struct verdef *v = verdef; v; v = v->next ? (struct verdef *)((char *)v + v->next) : 0) {
        struct verdaux *a = (struct verdaux *)((char *)v + v->aux);
        if (seq(strtab + a->name, "LINUX_2.6.39")) want = v->ndx;
    }
    versioned = want > 0;
    for (u64 i = 0; i < count; i++) {
        const char *n = strtab + symtab[i].name;
        void *fn = (void *)(bias + symtab[i].value);
        if (versym && versym[i] != want) {
            if (n[0] == '_') versioned = 0;
            continue;
        }
        if (seq(n, "__kernel_clock_gettime")) vdso_gettime = (clock_gettime_fn)fn;
        if (seq(n, "__kernel_gettimeofday")) vdso_gettimeofday = (gettimeofday_fn)fn;
        if (seq(n, "__kernel_clock_getres")) vdso_getres = (clock_getres_fn)fn;
        if (seq(n, "__kernel_rt_sigreturn")) vdso_sigreturn = (u64)fn;
    }
    return vdso_gettime && vdso_gettimeofday && vdso_getres;
}

static char buf[16384];
static i64 readfile(const char *path) {
    int fd = (int)sys(NR_openat, -100, path, 0, 0);
    if (fd < 0) return fd;
    i64 n = 0, r;
    while ((r = sys(NR_read, fd, buf + n, sizeof buf - 1 - n)) > 0) n += r;
    sys(NR_close, fd);
    buf[n] = 0;
    return n;
}

static int vdso_monotonic_against_svc(void) {
    // Interleaved, each read at least the one before: the two compute one clock.
    u64 last = 0;
    for (int i = 0; i < 20000; i++) {
        struct timespec t;
        if (vdso_gettime(1, &t) != 0) return 0;
        u64 v = ns_of(t), s = svc_ns(1);
        if (v < last || s < v) return 0;
        last = s;
    }
    return 1;
}

// CLOCK_REALTIME, read both ways in turn for 300 ms, across three of the host's
// corrections of it (ten a second): each read at least the one before. zeroemu
// slews it toward the host's wall clock as NTP slews Linux's, never stepping it
// back for a correction.
static int vdso_realtime_never_back(void) {
    u64 last = 0, end = svc_ns(1) + 300000000;
    while (svc_ns(1) < end) {
        struct timespec t;
        if (vdso_gettime(0, &t) != 0) return 0;
        u64 v = ns_of(t), s = svc_ns(0);
        if (v < last || s < v) return 0;
        last = s;
    }
    return 1;
}

static void vdso_thread(void *arg) {
    thread_ok[(u64)arg] = vdso_monotonic_against_svc();
}

// Whether the line of `text` holding `name` also holds `what`.
static int line_has(const char *text, const char *name, const char *what) {
    for (const char *l = text; *l;) {
        const char *e = l;
        while (*e && *e != '\n') e++;
        if (contains(l, e - l, name)) return contains(l, e - l, what);
        l = *e ? e + 1 : e;
    }
    return 0;
}

// A handler installed as bionic installs them on arm64, without SA_RESTORER: it
// returns to wherever the kernel put in x30.
struct sigaction_k { void (*handler)(int); u64 flags; void *restorer; u64 mask; };
static volatile u64 handler_lr;
static volatile int handled;
static void on_usr1(int sig) {
    handler_lr = (u64)__builtin_return_address(0);
    handled = sig;
}

static u64 now_ns(void) {
    struct timespec t;
    vdso_gettime(1, &t);
    return ns_of(t);
}

static int run(u64 *sp) {
    u64 argc = sp[0];
    char **envp = (char **)(sp + 1 + argc + 1);
    while (*envp) envp++;
    u64 sysinfo_ehdr = 0;
    for (u64 *a = (u64 *)(envp + 1); a[0]; a += 2)
        if (a[0] == 33) sysinfo_ehdr = a[1];

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

    // The other clocks are CLOCK_MONOTONIC plus an offset: BOOTTIME, MONOTONIC_RAW,
    // MONOTONIC_COARSE and BOOTTIME_ALARM add nothing.
    static const int mono_ids[] = {4, 6, 7, 9};
    int between = 1;
    for (u64 i = 0; i < sizeof mono_ids / sizeof mono_ids[0]; i++) {
        u64 a = svc_ns(1), v = svc_ns(mono_ids[i]), b = svc_ns(1);
        if (!(a <= v && v <= b)) between = 0;
    }
    check(between, "BOOTTIME, MONOTONIC_RAW, MONOTONIC_COARSE and BOOTTIME_ALARM are CLOCK_MONOTONIC");
    // The wall clocks: REALTIME, REALTIME_COARSE, REALTIME_ALARM and TAI agree.
    static const int wall_ids[] = {5, 8, 11};
    int same = 1;
    for (u64 i = 0; i < sizeof wall_ids / sizeof wall_ids[0]; i++) {
        u64 a = svc_ns(0), v = svc_ns(wall_ids[i]), b = svc_ns(0);
        if (!(a <= v && v <= b)) same = 0;
    }
    check(same, "REALTIME_COARSE, REALTIME_ALARM and TAI are CLOCK_REALTIME");
    check(svc_ns(0) / 1000000000 > 1700000000, "CLOCK_REALTIME is the date");
    struct timeval tv = {0, -1};
    int tz[2] = {7, 7};
    u64 r0 = svc_ns(0);
    check(sys(NR_gettimeofday, &tv, tz) == 0 && tz[0] == 0 && tz[1] == 0, "gettimeofday zeroes the time zone");
    u64 r1 = svc_ns(0);
    u64 us = (u64)tv.sec * 1000000 + (u64)tv.usec;
    check(tv.usec >= 0 && tv.usec < 1000000 && r0 / 1000 <= us && us <= r1 / 1000, "gettimeofday is CLOCK_REALTIME in microseconds");

    // getcpu: a CPU below the count sched_getaffinity gives, on node 0, the same each time.
    u64 mask = 0;
    sys(NR_sched_getaffinity, 0, 8, &mask);
    u32 ncpu = 0;
    for (u64 m = mask; m; m >>= 1) ncpu += m & 1;
    u32 cpu = 99, node = 99, cpu2 = 98;
    check(sys(NR_getcpu, &cpu, &node, 0) == 0 && cpu < ncpu && node == 0, "getcpu: a CPU Android counts, node 0");
    check(sys(NR_getcpu, &cpu2, 0, 0) == 0 && cpu2 == cpu, "getcpu: the same CPU again, no node wanted");
    check(sys(NR_getcpu, 0, 0, 0) == 0, "getcpu with nothing wanted");
    check(sys(NR_getcpu, 8, 0, 0) == -EFAULT, "getcpu to a bad address is EFAULT");

    // The vDSO.
    check(sysinfo_ehdr != 0 && sysinfo_ehdr % 4096 == 0, "AT_SYSINFO_EHDR is a page");
    if (!sysinfo_ehdr) {
        puts_(failures ? "SOME CHECKS FAILED\n" : "all checks passed\n");
        return failures;
    }
    int found = find_vdso(sysinfo_ehdr);
    check(found, "__kernel_clock_gettime, __kernel_gettimeofday and __kernel_clock_getres, as bionic looks for them");
    check(versioned, "versioned LINUX_2.6.39, as on Linux");
    if (!found) {
        puts_("SOME CHECKS FAILED\n");
        return failures + 1;
    }
    i64 n = readfile("/proc/self/maps");
    check(n > 0 && line_has(buf, "[vvar]", " r--p ") && line_has(buf, "[vdso]", " r-xp "), "/proc/self/maps: [vvar] read-only, [vdso] read and execute");
    char want[24];
    int w = 0;
    for (int sh = 60; sh >= 0; sh -= 4)
        if (w || sysinfo_ehdr >> sh & 15) want[w++] = "0123456789abcdef"[sysinfo_ehdr >> sh & 15];
    want[w++] = '-';
    want[w] = 0;
    check(line_has(buf, "[vdso]", want), "[vdso] starts at AT_SYSINFO_EHDR");
    check(!contains(buf, n, "[sigpage]"), "no [sigpage]: handlers return through the vDSO");

    // Signal handlers return to __kernel_rt_sigreturn, and from there to where the
    // signal came in.
    struct sigaction_k sa = {on_usr1, 0x10000000 /* SA_RESTART */, 0, 0};
    check(sys(NR_rt_sigaction, 10 /* SIGUSR1 */, &sa, 0, 8) == 0, "a SIGUSR1 handler, no restorer");
    sys(NR_tgkill, sys(NR_getpid), sys(NR_gettid), 10);
    check(handled == 10, "the handler ran and came back");
    check(vdso_sigreturn != 0 && handler_lr == vdso_sigreturn, "it returned to __kernel_rt_sigreturn");

    check(vdso_monotonic_against_svc(), "vDSO CLOCK_MONOTONIC and the syscall's agree, read in turn");
    // Each clock it answers, between two syscalls on the same clock: the wall clocks
    // too, as both compute them from the same numbers.
    static const int ids[] = {0, 1, 4, 5, 6, 7, 8, 9, 11};
    int in_turn = 1;
    for (u64 i = 0; i < sizeof ids / sizeof ids[0]; i++) {
        int id = ids[i];
        u64 a = svc_ns(id);
        struct timespec t = {-1, -1};
        int r = vdso_gettime(id, &t);
        u64 b = svc_ns(id);
        u64 v = ns_of(t);
        if (r != 0 || t.nsec < 0 || t.nsec >= 1000000000) in_turn = 0;
        if (!(a <= v && v <= b)) in_turn = 0;
    }
    check(in_turn, "every clock it answers, between two syscalls");
    check(vdso_realtime_never_back(), "CLOCK_REALTIME never goes back, read both ways for 300 ms");
    struct timespec rt = {0, 0};
    vdso_gettime(0, &rt);
    check(rt.sec > 1700000000, "its CLOCK_REALTIME is the date");

    // gettimeofday: microseconds of CLOCK_REALTIME, and a zero time zone.
    struct timeval tv2 = {0, -1};
    tv.usec = -1;
    tz[0] = tz[1] = 7;
    check(vdso_gettimeofday(&tv, tz) == 0 && tv.usec >= 0 && tv.usec < 1000000 && tz[0] == 0 && tz[1] == 0, "gettimeofday, with the time zone zeroed");
    sys(NR_gettimeofday, &tv2, 0);
    i64 d = (tv2.sec - tv.sec) * 1000000 + (tv2.usec - tv.usec);
    check(d >= -1000 && d < 1000000, "gettimeofday agrees with the syscall's");
    check(vdso_gettimeofday(0, 0) == 0, "gettimeofday with nothing wanted");

    // clock_getres: what the syscall says.
    struct timespec res = {5, 5}, sres = {6, 6};
    check(vdso_getres(1, &res) == 0 && sys(NR_clock_getres, 1, &sres) == 0 && res.sec == sres.sec && res.nsec == sres.nsec, "clock_getres as the syscall answers it");
    check(vdso_getres(1, 0) == 0, "clock_getres with nothing wanted");

    // What it doesn't answer goes to the syscall: the CPU-time clocks and ids
    // Linux doesn't have, with the syscall's result.
    struct timespec cpu1 = {-1, -1};
    check(vdso_gettime(3, &cpu1) == 0 && cpu1.sec >= 0 && cpu1.nsec >= 0 && ns_of(cpu1) > 0, "CLOCK_THREAD_CPUTIME_ID goes to the syscall");
    check(vdso_gettime(2, &cpu1) == 0 && ns_of(cpu1) > 0, "CLOCK_PROCESS_CPUTIME_ID too");
    check(vdso_gettime(-6 /* this thread's, by tid 0 */, &cpu1) == 0, "a pthread_getcpuclockid id too");
    check(vdso_gettime(3 | ~0x7fffffff, &cpu1) == -EINVAL && sys(NR_clock_gettime, 3 | ~0x7fffffff, &cpu1) == -EINVAL, "an impossible CPU clock is EINVAL, as from the syscall");
    check(vdso_gettime(10, &cpu1) == sys(NR_clock_gettime, 10, &cpu1), "an id Linux doesn't have answers as the syscall does");

    // Threads on other vCPUs read the same clock.
    for (int i = 0; i < THREADS; i++) {
        tids[i] = 1;
        spawn(stacks[i] + sizeof stacks[i], vdso_thread, (void *)(u64)i, &tids[i]);
    }
    all = 1;
    for (int i = 0; i < THREADS; i++) {
        join(&tids[i]);
        all &= thread_ok[i];
    }
    check(all, "and in other threads");

    // How long a clock read takes each way.
    u64 t0 = now_ns();
    struct timespec x;
    for (int i = 0; i < 1000000; i++) vdso_gettime(1, &x);
    u64 t1 = now_ns();
    for (int i = 0; i < 100000; i++) sys(NR_clock_gettime, 1, &x);
    u64 t2 = now_ns();
    puts_("info clock_gettime: vDSO ");
    putn((t1 - t0) / 1000000);
    puts_(" ns, syscall ");
    putn((t2 - t1) / 100000);
    puts_(" ns\n");


    puts_(failures ? "SOME CHECKS FAILED\n" : "all checks passed\n");
    return failures;
}

void __attribute__((noreturn)) cstart(u64 *sp) {
    sys(NR_exit_group, run(sp));
    __builtin_unreachable();
}

__asm__(".global _start\n_start:\n mov x0, sp\n bl cstart\n");

// Freestanding arm64 test of userfaultfd and MREMAP_DONTUNMAP, in the way ART's
// compacting collector uses them: move a space's pages away, register the emptied
// range, and map each page as threads fault on it, from their SIGBUS handlers.

typedef unsigned long u64;
typedef long i64;
typedef unsigned int u32;

#define NR_close 57
#define NR_read 63
#define NR_write 64
#define NR_ioctl 29
#define NR_exit_group 94
#define NR_futex 98
#define NR_rt_sigaction 134
#define NR_mremap 216
#define NR_clone 220
#define NR_mmap 222
#define NR_wait4 260
#define NR_userfaultfd 282
#define NR_pipe2 59

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

#define PAGE 4096ul
#define EFAULT 14
#define EBUSY 16
#define EEXIST 17
#define EINVAL 22
#define EAGAIN 11
#define ENOENT 2
#define O_CLOEXEC 02000000
#define UFFD_USER_MODE_ONLY 1
#define UFFD_API 0xaa
#define UFFD_FEATURE_SIGBUS (1 << 7)
#define UFFDIO_API 0xc018aa3f
#define UFFDIO_REGISTER 0xc020aa00
#define UFFDIO_UNREGISTER 0x8010aa01
#define UFFDIO_COPY 0xc028aa03
#define UFFDIO_ZEROPAGE 0xc020aa04
#define MODE_MISSING 1
#define MREMAP_MAYMOVE 1
#define MREMAP_FIXED 2
#define MREMAP_DONTUNMAP 4
#define PROT_RW 3
#define MAP_PRIVATE_ANON 0x22
#define MAP_SHARED_ANON 0x21
#define SIGBUS 7
#define BUS_ADRERR 2

struct api_args { u64 api, features, ioctls; };
struct register_args { u64 start, len, mode, ioctls; };
struct range_args { u64 start, len; };
struct copy_args { u64 dst, src, len, mode; i64 copy; };
struct zero_args { u64 start, len, mode; i64 zeropage; };
struct sigaction_k { void *handler; u64 flags; void *restorer; u64 mask; };
struct siginfo_k { int signo, err, code, pad; u64 addr; };

static char *map_anon(u64 len) { return (char *)sys(NR_mmap, 0, len, PROT_RW, MAP_PRIVATE_ANON, -1, 0); }

static int open_uffd(void) {
    int fd = (int)sys(NR_userfaultfd, O_CLOEXEC | UFFD_USER_MODE_ONLY);
    struct api_args api = { UFFD_API, UFFD_FEATURE_SIGBUS, 0 };
    sys(NR_ioctl, fd, UFFDIO_API, &api);
    return fd;
}

static i64 reg(int fd, char *p, u64 len) {
    struct register_args r = { (u64)p, len, MODE_MISSING, 0 };
    return sys(NR_ioctl, fd, UFFDIO_REGISTER, &r);
}
static i64 unreg(int fd, char *p, u64 len) {
    struct range_args r = { (u64)p, len };
    return sys(NR_ioctl, fd, UFFDIO_UNREGISTER, &r);
}

// The handler plays ART's part: page N of the space holds the byte N+1.
static int uffd;
static char *space;
static u64 space_pages;
static char buffers[64][PAGE] __attribute__((aligned(4096)));
static volatile int sigbus_count, bad_sigbus, eexist_seen;
static volatile int next_buffer;

static void on_bus(int sig, struct siginfo_k *info, void *ctx) {
    (void)ctx;
    __atomic_fetch_add(&sigbus_count, 1, __ATOMIC_SEQ_CST);
    u64 page = (info->addr - (u64)space) / PAGE;
    if (sig != SIGBUS || info->code != BUS_ADRERR || page >= space_pages) {
        bad_sigbus = 1;
        sys(NR_exit_group, 99);
    }
    char *buf = buffers[__atomic_fetch_add(&next_buffer, 1, __ATOMIC_SEQ_CST) % 64];
    memset(buf, (int)(page + 1), PAGE);
    struct copy_args c = { (u64)space + page * PAGE, (u64)buf, PAGE, 0, 0 };
    i64 r = sys(NR_ioctl, uffd, UFFDIO_COPY, &c);
    if (r == -EEXIST) {
        __atomic_fetch_add(&eexist_seen, 1, __ATOMIC_SEQ_CST); // someone else mapped it first
    } else if (r != 0 || c.copy != PAGE) {
        bad_sigbus = 1;
        sys(NR_exit_group, 98);
    }
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

static volatile int wrong_byte;
static void reader(void *arg) {
    (void)arg;
    for (u64 i = 0; i < space_pages; i++) {
        if (((volatile char *)space)[i * PAGE + 7] != (char)(i + 1)) wrong_byte = 1;
    }
}

#define N_READERS 6
#define STACK (64 * 1024)
static char stacks[N_READERS][STACK] __attribute__((aligned(4096)));
static int tids[N_READERS];

int cmain(void) {
    // ---- the descriptor
    check(sys(NR_userfaultfd, 0x10) == -EINVAL, "unknown flags: EINVAL");
    int fd = (int)sys(NR_userfaultfd, O_CLOEXEC | UFFD_USER_MODE_ONLY);
    check(fd >= 0, "userfaultfd(O_CLOEXEC | UFFD_USER_MODE_ONLY)");
    struct register_args early = { 0x10000, PAGE, MODE_MISSING, 0 };
    check(sys(NR_ioctl, fd, UFFDIO_REGISTER, &early) == -EINVAL, "nothing works before UFFDIO_API");
    struct api_args bad = { 0x55, 0, 0 };
    check(sys(NR_ioctl, fd, UFFDIO_API, &bad) == -EINVAL, "UFFDIO_API with a wrong version: EINVAL");
    struct api_args asked = { UFFD_API, 0, 0 };
    check(sys(NR_ioctl, fd, UFFDIO_API, &asked) == 0 && (asked.features & UFFD_FEATURE_SIGBUS), "zero features asks what there is: SIGBUS is there");
    check(sys(NR_ioctl, fd, UFFDIO_API, &asked) == -EINVAL, "UFFDIO_API once only");
    sys(NR_close, fd);
    uffd = open_uffd();
    check(uffd >= 0, "a descriptor for the rest");
    char rd[8];
    check(sys(NR_read, uffd, rd, 8) == -EAGAIN, "no events to read");

    // ---- MREMAP_DONTUNMAP
    char *a = map_anon(4 * PAGE), *b = map_anon(4 * PAGE);
    memset(a, 0x5a, 4 * PAGE);
    check(sys(NR_mremap, a, 4 * PAGE, 4 * PAGE, MREMAP_DONTUNMAP, 0) == -EINVAL, "DONTUNMAP needs MAYMOVE");
    check(sys(NR_mremap, a, 4 * PAGE, 2 * PAGE, MREMAP_MAYMOVE | MREMAP_DONTUNMAP, 0) == -EINVAL, "DONTUNMAP can't change the size");
    check(sys(NR_mremap, a, 4 * PAGE, 4 * PAGE, MREMAP_MAYMOVE | MREMAP_FIXED | MREMAP_DONTUNMAP, b) == (i64)b, "pages moved to a fixed place");
    check(b[0] == 0x5a && b[4 * PAGE - 1] == 0x5a, "they're there");
    check(a[0] == 0 && a[4 * PAGE - 1] == 0, "and the old range is still mapped, without them");
    a[0] = 1;
    check(b[0] == 0x5a && a[0] == 1, "the two are separate");
    char *sh = (char *)sys(NR_mmap, 0, PAGE, PROT_RW, MAP_SHARED_ANON, -1, 0);
    check(sys(NR_mremap, sh, PAGE, PAGE, MREMAP_MAYMOVE | MREMAP_DONTUNMAP, 0) == -EINVAL, "DONTUNMAP is for private anonymous memory");

    // ---- registering
    check(reg(uffd, (char *)sh, PAGE) == -EINVAL, "shared memory can't be registered here");
    check(reg(uffd, a + 1, PAGE) == -EINVAL, "an unaligned range: EINVAL");
    struct register_args wrong_mode = { (u64)a, PAGE, 2, 0 };
    check(sys(NR_ioctl, uffd, UFFDIO_REGISTER, &wrong_mode) == -EINVAL, "only missing-page mode");
    int other = open_uffd();
    check(reg(uffd, b, PAGE) == 0 && reg(other, b, PAGE) == -EBUSY, "one descriptor at a time");
    check(unreg(uffd, b, PAGE) == 0 && reg(other, b, PAGE) == 0, "free once unregistered");
    sys(NR_close, other);
    check(reg(uffd, b, PAGE) == 0, "and when the other closes, it's gone");
    check(unreg(uffd, b, PAGE) == 0, "unregistered");

    // ---- a SIGBUS handler supplies pages
    struct sigaction_k act = { (void *)on_bus, 4 /* SA_SIGINFO */, 0, 0 };
    check(sys(NR_rt_sigaction, SIGBUS, &act, 0, 8) == 0, "rt_sigaction(SIGBUS)");
    space_pages = 512;
    u64 size = space_pages * PAGE;
    space = map_anon(size);
    char *from = map_anon(size);
    for (u64 i = 0; i < space_pages; i++) space[i * PAGE] = 0x11;
    check(sys(NR_mremap, space, size, size, MREMAP_MAYMOVE | MREMAP_FIXED | MREMAP_DONTUNMAP, from) == (i64)from, "the space's pages move out");
    check(from[0] == 0x11, "to the from-space");
    check(reg(uffd, space, size) == 0, "the emptied space registered");

    volatile char first = space[3 * PAGE + 5];
    check(sigbus_count == 1 && first == 4 && !bad_sigbus, "touching a page raises SIGBUS and the handler maps it");
    space[3 * PAGE + 5] = 9;
    check(space[3 * PAGE + 5] == 9 && sigbus_count == 1, "then it's ordinary memory");

    // ---- the ioctls' edges
    char *src = map_anon(4 * PAGE);
    memset(src, 0x77, 4 * PAGE);
    struct copy_args c = { (u64)space + 3 * PAGE, (u64)src, PAGE, 0, 0 };
    check(sys(NR_ioctl, uffd, UFFDIO_COPY, &c) == -EEXIST && c.copy == -EEXIST, "COPY onto a mapped page: EEXIST");
    c = (struct copy_args){ (u64)space + 1 * PAGE, (u64)src, 3 * PAGE, 0, 0 };
    check(sys(NR_ioctl, uffd, UFFDIO_COPY, &c) == -EAGAIN && c.copy == 2 * PAGE, "COPY up to a mapped page: EAGAIN and how far it got");
    check(space[PAGE] == 0x77 && space[2 * PAGE] == 0x77, "those pages are in");
    c = (struct copy_args){ (u64)space + 4 * PAGE, (u64)src + 1, PAGE, 0, 0 };
    check(sys(NR_ioctl, uffd, UFFDIO_COPY, &c) == -EINVAL, "COPY from an unaligned source: EINVAL");
    c = (struct copy_args){ (u64)src, (u64)buffers[0], PAGE, 0, 0 };
    check(sys(NR_ioctl, uffd, UFFDIO_COPY, &c) == -ENOENT, "COPY to unregistered memory: ENOENT");
    c = (struct copy_args){ (u64)space + 4 * PAGE, (u64)0x10000, PAGE, 0, 0 };
    check(sys(NR_ioctl, uffd, UFFDIO_COPY, &c) == -EFAULT, "COPY from nowhere: EFAULT");
    struct zero_args z = { (u64)space + 4 * PAGE, PAGE, 0, 0 };
    check(sys(NR_ioctl, uffd, UFFDIO_ZEROPAGE, &z) == 0 && z.zeropage == PAGE, "ZEROPAGE");
    check(space[4 * PAGE] == 0 && sigbus_count == 1, "reads zeros, with no fault");
    check(sys(NR_ioctl, uffd, UFFDIO_ZEROPAGE, &z) == -EEXIST && z.zeropage == -EEXIST, "ZEROPAGE onto a mapped page: EEXIST");

    // ---- the kernel gets EFAULT rather than a page (UFFD_USER_MODE_ONLY)
    int p[2];
    sys(NR_pipe2, p, 0);
    check(sys(NR_write, p[1], space + 5 * PAGE, 8) == -EFAULT, "write(2) from a missing page: EFAULT");
    sys(NR_write, p[1], "12345678", 8);
    check(sys(NR_read, p[0], space + 5 * PAGE, 8) == -EFAULT, "read(2) into one: EFAULT");
    check(sigbus_count == 1, "and no signal for it");

    // ---- threads race for pages
    __atomic_store_n(&sigbus_count, 0, __ATOMIC_SEQ_CST);
    // The first pages hold test values by now: start the space over, as a GC cycle does.
    check(unreg(uffd, space, size) == 0, "unregister before the next cycle");
    check(sys(NR_mremap, space, size, size, MREMAP_MAYMOVE | MREMAP_FIXED | MREMAP_DONTUNMAP, from) == (i64)from, "the next cycle's mremap finds it all one mapping");
    check(reg(uffd, space, size) == 0, "registered again");
    for (int i = 0; i < N_READERS; i++) {
        tids[i] = 1;
        spawn(stacks[i] + STACK, reader, 0, &tids[i]);
    }
    for (int i = 0; i < N_READERS; i++) join(&tids[i]);
    check(!bad_sigbus && !wrong_byte, "six threads read every page, each seeing the right one");
    check(sigbus_count >= (int)space_pages, "every page took a fault");
    puts_(eexist_seen ? "     (threads did race for a page)\n" : "     (no two threads met on a page)\n");

    // ---- after the collector
    check(unreg(uffd, space, size) == 0, "unregistered");
    char *fresh = map_anon(2 * PAGE);
    check(reg(uffd, fresh, 2 * PAGE) == 0 && unreg(uffd, fresh, 2 * PAGE) == 0 && fresh[0] == 0, "after unregistering, a missing page is an ordinary zero page");

    // ---- forks and closing
    char *kept = map_anon(2 * PAGE);
    check(reg(uffd, kept, 2 * PAGE) == 0, "registered for fork");
    i64 pid = sys(NR_clone, 17, 0, 0, 0, 0);
    if (pid == 0) {
        act.handler = 0;
        sys(NR_rt_sigaction, SIGBUS, &act, 0, 8);
        sys(NR_exit_group, kept[0] == 0 ? 0 : 1);
    }
    int st = -1;
    sys(NR_wait4, pid, &st, 0, 0);
    check(st == 0, "a fork's child faults its pages in as usual");
    int before = sigbus_count;
    sys(NR_close, uffd);
    check(kept[PAGE] == 0 && sigbus_count == before, "closing the descriptor ends it for the parent too");

    puts_(failures ? "SOME CHECKS FAILED\n" : "all checks passed\n");
    return failures;
}

void __attribute__((noreturn)) cstart(void) {
    sys(NR_exit_group, cmain());
    __builtin_unreachable();
}

__asm__(".global _start\n_start:\n bl cstart\n");

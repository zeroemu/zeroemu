// Freestanding arm64 test of zeroemu's writable filesystems and shared memory
// (no libc): tmpfs files, MAP_SHARED across fork and between processes,
// memfd passed over a socket and mapped by the receiver (the ashmem pattern).
// Exits with the failure count.

typedef unsigned long u64;
typedef long i64;

#define NR_dup 23
#define NR_unlinkat 35
#define NR_ftruncate 46
#define NR_openat 56
#define NR_close 57
#define NR_lseek 62
#define NR_read 63
#define NR_write 64
#define NR_pread64 67
#define NR_newfstatat 79
#define NR_fstat 80
#define NR_exit_group 94
#define NR_socketpair 199
#define NR_sendmsg 211
#define NR_recvmsg 212
#define NR_munmap 215
#define NR_clone 220
#define NR_mmap 222
#define NR_wait4 260
#define NR_memfd_create 279

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
static int seq(const char *a, const char *b, u64 n) { while (n--) if (*a++ != *b++) return 0; return 1; }
static void puts_(const char *s) { sys(NR_write, 1, s, slen(s)); }

static int failures;
static void check(int cond, const char *name) {
    puts_(cond ? "ok   " : "FAIL ");
    puts_(name);
    puts_("\n");
    if (!cond) failures++;
}

#define AT_FDCWD -100
#define O_RDWR 2
#define O_CREAT 0100
#define O_TRUNC 01000
#define O_APPEND 02000
#define PROT_RW 3
#define MAP_SHARED 1
#define MAP_ANON 0x20

static i64 fork_(void) { return sys(NR_clone, 17, 0, 0, 0, 0); }
static int wait_status(i64 pid) { int st = -1; sys(NR_wait4, pid, &st, 0, 0); return st; }
static void *mmap_(u64 len, int flags, int fd) { return (void *)sys(NR_mmap, 0, len, PROT_RW, flags, fd, 0); }

struct iovec { void *base; u64 len; };
struct msghdr { void *name; unsigned namelen, pad; struct iovec *iov; u64 iovlen; void *control; u64 controllen; int flags, pad2; };

int cmain(void) {
    char buf[64];

    // ---- tmpfs file basics ----
    int fd = (int)sys(NR_openat, AT_FDCWD, "/data/local/tmp/t", O_RDWR | O_CREAT | O_TRUNC, 0644);
    check(fd >= 0, "create a file on /data");
    sys(NR_write, fd, "abcdef", 6);
    sys(NR_lseek, fd, 2, 0);
    check(sys(NR_read, fd, buf, 64) == 4 && seq(buf, "cdef", 4), "write, lseek, read");
    int afd = (int)sys(NR_openat, AT_FDCWD, "/data/local/tmp/t", O_RDWR | O_APPEND, 0);
    sys(NR_write, afd, "XY", 2);
    check(sys(NR_pread64, fd, buf, 64, 0) == 8 && seq(buf, "abcdefXY", 8), "O_APPEND appends");
    sys(NR_ftruncate, fd, 3);
    check(sys(NR_pread64, fd, buf, 64, 0) == 3, "ftruncate shrinks");
    sys(NR_unlinkat, AT_FDCWD, "/data/local/tmp/t", 0);
    check(sys(NR_openat, AT_FDCWD, "/data/local/tmp/t", 0, 0) == -2 && sys(NR_pread64, fd, buf, 64, 0) == 3,
          "unlinked file stays readable while open");
    i64 ro = sys(NR_openat, AT_FDCWD, "/system/new", O_RDWR | O_CREAT, 0644);
    check(ro == -30 /* EROFS: image */ || ro == -2 /* ENOENT: no image, no /system */, "no file appears under /system");

    // ---- MAP_SHARED anonymous memory survives fork as shared ----
    volatile int *shared = mmap_(4096, MAP_SHARED | MAP_ANON, -1);
    volatile int *priv = mmap_(4096, 2 /* MAP_PRIVATE */ | MAP_ANON, -1);
    shared[0] = 1;
    priv[0] = 1;
    i64 pid = fork_();
    if (pid == 0) { shared[0] = 42; priv[0] = 42; sys(NR_exit_group, 0); }
    wait_status(pid);
    check(shared[0] == 42 && priv[0] == 1, "fork: MAP_SHARED shared, MAP_PRIVATE copied");

    // ---- a tmpfs file mapped shared by two processes, coherent with write() ----
    int sf = (int)sys(NR_openat, AT_FDCWD, "/dev/shm-test", O_RDWR | O_CREAT | O_TRUNC, 0600);
    sys(NR_ftruncate, sf, 8192);
    char *m = mmap_(8192, MAP_SHARED, sf);
    pid = fork_();
    if (pid == 0) {
        char *cm = mmap_(8192, MAP_SHARED, sf); // a second, independent mapping
        memcpy(cm + 4096, "from child", 10);
        sys(NR_exit_group, 0);
    }
    wait_status(pid);
    char fbuf[16];
    sys(NR_pread64, sf, fbuf, 10, 4096);
    check(seq(m + 4096, "from child", 10) && seq(fbuf, "from child", 10), "file pages shared across processes and read()");
    sys(NR_lseek, sf, 0, 0);
    sys(NR_write, sf, "written", 7);
    check(seq(m, "written", 7), "write() shows up in an existing mapping");

    // ---- memfd passed over a socket, mapped by the receiver (ashmem pattern) ----
    int mfd = (int)sys(NR_memfd_create, "region", 0);
    sys(NR_ftruncate, mfd, 4096);
    volatile char *region = mmap_(4096, MAP_SHARED, mfd);
    int sv[2];
    sys(NR_socketpair, 1, 1, 0, sv);
    pid = fork_();
    if (pid == 0) {
        union { char b[32]; u64 align; } ctl;
        char d;
        struct iovec iov = { &d, 1 };
        struct msghdr mh = { 0, 0, 0, &iov, 1, ctl.b, sizeof ctl.b, 0, 0 };
        if (sys(NR_recvmsg, sv[1], &mh, 0) != 1) sys(NR_exit_group, 1);
        int got = *(int *)(ctl.b + 16);
        volatile char *r = mmap_(4096, MAP_SHARED, got);
        memcpy((char *)r, "via memfd", 9);
        sys(NR_exit_group, 0);
    }
    {
        union { char b[24]; u64 align; } ctl;
        memset(&ctl, 0, sizeof ctl);
        *(u64 *)ctl.b = 20;
        *(int *)(ctl.b + 8) = 1;
        *(int *)(ctl.b + 12) = 1;
        *(int *)(ctl.b + 16) = mfd;
        struct iovec iov = { "M", 1 };
        struct msghdr mh = { 0, 0, 0, &iov, 1, ctl.b, 24, 0, 0 };
        sys(NR_sendmsg, sv[0], &mh, 0);
        check(wait_status(pid) == 0 && seq((char *)region, "via memfd", 9), "memfd over SCM_RIGHTS, mapped in both");
    }

    // ---- unmapping a shared view leaves the object intact ----
    sys(NR_munmap, m, 8192);
    char *again = mmap_(8192, MAP_SHARED, sf);
    check(seq(again, "written", 7) && seq(again + 4096, "from child", 10), "remapping sees the same contents");

    puts_(failures ? "SOME CHECKS FAILED\n" : "all checks passed\n");
    return failures;
}

void __attribute__((noreturn)) cstart(void) {
    sys(NR_exit_group, cmain());
    __builtin_unreachable();
}

__asm__(".global _start\n_start:\n bl cstart\n");

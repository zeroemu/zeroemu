// Freestanding arm64 test of zeroemu's mount layer (no libc): mount(2) and
// umount2(2) on the guest's tmpfs root, propagation, tmpfs size limits,
// /proc/self/mountinfo and its poll notification, unshare/setns and
// /proc/self/ns, sysctl writes, and pipe sizes (F_GETPIPE_SZ/F_SETPIPE_SZ).
// Exits with the failure count.

typedef unsigned long u64;
typedef long i64;
typedef unsigned int u32;

#define NR_epoll_create1 20
#define NR_epoll_ctl 21
#define NR_epoll_pwait 22
#define NR_fcntl 25
#define NR_mkdirat 34
#define NR_linkat 37
#define NR_umount2 39
#define NR_mount 40
#define NR_statfs 43
#define NR_truncate 45
#define NR_openat 56
#define NR_close 57
#define NR_pipe2 59
#define NR_read 63
#define NR_write 64
#define NR_readlinkat 78
#define NR_newfstatat 79
#define NR_fstat 80
#define NR_utimensat 88
#define NR_exit_group 94
#define NR_unshare 97
#define NR_setns 268

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
// Whether `needle` occurs in the first `n` bytes of `hay`.
static int contains(const char *hay, i64 n, const char *needle) {
    u64 m = slen(needle);
    for (i64 i = 0; i + (i64)m <= n; i++)
        if (seq(hay + i, needle, m)) return 1;
    return 0;
}

static int failures;
static void check(int cond, const char *name) {
    puts_(cond ? "ok   " : "FAIL ");
    puts_(name);
    puts_("\n");
    if (!cond) failures++;
}

#define AT_FDCWD -100
#define O_RDONLY 0
#define O_WRONLY 1
#define O_RDWR 2
#define O_CREAT 0100
#define O_NONBLOCK 04000
#define EPERM 1
#define ENOENT 2
#define EBADF 9
#define EAGAIN 11
#define EBUSY 16
#define EXDEV 18
#define ENODEV 19
#define EINVAL 22
#define ENOSPC 28
#define EROFS 30
#define MS_RDONLY 1
#define MS_NOSUID 2
#define MS_REMOUNT 32
#define MS_BIND 4096
#define MS_REC 16384
#define MS_PRIVATE (1 << 18)
#define MS_SHARED (1 << 20)
#define CLONE_NEWNS 0x20000
#define CLONE_NEWNET 0x40000000
#define F_SETPIPE_SZ 1031
#define F_GETPIPE_SZ 1032

struct epoll_event { u32 events; u32 pad; u64 data; }; // arm64: not packed

static char buf[16384];

static i64 slurp(const char *path) {
    int fd = (int)sys(NR_openat, AT_FDCWD, path, O_RDONLY, 0);
    if (fd < 0) return fd;
    i64 n = 0, r;
    while ((r = sys(NR_read, fd, buf + n, sizeof buf - 1 - n)) > 0) n += r;
    sys(NR_close, fd);
    buf[n] = 0;
    return n;
}

static i64 put(const char *path, const char *s) {
    int fd = (int)sys(NR_openat, AT_FDCWD, path, O_WRONLY | O_CREAT, 0644);
    if (fd < 0) return fd;
    i64 r = sys(NR_write, fd, s, slen(s));
    sys(NR_close, fd);
    return r;
}

int cmain(void) {
    // ---- mount/umount2 ----
    sys(NR_mkdirat, AT_FDCWD, "/tmp/m", 0755);
    check(sys(NR_mount, "tmpfs", "/tmp/m", "tmpfs", MS_NOSUID, "size=8k,mode=0700") == 0, "mount tmpfs with options");
    u64 st[16];
    sys(NR_newfstatat, AT_FDCWD, "/tmp/m", st, 0);
    check((((u32 *)st)[4] & 07777) == 0700, "mode= sets the root's permissions");
    u64 sfs[15];
    check(sys(NR_statfs, "/tmp/m", sfs) == 0 && sfs[0] == 0x01021994 && sfs[2] == 2 && (sfs[10] & 2), "statfs: tmpfs magic, size= blocks, ST_NOSUID");
    i64 n = slurp("/proc/self/mountinfo");
    check(contains(buf, n, " / /tmp/m rw,nosuid,relatime - tmpfs tmpfs rw,seclabel,size=8k,mode=700\n"), "mountinfo shows the new mount");
    static char page[8192];
    int fd = (int)sys(NR_openat, AT_FDCWD, "/tmp/m/f", O_RDWR | O_CREAT, 0644);
    check(sys(NR_write, fd, page, 4096) == 4096 && sys(NR_write, fd, page, 8192) == 4096 && sys(NR_write, fd, page, 1) == -ENOSPC, "size= limits contents: short write, then ENOSPC");
    sys(NR_close, fd);
    check(sys(NR_umount2, "/tmp/m", 0) == 0 && sys(NR_umount2, "/tmp/m", 0) == -EINVAL, "umount2, then EINVAL: not a mount point");
    check(sys(NR_openat, AT_FDCWD, "/tmp/m/f", O_RDONLY, 0) == -ENOENT, "the mount's files are gone with it");
    check(sys(NR_mount, "none", "/tmp/m", "nosuchfs", 0, 0) == -ENODEV, "unknown fstype: ENODEV");
    check(sys(NR_mount, "none", "/tmp/nowhere", "tmpfs", 0, 0) == -ENOENT, "missing target: ENOENT");
    check(sys(NR_mount, "none", "/tmp/m", 0, 0, 0) == -EINVAL, "no fstype: EINVAL");

    // ---- bind, remount, propagation ----
    sys(NR_mkdirat, AT_FDCWD, "/tmp/src", 0755);
    sys(NR_mkdirat, AT_FDCWD, "/tmp/dst", 0755);
    put("/tmp/src/hello", "bound\n");
    check(sys(NR_mount, "/tmp/src", "/tmp/dst", 0, MS_BIND, 0) == 0 && slurp("/tmp/dst/hello") == 6 && seq(buf, "bound", 5), "bind mount shows the source");
    put("/tmp/dst/also", "bound\n");
    // Linux compares vfsmounts, not superblocks (do_linkat, do_renameat2).
    check(sys(NR_linkat, AT_FDCWD, "/tmp/src/hello", AT_FDCWD, "/tmp/dst/l", 0) == -EXDEV, "link across a bind mount: EXDEV");
    int dfd = (int)sys(NR_openat, AT_FDCWD, "/tmp/dst/also", O_RDWR, 0);
    check(dfd >= 0 && sys(NR_mount, 0, "/tmp/dst", 0, MS_REMOUNT | MS_BIND | MS_RDONLY, 0) == 0, "remount,bind,ro");
    check(sys(NR_write, dfd, "no", 2) == -EROFS && put("/tmp/dst/x", "no") == -EROFS && put("/tmp/src/x", "yes") == 3, "read-only there only, including an fd opened before");
    check(sys(NR_mount, "", "/", 0, MS_SHARED | MS_REC, 0) == 0, "make / rshared");
    n = slurp("/proc/self/mountinfo");
    check(contains(buf, n, " shared:"), "mountinfo shows peer groups");
    check(sys(NR_mount, "", "/tmp/src", 0, MS_PRIVATE, 0) == -EINVAL, "propagation change off a mount point: EINVAL");
    check(sys(NR_mount, "", "/tmp/dst", 0, MS_PRIVATE | MS_RDONLY, 0) == -EINVAL, "propagation flags with others: EINVAL");
    check(sys(NR_umount2, "/tmp/dst", 2 /* MNT_DETACH */) == 0, "umount2 MNT_DETACH");
    check(sys(NR_mkdirat, AT_FDCWD, "/tmp", 0755) == -17, "mkdir of a mount point: EEXIST");

    // A remount to read-only covers descriptors opened while it was writable.
    sys(NR_mkdirat, AT_FDCWD, "/tmp/ro", 0755);
    check(sys(NR_mount, "tmpfs", "/tmp/ro", "tmpfs", 0, 0) == 0, "mount tmpfs to remount");
    int wfd = (int)sys(NR_openat, AT_FDCWD, "/tmp/ro/f", O_RDWR | O_CREAT, 0644);
    check(sys(NR_write, wfd, "ab", 2) == 2 && sys(NR_mount, 0, "/tmp/ro", 0, MS_REMOUNT | MS_RDONLY, 0) == 0, "remount the tmpfs read-only");
    check(sys(NR_write, wfd, "cd", 2) == -EROFS, "write through a pre-opened fd: EROFS");
    check(sys(NR_truncate, "/tmp/ro/f", 0) == -EROFS, "truncate on a read-only mount: EROFS");
    check(sys(NR_utimensat, AT_FDCWD, "/tmp/ro/f", 0, 0) == -EROFS, "utimensat on a read-only tmpfs: EROFS");

    // ---- /proc/self/mounts notifies pollers of changes ----
    int mfd = (int)sys(NR_openat, AT_FDCWD, "/proc/self/mounts", O_RDONLY, 0);
    int ep = (int)sys(NR_epoll_create1, 0);
    struct epoll_event ev = { 0x8 | 0x2 /* EPOLLERR | EPOLLPRI */, 0, 7 }, out[2];
    check(sys(NR_epoll_ctl, ep, 1, mfd, &ev) == 0, "epoll accepts /proc/self/mounts");
    i64 quiet = sys(NR_epoll_pwait, ep, out, 2, 0, 0, 8);
    sys(NR_mount, "tmpfs", "/tmp/m", "tmpfs", 0, 0);
    i64 woke = sys(NR_epoll_pwait, ep, out, 2, 1000, 0, 8);
    check(quiet == 0 && woke == 1 && (out[0].events & 0x2), "a mount wakes it with EPOLLPRI");
    sys(NR_umount2, "/tmp/m", 0);

    // ---- namespaces ----
    check(sys(NR_unshare, CLONE_NEWNS) == 0, "unshare(CLONE_NEWNS)");
    check(sys(NR_unshare, CLONE_NEWNET) == -EINVAL, "unshare(CLONE_NEWNET): EINVAL");
    char link[64];
    i64 ln = sys(NR_readlinkat, AT_FDCWD, "/proc/self/ns/mnt", link, sizeof link);
    check(ln == 16 && seq(link, "mnt:[4026532001]", 16), "readlink /proc/self/ns/mnt: a new namespace");
    int nfd = (int)sys(NR_openat, AT_FDCWD, "/proc/self/ns/mnt", O_RDONLY, 0);
    sys(NR_fstat, nfd, st);
    check(nfd >= 0 && st[1] == 4026532001ul, "open /proc/self/ns/mnt: the nsfs inode");
    check(sys(NR_setns, nfd, CLONE_NEWNS) == 0 && sys(NR_setns, nfd, 0) == 0, "setns to the mount namespace");
    check(sys(NR_setns, nfd, CLONE_NEWNET) == -EINVAL, "setns with the wrong type: EINVAL");
    check(sys(NR_setns, 1, CLONE_NEWNS) == -EINVAL, "setns on a non-namespace fd: EINVAL");

    // ---- sysctls ----
    check(put("/proc/sys/kernel/kptr_restrict", "4") == -EINVAL && put("/proc/sys/kernel/kptr_restrict", "2\n") == 2, "kptr_restrict: out of range refused, 2 taken");
    check(slurp("/proc/sys/kernel/kptr_restrict") == 2 && seq(buf, "2\n", 2), "kptr_restrict reads back");
    check(put("/proc/sys/kernel/osrelease", "x") < 0, "read-only sysctl refuses writes");

    // ---- pipe sizes ----
    int p[2];
    sys(NR_pipe2, p, O_NONBLOCK);
    check(sys(NR_fcntl, p[1], F_GETPIPE_SZ) == 65536, "F_GETPIPE_SZ: 64 KiB by default");
    check(sys(NR_fcntl, p[0], F_SETPIPE_SZ, 100000) == 131072 && sys(NR_fcntl, p[1], F_GETPIPE_SZ) == 131072, "F_SETPIPE_SZ rounds up to a power of two");
    static char big[100000];
    check(sys(NR_write, p[1], big, sizeof big) == (i64)sizeof big, "the capacity really grew");
    check(sys(NR_fcntl, p[1], F_SETPIPE_SZ, 4096) == -EBUSY, "shrinking below the queued bytes: EBUSY");
    while (sys(NR_read, p[0], big, sizeof big) > 0) {}
    check(sys(NR_fcntl, p[1], F_SETPIPE_SZ, 1) == 4096, "shrinks to one page once drained");
    check(sys(NR_write, p[1], big, 8192) == 4096 && sys(NR_write, p[1], big, 1) == -EAGAIN, "a one-page pipe holds one page");
    check(sys(NR_fcntl, p[1], F_SETPIPE_SZ, (1ul << 31) + 1) == -EINVAL, "F_SETPIPE_SZ above 2 GiB: EINVAL");
    check(sys(NR_fcntl, nfd, F_GETPIPE_SZ) == -EBADF, "F_GETPIPE_SZ on a non-pipe: EBADF");

    puts_(failures ? "SOME CHECKS FAILED\n" : "all checks passed\n");
    return failures;
}

void __attribute__((noreturn)) cstart(void) {
    sys(NR_exit_group, cmain());
    __builtin_unreachable();
}

__asm__(".global _start\n_start:\n bl cstart\n");

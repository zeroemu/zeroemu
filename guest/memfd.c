// Freestanding arm64 test of zeroemu's memfd seals (fcntl F_ADD_SEALS and
// F_GET_SEALS), as Linux has them. Android 16 QPR2's hwui parcels a bitmap
// over 12 KB as memfd_create, write, then F_ADD_SEALS(F_SEAL_GROW |
// F_SEAL_SHRINK | F_SEAL_FUTURE_WRITE); the receiver maps it MAP_SHARED and
// read-only, and libcutils tells it is a memfd by its /proc/self/fd link. ART's
// zygote seals its JIT cache the same way while its writable views stay mapped.

typedef unsigned long u64;
typedef long i64;
typedef unsigned int u32;

#define NR_dup 23
#define NR_fcntl 25
#define NR_ioctl 29
#define NR_ftruncate 46
#define NR_fallocate 47
#define NR_openat 56
#define NR_close 57
#define NR_pipe2 59
#define NR_read 63
#define NR_write 64
#define NR_pread64 67
#define NR_pwrite64 68
#define NR_readlinkat 78
#define NR_fstat 80
#define NR_exit 93
#define NR_exit_group 94
#define NR_munmap 215
#define NR_mremap 216
#define NR_clone 220
#define NR_mmap 222
#define NR_mprotect 226
#define NR_madvise 233
#define NR_wait4 260
#define NR_memfd_create 279

#define EPERM 1
#define EBADF 9
#define EACCES 13
#define EBUSY 16
#define EINVAL 22
#define ENOTTY 25

#define O_RDONLY 0
#define O_RDWR 2
#define O_CREAT 0100
#define O_TRUNC 01000
#define MFD_CLOEXEC 1
#define MFD_ALLOW_SEALING 2
#define MFD_NOEXEC_SEAL 8
#define MFD_EXEC 0x10
#define F_ADD_SEALS 1033
#define F_GET_SEALS 1034
#define F_SEAL_SEAL 1
#define F_SEAL_SHRINK 2
#define F_SEAL_GROW 4
#define F_SEAL_WRITE 8
#define F_SEAL_FUTURE_WRITE 16
#define F_SEAL_EXEC 32
#define PROT_READ 1
#define PROT_WRITE 2
#define PROT_EXEC 4
#define MAP_SHARED 1
#define MAP_PRIVATE 2
#define MAP_FIXED 0x10
#define MAP_ANONYMOUS 0x20
#define MAP_FIXED_NOREPLACE 0x100000
#define MADV_DONTFORK 10
#define MREMAP_MAYMOVE 1
#define FALLOC_FL_KEEP_SIZE 1
#define FALLOC_FL_PUNCH_HOLE 2
#define ASHMEM_GET_SIZE 0x7704

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
static void puts_(const char *s) { sys(NR_write, 1, s, slen(s)); }
static int starts(const char *s, const char *prefix) { while (*prefix && *s == *prefix) s++, prefix++; return !*prefix; }

static int failures;
static void check(int cond, const char *name) {
    puts_(cond ? "ok   " : "FAIL ");
    puts_(name);
    puts_("\n");
    if (!cond) failures++;
}

static i64 fork_(void) { return sys(NR_clone, 17 /* SIGCHLD */, 0, 0, 0, 0); }
static int wait_status(i64 pid) { int st = -1; sys(NR_wait4, pid, &st, 0, 0); return st; }

// The size of the bitmap in the report: 347 x 346 x 4 bytes, not a whole number of pages.
#define SIZE 480248
static unsigned char buf[SIZE];
#define PIXELS (F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_FUTURE_WRITE)

static i64 size_of(int fd) {
    static u64 st[16];
    return sys(NR_fstat, fd, st) == 0 ? (i64)st[6] : -1; // st_size
}

static u32 mode_of(int fd) {
    static u64 st[16];
    return sys(NR_fstat, fd, st) == 0 ? ((u32 *)st)[4] : 0; // st_mode
}

static int link_of(int fd, char *out, int len) {
    char path[32] = "/proc/self/fd/";
    int i = 14;
    if (fd >= 10) path[i++] = (char)('0' + fd / 10);
    path[i++] = (char)('0' + fd % 10);
    path[i] = 0;
    i64 n = sys(NR_readlinkat, -100, path, out, len - 1);
    if (n < 0) return 0;
    out[n] = 0;
    return 1;
}

static int has_pixels(const unsigned char *p) {
    for (int i = 0; i < SIZE; i++)
        if (p[i] != (unsigned char)(i * 7)) return 0;
    return 1;
}

// What another process does with the descriptor it was sent: hwui's reader, and
// libcutils' checks on it. Run in a child, which has the same open file.
static int receiver(int fd) {
    int bad = 0;
    static char link[128];
    bad += !(sys(NR_fcntl, fd, F_GET_SEALS) == PIXELS);
    bad += !(link_of(fd, link, sizeof link) && starts(link, "/memfd:bitmap"));
    bad += !(size_of(fd) == SIZE);
    bad += !(sys(NR_fcntl, fd, F_ADD_SEALS, F_SEAL_FUTURE_WRITE) == 0); // ashmem_set_prot_region(PROT_READ)
    unsigned char *r = (unsigned char *)sys(NR_mmap, 0, SIZE, PROT_READ, MAP_SHARED, fd, 0);
    bad += !((i64)r > 0 && has_pixels(r));
    bad += !(sys(NR_mmap, 0, SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0) == -EPERM);
    return bad;
}

int cmain(void) {
    for (int i = 0; i < SIZE; i++) buf[i] = (unsigned char)(i * 7);

    // hwui's writer.
    int fd = (int)sys(NR_memfd_create, "bitmap", MFD_CLOEXEC | MFD_ALLOW_SEALING);
    check(fd >= 0, "memfd_create with MFD_ALLOW_SEALING");
    check(sys(NR_fcntl, fd, F_GET_SEALS) == 0, "F_GET_SEALS: none yet");
    check(mode_of(fd) == 0100777, "fstat: a regular file, mode 0777");
    static char link[128];
    check(link_of(fd, link, sizeof link) && starts(link, "/memfd:bitmap"), "its /proc/self/fd link starts with /memfd:");
    check(sys(NR_write, fd, buf, SIZE) == SIZE && size_of(fd) == SIZE, "write the pixels; fstat has the size");
    check(sys(NR_fcntl, fd, F_ADD_SEALS, PIXELS) == 0, "F_ADD_SEALS grow, shrink and future write");
    check(sys(NR_fcntl, fd, F_GET_SEALS) == PIXELS, "F_GET_SEALS returns them");
    int dfd = (int)sys(NR_dup, fd);
    check(sys(NR_fcntl, dfd, F_GET_SEALS) == PIXELS, "a dup shares the seals");
    sys(NR_close, dfd);
    check(sys(NR_ioctl, fd, ASHMEM_GET_SIZE, 0) == -ENOTTY, "no ashmem ioctls on a memfd, so libcutils keeps /dev/ashmem");

    // What the seals forbid.
    check(sys(NR_pwrite64, fd, buf, 16, 0) == -EPERM, "future write: pwrite is refused");
    check(sys(NR_write, fd, buf, 16) == -EPERM, "future write: write is refused");
    check(sys(NR_write, fd, buf, 0) == 0, "an empty write still returns 0");
    check(sys(NR_ftruncate, fd, 4096) == -EPERM, "shrink: a smaller ftruncate is refused");
    check(sys(NR_ftruncate, fd, SIZE + 4096) == -EPERM, "grow: a larger ftruncate is refused");
    check(sys(NR_ftruncate, fd, SIZE) == 0, "an ftruncate to the same size is allowed");
    check(sys(NR_fallocate, fd, 0, 0, SIZE + 8192) == -EPERM, "grow: fallocate past the end is refused");
    check(sys(NR_fallocate, fd, FALLOC_FL_KEEP_SIZE, 0, SIZE + 8192) == -EPERM, "grow: even keeping the size");
    check(sys(NR_fallocate, fd, 0, 0, 4096) == 0, "fallocate inside the file is allowed");
    check(sys(NR_fallocate, fd, FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE, 0, 4096) == -EPERM, "future write: punching a hole is refused");
    check(sys(NR_mmap, 0, SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0) == -EPERM, "future write: a writable shared mapping is refused");

    // hwui's reader: a shared read-only mapping of the received fd.
    unsigned char *r = (unsigned char *)sys(NR_mmap, 0, SIZE, PROT_READ, MAP_SHARED, fd, 0);
    check((i64)r > 0, "a read-only shared mapping is allowed");
    check((i64)r > 0 && has_pixels(r), "it has every byte, the last partial page too");
    check(sys(NR_mprotect, r, SIZE, PROT_READ | PROT_WRITE) == -EACCES, "mprotect can't make it writable");
    sys(NR_munmap, r, SIZE);

    unsigned char *pv = (unsigned char *)sys(NR_mmap, 0, SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
    check((i64)pv > 0, "a writable private mapping is allowed");
    if ((i64)pv > 0) {
        pv[100] = (unsigned char)(buf[100] + 1);
        unsigned char b = 0;
        check(sys(NR_pread64, fd, &b, 1, 100) == 1 && b == buf[100], "writing it leaves the file alone");
        sys(NR_munmap, pv, SIZE);
    }

    i64 pid = fork_();
    if (pid == 0) sys(NR_exit, receiver(fd));
    check(pid > 0 && wait_status(pid) == 0, "another process: same seals, /memfd: link, size, mapping, refusals");
    sys(NR_close, fd);

    // ART's zygote (jit_memory_region.cc): a writable view kept out of the apps it
    // forks, then F_SEAL_SHRINK | GROW | SEAL | FUTURE_WRITE. The writable view keeps
    // working; after the seal only read-only and executable views can be added, and
    // the executable one replaces part of a read-only one.
    fd = (int)sys(NR_memfd_create, "jit-zygote-cache", MFD_ALLOW_SEALING);
    check(sys(NR_ftruncate, fd, 8192) == 0, "a second memfd, sized with ftruncate");
    unsigned char *w = (unsigned char *)sys(NR_mmap, 0, 8192, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    check((i64)w > 0 && sys(NR_madvise, w, 8192, MADV_DONTFORK) == 0
              && sys(NR_fcntl, fd, F_ADD_SEALS, F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_SEAL | F_SEAL_FUTURE_WRITE) == 0
              && sys(NR_fcntl, fd, F_GET_SEALS) == (F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_SEAL | F_SEAL_FUTURE_WRITE),
          "map it writable and out of children, then seal it as ART does");
    if ((i64)w > 0) {
        w[5000] = 42;
        unsigned char b = 0;
        check(sys(NR_pread64, fd, &b, 1, 5000) == 1 && b == 42, "the earlier mapping can still write");
        unsigned char *ro = (unsigned char *)sys(NR_mmap, 0, 8192, PROT_READ, MAP_SHARED, fd, 0);
        check((i64)ro > 0 && ro[5000] == 42, "a read-only view made after the seal sees it");
        if ((i64)ro > 0) {
            unsigned char *rx = (unsigned char *)sys(NR_mmap, ro + 4096, 4096, PROT_READ | PROT_EXEC, MAP_SHARED | MAP_FIXED, fd, 4096);
            check(rx == ro + 4096 && rx[5000 - 4096] == 42 && sys(NR_mprotect, rx, 4096, PROT_READ | PROT_WRITE) == -EACCES,
                  "an executable view over part of it, which can't be made writable");
            i64 child = fork_();
            if (child == 0) {
                // The writable view's range is free in the child: NOREPLACE takes it.
                i64 there = sys(NR_mmap, w, 4096, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
                sys(NR_exit, !(there == (i64)w && rx[5000 - 4096] == 42));
            }
            check(child > 0 && wait_status(child) == 0, "a forked child has the executable view and not the writable one");
            sys(NR_munmap, ro, 8192);
        }
        sys(NR_munmap, w, 8192);
    }
    sys(NR_close, fd);

    // F_SEAL_WRITE waits until no shared mapping may write, in any process, read-only
    // ones of a writable descriptor too (Linux 6.7 and later count those).
    fd = (int)sys(NR_memfd_create, "write", MFD_ALLOW_SEALING);
    sys(NR_ftruncate, fd, 8192);
    w = (unsigned char *)sys(NR_mmap, 0, 8192, PROT_READ, MAP_SHARED, fd, 0);
    check((i64)w > 0 && sys(NR_fcntl, fd, F_ADD_SEALS, F_SEAL_WRITE) == -EBUSY, "F_SEAL_WRITE with a shared mapping that may write: EBUSY");
    // Something just past it, so that growing it has to move it.
    i64 blocker = sys(NR_mmap, w + 8192, 4096, 0, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
    unsigned char *moved = (unsigned char *)sys(NR_mremap, w, 8192, 16384, MREMAP_MAYMOVE);
    check((i64)moved > 0 && moved != w && sys(NR_fcntl, fd, F_ADD_SEALS, F_SEAL_WRITE) == -EBUSY, "still EBUSY once mremap has moved it");
    if ((i64)moved > 0) w = moved;
    if (blocker > 0) sys(NR_munmap, blocker, 4096);
    int p[2];
    sys(NR_pipe2, p, 0);
    pid = fork_();
    if (pid == 0) {
        char c;
        sys(NR_read, p[0], &c, 1); // keep the inherited mapping until told
        sys(NR_exit, 0);
    }
    sys(NR_munmap, w, 16384);
    check(sys(NR_fcntl, fd, F_ADD_SEALS, F_SEAL_WRITE) == -EBUSY, "EBUSY while a forked child still has the mapping");
    sys(NR_write, p[1], "x", 1);
    wait_status(pid);
    sys(NR_close, p[0]);
    sys(NR_close, p[1]);
    unsigned char *pw = (unsigned char *)sys(NR_mmap, 0, 8192, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
    check(sys(NR_fcntl, fd, F_ADD_SEALS, F_SEAL_WRITE) == 0, "once it has exited, F_SEAL_WRITE is added; private mappings don't count");
    if ((i64)pw > 0) sys(NR_munmap, pw, 8192);
    check(sys(NR_mmap, 0, 8192, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0) == -EPERM, "write: a writable shared mapping is refused");
    r = (unsigned char *)sys(NR_mmap, 0, 8192, PROT_READ, MAP_SHARED, fd, 0);
    check((i64)r > 0 && sys(NR_mprotect, r, 8192, PROT_READ | PROT_WRITE) == -EACCES, "a read-only one is allowed, and stays so");
    if ((i64)r > 0) sys(NR_munmap, r, 8192);
    check(sys(NR_pwrite64, fd, buf, 1, 0) == -EPERM && sys(NR_ftruncate, fd, 0) == 0, "write: no writes, but it can still shrink");

    // F_SEAL_SEAL, unknown bits.
    check(sys(NR_fcntl, fd, F_ADD_SEALS, 64) == -EINVAL, "an unknown seal: EINVAL");
    check(sys(NR_fcntl, fd, F_ADD_SEALS, F_SEAL_SEAL) == 0 && sys(NR_fcntl, fd, F_ADD_SEALS, F_SEAL_SHRINK) == -EPERM, "after F_SEAL_SEAL, no more seals");
    sys(NR_close, fd);

    fd = (int)sys(NR_memfd_create, "plain", 0);
    check(sys(NR_fcntl, fd, F_GET_SEALS) == F_SEAL_SEAL, "without MFD_ALLOW_SEALING: sealed against seals");
    check(sys(NR_fcntl, fd, F_ADD_SEALS, F_SEAL_WRITE) == -EPERM, "so F_ADD_SEALS is refused");
    sys(NR_close, fd);

    // F_SEAL_GROW alone: writes inside the file still work; past the end they don't.
    fd = (int)sys(NR_memfd_create, "grow", MFD_ALLOW_SEALING);
    sys(NR_ftruncate, fd, 10000);
    check(sys(NR_fcntl, fd, F_ADD_SEALS, F_SEAL_GROW) == 0, "seal a memfd against growing only");
    check(sys(NR_pwrite64, fd, buf, 100, 4096) == 100, "grow: a write inside the file works");
    check(sys(NR_pwrite64, fd, buf, 100, 10000) == -EPERM, "grow: a write at the end is refused");
    check(sys(NR_pwrite64, fd, buf, 12000, 0) == 8192 && size_of(fd) == 10000, "grow: a write over the end stops at the last page boundary before it");
    check(sys(NR_pwrite64, fd, buf, 1, 20000) == -EPERM && size_of(fd) == 10000, "grow: one past the end, and the size stays");
    sys(NR_close, fd);

    // MFD_NOEXEC_SEAL; F_SEAL_EXEC on an executable memfd seals writing too, without
    // waiting for writable mappings (they keep working).
    fd = (int)sys(NR_memfd_create, "noexec", MFD_NOEXEC_SEAL);
    check(fd >= 0 && sys(NR_fcntl, fd, F_GET_SEALS) == F_SEAL_EXEC && mode_of(fd) == 0100666, "MFD_NOEXEC_SEAL: mode 0666, F_SEAL_EXEC set");
    check(sys(NR_fcntl, fd, F_ADD_SEALS, F_SEAL_SHRINK) == 0, "and sealing is allowed without MFD_ALLOW_SEALING");
    sys(NR_close, fd);
    fd = (int)sys(NR_memfd_create, "exec", MFD_ALLOW_SEALING);
    sys(NR_ftruncate, fd, 4096);
    w = (unsigned char *)sys(NR_mmap, 0, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    check(sys(NR_fcntl, fd, F_ADD_SEALS, F_SEAL_EXEC) == 0, "F_SEAL_EXEC with a writable mapping");
    check(sys(NR_fcntl, fd, F_GET_SEALS) == (F_SEAL_EXEC | F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE | F_SEAL_FUTURE_WRITE), "on an executable memfd it brings the write seals");
    if ((i64)w > 0) {
        w[10] = 7;
        unsigned char b = 0;
        check(sys(NR_pread64, fd, &b, 1, 10) == 1 && b == 7, "and the mapping still writes");
        sys(NR_munmap, w, 4096);
    }
    sys(NR_close, fd);

    // memfd_create's own checks.
    check(sys(NR_memfd_create, "bad", 0x100) == -EINVAL, "an unknown flag: EINVAL");
    check(sys(NR_memfd_create, "bad", MFD_EXEC | MFD_NOEXEC_SEAL) == -EINVAL, "MFD_EXEC with MFD_NOEXEC_SEAL: EINVAL");
    static char longname[300];
    for (int i = 0; i < 250; i++) longname[i] = 'n';
    check(sys(NR_memfd_create, longname, 0) == -EINVAL, "a 250-byte name: EINVAL");
    longname[249] = 0;
    fd = (int)sys(NR_memfd_create, longname, 0);
    check(fd >= 0, "a 249-byte name is allowed");
    sys(NR_close, fd);

    // A write over IO_MAX goes in whole, as on Linux: hwui writes a bitmap in one call.
    u64 big = (17 << 20) + 123;
    unsigned char *src = (unsigned char *)sys(NR_mmap, 0, big, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    fd = (int)sys(NR_memfd_create, "big", MFD_ALLOW_SEALING);
    if ((i64)src > 0) {
        src[big - 1] = 9;
        check(sys(NR_write, fd, src, big) == (i64)big && size_of(fd) == (i64)big, "a 17 MB write is written whole");
        unsigned char b = 0;
        check(sys(NR_pread64, fd, &b, 1, big - 1) == 1 && b == 9, "its last byte arrives");
        sys(NR_munmap, src, big);
    }
    sys(NR_close, fd);

    // Descriptors that aren't memfds.
    sys(NR_pipe2, p, 0);
    check(sys(NR_fcntl, p[0], F_GET_SEALS) == -EINVAL, "F_GET_SEALS on a pipe: EINVAL");
    check(sys(NR_fcntl, p[0], F_ADD_SEALS, F_SEAL_GROW) == -EPERM, "F_ADD_SEALS on its read end: EPERM, write access comes first");
    check(sys(NR_fcntl, p[1], F_ADD_SEALS, F_SEAL_GROW) == -EINVAL, "and on its write end: EINVAL");
    sys(NR_close, p[0]);
    sys(NR_close, p[1]);
    fd = (int)sys(NR_openat, -100, "/data/local/tmp/sealed", O_RDWR | O_CREAT | O_TRUNC, 0644);
    check(fd >= 0 && sys(NR_fcntl, fd, F_GET_SEALS) == F_SEAL_SEAL, "a tmpfs file is sealed against seals");
    check(sys(NR_fcntl, fd, F_ADD_SEALS, F_SEAL_GROW) == -EPERM && sys(NR_write, fd, "ok", 2) == 2, "so none can be added, and it is written as ever");
    sys(NR_close, fd);
    fd = (int)sys(NR_openat, -100, "/data/local/tmp/sealed", O_RDONLY, 0);
    check(fd >= 0 && sys(NR_fcntl, fd, F_ADD_SEALS, 0) == -EPERM, "opened read-only: EPERM");
    sys(NR_close, fd);
    fd = (int)sys(NR_openat, -100, "/dev/ashmem", O_RDWR, 0);
    check(fd >= 0 && sys(NR_fcntl, fd, F_GET_SEALS) == -EINVAL, "F_GET_SEALS on /dev/ashmem: EINVAL");
    sys(NR_close, fd);
    check(sys(NR_fcntl, 999, F_GET_SEALS) == -EBADF, "F_GET_SEALS on a closed descriptor: EBADF");

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

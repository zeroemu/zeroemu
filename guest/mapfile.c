// Freestanding arm64 test of mapping and reading files: what the page cache and files
// that can leave memory must not change. Written to pass on real Linux too.

typedef unsigned long u64;
typedef long i64;
typedef unsigned int u32;
typedef unsigned char u8;

#define NR_futex 98
#define NR_openat 56
#define NR_close 57
#define NR_lseek 62
#define NR_read 63
#define NR_write 64
#define NR_pread64 67
#define NR_pwrite64 68
#define NR_fstat 80
#define NR_ftruncate 46
#define NR_unlinkat 35
#define NR_exit 93
#define NR_exit_group 94
#define NR_clone 220
#define NR_wait4 260
#define NR_munmap 215
#define NR_mmap 222
#define NR_mprotect 226
#define NR_madvise 233
#define NR_mincore 232
#define NR_getpid 172

#define AT_FDCWD (-100)
#define O_RDONLY 0
#define O_RDWR 2
#define O_CREAT 0100
#define O_TRUNC 01000
#define PROT_READ 1
#define PROT_WRITE 2
#define MAP_SHARED 1
#define MAP_PRIVATE 2
#define MAP_ANONYMOUS 0x20
#define MADV_DONTNEED 4
#define SIGCHLD 17
#define EINVAL 22
#define PAGE 4096L

static inline i64 sc6(long n, long a, long b, long c, long d, long e, long f) {
    register long x8 __asm__("x8") = n;
    register long x0 __asm__("x0") = a;
    register long x1 __asm__("x1") = b;
    register long x2 __asm__("x2") = c;
    register long x3 __asm__("x3") = d;
    register long x4 __asm__("x4") = e;
    register long x5 __asm__("x5") = f;
    __asm__ volatile("svc #0" : "+r"(x0) : "r"(x8), "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5) : "memory", "cc");
    return x0;
}
#define sc(n, a, b, c) sc6(n, (long)(a), (long)(b), (long)(c), 0, 0, 0)

static u64 slen(const char *s) { u64 n = 0; while (s[n]) n++; return n; }
static void print(const char *s) { sc(NR_write, 1, s, slen(s)); }
static int failures;
static void check(int ok, const char *what) {
    if (!ok) { print("FAIL "); print(what); print("\n"); failures++; }
}
static int same(const u8 *a, u8 v, long n) {
    for (long i = 0; i < n; i++) if (a[i] != v) return 0;
    return 1;
}
static void fill(u8 *a, u8 v, long n) { for (long i = 0; i < n; i++) a[i] = v; }
static long open_rw(const char *p) { return sc6(NR_openat, AT_FDCWD, (long)p, O_RDWR | O_CREAT | O_TRUNC, 0600, 0, 0); }
static void *map(long len, int prot, int flags, long fd, long off) { return (void *)sc6(NR_mmap, 0, len, prot, flags, fd, off); }

static u8 big[PAGE * 16];

static void private_mappings(const char *path) {
    long fd = open_rw(path);
    fill(big, 7, sizeof big);
    check(sc(NR_write, fd, big, sizeof big) == sizeof big, "write the file");
    u8 *a = map(PAGE * 16, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
    u8 *b = map(PAGE * 16, PROT_READ, MAP_PRIVATE, fd, 0);
    check(same(a, 7, PAGE * 16), "a private mapping reads the file");
    check(same(b, 7, PAGE * 16), "so does another");
    a[PAGE * 3] = 9;
    check(a[PAGE * 3] == 9, "a private mapping can be written");
    check(b[PAGE * 3] == 7, "another mapping doesn't see that");
    u8 c = 0;
    check(sc6(NR_pread64, fd, (long)&c, 1, PAGE * 3, 0, 0) == 1 && c == 7, "nor does the file");
    // A page not yet written shows what is written to the file.
    u8 v = 5;
    check(sc6(NR_pwrite64, fd, (long)&v, 1, PAGE * 5, 0, 0) == 1, "write to the file");
    check(b[PAGE * 5] == 5, "a page not written shows the file changing");
    check(a[PAGE * 3] == 9, "a page written doesn't");
    // Dropped, a private page is the file's again.
    check(sc(NR_madvise, a, PAGE * 16, MADV_DONTNEED) == 0, "MADV_DONTNEED");
    check(a[PAGE * 3] == 7, "dropped, it reads the file again");
    // The mapping outlives the descriptor and the name.
    sc(NR_close, fd, 0, 0);
    check(sc(NR_unlinkat, AT_FDCWD, path, 0) == 0, "unlink");
    check(b[PAGE * 15] == 7, "a mapping outlives its file's name");
    a[PAGE * 15] = 1;
    check(b[PAGE * 15] == 7, "and copies still");
    sc(NR_munmap, a, PAGE * 16, 0);
    sc(NR_munmap, b, PAGE * 16, 0);
}

static void shared_mappings(const char *path) {
    long fd = open_rw(path);
    check(sc(NR_ftruncate, fd, PAGE * 4, 0) == 0, "ftruncate up");
    u8 *m = map(PAGE * 4, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    m[PAGE + 1] = 3;
    u8 c = 0;
    check(sc6(NR_pread64, fd, (long)&c, 1, PAGE + 1, 0, 0) == 1 && c == 3, "read sees a shared mapping's writes");
    u8 v = 4;
    sc6(NR_pwrite64, fd, (long)&v, 1, PAGE + 2, 0, 0);
    check(m[PAGE + 2] == 4, "a shared mapping sees write");
    // Across fork, in the same frames.
    long pid = sc6(NR_clone, SIGCHLD, 0, 0, 0, 0, 0);
    if (pid == 0) {
        m[PAGE * 2] = 42;
        sc(NR_exit, 0, 0, 0);
    }
    int st = 0;
    sc6(NR_wait4, pid, (long)&st, 0, 0, 0, 0);
    check(m[PAGE * 2] == 42, "a child's writes to a shared mapping stay");
    // Discarding a shared mapping's pages doesn't lose them.
    check(sc(NR_madvise, m, PAGE * 4, MADV_DONTNEED) == 0, "MADV_DONTNEED shared");
    check(m[PAGE + 1] == 3, "the file still has them");
    // Cut short and grown again, what was past the end is zeros.
    check(sc(NR_ftruncate, fd, PAGE + 2, 0) == 0, "ftruncate down");
    check(sc(NR_ftruncate, fd, PAGE * 4, 0) == 0, "ftruncate up again");
    c = 1;
    check(sc6(NR_pread64, fd, (long)&c, 1, PAGE + 2, 0, 0) == 1 && c == 0, "past the cut reads zero");
    c = 0;
    check(sc6(NR_pread64, fd, (long)&c, 1, PAGE + 1, 0, 0) == 1 && c == 3, "before it, still there");
    sc(NR_munmap, m, PAGE * 4, 0);
    sc(NR_close, fd, 0, 0);
    sc(NR_unlinkat, AT_FDCWD, path, 0);
}

struct stat_ { u64 dev, ino; u32 mode, nlink, uid, gid; u64 rdev, pad1; i64 size; u32 blksize, pad2; i64 blocks, atime, atime_ns, mtime, mtime_ns, ctime, ctime_ns; u32 u4, u5; };

static void edges(const char *path) {
    long fd = open_rw(path);
    check(sc(NR_ftruncate, fd, -1, 0) == -EINVAL, "ftruncate to a negative size is EINVAL");
    check(sc(NR_write, fd, "abc", 3) == 3, "write");
    // Its last name gone, an open file goes on, as tmpfile() relies on.
    check(sc(NR_unlinkat, AT_FDCWD, path, 0) == 0, "unlink while open");
    struct stat_ st;
    check(sc(NR_fstat, fd, &st, 0) == 0, "fstat with its last name gone");
    check(st.nlink == 0, "says it has no names");
    check(st.size == 3, "says its size");
    char b[4] = {0};
    check(sc6(NR_pread64, fd, (long)b, 3, 0, 0, 0) == 3 && b[1] == 'b', "reads as before");
    sc(NR_close, fd, 0, 0);
}

__asm__(".global _start\n_start:\n bl cstart\n");

void cstart(void) {
    private_mappings("/data/mapfile-a");
    shared_mappings("/data/mapfile-b");
    edges("/data/mapfile-c");
    if (!failures) print("all checks passed\n");
    sc(NR_exit_group, failures != 0, 0, 0);
}

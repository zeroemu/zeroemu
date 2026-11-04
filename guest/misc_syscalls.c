// Freestanding arm64 test of droidrt's msync, mlock family, mincore, sendfile,
// copy_file_range and the quota and module stubs.

typedef unsigned long u64;
typedef long i64;
typedef unsigned int u32;

#define NR_openat 56
#define NR_quotactl 60
#define NR_close 57
#define NR_lseek 62
#define NR_read 63
#define NR_write 64
#define NR_sendfile 71
#define NR_exit_group 94
#define NR_munmap 215
#define NR_mmap 222
#define NR_msync 227
#define NR_mlock 228
#define NR_munlock 229
#define NR_mlockall 230
#define NR_mincore 232
#define NR_memfd_create 279
#define NR_mlock2 284
#define NR_copy_file_range 285

#define EINVAL 22
#define ENOMEM 12
#define ESRCH 3

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
static int same(const char *a, const char *b, u64 n) { while (n--) if (*a++ != *b++) return 0; return 1; }

static int failures;
static void check(int cond, const char *name) {
    puts_(cond ? "ok   " : "FAIL ");
    puts_(name);
    puts_("\n");
    if (!cond) failures++;
}

int cmain(void) {
    char *m = (char *)sys(NR_mmap, 0, 16384, 3, 0x22, -1, 0);
    sys(NR_munmap, m + 8192, 4096); // a hole in the middle

    check(sys(NR_msync, m + 1, 4096, 4) == -EINVAL, "msync: unaligned EINVAL");
    check(sys(NR_msync, m, 4096, 4 | 1) == -EINVAL, "msync: MS_SYNC with MS_ASYNC EINVAL");
    check(sys(NR_msync, m, 4096, 8) == -EINVAL, "msync: unknown flag EINVAL");
    check(sys(NR_msync, m, 16384, 4) == -ENOMEM, "msync: a hole ENOMEM");
    check(sys(NR_msync, m, 8192, 4) == 0, "msync: mapped memory");

    check(sys(NR_mlock, m, 8192) == 0 && sys(NR_munlock, m, 8192) == 0, "mlock and munlock");
    check(sys(NR_mlock, m, 16384) == -ENOMEM, "mlock: a hole ENOMEM");
    check(sys(NR_mlock2, m, 4096, 1) == 0 && sys(NR_mlock2, m, 4096, 2) == -EINVAL, "mlock2: MLOCK_ONFAULT only");
    check(sys(NR_mlockall, 1) == 0 && sys(NR_mlockall, 0) == -EINVAL && sys(NR_mlockall, 4) == -EINVAL, "mlockall flags");

    static unsigned char vec[4];
    m[4096] = 1;
    check(sys(NR_mincore, m, 8192, vec) == 0 && (vec[0] & 1) == 0 && (vec[1] & 1) == 1, "mincore: touched page in, untouched out");
    check(sys(NR_mincore, m, 16384, vec) == -ENOMEM, "mincore: a hole ENOMEM");
    check(sys(NR_mincore, m + 1, 4096, vec) == -EINVAL, "mincore: unaligned EINVAL");

    int in = (int)sys(NR_memfd_create, "in", 0), out = (int)sys(NR_memfd_create, "out", 0);
    sys(NR_write, in, "hello world", 11);
    sys(NR_lseek, in, 0, 0);
    check(sys(NR_sendfile, out, in, 0, 5) == 5 && sys(NR_lseek, in, 0, 1) == 5, "sendfile: no offset moves the input");
    i64 off = 6;
    check(sys(NR_sendfile, out, in, &off, 5) == 5 && off == 11 && sys(NR_lseek, in, 0, 1) == 5, "sendfile: an offset is updated instead");
    i64 eof = 11;
    check(sys(NR_sendfile, out, in, &eof, 5) == 0, "sendfile: end of file is 0");
    static char buf[16];
    sys(NR_lseek, out, 0, 0);
    check(sys(NR_read, out, buf, 16) == 10 && same(buf, "helloworld", 10), "the bytes arrived");

    int to = (int)sys(NR_memfd_create, "to", 0);
    i64 a = 6, b = 2;
    sys(NR_write, to, "xx", 2);
    check(sys(NR_copy_file_range, in, &a, to, &b, 5, 0) == 5 && a == 11 && b == 7, "copy_file_range: both offsets advance");
    check(sys(NR_copy_file_range, in, &a, to, &b, 5, 1) == -EINVAL, "copy_file_range: flags EINVAL");

    check(sys(NR_quotactl, 0, "/dev/x", 0, 0) == -ESRCH, "quotactl: quotas off");

    puts_(failures ? "SOME CHECKS FAILED\n" : "all checks passed\n");
    return failures;
}

void __attribute__((noreturn)) cstart(void) {
    sys(NR_exit_group, cmain());
    __builtin_unreachable();
}

__asm__(".global _start\n_start:\n bl cstart\n");

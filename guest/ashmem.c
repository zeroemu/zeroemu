// Freestanding arm64 test of droidrt's /dev/ashmem: name and size ioctls,
// shared mappings of one region, the size fixed once mapped, the protection
// mask, and fstat as libcutils checks it.

typedef unsigned long u64;
typedef long i64;
typedef unsigned int u32;

#define NR_ioctl 29
#define NR_openat 56
#define NR_write 64
#define NR_fstat 80
#define NR_exit_group 94
#define NR_munmap 215
#define NR_mmap 222

#define EINVAL 22
#define EPERM 1
#define ASHMEM_SET_NAME 0x41007701
#define ASHMEM_GET_NAME 0x81007702
#define ASHMEM_SET_SIZE 0x40087703
#define ASHMEM_GET_SIZE 0x7704
#define ASHMEM_SET_PROT_MASK 0x40087705
#define ASHMEM_GET_PROT_MASK 0x7706

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
static int streq(const char *a, const char *b) { while (*a && *a == *b) a++, b++; return *a == *b; }

static int failures;
static void check(int cond, const char *name) {
    puts_(cond ? "ok   " : "FAIL ");
    puts_(name);
    puts_("\n");
    if (!cond) failures++;
}

int cmain(void) {
    int fd = (int)sys(NR_openat, -100, "/dev/ashmem", 02 /* O_RDWR */, 0);
    check(fd >= 0, "open /dev/ashmem");
    static char name[256];
    check(sys(NR_ioctl, fd, ASHMEM_SET_NAME, "test-region") == 0 && sys(NR_ioctl, fd, ASHMEM_GET_NAME, name) == 0 && streq(name, "test-region"),
          "name a region");
    check(sys(NR_ioctl, fd, ASHMEM_SET_SIZE, 8192) == 0 && sys(NR_ioctl, fd, ASHMEM_GET_SIZE) == 8192, "size it");

    char *a = (char *)sys(NR_mmap, 0, 8192, 3, 1 /* MAP_SHARED */, fd, 0);
    char *b = (char *)sys(NR_mmap, 0, 8192, 3, 1, fd, 0);
    check((i64)a > 0 && (i64)b > 0 && a != b, "map it twice");
    a[4100] = 42;
    check(b[4100] == 42, "both mappings share the pages");
    check(sys(NR_ioctl, fd, ASHMEM_SET_SIZE, 4096) == -EINVAL, "the size is fixed once mapped");
    check(sys(NR_mmap, 0, 16384, 3, 1, fd, 0) == -EINVAL, "no mapping past the size");

    check(sys(NR_ioctl, fd, ASHMEM_SET_PROT_MASK, 1 /* PROT_READ */) == 0 && sys(NR_ioctl, fd, ASHMEM_GET_PROT_MASK) == 1, "drop PROT_WRITE from the mask");
    check(sys(NR_mmap, 0, 8192, 3, 1, fd, 0) == -EPERM, "then writable mappings are refused");
    char *r = (char *)sys(NR_mmap, 0, 8192, 1, 1, fd, 0);
    check((i64)r > 0 && r[4100] == 42, "a read-only one still sees the data");
    check(sys(NR_ioctl, fd, ASHMEM_SET_PROT_MASK, 3) == -EINVAL, "the mask never grows back");

    static u64 st[16];
    check(sys(NR_fstat, fd, st) == 0 && (((u32 *)st)[4] & 0170000) == 0020000 && st[4] == ((10 << 8) | 61), "fstat: the ashmem char device");

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

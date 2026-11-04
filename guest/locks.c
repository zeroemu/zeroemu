// Freestanding arm64 test of droidrt's advisory file locks: open file
// description (OFD) record locks, which netd's BPF map locking relies on,
// POSIX record locks (owned by the process), and flock.

typedef unsigned long u64;
typedef long i64;
typedef unsigned int u32;

#define NR_fcntl 25
#define NR_flock 32
#define NR_openat 56
#define NR_close 57
#define NR_write 64
#define NR_exit_group 94

#define EAGAIN 11
#define F_SETLK 6
#define F_OFD_GETLK 36
#define F_OFD_SETLK 37
#define F_RDLCK 0
#define F_WRLCK 1
#define F_UNLCK 2
#define LOCK_SH 1
#define LOCK_EX 2
#define LOCK_NB 4
#define LOCK_UN 8

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

static int failures;
static void check(int cond, const char *name) {
    puts_(cond ? "ok   " : "FAIL ");
    puts_(name);
    puts_("\n");
    if (!cond) failures++;
}

struct flock {
    short l_type, l_whence;
    i64 l_start, l_len;
    int l_pid;
};

static i64 lock(int fd, int cmd, short type, i64 start, i64 len, struct flock *out) {
    struct flock fl;
    memset(&fl, 0, sizeof fl);
    fl.l_type = type;
    fl.l_start = start;
    fl.l_len = len;
    i64 r = sys(NR_fcntl, fd, cmd, &fl);
    if (out) *out = fl;
    return r;
}

int cmain(void) {
    // Two opens: two open file descriptions of one file.
    int a = (int)sys(NR_openat, -100, "/tmp/locks", 0102 /* O_RDWR|O_CREAT */, 0600);
    int b = (int)sys(NR_openat, -100, "/tmp/locks", 02 /* O_RDWR */, 0);
    check(a >= 0 && b >= 0, "open one file twice");

    // As libbpf_android locks a map: one byte at the map's id.
    check(lock(a, F_OFD_SETLK, F_WRLCK, 5, 1, 0) == 0, "OFD write lock");
    check(lock(b, F_OFD_SETLK, F_WRLCK, 5, 1, 0) == -EAGAIN, "a second description cannot take it");
    check(lock(b, F_OFD_SETLK, F_RDLCK, 5, 1, 0) == -EAGAIN, "nor share it");
    check(lock(b, F_OFD_SETLK, F_WRLCK, 6, 1, 0) == 0, "the next byte is free");
    struct flock got;
    check(lock(b, F_OFD_GETLK, F_RDLCK, 0, 0, &got) == 0 && got.l_type == F_WRLCK && got.l_start == 5 && got.l_len == 1 && got.l_pid == -1,
          "OFD GETLK reports the holder");
    check(lock(a, F_OFD_SETLK, F_WRLCK, 6, 1, 0) == -EAGAIN, "OFD locks conflict within one process");
    sys(NR_close, a);
    check(lock(b, F_OFD_SETLK, F_WRLCK, 5, 1, 0) == 0, "closing the description releases its lock");
    check(lock(b, F_OFD_SETLK, F_UNLCK, 0, 0, 0) == 0 && lock(b, F_OFD_GETLK, F_WRLCK, 0, 0, &got) == 0 && got.l_type == F_UNLCK,
          "unlock everything; GETLK then says F_UNLCK");

    // POSIX locks belong to the process: its own opens never conflict.
    a = (int)sys(NR_openat, -100, "/tmp/locks", 02, 0);
    check(lock(a, F_SETLK, F_WRLCK, 0, 10, 0) == 0 && lock(b, F_SETLK, F_WRLCK, 0, 10, 0) == 0, "POSIX locks: one owner per process");

    // flock: whole file, per description.
    check(sys(NR_flock, a, LOCK_EX) == 0, "flock exclusive");
    check(sys(NR_flock, b, LOCK_SH | LOCK_NB) == -EAGAIN, "flock shared blocked by it");
    check(sys(NR_flock, a, LOCK_UN) == 0 && sys(NR_flock, b, LOCK_SH | LOCK_NB) == 0 && sys(NR_flock, a, LOCK_SH | LOCK_NB) == 0,
          "after unlock, two shared locks");
    check(sys(NR_flock, a, LOCK_EX | LOCK_NB) == -EAGAIN, "exclusive waits for the other shared lock");

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

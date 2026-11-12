// Freestanding arm64 test of zeroemu's inotify: a watched directory hears
// a file's create, write, close, rename and delete, with names and a shared
// rename cookie; reads are whole events; removing a watch says IN_IGNORED.

typedef unsigned long u64;
typedef long i64;
typedef unsigned int u32;

#define NR_inotify_init1 26
#define NR_inotify_add_watch 27
#define NR_inotify_rm_watch 28
#define NR_unlinkat 35
#define NR_renameat 38
#define NR_openat 56
#define NR_close 57
#define NR_read 63
#define NR_write 64
#define NR_exit_group 94

#define IN_MODIFY 0x2
#define IN_CLOSE_WRITE 0x8
#define IN_MOVED_FROM 0x40
#define IN_MOVED_TO 0x80
#define IN_CREATE 0x100
#define IN_DELETE 0x200
#define IN_IGNORED 0x8000
#define IN_NONBLOCK 04000

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

struct ev { int wd; u32 mask, cookie, len; char name[]; };

int cmain(void) {
    int in = (int)sys(NR_inotify_init1, IN_NONBLOCK);
    check(in >= 0, "inotify_init1");
    static char buf[4096];
    check(sys(NR_read, in, buf, sizeof buf) == -11, "nothing yet: EAGAIN");
    check(sys(NR_inotify_add_watch, in, "/tmp/missing", IN_CREATE) == -2, "watching a missing path: ENOENT");
    int wd = (int)sys(NR_inotify_add_watch, in, "/tmp", IN_CREATE | IN_DELETE | IN_MODIFY | IN_CLOSE_WRITE | IN_MOVED_FROM | IN_MOVED_TO);
    check(wd > 0, "watch /tmp");

    int fd = (int)sys(NR_openat, -100, "/tmp/x", 0102 /* O_RDWR|O_CREAT */, 0600);
    sys(NR_write, fd, "hi", 2);
    sys(NR_close, fd);
    sys(NR_renameat, -100, "/tmp/x", -100, "/tmp/y");
    sys(NR_unlinkat, -100, "/tmp/y", 0);

    i64 n = sys(NR_read, in, buf, sizeof buf);
    u32 want[] = {IN_CREATE, IN_MODIFY, IN_CLOSE_WRITE, IN_MOVED_FROM, IN_MOVED_TO, IN_DELETE};
    const char *names[] = {"x", "x", "x", "x", "y", "y"};
    int i = 0, ok = n > 0;
    u32 cookie = 0;
    for (i64 off = 0; ok && off < n && i < 6; i++) {
        struct ev *e = (struct ev *)(buf + off);
        ok = e->wd == wd && e->mask == want[i] && e->len % 16 == 0 && streq(e->name, names[i]);
        if (want[i] == IN_MOVED_FROM) cookie = e->cookie;
        if (want[i] == IN_MOVED_TO) ok = ok && cookie != 0 && e->cookie == cookie;
        off += 16 + e->len;
    }
    check(ok && i == 6, "create, modify, close-write, moved-from/to (one cookie), delete");
    check(sys(NR_read, in, buf, 8) == -11, "queue drained");

    sys(NR_openat, -100, "/tmp/z", 0102, 0600);
    check(sys(NR_read, in, buf, 8) == -22, "a buffer smaller than the event: EINVAL");
    check(sys(NR_inotify_rm_watch, in, wd) == 0, "remove the watch");
    n = sys(NR_read, in, buf, sizeof buf);
    struct ev *last = (struct ev *)(buf + n - 16);
    check(n >= 16 && last->mask == IN_IGNORED, "IN_IGNORED follows");

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

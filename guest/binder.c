// Freestanding arm64 test of droidrt's binder driver (no libc), speaking the
// raw protocol: a context manager and a client in separate processes, with
// object and fd translation, a one-way call, refcount notifications, and a
// death notification. Exits with the failure count.

typedef unsigned long u64;
typedef long i64;
typedef unsigned int u32;

#define NR_ioctl 29
#define NR_openat 56
#define NR_close 57
#define NR_pipe2 59
#define NR_read 63
#define NR_write 64
#define NR_exit_group 94
#define NR_clone 220
#define NR_mmap 222
#define NR_wait4 260

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

#define BINDER_WRITE_READ 0xc0306201
#define BINDER_SET_CONTEXT_MGR 0x40046207
#define BINDER_VERSION 0xc0046209
#define BC_TRANSACTION 0x40406300
#define BC_REPLY 0x40406301
#define BC_FREE_BUFFER 0x40086303
#define BC_ENTER_LOOPER 0x630c
#define BC_REQUEST_DEATH_NOTIFICATION 0x400c630e
#define BR_TRANSACTION 0x80407202
#define BR_REPLY 0x80407203
#define BR_TRANSACTION_COMPLETE 0x7206
#define BR_INCREFS 0x80107207
#define BR_ACQUIRE 0x80107208
#define BR_NOOP 0x720c
#define BR_DEAD_BINDER 0x8008720f
#define TYPE_BINDER 0x73622a85
#define TYPE_HANDLE 0x73682a85
#define TYPE_FD 0x66642a85
#define TF_ONE_WAY 1

struct bwr { u64 wsize, wcons, wbuf, rsize, rcons, rbuf; };
struct txn {
    u64 target, cookie;
    u32 code, flags;
    int sender_pid;
    u32 sender_euid;
    u64 data_size, offsets_size, buffer, offsets;
};
struct flat { u32 type, flags; u64 binder_or_handle, cookie; };

static int open_binder(void) {
    int fd = (int)sys(NR_openat, -100, "/dev/binder", 02000002 /* O_RDWR|O_CLOEXEC */, 0);
    if (fd >= 0) sys(NR_mmap, 0, 128 * 1024, 1 /* PROT_READ */, 2 /* MAP_PRIVATE */, fd, 0);
    return fd;
}

static i64 bw(int fd, void *w, u64 wn, void *r, u64 rn, u64 *got) {
    struct bwr b = { wn, 0, (u64)w, rn, 0, (u64)r };
    i64 ret = sys(NR_ioctl, fd, BINDER_WRITE_READ, &b);
    if (got) *got = b.rcons;
    return ret;
}

// Reads until a command of interest arrives; returns a pointer to its payload.
static u32 rbuf[1024];
static u32 *expect(int fd, u32 want, int *seen_acquire) {
    for (int tries = 0; tries < 50; tries++) {
        u64 got = 0;
        if (bw(fd, 0, 0, rbuf, sizeof rbuf, &got) < 0) return 0;
        char *p = (char *)rbuf, *end = p + got;
        u32 *found = 0;
        // Scan the whole batch: later commands (e.g. BR_ACQUIRE) count too.
        while (p < end) {
            u32 cmd = *(u32 *)p;
            p += 4;
            if (cmd == want && !found) found = (u32 *)p;
            if ((cmd == BR_ACQUIRE || cmd == BR_INCREFS) && seen_acquire) *seen_acquire = 1;
            p += (cmd >> 16) & 0x3fff;
        }
        if (found) return found;
    }
    return 0;
}

static void send_txn(int fd, u32 cmd, u32 target, u32 code, u32 flags, void *data, u64 dsize, u64 *offs, u64 osize) {
    struct { u32 cmd; struct txn t; } __attribute__((packed)) w;
    memset(&w, 0, sizeof w);
    w.cmd = cmd;
    w.t.target = target;
    w.t.code = code;
    w.t.flags = flags;
    w.t.data_size = dsize;
    w.t.offsets_size = osize;
    w.t.buffer = (u64)data;
    w.t.offsets = (u64)offs;
    bw(fd, &w, sizeof w, 0, 0, 0);
}

int cmain(void) {
    int mgr = open_binder();
    int ver = 0;
    check(mgr >= 0 && sys(NR_ioctl, mgr, BINDER_VERSION, &ver) == 0 && ver == 8, "open /dev/binder, protocol 8");
    check(sys(NR_ioctl, mgr, BINDER_SET_CONTEXT_MGR, 0) == 0, "become context manager");
    u32 enter = BC_ENTER_LOOPER;
    bw(mgr, &enter, 4, 0, 0, 0);

    int pp[2];
    sys(NR_pipe2, pp, 0);
    i64 pid = sys(NR_clone, 17, 0, 0, 0, 0);
    if (pid == 0) {
        int fd = open_binder();
        struct { char msg[8]; struct flat obj; struct flat fdo; } __attribute__((packed)) d;
        memcpy(d.msg, "ping\0\0\0\0", 8);
        d.obj = (struct flat){ TYPE_BINDER, 0, 0x1234, 0x5678 };
        d.fdo = (struct flat){ TYPE_FD, 0, (u64)pp[1], 0 };
        u64 offs[2] = { 8, 32 };
        send_txn(fd, BC_TRANSACTION, 0, 7, 0x10 /* TF_ACCEPT_FDS */, &d, sizeof d, offs, sizeof offs);
        int acquired = 0;
        struct txn *r = (struct txn *)expect(fd, BR_REPLY, &acquired);
        int ok = r && r->data_size == 4 && seq((char *)r->buffer, "pong", 4);
        // A one-way call: no reply comes back, only TRANSACTION_COMPLETE.
        send_txn(fd, BC_TRANSACTION, 0, 9, TF_ONE_WAY, "async", 5, 0, 0);
        ok = ok && expect(fd, BR_TRANSACTION_COMPLETE, &acquired) != 0;
        if (!acquired) expect(fd, BR_ACQUIRE, &acquired); // the manager now holds our object
        sys(NR_exit_group, ok ? (acquired ? 0 : 3) : 2);
    }
    sys(NR_close, pp[1]);

    struct txn *t = (struct txn *)expect(mgr, BR_TRANSACTION, 0);
    int ok = t && t->code == 7 && t->sender_pid == (int)pid && t->data_size == 56 && t->offsets_size == 16;
    check(ok, "BR_TRANSACTION with code, sender pid, sizes");
    if (ok) {
        char *data = (char *)t->buffer;
        u64 *offs = (u64 *)t->offsets;
        struct flat *obj = (struct flat *)(data + offs[0]);
        struct flat *fdo = (struct flat *)(data + offs[1]);
        check(seq(data, "ping", 4), "transaction data copied");
        check(obj->type == TYPE_HANDLE && obj->binder_or_handle != 0, "child's binder arrives as a handle");
        int passed = (int)fdo->binder_or_handle;
        check(fdo->type == TYPE_FD && sys(NR_write, passed, "via binder fd", 13) == 13, "fd translated into the receiver");
        sys(NR_close, passed);
        u32 handle = (u32)obj->binder_or_handle;

        // Reply, then free the buffer.
        send_txn(mgr, BC_REPLY, 0, 0, 0, "pong", 4, 0, 0);
        struct { u32 cmd; u64 ptr; } __attribute__((packed)) fb = { BC_FREE_BUFFER, t->buffer };
        bw(mgr, &fb, sizeof fb, 0, 0, 0);

        // Watch the child's object die with it.
        struct { u32 cmd; u32 handle; u64 cookie; } __attribute__((packed)) dn = { BC_REQUEST_DEATH_NOTIFICATION, handle, 0xdead };
        bw(mgr, &dn, sizeof dn, 0, 0, 0);

        struct txn *a = (struct txn *)expect(mgr, BR_TRANSACTION, 0);
        check(a && a->code == 9 && (a->flags & TF_ONE_WAY) && seq((char *)a->buffer, "async", 5), "one-way transaction delivered");
        if (a) {
            struct { u32 cmd; u64 ptr; } __attribute__((packed)) fb2 = { BC_FREE_BUFFER, a->buffer };
            bw(mgr, &fb2, sizeof fb2, 0, 0, 0);
        }
    }
    char buf[32];
    check(sys(NR_read, pp[0], buf, 32) == 13 && seq(buf, "via binder fd", 13), "child's pipe received the write");
    int st = -1;
    sys(NR_wait4, pid, &st, 0, 0);
    check(st == 0, "child got BR_REPLY, one-way completion, and BR_ACQUIRE");
    u64 *cookie = (u64 *)expect(mgr, BR_DEAD_BINDER, 0);
    check(cookie && *cookie == 0xdead, "death notification when the child exits");

    puts_(failures ? "SOME CHECKS FAILED\n" : "all checks passed\n");
    return failures;
}

void __attribute__((noreturn)) cstart(void) {
    sys(NR_exit_group, cmain());
    __builtin_unreachable();
}

__asm__(".global _start\n_start:\n bl cstart\n");

// Freestanding arm64 test of droidrt's binder driver: a thread in the middle
// of an incoming sync call must not be handed another one when it reads after
// its own one-way call. It would nest it, and its two replies would pop the
// transactions in the wrong order, swapping them between the two callers.

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

// Repro: a single-threaded context manager (like servicemanager) is handling a
// sync call from A when it makes a one-way call (like onClients/onRegistration).
// Meanwhile B's sync call sits in the manager's process todo. Linux never gives
// process work to a thread with a non-empty transaction stack; droidrt does.
static void putn(u64 v) { char b[24]; int i = 23; b[i] = 0; do { b[--i] = '0' + v % 10; v /= 10; } while (v); puts_(b + i); }
static const char *name(u32 c) {
    switch (c) { case BR_NOOP: return "BR_NOOP"; case BR_TRANSACTION_COMPLETE: return "BR_TRANSACTION_COMPLETE";
    case BR_TRANSACTION: return "BR_TRANSACTION"; case BR_REPLY: return "BR_REPLY"; case BR_INCREFS: return "BR_INCREFS";
    case BR_ACQUIRE: return "BR_ACQUIRE"; default: return "other"; }
}
int cmain(void) {
    int mgr = open_binder();
    check(sys(NR_ioctl, mgr, BINDER_SET_CONTEXT_MGR, 0) == 0, "become context manager");
    u32 enter = BC_ENTER_LOOPER;
    bw(mgr, &enter, 4, 0, 0, 0);
    int sent[2];
    sys(NR_pipe2, sent, 0);

    i64 a = sys(NR_clone, 17, 0, 0, 0, 0);
    if (a == 0) {
        int fd = open_binder();
        struct flat obj = { TYPE_BINDER, 0, 0x1111, 0x2222 };
        u64 off = 0;
        send_txn(fd, BC_TRANSACTION, 0, 1, 0, &obj, sizeof obj, &off, 8);
        struct txn *r = (struct txn *)expect(fd, BR_REPLY, 0);
        sys(NR_exit_group, r ? (int)r->data_size : 99);
    }
    struct txn *t1 = (struct txn *)expect(mgr, BR_TRANSACTION, 0);
    check(t1 && t1->code == 1, "manager is handling A's call (code 1)");
    u32 h = t1 ? (u32)((struct flat *)t1->buffer)->binder_or_handle : 0;

    i64 b = sys(NR_clone, 17, 0, 0, 0, 0);
    if (b == 0) {
        int fd = open_binder();
        send_txn(fd, BC_TRANSACTION, 0, 2, 0, "b", 1, 0, 0); // write only: now queued at the manager
        sys(NR_write, sent[1], "x", 1);
        struct txn *r = (struct txn *)expect(fd, BR_REPLY, 0);
        sys(NR_exit_group, r ? (int)r->data_size : 99);
    }
    char c;
    sys(NR_read, sent[0], &c, 1);

    // One-way call back to A while still inside A's call, written and read in
    // one BINDER_WRITE_READ with a 256-byte read buffer, exactly like libbinder.
    struct { u32 cmd; struct txn t; } __attribute__((packed)) w;
    memset(&w, 0, sizeof w);
    w.cmd = BC_TRANSACTION; w.t.target = h; w.t.code = 3; w.t.flags = TF_ONE_WAY; w.t.data_size = 1; w.t.buffer = (u64)"o";
    u32 in[64];
    u64 got = 0;
    bw(mgr, &w, sizeof w, in, 256, &got);
    puts_("manager's read after its one-way call:");
    int nested = 0;
    for (char *p = (char *)in, *end = p + got; p < end;) {
        u32 cmd = *(u32 *)p;
        puts_(" "); puts_(name(cmd));
        if (cmd == BR_TRANSACTION && ((struct txn *)(p + 4))->code == 2) nested = 1;
        p += 4 + ((cmd >> 16) & 0x3fff);
    }
    puts_("\n");
    check(!nested, "no BR_TRANSACTION handed to a thread that is mid-transaction (Linux behaviour)");

    // libbinder then runs B's call nested and flushes both replies in one write:
    // the outer (A's, 4 bytes) first, then the inner (B's, 8 bytes).
    struct { u32 c1; struct txn r1; u32 c2; struct txn r2; } __attribute__((packed)) rr;
    memset(&rr, 0, sizeof rr);
    rr.c1 = BC_REPLY; rr.r1.data_size = 4; rr.r1.buffer = (u64)"AAAA";
    rr.c2 = BC_REPLY; rr.r2.data_size = 8; rr.r2.buffer = (u64)"BBBBBBBB";
    if (!nested) { // the correct driver: reply to A now; B is still queued
        bw(mgr, &rr.c1, 4 + sizeof rr.r1, 0, 0, 0);
        struct txn *t2 = (struct txn *)expect(mgr, BR_TRANSACTION, 0);
        if (t2) bw(mgr, &rr.c2, 4 + sizeof rr.r2, 0, 0, 0);
    } else {
        bw(mgr, &rr, sizeof rr, 0, 0, 0);
    }
    int sa = -1, sb = -1;
    sys(NR_wait4, a, &sa, 0, 0);
    sys(NR_wait4, b, &sb, 0, 0);
    puts_("A (expects 4 bytes) got "); putn((u64)((sa >> 8) & 0xff)); puts_("; B (expects 8 bytes) got "); putn((u64)((sb >> 8) & 0xff)); puts_("\n");
    check(((sa >> 8) & 0xff) == 4 && ((sb >> 8) & 0xff) == 8, "each caller gets its own reply");
    puts_(failures ? "SOME CHECKS FAILED\n" : "all checks passed\n");
    return failures;
}

void __attribute__((noreturn)) cstart(void) {
    sys(NR_exit_group, cmain());
    __builtin_unreachable();
}

__asm__(".global _start\n_start:\n bl cstart\n");

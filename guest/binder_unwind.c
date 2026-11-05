// Freestanding arm64 test of droidrt's binder driver: a thread's transaction
// stack unwinds in order, as in Linux. A call whose target died ends only when
// the thread is back down to it, or the inner wait takes its BR_DEAD_REPLY and the
// inner reply reaches a thread waiting for nothing, which libbinder aborts on.
// A call back up a chain of processes finds the thread at the chain's head.

typedef unsigned long u64;
typedef long i64;
typedef unsigned int u32;

#define NR_ioctl 29
#define NR_openat 56
#define NR_close 57
#define NR_write 64
#define NR_exit_group 94
#define NR_nanosleep 101
#define NR_kill 129
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
#define BC_ACQUIRE 0x40046305
#define BC_ENTER_LOOPER 0x630c
#define BC_REQUEST_DEATH_NOTIFICATION 0x400c630e
#define BR_TRANSACTION 0x80407202
#define BR_REPLY 0x80407203
#define BR_TRANSACTION_COMPLETE 0x7206
#define BR_INCREFS 0x80107207
#define BR_ACQUIRE 0x80107208
#define BR_RELEASE 0x80107209
#define BR_DECREFS 0x8010720a
#define BR_NOOP 0x720c
#define BR_SPAWN_LOOPER 0x720d
#define BR_DEAD_REPLY 0x7205
#define BR_DEAD_BINDER 0x8008720f
#define TYPE_BINDER 0x73622a85
#define TYPE_HANDLE 0x73682a85
#define TYPE_FD 0x66642a85
#define CODE_X 1
#define CODE_Y 2
#define CODE_Z 3
#define CODE_CALL_X 10
#define CODE_CALLBACK 11
#define CODE_PLAIN 20
#define CODE_RELAY 21
#define CODE_RELAYED 22
#define CODE_CHAIN 23

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
    int fd = (int)sys(NR_openat, -100, "/dev/binder", 02004002 /* O_RDWR|O_NONBLOCK|O_CLOEXEC */, 0);
    if (fd >= 0) sys(NR_mmap, 0, 128 * 1024, 1 /* PROT_READ */, 2 /* MAP_PRIVATE */, fd, 0);
    return fd;
}

static void nap(u64 ms) {
    struct { u64 s, ns; } ts = { ms / 1000, ms % 1000 * 1000000 };
    sys(NR_nanosleep, &ts, 0);
}

static void write_cmds(int fd, void *w, u64 n) {
    struct bwr b = { n, 0, (u64)w, 0, 0, 0 };
    sys(NR_ioctl, fd, BINDER_WRITE_READ, &b);
}

// The next command worth looking at, 0 after seconds of silence. Reads like
// libbinder: one 256-byte buffer, consumed before the next read.
static u32 in[64];
static u64 in_len, in_pos;
static u32 next_cmd(int fd, struct txn **t) {
    for (int waited = 0; waited < 5000;) {
        if (in_pos >= in_len) {
            struct bwr b = { 0, 0, 0, sizeof in, 0, (u64)in };
            in_pos = in_len = 0;
            if (sys(NR_ioctl, fd, BINDER_WRITE_READ, &b) == 0) in_len = b.rcons;
        }
        if (in_pos >= in_len) {
            nap(2);
            waited += 2;
            continue;
        }
        u32 cmd = *(u32 *)((char *)in + in_pos);
        void *arg = (char *)in + in_pos + 4;
        in_pos += 4 + ((cmd >> 16) & 0x3fff);
        if (cmd == BR_NOOP || cmd == BR_SPAWN_LOOPER || cmd == BR_INCREFS || cmd == BR_ACQUIRE || cmd == BR_RELEASE || cmd == BR_DECREFS) continue;
        if (t) *t = arg;
        return cmd;
    }
    return 0;
}

static void send_txn(int fd, u32 cmd, u32 target, u32 code, void *data, u64 dsize, u64 *offs, u64 osize) {
    struct { u32 cmd; struct txn t; } __attribute__((packed)) w;
    memset(&w, 0, sizeof w);
    w.cmd = cmd;
    w.t.target = target;
    w.t.code = code;
    w.t.data_size = dsize;
    w.t.offsets_size = osize;
    w.t.buffer = (u64)data;
    w.t.offsets = (u64)offs;
    write_cmds(fd, &w, sizeof w);
}
static void reply(int fd, const char *data, u64 n) { send_txn(fd, BC_REPLY, 0, 0, (void *)data, n, 0, 0); }

static void acquire(int fd, u32 handle) {
    struct { u32 cmd, handle; } w = { BC_ACQUIRE, handle };
    write_cmds(fd, &w, sizeof w);
}

// A sync call and its result: 1 for a reply of `n` bytes, 0 for anything else.
static int call_for_reply(int fd, u32 handle, u32 code, u64 n) {
    struct txn *r = 0;
    send_txn(fd, BC_TRANSACTION, handle, code, 0, 0, 0, 0);
    u32 c = next_cmd(fd, 0);
    if (c != BR_TRANSACTION_COMPLETE) return 0;
    return next_cmd(fd, &r) == BR_REPLY && r->data_size == n;
}

// Hands this process's one object to the test, which is the context manager.
static int serve_start(u32 code) {
    int fd = open_binder();
    struct flat obj = { TYPE_BINDER, 0, code * 0x100, code * 0x1000 };
    u64 off = 0;
    struct txn *r = 0;
    send_txn(fd, BC_TRANSACTION, 0, code, &obj, sizeof obj, &off, 8);
    while (next_cmd(fd, &r) != BR_REPLY) {}
    return fd;
}

// Calls back to the test from inside its call, and stays there until killed.
static void __attribute__((noreturn)) dies_in_callback(void) {
    int fd = serve_start(CODE_X);
    for (;;) {
        struct txn *t = 0;
        if (next_cmd(fd, &t) == BR_TRANSACTION && t->code == CODE_CALL_X)
            send_txn(fd, BC_TRANSACTION, 0, CODE_CALLBACK, 0, 0, 0, 0);
    }
}

// Answers CODE_PLAIN; on CODE_RELAY calls the object it was given.
static void __attribute__((noreturn)) third_party(void) {
    int fd = serve_start(CODE_Y);
    for (;;) {
        struct txn *t = 0;
        if (next_cmd(fd, &t) != BR_TRANSACTION) continue;
        if (t->code == CODE_RELAY) {
            u32 h = (u32)((struct flat *)t->buffer)->binder_or_handle;
            acquire(fd, h);
            call_for_reply(fd, h, CODE_RELAYED, 0);
        }
        reply(fd, "YYYY", 4);
    }
}

// On CODE_RELAYED calls the test, two processes down from the test's own call.
static void __attribute__((noreturn)) chain_end(void) {
    int fd = serve_start(CODE_Z);
    for (;;) {
        struct txn *t = 0;
        if (next_cmd(fd, &t) != BR_TRANSACTION) continue;
        call_for_reply(fd, 0, CODE_CHAIN, 0);
        reply(fd, 0, 0);
    }
}

int cmain(void) {
    int mgr = open_binder();
    check(sys(NR_ioctl, mgr, BINDER_SET_CONTEXT_MGR, 0) == 0, "become context manager");
    u32 enter = BC_ENTER_LOOPER;
    write_cmds(mgr, &enter, 4);

    i64 x = sys(NR_clone, 17, 0, 0, 0, 0);
    if (x == 0) dies_in_callback();
    i64 y = sys(NR_clone, 17, 0, 0, 0, 0);
    if (y == 0) third_party();
    i64 z = sys(NR_clone, 17, 0, 0, 0, 0);
    if (z == 0) chain_end();

    u32 handles[4] = { 0 };
    for (int i = 0; i < 3; i++) {
        struct txn *t = 0;
        if (next_cmd(mgr, &t) != BR_TRANSACTION) break;
        u32 h = (u32)((struct flat *)t->buffer)->binder_or_handle;
        u32 code = t->code;
        handles[code] = h;
        acquire(mgr, h);
        reply(mgr, 0, 0);
        check(next_cmd(mgr, 0) == BR_TRANSACTION_COMPLETE, "server registered");
    }
    u32 hx = handles[CODE_X], hy = handles[CODE_Y], hz = handles[CODE_Z];
    check(hx && hy && hz, "have all three servers");

    // Calling X, which calls back: the callback is on top of the call to X.
    send_txn(mgr, BC_TRANSACTION, hx, CODE_CALL_X, 0, 0, 0, 0);
    check(next_cmd(mgr, 0) == BR_TRANSACTION_COMPLETE, "call to X accepted");
    struct txn *t = 0;
    check(next_cmd(mgr, &t) == BR_TRANSACTION && t->code == CODE_CALLBACK, "X's callback comes to the thread calling X");

    sys(NR_kill, x, 9);
    sys(NR_wait4, x, 0, 0, 0);
    nap(200); // the driver lets go of a dead process's binder on a thread of its own

    // Still inside the callback: what this thread calls next answers for itself.
    check(call_for_reply(mgr, hy, CODE_PLAIN, 4), "X died: a call made inside its callback gets its own reply");
    reply(mgr, 0, 0);
    check(next_cmd(mgr, 0) == BR_TRANSACTION_COMPLETE, "the callback's reply completes");
    check(next_cmd(mgr, 0) == BR_DEAD_REPLY, "only now does the call to X end, in BR_DEAD_REPLY");
    check(call_for_reply(mgr, hy, CODE_PLAIN, 4), "the thread's stack is clean afterwards");

    // test -> Y -> Z -> test: the last call belongs on the thread at the head of
    // the chain, though Z's own stack never mentions this process. Elsewhere it
    // would wait on locks that thread holds.
    struct flat obj = { TYPE_HANDLE, 0, hz, 0 };
    u64 off = 0;
    send_txn(mgr, BC_TRANSACTION, hy, CODE_RELAY, &obj, sizeof obj, &off, 8);
    check(next_cmd(mgr, 0) == BR_TRANSACTION_COMPLETE, "call down the chain accepted");
    t = 0;
    check(next_cmd(mgr, &t) == BR_TRANSACTION && t->code == CODE_CHAIN, "a call back up a chain comes to the thread at its head");
    reply(mgr, 0, 0);
    struct txn *r = 0;
    u32 c = next_cmd(mgr, 0);
    if (c == BR_TRANSACTION_COMPLETE) c = next_cmd(mgr, &r);
    check(c == BR_REPLY && r && r->data_size == 4, "and the chain unwinds to its reply");

    sys(NR_kill, y, 9);
    sys(NR_kill, z, 9);
    sys(NR_wait4, y, 0, 0, 0);
    sys(NR_wait4, z, 0, 0, 0);
    puts_(failures ? "SOME CHECKS FAILED\n" : "all checks passed\n");
    return failures;
}

void __attribute__((noreturn)) cstart(void) {
    sys(NR_exit_group, cmain());
    __builtin_unreachable();
}

__asm__(".global _start\n_start:\n bl cstart\n");

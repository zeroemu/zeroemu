// Freestanding arm64 test of binder's reference counting: an object's owner hears
// BR_INCREFS and BR_ACQUIRE when others first hold it, and BR_RELEASE and
// BR_DECREFS when the last lets go, by releasing it or by dying. A buffer holds
// what it carries until it is freed.

typedef unsigned long u64;
typedef long i64;
typedef unsigned int u32;

#define NR_openat 56
#define NR_write 64
#define NR_ioctl 29
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
#define sys(...) sys6_(__VA_ARGS__, 0, 0, 0, 0, 0, 0)
#define sys6_(n, a, b, c, d, e, f, ...) sys6(n, (i64)(a), (i64)(b), (i64)(c), (i64)(d), (i64)(e), (i64)(f))

void *memset(void *d, int c, u64 n) { char *p = d; while (n--) *p++ = (char)c; return d; }
void *memcpy(void *d, const void *s, u64 n) { char *a = d; const char *b = s; while (n--) *a++ = *b++; return d; }
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
#define BC_TRANSACTION 0x40406300
#define BC_REPLY 0x40406301
#define BC_FREE_BUFFER 0x40086303
#define BC_INCREFS 0x40046304
#define BC_ACQUIRE 0x40046305
#define BC_RELEASE 0x40046306
#define BC_DECREFS 0x40046307
#define BC_INCREFS_DONE 0x40106308
#define BC_ACQUIRE_DONE 0x40106309
#define BC_ENTER_LOOPER 0x630c
#define BR_TRANSACTION 0x80407202
#define BR_REPLY 0x80407203
#define BR_DEAD_REPLY 0x7205
#define BR_INCREFS 0x80107207
#define BR_ACQUIRE 0x80107208
#define BR_RELEASE 0x80107209
#define BR_DECREFS 0x8010720a
#define TYPE_BINDER 0x73622a85
#define TYPE_HANDLE 0x73682a85

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

static void command(int fd, u32 cmd, u32 handle) {
    struct { u32 cmd; u32 handle; } __attribute__((packed)) c = { cmd, handle };
    bw(fd, &c, sizeof c, 0, 0, 0);
}

static void free_buffer(int fd, u64 buffer) {
    struct { u32 cmd; u64 ptr; } __attribute__((packed)) c = { BC_FREE_BUFFER, buffer };
    bw(fd, &c, sizeof c, 0, 0, 0);
}

// Everything the driver said, in order. Reads acknowledge what the protocol
// wants acknowledged, as libbinder does.
static struct { u32 cmd; u64 ptr; struct txn t; } said[64];
static int nsaid;
static u32 rbuf[1024];

static void pump(int fd) {
    u64 got = 0;
    if (bw(fd, 0, 0, rbuf, sizeof rbuf, &got) < 0) return;
    char *p = (char *)rbuf, *end = p + got;
    while (p < end) {
        u32 cmd = *(u32 *)p;
        p += 4;
        u32 size = (cmd >> 16) & 0x3fff;
        if (nsaid < 64) {
            said[nsaid].cmd = cmd;
            if (size == 16) said[nsaid].ptr = *(u64 *)p;
            if (cmd == BR_TRANSACTION || cmd == BR_REPLY) memcpy(&said[nsaid].t, p, sizeof(struct txn));
            nsaid++;
        }
        if (cmd == BR_INCREFS || cmd == BR_ACQUIRE) {
            struct { u32 cmd; u64 ptr, cookie; } __attribute__((packed)) done = { cmd == BR_INCREFS ? BC_INCREFS_DONE : BC_ACQUIRE_DONE, *(u64 *)p, *(u64 *)(p + 8) };
            bw(fd, &done, sizeof done, 0, 0, 0);
        }
        p += size;
    }
}

static int find(u32 cmd, u64 ptr) {
    for (int i = 0; i < nsaid; i++) {
        if (said[i].cmd == cmd && (!ptr || said[i].ptr == ptr)) return i;
    }
    return -1;
}

// Waits for a command; -1 if it does not come.
static int await(int fd, u32 cmd, u64 ptr) {
    for (int tries = 0; tries < 200; tries++) {
        int i = find(cmd, ptr);
        if (i >= 0) return i;
        pump(fd);
    }
    return find(cmd, ptr);
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
    bw(fd, &w, sizeof w, 0, 0, 0);
}

#define CHILD_OBJECT 0x1234
#define MANAGER_OBJECT 0x3333

static void child(void) {
    int fd = open_binder();
    int bad = 0;
    struct flat obj = { TYPE_BINDER, 0, CHILD_OBJECT, 0x5678 };
    u64 offs[1] = { 0 };
    send_txn(fd, BC_TRANSACTION, 0, 1, &obj, sizeof obj, offs, sizeof offs);
    int r = await(fd, BR_REPLY, 0);
    if (r < 0) bad |= 1;
    if (find(BR_INCREFS, CHILD_OBJECT) < 0 || find(BR_ACQUIRE, CHILD_OBJECT) < 0) bad |= 2;
    if (find(BR_RELEASE, CHILD_OBJECT) >= 0) bad |= 4; // the manager holds it

    // The reply carries the manager's object. Hold it, then free the buffer.
    if (r >= 0) {
        struct flat *h = (struct flat *)said[r].t.buffer;
        if (h->type != TYPE_HANDLE || !h->binder_or_handle) bad |= 8;
        command(fd, BC_ACQUIRE, (u32)h->binder_or_handle);
        free_buffer(fd, said[r].t.buffer);
    }
    // The manager now lets go of ours. Then we die holding its object.
    if (await(fd, BR_RELEASE, CHILD_OBJECT) < 0) bad |= 16;
    if (await(fd, BR_DECREFS, CHILD_OBJECT) < 0) bad |= 32;
    sys(NR_exit_group, bad);
}

int cmain(void) {
    int mgr = open_binder();
    check(sys(NR_ioctl, mgr, BINDER_SET_CONTEXT_MGR, 0) == 0, "become context manager");
    u32 enter = BC_ENTER_LOOPER;
    bw(mgr, &enter, 4, 0, 0, 0);

    i64 pid = sys(NR_clone, 17, 0, 0, 0, 0);
    if (pid == 0) child();

    int t = await(mgr, BR_TRANSACTION, 0);
    check(t >= 0, "the child's call arrives");
    u32 handle = 0;
    if (t >= 0) {
        struct flat *o = (struct flat *)said[t].t.buffer;
        handle = (u32)o->binder_or_handle;
        check(o->type == TYPE_HANDLE && handle, "its object is a handle here");
        u64 buffer = said[t].t.buffer;
        command(mgr, BC_ACQUIRE, handle);
        free_buffer(mgr, buffer);

        struct flat mine = { TYPE_BINDER, 0, MANAGER_OBJECT, 0x4444 };
        u64 offs[1] = { 0 };
        send_txn(mgr, BC_REPLY, 0, 0, &mine, sizeof mine, offs, sizeof offs);
    }
    check(await(mgr, BR_ACQUIRE, MANAGER_OBJECT) >= 0 && find(BR_INCREFS, MANAGER_OBJECT) >= 0, "the owner hears BR_INCREFS and BR_ACQUIRE");
    check(find(BR_RELEASE, MANAGER_OBJECT) < 0, "and no BR_RELEASE while the buffer holds it");

    command(mgr, BC_RELEASE, handle);
    int st = -1;
    sys(NR_wait4, pid, &st, 0, 0);
    int code = (st >> 8) & 0xff;
    check(code == 0, "the child's checks: told on acquire, told on release, nothing early");
    if (code) {
        char digits[8] = {'0' + code / 10, '0' + code % 10, '\n', 0};
        puts_("     child's failure bits: "), puts_(digits);
    }

    check(await(mgr, BR_RELEASE, MANAGER_OBJECT) >= 0, "a process that dies releases what it held");
    check(await(mgr, BR_DECREFS, MANAGER_OBJECT) >= 0, "and BR_DECREFS follows");

    // The handle died with its last reference.
    nsaid = 0;
    send_txn(mgr, BC_TRANSACTION, handle, 2, "x", 1, 0, 0);
    check(await(mgr, BR_DEAD_REPLY, 0) >= 0, "a released handle is gone");

    puts_(failures ? "SOME CHECKS FAILED\n" : "all checks passed\n");
    return failures;
}

void __attribute__((noreturn)) cstart(void) {
    sys(NR_exit_group, cmain());
    __builtin_unreachable();
}

__asm__(".global _start\n_start:\n bl cstart\n");

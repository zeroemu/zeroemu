// Freestanding arm64 test of droidrt's bpf(2): hash, array, per-CPU and
// LPM-trie maps; update flags; key iteration; program loading and info;
// pinning in bpffs and getting the object back; ids.

typedef unsigned long u64;
typedef long i64;
typedef unsigned int u32;

#define NR_mkdirat 34
#define NR_openat 56
#define NR_mount 40
#define NR_close 57
#define NR_write 64
#define NR_exit_group 94
#define NR_bpf 280

#define ENOENT 2
#define E2BIG 7
#define EEXIST 17
#define EINVAL 22

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

static int failures;
static void check(int cond, const char *name) {
    puts_(cond ? "ok   " : "FAIL ");
    puts_(name);
    puts_("\n");
    if (!cond) failures++;
}

static u64 attr[18];
static i64 bpf(int cmd) { return sys(NR_bpf, cmd, attr, sizeof attr); }
static void clear(void) { memset(attr, 0, sizeof attr); }

static int map_create(u32 type, u32 key, u32 value, u32 max) {
    clear();
    u32 *a = (u32 *)attr;
    a[0] = type, a[1] = key, a[2] = value, a[3] = max;
    return (int)bpf(0);
}
static i64 elem(int cmd, int fd, void *key, void *value, u64 flags) {
    clear();
    attr[0] = (u32)fd, attr[1] = (u64)key, attr[2] = (u64)value, attr[3] = flags;
    return bpf(cmd);
}

int cmain(void) {
    int h = map_create(1 /* HASH */, 4, 8, 2);
    check(h >= 0, "create a hash map");
    u32 k1 = 1, k2 = 2, k3 = 3, next = 0;
    u64 v = 11, out = 0;
    check(elem(2, h, &k1, &v, 0) == 0 && elem(1, h, &k1, &out, 0) == 0 && out == 11, "update and lookup");
    check(elem(2, h, &k1, &v, 1 /* NOEXIST */) == -EEXIST && elem(2, h, &k2, &v, 2 /* EXIST */) == -ENOENT, "NOEXIST and EXIST");
    v = 22;
    check(elem(2, h, &k2, &v, 0) == 0 && elem(2, h, &k3, &v, 0) == -E2BIG, "a full hash map: E2BIG");
    check(elem(4, h, 0, &next, 0) == 0 && next == 1 && elem(4, h, &next, &next, 0) == 0 && next == 2 && elem(4, h, &next, &next, 0) == -ENOENT, "iterate keys");
    check(elem(3, h, &k1, 0, 0) == 0 && elem(1, h, &k1, &out, 0) == -ENOENT, "delete");

    int a = map_create(2 /* ARRAY */, 4, 4, 4);
    u32 i = 3, val = 0, big = 4;
    check(a >= 0 && elem(1, a, &i, &val, 0) == 0 && val == 0, "array elements start zeroed");
    check(elem(3, a, &i, 0, 0) == -EINVAL && elem(2, a, &big, &val, 0) == -E2BIG, "array: no delete, bounded index");

    int p = map_create(6 /* PERCPU_ARRAY */, 4, 4, 1);
    static u64 slots[64];
    i = 0;
    check(p >= 0 && elem(1, p, &i, slots, 0) == 0, "per-CPU array lookup fills one slot per CPU");

    int t = map_create(11 /* LPM_TRIE */, 8, 4, 8);
    u32 pfx16[2] = { 16, 0x0000a8c0 }, host[2] = { 32, 0x0501a8c0 }, got = 0, tag = 7;
    check(t >= 0 && elem(2, t, pfx16, &tag, 0) == 0 && elem(1, t, host, &got, 0) == 0 && got == 7, "LPM trie: longest prefix match");

    static u64 insns[2] = { 0x00000000000000b7ul /* r0 = 0 */, 0x0000000000000095ul /* exit */ };
    clear();
    u32 *pa = (u32 *)attr;
    pa[0] = 1 /* SOCKET_FILTER */, pa[1] = 2;
    attr[1] = (u64)insns;
    attr[2] = (u64)"GPL";
    int prog = (int)bpf(5);
    check(prog >= 0, "load a program");
    static u32 info[58];
    clear();
    attr[0] = (u32)prog | (u64)sizeof info << 32;
    attr[1] = (u64)info;
    check(bpf(15) == 0 && info[0] == 1 && info[4] == 16, "program info: type and jited length");

    sys(NR_mkdirat, -100, "/tmp/bpf", 0755);
    check(sys(NR_mount, "bpf", "/tmp/bpf", "bpf", 0, 0) == 0, "mount bpffs");
    clear();
    attr[0] = (u64)"/tmp/bpf/map_h";
    attr[1] = (u32)h;
    check(bpf(6) == 0, "pin a map");
    sys(NR_close, h);
    clear();
    attr[0] = (u64)"/tmp/bpf/map_h";
    int h2 = (int)bpf(7);
    check(h2 >= 0 && elem(1, h2, &k2, &out, 0) == 0 && out == 22, "get the pinned map back, contents intact");
    clear();
    attr[0] = (u64)"/tmp/not_bpf";
    attr[1] = (u32)h2;
    check(bpf(6) < 0, "pinning outside bpffs fails");

    clear();
    u32 *ia = (u32 *)attr;
    int seen = 0;
    while (bpf(12 /* MAP_GET_NEXT_ID */) == 0) { seen++; ia[0] = ia[1]; }
    check(seen == 4, "map ids iterate over the four live maps");

    // netd aborts unless a query finds the programs attached to the root cgroup.
    int cg = (int)sys(NR_openat, -100, "/tmp", 0x4000 /* O_DIRECTORY */, 0);
    static u32 ids[4];
    clear();
    pa[0] = (u32)cg, pa[1] = (u32)prog, pa[2] = 1 /* CGROUP_INET_EGRESS */;
    check(bpf(8 /* PROG_ATTACH */) == 0, "attach a program to a cgroup");
    clear();
    pa[0] = (u32)cg, pa[1] = 1, pa[6] = 4;
    attr[2] = (u64)ids;
    check(bpf(16 /* PROG_QUERY */) == 0 && pa[6] == 1 && ids[0] == info[1], "query lists the attached program");
    clear();
    pa[0] = (u32)cg, pa[1] = 0 /* CGROUP_INET_INGRESS */;
    check(bpf(16) == 0 && pa[6] == 0, "other attach types are empty");
    clear();
    pa[0] = (u32)cg, pa[1] = (u32)prog, pa[2] = 1;
    int detached = bpf(9 /* PROG_DETACH */) == 0;
    clear();
    pa[0] = (u32)cg, pa[1] = 1;
    check(detached && bpf(16) == 0 && pa[6] == 0, "detach removes it");

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

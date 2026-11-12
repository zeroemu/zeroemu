// Freestanding arm64 test of zeroemu's virtio-gpu DRM node: version and
// capsets, a guest blob and a host-visible blob (mmap both), PRIME, a
// sync_file fence, and one atomic page flip. Exits 0 with no device, so the
// default headless run stays green; ZEROEMU_GPU=fake is what exercises it.

typedef unsigned long u64;
typedef long i64;
typedef unsigned int u32;
typedef unsigned char u8;

#define NR_ioctl 29
#define NR_close 57
#define NR_read 63
#define NR_write 64
#define NR_ppoll 73
#define NR_exit_group 94
#define NR_munmap 215
#define NR_mmap 222
#define NR_openat 56

#define AT_FDCWD (-100)
#define O_RDWR 2
#define PROT_RW 3
#define MAP_SHARED 1

#define ENOENT 2
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

void *memset(void *d, int c, u64 n) { u8 *p = d; while (n--) *p++ = (u8)c; return d; }
void *memcpy(void *d, const void *s, u64 n) { u8 *p = d; const u8 *q = s; while (n--) *p++ = *q++; return d; }
static u64 slen(const char *s) { u64 n = 0; while (s[n]) n++; return n; }
static void puts_(const char *s) { sys(NR_write, 1, s, slen(s)); }

static int failures;
static void check(int cond, const char *name) {
    puts_(cond ? "ok   " : "FAIL ");
    puts_(name);
    puts_("\n");
    if (!cond) failures++;
}

static void w32(u8 *b, int o, u32 v) { memcpy(b + o, &v, 4); }
static void w64(u8 *b, int o, u64 v) { memcpy(b + o, &v, 8); }
static u32 r32(u8 *b, int o) { u32 v; memcpy(&v, b + o, 4); return v; }
static u64 r64(u8 *b, int o) { u64 v; memcpy(&v, b + o, 8); return v; }

static u64 ioc(u32 dir, u32 type, u32 nr, u32 size) {
    return ((u64)dir << 30) | ((u64)size << 16) | ((u64)type << 8) | nr;
}
static i64 xioctl(int fd, u64 cmd, void *arg) { return sys(NR_ioctl, fd, cmd, arg); }

static u8 buf[256];
static u8 scratch[256];

static i64 map_gem(int fd, u32 handle, u64 len) {
    memset(buf, 0, 16);
    w32(buf, 8, handle);
    if (xioctl(fd, ioc(3, 'd', 0x41, 16), buf) < 0) return -1;
    return sys(NR_mmap, 0, len, PROT_RW, MAP_SHARED, fd, r64(buf, 0));
}

int cmain(void) {
    int rd = (int)sys(NR_openat, AT_FDCWD, "/dev/dri/renderD128", O_RDWR, 0);
    if (rd < 0) {
        puts_("no drm device, skipping\n");
        return 0;
    }
    int card = (int)sys(NR_openat, AT_FDCWD, "/dev/dri/card0", O_RDWR, 0);
    check(card >= 0, "open card0");

    memset(buf, 0, 64);
    w64(buf, 16, 64);
    w64(buf, 24, (u64)scratch);
    check(xioctl(rd, ioc(3, 'd', 0x00, 64), buf) == 0 && scratch[0] == 'v', "VERSION name virtio_gpu");

    memset(buf, 0, 16);
    w64(buf, 0, 7);
    w64(buf, 8, (u64)scratch);
    check(xioctl(rd, ioc(3, 'd', 0x43, 16), buf) == 0, "GETPARAM");
    u64 mask = r64(scratch, 0);
    check((mask & (1ul << 8)) != 0 && (mask & (1ul << 9)) != 0, "capsets 8 and 9");

    w64(scratch, 0, 1);
    w64(scratch, 8, 8);
    memset(buf, 0, 16);
    w32(buf, 0, 1);
    w64(buf, 8, (u64)scratch);
    check(xioctl(rd, ioc(3, 'd', 0x4b, 16), buf) == 0, "CONTEXT_INIT capset 8");

    memset(buf, 0, 48);
    w32(buf, 0, 1); // GUEST
    w32(buf, 4, 1); // MAPPABLE
    w64(buf, 16, 4096);
    check(xioctl(rd, ioc(3, 'd', 0x4a, 48), buf) == 0, "guest blob");
    u32 ghandle = r32(buf, 8);
    u8 *gp = (u8 *)map_gem(rd, ghandle, 4096);
    check((u64)gp < (u64)-4096, "mmap guest blob");
    if ((u64)gp < (u64)-4096) {
        gp[0] = 0x5a;
        check(gp[0] == 0x5a, "guest blob store is visible");
        sys(NR_munmap, gp, 4096);
    }

    memset(buf, 0, 48);
    w32(buf, 0, 2); // HOST3D
    w32(buf, 4, 1);
    w64(buf, 16, 16384);
    check(xioctl(rd, ioc(3, 'd', 0x4a, 48), buf) == 0, "host blob");
    u32 hhandle = r32(buf, 8);
    u8 *hp = (u8 *)map_gem(rd, hhandle, 16384);
    check((u64)hp < (u64)-4096, "mmap host blob");
    if ((u64)hp < (u64)-4096) {
        hp[0] = 0xa5;
        check(hp[0] == 0xa5, "host blob store is visible");
        sys(NR_munmap, hp, 16384);
    }

    memset(buf, 0, 12);
    w32(buf, 0, hhandle);
    check(xioctl(rd, ioc(3, 'd', 0x2d, 12), buf) == 0, "PRIME handle to fd");
    int dma = (int)r32(buf, 8);
    u8 *dp = (u8 *)sys(NR_mmap, 0, 16384, PROT_RW, MAP_SHARED, dma, 0);
    check((u64)dp < (u64)-4096 && dp[0] == 0xa5, "dma-buf mmap sees the host blob");
    if ((u64)dp < (u64)-4096) sys(NR_munmap, dp, 16384);
    memset(buf, 0, 12);
    w32(buf, 8, (u32)dma);
    check(card >= 0 && xioctl(card, ioc(3, 'd', 0x2e, 12), buf) == 0 && r32(buf, 0) >= 1, "PRIME fd to handle");

    memset(buf, 0, 40);
    w32(buf, 0, 2); // FENCE_FD_OUT
    check(xioctl(rd, ioc(3, 'd', 0x42, 40), buf) == 0, "EXECBUFFER fence out");
    int sfd = (int)r32(buf, 28);
    u8 pfd[8];
    memset(pfd, 0, 8);
    w32(pfd, 0, (u32)sfd);
    pfd[4] = 1; // POLLIN
    check(sys(NR_ppoll, pfd, 1, 0, 0) == 1 && (pfd[6] & 1) != 0, "fence fd is POLLIN");
    memset(buf, 0, 56);
    check(xioctl(sfd, ioc(3, '>', 4, 56), buf) == 0 && (int)r32(buf, 32) == 1, "SYNC_IOC_FILE_INFO signaled");

    memset(buf, 0, 16);
    w64(buf, 0, 3); // DRM_CLIENT_CAP_ATOMIC
    w64(buf, 8, 1);
    check(card >= 0 && xioctl(card, ioc(1, 'd', 0x0d, 16), buf) == 0, "SET_CLIENT_CAP atomic");

    memset(buf, 0, 32);
    w32(buf, 0, 4);
    w32(buf, 4, 4);
    w32(buf, 8, 32);
    check(card >= 0 && xioctl(card, ioc(3, 'd', 0xb2, 32), buf) == 0, "CREATE_DUMB");
    u32 dumb = r32(buf, 16);
    memset(buf, 0, 16);
    w32(buf, 0, dumb);
    check(xioctl(card, ioc(3, 'd', 0xb3, 16), buf) == 0, "MAP_DUMB");
    u8 *db = (u8 *)sys(NR_mmap, 0, 4096, PROT_RW, MAP_SHARED, card, r64(buf, 8));
    check((u64)db < (u64)-4096, "mmap dumb buffer");
    if ((u64)db < (u64)-4096) {
        db[0] = 1;
        check(db[0] == 1, "dumb buffer store");
        sys(NR_munmap, db, 4096);
    }

    memset(buf, 0, 104);
    w32(buf, 4, 4);
    w32(buf, 8, 4);
    w32(buf, 20, dumb);
    check(xioctl(card, ioc(3, 'd', 0xb8, 104), buf) == 0, "ADDFB2");
    u32 fb = r32(buf, 0);
    static u32 objs[1], counts[1], props[1];
    static u64 vals[1];
    objs[0] = 4; // plane
    counts[0] = 1;
    props[0] = 21; // FB_ID
    vals[0] = fb;
    memset(buf, 0, 56);
    w32(buf, 0, 0x0400 | 0x01); // ALLOW_MODESET | PAGE_FLIP_EVENT
    w32(buf, 4, 1);
    w64(buf, 8, (u64)objs);
    w64(buf, 16, (u64)counts);
    w64(buf, 24, (u64)props);
    w64(buf, 32, (u64)vals);
    check(xioctl(card, ioc(3, 'd', 0xbc, 56), buf) == 0, "atomic commit");
    u8 ev[32];
    check(sys(NR_read, card, ev, 32) == 32 && r32(ev, 0) == 2, "page-flip event");

    sys(NR_close, dma);
    sys(NR_close, sfd);
    sys(NR_close, rd);
    sys(NR_close, card);
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

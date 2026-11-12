// Freestanding arm64 test of droidrt's /dev/fuse and fuse mounts (no libc), as
// vold and MediaProvider's daemon use them: mount with fd=, the daemon taking
// FUSE_INIT from a second thread by splice (as libfuse reads) and answering it,
// FUSE_DEV_IOC_CLONE, the device's refusals, and the mount showing /data/media
// with no permission checks, chmod changing nothing, and new files belonging to
// the daemon. Unmounting ends the daemon's blocked read with ENODEV.
typedef unsigned long u64;
typedef long i64;
typedef unsigned int u32;
typedef unsigned short u16;

#define NR_listxattr 11
#define NR_ioctl 29
#define NR_mkdirat 34
#define NR_umount2 39
#define NR_mount 40
#define NR_statfs 43
#define NR_fchmodat 53
#define NR_openat 56
#define NR_close 57
#define NR_pipe2 59
#define NR_read 63
#define NR_write 64
#define NR_ppoll 73
#define NR_splice 76
#define NR_newfstatat 79
#define NR_exit 93
#define NR_exit_group 94
#define NR_futex 98
#define NR_setresuid 147
#define NR_setresgid 149
#define NR_setgroups 159
#define NR_clone 220
#define NR_mmap 222
#define NR_wait4 260

#define O_RDONLY 0
#define O_WRONLY 1
#define O_RDWR 2
#define O_CREAT 0100
#define O_NONBLOCK 04000
#define O_CLOEXEC 02000000
#define AT_FDCWD -100
#define MS_NOSUID 2
#define MS_NODEV 4
#define EPERM 1
#define ENOENT 2
#define EAGAIN 11
#define EACCES 13
#define ENODEV 19
#define EINVAL 22
#define FUSE_DEV_IOC_CLONE 0x8004e500
#define FUSE_INIT 26
#define FS_IOC_GETFLAGS 0x80086601
#define FS_IOC_SETFLAGS 0x40086602
#define FS_IOC_FSGETXATTR 0x801c581f
#define FS_IOC_FSSETXATTR 0x401c5820
#define FS_PROJINHERIT_FL 0x20000000
#define FS_XFLAG_PROJINHERIT 0x200
#define ENOTTY 25

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
static int same(const char *a, const char *b, u64 n) { while (n--) if (*a++ != *b++) return 0; return 1; }
static int contains(const char *hay, i64 n, const char *needle) {
    u64 m = slen(needle);
    for (i64 i = 0; i + (i64)m <= n; i++) if (same(hay + i, needle, m)) return 1;
    return 0;
}
static char *append(char *d, const char *s) { while (*s) *d++ = *s++; *d = 0; return d; }
static char *append_num(char *d, u64 v) {
    char tmp[24];
    int n = 0;
    do tmp[n++] = (char)('0' + v % 10); while (v /= 10);
    while (n) *d++ = tmp[--n];
    *d = 0;
    return d;
}

static int failures;
static void check(int cond, const char *name) {
    puts_(cond ? "ok   " : "FAIL ");
    puts_(name);
    puts_("\n");
    if (!cond) failures++;
}

#define CLONE_THREAD_FLAGS (0x100 | 0x200 | 0x400 | 0x800 | 0x10000 | 0x40000 | 0x200000)

static i64 spawn(void *stack_top, void (*fn)(void *), void *arg, int *ctid) {
    register i64 x0 __asm__("x0") = CLONE_THREAD_FLAGS;
    register i64 x1 __asm__("x1") = (i64)stack_top;
    register i64 x2 __asm__("x2") = 0;
    register i64 x3 __asm__("x3") = 0;
    register i64 x4 __asm__("x4") = (i64)ctid;
    register i64 x8 __asm__("x8") = NR_clone;
    register void *x19 __asm__("x19") = (void *)fn;
    register void *x20 __asm__("x20") = arg;
    __asm__ volatile(
        "svc #0\n"
        "cbnz x0, 1f\n"
        "mov x0, x20\n"
        "blr x19\n"
        "mov x0, #0\n"
        "mov x8, #93\n"
        "svc #0\n"
        "1:\n"
        : "+r"(x0)
        : "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x8), "r"(x19), "r"(x20)
        : "memory", "x30");
    return x0;
}

static i64 fork_(void) { return sys(NR_clone, 17 /* SIGCHLD */, 0, 0, 0, 0); }
static int wait_(i64 pid) {
    int st = 0;
    sys(NR_wait4, pid, &st, 0, 0);
    return st;
}

/// Waits until *word is nonzero.
static void await_(volatile int *word) {
    while (__atomic_load_n(word, __ATOMIC_ACQUIRE) == 0) sys(NR_futex, word, 128 /* WAIT|PRIVATE */, 0, 0);
}
static void signal_(volatile int *word, int v) {
    __atomic_store_n(word, v, __ATOMIC_RELEASE);
    sys(NR_futex, word, 129 /* WAKE|PRIVATE */, 0x7fffffff);
}

// FUSE_INIT's answer: fuse_out_header and a 7.31 fuse_init_out.
static void init_reply(char *out, u64 unique) {
    memset(out, 0, 80);
    *(u32 *)(out + 0) = 80;
    *(u64 *)(out + 8) = unique;
    *(u32 *)(out + 16) = 7;         // major
    *(u32 *)(out + 20) = 31;        // minor
    *(u32 *)(out + 24) = 131072;    // max_readahead
    *(u32 *)(out + 28) = 1;         // FUSE_ASYNC_READ
    *(u32 *)(out + 36) = 131072;    // max_write
}

static int fusefd;
static char req[65536];
static i64 spliced, req_len, reply_written, last_read;
static volatile int init_done, daemon_done;

static void daemon_thread(void *arg) {
    (void)arg;
    // libfuse's receive: splice from the device into a pipe, then read the pipe.
    int p[2];
    sys(NR_pipe2, p, O_CLOEXEC);
    spliced = sys(NR_splice, fusefd, 0, p[1], 0, sizeof req, 0);
    req_len = spliced > 0 ? sys(NR_read, p[0], req, sizeof req) : spliced;
    static char out[80];
    init_reply(out, *(u64 *)(req + 8));
    reply_written = sys(NR_write, fusefd, out, 80);
    signal_(&init_done, 1);
    // Then wait for the next request, which only the unmount ends.
    static char more[65536];
    last_read = sys(NR_read, fusefd, more, sizeof more);
    signal_(&daemon_done, 1);
}

static int mount_fuse(const char *at, int fd, const char *extra) {
    static char opts[128];
    char *e = append(opts, "fd=");
    e = append_num(e, (u64)fd);
    append(e, extra);
    return (int)sys(NR_mount, "/dev/fuse", at, "fuse", MS_NOSUID | MS_NODEV, opts);
}

static int put(const char *path, const char *text) {
    int fd = (int)sys(NR_openat, AT_FDCWD, path, O_WRONLY | O_CREAT, 0644);
    if (fd < 0) return fd;
    i64 n = sys(NR_write, fd, text, slen(text));
    sys(NR_close, fd);
    return n == (i64)slen(text) ? 0 : -1;
}

static int has(const char *path, const char *text) {
    static char buf[256];
    int fd = (int)sys(NR_openat, AT_FDCWD, path, O_RDONLY, 0);
    if (fd < 0) return 0;
    i64 n = sys(NR_read, fd, buf, sizeof buf);
    sys(NR_close, fd);
    return n == (i64)slen(text) && same(buf, text, (u64)n);
}

int cmain(void) {
    static char buf[65536];
    u64 st[16];

    fusefd = (int)sys(NR_openat, AT_FDCWD, "/dev/fuse", O_RDWR | O_CLOEXEC, 0);
    check(fusefd >= 0, "open /dev/fuse");
    check(sys(NR_read, fusefd, buf, sizeof buf) == -EPERM, "reading before any mount: EPERM");

    // The lower filesystem, as init and vold make it.
    sys(NR_mkdirat, AT_FDCWD, "/data/media", 0770);
    sys(NR_mkdirat, AT_FDCWD, "/data/media/0", 0770);
    sys(NR_mkdirat, AT_FDCWD, "/tmp/f", 0755);
    sys(NR_mkdirat, AT_FDCWD, "/tmp/g", 0755);

    check(mount_fuse("/tmp/f", fusefd, ",user_id=0,group_id=0") == -EINVAL, "mount without rootmode: EINVAL");
    int null = (int)sys(NR_openat, AT_FDCWD, "/dev/null", O_RDWR, 0);
    check(mount_fuse("/tmp/f", null, ",rootmode=40000,user_id=0,group_id=0") == -EINVAL, "fd= must be /dev/fuse");
    check(mount_fuse("/tmp/f", fusefd, ",rootmode=40000,user_id=0,group_id=0,nosuchoption") == -EINVAL, "an unknown option: EINVAL");
    check(mount_fuse("/tmp/f", fusefd, ",rootmode=40000,allow_other,user_id=0,group_id=0") == 0, "mount fuse as vold does");
    check(mount_fuse("/tmp/g", fusefd, ",rootmode=40000,user_id=0,group_id=0") == -EINVAL, "one mount per descriptor");

    int m = (int)sys(NR_openat, AT_FDCWD, "/proc/mounts", O_RDONLY, 0);
    i64 n = sys(NR_read, m, buf, sizeof buf);
    sys(NR_close, m);
    check(contains(buf, n, "/dev/fuse /tmp/f fuse rw,nosuid,nodev,relatime,user_id=0,group_id=0,allow_other 0 0\n"), "/proc/mounts shows it as fuse");
    u64 sfs[15];
    check(sys(NR_statfs, "/tmp/f", sfs) == 0 && sfs[0] == 0x65735546, "statfs: FUSE_SUPER_MAGIC");

    // The daemon, in a second thread.
    char *stacks = (char *)sys(NR_mmap, 0, 65536, 3, 0x22, -1, 0);
    static int tid;
    check(spawn(stacks + 65536, daemon_thread, 0, &tid) > 0, "start the daemon thread");
    await_(&init_done);
    check(spliced == 56 && req_len == 56, "FUSE_INIT spliced into a pipe whole: 56 bytes");
    check(*(u32 *)(req + 0) == 56 && *(u32 *)(req + 4) == FUSE_INIT && *(u64 *)(req + 8) != 0 && *(u64 *)(req + 16) == 0, "its header: len, opcode, unique, nodeid 0");
    check(*(u32 *)(req + 24) == 0 && *(u32 *)(req + 28) == 0, "from the mounter's ids");
    check(*(u32 *)(req + 40) == 7 && *(u32 *)(req + 44) >= 31, "protocol 7.31 or later");
    check(!(*(u32 *)(req + 52) & (1u << 31)), "no passthrough offered");
    check(reply_written == 80, "the answer is taken");

    // A second descriptor joins the connection.
    int c = (int)sys(NR_openat, AT_FDCWD, "/dev/fuse", O_RDWR | O_NONBLOCK, 0);
    u32 master = (u32)fusefd;
    check(sys(NR_ioctl, c, FUSE_DEV_IOC_CLONE, &master) == 0, "FUSE_DEV_IOC_CLONE");
    check(sys(NR_ioctl, c, FUSE_DEV_IOC_CLONE, &master) == -EINVAL, "a clone only once");
    check(sys(NR_read, c, buf, sizeof buf) == -EAGAIN, "nothing more to read: EAGAIN");
    check(sys(NR_read, c, buf, 4096) == -EINVAL, "a read buffer under 8 KiB: EINVAL");
    static char out[80];
    init_reply(out, 12345);
    check(sys(NR_write, c, out, 80) == -ENOENT, "an answer to nothing: ENOENT");
    check(sys(NR_write, c, out, 79) == -EINVAL, "a length that isn't the write's: EINVAL");
    memset(out, 0, 32);
    *(u32 *)out = 32;
    *(int *)(out + 4) = 3; // FUSE_NOTIFY_INVAL_ENTRY
    check(sys(NR_write, c, out, 32) == 32, "a notification is taken");
    struct { int fd; short events, revents; } pfd = {c, 1 | 4, 0};
    u64 zero[2] = {0, 0};
    check(sys(NR_ppoll, &pfd, 1, zero, 0, 8) == 1 && pfd.revents == 4, "poll: writable, nothing to read");

    // The mount shows /data/media.
    check(put("/tmp/f/0/hello", "hi there") == 0 && has("/data/media/0/hello", "hi there"), "written through the mount, read from /data/media");
    check(put("/data/media/0/lower", "below") == 0 && has("/tmp/f/0/lower", "below"), "written to /data/media, read through the mount");
    u64 lower[16];
    check(sys(NR_newfstatat, AT_FDCWD, "/tmp/f/0/hello", st, 0) == 0 && sys(NR_newfstatat, AT_FDCWD, "/data/media/0/hello", lower, 0) == 0 && st[0] != lower[0] && st[1] == lower[1], "same inode, the mount's own st_dev");
    check(sys(NR_fchmodat, AT_FDCWD, "/tmp/f/0/hello", 0600, 0) == 0, "chmod on the mount succeeds");
    sys(NR_newfstatat, AT_FDCWD, "/tmp/f/0/hello", st, 0);
    check((((u32 *)st)[4] & 0777) == 0644, "and changes nothing");

    // vold's quota setup on /data/media: a project id that new files and directories inherit.
    sys(NR_mkdirat, AT_FDCWD, "/data/media/0/app", 0770);
    int d = (int)sys(NR_openat, AT_FDCWD, "/data/media/0/app", O_RDONLY, 0);
    u32 fsx[7] = {0};
    check(sys(NR_ioctl, d, FS_IOC_FSGETXATTR, fsx) == 0 && fsx[3] == 0, "FS_IOC_FSGETXATTR: no project id yet");
    fsx[3] = 1234;
    check(sys(NR_ioctl, d, FS_IOC_FSSETXATTR, fsx) == 0, "FS_IOC_FSSETXATTR sets one");
    u32 fl = 0;
    check(sys(NR_ioctl, d, FS_IOC_GETFLAGS, &fl) == 0 && fl == 0, "FS_IOC_GETFLAGS");
    fl = FS_PROJINHERIT_FL;
    check(sys(NR_ioctl, d, FS_IOC_SETFLAGS, &fl) == 0, "FS_IOC_SETFLAGS: project id inheritance");
    sys(NR_close, d);
    sys(NR_mkdirat, AT_FDCWD, "/data/media/0/app/files", 0770);
    put("/data/media/0/app/files/f", "x");
    d = (int)sys(NR_openat, AT_FDCWD, "/data/media/0/app/files", O_RDONLY, 0);
    fsx[0] = fsx[3] = 0;
    check(sys(NR_ioctl, d, FS_IOC_FSGETXATTR, fsx) == 0 && fsx[3] == 1234 && (fsx[0] & FS_XFLAG_PROJINHERIT), "a new directory inherits the id and passes it on");
    sys(NR_close, d);
    d = (int)sys(NR_openat, AT_FDCWD, "/data/media/0/app/files/f", O_RDONLY, 0);
    fsx[0] = fsx[3] = 0;
    check(sys(NR_ioctl, d, FS_IOC_FSGETXATTR, fsx) == 0 && fsx[3] == 1234 && !(fsx[0] & FS_XFLAG_PROJINHERIT), "a new file inherits the id only");
    sys(NR_close, d);
    n = sys(NR_listxattr, "/data/media/0/app", buf, sizeof buf);
    check(n >= 0 && !contains(buf, n, "droidrt"), "listxattr shows none of it");
    d = (int)sys(NR_openat, AT_FDCWD, "/tmp/f/0/app", O_RDONLY, 0);
    check(sys(NR_ioctl, d, FS_IOC_GETFLAGS, &fl) == -ENOTTY, "through the fuse mount: ENOTTY (the daemon answers no ioctls)");
    sys(NR_close, d);

    // An app's uid: the kernel refuses nothing on the mount, as without default_permissions.
    put("/tmp/notmine", "root's");
    i64 pid = fork_();
    if (pid == 0) {
        if (sys(NR_setgroups, 0, 0) || sys(NR_setresgid, 10001, 10001, 10001) || sys(NR_setresuid, 10001, 10001, 10001)) sys(NR_exit_group, 99);
        int bad = 0;
        int fd = (int)sys(NR_openat, AT_FDCWD, "/tmp/f/0/hello", O_RDWR, 0);
        if (fd < 0) bad |= 1;
        if (sys(NR_openat, AT_FDCWD, "/data/media/0/hello", O_RDONLY, 0) != -EACCES) bad |= 2;
        if (put("/tmp/f/0/new", "app") != 0) bad |= 4;
        // Not the owner: FS_IOC_SETFLAGS is EPERM, as chmod would be.
        int nm = (int)sys(NR_openat, AT_FDCWD, "/tmp/notmine", O_RDONLY, 0);
        u32 f0 = 0;
        if (nm < 0 || sys(NR_ioctl, nm, FS_IOC_SETFLAGS, &f0) != -EPERM) bad |= 8;
        sys(NR_exit_group, bad);
    }
    int ws = wait_(pid);
    check(((ws >> 8) & 0xff) == 0, "uid 10001 opens and creates on the mount; /data/media still refuses it; FS_IOC_SETFLAGS on root's file: EPERM");
    sys(NR_newfstatat, AT_FDCWD, "/data/media/0/new", st, 0);
    check(((u32 *)st)[6] == 0, "what it created there belongs to the daemon (root here)");

    // A daemon of another uid: what is created belongs to it, as on the lower filesystem.
    int fd2 = (int)sys(NR_openat, AT_FDCWD, "/dev/fuse", O_RDWR, 0);
    check(mount_fuse("/tmp/g", fd2, ",rootmode=40000,allow_other,user_id=0,group_id=0") == 0, "a second mount");
    pid = fork_();
    if (pid == 0) {
        if (sys(NR_setgroups, 0, 0) || sys(NR_setresgid, 1077, 1077, 1077) || sys(NR_setresuid, 1076, 1076, 1076)) sys(NR_exit_group, 99);
        i64 r = sys(NR_read, fd2, req, sizeof req);
        static char o[80];
        init_reply(o, *(u64 *)(req + 8));
        sys(NR_exit_group, r == 56 && sys(NR_write, fd2, o, 80) == 80 ? 0 : 1);
    }
    ws = wait_(pid);
    check(((ws >> 8) & 0xff) == 0, "the second daemon (uid 1076) answers FUSE_INIT");
    check(put("/tmp/g/0/owned", "mine") == 0 && sys(NR_newfstatat, AT_FDCWD, "/data/media/0/owned", st, 0) == 0 && ((u32 *)st)[6] == 1076 && ((u32 *)st)[7] == 1077, "a file created by root belongs to the daemon, 1076:1077");
    check(sys(NR_umount2, "/tmp/g", 0) == 0, "unmount the second");
    check(sys(NR_read, fd2, buf, sizeof buf) == -ENODEV, "its descriptor reads ENODEV");

    // Unmounting ends the first daemon's blocked read.
    check(sys(NR_umount2, "/tmp/f", 0) == 0, "unmount");
    await_(&daemon_done);
    check(last_read == -ENODEV, "the daemon's blocked read ends with ENODEV");
    pfd.revents = 0;
    check(sys(NR_ppoll, &pfd, 1, zero, 0, 8) == 1 && (pfd.revents & 8), "poll: POLLERR");
    check(has("/data/media/0/hello", "hi there"), "the files stay in /data/media");

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

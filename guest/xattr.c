// Freestanding test of zeroemu's extended attributes (no libc), built for
// arm64 and x86_64: the *xattr syscalls' Linux semantics on tmpfs (flags,
// sizes, namespaces, symlinks, fds of every kind), labels inherited from the
// parent directory, attributes following the inode through rename and link,
// and the labels the kernel's own mounts start with. Exits with the failure count.

typedef unsigned long u64;
typedef long i64;

#if defined(__aarch64__)
#define NR_setxattr 5
#define NR_lsetxattr 6
#define NR_fsetxattr 7
#define NR_getxattr 8
#define NR_lgetxattr 9
#define NR_fgetxattr 10
#define NR_listxattr 11
#define NR_llistxattr 12
#define NR_flistxattr 13
#define NR_removexattr 14
#define NR_lremovexattr 15
#define NR_fremovexattr 16
#define NR_mkdirat 34
#define NR_unlinkat 35
#define NR_symlinkat 36
#define NR_linkat 37
#define NR_renameat 38
#define NR_openat 56
#define NR_close 57
#define NR_pipe2 59
#define NR_write 64
#define NR_exit_group 94
#define NR_socketpair 199
#define NR_memfd_create 279

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
#elif defined(__x86_64__)
#define NR_write 1
#define NR_close 3
#define NR_socketpair 53
#define NR_setxattr 188
#define NR_lsetxattr 189
#define NR_fsetxattr 190
#define NR_getxattr 191
#define NR_lgetxattr 192
#define NR_fgetxattr 193
#define NR_listxattr 194
#define NR_llistxattr 195
#define NR_flistxattr 196
#define NR_removexattr 197
#define NR_lremovexattr 198
#define NR_fremovexattr 199
#define NR_exit_group 231
#define NR_openat 257
#define NR_mkdirat 258
#define NR_unlinkat 263
#define NR_renameat 264
#define NR_linkat 265
#define NR_symlinkat 266
#define NR_pipe2 293
#define NR_memfd_create 319

static i64 sys6(i64 n, i64 a, i64 b, i64 c, i64 d, i64 e, i64 f) {
    register i64 r10 __asm__("r10") = d;
    register i64 r8 __asm__("r8") = e;
    register i64 r9 __asm__("r9") = f;
    __asm__ volatile("syscall" : "+a"(n) : "D"(a), "S"(b), "d"(c), "r"(r10), "r"(r8), "r"(r9) : "rcx", "r11", "memory");
    return n;
}
#else
#error unsupported guest arch
#endif
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

#define AT_FDCWD -100
#define AT_REMOVEDIR 0x200
#define O_RDWR 2
#define O_CREAT 0100
#define XATTR_CREATE 1
#define XATTR_REPLACE 2
#define EPERM 1
#define ENOENT 2
#define E2BIG 7
#define EBADF 9
#define EEXIST 17
#define EINVAL 22
#define ERANGE 34
#define ENODATA 61
#define EOPNOTSUPP 95

static i64 creat_(const char *p) { return sys(NR_openat, AT_FDCWD, p, O_RDWR | O_CREAT, 0644); }
static i64 set(const char *p, const char *n, const char *v, int flags) { return sys(NR_setxattr, p, n, v, slen(v), flags); }
static char buf[70000];
// getxattr into buf; returns the length or -errno. buf is NUL-terminated after it.
static i64 get(const char *p, const char *n) {
    memset(buf, 0, 256);
    return sys(NR_getxattr, p, n, buf, sizeof buf);
}
static int is(const char *s) { return seq(buf, s, slen(s) + 1); }
// Whether a NUL-separated list of `len` bytes in buf holds `name`.
static int listed(i64 len, const char *name) {
    for (i64 i = 0; i < len; i += slen(buf + i) + 1)
        if (seq(buf + i, name, slen(name) + 1)) return 1;
    return 0;
}

int cmain(void) {
    // Kernel-made mounts start labeled; contexts read back NUL-terminated.
    check(get("/dev/null", "security.selinux") == 26 && is("u:object_r:null_device:s0"), "/dev/null is null_device");
    check(get("/dev", "security.selinux") > 0 && is("u:object_r:device:s0"), "/dev is device");
    check(get("/dev/socket", "security.selinux") > 0 && is("u:object_r:socket_device:s0"), "/dev/socket is socket_device");
    check(get("/sys/fs/selinux", "security.selinux") > 0 && is("u:object_r:selinuxfs:s0"), "/sys/fs/selinux is selinuxfs");
    check(get("/data/local/tmp", "security.selinux") > 0 && is("u:object_r:shell_data_file:s0"), "/data/local/tmp is shell_data_file");
    check(get("/", "security.selinux") == -ENODATA, "unlabeled root: ENODATA");
    check(get("/nonexistent", "security.selinux") == -ENOENT, "missing path: ENOENT");
    // get looks the path up before the name; set/remove copy the name first.
    check(sys(NR_getxattr, "/nonexistent", "", buf, 8) == -ENOENT, "get: missing path before empty name");
    check(sys(NR_setxattr, "/nonexistent", "", buf, 1, 0) == -ERANGE, "set: empty name before missing path");
    check(sys(NR_removexattr, "/nonexistent", "") == -ERANGE, "remove: empty name before missing path");

    // New nodes inherit their directory's label.
    check(sys(NR_mkdirat, AT_FDCWD, "/tmp/x", 0755) == 0, "mkdir /tmp/x");
    check(get("/tmp/x", "security.selinux") == 20 && is("u:object_r:tmpfs:s0"), "new dir inherits tmpfs");
    check(sys(NR_getxattr, "/tmp/x", "security.selinux", 0, 0) == 20, "size 0 returns the length");
    check(sys(NR_getxattr, "/tmp/x", "security.selinux", buf, 5) == -ERANGE, "short buffer: ERANGE");
    const char *custom = "u:object_r:custom_file:s0";
    check(sys(NR_setxattr, "/tmp/x", "security.selinux", custom, slen(custom) + 1, 0) == 0, "relabel the dir");
    i64 fd = creat_("/tmp/x/f");
    check(fd >= 0 && get("/tmp/x/f", "security.selinux") > 0 && is(custom), "file inherits the new label");
    check(sys(NR_symlinkat, "f", AT_FDCWD, "/tmp/x/l") == 0 && sys(NR_lgetxattr, "/tmp/x/l", "security.selinux", buf, 256) > 0 && is(custom), "symlink inherits");

    // XATTR_CREATE / XATTR_REPLACE, flags, sizes.
    check(set("/tmp/x/f", "user.a", "1", XATTR_CREATE) == 0, "create user.a");
    check(set("/tmp/x/f", "user.a", "1", XATTR_CREATE) == -EEXIST, "XATTR_CREATE on existing: EEXIST");
    check(set("/tmp/x/f", "user.b", "1", XATTR_REPLACE) == -ENODATA, "XATTR_REPLACE on missing: ENODATA");
    check(set("/tmp/x/f", "user.a", "22", XATTR_REPLACE) == 0 && get("/tmp/x/f", "user.a") == 2 && is("22"), "replace user.a");
    check(set("/tmp/x/f", "user.a", "1", 4) == -EINVAL, "unknown flags: EINVAL");
    check(sys(NR_setxattr, "/tmp/x/f", "user.empty", 0, 0, 0) == 0 && get("/tmp/x/f", "user.empty") == 0, "empty value");
    check(get("/tmp/x/f", "user.missing") == -ENODATA, "missing attribute: ENODATA");
    check(sys(NR_setxattr, "/tmp/x/f", "user.big", buf, 65537, 0) == -E2BIG, "value over 64 KiB: E2BIG");
    memset(buf, 'v', 65536);
    check(sys(NR_setxattr, "/tmp/x/f", "user.big", buf, 65536, 0) == 0 && get("/tmp/x/f", "user.big") == 65536, "64 KiB value");
    check(sys(NR_removexattr, "/tmp/x/f", "user.big") == 0, "remove user.big");

    // Names: a namespace prefix, a suffix, 1..255 bytes.
    check(set("/tmp/x/f", "foo.bar", "1", 0) == -EOPNOTSUPP && get("/tmp/x/f", "foo.bar") == -EOPNOTSUPP, "unknown namespace: EOPNOTSUPP");
    check(set("/tmp/x/f", "user.", "1", 0) == -EINVAL, "empty suffix: EINVAL");
    check(set("/tmp/x/f", "", "1", 0) == -ERANGE && get("/tmp/x/f", "") == -ERANGE, "empty name: ERANGE");
    // vold puts a default ACL on /data/media/0, and user 0's data is destroyed if it can't.
    static const char acl[12] = {2, 0, 0, 0, 1, 0, 7, 0, 0, 0, 0, 0};
    check(sys(NR_setxattr, "/tmp/x/f", "system.posix_acl_access", "1", 1, 0) == -EINVAL, "a malformed ACL: EINVAL");
    check(get("/tmp/x/f", "system.posix_acl_access") == -ENODATA, "no ACL yet: ENODATA");
    check(sys(NR_setxattr, "/tmp/x", "system.posix_acl_default", acl, sizeof acl, 0) == 0, "set a default ACL on a directory");
    check(sys(NR_getxattr, "/tmp/x", "system.posix_acl_default", buf, 256) == sizeof acl && buf[6] == 7, "and read it back");
    check(sys(NR_removexattr, "/tmp/x", "system.posix_acl_default") == 0, "and remove it");
    check(set("/tmp/x/f", "system.other", "1", 0) == -EOPNOTSUPP, "other system.* names: EOPNOTSUPP");
    char name[300];
    memcpy(name, "user.", 5);
    memset(name + 5, 'n', 250);
    name[255] = 0;
    check(set("/tmp/x/f", name, "1", 0) == 0, "255-byte name");
    name[255] = 'n';
    name[256] = 0;
    check(set("/tmp/x/f", name, "1", 0) == -ERANGE && get("/tmp/x/f", name) == -ERANGE, "256-byte name: ERANGE");
    name[255] = 0;
    check(sys(NR_removexattr, "/tmp/x/f", name) == 0, "remove the long name");

    // listxattr: NUL-separated names, size 0 gives the length, ERANGE if short.
    set("/tmp/x/f", "trusted.t", "t", 0);
    i64 need = sys(NR_listxattr, "/tmp/x/f", 0, 0);
    i64 got = sys(NR_listxattr, "/tmp/x/f", buf, sizeof buf);
    check(need == got && got == 17 + 7 + 11 + 10, "listxattr length");
    check(listed(got, "security.selinux") && listed(got, "user.a") && listed(got, "user.empty") && listed(got, "trusted.t"), "listxattr names");
    check(sys(NR_listxattr, "/tmp/x/f", buf, got - 1) == -ERANGE, "listxattr short buffer: ERANGE");
    check(sys(NR_removexattr, "/tmp/x/f", "trusted.t") == 0 && sys(NR_removexattr, "/tmp/x/f", "trusted.t") == -ENODATA, "removexattr, then ENODATA");

    // l* variants act on the link itself; user.* only on files and directories.
    check(sys(NR_lsetxattr, "/tmp/x/l", "trusted.link", "L", 1, 0) == 0, "lsetxattr on a symlink");
    check(sys(NR_lgetxattr, "/tmp/x/l", "trusted.link", buf, 256) == 1, "lgetxattr reads the link");
    check(get("/tmp/x/l", "trusted.link") == -ENODATA && get("/tmp/x/l", "user.a") == 2, "getxattr follows the link");
    check(sys(NR_lsetxattr, "/tmp/x/l", "user.x", "1", 1, 0) == -EPERM, "user.* on a symlink: EPERM");
    check(sys(NR_lgetxattr, "/tmp/x/l", "user.x", buf, 256) == -ENODATA, "user.* get on a symlink: ENODATA");
    got = sys(NR_llistxattr, "/tmp/x/l", buf, sizeof buf);
    check(listed(got, "trusted.link") && !listed(got, "user.a"), "llistxattr lists the link's");
    check(sys(NR_lremovexattr, "/tmp/x/l", "trusted.link") == 0, "lremovexattr");

    // f* variants: files, pipes, sockets, memfds, devices, bad fds.
    check(sys(NR_fsetxattr, fd, "user.fd", "F", 1, 0) == 0 && sys(NR_fgetxattr, fd, "user.fd", buf, 256) == 1 && buf[0] == 'F', "fsetxattr/fgetxattr on a file");
    got = sys(NR_flistxattr, fd, buf, sizeof buf);
    check(listed(got, "user.fd") && listed(got, "security.selinux"), "flistxattr");
    check(sys(NR_fremovexattr, fd, "user.fd") == 0 && get("/tmp/x/f", "user.fd") == -ENODATA, "fremovexattr");
    int p[2];
    sys(NR_pipe2, p, 0);
    check(sys(NR_fgetxattr, p[0], "security.selinux", buf, 256) == -EOPNOTSUPP, "pipe: fgetxattr EOPNOTSUPP");
    check(sys(NR_fsetxattr, p[1], "user.x", "1", 1, 0) == -EOPNOTSUPP, "pipe: fsetxattr EOPNOTSUPP");
    check(sys(NR_flistxattr, p[0], buf, 256) == 0, "pipe: empty list");
    int sv[2];
    sys(NR_socketpair, 1 /* AF_UNIX */, 1 /* SOCK_STREAM */, 0, sv);
    check(sys(NR_fsetxattr, sv[0], "security.selinux", custom, slen(custom) + 1, 0) == 0, "socket: label accepted");
    check(sys(NR_fsetxattr, sv[0], "security.", custom, 1, 0) == -EINVAL, "socket: empty security suffix EINVAL");
    i64 mfd = sys(NR_memfd_create, "x", 0);
    check(sys(NR_fsetxattr, mfd, "user.m", "M", 1, 0) == 0 && sys(NR_fgetxattr, mfd, "user.m", buf, 256) == 1 && buf[0] == 'M', "memfd xattrs");
    check(sys(NR_fgetxattr, mfd, "system.other", buf, 8) == -EOPNOTSUPP, "memfd get system.*: EOPNOTSUPP");
    i64 nfd = sys(NR_openat, AT_FDCWD, "/dev/null", O_RDWR, 0);
    check(sys(NR_fgetxattr, nfd, "security.selinux", buf, 256) == 26 && is("u:object_r:null_device:s0"), "fgetxattr on /dev/null");
    check(sys(NR_fgetxattr, 999, "security.selinux", buf, 256) == -EBADF, "bad fd: EBADF");
    // A bad fd fails before the name is inspected.
    check(sys(NR_fgetxattr, 999, "", buf, 8) == -EBADF, "fgetxattr: bad fd before empty name");
    check(sys(NR_fsetxattr, 999, "", buf, 1, 0) == -EBADF, "fsetxattr: bad fd before empty name");
    check(sys(NR_fremovexattr, 999, "") == -EBADF, "fremovexattr: bad fd before empty name");

    // Attributes belong to the inode: they follow rename and link, and die with it.
    set("/tmp/x/f", "user.k", "keep", 0);
    check(sys(NR_renameat, AT_FDCWD, "/tmp/x/f", AT_FDCWD, "/tmp/x/g") == 0 && get("/tmp/x/g", "user.k") == 4 && is("keep"), "survives rename");
    check(sys(NR_linkat, AT_FDCWD, "/tmp/x/g", AT_FDCWD, "/tmp/x/h", 0) == 0 && get("/tmp/x/h", "user.k") == 4, "visible through a hard link");
    sys(NR_unlinkat, AT_FDCWD, "/tmp/x/g", 0);
    check(get("/tmp/x/h", "user.k") == 4, "survives unlinking the other name");
    sys(NR_close, fd);
    sys(NR_unlinkat, AT_FDCWD, "/tmp/x/h", 0);
    fd = creat_("/tmp/x/h");
    check(fd >= 0 && get("/tmp/x/h", "user.k") == -ENODATA && is(""), "a new inode starts without them");
    check(get("/tmp/x/h", "security.selinux") > 0 && is(custom), "...but with its directory's label");

    puts_(failures ? "SOME CHECKS FAILED\n" : "all checks passed\n");
    return failures;
}

void __attribute__((noreturn)) cstart(void) {
    sys(NR_exit_group, cmain());
    __builtin_unreachable();
}

#if defined(__aarch64__)
__asm__(".global _start\n_start:\n bl cstart\n");
#elif defined(__x86_64__)
__asm__(".global _start\n_start:\n call cstart\n");
#endif

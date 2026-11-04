// Freestanding arm64 test of droidrt's SELinux interface (no libc, no image):
// selinuxfs before and after a policy load (the CIL is written to the tmpfs
// root first), its transaction files, booleans and status page,
// /proc/<pid>/attr, and SO_PEERSEC. Exits with the failure count.

typedef unsigned long u64;
typedef long i64;
typedef unsigned int u32;

#define NR_mkdirat 34
#define NR_statfs 43
#define NR_openat 56
#define NR_close 57
#define NR_read 63
#define NR_write 64
#define NR_exit_group 94
#define NR_getpid 172
#define NR_socket 198
#define NR_socketpair 199
#define NR_bind 200
#define NR_listen 201
#define NR_accept 202
#define NR_connect 203
#define NR_getsockopt 209
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

#define AT_FDCWD -100
#define O_RDONLY 0
#define O_WRONLY 1
#define O_RDWR 2
#define O_CREAT 0100
#define EACCES 13
#define EINVAL 22
#define ERANGE 34
#define ENOENT 2
#define ENOPROTOOPT 92

static int open_(const char *path, int flags) { return (int)sys(NR_openat, AT_FDCWD, path, flags, 0644); }

// Reads a whole (small) file; returns its length or -errno.
static i64 cat(const char *path, char *buf, u64 cap) {
    int fd = open_(path, O_RDONLY);
    if (fd < 0) return fd;
    i64 n = sys(NR_read, fd, buf, cap);
    sys(NR_close, fd);
    return n;
}

// Writes `s` (with `extra` trailing bytes, e.g. 1 for its NUL) to `path`.
static i64 put(const char *path, const char *s, u64 extra) {
    int fd = open_(path, O_WRONLY);
    if (fd < 0) return fd;
    i64 n = sys(NR_write, fd, s, slen(s) + extra);
    sys(NR_close, fd);
    return n;
}

// A selinuxfs transaction: write the request, read the answer on the same fd.
static i64 transact(const char *file, const char *req, char *out, u64 cap) {
    int fd = open_(file, O_RDWR);
    if (fd < 0) return fd;
    i64 n = sys(NR_write, fd, req, slen(req));
    if (n >= 0) n = sys(NR_read, fd, out, cap);
    sys(NR_close, fd);
    return n;
}

static int is(const char *buf, i64 n, const char *want, u64 want_len) { return n == (i64)want_len && seq(buf, want, want_len); }

// A policy as Android ships it, much shortened: classes (kernel order from
// classorder, permissions from the common first), a domain attribute, a type
// transition from an attribute, a boolean and an initial SID.
static const char policy[] =
    "(common file (ioctl read write create getattr))\n"
    "(class security (compute_av compute_create))\n"
    "(class process (fork transition))\n"
    "(class file (execute_no_trans entrypoint))\n"
    "(classcommon file file)\n"
    "(class unix_stream_socket (connectto))\n"
    "(classorder (security process file unix_stream_socket))\n"
    "(boolean ro_bool true)\n"
    "(sid kernel)\n(sidcontext kernel (u r kernel ((s0) (s0))))\n(sidorder (kernel))\n"
    "(policycap open_perms)\n"
    "(role object_r)\n(role r)\n(user u)\n(userrole u r)\n(userrole u object_r)\n"
    "(type kernel)\n(type init)\n(type shell)\n(type logd)\n(type logd_exec)\n(type system_file)\n"
    "(typeattribute domain)\n(typeattributeset domain (kernel init shell logd))\n"
    "(typeattribute init_202504)\n(typeattributeset init_202504 (init))\n(roletype r domain)\n"
    "(allow domain system_file (file (read)))\n"
    "(typetransition init_202504 logd_exec process logd)\n";

int cmain(void) {
    char buf[256];
    i64 n;

    // ---- before any policy ----
    u64 st[15];
    check(sys(NR_statfs, "/sys/fs/selinux", st) == 0 && (u32)st[0] == 0xf97cff8cu, "selinuxfs: statfs says SELINUX_MAGIC");
    n = cat("/sys/fs/selinux/enforce", buf, sizeof buf);
    check(is(buf, n, "0", 1), "enforce reads 0 (permissive)");
    n = cat("/sys/fs/selinux/mls", buf, sizeof buf);
    check(is(buf, n, "1", 1), "mls reads 1");
    check(cat("/sys/fs/selinux/class/process/index", buf, sizeof buf) == -ENOENT, "no policy: no classes");
    n = cat("/proc/self/attr/current", buf, sizeof buf);
    check(is(buf, n, "u:r:shell:s0", 13), "attr/current: u:r:shell:s0, NUL-terminated");

    // ---- load the policy: CIL on the tmpfs root, then a write to load ----
    sys(NR_mkdirat, AT_FDCWD, "/system", 0755);
    sys(NR_mkdirat, AT_FDCWD, "/system/etc", 0755);
    sys(NR_mkdirat, AT_FDCWD, "/system/etc/selinux", 0755);
    int pf = open_("/system/etc/selinux/plat_sepolicy.cil", O_WRONLY | O_CREAT);
    sys(NR_write, pf, policy, sizeof policy - 1);
    sys(NR_close, pf);
    int sfd = open_("/sys/fs/selinux/status", O_RDONLY);
    volatile u32 *status = (volatile u32 *)sys(NR_mmap, 0, 4096, 1 /* PROT_READ */, 1 /* MAP_SHARED */, sfd, 0);
    u32 seq0 = status[1];
    check(status[0] == 1 && status[3] == 0 && (seq0 & 1) == 0, "status page: version 1, no policy load yet");
    check(put("/sys/fs/selinux/load", "\x8c\xff\x7c\xf9" "binary policy", 0) == 17, "load accepts a binary policy");
    check(status[3] == 1 && status[1] != seq0 && (status[1] & 1) == 0, "status page: policyload counted, sequence even");

    // ---- classes and permissions ----
    n = cat("/sys/fs/selinux/class/process/index", buf, sizeof buf);
    check(is(buf, n, "2", 1), "class/process/index is 2");
    n = cat("/sys/fs/selinux/class/unix_stream_socket/index", buf, sizeof buf);
    check(is(buf, n, "4", 1), "class index follows classorder");
    n = cat("/sys/fs/selinux/class/file/perms/execute_no_trans", buf, sizeof buf);
    check(is(buf, n, "6", 1), "perm value: own permissions after the common's (bit 5 + 1)");
    n = cat("/sys/fs/selinux/class/file/perms/ioctl", buf, sizeof buf);
    check(is(buf, n, "1", 1), "perm value: the common's first is 1");
    n = cat("/sys/fs/selinux/initial_contexts/kernel", buf, sizeof buf);
    check(is(buf, n, "u:r:kernel:s0", 14), "initial_contexts/kernel");
    n = cat("/sys/fs/selinux/policy_capabilities/open_perms", buf, sizeof buf);
    check(is(buf, n, "1", 1), "policy_capabilities/open_perms");

    // ---- transactions ----
    n = transact("/sys/fs/selinux/create", "u:r:init:s0 u:object_r:logd_exec:s0 2", buf, sizeof buf);
    check(is(buf, n, "u:r:logd:s0", 12), "create: init executing logd_exec enters logd");
    n = transact("/sys/fs/selinux/create", "u:r:shell:s0 u:object_r:logd_exec:s0 2", buf, sizeof buf);
    check(is(buf, n, "u:r:shell:s0", 13), "create: no transition keeps the domain");
    n = transact("/sys/fs/selinux/create", "u:r:shell:s0 u:object_r:system_file:s0 3", buf, sizeof buf);
    check(is(buf, n, "u:object_r:system_file:s0", 26), "create: a file takes its parent's type");
    n = transact("/sys/fs/selinux/access", "u:r:shell:s0 u:object_r:system_file:s0 3 2", buf, sizeof buf);
    check(is(buf, n, "ffffffff ffffffff 0 ffffffff 1 0", 32), "access: everything allowed and decided");
    n = transact("/sys/fs/selinux/context", "u:r:logd:s0-s0", buf, sizeof buf);
    check(is(buf, n, "u:r:logd:s0", 12), "context: canonical form");
    check(transact("/sys/fs/selinux/context", "u:r:nosuch:s0", buf, sizeof buf) == -EINVAL, "context: unknown type is EINVAL");
    check(transact("/sys/fs/selinux/context", "u:r:system_file:s0", buf, sizeof buf) == -EINVAL, "context: role r cannot hold a file type");
    n = transact("/sys/fs/selinux/user", "u:r:shell:s0 u", buf, sizeof buf);
    check(is(buf, n, "0", 2), "user: no contexts");

    // ---- booleans ----
    n = cat("/sys/fs/selinux/booleans/ro_bool", buf, sizeof buf);
    check(is(buf, n, "1 1", 3), "boolean: current and pending");
    put("/sys/fs/selinux/booleans/ro_bool", "0", 1);
    n = cat("/sys/fs/selinux/booleans/ro_bool", buf, sizeof buf);
    check(is(buf, n, "1 0", 3), "boolean write sets pending");
    put("/sys/fs/selinux/commit_pending_bools", "1", 1);
    n = cat("/sys/fs/selinux/booleans/ro_bool", buf, sizeof buf);
    check(is(buf, n, "0 0", 3), "commit_pending_bools commits");

    // ---- enforce, reported back and on the status page ----
    u32 seq1 = status[1];
    check(put("/sys/fs/selinux/enforce", "1", 0) == 1, "enforce: write 1");
    n = cat("/sys/fs/selinux/enforce", buf, sizeof buf);
    check(is(buf, n, "1", 1) && status[2] == 1 && status[1] == seq1 + 2, "enforce reads 1; status page updated");
    put("/sys/fs/selinux/enforce", "0", 0);

    // ---- /proc attributes ----
    check(put("/proc/thread-self/attr/fscreate", "u:object_r:system_file:s0", 1) == 26, "setfscreatecon (thread-self)");
    n = cat("/proc/self/task/1/attr/fscreate", buf, sizeof buf);
    check(is(buf, n, "u:object_r:system_file:s0", 26), "fscreate reads back per thread");
    put("/proc/thread-self/attr/fscreate", "", 0);
    check(cat("/proc/thread-self/attr/fscreate", buf, sizeof buf) == 0, "an empty write clears fscreate");
    check(put("/proc/self/attr/exec", "u:r:nosuch:s0", 1) == -EINVAL, "exec: invalid context refused");
    check(put("/proc/self/attr/prev", "u:r:logd:s0", 1) == -EINVAL, "prev is not writable");
    i64 pid = sys(NR_clone, 17 /* SIGCHLD */, 0, 0, 0, 0);
    if (pid == 0) {
        // Another process may not set our attributes.
        sys(NR_exit_group, put("/proc/1/attr/exec", "u:r:logd:s0", 1) == -EACCES ? 0 : 1);
    }
    int wst = -1;
    sys(NR_wait4, pid, &wst, 0, 0);
    check(wst == 0, "writing another process's attr is EACCES");

    // ---- SO_PEERSEC ----
    int sv[2];
    sys(NR_socketpair, 1, 1 /* SOCK_STREAM */, 0, sv);
    u32 len = sizeof buf;
    i64 r = sys(NR_getsockopt, sv[0], 1 /* SOL_SOCKET */, 31 /* SO_PEERSEC */, buf, &len);
    check(r == 0 && is(buf, len, "u:r:shell:s0", 13), "SO_PEERSEC: the peer's context");
    len = 4;
    r = sys(NR_getsockopt, sv[0], 1, 31, buf, &len);
    check(r == -ERANGE && len == 13, "SO_PEERSEC: ERANGE says the length needed");
    put("/proc/thread-self/attr/sockcreate", "u:r:logd:s0", 1);
    int sw[2];
    sys(NR_socketpair, 1, 1, 0, sw);
    put("/proc/thread-self/attr/sockcreate", "", 0);
    len = sizeof buf;
    r = sys(NR_getsockopt, sw[1], 1, 31, buf, &len);
    check(r == 0 && is(buf, len, "u:r:logd:s0", 12), "SO_PEERSEC: a sockcreate label");
    int dg[2];
    sys(NR_socketpair, 1, 2 /* SOCK_DGRAM */, 0, dg);
    len = sizeof buf;
    check(sys(NR_getsockopt, dg[0], 1, 31, buf, &len) == -ENOPROTOOPT, "SO_PEERSEC on a datagram socket: ENOPROTOOPT");
    // A named server (as init's property service): each end sees the other's label.
    struct { unsigned short family; char path[14]; } addr = { 1, "\0selinux-test" };
    int srv = (int)sys(NR_socket, 1, 1, 0);
    sys(NR_bind, srv, &addr, sizeof addr);
    sys(NR_listen, srv, 4);
    put("/proc/thread-self/attr/sockcreate", "u:r:logd:s0", 1);
    int cli = (int)sys(NR_socket, 1, 1, 0);
    i64 conn = sys(NR_connect, cli, &addr, sizeof addr);
    put("/proc/thread-self/attr/sockcreate", "", 0);
    int acc = (int)sys(NR_accept, srv, 0, 0);
    len = sizeof buf;
    r = sys(NR_getsockopt, acc, 1, 31, buf, &len);
    check(conn == 0 && r == 0 && is(buf, len, "u:r:logd:s0", 12), "SO_PEERSEC: a server sees its client's label");
    len = sizeof buf;
    r = sys(NR_getsockopt, cli, 1, 31, buf, &len);
    check(r == 0 && is(buf, len, "u:r:shell:s0", 13), "SO_PEERSEC: a client sees the server's label");
    // setsockcreatecon applies at socket(). init clears it before listen(); a client may clear it before connect().
    put("/proc/thread-self/attr/sockcreate", "u:r:logd:s0", 1);
    int srv2 = (int)sys(NR_socket, 1, 1, 0);
    put("/proc/thread-self/attr/sockcreate", "", 0);
    struct { unsigned short family; char path[14]; } addr2 = { 1, "\0selinux-sock" };
    sys(NR_bind, srv2, &addr2, sizeof addr2);
    sys(NR_listen, srv2, 1);
    int cli2 = (int)sys(NR_socket, 1, 1, 0);
    conn = sys(NR_connect, cli2, &addr2, sizeof addr2);
    len = sizeof buf;
    r = sys(NR_getsockopt, cli2, 1, 31, buf, &len);
    check(conn == 0 && r == 0 && is(buf, len, "u:r:logd:s0", 12), "SO_PEERSEC: server label is fixed at socket(), not listen()");
    put("/proc/thread-self/attr/sockcreate", "u:r:logd:s0", 1);
    int cli3 = (int)sys(NR_socket, 1, 1, 0);
    put("/proc/thread-self/attr/sockcreate", "", 0);
    conn = sys(NR_connect, cli3, &addr, sizeof addr);
    int acc3 = (int)sys(NR_accept, srv, 0, 0);
    len = sizeof buf;
    r = sys(NR_getsockopt, acc3, 1, 31, buf, &len);
    check(conn == 0 && r == 0 && is(buf, len, "u:r:logd:s0", 12), "SO_PEERSEC: client label is fixed at socket(), not connect()");

    // ---- setcon ----
    check(put("/proc/self/attr/current", "u:r:logd:s0", 1) == 12, "setcon: write current");
    n = cat("/proc/self/attr/current", buf, sizeof buf);
    check(is(buf, n, "u:r:logd:s0", 12), "current is the new context");
    n = cat("/proc/self/attr/prev", buf, sizeof buf);
    check(is(buf, n, "u:r:shell:s0", 13), "prev keeps the exec-time context");

    puts_(failures ? "SOME CHECKS FAILED\n" : "all checks passed\n");
    return failures;
}

void __attribute__((noreturn)) cstart(void) {
    sys(NR_exit_group, cmain());
    __builtin_unreachable();
}

__asm__(".global _start\n_start:\n bl cstart\n");

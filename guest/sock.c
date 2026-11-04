// Freestanding arm64 test of droidrt's socket namespace (no libc): AF_UNIX
// path bindings as filesystem nodes (bind/stat/connect/unlink/rebind, chmod,
// lchown, symlinks, hard links) and AF_NETLINK basics (port ids, dumps,
// acks, audit, uevent multicast). Exits with the failure count.

typedef unsigned long u64;
typedef long i64;
typedef unsigned int u32;
typedef unsigned short u16;

#define NR_epoll_create1 20
#define NR_epoll_ctl 21
#define NR_epoll_pwait 22
#define NR_mknodat 33
#define NR_mkdirat 34
#define NR_unlinkat 35
#define NR_symlinkat 36
#define NR_linkat 37
#define NR_renameat 38
#define NR_chdir 49
#define NR_fchmod 52
#define NR_fchmodat 53
#define NR_fchownat 54
#define NR_openat 56
#define NR_close 57
#define NR_read 63
#define NR_write 64
#define NR_ppoll 73
#define NR_newfstatat 79
#define NR_exit_group 94
#define NR_getpid 172
#define NR_socket 198
#define NR_socketpair 199
#define NR_bind 200
#define NR_listen 201
#define NR_accept 202
#define NR_connect 203
#define NR_getsockname 204
#define NR_getpeername 205
#define NR_sendto 206
#define NR_recvfrom 207
#define NR_setsockopt 208
#define NR_getsockopt 209
#define NR_sendmsg 211
#define NR_recvmsg 212
#define NR_accept4 242

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
static int seq(const void *a, const void *b, u64 n) { const char *x = a, *y = b; while (n--) if (*x++ != *y++) return 0; return 1; }
static void puts_(const char *s) { sys(NR_write, 1, s, slen(s)); }

static int failures;
static void check(int cond, const char *name) {
    puts_(cond ? "ok   " : "FAIL ");
    puts_(name);
    puts_("\n");
    if (!cond) failures++;
}

#define AT_FDCWD -100
#define AT_SYMLINK_NOFOLLOW 0x100
#define O_PATH 010000000
#define S_IFMT 0170000
#define S_IFSOCK 0140000
#define ENOENT 2
#define ENXIO 6
#define EAGAIN 11
#define ENOTDIR 20
#define EINVAL 22
#define EROFS 30
#define ENODEV 19
#define EPROTOTYPE 91
#define EPROTONOSUPPORT 93
#define ESOCKTNOSUPPORT 94
#define EADDRINUSE 98
#define EISCONN 106
#define ECONNREFUSED 111
#define SOCK_STREAM 1
#define SOCK_DGRAM 2
#define SOCK_RAW 3
#define SOCK_NONBLOCK 04000

struct stat { u64 dev, ino; u32 mode, nlink, uid, gid; u64 rdev, pad; i64 size; int blksize, pad2; i64 blocks, times[6]; u32 unused[2]; };
struct sockaddr_un { u16 family; char path[108]; };
struct sockaddr_nl { u16 family, pad; u32 pid, groups; };
struct nlmsghdr { u32 len; u16 type, flags; u32 seq, pid; };
struct iovec { void *base; u64 len; };
struct msghdr { void *name; u32 namelen; u32 pad; struct iovec *iov; u64 iovlen; void *control; u64 controllen; int flags; int pad2; };
struct epoll_event { u32 events; u32 pad; u64 data; };

static u64 un(struct sockaddr_un *a, const char *path) {
    memset(a, 0, sizeof *a);
    a->family = 1;
    memcpy(a->path, path, slen(path));
    return 2 + slen(path) + 1;
}
static int mode_of(const char *path, int flags) {
    struct stat st;
    if (sys(NR_newfstatat, AT_FDCWD, path, &st, flags) != 0) return -1;
    return (int)st.mode;
}
static i64 bind_path(int fd, const char *path) { struct sockaddr_un a; u64 n = un(&a, path); return sys(NR_bind, fd, &a, n); }
static i64 connect_path(int fd, const char *path) { struct sockaddr_un a; u64 n = un(&a, path); return sys(NR_connect, fd, &a, n); }
static int stream(void) { return (int)sys(NR_socket, 1, SOCK_STREAM, 0); }
// A listening stream socket at `path`.
static int server(const char *path) {
    int s = stream();
    if (bind_path(s, path) != 0 || sys(NR_listen, s, 8) != 0) return -1;
    return s;
}
// Connects to `path` and checks that `srv` accepts it and bytes flow.
static int reaches(int srv, const char *path) {
    int c = stream();
    if (connect_path(c, path) != 0) { sys(NR_close, c); return 0; }
    int conn = (int)sys(NR_accept4, srv, 0, 0, SOCK_NONBLOCK);
    char b[4] = { 0 };
    int ok = conn >= 0 && sys(NR_write, c, "abc", 3) == 3 && sys(NR_read, conn, b, 4) == 3 && seq(b, "abc", 3);
    sys(NR_close, c);
    if (conn >= 0) sys(NR_close, conn);
    return ok;
}

static void unix_paths(void) {
    sys(NR_mkdirat, AT_FDCWD, "/tmp/u", 0755);
    int srv = server("/tmp/u/s1");
    check(srv >= 0, "bind + listen on a path");
    check(mode_of("/tmp/u/s1", 0) == (S_IFSOCK | 0755), "the path is an S_IFSOCK node, mode 0777 & ~umask");
    int other = stream();
    check(bind_path(other, "/tmp/u/s1") == -EADDRINUSE, "binding an existing path: EADDRINUSE");
    check(bind_path(other, "/tmp/nodir/x") == -ENOENT, "binding under a missing directory: ENOENT");
    sys(NR_close, sys(NR_openat, AT_FDCWD, "/tmp/u/file", 0101 /* O_WRONLY|O_CREAT */, 0644));
    check(bind_path(other, "/tmp/u/file/x") == -ENOTDIR, "binding under a regular file: ENOTDIR");
    check(bind_path(other, "/proc/sock") == -EROFS, "binding on a read-only filesystem: EROFS");
    check(sys(NR_listen, other, 1) == -EINVAL, "listen on an unbound socket: EINVAL");
    sys(NR_symlinkat, "/tmp/u/gone", AT_FDCWD, "/tmp/u/dangling");
    check(bind_path(other, "/tmp/u/dangling") == -EADDRINUSE, "binding over a dangling symlink: EADDRINUSE");

    check(reaches(srv, "/tmp/u/s1"), "connect by path reaches the listener");
    sys(NR_symlinkat, "/tmp/u/s1", AT_FDCWD, "/tmp/u/link");
    sys(NR_symlinkat, "/tmp/u", AT_FDCWD, "/tmp/dirlink");
    check(reaches(srv, "/tmp/u/link"), "connect through a symlink to the node");
    check(reaches(srv, "/tmp/dirlink/s1"), "connect through a symlinked directory");
    sys(NR_chdir, "/tmp/u");
    check(reaches(srv, "s1") && reaches(srv, "../u/./s1"), "relative paths resolve against the cwd");
    sys(NR_linkat, AT_FDCWD, "/tmp/u/s1", AT_FDCWD, "/tmp/u/hard", 0);
    sys(NR_renameat, AT_FDCWD, "/tmp/u/hard", AT_FDCWD, "/tmp/u/moved");
    check(reaches(srv, "/tmp/u/moved"), "a hard link, renamed, is the same socket");

    // Names reported back are the bound path.
    int c = stream();
    connect_path(c, "/tmp/u/link");
    struct sockaddr_un got;
    u32 glen = sizeof got;
    sys(NR_getpeername, c, &got, &glen);
    check(glen == 2 + 10 && seq(got.path, "/tmp/u/s1", 10), "getpeername: the listener's path");
    char con[32];
    u32 clen = 4;
    i64 small = sys(NR_getsockopt, c, 1, 31 /* SO_PEERSEC */, con, &clen);
    u32 need = clen;
    clen = sizeof con;
    check(small == -34 /* ERANGE */ && need == 13 && sys(NR_getsockopt, c, 1, 31, con, &clen) == 0 && clen == 13 && seq(con, "u:r:shell:s0", 13), "SO_PEERSEC (getpeercon): the peer's context");
    glen = sizeof got;
    int conn = (int)sys(NR_accept, srv, &got, &glen);
    check(conn >= 0 && glen == 2, "accept: an unbound client has no name");
    glen = sizeof got;
    sys(NR_getsockname, srv, &got, &glen);
    check(glen == 12 && seq(got.path, "/tmp/u/s1", 10), "getsockname: the bound path");
    int rel = stream();
    bind_path(rel, "rel");
    glen = sizeof got;
    sys(NR_getsockname, rel, &got, &glen);
    check(glen == 2 + 4 && seq(got.path, "rel", 4) && mode_of("/tmp/u/rel", 0) > 0, "a relative bind: node in the cwd, name as given");

    // Attributes, the way init's CreateSocket sets them.
    check(sys(NR_fchmodat, AT_FDCWD, "/tmp/u/s1", 0660) == 0 && mode_of("/tmp/u/s1", 0) == (S_IFSOCK | 0660), "chmod on the node");
    int pfd = (int)sys(NR_openat, AT_FDCWD, "/tmp/u/s1", O_PATH | 0400000 /* O_NOFOLLOW */);
    check(pfd >= 0 && sys(NR_fchmod, pfd, 0666) == 0 && mode_of("/tmp/u/s1", 0) == (S_IFSOCK | 0666), "fchmodat(AT_SYMLINK_NOFOLLOW) as bionic does it (O_PATH + fchmod)");
    sys(NR_close, pfd);
    struct stat st;
    sys(NR_fchownat, AT_FDCWD, "/tmp/u/s1", 1036, 1037, AT_SYMLINK_NOFOLLOW);
    sys(NR_newfstatat, AT_FDCWD, "/tmp/u/s1", &st, AT_SYMLINK_NOFOLLOW);
    check(st.uid == 1036 && st.gid == 1037, "lchown on the node");
    sys(NR_fchownat, AT_FDCWD, "/tmp/u/link", 7, 7, AT_SYMLINK_NOFOLLOW);
    sys(NR_newfstatat, AT_FDCWD, "/tmp/u/s1", &st, 0);
    check(st.uid == 1036, "lchown on a symlink leaves the socket alone");
    check(sys(NR_openat, AT_FDCWD, "/tmp/u/s1", 2) == -ENXIO, "open(2) on a socket node: ENXIO");

    // unlink: existing peers keep working, new connects fail.
    sys(NR_write, c, "late", 4);
    check(sys(NR_unlinkat, AT_FDCWD, "/tmp/u/s1", 0) == 0, "unlink the socket's path");
    char b[8];
    check(sys(NR_read, conn, b, 8) == 4 && seq(b, "late", 4), "an accepted connection survives the unlink");
    int c2 = stream();
    check(connect_path(c2, "/tmp/u/s1") == -ENOENT, "connect after unlink: ENOENT");
    check(connect_path(c2, "/tmp/u/link") == -ENOENT, "a symlink to the unlinked path dangles: ENOENT");
    check(reaches(srv, "/tmp/u/moved"), "the remaining hard link still reaches the socket");
    sys(NR_unlinkat, AT_FDCWD, "/tmp/u/moved", 0);
    check(connect_path(c2, "/tmp/u/moved") == -ENOENT, "with every link gone, unreachable");

    // Rebinding the path gives a new socket; the old one is not resurrected.
    int srv2 = server("/tmp/u/s1");
    check(srv2 >= 0 && reaches(srv2, "/tmp/u/s1"), "rebinding the unlinked path");
    struct { int fd; short events, revents; } lp = { srv, 1, 0 };
    u64 now[2] = { 0, 0 };
    check(sys(NR_ppoll, &lp, 1, now, 0, 8) == 0, "the old listener sees nothing");

    // Nodes with nothing listening.
    sys(NR_mknodat, AT_FDCWD, "/tmp/u/bare", S_IFSOCK | 0666, 0);
    check(connect_path(c2, "/tmp/u/bare") == -ECONNREFUSED, "a socket node no socket is bound to: ECONNREFUSED");
    int idle = stream();
    bind_path(idle, "/tmp/u/idle");
    check(connect_path(c2, "/tmp/u/idle") == -ECONNREFUSED, "bound but not listening: ECONNREFUSED");
    sys(NR_close, idle);
    check(connect_path(c2, "/tmp/u/idle") == -ECONNREFUSED && mode_of("/tmp/u/idle", 0) > 0, "closing leaves the node; connect: ECONNREFUSED");
    int again = stream();
    check(bind_path(again, "/tmp/u/idle") == -EADDRINUSE, "the stale node still blocks bind");
    sys(NR_unlinkat, AT_FDCWD, "/tmp/u/idle", 0);
    check(bind_path(again, "/tmp/u/idle") == 0 && sys(NR_listen, again, 1) == 0 && reaches(again, "/tmp/u/idle"), "unlink, then bind again");
    check(connect_path(c2, "/tmp/u/file") == -ECONNREFUSED, "connect to a regular file: ECONNREFUSED");

    // Datagrams by path.
    int d = (int)sys(NR_socket, 1, SOCK_DGRAM, 0), dc = (int)sys(NR_socket, 1, SOCK_DGRAM, 0);
    bind_path(d, "/tmp/u/dg");
    bind_path(dc, "/tmp/u/dgc");
    struct sockaddr_un to;
    u64 tlen = un(&to, "/tmp/u/dg");
    sys(NR_sendto, dc, "dgram", 5, 0, &to, tlen);
    struct sockaddr_un from;
    u32 flen = sizeof from;
    i64 n = sys(NR_recvfrom, d, b, 8, 0, &from, &flen);
    check(n == 5 && seq(b, "dgram", 5) && seq(from.path, "/tmp/u/dgc", 11), "sendto a path; recvfrom names the sender's path");
    check(connect_path(c2, "/tmp/u/dg") == -EPROTOTYPE, "stream connect to a datagram socket: EPROTOTYPE");
    connect_path(dc, "/tmp/u/dg");
    sys(NR_unlinkat, AT_FDCWD, "/tmp/u/dg", 0);
    check(sys(NR_write, dc, "still", 5) == 5 && sys(NR_read, d, b, 8) == 5, "a connected datagram socket outlives the unlink");
    check(sys(NR_sendto, dc, "x", 1, 0, &to, tlen) == -ENOENT, "sendto the unlinked path: ENOENT");
    sys(NR_close, d);
    check(sys(NR_write, dc, "x", 1) == -ECONNREFUSED && sys(NR_write, dc, "x", 1) == -107 /* ENOTCONN */, "the peer closed: ECONNREFUSED once, then unconnected");
    check(sys(NR_sendto, srv2, "x", 1, 0, &to, tlen) == -95 /* EOPNOTSUPP */ && sys(NR_sendto, c, "x", 1, 0, &to, tlen) == -EISCONN, "a stream socket refuses a destination");

    // Autobind: an empty address picks an abstract name.
    int ab = stream();
    struct sockaddr_un e = { 1 };
    sys(NR_bind, ab, &e, 2);
    glen = sizeof got;
    sys(NR_getsockname, ab, &got, &glen);
    check(glen == 8 && got.path[0] == 0, "autobind: a 5-hex-digit abstract name");

    // A rename onto one name of a hard-linked socket drops that link only.
    int hl = server("/tmp/u/hl");
    sys(NR_linkat, AT_FDCWD, "/tmp/u/hl", AT_FDCWD, "/tmp/u/hl2", 0);
    sys(NR_close, sys(NR_openat, AT_FDCWD, "/tmp/u/other", 0101, 0644));
    sys(NR_renameat, AT_FDCWD, "/tmp/u/other", AT_FDCWD, "/tmp/u/hl");
    check(reaches(hl, "/tmp/u/hl2"), "rename over one hard link leaves the other bound");

    // connect(2) on a datagram records the peer for SO_PEERCRED.
    int dg = (int)sys(NR_socket, 1, SOCK_DGRAM, 0);
    int me = (int)sys(NR_socket, 1, SOCK_DGRAM, 0);
    bind_path(dg, "/tmp/u/cred");
    connect_path(me, "/tmp/u/cred");
    struct { int pid; u32 uid, gid; } pc;
    u32 pcl = sizeof pc;
    check(sys(NR_getsockopt, me, 1, 17 /* SO_PEERCRED */, &pc, &pcl) == 0 && pc.pid == (int)sys(NR_getpid, 0), "datagram SO_PEERCRED: the peer's pid");
    sys(NR_sendto, me, "abcdefgh", 8, 0, 0, 0);
    char tiny[3];
    check(sys(NR_recvfrom, dg, tiny, 3, 0x20 /* MSG_TRUNC */, 0, 0) == 8 && seq(tiny, "abc", 3), "MSG_TRUNC: return value is the real datagram length");

    // A later cmsg length that wraps usize must be rejected, not panic.
    int bad = (int)sys(NR_socket, 1, SOCK_DGRAM, 0);
    char one[] = "x";
    struct iovec biov = { one, 1 };
    unsigned char bctl[40];
    memset(bctl, 0, sizeof bctl);
    bctl[0] = 16; // first header, skipped
    memset(bctl + 16, 0xff, 8); // second cmsg len wraps
    bctl[24] = 1; // SOL_SOCKET
    bctl[28] = 1; // SCM_RIGHTS
    struct msghdr bm = { 0, 0, 0, &biov, 1, bctl, sizeof bctl, 0, 0 };
    check(sys(NR_sendmsg, bad, &bm, 0) == -EINVAL, "SCM_RIGHTS length that wraps is EINVAL");
}

// ---- netlink ----

static int nl_socket(int type, int proto) { return (int)sys(NR_socket, 16, type, proto); }
static u32 nl_port(int fd) {
    struct sockaddr_nl a = { 0 };
    u32 len = sizeof a;
    sys(NR_getsockname, fd, &a, &len);
    return len == 12 && a.family == 16 ? a.pid : 0;
}
// Sends one netlink message (header + payload) to the kernel.
static i64 nl_send(int fd, u16 type, u16 flags, u32 sq, const void *payload, u32 plen) {
    union { char b[256]; struct nlmsghdr h; } m;
    memset(&m, 0, sizeof m);
    m.h.len = 16 + plen;
    m.h.type = type;
    m.h.flags = flags;
    m.h.seq = sq;
    memcpy(m.b + 16, payload, plen);
    struct sockaddr_nl k = { 16, 0, 0, 0 };
    return sys(NR_sendto, fd, &m, (16 + plen + 3) & ~3u, 0, &k, sizeof k);
}
static union { char b[512]; struct nlmsghdr h; } reply;
static struct sockaddr_nl reply_from;
static i64 nl_recv(int fd, int flags) {
    u32 len = sizeof reply_from;
    memset(&reply, 0, sizeof reply);
    return sys(NR_recvfrom, fd, &reply, sizeof reply, flags, &reply_from, &len);
}

static void netlink(void) {
    check(nl_socket(SOCK_RAW, 99) == -EPROTONOSUPPORT, "netlink: unknown protocol EPROTONOSUPPORT");
    check(nl_socket(SOCK_STREAM, 0) == -ESOCKTNOSUPPORT, "netlink: SOCK_STREAM ESOCKTNOSUPPORT");
    int r = nl_socket(SOCK_RAW, 0);
    struct sockaddr_nl a = { 16, 0, 0, 0 };
    check(r >= 0 && sys(NR_bind, r, &a, sizeof a) == 0 && nl_port(r) == (u32)sys(NR_getpid, 0), "NETLINK_ROUTE bind: port id is the pid");
    int r2 = nl_socket(SOCK_DGRAM, 0);
    sys(NR_bind, r2, &a, sizeof a);
    u32 p2 = nl_port(r2);
    check(p2 != 0 && p2 != nl_port(r), "a second socket gets another port id");
    int r3 = nl_socket(SOCK_RAW, 0);
    struct sockaddr_nl taken = { 16, 0, p2, 0 };
    check(sys(NR_bind, r3, &taken, sizeof taken) == -EADDRINUSE, "binding a taken port id: EADDRINUSE");
    check(nl_recv(r, 0x40 /* MSG_DONTWAIT */) == -EAGAIN, "nothing to receive: EAGAIN");
    struct { int fd; short events, revents; } pfd = { r, 1 | 4, 0 };
    u64 zero[2] = { 0, 0 };
    check(sys(NR_ppoll, &pfd, 1, zero, 0, 8) == 1 && pfd.revents == 4, "poll: writable, not readable");

    unsigned char ifinfo[16] = { 0 };
    // Only lo exists: a link dump is one RTM_NEWLINK, then NLMSG_DONE.
    nl_send(r, 18 /* RTM_GETLINK */, 1 | 0x300 /* REQUEST|DUMP */, 7, ifinfo, 16);
    i64 n = nl_recv(r, 0);
    check(n > 32 && reply.h.type == 16 && reply.h.flags == 2 /* MULTI */ && reply.h.seq == 7 && *(int *)(reply.b + 20) == 1 && seq(reply.b + 36, "lo", 3), "RTM_GETLINK dump: lo, index 1");
    n = nl_recv(r, 0);
    check(n == 20 && reply.h.type == 3 && reply.h.seq == 7 && reply.h.pid == nl_port(r) && *(int *)(reply.b + 16) == 0 && reply_from.pid == 0, "RTM_GETLINK dump ends with NLMSG_DONE");
    nl_send(r, 16 /* RTM_NEWLINK */, 1 | 4 /* ACK */, 8, ifinfo, 16);
    n = nl_recv(r, 0);
    check(n == 36 && reply.h.type == 2 && *(int *)(reply.b + 16) == 0 && reply.h.seq == 8 && reply.h.flags == 0x100, "NLM_F_ACK: NLMSG_ERROR 0 (capped)");
    *(int *)(ifinfo + 4) = 99;
    nl_send(r, 18, 1, 9, ifinfo, 16);
    n = nl_recv(r, 0);
    check(n == 52 && reply.h.type == 2 && *(int *)(reply.b + 16) == -ENODEV, "RTM_GETLINK for a missing link: ENODEV, request echoed");
    *(int *)(ifinfo + 4) = 1;
    nl_send(r, 18, 1, 9, ifinfo, 16);
    n = nl_recv(r, 0);
    check(n > 32 && reply.h.type == 16 && reply.h.flags == 0 && *(int *)(reply.b + 20) == 1, "RTM_GETLINK for lo: its RTM_NEWLINK");
    *(int *)(ifinfo + 4) = 0;
    // lo's two addresses, then NLMSG_DONE.
    nl_send(r, 22 /* RTM_GETADDR */, 1 | 0x300, 10, ifinfo, 8);
    u32 trunc_len = (u32)nl_recv(r, 0x2 | 0x20 /* MSG_PEEK|MSG_TRUNC */);
    n = nl_recv(r, 0);
    check(trunc_len == n && n > 24 && reply.h.type == 20 && reply.h.seq == 10 && reply.b[16] == 2, "MSG_PEEK|MSG_TRUNC sizes the next message: lo's IPv4 address");
    n = nl_recv(r, 0);
    check(n > 24 && reply.h.type == 20 && reply.b[16] == 10, "and its IPv6 address");
    n = nl_recv(r, 0);
    check(n == 20 && reply.h.type == 3 && reply.h.seq == 10, "RTM_GETADDR dump ends with NLMSG_DONE");

    // Unicast between processes' sockets.
    struct sockaddr_nl peer = { 16, 0, nl_port(r), 0 };
    sys(NR_sendto, r2, "hey", 3, 0, &peer, sizeof peer);
    n = nl_recv(r, 0);
    check(n == 3 && seq(reply.b, "hey", 3) && reply_from.pid == p2, "unicast to another socket's port id");

    // logd's audit registration.
    int au = nl_socket(SOCK_RAW, 9);
    u32 status[11] = { 4 /* AUDIT_STATUS_PID */, 0, 0, 1234 };
    nl_send(au, 1001 /* AUDIT_SET */, 1 | 4, 1, status, sizeof status);
    n = nl_recv(au, 0);
    check(n == 36 && reply.h.type == 2 && *(int *)(reply.b + 16) == 0, "AUDIT_SET is acked");
    nl_send(au, 1000 /* AUDIT_GET */, 1, 2, 0, 0);
    n = nl_recv(au, 0);
    check(n == 60 && reply.h.type == 1000 && ((u32 *)(reply.b + 16))[3] == 1234, "AUDIT_GET reports the registered pid");
    int se = nl_socket(SOCK_RAW, 7);
    check(nl_send(se, 16, 1, 1, 0, 0) == -ECONNREFUSED, "NETLINK_SELINUX takes no requests");

    // ueventd's socket: buffer sizes, credentials, all groups, then a uevent.
    int ue = nl_socket(SOCK_DGRAM | 02000000 /* CLOEXEC */, 15);
    int sz = 1 << 20, rb = 0, on = 1;
    u32 l = 4;
    sys(NR_setsockopt, ue, 1, 8 /* SO_RCVBUF */, &sz, 4);
    sys(NR_getsockopt, ue, 1, 8, &rb, &l);
    check(rb == 2 * 212992, "SO_RCVBUF: doubled, capped at rmem_max");
    sys(NR_setsockopt, ue, 1, 33 /* SO_RCVBUFFORCE */, &sz, 4);
    sys(NR_getsockopt, ue, 1, 8, &rb, &l);
    check(rb == 2 * sz, "SO_RCVBUFFORCE: past the cap");
    sys(NR_setsockopt, ue, 1, 16 /* SO_PASSCRED */, &on, 4);
    struct sockaddr_nl all = { 16, 0, 0, 0xffffffff };
    struct sockaddr_nl back = { 0 };
    u32 blen = sizeof back;
    check(sys(NR_bind, ue, &all, sizeof all) == 0 && sys(NR_getsockname, ue, &back, &blen) == 0 && back.groups == 0xffffffff, "uevent bind to every group");
    int ep = (int)sys(NR_epoll_create1, 0);
    struct epoll_event ev = { 1, 0, 55 }, out[2];
    sys(NR_epoll_ctl, ep, 1, ue, &ev);
    check(sys(NR_epoll_pwait, ep, out, 2, 20, 0, 8) == 0, "epoll: no uevents yet");
    int inj = nl_socket(SOCK_DGRAM, 15);
    const char event[] = "add@/devices/x\0ACTION=add\0DEVPATH=/devices/x";
    nl_send(inj, 16, 1, 1, event, sizeof event);
    check(sys(NR_epoll_pwait, ep, out, 2, 1000, 0, 8) == 1 && out[0].data == 55, "epoll wakes for a uevent");
    union { char b[64]; u64 align; } ctl;
    char buf[128];
    struct iovec iov = { buf, sizeof buf };
    struct sockaddr_nl src;
    struct msghdr m = { &src, sizeof src, 0, &iov, 1, ctl.b, sizeof ctl.b, 0, 0 };
    n = sys(NR_recvmsg, ue, &m, 0);
    u32 *cred = (u32 *)(ctl.b + 16);
    check(n == (i64)sizeof event + 9 && seq(buf, event, sizeof event) && seq(buf + sizeof event, "SEQNUM=1", 9), "the uevent arrives with a SEQNUM");
    check(src.pid == 0 && src.groups == 1 && m.controllen >= 28 && *(int *)(ctl.b + 12) == 2 && cred[1] == 0, "from the kernel, group 1, root credentials");
    int g = 5;
    u32 mem[2] = { 0 }, mlen = sizeof mem;
    sys(NR_setsockopt, r, 270 /* SOL_NETLINK */, 1 /* ADD_MEMBERSHIP */, &g, 4);
    sys(NR_getsockopt, r, 270, 9 /* LIST_MEMBERSHIPS */, mem, &mlen);
    check(mem[0] == 1u << 4 && mlen == 8, "NETLINK_ADD_MEMBERSHIP / LIST_MEMBERSHIPS");
}

// SOL_SOCKET options read back as set; timeouts end blocking calls.
// Zygote aborts without the 16-byte SO_RCVTIMEO read-back.
static void sockopts(void) {
    int sv[2];
    check(sys(NR_socketpair, 1 /* AF_UNIX */, 1 /* SOCK_STREAM */, 0, sv) == 0, "socketpair for options");
    long tv[2] = {7, 7};
    int len = 16;
    check(sys(NR_getsockopt, sv[0], 1, 20 /* SO_RCVTIMEO */, tv, &len) == 0 && len == 16 && tv[0] == 0 && tv[1] == 0, "SO_RCVTIMEO reads as 16 bytes of zero");
    tv[0] = 0, tv[1] = 50000;
    check(sys(NR_setsockopt, sv[0], 1, 20, tv, 16) == 0, "set a 50 ms receive timeout");
    tv[0] = tv[1] = 7;
    check(sys(NR_getsockopt, sv[0], 1, 20, tv, &len) == 0 && tv[0] == 0 && tv[1] == 50000, "and read it back");
    check(sys(NR_setsockopt, sv[0], 1, 20, tv, 4) == -22, "a short timeval: EINVAL");
    long bad[2] = {0, 1000000};
    check(sys(NR_setsockopt, sv[0], 1, 20, bad, 16) == -33, "microseconds out of range: EDOM");
    char c;
    check(sys(NR_read, sv[0], &c, 1) == -11, "an empty socket's read times out: EAGAIN");
    sys(NR_write, sv[1], "x", 1);
    check(sys(NR_read, sv[0], &c, 1) == 1 && c == 'x', "queued data still comes first");
    long linger[2] = {7, 7};
    len = 8;
    check(sys(NR_getsockopt, sv[0], 1, 13 /* SO_LINGER */, linger, &len) == 0 && len == 8 && (int)linger[0] == 0, "SO_LINGER reads as 8 bytes");
    int v = 7;
    len = 4;
    check(sys(NR_getsockopt, sv[0], 1, 18 /* SO_RCVLOWAT */, &v, &len) == 0 && v == 1, "SO_RCVLOWAT defaults to 1");
    v = 1;
    sys(NR_setsockopt, sv[0], 1, 2 /* SO_REUSEADDR */, &v, 4);
    v = 0;
    check(sys(NR_getsockopt, sv[0], 1, 2, &v, &len) == 0 && v == 1, "SO_REUSEADDR reads back");
    sys(NR_close, sv[0]);
    sys(NR_close, sv[1]);
}

int cmain(void) {
    unix_paths();
    netlink();
    sockopts();
    puts_(failures ? "SOME CHECKS FAILED\n" : "all checks passed\n");
    return failures;
}

void __attribute__((noreturn)) cstart(void) {
    sys(NR_exit_group, cmain());
    __builtin_unreachable();
}

__asm__(".global _start\n_start:\n bl cstart\n");

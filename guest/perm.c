// Freestanding arm64 test of file permissions (no libc): what a process that has
// dropped from root to an app's uid may and may not do to files it doesn't own,
// and what root's capabilities still let through. Each check is what Linux does
// (fs/namei.c, fs/attr.c, fs/open.c, mm/mmap.c, net/unix/af_unix.c). Runs as root
// on droidrt's tmpfs; the restricted checks run in a child that drops to uid 10001.
typedef unsigned long u64;
typedef long i64;
typedef unsigned int u32;
typedef unsigned short u16;

#define NR_setxattr 5
#define NR_ioctl 29
#define NR_mknodat 33
#define NR_mkdirat 34
#define NR_unlinkat 35
#define NR_linkat 37
#define NR_renameat 38
#define NR_mount 40
#define NR_truncate 45
#define NR_chdir 49
#define NR_fchdir 50
#define NR_fchmodat 53
#define NR_fchownat 54
#define NR_openat 56
#define NR_close 57
#define NR_read 63
#define NR_write 64
#define NR_newfstatat 79
#define NR_utimensat 88
#define NR_exit_group 94
#define NR_nanosleep 101
#define NR_kill 129
#define NR_setresuid 147
#define NR_setresgid 149
#define NR_setgroups 159
#define NR_umask 166
#define NR_socket 198
#define NR_bind 200
#define NR_listen 201
#define NR_connect 203
#define NR_munmap 215
#define NR_clone 220
#define NR_execve 221
#define NR_mmap 222
#define NR_mprotect 226
#define NR_wait4 260

#define O_RDONLY 0
#define O_WRONLY 1
#define O_RDWR 2
#define O_CREAT 0100
#define O_TRUNC 01000
#define O_DIRECTORY 040000
#define O_PATH 010000000
#define AT_FDCWD -100
#define AT_REMOVEDIR 0x200
#define PROT_READ 1
#define PROT_WRITE 2
#define PROT_EXEC 4
#define MAP_SHARED 1
#define MAP_PRIVATE 2
#define MS_NOEXEC 8
#define EPERM 1
#define ENOENT 2
#define ENOEXEC 8
#define EACCES 13
#define ASHMEM_SET_SIZE 0x40087703
#define ASHMEM_SET_PROT_MASK 0x40087705
#define DM_VERSION_IOCTL 0xc138fd00

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
static u64 slen(const char *s) { u64 n = 0; while (s[n]) n++; return n; }
static void puts_(const char *s) { sys(NR_write, 1, s, slen(s)); }
static int failures;
static void check(int cond, const char *name) {
    puts_(cond ? "ok   " : "FAIL ");
    puts_(name);
    puts_("\n");
    if (!cond) failures++;
}

static i64 open_(const char *p, i64 flags) { return sys(NR_openat, AT_FDCWD, p, flags | 02000000, 0); }
static i64 make(const char *p, u32 mode) {
    i64 fd = sys(NR_openat, AT_FDCWD, p, O_CREAT | O_RDWR | 02000000, mode);
    if (fd < 0) return fd;
    sys(NR_write, fd, "hello", 5);
    sys(NR_close, fd);
    return sys(NR_fchmodat, AT_FDCWD, p, mode); // past the umask
}
static i64 mkdir_(const char *p, u32 mode) {
    i64 r = sys(NR_mkdirat, AT_FDCWD, p, mode);
    return r < 0 ? r : sys(NR_fchmodat, AT_FDCWD, p, mode);
}
struct stat { u64 dev, ino; u32 mode, nlink, uid, gid; u64 rdev, pad; i64 size; int blksize, pad2; i64 blocks, at[2], mt[2], ct[2]; u32 unused[2]; };
static u32 mode_of(const char *p) { struct stat st; memset(&st, 0, sizeof st); sys(NR_newfstatat, AT_FDCWD, p, &st, 0x100); return st.mode & 07777; }
static u32 uid_of(const char *p) { struct stat st; memset(&st, 0, sizeof st); st.uid = 12345; sys(NR_newfstatat, AT_FDCWD, p, &st, 0x100); return st.uid; }
static int ok_fd(i64 fd) { if (fd < 0) return 0; sys(NR_close, fd); return 1; }

struct sockaddr_un { u16 family; char path[108]; };
static u64 un(struct sockaddr_un *a, const char *path) {
    memset(a, 0, sizeof *a);
    a->family = 1;
    u64 n = slen(path);
    for (u64 i = 0; i < n; i++) a->path[i] = path[i];
    return 2 + n + 1;
}
static i64 bind_path(int fd, const char *path) { struct sockaddr_un a; u64 n = un(&a, path); return sys(NR_bind, fd, &a, n); }
static i64 connect_path(int fd, const char *path) { struct sockaddr_un a; u64 n = un(&a, path); return sys(NR_connect, fd, &a, n); }
static i64 sock_(void) { return sys(NR_socket, 1, 1 | 02000000, 0); }

static i64 fork_(void) { return sys(NR_clone, 17 /* SIGCHLD */, 0, 0, 0, 0); }
static void nap_ms(i64 ms) { i64 ts[2] = {ms / 1000, (ms % 1000) * 1000000}; sys(NR_nanosleep, ts, 0); }
static i64 reap(i64 pid, i64 ms) {
    int st = 0;
    for (i64 t = 0; t < ms; t += 20) {
        if (sys(NR_wait4, pid, &st, 1 /* WNOHANG */, 0) == pid) return st;
        nap_ms(20);
    }
    sys(NR_kill, pid, 9);
    sys(NR_wait4, pid, &st, 0, 0);
    return -1;
}
static i64 exec_(const char *p) {
    const char *argv[] = {p, 0};
    const char *envp[] = {0};
    return sys(NR_execve, p, argv, envp);
}

static int dm_fd;

// Everything here runs as uid/gid 10001 with no capabilities and no extra groups.
static void as_app(void) {
    // --- open: read and write by mode, search on every directory walked
    check(open_("/tmp/p/secret", O_RDONLY) == -EACCES, "app: read of root's 0600 file is EACCES");
    check(open_("/tmp/p/secret", O_RDWR) == -EACCES, "app: read-write of root's 0600 file is EACCES");
    check(open_("/tmp/p/secret", O_WRONLY) == -EACCES, "app: write of root's 0600 file is EACCES");
    check(ok_fd(open_("/tmp/p/secret", O_PATH)), "app: O_PATH needs no permission on the file itself");
    check(ok_fd(open_("/tmp/p/pub", O_RDONLY)), "app: reads root's 0644 file");
    check(open_("/tmp/p/pub", O_WRONLY) == -EACCES, "app: can't write root's 0644 file");
    check(open_("/tmp/p/pub", O_RDONLY | O_TRUNC) == -EACCES, "app: O_TRUNC needs write permission");
    check(open_("/tmp/p/priv/inner", O_RDONLY) == -EACCES, "app: no search permission on a 0700 directory: open is EACCES");
    struct stat st;
    check(sys(NR_newfstatat, AT_FDCWD, "/tmp/p/priv/inner", &st, 0) == -EACCES, "app: ... and stat is EACCES");
    check(open_("/tmp/p/priv", O_RDONLY | O_DIRECTORY) == -EACCES, "app: can't list a 0700 directory");
    check(sys(NR_chdir, "/tmp/p/priv") == -EACCES, "app: chdir needs search permission");
    i64 pd = open_("/tmp/p/priv", O_PATH | O_DIRECTORY);
    check(pd >= 0 && sys(NR_fchdir, pd) == -EACCES, "app: fchdir needs search permission");
    check(ok_fd(open_("/tmp/p/sticky/roots", O_RDWR)), "app: opens a 0666 file read-write");

    // --- creating and removing need write and search on the directory
    check(open_("/tmp/p/new", O_CREAT | O_RDWR) == -EACCES, "app: can't create in root's 0755 directory");
    check(sys(NR_mkdirat, AT_FDCWD, "/tmp/p/newdir", 0755) == -EACCES, "app: can't mkdir there");
    check(sys(NR_unlinkat, AT_FDCWD, "/tmp/p/secret", 0) == -EACCES, "app: can't unlink from it");
    check(sys(NR_renameat, AT_FDCWD, "/tmp/p/pub", AT_FDCWD, "/tmp/p/sticky/pub") == -EACCES, "app: can't rename out of it");
    check(sys(NR_mknodat, AT_FDCWD, "/tmp/p/sticky/null", 020666, 0x103) == -EPERM, "app: mknod of a device needs CAP_MKNOD");
    check(make("/tmp/p/sticky/mine", 0600) == 0, "app: creates a file in a sticky world-writable directory");
    check(uid_of("/tmp/p/sticky/mine") == 10001, "app: ... which it owns");
    i64 fd = open_("/tmp/p/sticky/mine", O_RDWR);
    char buf[8];
    check(fd >= 0 && sys(NR_read, fd, buf, 5) == 5, "app: reads its own 0600 file");
    sys(NR_close, fd);

    // --- fs.protected_hardlinks: no hard link to a file it couldn't read and write
    check(sys(NR_linkat, AT_FDCWD, "/tmp/p/secret", AT_FDCWD, "/tmp/p/sticky/hl", 0) == -EPERM, "app: can't hard-link root's 0600 file");
    check(sys(NR_linkat, AT_FDCWD, "/tmp/p/sticky/mine", AT_FDCWD, "/tmp/p/sticky/mine2", 0) == 0, "app: hard-links its own file");
    check(sys(NR_renameat, AT_FDCWD, "/tmp/p/sticky/mine2", AT_FDCWD, "/tmp/p/sticky/mine2") == 0, "app: renaming a name onto itself asks nothing");

    // --- the sticky bit: only the file's or the directory's owner removes it
    check(sys(NR_unlinkat, AT_FDCWD, "/tmp/p/sticky/roots", 0) == -EPERM, "app: can't unlink root's file from a sticky directory");
    check(sys(NR_renameat, AT_FDCWD, "/tmp/p/sticky/roots", AT_FDCWD, "/tmp/p/sticky/moved") == -EPERM, "app: can't rename it either");
    check(sys(NR_renameat, AT_FDCWD, "/tmp/p/sticky/mine", AT_FDCWD, "/tmp/p/sticky/roots") == -EPERM, "app: nor rename over it");

    // --- moving a directory to another parent writes its "..": needs write on it
    check(sys(NR_renameat, AT_FDCWD, "/tmp/p/ww/rootdir", AT_FDCWD, "/tmp/p/ww/appdir/rootdir") == -EACCES, "app: can't move root's directory to another parent");
    check(sys(NR_renameat, AT_FDCWD, "/tmp/p/ww/rootdir", AT_FDCWD, "/tmp/p/ww/rootdir2") == 0, "app: renames it within the same writable directory");

    // --- attributes
    check(sys(NR_fchmodat, AT_FDCWD, "/tmp/p/pub", 0666) == -EPERM, "app: chmod of root's file is EPERM");
    check(sys(NR_fchownat, AT_FDCWD, "/tmp/p/pub", 10001, 10001, 0) == -EPERM, "app: chown of root's file is EPERM");
    check(sys(NR_fchownat, AT_FDCWD, "/tmp/p/sticky/mine", 0, -1, 0) == -EPERM, "app: can't give its own file away");
    check(sys(NR_fchownat, AT_FDCWD, "/tmp/p/sticky/mine", -1, 0, 0) == -EPERM, "app: can't chgrp to a group it isn't in");
    check(sys(NR_fchownat, AT_FDCWD, "/tmp/p/sticky/mine", 10001, 10001, 0) == 0, "app: chown of its own file to itself is allowed");
    check(sys(NR_fchmodat, AT_FDCWD, "/tmp/p/sticky/mine", 0640) == 0 && mode_of("/tmp/p/sticky/mine") == 0640, "app: chmods its own file");
    check(make("/tmp/p/sgid/f", 0644) == 0 && sys(NR_fchmodat, AT_FDCWD, "/tmp/p/sgid/f", 02755) == 0 && mode_of("/tmp/p/sgid/f") == 0755,
          "app: chmod drops set-gid when it isn't in the file's group");
    check(sys(NR_utimensat, AT_FDCWD, "/tmp/p/pub", 0, 0) == -EACCES, "app: touching a file it can't write is EACCES");
    i64 times[4] = {1, 0, 2, 0};
    check(sys(NR_utimensat, AT_FDCWD, "/tmp/p/sticky/roots", times, 0) == -EPERM, "app: explicit times need ownership");
    check(sys(NR_utimensat, AT_FDCWD, "/tmp/p/sticky/roots", 0, 0) == 0, "app: touching a file it can write is allowed");
    check(sys(NR_truncate, "/tmp/p/pub", 0) == -EACCES, "app: truncate needs write permission");
    check(sys(NR_setxattr, "/tmp/p/sticky/mine", "trusted.x", "v", 1, 0) == -EPERM, "app: trusted.* needs CAP_SYS_ADMIN");
    check(sys(NR_setxattr, "/tmp/p/pub", "security.selinux", "u:object_r:x:s0", 16, 0) == -EPERM, "app: relabelling root's file is EPERM");

    // --- execve needs an x bit for its caller
    check(exec_("/tmp/p/rootonly") == -EACCES, "app: execve of root's 0700 file is EACCES");
    check(exec_("/tmp/p/plain") == -EACCES, "app: execve of a 0644 file is EACCES");
    check(exec_("/tmp/p/junk") == -ENOEXEC, "app: execve of a 0755 file gets as far as reading it");

    // --- unix sockets: connect needs write on the node, bind write on the directory
    i64 s = sock_();
    check(connect_path((int)s, "/tmp/p/sock600") == -EACCES, "app: connect to root's 0600 socket is EACCES");
    sys(NR_close, s);
    s = sock_();
    check(connect_path((int)s, "/tmp/p/sock666") == 0, "app: connect to a 0666 socket works");
    sys(NR_close, s);
    s = sock_();
    check(bind_path((int)s, "/tmp/p/mysock") == -EACCES, "app: bind in root's 0755 directory is EACCES");
    check(bind_path((int)s, "/tmp/p/sticky/mysock") == 0 && uid_of("/tmp/p/sticky/mysock") == 10001, "app: a socket it binds belongs to it");
    sys(NR_close, s);

    // --- devices: the node's mode, and device-mapper wants CAP_SYS_ADMIN
    check(open_("/dev/device-mapper", O_RDWR) == -EACCES, "app: /dev/device-mapper is root's alone");
    static char dm[312];
    memset(dm, 0, sizeof dm);
    ((u32 *)dm)[0] = 4;
    ((u32 *)dm)[3] = sizeof dm;
    check(sys(NR_ioctl, dm_fd, DM_VERSION_IOCTL, dm) == -EACCES, "app: a device-mapper ioctl on an inherited descriptor is EACCES");
}

static int cmain(void) {
    sys(NR_umask, 0);
    // A fresh tree: root's files and directories, as an app would find them.
    check(mkdir_("/tmp/p", 0755) == 0, "root: /tmp/p");
    check(make("/tmp/p/secret", 0600) == 0 && make("/tmp/p/pub", 0644) == 0, "root: a private and a public file");
    check(mkdir_("/tmp/p/priv", 0700) == 0 && make("/tmp/p/priv/inner", 0644) == 0, "root: a private directory");
    check(mkdir_("/tmp/p/sticky", 01777) == 0 && make("/tmp/p/sticky/roots", 0666) == 0, "root: a sticky directory");
    check(mkdir_("/tmp/p/ww", 0777) == 0 && mkdir_("/tmp/p/ww/rootdir", 0755) == 0 && mkdir_("/tmp/p/ww/appdir", 0777) == 0, "root: a world-writable directory");
    check(sys(NR_fchownat, AT_FDCWD, "/tmp/p/ww/appdir", 10001, 10001, 0) == 0, "root: ... with a directory of the app's");
    check(mkdir_("/tmp/p/sgid", 02777) == 0 && sys(NR_fchownat, AT_FDCWD, "/tmp/p/sgid", 0, 777, 0) == 0, "root: a set-gid directory of group 777");
    check(make("/tmp/p/rootonly", 0700) == 0 && make("/tmp/p/plain", 0644) == 0 && make("/tmp/p/junk", 0755) == 0, "root: files to execute");
    i64 l1 = sock_(), l2 = sock_();
    check(bind_path((int)l1, "/tmp/p/sock600") == 0 && sys(NR_fchmodat, AT_FDCWD, "/tmp/p/sock600", 0600) == 0 && sys(NR_listen, l1, 4) == 0, "root: a 0600 socket");
    check(bind_path((int)l2, "/tmp/p/sock666") == 0 && sys(NR_fchmodat, AT_FDCWD, "/tmp/p/sock666", 0666) == 0 && sys(NR_listen, l2, 4) == 0, "root: a 0666 socket");
    dm_fd = (int)open_("/dev/device-mapper", O_RDWR);
    check(dm_fd >= 0, "root: opens /dev/device-mapper");

    i64 pid = fork_();
    if (pid == 0) {
        int fail = sys(NR_setgroups, 0, 0) || sys(NR_setresgid, 10001, 10001, 10001) || sys(NR_setresuid, 10001, 10001, 10001);
        if (!fail) as_app();
        sys(NR_exit_group, fail ? 100 : failures);
    }
    check(reap(pid, 20000) == 0, "the app's checks all passed");

    // --- root: CAP_DAC_OVERRIDE and CAP_DAC_READ_SEARCH still let it through
    check(make("/tmp/p/none", 0) == 0 && ok_fd(open_("/tmp/p/none", O_RDWR)), "root: opens a 0000 file read-write");
    check(mkdir_("/tmp/p/closed", 0) == 0 && make("/tmp/p/closed/f", 0) == 0 && ok_fd(open_("/tmp/p/closed/f", O_RDONLY)), "root: walks into a 0000 directory");
    check(exec_("/tmp/p/plain") == -EACCES, "root: execve of a file with no x bit is EACCES even so");
    check(exec_("/tmp/p/rootonly") == -ENOEXEC, "root: execve of its 0700 file gets as far as reading it");
    check(mkdir_("/tmp/p/nx", 0755) == 0 && sys(NR_mount, "none", "/tmp/p/nx", "tmpfs", MS_NOEXEC, 0) == 0 && make("/tmp/p/nx/junk", 0755) == 0,
          "root: a noexec tmpfs");
    check(exec_("/tmp/p/nx/junk") == -EACCES, "root: execve from a noexec mount is EACCES");
    i64 nfd = open_("/tmp/p/nx/junk", O_RDONLY);
    check(sys(NR_mmap, 0, 4096, PROT_READ | PROT_EXEC, MAP_PRIVATE, nfd, 0) == -EPERM, "root: PROT_EXEC mapping from a noexec mount is EPERM");
    u64 m = (u64)sys(NR_mmap, 0, 4096, PROT_READ, MAP_PRIVATE, nfd, 0);
    check(m < (u64)-4096 && sys(NR_mprotect, m, 4096, PROT_READ | PROT_EXEC) == -EACCES, "root: ... and mprotect can't add it later");
    sys(NR_close, nfd);
    check(make("/tmp/p/suid", 04755) == 0 && sys(NR_fchownat, AT_FDCWD, "/tmp/p/suid", 0, 0, 0) == 0 && mode_of("/tmp/p/suid") == 0755, "root: chown clears set-uid, for root too");

    // --- mmap follows what the descriptor was opened for
    i64 ro = open_("/tmp/p/pub", O_RDONLY);
    check(sys(NR_mmap, 0, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, ro, 0) == -EACCES, "MAP_SHARED|PROT_WRITE of an O_RDONLY descriptor is EACCES");
    m = (u64)sys(NR_mmap, 0, 4096, PROT_READ, MAP_SHARED, ro, 0);
    check(m < (u64)-4096, "MAP_SHARED|PROT_READ of it works");
    check(sys(NR_mprotect, m, 4096, PROT_READ | PROT_WRITE) == -EACCES, "mprotect can't make that shared mapping writable");
    u64 p = (u64)sys(NR_mmap, 0, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE, ro, 0);
    check(p < (u64)-4096, "a private writable mapping of it works");
    if (p < (u64)-4096) *(volatile char *)p = 'X';
    char buf[8] = {0};
    i64 again = open_("/tmp/p/pub", O_RDONLY);
    check(sys(NR_read, again, buf, 5) == 5 && buf[0] == 'h', "... and writes to it stay private");
    sys(NR_close, again);
    sys(NR_close, ro);
    i64 wo = open_("/tmp/p/pub", O_WRONLY);
    check(sys(NR_mmap, 0, 4096, PROT_READ, MAP_SHARED, wo, 0) == -EACCES, "any mapping of an O_WRONLY descriptor is EACCES");
    sys(NR_close, wo);

    // --- ashmem's protection mask holds at mprotect, as it does at mmap
    i64 a = open_("/dev/ashmem", O_RDWR);
    check(a >= 0 && sys(NR_ioctl, a, ASHMEM_SET_SIZE, 4096) == 0, "ashmem region");
    m = (u64)sys(NR_mmap, 0, 4096, PROT_READ, MAP_SHARED, a, 0);
    check(m < (u64)-4096 && sys(NR_ioctl, a, ASHMEM_SET_PROT_MASK, PROT_READ) == 0, "mapped read-only, then the mask drops write");
    check(sys(NR_mmap, 0, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, a, 0) == -EPERM, "a writable mapping past the mask is EPERM");
    u64 m2 = (u64)sys(NR_mmap, 0, 4096, PROT_READ, MAP_SHARED, a, 0);
    check(m2 < (u64)-4096 && sys(NR_mprotect, m2, 4096, PROT_READ | PROT_WRITE) == -EACCES, "mprotect past the mask is EACCES");

    puts_(failures ? "SOME CHECKS FAILED\n" : "all checks passed\n");
    return failures;
}

void cstart(void) { sys(NR_exit_group, cmain()); }
__asm__(".global _start\n_start:\n bl cstart\n");

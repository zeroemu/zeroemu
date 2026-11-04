// Freestanding arm64 test of droidrt's credentials and process control (no
// libc): uids/gids and groups, capabilities and securebits, prctl, seccomp,
// rlimits, scheduling and I/O priorities, process groups and sessions,
// reparenting to pid 1 and to a subreaper, parent-death signals, waitid,
// SIGCHLD auto-reaping, personality, hostnames, process_vm_readv/writev,
// and reboot. Runs as pid 1; ends with reboot(POWER_OFF) if every check
// passed, else exits with the failure count.

typedef unsigned long u64;
typedef long i64;
typedef unsigned int u32;
typedef unsigned short u16;

#define NR_ioprio_set 30
#define NR_ioprio_get 31
#define NR_fcntl 25
#define NR_dup3 24
#define NR_openat 56
#define NR_close 57
#define NR_pipe2 59
#define NR_read 63
#define NR_write 64
#define NR_capget 90
#define NR_capset 91
#define NR_personality 92
#define NR_exit_group 94
#define NR_waitid 95
#define NR_ppoll 73
#define NR_signalfd4 74
#define NR_nanosleep 101
#define NR_rt_sigprocmask 135
#define NR_sched_setparam 118
#define NR_sched_setscheduler 119
#define NR_sched_getscheduler 120
#define NR_sched_getparam 121
#define NR_sched_get_priority_max 125
#define NR_sched_get_priority_min 126
#define NR_sched_rr_get_interval 127
#define NR_kill 129
#define NR_rt_sigaction 134
#define NR_setpriority 140
#define NR_getpriority 141
#define NR_reboot 142
#define NR_setregid 143
#define NR_setgid 144
#define NR_setreuid 145
#define NR_setuid 146
#define NR_setresuid 147
#define NR_getresuid 148
#define NR_setresgid 149
#define NR_getresgid 150
#define NR_setfsuid 151
#define NR_setpgid 154
#define NR_getpgid 155
#define NR_getsid 156
#define NR_setsid 157
#define NR_getgroups 158
#define NR_setgroups 159
#define NR_uname 160
#define NR_sethostname 161
#define NR_setdomainname 162
#define NR_getrlimit 163
#define NR_setrlimit 164
#define NR_prctl 167
#define NR_getpid 172
#define NR_getppid 173
#define NR_getuid 174
#define NR_geteuid 175
#define NR_getgid 176
#define NR_getegid 177
#define NR_gettid 178
#define NR_clone 220
#define NR_wait4 260
#define NR_prlimit64 261
#define NR_process_vm_readv 270
#define NR_process_vm_writev 271
#define NR_sched_setattr 274
#define NR_sched_getattr 275
#define NR_seccomp 277

#define EPERM 1
#define ESRCH 3
#define EBADF 9
#define ECHILD 10
#define EMFILE 24
#define EFAULT 14
#define EACCES 13
#define EINVAL 22
#define E2BIG 7
#define EOPNOTSUPP 95

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
static int seq(const char *a, const char *b, u64 n) { while (n--) if (*a++ != *b++) return 0; return 1; }
static int has(const char *hay, const char *needle) {
    u64 n = slen(needle);
    for (; *hay; hay++) if (seq(hay, needle, n)) return 1;
    return 0;
}
static void puts_(const char *s) { sys(NR_write, 1, s, slen(s)); }

static int failures;
static void check(int cond, const char *name) {
    puts_(cond ? "ok   " : "FAIL ");
    puts_(name);
    puts_("\n");
    if (!cond) failures++;
}

static i64 fork_(void) { return sys(NR_clone, 17 /* SIGCHLD */, 0, 0, 0, 0); }
static int pid_self(void) { return (int)sys(NR_getpid); }
static int wait_status(i64 pid) { int st = -1; sys(NR_wait4, pid, &st, 0, 0); return st; }
/// Children run their own checks and exit with their failure count.
static void child_passed(i64 pid) { if (wait_status(pid) != 0) failures++; }
static void __attribute__((noreturn)) exit_(int code) { sys(NR_exit_group, code); __builtin_unreachable(); }
static void sleep_ms(u64 ms) { u64 ts[2] = { ms / 1000, (ms % 1000) * 1000000 }; sys(NR_nanosleep, ts, 0); }
static i64 prctl(i64 op, i64 a, i64 b, i64 c, i64 d) { return sys(NR_prctl, op, a, b, c, d); }

static char buf[4096];
static int readfile(const char *path) {
    int fd = (int)sys(NR_openat, -100, path, 0, 0);
    if (fd < 0) return fd;
    int n = 0;
    i64 r;
    while (n < (int)sizeof buf - 1 && (r = sys(NR_read, fd, buf + n, sizeof buf - 1 - n)) > 0) n += (int)r;
    sys(NR_close, fd);
    buf[n] = 0;
    return n;
}

struct caphdr { u32 version; int pid; };
struct capdata { u32 eff, prm, inh; };
#define CAP_V1 0x19980330
#define CAP_V3 0x20080522
static int capget_(struct capdata d[2]) {
    struct caphdr h = { CAP_V3, 0 };
    memset(d, 0, 2 * sizeof *d);
    return (int)sys(NR_capget, &h, d);
}
static int capset_(u64 eff, u64 prm, u64 inh) {
    struct caphdr h = { CAP_V3, 0 };
    struct capdata d[2] = { { (u32)eff, (u32)prm, (u32)inh }, { (u32)(eff >> 32), (u32)(prm >> 32), (u32)(inh >> 32) } };
    return (int)sys(NR_capset, &h, d);
}

#define PR_SET_PDEATHSIG 1
#define PR_GET_PDEATHSIG 2
#define PR_GET_DUMPABLE 3
#define PR_SET_DUMPABLE 4
#define PR_GET_KEEPCAPS 7
#define PR_SET_KEEPCAPS 8
#define PR_SET_NAME 15
#define PR_GET_NAME 16
#define PR_GET_SECCOMP 21
#define PR_CAPBSET_READ 23
#define PR_CAPBSET_DROP 24
#define PR_GET_SECUREBITS 27
#define PR_SET_SECUREBITS 28
#define PR_SET_TIMERSLACK 29
#define PR_GET_TIMERSLACK 30
#define PR_SET_MM 35
#define PR_SET_CHILD_SUBREAPER 36
#define PR_GET_CHILD_SUBREAPER 37
#define PR_SET_NO_NEW_PRIVS 38
#define PR_GET_NO_NEW_PRIVS 39
#define PR_CAP_AMBIENT 47
#define PR_GET_SPECULATION_CTRL 52
#define PR_SET_SPECULATION_CTRL 53
#define PR_SET_TAGGED_ADDR_CTRL 55
#define PR_GET_TAGGED_ADDR_CTRL 56
#define PR_SET_VMA 0x53564d41

#define MAGIC1 0xfee1dead
#define MAGIC2 0x28121969

struct sigaction_ { u64 handler, flags, restorer, mask; };
static void set_sigchld(u64 handler, u64 flags) {
    struct sigaction_ a = { handler, flags, 0, 0 };
    sys(NR_rt_sigaction, 17, &a, 0, 8);
}

struct siginfo_ { int signo, errno_, code, pad; int pid; u32 uid; int status; char rest[100]; };
struct iovec { void *base; u64 len; };

static char vm_buf[16] = "before";

static void ids_and_groups(void) {
    check(sys(NR_getuid) == 0 && sys(NR_geteuid) == 0 && sys(NR_getgid) == 0 && sys(NR_getegid) == 0, "starts as root");
    u32 r = 9, e = 9, s = 9;
    check(sys(NR_getresuid, &r, &e, &s) == 0 && r == 0 && e == 0 && s == 0, "getresuid");
    u32 gs[3] = { 30, 10, 20 }, got[8];
    check(sys(NR_setgroups, 3, gs) == 0, "setgroups");
    check(sys(NR_getgroups, 0, 0) == 3 && sys(NR_getgroups, 8, got) == 3 && got[0] == 10 && got[1] == 20 && got[2] == 30, "getgroups returns them sorted");
    check(sys(NR_getgroups, 1, got) == -EINVAL, "getgroups into a short list: EINVAL");
    readfile("/proc/self/status");
    check(has(buf, "Groups:\t10 20 30\n") && has(buf, "Uid:\t0\t0\t0\t0\n"), "/proc/self/status Uid and Groups");
    check(sys(NR_setgroups, 0, 0) == 0 && sys(NR_getgroups, 0, 0) == 0, "setgroups(0) clears them");

    // setreuid/setresuid juggling, then dropping privileges for good
    i64 pid = fork_();
    if (pid == 0) {
        failures = 0;
        check(sys(NR_setreuid, 1000, 2000) == 0 && sys(NR_getresuid, &r, &e, &s) == 0 && r == 1000 && e == 2000 && s == 2000, "setreuid sets the saved uid");
        check(sys(NR_setreuid, -1, 1000) == 0 && sys(NR_getresuid, &r, &e, &s) == 0 && e == 1000 && s == 2000, "setreuid back to the real uid keeps the saved one");
        check(sys(NR_setreuid, -1, 2000) == 0 && sys(NR_geteuid) == 2000, "unprivileged setreuid to the saved uid");
        check(sys(NR_setresuid, 3000, -1, -1) == -EPERM, "setresuid to a foreign uid: EPERM");
        check(sys(NR_setregid, 50, 60) == -EPERM && sys(NR_setgid, 50) == -EPERM, "no CAP_SETGID once uids left root");
        exit_(failures);
    }
    child_passed(pid);

    pid = fork_();
    if (pid == 0) {
        failures = 0;
        struct capdata d[2];
        check(sys(NR_setresgid, 1000, 1000, 1000) == 0 && sys(NR_setresuid, 1000, 1000, 1000) == 0, "setresgid + setresuid to 1000");
        check(sys(NR_getuid) == 1000 && sys(NR_geteuid) == 1000 && sys(NR_getgid) == 1000 && sys(NR_getegid) == 1000, "ids read back");
        check(capget_(d) == 0 && (d[0].eff | d[0].prm | d[1].eff | d[1].prm) == 0, "leaving uid 0 clears permitted and effective");
        check(sys(NR_setuid, 0) == -EPERM && sys(NR_setgroups, 0, 0) == -EPERM, "setuid(0)/setgroups: EPERM");
        check(sys(NR_setresuid, -1, 1000, -1) == 0, "a no-op setresuid succeeds");
        check(capset_(1, 1, 0) == -EPERM, "capset cannot add permitted caps");
        readfile("/proc/self/status");
        check(has(buf, "Uid:\t1000\t1000\t1000\t1000\n") && has(buf, "Gid:\t1000\t1000\t1000\t1000\n") && has(buf, "CapEff:\t0000000000000000\n"), "/proc/self/status after the drop");
        check(sys(NR_kill, 1, 0) == -EPERM && sys(NR_kill, sys(NR_getpid), 0) == 0, "kill another uid's process: EPERM");
        check(sys(NR_reboot, MAGIC1, MAGIC2, 0x4321fedc, 0) == -EPERM, "reboot without CAP_SYS_BOOT: EPERM");
        check(sys(NR_sethostname, "x", 1) == -EPERM, "sethostname without CAP_SYS_ADMIN: EPERM");
        u64 rl[2] = { 64, 8192 };
        check(sys(NR_setrlimit, 7, rl) == -EPERM, "raising a hard limit: EPERM");
        rl[1] = 2048;
        check(sys(NR_setrlimit, 7, rl) == 0, "lowering it is fine");
        rl[1] = 4096;
        check(sys(NR_setrlimit, 7, rl) == -EPERM, "and it cannot go back up");
        check(sys(NR_setpriority, 0, 0, 5) == 0 && sys(NR_setpriority, 0, 0, 2) == -EACCES && sys(NR_getpriority, 0, 0) == 15, "unprivileged nice only goes up");
        int prio = 10;
        check(sys(NR_sched_setscheduler, 0, 1, &prio) == -EPERM, "SCHED_FIFO without CAP_SYS_NICE: EPERM");
        u64 filter = 0x7fff000000000006ul; // BPF_RET|BPF_K, SECCOMP_RET_ALLOW
        struct { u16 len; u16 pad[3]; void *filter; } prog = { 1, { 0 }, &filter };
        check(sys(NR_seccomp, 1, 0, &prog) == -EACCES, "seccomp filter without no_new_privs: EACCES");
        check(sys(NR_process_vm_readv, 1, 0, 0, 0, 0, 0) == -EPERM, "process_vm_readv of another uid: EPERM");
        exit_(failures);
    }
    child_passed(pid);

    pid = fork_();
    if (pid == 0) {
        failures = 0;
        check(sys(NR_setfsuid, 1234) == 0 && sys(NR_setfsuid, -1) == 1234, "setfsuid returns the old fsuid");
        readfile("/proc/self/status");
        check(has(buf, "Uid:\t0\t0\t0\t1234\n") && has(buf, "CapEff:\t000001fef7fffde0\n"), "a non-root fsuid drops the filesystem caps");
        sys(NR_setfsuid, 0);
        readfile("/proc/self/status");
        check(has(buf, "CapEff:\t000001ffffffffff\n"), "fsuid 0 restores them");
        exit_(failures);
    }
    child_passed(pid);
}

static void capabilities(void) {
    struct capdata d[2];
    check(capget_(d) == 0 && d[0].eff == 0xffffffff && d[1].eff == 0x1ff && d[0].prm == 0xffffffff && d[1].prm == 0x1ff && d[0].inh == 0, "capget v3: all 41 capabilities");
    struct caphdr h = { 0x12345678, 0 };
    check(sys(NR_capget, &h, d) == -EINVAL && h.version == CAP_V3, "capget with a bad version: EINVAL and the preferred version");
    h.version = 0;
    check(sys(NR_capget, &h, 0) == 0 && h.version == CAP_V3, "libcap's version probe");
    h.version = CAP_V1;
    d[1].eff = 0xdead;
    check(sys(NR_capget, &h, d) == 0 && d[0].eff == 0xffffffff && d[1].eff == 0xdead, "capget v1 fills one word");
    h.pid = 99999;
    h.version = CAP_V3;
    check(sys(NR_capget, &h, d) == -ESRCH, "capget of a missing pid: ESRCH");
    check(prctl(PR_CAPBSET_READ, 40, 0, 0, 0) == 1 && prctl(PR_CAPBSET_READ, 41, 0, 0, 0) == -EINVAL, "CAP_LAST_CAP is 40");
    check(prctl(PR_CAP_AMBIENT, 1, 0, 0, 0) == 0 && prctl(PR_GET_SECUREBITS, 0, 0, 0, 0) == 0, "ambient set and securebits start empty");
    readfile("/proc/self/status");
    check(has(buf, "CapEff:\t000001ffffffffff\n") && has(buf, "CapBnd:\t000001ffffffffff\n") && has(buf, "CapAmb:\t0000000000000000\n"), "/proc/self/status capability lines");

    // keepcaps across a uid change, then ambient capabilities
    i64 pid = fork_();
    if (pid == 0) {
        failures = 0;
        check(prctl(PR_SET_KEEPCAPS, 1, 0, 0, 0) == 0 && prctl(PR_GET_KEEPCAPS, 0, 0, 0, 0) == 1 && prctl(PR_SET_KEEPCAPS, 2, 0, 0, 0) == -EINVAL, "PR_SET_KEEPCAPS");
        check(sys(NR_setresuid, 1000, 1000, 1000) == 0 && capget_(d) == 0 && d[0].prm == 0xffffffff && d[0].eff == 0, "keepcaps: permitted survives the uid change, effective does not");
        u64 nbs = 1ul << 10; // CAP_NET_BIND_SERVICE
        check(capset_(nbs, nbs, nbs) == 0 && capget_(d) == 0 && d[0].eff == nbs && d[0].prm == nbs && d[0].inh == nbs, "capset narrows the sets");
        check(prctl(PR_CAP_AMBIENT, 2, 10, 0, 0) == 0 && prctl(PR_CAP_AMBIENT, 1, 10, 0, 0) == 1, "PR_CAP_AMBIENT_RAISE");
        check(prctl(PR_CAP_AMBIENT, 2, 11, 0, 0) == -EPERM, "raising a cap not permitted+inheritable: EPERM");
        readfile("/proc/self/status");
        check(has(buf, "CapAmb:\t0000000000000400\n"), "/proc/self/status CapAmb");
        check(capset_(nbs, nbs, 0) == 0 && prctl(PR_CAP_AMBIENT, 1, 10, 0, 0) == 0, "dropping the inheritable bit drops the ambient one");
        check(prctl(PR_CAP_AMBIENT, 4, 0, 0, 0) == 0 && prctl(PR_CAP_AMBIENT, 9, 10, 0, 0) == -EINVAL, "CLEAR_ALL; unknown ambient op: EINVAL");
        check(prctl(PR_SET_SECUREBITS, 0x10, 0, 0, 0) == -EPERM, "securebits need CAP_SETPCAP");
        exit_(failures);
    }
    child_passed(pid);

    pid = fork_();
    if (pid == 0) {
        failures = 0;
        check(prctl(PR_SET_SECUREBITS, 0x30, 0, 0, 0) == 0 && prctl(PR_GET_SECUREBITS, 0, 0, 0, 0) == 0x30, "PR_SET_SECUREBITS KEEP_CAPS|KEEP_CAPS_LOCKED");
        check(prctl(PR_GET_KEEPCAPS, 0, 0, 0, 0) == 1 && prctl(PR_SET_KEEPCAPS, 0, 0, 0, 0) == -EPERM, "a locked keepcaps cannot change");
        check(prctl(PR_SET_SECUREBITS, 0, 0, 0, 0) == -EPERM && prctl(PR_SET_SECUREBITS, 0x130, 0, 0, 0) == -EPERM, "locks stay; unknown bits refused");
        check(prctl(PR_CAPBSET_DROP, 22, 0, 0, 0) == 0 && prctl(PR_CAPBSET_READ, 22, 0, 0, 0) == 0, "PR_CAPBSET_DROP");
        readfile("/proc/self/status");
        check(has(buf, "CapBnd:\t000001ffffbfffff\n"), "/proc/self/status CapBnd after the drop");
        check(capset_(0, 0x1fffffffffful, 1ul << 22) == -EPERM, "inheritable beyond the bounding set: EPERM");
        exit_(failures);
    }
    child_passed(pid);
}

static void limits(void) {
    u64 rl[2];
    check(sys(NR_getrlimit, 3, rl) == 0 && rl[0] == 8ul << 20 && rl[1] == ~0ul, "RLIMIT_STACK is the 8 MiB stack");
    check(sys(NR_prlimit64, 0, 7, 0, rl) == 0 && rl[0] == 1024 && rl[1] == 4096, "RLIMIT_NOFILE starts at 1024/4096");
    u64 bad[2] = { 100, 50 };
    check(sys(NR_setrlimit, 7, bad) == -EINVAL && sys(NR_getrlimit, 16, rl) == -EINVAL, "cur > max and bad resources: EINVAL");
    u64 big[2] = { 1024, 8192 };
    check(sys(NR_setrlimit, 7, big) == 0, "root raises a hard limit");

    i64 pid = fork_();
    if (pid == 0) {
        failures = 0;
        u64 small[2] = { 16, 32 };
        check(sys(NR_setrlimit, 7, small) == 0, "setrlimit NOFILE 16");
        int n = 0, last = 0;
        for (;;) {
            i64 fd = sys(NR_fcntl, 0, 0 /* F_DUPFD */, 0);
            if (fd < 0) { last = (int)fd; break; }
            n++;
        }
        check(last == -EMFILE && n == 13, "fd allocation stops at the limit (EMFILE)");
        check(sys(NR_dup3, 0, 16, 0) == -EBADF && sys(NR_close, 15) == 0 && sys(NR_dup3, 0, 15, 0) == 15, "dup3 beyond the limit: EBADF");
        exit_(failures);
    }
    child_passed(pid);

    // prlimit64 on another process
    int p[2];
    sys(NR_pipe2, p, 0);
    pid = fork_();
    if (pid == 0) {
        char c;
        sys(NR_read, p[0], &c, 1);
        sys(NR_getrlimit, 4, rl);
        exit_(rl[0] == 1ul << 20 ? 0 : 1);
    }
    u64 core[2] = { 1ul << 20, ~0ul }, old[2];
    check(sys(NR_prlimit64, pid, 4, core, old) == 0 && old[0] == 0 && old[1] == ~0ul, "prlimit64 sets another process's RLIMIT_CORE");
    sys(NR_write, p[1], "x", 1);
    check(wait_status(pid) == 0, "which it then sees");
    check(sys(NR_prlimit64, 99999, 4, 0, old) == -ESRCH, "prlimit64 of a missing pid: ESRCH");
    sys(NR_close, p[0]);
    sys(NR_close, p[1]);
}

struct sched_attr { u32 size, policy; u64 flags; int nice; u32 prio; u64 runtime, deadline, period; u32 umin, umax; };

static void scheduling(void) {
    check(sys(NR_setpriority, 0, 0, 5) == 0 && sys(NR_getpriority, 0, 0) == 15, "setpriority; getpriority returns 20 - nice");
    check(sys(NR_setpriority, 0, 0, -30) == 0 && sys(NR_getpriority, 0, 0) == 40, "nice clamps at -20");
    check(sys(NR_setpriority, 1, 0, 3) == 0 && sys(NR_getpriority, 0, sys(NR_gettid)) == 17, "PRIO_PGRP reaches the caller");
    check(sys(NR_setpriority, 2, 0, 0) == 0 && sys(NR_getpriority, 2, 0) == 20, "PRIO_USER");
    check(sys(NR_setpriority, 5, 0, 0) == -EINVAL && sys(NR_setpriority, 0, 99999, 0) == -ESRCH, "bad which: EINVAL; missing pid: ESRCH");
    readfile("/proc/self/stat");
    sys(NR_setpriority, 0, 0, 4);
    readfile("/proc/self/stat");
    check(has(buf, " 24 4 1 0 "), "/proc/self/stat priority and nice");
    sys(NR_setpriority, 0, 0, 0);

    int prio = 10, out = 0;
    check(sys(NR_sched_setscheduler, 0, 1 /* FIFO */, &prio) == 0 && sys(NR_sched_getscheduler, 0) == 1 && sys(NR_sched_getparam, 0, &out) == 0 && out == 10, "SCHED_FIFO 10 reads back");
    prio = 20;
    check(sys(NR_sched_setparam, 0, &prio) == 0 && sys(NR_sched_getparam, 0, &out) == 0 && out == 20 && sys(NR_sched_getscheduler, 0) == 1, "sched_setparam keeps the policy");
    prio = 5;
    check(sys(NR_sched_setscheduler, 0, 0, &prio) == -EINVAL && sys(NR_sched_setscheduler, 0, 1, 0) == -EINVAL, "SCHED_OTHER with a priority, or no param: EINVAL");
    prio = 100;
    check(sys(NR_sched_setscheduler, 0, 2, &prio) == -EINVAL && sys(NR_sched_setscheduler, 0, 4, &prio) == -EINVAL, "priority 100 / policy 4: EINVAL");
    check(sys(NR_sched_get_priority_max, 1) == 99 && sys(NR_sched_get_priority_min, 2) == 1 && sys(NR_sched_get_priority_max, 0) == 0 && sys(NR_sched_get_priority_max, 42) == -EINVAL, "sched_get_priority_max/min");
    prio = 1;
    u64 ts[2] = { 9, 9 };
    check(sys(NR_sched_setscheduler, 0, 2, &prio) == 0 && sys(NR_sched_rr_get_interval, 0, ts) == 0 && ts[0] == 0 && ts[1] == 100000000, "SCHED_RR timeslice is 100 ms");

    struct sched_attr a = { 56, 0, 0, 7, 0, 0, 0, 0, 0, 0 }, b;
    memset(&b, 0xff, sizeof b);
    check(sys(NR_sched_setattr, 0, &a, 0) == 0 && sys(NR_sched_getattr, 0, &b, sizeof b, 0) == 0 && b.size == 56 && b.policy == 0 && b.nice == 7 && b.umax == 1024, "sched_setattr/getattr round trip");
    check(sys(NR_getpriority, 0, 0) == 13, "sched_setattr's nice is setpriority's");
    a.size = 47;
    check(sys(NR_sched_setattr, 0, &a, 0) == -E2BIG && a.size == 56, "short sched_attr: E2BIG with the kernel's size");
    a.size = 56;
    a.flags = 0x20 | 0x40;
    a.umin = 100;
    a.umax = 50;
    check(sys(NR_sched_setattr, 0, &a, 0) == -EINVAL, "util_min > util_max: EINVAL");
    a.umax = 900;
    check(sys(NR_sched_setattr, 0, &a, 0) == 0 && sys(NR_sched_getattr, 0, &b, sizeof b, 0) == 0 && b.umin == 100 && b.umax == 900, "utilization clamps read back");

    prio = 30;
    check(sys(NR_sched_setscheduler, 0, 1 | 0x40000000, &prio) == 0 && sys(NR_sched_getscheduler, 0) == 0x40000001, "SCHED_RESET_ON_FORK is reported");
    i64 pid = fork_();
    if (pid == 0) exit_(sys(NR_sched_getscheduler, 0) == 0 && sys(NR_getpriority, 0, 0) == 20 ? 0 : 1);
    check(wait_status(pid) == 0, "a reset-on-fork child starts as SCHED_OTHER, nice 0");
    prio = 0;
    sys(NR_sched_setscheduler, 0, 0, &prio);
    sys(NR_setpriority, 0, 0, 0);

    int be3 = 2 << 13 | 3;
    check(sys(NR_ioprio_set, 1, 0, be3) == 0 && sys(NR_ioprio_get, 1, 0) == be3, "ioprio_set/get best-effort 3");
    check(sys(NR_ioprio_set, 1, 0, 5 << 13) == -EINVAL && sys(NR_ioprio_set, 1, 0, 1) == -EINVAL && sys(NR_ioprio_set, 4, 0, be3) == -EINVAL, "bad I/O priorities: EINVAL");
    pid = fork_();
    if (pid == 0) exit_(sys(NR_ioprio_get, 1, 0) == be3 ? 0 : 1);
    check(wait_status(pid) == 0, "I/O priority is inherited");
}

static void prctls(void) {
    char name[16];
    check(prctl(PR_SET_NAME, (i64) "creds-test", 0, 0, 0) == 0 && prctl(PR_GET_NAME, (i64)name, 0, 0, 0) == 0 && seq(name, "creds-test", 11), "PR_SET_NAME/PR_GET_NAME");
    readfile("/proc/self/comm");
    check(seq(buf, "creds-test\n", 12), "/proc/self/comm shows it");
    char path[64] = "/proc/self/task/1/comm";
    readfile(path);
    check(seq(buf, "creds-test\n", 12), "/proc/self/task/<tid>/comm too");
    prctl(PR_SET_NAME, (i64) "0123456789abcdefXYZ", 0, 0, 0);
    prctl(PR_GET_NAME, (i64)name, 0, 0, 0);
    check(seq(name, "0123456789abcde", 16), "names truncate to 15 bytes");
    check(prctl(PR_GET_DUMPABLE, 0, 0, 0, 0) == 1 && prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) == 0 && prctl(PR_GET_DUMPABLE, 0, 0, 0, 0) == 0, "PR_SET_DUMPABLE");
    check(prctl(PR_SET_DUMPABLE, 2, 0, 0, 0) == -EINVAL && prctl(PR_SET_DUMPABLE, 1, 0, 0, 0) == 0, "dumpable 2: EINVAL");
    int sig = 0;
    check(prctl(PR_SET_PDEATHSIG, 65, 0, 0, 0) == -EINVAL && prctl(PR_SET_PDEATHSIG, 10, 0, 0, 0) == 0 && prctl(PR_GET_PDEATHSIG, (i64)&sig, 0, 0, 0) == 0 && sig == 10, "PR_SET/GET_PDEATHSIG");
    prctl(PR_SET_PDEATHSIG, 0, 0, 0, 0);
    check(prctl(PR_GET_TIMERSLACK, 0, 0, 0, 0) == 50000 && prctl(PR_SET_TIMERSLACK, 1000, 0, 0, 0) == 0 && prctl(PR_GET_TIMERSLACK, 0, 0, 0, 0) == 1000, "PR_SET_TIMERSLACK");
    check(prctl(PR_SET_TIMERSLACK, 0, 0, 0, 0) == 0 && prctl(PR_GET_TIMERSLACK, 0, 0, 0, 0) == 50000, "timer slack 0 restores the default");
    check(prctl(PR_SET_TAGGED_ADDR_CTRL, 1, 0, 0, 0) == 0 && prctl(PR_GET_TAGGED_ADDR_CTRL, 0, 0, 0, 0) == 1, "tagged address ABI");
    check(prctl(PR_SET_TAGGED_ADDR_CTRL, 1 | 2, 0, 0, 0) == -EINVAL, "no MTE: EINVAL");
    check(prctl(PR_GET_SPECULATION_CTRL, 0, 0, 0, 0) == 3 && prctl(PR_SET_SPECULATION_CTRL, 0, 4, 0, 0) == 0 && prctl(PR_GET_SPECULATION_CTRL, 0, 0, 0, 0) == 5, "speculation control: store bypass");
    check(prctl(PR_SET_SPECULATION_CTRL, 0, 8, 0, 0) == 0 && prctl(PR_SET_SPECULATION_CTRL, 0, 2, 0, 0) == -EPERM && prctl(PR_GET_SPECULATION_CTRL, 0, 0, 0, 0) == 9, "force-disable sticks");
    check(prctl(PR_SET_MM, 1, 0, 0, 0) == -EPERM && prctl(9999, 0, 0, 0, 0) == -EINVAL && prctl(PR_SET_VMA, 0, 0, 0, 0) == 0, "PR_SET_MM: EPERM; unknown: EINVAL; PR_SET_VMA ok");

    i64 pid = fork_();
    if (pid == 0) {
        failures = 0;
        check(prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) == 0 && prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0 && prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) == 1, "PR_SET_NO_NEW_PRIVS");
        check(prctl(PR_SET_NO_NEW_PRIVS, 0, 0, 0, 0) == -EINVAL, "no_new_privs cannot be unset");
        u64 filter = 0x7fff000000000006ul;
        struct { u16 len; u16 pad[3]; void *filter; } prog = { 1, { 0 }, &filter }, empty = { 0, { 0 }, &filter };
        check(sys(NR_seccomp, 1, 0, &empty) == -EINVAL, "an empty filter: EINVAL");
        check(sys(NR_seccomp, 1, 0, &prog) == 0 && prctl(PR_GET_SECCOMP, 0, 0, 0, 0) == 2, "seccomp filter installs (mode 2)");
        check(sys(NR_seccomp, 1, 1 /* TSYNC */, &prog) == 0 && sys(NR_getpid) == pid_self(), "a second filter; syscalls still run");
        check(sys(NR_seccomp, 0, 0, 0) == -EINVAL, "no strict mode on top of a filter");
        u32 allow = 0x7fff0000, bogus = 0x12345678;
        check(sys(NR_seccomp, 2, 0, &allow) == 0 && sys(NR_seccomp, 2, 0, &bogus) == -EOPNOTSUPP && sys(NR_seccomp, 99, 0, 0) == -EINVAL, "SECCOMP_GET_ACTION_AVAIL");
        readfile("/proc/self/status");
        check(has(buf, "NoNewPrivs:\t1\n") && has(buf, "Seccomp:\t2\n") && has(buf, "Seccomp_filters:\t2\n"), "/proc/self/status seccomp lines");
        check(prctl(PR_GET_CHILD_SUBREAPER, (i64)&filter, 0, 0, 0) == 0 && (u32)filter == 0, "PR_GET_CHILD_SUBREAPER");
        exit_(failures);
    }
    child_passed(pid);

    check(sys(NR_personality, 0xffffffff) == 0 && sys(NR_personality, 0x0040000) == 0 && sys(NR_personality, 0xffffffff) == 0x0040000, "personality: query and set");
    check(sys(NR_personality, 0) == 0x0040000 && sys(NR_personality, 8 /* PER_LINUX32 */) == -EINVAL, "no PER_LINUX32 on arm64");

    check(sys(NR_sethostname, "droidrt-test", 12) == 0 && sys(NR_setdomainname, "example", 7) == 0, "sethostname/setdomainname");
    char uts[65 * 6];
    sys(NR_uname, uts);
    check(seq(uts + 65, "droidrt-test", 13) && seq(uts + 325, "example", 8), "uname reflects them");
    readfile("/proc/sys/kernel/hostname");
    check(seq(buf, "droidrt-test\n", 14), "/proc/sys/kernel/hostname");
    check(sys(NR_sethostname, uts, 65) == -EINVAL, "names over 64 bytes: EINVAL");
}

static void groups_and_sessions(void) {
    check(sys(NR_getpgid, 0) == 0 && sys(NR_getsid, 0) == 0, "pid 1 is in group and session 0, like init");
    int p[2], q[2];
    sys(NR_pipe2, p, 0);
    sys(NR_pipe2, q, 0);
    i64 pid = fork_();
    if (pid == 0) {
        failures = 0;
        int me = pid_self();
        check(sys(NR_getpgid, 0) == 0 && sys(NR_getsid, 0) == 0, "a child inherits group and session");
        char x;
        sys(NR_write, q[1], "r", 1);
        sys(NR_read, p[0], &x, 1); // the parent moves us first
        check(sys(NR_getpgid, 0) == me && sys(NR_setsid) == -EPERM, "the parent's setpgid made us a group leader, which cannot setsid");
        check(sys(NR_setpgid, 0, 0) == 0 && sys(NR_getpgid, 0) == me, "setpgid(0, 0) on ourselves");
        i64 c = fork_();
        if (c == 0) {
            failures = 0;
            int gc = pid_self();
            check(sys(NR_getpgid, 0) == me && sys(NR_setsid) == gc && sys(NR_getsid, 0) == gc && sys(NR_getpgid, 0) == gc, "setsid makes a new session and group");
            check(sys(NR_setpgid, 0, me) == -EPERM, "joining a group in another session: EPERM");
            exit_(failures);
        }
        child_passed(c);
        exit_(failures);
    }
    char ready;
    sys(NR_read, q[0], &ready, 1);
    sys(NR_close, q[0]);
    sys(NR_close, q[1]);
    check(sys(NR_setpgid, pid, 0) == 0 && sys(NR_getpgid, pid) == pid && sys(NR_getsid, pid) == 0, "setpgid on a child");
    sys(NR_write, p[1], "x", 1);
    child_passed(pid);
    check(sys(NR_kill, 0, 0) == 0, "kill(0) reaches our own group");
    check(sys(NR_setpgid, 99999, 0) == -ESRCH && sys(NR_getpgid, 99999) == -ESRCH && sys(NR_setpgid, 0, -1) == -EINVAL, "setpgid/getpgid errors");

    // kill(-pgid) reaches the whole group, including a grandchild
    pid = fork_();
    if (pid == 0) {
        sys(NR_setpgid, 0, 0);
        if (fork_() == 0) {
            sys(NR_write, p[1], "g", 1);
            sleep_ms(5000);
            exit_(0);
        }
        sys(NR_write, p[1], "c", 1);
        sleep_ms(5000);
        exit_(0);
    }
    char two[2];
    sys(NR_read, p[0], two, 1);
    sys(NR_read, p[0], two + 1, 1);
    check(sys(NR_kill, -pid, 15) == 0, "kill(-pgid, SIGTERM)");
    int s1 = wait_status(pid), s2 = wait_status(-1);
    check((s1 & 0x7f) == 15 && (s2 & 0x7f) == 15, "both group members die; the orphan is reaped by pid 1");
    check(sys(NR_kill, -pid, 0) == -ESRCH && sys(NR_kill, -1, 0) == -ESRCH, "an empty group: ESRCH; kill(-1) skips init and the caller");

    // wait4 for a process group
    pid = fork_();
    if (pid == 0) {
        sys(NR_setpgid, 0, 0);
        sleep_ms(30);
        exit_(4);
    }
    for (int i = 0; i < 200 && sys(NR_getpgid, pid) != pid; i++) sleep_ms(5);
    int st = 0;
    check(sys(NR_wait4, -pid, &st, 0, 0) == pid && st >> 8 == 4, "wait4(-pgid)");
    sys(NR_close, p[0]);
    sys(NR_close, p[1]);
}

static void process_tree(void) {
    int p[2];
    sys(NR_pipe2, p, 0);
    // The acceptance case: a child forks a grandchild and exits.
    i64 a = fork_();
    if (a == 0) {
        i64 g = fork_();
        if (g == 0) {
            for (int i = 0; i < 500 && sys(NR_getppid) != 1; i++) sleep_ms(5);
            char r = sys(NR_getppid) == 1 ? 'y' : 'n';
            sys(NR_write, p[1], &r, 1);
            exit_(42);
        }
        int gp = (int)g;
        sys(NR_write, p[1], &gp, 4);
        exit_(0);
    }
    int g = 0;
    char r = 0;
    sys(NR_read, p[0], &g, 4);
    check(wait_status(a) == 0, "the middle process exits");
    sys(NR_read, p[0], &r, 1);
    check(r == 'y', "the grandchild sees getppid() == 1");
    int st = 0;
    check(sys(NR_wait4, -1, &st, 0, 0) == g && st >> 8 == 42, "pid 1 reaps the orphan with wait4(-1)");

    // An orphan that is already a zombie arrives in pid 1's children, ready to reap.
    a = fork_();
    if (a == 0) {
        i64 z = fork_();
        if (z == 0) exit_(7);
        int zp = (int)z;
        sys(NR_write, p[1], &zp, 4);
        sleep_ms(50);
        exit_(0);
    }
    sys(NR_read, p[0], &g, 4);
    check(wait_status(a) == 0, "a parent exits leaving a zombie");
    struct siginfo_ si;
    memset(&si, 0, sizeof si);
    check(sys(NR_waitid, 1 /* P_PID */, g, &si, 4 | 1 /* WEXITED|WNOHANG */, 0) == 0 && si.pid == g && si.status == 7 && si.code == 1, "the zombie is reparented and reapable at once");

    // A subreaper adopts orphans before pid 1 does.
    i64 s = fork_();
    if (s == 0) {
        failures = 0;
        int me = pid_self(), v = 0;
        check(prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) == 0 && prctl(PR_GET_CHILD_SUBREAPER, (i64)&v, 0, 0, 0) == 0 && v == 1, "PR_SET_CHILD_SUBREAPER");
        i64 m = fork_();
        if (m == 0) {
            if (fork_() == 0) {
                for (int i = 0; i < 500 && sys(NR_getppid) != me; i++) sleep_ms(5);
                exit_(sys(NR_getppid) == me ? 5 : 6);
            }
            exit_(0);
        }
        check(wait_status(m) == 0, "the subreaper's child exits");
        int gst = 0;
        check(sys(NR_wait4, -1, &gst, 0, 0) > 0 && gst >> 8 == 5, "the subreaper reaps its orphaned grandchild");
        exit_(failures);
    }
    child_passed(s);

    // Parent-death signal: the grandchild dies with SIGUSR2 when its parent exits.
    a = fork_();
    if (a == 0) {
        if (fork_() == 0) {
            int sig = 0;
            prctl(PR_SET_PDEATHSIG, 12, 0, 0, 0);
            prctl(PR_GET_PDEATHSIG, (i64)&sig, 0, 0, 0);
            sys(NR_write, p[1], sig == 12 ? "y" : "n", 1);
            sleep_ms(5000);
            exit_(0);
        }
        char c;
        sys(NR_read, p[0], &c, 1);
        exit_(c == 'y' ? 0 : 1);
    }
    check(wait_status(a) == 0, "PR_SET_PDEATHSIG in the grandchild");
    st = 0;
    check(sys(NR_wait4, -1, &st, 0, 0) > 0 && (st & 0x7f) == 12, "the parent's exit delivers the parent-death signal");

    // waitid
    a = fork_();
    if (a == 0) {
        sleep_ms(50);
        exit_(9);
    }
    memset(&si, 0xff, sizeof si);
    check(sys(NR_waitid, 1, a, &si, 4 | 1, 0) == 0 && si.pid == 0 && si.signo == 0, "waitid WNOHANG with nothing exited");
    check(sys(NR_waitid, 1, a, &si, 4 | 0x01000000 /* WNOWAIT */, 0) == 0 && si.signo == 17 && si.code == 1 && si.status == 9 && si.pid == a && si.uid == 0, "waitid WNOWAIT reports without reaping");
    memset(&si, 0, sizeof si);
    check(sys(NR_waitid, 0 /* P_ALL */, 0, &si, 4, 0) == 0 && si.pid == a, "waitid P_ALL reaps it");
    check(sys(NR_waitid, 0, 0, &si, 4, 0) == -ECHILD && sys(NR_waitid, 0, 0, &si, 1, 0) == -EINVAL && sys(NR_waitid, 1, 0, &si, 4, 0) == -EINVAL, "waitid errors");
    a = fork_();
    if (a == 0) {
        sys(NR_kill, pid_self(), 15);
        sleep_ms(1000);
        exit_(0);
    }
    check(sys(NR_waitid, 1, a, &si, 4, 0) == 0 && si.code == 2 && si.status == 15, "waitid: CLD_KILLED by SIGTERM");

    // SIGCHLD ignored: children are reaped as they exit.
    set_sigchld(1 /* SIG_IGN */, 0);
    a = fork_();
    if (a == 0) exit_(3);
    check(sys(NR_wait4, a, &st, 0, 0) == -ECHILD, "SIGCHLD SIG_IGN auto-reaps (wait4: ECHILD)");
    set_sigchld(0, 2 /* SA_NOCLDWAIT */);
    a = fork_();
    if (a == 0) exit_(3);
    check(sys(NR_wait4, a, &st, 0, 0) == -ECHILD, "SA_NOCLDWAIT auto-reaps");
    set_sigchld(0, 0);
    sys(NR_close, p[0]);
    sys(NR_close, p[1]);

    // pid 1 gets only the signals it handles, like init.
    a = fork_();
    if (a == 0) exit_(sys(NR_kill, 1, 15) == 0 && sys(NR_kill, 1, 9) == 0 ? 0 : 1);
    check(wait_status(a) == 0, "SIGTERM and SIGKILL to pid 1 are accepted");
    sleep_ms(20);
    check(1, "and ignored: pid 1 still runs");

    // A blocked SIGCHLD is queued despite its default disposition: init reads it from a signalfd.
    u64 chld = 1ul << 16;
    sys(NR_rt_sigprocmask, 0 /* SIG_BLOCK */, &chld, 0, 8);
    int sfd = (int)sys(NR_signalfd4, -1, &chld, 8, 0);
    a = fork_();
    if (a == 0) exit_(6);
    unsigned char rec[128];
    check(sys(NR_read, sfd, rec, 128) == 128 && *(u32 *)rec == 17 && *(int *)(rec + 12) == (int)a && *(int *)(rec + 40) == 6, "a blocked SIGCHLD reaches pid 1's signalfd");
    check(wait_status(a) >> 8 == 6, "and the child is still there to reap");
    sys(NR_close, sfd);
    sys(NR_rt_sigprocmask, 1 /* SIG_UNBLOCK */, &chld, 0, 8);
    a = fork_();
    if (a == 0) {
        // SIGCHLD (default: ignore) left pending while blocked, then unblocked by ppoll's mask.
        sys(NR_rt_sigprocmask, 0, &chld, 0, 8);
        i64 k = fork_();
        if (k == 0) exit_(0);
        wait_status(k);
        u64 ts[2] = { 0, 30000000 }, none = 0;
        exit_(sys(NR_ppoll, 0, 0, ts, &none, 8) == 0 ? 0 : 1);
    }
    check(wait_status(a) == 0, "a pending ignored signal does not interrupt a wait that unblocks it");

    // A pid 1 that never reaps cannot pile up orphaned zombies without bound.
    a = fork_();
    if (a == 0) {
        for (int i = 0; i < 300; i++) {
            i64 k;
            while ((k = fork_()) < 0) sleep_ms(1);
            if (k == 0) exit_(0);
            sys(NR_waitid, 1, k, &si, 4 | 0x01000000, 0); // a zombie, left unreaped
        }
        exit_(0);
    }
    check(wait_status(a) == 0, "a process exits leaving 300 zombies");
    int reaped = 0;
    while (sys(NR_wait4, -1, &st, 1 /* WNOHANG */, 0) > 0) reaped++;
    check(reaped == 256, "pid 1 keeps at most 256 adopted zombies");
}

// Linux ptrace_may_access (REALCREDS) requires the caller's real uid and gid
// to equal every one of the target's real, effective and saved ids. Matching
// only the effective uid, while dumpable, must not allow process_vm.
static void cross_cred(void) {
    int p[2], q[2];
    sys(NR_pipe2, p, 0);
    sys(NR_pipe2, q, 0);
    i64 mid = fork_();
    if (mid == 0) {
        failures = 0;
        i64 v = fork_();
        if (v == 0) {
            sys(NR_setresuid, 0, 1000, 0);
            prctl(PR_SET_DUMPABLE, 1, 0, 0, 0);
            memcpy(vm_buf, "secret!", 8);
            sys(NR_write, p[1], "v", 1);
            char d;
            sys(NR_read, q[0], &d, 1);
            exit_(0);
        }
        char c;
        sys(NR_read, p[0], &c, 1);
        sys(NR_setresuid, 1000, 1000, 1000);
        char got[8] = { 0 };
        struct iovec lr = { got, 7 }, rr = { vm_buf, 7 };
        check(sys(NR_process_vm_readv, v, &lr, 1, &rr, 1, 0) == -EPERM, "process_vm: one matching uid is not enough");
        sys(NR_write, q[1], "d", 1);
        wait_status(v);
        i64 peer = fork_();
        if (peer == 0) {
            prctl(PR_SET_DUMPABLE, 1, 0, 0, 0);
            memcpy(vm_buf, "peer-ok", 8);
            sys(NR_write, p[1], "p", 1);
            sys(NR_read, q[0], &c, 1);
            exit_(0);
        }
        sys(NR_read, p[0], &c, 1);
        char got2[8] = { 0 };
        struct iovec l2 = { got2, 7 }, r2 = { vm_buf, 7 };
        check(sys(NR_process_vm_readv, peer, &l2, 1, &r2, 1, 0) == 7 && seq(got2, "peer-ok", 7), "process_vm: equal ids and dumpable");
        sys(NR_write, q[1], "d", 1);
        wait_status(peer);
        exit_(failures);
    }
    child_passed(mid);
    sys(NR_close, p[0]);
    sys(NR_close, p[1]);
    sys(NR_close, q[0]);
    sys(NR_close, q[1]);
}

static void vm_access(void) {
    char src[32] = "process_vm_readv works", dst[32] = { 0 };
    struct iovec l[2] = { { dst, 10 }, { dst + 10, 12 } }, r = { src, 22 };
    check(sys(NR_process_vm_readv, pid_self(), l, 2, &r, 1, 0) == 22 && seq(dst, src, 22), "process_vm_readv on ourselves, scattered");
    struct iovec bad = { (void *)0x10, 8 };
    check(sys(NR_process_vm_readv, pid_self(), l, 1, &bad, 1, 0) == -EFAULT, "an unmapped remote address: EFAULT");
    check(sys(NR_process_vm_readv, pid_self(), l, 1, &r, 1, 1) == -EINVAL && sys(NR_process_vm_readv, 99999, l, 1, &r, 1, 0) == -ESRCH, "flags: EINVAL; missing pid: ESRCH");
    int p[2], q[2];
    sys(NR_pipe2, p, 0);
    sys(NR_pipe2, q, 0);
    i64 pid = fork_();
    if (pid == 0) {
        char c;
        memcpy(vm_buf, "child!", 7);
        sys(NR_write, q[1], "r", 1);
        sys(NR_read, p[0], &c, 1);
        exit_(seq(vm_buf, "after", 6) ? 0 : 1);
    }
    char c, got[8] = { 0 };
    sys(NR_read, q[0], &c, 1);
    struct iovec lr = { got, 7 }, rr = { vm_buf, 7 };
    check(sys(NR_process_vm_readv, pid, &lr, 1, &rr, 1, 0) == 7 && seq(got, "child!", 7), "process_vm_readv from a child");
    struct iovec lw = { "after", 6 }, rw = { vm_buf, 6 };
    check(sys(NR_process_vm_writev, pid, &lw, 1, &rw, 1, 0) == 6, "process_vm_writev into a child");
    sys(NR_write, p[1], "w", 1);
    check(wait_status(pid) == 0 && seq(vm_buf, "before", 7), "the child saw the write; ours is untouched");
}

int cmain(void) {
    ids_and_groups();
    capabilities();
    limits();
    scheduling();
    prctls();
    groups_and_sessions();
    process_tree();
    vm_access();
    cross_cred();
    check(sys(NR_reboot, MAGIC1, MAGIC2, 0 /* CAD_OFF */, 0) == 0, "reboot CAD_OFF");
    check(sys(NR_reboot, 0x12345678, MAGIC2, 0x4321fedc, 0) == -EINVAL && sys(NR_reboot, MAGIC1, MAGIC2, 0x11111111, 0) == -EINVAL, "reboot: bad magic or command: EINVAL");
    if (failures) {
        puts_("SOME CHECKS FAILED\n");
        return failures;
    }
    puts_("all checks passed\n");
    sys(NR_reboot, MAGIC1, MAGIC2, 0x4321fedc /* POWER_OFF */, 0);
    puts_("FAIL reboot returned\n");
    return 1;
}

void __attribute__((noreturn)) cstart(void) {
    sys(NR_exit_group, cmain());
    __builtin_unreachable();
}

__asm__(".global _start\n_start:\n bl cstart\n");

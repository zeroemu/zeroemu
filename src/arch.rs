//! Guest architecture. The guest ISA always matches the host CPU so guest code
//! runs natively: arm64 on Apple Silicon / Windows on ARM, x86_64 elsewhere.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Arch {
    Aarch64,
    X86_64,
}

impl Arch {
    pub const HOST: Arch = if cfg!(target_arch = "aarch64") {
        Arch::Aarch64
    } else {
        Arch::X86_64
    };

    pub fn elf_machine(self) -> u16 {
        match self {
            Arch::Aarch64 => 183, // EM_AARCH64
            Arch::X86_64 => 62,   // EM_X86_64
        }
    }

    pub fn hwcap(self) -> u64 {
        match self {
            // FP | ASIMD | AES | PMULL | SHA1 | SHA2 | CRC32 | ATOMICS | FPHP | ASIMDHP
            Arch::Aarch64 => 0b111_1111_1011,
            // x86_64 userspace reads CPUID directly; AT_HWCAP is informational.
            Arch::X86_64 => 0,
        }
    }

    /// Maps an arch-specific syscall number to the arch-neutral one the kernel
    /// layer implements. Linux's arm64 table is the "generic" table, so arm64
    /// numbers pass through and x86_64 numbers are translated.
    pub fn sysno(self, nr: u64) -> Option<Sysno> {
        match self {
            Arch::Aarch64 => Sysno::from_generic(nr),
            Arch::X86_64 => Sysno::from_x86_64(nr),
        }
    }
}

macro_rules! syscalls {
    ($($name:ident = $generic:literal, $x86:literal;)*) => {
        #[allow(non_camel_case_types)]
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub enum Sysno { $($name,)* }

        impl Sysno {
            fn from_generic(nr: u64) -> Option<Sysno> {
                match nr { $($generic => Some(Sysno::$name),)* _ => None }
            }
            fn from_x86_64(nr: u64) -> Option<Sysno> {
                match nr { $($x86 => Some(Sysno::$name),)* _ => None }
            }
        }
    };
}

// name = arm64/generic number, x86_64 number
syscalls! {
    setxattr = 5, 188;
    lsetxattr = 6, 189;
    fsetxattr = 7, 190;
    getxattr = 8, 191;
    lgetxattr = 9, 192;
    fgetxattr = 10, 193;
    listxattr = 11, 194;
    llistxattr = 12, 195;
    flistxattr = 13, 196;
    removexattr = 14, 197;
    lremovexattr = 15, 198;
    fremovexattr = 16, 199;
    eventfd2 = 19, 290;
    epoll_create1 = 20, 291;
    epoll_ctl = 21, 233;
    epoll_pwait = 22, 281;
    epoll_pwait2 = 441, 441;
    getcwd = 17, 79;
    dup = 23, 32;
    dup3 = 24, 292;
    fcntl = 25, 72;
    ioctl = 29, 16;
    flock = 32, 73;
    inotify_init1 = 26, 294;
    inotify_add_watch = 27, 254;
    inotify_rm_watch = 28, 255;
    mknodat = 33, 259;
    mkdirat = 34, 258;
    unlinkat = 35, 263;
    symlinkat = 36, 266;
    linkat = 37, 265;
    renameat = 38, 264;
    umount2 = 39, 166;
    mount = 40, 165;
    statfs = 43, 137;
    fstatfs = 44, 138;
    truncate = 45, 76;
    ftruncate = 46, 77;
    fallocate = 47, 285;
    faccessat = 48, 269;
    chdir = 49, 80;
    fchdir = 50, 81;
    fchmod = 52, 91;
    fchmodat = 53, 268;
    fchownat = 54, 260;
    fchown = 55, 93;
    openat = 56, 257;
    close = 57, 3;
    pipe2 = 59, 293;
    getdents64 = 61, 217;
    lseek = 62, 8;
    read = 63, 0;
    write = 64, 1;
    readv = 65, 19;
    writev = 66, 20;
    pread64 = 67, 17;
    pwrite64 = 68, 18;
    ppoll = 73, 271;
    pselect6 = 72, 270;
    signalfd4 = 74, 289;
    timerfd_create = 85, 283;
    getitimer = 102, 36;
    setitimer = 103, 38;
    timer_create = 107, 222;
    timer_gettime = 108, 224;
    timer_getoverrun = 109, 225;
    timer_settime = 110, 223;
    timer_delete = 111, 226;
    timerfd_settime = 86, 286;
    timerfd_gettime = 87, 287;
    utimensat = 88, 280;
    readlinkat = 78, 267;
    newfstatat = 79, 262;
    fstat = 80, 5;
    sync = 81, 162;
    fsync = 82, 74;
    fdatasync = 83, 75;
    exit = 93, 60;
    exit_group = 94, 231;
    set_tid_address = 96, 218;
    unshare = 97, 272;
    futex = 98, 202;
    set_robust_list = 99, 273;
    nanosleep = 101, 35;
    clock_gettime = 113, 228;
    clock_getres = 114, 229;
    clock_nanosleep = 115, 230;
    sched_getscheduler = 120, 145;
    sched_getparam = 121, 143;
    sched_setaffinity = 122, 203;
    sched_getaffinity = 123, 204;
    sched_yield = 124, 24;
    kill = 129, 62;
    tkill = 130, 200;
    tgkill = 131, 234;
    sigaltstack = 132, 131;
    rt_sigaction = 134, 13;
    rt_sigprocmask = 135, 14;
    rt_sigpending = 136, 127;
    rt_sigtimedwait = 137, 128;
    rt_sigsuspend = 133, 130;
    rt_sigreturn = 139, 15;
    rt_sigqueueinfo = 138, 129;
    rt_tgsigqueueinfo = 240, 297;
    accept4 = 242, 288;
    uname = 160, 63;
    setpgid = 154, 109;
    getpgid = 155, 121;
    getsid = 156, 124;
    setsid = 157, 112;
    getgroups = 158, 115;
    getrusage = 165, 98;
    umask = 166, 95;
    prctl = 167, 157;
    gettimeofday = 169, 96;
    getpid = 172, 39;
    getppid = 173, 110;
    getuid = 174, 102;
    geteuid = 175, 107;
    getgid = 176, 104;
    getegid = 177, 108;
    gettid = 178, 186;
    sysinfo = 179, 99;
    // credentials, capabilities, limits, scheduling, process control
    setregid = 143, 114;
    setgid = 144, 106;
    setreuid = 145, 113;
    setuid = 146, 105;
    setresuid = 147, 117;
    getresuid = 148, 118;
    setresgid = 149, 119;
    getresgid = 150, 120;
    setfsuid = 151, 122;
    setfsgid = 152, 123;
    setgroups = 159, 116;
    capget = 90, 125;
    capset = 91, 126;
    personality = 92, 135;
    waitid = 95, 247;
    seccomp = 277, 317;
    getrlimit = 163, 97;
    setrlimit = 164, 160;
    sethostname = 161, 170;
    setdomainname = 162, 171;
    reboot = 142, 169;
    process_vm_readv = 270, 310;
    process_vm_writev = 271, 311;
    setpriority = 140, 141;
    getpriority = 141, 140;
    sched_setparam = 118, 142;
    sched_setscheduler = 119, 144;
    sched_get_priority_max = 125, 146;
    sched_get_priority_min = 126, 147;
    sched_rr_get_interval = 127, 148;
    sched_setattr = 274, 314;
    sched_getattr = 275, 315;
    ioprio_set = 30, 251;
    ioprio_get = 31, 252;
    // x86_64-only (arm64 libcs use getpgid(0)); numbered after its x86_64 number.
    getpgrp = 0xffff_0111, 111;
    socket = 198, 41;
    socketpair = 199, 53;
    bind = 200, 49;
    listen = 201, 50;
    accept = 202, 43;
    connect = 203, 42;
    getsockname = 204, 51;
    getpeername = 205, 52;
    sendto = 206, 44;
    recvfrom = 207, 45;
    setsockopt = 208, 54;
    getsockopt = 209, 55;
    shutdown = 210, 48;
    sendmsg = 211, 46;
    recvmsg = 212, 47;
    brk = 214, 12;
    munmap = 215, 11;
    mremap = 216, 25;
    clone = 220, 56;
    execve = 221, 59;
    mmap = 222, 9;
    mprotect = 226, 10;
    madvise = 233, 28;
    wait4 = 260, 61;
    prlimit64 = 261, 302;
    setns = 268, 308;
    renameat2 = 276, 316;
    getrandom = 278, 318;
    memfd_create = 279, 319;
    msync = 227, 26;
    mlock = 228, 149;
    munlock = 229, 150;
    mlockall = 230, 151;
    munlockall = 231, 152;
    mincore = 232, 27;
    mlock2 = 284, 325;
    quotactl = 60, 179;
    sendfile = 71, 40;
    copy_file_range = 285, 326;
    init_module = 105, 175;
    delete_module = 106, 176;
    finit_module = 273, 313;
    settimeofday = 170, 164;
    bpf = 280, 321;
    membarrier = 283, 324;
    statx = 291, 332;
    rseq = 293, 334;
    clone3 = 435, 435;
    faccessat2 = 439, 439;
    // x86_64-only (sets the FS base for TLS); arm64 sets TPIDR_EL0 directly.
    arch_prctl = 0xffff_0000, 158;
    // x86_64-only legacy calls (the generic table has only the *at/clone forms).
    dup2 = 0xffff_0001, 33;
    fork = 0xffff_0002, 57;
    vfork = 0xffff_0003, 58;
    pipe = 0xffff_0004, 22;
    alarm = 0xffff_0005, 37;
}

/// Open flags whose values differ between the generic (arm64) and x86_64 ABIs.
pub struct OpenFlags {
    pub directory: u64,
    pub nofollow: u64,
}

impl Arch {
    /// clone(2) arguments as (flags, stack, parent_tid, child_tid, tls): arm64
    /// passes tls before child_tid (CLONE_BACKWARDS), x86_64 after.
    pub fn clone_args(self, a: [u64; 6]) -> (u64, u64, u64, u64, u64) {
        match self {
            Arch::Aarch64 => (a[0], a[1], a[2], a[4], a[3]),
            Arch::X86_64 => (a[0], a[1], a[2], a[3], a[4]),
        }
    }

    /// `struct epoll_event` as (size, offset of `data`): packed on x86_64,
    /// naturally aligned on arm64.
    pub fn epoll_event_layout(self) -> (usize, usize) {
        match self {
            Arch::Aarch64 => (16, 8),
            Arch::X86_64 => (12, 4),
        }
    }

    pub fn open_flags(self) -> OpenFlags {
        match self {
            Arch::Aarch64 => OpenFlags {
                directory: 0o40000,
                nofollow: 0o100000,
            },
            Arch::X86_64 => OpenFlags {
                directory: 0o200000,
                nofollow: 0o400000,
            },
        }
    }

    /// Encodes `struct stat` (arm64: generic 128-byte layout; x86_64: 144 bytes).
    pub fn encode_stat(self, st: &crate::vfs::Stat) -> Vec<u8> {
        let mut b = vec![0u8; if self == Arch::Aarch64 { 128 } else { 144 }];
        let mut put = |off: usize, v: &[u8]| b[off..off + v.len()].copy_from_slice(v);
        let blocks = st.size.div_ceil(512);
        put(0, &st.dev.to_le_bytes());
        put(8, &st.ino.to_le_bytes());
        match self {
            Arch::Aarch64 => {
                put(16, &st.mode.to_le_bytes());
                put(20, &st.nlink.to_le_bytes());
                put(24, &st.uid.to_le_bytes());
                put(28, &st.gid.to_le_bytes());
                put(32, &st.rdev.to_le_bytes());
                put(56, &4096u32.to_le_bytes());
            }
            Arch::X86_64 => {
                put(16, &(st.nlink as u64).to_le_bytes());
                put(24, &st.mode.to_le_bytes());
                put(28, &st.uid.to_le_bytes());
                put(32, &st.gid.to_le_bytes());
                put(40, &st.rdev.to_le_bytes());
                put(56, &4096u64.to_le_bytes());
            }
        }
        put(48, &st.size.to_le_bytes());
        put(64, &blocks.to_le_bytes());
        for t in [72, 88, 104] {
            put(t, &st.mtime.to_le_bytes()); // atime, mtime, ctime
        }
        b
    }
}

/// Strips an arm64 pointer tag (top byte). Android tags heap pointers and
/// passes them to syscalls under the tagged-address ABI; x86_64 has no tags.
pub fn untag(addr: u64) -> u64 {
    if Arch::HOST == Arch::Aarch64 { addr & 0x00ff_ffff_ffff_ffff } else { addr }
}

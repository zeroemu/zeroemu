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
    getcwd = 17, 79;
    dup = 23, 32;
    dup3 = 24, 292;
    fcntl = 25, 72;
    ioctl = 29, 16;
    statfs = 43, 137;
    fstatfs = 44, 138;
    faccessat = 48, 269;
    chdir = 49, 80;
    openat = 56, 257;
    close = 57, 3;
    getdents64 = 61, 217;
    lseek = 62, 8;
    read = 63, 0;
    write = 64, 1;
    readv = 65, 19;
    writev = 66, 20;
    pread64 = 67, 17;
    readlinkat = 78, 267;
    newfstatat = 79, 262;
    fstat = 80, 5;
    exit = 93, 60;
    exit_group = 94, 231;
    set_tid_address = 96, 218;
    futex = 98, 202;
    set_robust_list = 99, 273;
    nanosleep = 101, 35;
    clock_gettime = 113, 228;
    clock_getres = 114, 229;
    clock_nanosleep = 115, 230;
    sched_getscheduler = 120, 145;
    sched_getparam = 121, 143;
    sched_getaffinity = 123, 204;
    sched_yield = 124, 24;
    kill = 129, 62;
    tgkill = 131, 234;
    sigaltstack = 132, 131;
    rt_sigaction = 134, 13;
    rt_sigprocmask = 135, 14;
    uname = 160, 63;
    setpgid = 154, 109;
    getpgid = 155, 121;
    getsid = 156, 124;
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
    socket = 198, 41;
    connect = 203, 42;
    brk = 214, 12;
    munmap = 215, 11;
    mremap = 216, 25;
    mmap = 222, 9;
    mprotect = 226, 10;
    madvise = 233, 28;
    prlimit64 = 261, 302;
    getrandom = 278, 318;
    statx = 291, 332;
    rseq = 293, 334;
    faccessat2 = 439, 439;
    // x86_64-only (sets the FS base for TLS); arm64 sets TPIDR_EL0 directly.
    arch_prctl = 0xffff_0000, 158;
}

/// Open flags whose values differ between the generic (arm64) and x86_64 ABIs.
pub struct OpenFlags {
    pub directory: u64,
    pub nofollow: u64,
}

impl Arch {
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

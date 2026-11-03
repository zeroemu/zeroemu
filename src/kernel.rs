//! The Linux personality: implements Linux syscall semantics on top of the
//! host OS. Nothing here may depend on POSIX; anything host-specific goes
//! through Rust's std, `mem`, or `vfs`, so the same code serves macOS and Windows.

use crate::arch::{Arch, Sysno};
use crate::errno::*;
use crate::hv::{SyscallRegs, Vcpu};
use crate::mem::{self, GuestMem, MMAP_BASE, STACK_SIZE, STACK_TOP};
use crate::vfs::{Dirent, Node, S_IFDIR, S_IFMT, S_IFREG, Stat, Vfs};
use std::io::{Read, Write};
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

const PAGE: u64 = 4096;

const AT_FDCWD: i64 = -100;
const AT_SYMLINK_NOFOLLOW: u64 = 0x100;
const AT_EMPTY_PATH: u64 = 0x1000;
const O_ACCMODE: u64 = 3;
const O_CREAT: u64 = 0o100;
const MAP_FIXED: u64 = 0x10;
const MAP_ANONYMOUS: u64 = 0x20;
const ARCH_SET_FS: u64 = 0x1002;
const RLIMIT_STACK: u64 = 3;
const RLIM_INFINITY: u64 = u64::MAX;
const F_DUPFD: u64 = 0;
const F_GETFD: u64 = 1;
const F_SETFD: u64 = 2;
const F_GETFL: u64 = 3;
const F_SETFL: u64 = 4;
const F_DUPFD_CLOEXEC: u64 = 1030;

pub enum Flow {
    Continue,
    Exit(i32),
}

enum Fd {
    Stdin,
    Stdout,
    Stderr,
    Null,
    File(Arc<std::sync::Mutex<OpenFile>>),
}

impl Clone for Fd {
    fn clone(&self) -> Self {
        match self {
            Fd::Stdin => Fd::Stdin,
            Fd::Stdout => Fd::Stdout,
            Fd::Stderr => Fd::Stderr,
            Fd::Null => Fd::Null,
            Fd::File(f) => Fd::File(f.clone()), // dup shares the file offset
        }
    }
}

struct OpenFile {
    node: Node,
    stat: Stat,
    pos: u64,
    data: Option<Arc<[u8]>>,
    dents: Option<Vec<Dirent>>,
}

pub struct Process {
    arch: Arch,
    vfs: Option<Arc<Vfs>>,
    fds: Vec<Option<Fd>>,
    cwd: String,
    exe: String,
    brk_start: u64,
    brk_limit: u64,
    brk: u64,
    mmap_next: u64,
    boot: Instant,
    pub strace: bool,
}

/// A C `int` syscall argument (fds, dirfds): only the low 32 bits are defined,
/// so AT_FDCWD arrives as 0xffffff9c.
fn int(v: u64) -> i64 {
    v as u32 as i32 as i64
}

fn page_up(v: u64) -> u64 {
    (v + PAGE - 1) & !(PAGE - 1)
}

impl Process {
    /// `image_end`: end of the main executable (start of brk); `brk_limit`: the
    /// next thing mapped above it (the interpreter, or the mmap area).
    pub fn new(
        arch: Arch,
        vfs: Option<Arc<Vfs>>,
        exe: String,
        image_end: u64,
        brk_limit: u64,
    ) -> Self {
        let brk = page_up(image_end);
        Process {
            arch,
            vfs,
            fds: vec![Some(Fd::Stdin), Some(Fd::Stdout), Some(Fd::Stderr)],
            cwd: "/".into(),
            exe,
            brk_start: brk,
            brk_limit: brk_limit.min(MMAP_BASE),
            brk,
            mmap_next: MMAP_BASE,
            boot: Instant::now(),
            strace: false,
        }
    }

    pub fn syscall(&mut self, mem: &GuestMem, vcpu: &mut dyn Vcpu) -> Flow {
        let regs = vcpu.syscall_regs();
        let sysno = self.arch.sysno(regs.nr);
        let ret = match sysno {
            Some(Sysno::exit) | Some(Sysno::exit_group) => {
                if self.strace {
                    eprintln!("[strace] exit({})", regs.args[0] as i32);
                }
                return Flow::Exit(regs.args[0] as i32);
            }
            Some(no) => self.dispatch(no, &regs, mem, vcpu),
            None => -ENOSYS,
        };
        if self.strace {
            let name = sysno.map_or_else(|| format!("syscall_{}", regs.nr), |s| format!("{s:?}"));
            let a = regs.args;
            let path = match sysno {
                Some(
                    Sysno::openat
                    | Sysno::newfstatat
                    | Sysno::readlinkat
                    | Sysno::faccessat
                    | Sysno::faccessat2
                    | Sysno::statx,
                ) => mem
                    .read_cstr(a[1])
                    .map(|p| format!(" \"{p}\""))
                    .unwrap_or_default(),
                _ => String::new(),
            };
            eprintln!(
                "[strace] {name}({:#x}, {:#x}, {:#x}, {:#x}){path} = {ret}",
                a[0], a[1], a[2], a[3]
            );
        } else if ret == -ENOSYS {
            eprintln!(
                "[droidrt] unimplemented syscall {} ({:?}, {:?})",
                regs.nr, sysno, self.arch
            );
        }
        vcpu.set_syscall_return(ret as u64);
        Flow::Continue
    }

    fn dispatch(&mut self, no: Sysno, r: &SyscallRegs, mem: &GuestMem, vcpu: &mut dyn Vcpu) -> i64 {
        let a = r.args;
        match no {
            // --- files ---
            Sysno::openat => self.openat(mem, int(a[0]), a[1], a[2]),
            Sysno::close => match self.fds.get_mut(a[0] as usize) {
                Some(slot @ Some(_)) => {
                    *slot = None;
                    0
                }
                _ => -EBADF,
            },
            Sysno::read => {
                let Some(buf) = mem.slice(a[1], a[2]) else {
                    return -EFAULT;
                };
                self.read(a[0], buf, None)
            }
            Sysno::pread64 => {
                let Some(buf) = mem.slice(a[1], a[2]) else {
                    return -EFAULT;
                };
                self.read(a[0], buf, Some(a[3]))
            }
            Sysno::readv => {
                let mut total = 0;
                for i in 0..a[2] {
                    let (Some(base), Some(len)) =
                        (mem.read_u64(a[1] + i * 16), mem.read_u64(a[1] + i * 16 + 8))
                    else {
                        return -EFAULT;
                    };
                    let Some(buf) = mem.slice(base, len) else {
                        return -EFAULT;
                    };
                    let n = self.read(a[0], buf, None);
                    if n < 0 {
                        return if total > 0 { total } else { n };
                    }
                    total += n;
                    if (n as u64) < len {
                        break;
                    }
                }
                total
            }
            Sysno::write => self.write(mem, a[0], a[1], a[2]),
            Sysno::writev => {
                let mut total = 0;
                for i in 0..a[2] {
                    let (Some(base), Some(len)) =
                        (mem.read_u64(a[1] + i * 16), mem.read_u64(a[1] + i * 16 + 8))
                    else {
                        return -EFAULT;
                    };
                    let n = self.write(mem, a[0], base, len);
                    if n < 0 {
                        return if total > 0 { total } else { n };
                    }
                    total += n;
                }
                total
            }
            Sysno::lseek => self.lseek(a[0], a[1] as i64, a[2]),
            Sysno::fstat => match self.fd_stat(a[0]) {
                Ok(st) => self.put_stat(mem, a[1], &st),
                Err(e) => -e,
            },
            Sysno::newfstatat => match self.path_stat(mem, int(a[0]), a[1], a[3]) {
                Ok(st) => self.put_stat(mem, a[2], &st),
                Err(e) => -e,
            },
            Sysno::statx => match self.path_stat(mem, int(a[0]), a[1], a[2]) {
                Ok(st) => put_statx(mem, a[4], &st),
                Err(e) => -e,
            },
            Sysno::faccessat | Sysno::faccessat2 => match self.path_stat(mem, int(a[0]), a[1], 0)
            {
                Ok(_) if a[2] & 2 != 0 => -EROFS, // W_OK on a read-only image
                Ok(_) => 0,
                Err(e) => -e,
            },
            Sysno::readlinkat => self.readlinkat(mem, int(a[0]), a[1], a[2], a[3]),
            Sysno::getdents64 => self.getdents64(mem, a[0], a[1], a[2]),
            Sysno::getcwd => {
                let mut s = self.cwd.clone().into_bytes();
                s.push(0);
                if (s.len() as u64) > a[1] {
                    return -ERANGE;
                }
                if !mem.write(a[0], &s) {
                    return -EFAULT;
                }
                s.len() as i64
            }
            Sysno::chdir => {
                let Some(path) = mem.read_cstr(a[0]) else {
                    return -EFAULT;
                };
                match self.resolve(AT_FDCWD, &path, true) {
                    Ok(n) => {
                        self.cwd = n.path;
                        0
                    }
                    Err(e) => -e,
                }
            }
            Sysno::dup => self.dup_to(a[0], 0),
            Sysno::dup3 => {
                let Some(Some(fd)) = self.fds.get(a[0] as usize).cloned() else {
                    return -EBADF;
                };
                if a[0] == a[1] {
                    return -EINVAL;
                }
                let new = a[1] as usize;
                if self.fds.len() <= new {
                    self.fds.resize_with(new + 1, || None);
                }
                self.fds[new] = Some(fd);
                new as i64
            }
            Sysno::fcntl => match a[1] {
                F_DUPFD | F_DUPFD_CLOEXEC => self.dup_to(a[0], a[2] as usize),
                F_GETFD | F_SETFD | F_SETFL => self.fd_exists(a[0]),
                F_GETFL => match self.fds.get(a[0] as usize) {
                    Some(Some(Fd::Stdout | Fd::Stderr)) => 1, // O_WRONLY
                    Some(Some(_)) => 0,                       // O_RDONLY
                    _ => -EBADF,
                },
                _ => -EINVAL,
            },
            Sysno::ioctl => match self.fd_exists(a[0]) {
                0 => -ENOTTY,
                e => e,
            },
            Sysno::fstatfs => match self.fd_exists(a[0]) {
                0 => put_statfs(mem, a[1]),
                e => e,
            },
            Sysno::statfs => {
                let Some(path) = mem.read_cstr(a[0]) else { return -EFAULT };
                match self.resolve(AT_FDCWD, &path, true) {
                    Ok(_) => put_statfs(mem, a[1]),
                    Err(e) => -e,
                }
            }
            // No sockets yet: logd and property service clients fall back quietly.
            Sysno::socket | Sysno::connect => -EACCES,
            Sysno::umask => 0o022,

            // --- memory ---
            Sysno::brk => {
                let want = a[0];
                if want >= self.brk_start && want < self.brk_limit {
                    let new = page_up(want);
                    let old = page_up(self.brk);
                    if new > old {
                        mem.slice(old, new - old).unwrap().fill(0);
                    }
                    self.brk = want;
                }
                self.brk as i64
            }
            Sysno::mmap => self.mmap(mem, a[0], a[1], a[3], int(a[4]), a[5]),
            Sysno::munmap | Sysno::mprotect | Sysno::madvise => 0,
            Sysno::mremap => self.mremap(mem, a[0], a[1], a[2], a[3], a[4]),

            // --- process / identity ---
            Sysno::set_tid_address | Sysno::gettid | Sysno::getpid => 1,
            Sysno::getppid => 0,
            Sysno::getpgid | Sysno::getsid => 1,
            Sysno::setpgid => 0,
            Sysno::getgroups => 0, // no supplementary groups
            Sysno::getuid | Sysno::geteuid | Sysno::getgid | Sysno::getegid => 0,
            Sysno::set_robust_list | Sysno::sched_yield | Sysno::prctl => 0,
            Sysno::rseq => -ENOSYS, // bionic falls back cleanly
            Sysno::futex => {
                // Single-threaded for now: a wait can never be woken, so report
                // the value as changed rather than deadlocking.
                if a[1] & 0x7f == 0 { -EAGAIN } else { 0 }
            }
            Sysno::rt_sigaction | Sysno::sigaltstack => 0, // accepted, not delivered yet
            Sysno::rt_sigprocmask => {
                if a[2] != 0 && !mem.write_u64(a[2], 0) {
                    return -EFAULT;
                }
                0
            }
            Sysno::kill | Sysno::tgkill => -EPERM,
            Sysno::prlimit64 => {
                if a[3] != 0 {
                    let cur = if a[1] == RLIMIT_STACK {
                        STACK_SIZE
                    } else {
                        RLIM_INFINITY
                    };
                    if !(mem.write_u64(a[3], cur) && mem.write_u64(a[3] + 8, RLIM_INFINITY)) {
                        return -EFAULT;
                    }
                }
                0
            }
            Sysno::sched_getscheduler => 0, // SCHED_OTHER
            Sysno::sched_getparam => {
                if mem.write(a[1], &0u32.to_le_bytes()) { 0 } else { -EFAULT }
            }
            Sysno::sched_getaffinity => {
                // One CPU: a single-byte mask.
                let len = a[1].min(8);
                let Some(buf) = mem.slice(a[2], len) else {
                    return -EFAULT;
                };
                buf.fill(0);
                if let Some(b) = buf.first_mut() {
                    *b = 1;
                }
                len as i64
            }
            Sysno::getrusage => match mem.slice(a[1], 144) {
                Some(b) => {
                    b.fill(0);
                    0
                }
                None => -EFAULT,
            },
            Sysno::sysinfo => match mem.slice(a[0], 112) {
                Some(b) => {
                    b.fill(0);
                    b[0..8].copy_from_slice(&self.boot.elapsed().as_secs().to_le_bytes());
                    b[32..40].copy_from_slice(&(mem::MEM_SIZE).to_le_bytes()); // totalram
                    b[104..108].copy_from_slice(&1u32.to_le_bytes()); // mem_unit
                    0
                }
                None => -EFAULT,
            },
            Sysno::arch_prctl => {
                if a[0] != ARCH_SET_FS {
                    return -EINVAL;
                }
                vcpu.set_tls(a[1]);
                0
            }

            // --- time / misc ---
            Sysno::uname => self.uname(mem, a[0]),
            Sysno::clock_gettime => {
                let (sec, nsec) = self.clock(a[0]);
                if !(mem.write_u64(a[1], sec) && mem.write_u64(a[1] + 8, nsec)) {
                    return -EFAULT;
                }
                0
            }
            Sysno::clock_getres => {
                if a[1] != 0 && !(mem.write_u64(a[1], 0) && mem.write_u64(a[1] + 8, 1)) {
                    return -EFAULT;
                }
                0
            }
            Sysno::gettimeofday => {
                let (sec, nsec) = self.clock(0);
                if a[0] != 0 && !(mem.write_u64(a[0], sec) && mem.write_u64(a[0] + 8, nsec / 1000))
                {
                    return -EFAULT;
                }
                0
            }
            Sysno::nanosleep | Sysno::clock_nanosleep => {
                let req = if no == Sysno::nanosleep { a[0] } else { a[2] };
                let (Some(s), Some(ns)) = (mem.read_u64(req), mem.read_u64(req + 8)) else {
                    return -EFAULT;
                };
                std::thread::sleep(std::time::Duration::new(s, ns as u32));
                0
            }
            Sysno::getrandom => {
                let Some(buf) = mem.slice(a[0], a[1]) else {
                    return -EFAULT;
                };
                mem::random_bytes(buf);
                a[1] as i64
            }
            Sysno::exit | Sysno::exit_group => unreachable!(),
        }
    }

    // ---- file helpers ----

    fn vfs(&self) -> Result<&Vfs, i64> {
        self.vfs.as_deref().ok_or(ENOENT)
    }

    fn fd_exists(&self, fd: u64) -> i64 {
        match self.fds.get(fd as usize) {
            Some(Some(_)) => 0,
            _ => -EBADF,
        }
    }

    fn alloc_fd(&mut self, fd: Fd, min: usize) -> i64 {
        let slot = (min..)
            .find(|&i| self.fds.get(i).is_none_or(|s| s.is_none()))
            .unwrap();
        if slot >= 1024 {
            return -EMFILE;
        }
        if self.fds.len() <= slot {
            self.fds.resize_with(slot + 1, || None);
        }
        self.fds[slot] = Some(fd);
        slot as i64
    }

    fn dup_to(&mut self, fd: u64, min: usize) -> i64 {
        match self.fds.get(fd as usize).cloned() {
            Some(Some(f)) => self.alloc_fd(f, min),
            _ => -EBADF,
        }
    }

    fn file(&self, fd: u64) -> Result<Arc<std::sync::Mutex<OpenFile>>, i64> {
        match self.fds.get(fd as usize) {
            Some(Some(Fd::File(f))) => Ok(f.clone()),
            Some(Some(_)) => Err(EINVAL),
            _ => Err(EBADF),
        }
    }

    /// Directory to resolve relative paths against for a *at() call.
    fn base_dir(&self, dirfd: i64) -> Result<String, i64> {
        if dirfd == AT_FDCWD {
            return Ok(self.cwd.clone());
        }
        let f = self.file(dirfd as u64)?;
        let f = f.lock().unwrap();
        if f.stat.mode & S_IFMT != S_IFDIR {
            return Err(ENOTDIR);
        }
        Ok(f.node.path.clone())
    }

    fn resolve(&self, dirfd: i64, path: &str, follow: bool) -> Result<Node, i64> {
        let base = if path.starts_with('/') {
            "/".to_string()
        } else {
            self.base_dir(dirfd)?
        };
        self.vfs()?.resolve(&base, path, follow)
    }

    fn openat(&mut self, mem: &GuestMem, dirfd: i64, path: u64, flags: u64) -> i64 {
        let Some(path) = mem.read_cstr(path) else {
            return -EFAULT;
        };
        if path == "/dev/null" {
            return self.alloc_fd(Fd::Null, 0);
        }
        let of = self.arch.open_flags();
        let node = match self.resolve(dirfd, &path, flags & of.nofollow == 0) {
            Ok(n) => n,
            Err(ENOENT) if flags & O_CREAT != 0 => return -EROFS,
            Err(e) => return -e,
        };
        if flags & O_ACCMODE != 0 {
            return -EROFS;
        }
        let stat = match self.vfs().and_then(|v| v.stat(&node)) {
            Ok(s) => s,
            Err(e) => return -e,
        };
        if flags & of.directory != 0 && stat.mode & S_IFMT != S_IFDIR {
            return -ENOTDIR;
        }
        let file = OpenFile {
            node,
            stat,
            pos: 0,
            data: None,
            dents: None,
        };
        self.alloc_fd(Fd::File(Arc::new(std::sync::Mutex::new(file))), 0)
    }

    fn file_data(&self, f: &mut OpenFile) -> Result<Arc<[u8]>, i64> {
        if f.stat.mode & S_IFMT == S_IFDIR {
            return Err(EISDIR);
        }
        if f.data.is_none() {
            f.data = Some(self.vfs()?.read_all(&f.node)?);
        }
        Ok(f.data.clone().unwrap())
    }

    fn read(&mut self, fd: u64, buf: &mut [u8], at: Option<u64>) -> i64 {
        match self.fds.get(fd as usize) {
            Some(Some(Fd::Stdin)) => return std::io::stdin().read(buf).map_or(-EIO, |n| n as i64),
            Some(Some(Fd::Null)) => return 0,
            Some(Some(Fd::File(_))) => {}
            Some(Some(_)) => return -EBADF,
            _ => return -EBADF,
        }
        let f = self.file(fd).unwrap();
        let mut f = f.lock().unwrap();
        let data = match self.file_data(&mut f) {
            Ok(d) => d,
            Err(e) => return -e,
        };
        let pos = at.unwrap_or(f.pos) as usize;
        let n = data.len().saturating_sub(pos).min(buf.len());
        buf[..n].copy_from_slice(&data[pos..pos + n]);
        if at.is_none() {
            f.pos += n as u64;
        }
        n as i64
    }

    fn write(&mut self, mem: &GuestMem, fd: u64, buf: u64, len: u64) -> i64 {
        let Some(data) = mem.slice(buf, len) else {
            return -EFAULT;
        };
        let res = match self.fds.get(fd as usize) {
            Some(Some(Fd::Stdout)) => std::io::stdout()
                .write_all(data)
                .and_then(|_| std::io::stdout().flush()),
            Some(Some(Fd::Stderr)) => std::io::stderr().write_all(data),
            Some(Some(Fd::Null)) => Ok(()),
            _ => return -EBADF,
        };
        res.map_or(-EIO, |_| len as i64)
    }

    fn lseek(&mut self, fd: u64, off: i64, whence: u64) -> i64 {
        let f = match self.file(fd) {
            Ok(f) => f,
            Err(EINVAL) => return -ESPIPE,
            Err(e) => return -e,
        };
        let mut f = f.lock().unwrap();
        let base = match whence {
            0 => 0,
            1 => f.pos as i64,
            2 => f.stat.size as i64,
            _ => return -EINVAL,
        };
        let new = base + off;
        if new < 0 {
            return -EINVAL;
        }
        f.pos = new as u64;
        new
    }

    fn fd_stat(&self, fd: u64) -> Result<Stat, i64> {
        let chr = |rdev| Stat {
            mode: 0o020620,
            rdev,
            nlink: 1,
            ..Default::default()
        };
        match self.fds.get(fd as usize) {
            Some(Some(Fd::Stdin | Fd::Stdout | Fd::Stderr)) => Ok(chr(0x8800)), // /dev/pts/0
            Some(Some(Fd::Null)) => Ok(chr(0x0103)),                            // /dev/null
            Some(Some(Fd::File(f))) => Ok(f.lock().unwrap().stat.clone()),
            _ => Err(EBADF),
        }
    }

    fn path_stat(&self, mem: &GuestMem, dirfd: i64, path: u64, flags: u64) -> Result<Stat, i64> {
        let path = mem.read_cstr(path).ok_or(EFAULT)?;
        if path.is_empty() && flags & AT_EMPTY_PATH != 0 {
            return if dirfd == AT_FDCWD {
                self.vfs()?.stat(&self.resolve(AT_FDCWD, &self.cwd, true)?)
            } else {
                self.fd_stat(dirfd as u64)
            };
        }
        let node = self.resolve(dirfd, &path, flags & AT_SYMLINK_NOFOLLOW == 0)?;
        self.vfs()?.stat(&node)
    }

    fn put_stat(&self, mem: &GuestMem, addr: u64, st: &Stat) -> i64 {
        if mem.write(addr, &self.arch.encode_stat(st)) {
            0
        } else {
            -EFAULT
        }
    }

    fn readlinkat(&self, mem: &GuestMem, dirfd: i64, path: u64, buf: u64, size: u64) -> i64 {
        let Some(path) = mem.read_cstr(path) else {
            return -EFAULT;
        };
        let fd_link = path.strip_prefix("/proc/self/fd/").and_then(|n| n.parse::<u64>().ok());
        let target = if path == "/proc/self/exe" {
            self.exe.clone().into_bytes()
        } else if let Some(fd) = fd_link {
            match self.fds.get(fd as usize) {
                Some(Some(Fd::File(f))) => f.lock().unwrap().node.path.clone().into_bytes(),
                Some(Some(Fd::Null)) => b"/dev/null".to_vec(),
                Some(Some(_)) => b"/dev/pts/0".to_vec(),
                _ => return -ENOENT,
            }
        } else {
            let node = match self.resolve(dirfd, &path, false) {
                Ok(n) => n,
                Err(e) => return -e,
            };
            let vfs = self.vfs().unwrap();
            match vfs.stat(&node) {
                Ok(st) if st.mode & S_IFMT == crate::vfs::S_IFLNK => match vfs.read_all(&node) {
                    Ok(t) => t.to_vec(),
                    Err(e) => return -e,
                },
                Ok(_) => return -EINVAL,
                Err(e) => return -e,
            }
        };
        let n = target.len().min(size as usize);
        if !mem.write(buf, &target[..n]) {
            return -EFAULT;
        }
        n as i64
    }

    fn getdents64(&mut self, mem: &GuestMem, fd: u64, buf: u64, count: u64) -> i64 {
        let f = match self.file(fd) {
            Ok(f) => f,
            Err(e) => return -e,
        };
        let mut f = f.lock().unwrap();
        if f.stat.mode & S_IFMT != S_IFDIR {
            return -ENOTDIR;
        }
        if f.dents.is_none() {
            match self.vfs().and_then(|v| v.readdir(&f.node)) {
                Ok(d) => f.dents = Some(d),
                Err(e) => return -e,
            }
        }
        let mut out = Vec::new();
        let mut idx = f.pos as usize;
        let dents = f.dents.as_ref().unwrap();
        while let Some(d) = dents.get(idx) {
            let reclen = (19 + d.name.len() + 1).next_multiple_of(8);
            if (out.len() + reclen) as u64 > count {
                break;
            }
            let mut rec = vec![0u8; reclen];
            rec[0..8].copy_from_slice(&d.ino.max(1).to_le_bytes());
            rec[8..16].copy_from_slice(&((idx + 1) as u64).to_le_bytes());
            rec[16..18].copy_from_slice(&(reclen as u16).to_le_bytes());
            rec[18] = d.dtype;
            rec[19..19 + d.name.len()].copy_from_slice(d.name.as_bytes());
            out.extend(rec);
            idx += 1;
        }
        if out.is_empty() && idx < dents.len() {
            return -EINVAL; // buffer too small for one entry
        }
        f.pos = idx as u64;
        if !mem.write(buf, &out) {
            return -EFAULT;
        }
        out.len() as i64
    }

    // ---- memory ----

    fn mmap(
        &mut self,
        mem: &GuestMem,
        addr: u64,
        len: u64,
        flags: u64,
        fd: i64,
        offset: u64,
    ) -> i64 {
        let len = page_up(len);
        if len == 0 {
            return -EINVAL;
        }
        let fixed = flags & MAP_FIXED != 0;
        let start = if fixed { addr } else { self.mmap_next };
        if start < crate::mem::BLOCK || start.saturating_add(len) > STACK_TOP - STACK_SIZE {
            return -ENOMEM;
        }
        if !fixed {
            self.mmap_next += len;
        }
        let dst = mem.slice(start, len).unwrap();
        if flags & MAP_ANONYMOUS != 0 {
            // Fresh bump-allocated memory has never been touched, so it is
            // already zero; zero-filling would commit every page of a large
            // reservation. MAP_FIXED may land on used memory, so clear it.
            if fixed {
                dst.fill(0);
            }
            return start as i64;
        }
        // File mapping: images are read-only, so a private copy is exact.
        let f = match self.file(fd as u64) {
            Ok(f) => f,
            Err(e) => return -e,
        };
        let mut f = f.lock().unwrap();
        if f.stat.mode & S_IFMT != S_IFREG {
            return -ENODEV;
        }
        let data = match self.file_data(&mut f) {
            Ok(d) => d,
            Err(e) => return -e,
        };
        let from = (offset as usize).min(data.len());
        let n = (data.len() - from).min(len as usize);
        dst[..n].copy_from_slice(&data[from..from + n]);
        dst[n..].fill(0);
        start as i64
    }

    /// Identity-mapped memory can't move pages, so a move is a copy.
    fn mremap(&mut self, mem: &GuestMem, old: u64, old_len: u64, new_len: u64, flags: u64, new_addr: u64) -> i64 {
        const MREMAP_MAYMOVE: u64 = 1;
        const MREMAP_FIXED: u64 = 2;
        let (old_len, new_len) = (page_up(old_len), page_up(new_len));
        if new_len == 0 || old & (PAGE - 1) != 0 {
            return -EINVAL;
        }
        if flags & MREMAP_FIXED == 0 && new_len <= old_len {
            return old as i64; // shrinking in place
        }
        if flags & MREMAP_MAYMOVE == 0 {
            return -ENOMEM;
        }
        let dst = if flags & MREMAP_FIXED != 0 {
            new_addr
        } else {
            let start = self.mmap_next;
            if start + new_len > STACK_TOP - STACK_SIZE {
                return -ENOMEM;
            }
            self.mmap_next += new_len;
            start
        };
        let keep = old_len.min(new_len);
        if !mem.copy_within(old, dst, keep) {
            return -EFAULT;
        }
        if let Some(tail) = mem.slice(dst + keep, new_len - keep) {
            tail.fill(0);
        }
        dst as i64
    }

    // ---- misc ----

    fn clock(&self, id: u64) -> (u64, u64) {
        let d = match id {
            0 | 5 => SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default(), // REALTIME(_COARSE)
            _ => self.boot.elapsed(),
        };
        (d.as_secs(), d.subsec_nanos() as u64)
    }

    fn uname(&mut self, mem: &GuestMem, buf: u64) -> i64 {
        let Some(out) = mem.slice(buf, 65 * 6) else {
            return -EFAULT;
        };
        out.fill(0);
        let machine = match self.arch {
            Arch::Aarch64 => "aarch64",
            Arch::X86_64 => "x86_64",
        };
        let fields = [
            "Linux",
            "localhost",
            "6.6.0-droidrt",
            "#1 SMP droidrt",
            machine,
            "(none)",
        ];
        for (i, f) in fields.iter().enumerate() {
            out[i * 65..i * 65 + f.len()].copy_from_slice(f.as_bytes());
        }
        0
    }
}

/// `struct statfs` (same 120-byte layout on arm64 and x86_64): a read-only ext4-like volume.
fn put_statfs(mem: &GuestMem, addr: u64) -> i64 {
    let mut b = [0u8; 120];
    b[0..8].copy_from_slice(&0xef53u64.to_le_bytes()); // f_type
    b[8..16].copy_from_slice(&4096u64.to_le_bytes()); // f_bsize
    b[64..72].copy_from_slice(&255u64.to_le_bytes()); // f_namelen
    b[72..80].copy_from_slice(&4096u64.to_le_bytes()); // f_frsize
    b[80..88].copy_from_slice(&1u64.to_le_bytes()); // f_flags = ST_RDONLY
    if mem.write(addr, &b) { 0 } else { -EFAULT }
}

fn put_statx(mem: &GuestMem, addr: u64, st: &Stat) -> i64 {
    let mut b = [0u8; 256];
    let mut put = |off: usize, v: &[u8]| b[off..off + v.len()].copy_from_slice(v);
    put(0, &0x7ffu32.to_le_bytes()); // STATX_BASIC_STATS
    put(4, &4096u32.to_le_bytes());
    put(16, &st.nlink.to_le_bytes());
    put(20, &st.uid.to_le_bytes());
    put(24, &st.gid.to_le_bytes());
    put(28, &(st.mode as u16).to_le_bytes());
    put(32, &st.ino.to_le_bytes());
    put(40, &st.size.to_le_bytes());
    put(48, &st.size.div_ceil(512).to_le_bytes());
    for t in [64, 80, 96, 112] {
        put(t, &st.mtime.to_le_bytes()); // atime, btime, ctime, mtime
    }
    put(128, &((st.rdev >> 8) as u32 & 0xfff).to_le_bytes());
    put(132, &(st.rdev as u32 & 0xff).to_le_bytes());
    put(140, &(st.dev as u32).to_le_bytes());
    if mem.write(addr, &b) { 0 } else { -EFAULT }
}

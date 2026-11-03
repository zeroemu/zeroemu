//! File descriptors: the open files of a process, pipes, and the file and
//! directory syscalls over the read-only VFS.

use super::epoll::Epoll;
use super::specialfd::{EventFd, SignalFd, TimerFd};
use super::unix::{self, Socket};
use super::wait::EVENTS;
use super::{ERESTARTSYS, Kernel, POLL, Thread, int};
use crate::arch::Sysno;
use crate::errno::*;
use crate::mm::SharedObject;
use crate::phys;
use crate::tmpfs::MemFile;
use crate::vfs::{Dirent, Node, S_IFDIR, S_IFLNK, S_IFMT, S_IFREG, Stat};
use std::collections::VecDeque;
use std::io::{Read, Write};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

const AT_FDCWD: i64 = -100;
const AT_SYMLINK_NOFOLLOW: u64 = 0x100;
const AT_EMPTY_PATH: u64 = 0x1000;
const O_ACCMODE: u32 = 3;
const O_WRONLY: u32 = 1;
const O_RDWR: u32 = 2;
const O_CREAT: u64 = 0o100;
const O_EXCL: u64 = 0o200;
const O_TRUNC: u64 = 0o1000;
const O_TMPFILE: u64 = 0o20000000;
const AT_REMOVEDIR: u64 = 0x200;
const S_IFCHR: u32 = 0o020000;
const O_APPEND: u32 = 0o2000;
const O_NONBLOCK: u32 = 0o4000;
const O_CLOEXEC: u64 = 0o2000000;
const F_DUPFD: u64 = 0;
const F_GETFD: u64 = 1;
const F_SETFD: u64 = 2;
const F_GETFL: u64 = 3;
const F_SETFL: u64 = 4;
const F_GETLK: u64 = 5;
const F_SETLK: u64 = 6;
const F_SETLKW: u64 = 7;
const F_DUPFD_CLOEXEC: u64 = 1030;
const F_GETPIPE_SZ: u64 = 1032;
const FD_CLOEXEC: u64 = 1;
const PIPE_CAP: usize = 64 << 10;
/// Largest single read/write we copy at once (Linux caps at ~2 GiB).
const IO_MAX: u64 = 16 << 20;

pub fn handles(no: Sysno) -> bool {
    use Sysno::*;
    matches!(
        no,
        openat | close | read | pread64 | readv | write | writev | pwrite64 | lseek | fstat | newfstatat | statx | faccessat
            | faccessat2 | readlinkat | getdents64 | getcwd | chdir | fchdir | dup | dup2 | dup3 | fcntl | ioctl | statfs
            | fstatfs | umask | pipe2 | ppoll | eventfd2 | epoll_create1 | epoll_ctl | epoll_pwait | timerfd_create
            | timerfd_settime | timerfd_gettime | signalfd4 | mknodat | mkdirat | unlinkat | symlinkat | linkat | renameat
            | renameat2 | truncate | ftruncate | fallocate | fchmod | fchmodat | fchown | fchownat | sync | fsync | fdatasync
            | utimensat | memfd_create
    )
}

pub enum Kind {
    Stdin,
    Stdout,
    Stderr,
    Null,
    Zero,
    Random,
    Node(Mutex<NodeFile>),
    /// A writable regular file (tmpfs or memfd): live contents.
    Mem(MemOpen),
    Pipe(PipeEnd),
    Event(EventFd),
    Timer(TimerFd),
    Signal(SignalFd),
    Epoll(Epoll),
    Socket(Arc<Socket>),
}

/// An open file description, shared by dup'd and inherited descriptors.
pub struct File {
    pub kind: Kind,
    flags: AtomicU32,
}

impl File {
    pub(super) fn new(kind: Kind, flags: u32) -> Arc<File> {
        Arc::new(File { kind, flags: AtomicU32::new(flags) })
    }
    pub(super) fn nonblock(&self) -> bool {
        self.flags.load(Ordering::Relaxed) & O_NONBLOCK != 0
    }
}

pub struct MemOpen {
    /// None for memfds, which have no name in the namespace.
    node: Option<Node>,
    name: String,
    pub file: Arc<MemFile>,
    pos: Mutex<u64>,
    readable: bool,
    writable: bool,
}

pub struct NodeFile {
    node: Node,
    stat: Stat,
    pos: u64,
    data: Option<Arc<[u8]>>,
    dents: Option<Vec<Dirent>>,
}

#[derive(Clone)]
struct Entry {
    file: Arc<File>,
    cloexec: bool,
}

#[derive(Clone)]
pub struct FdTable {
    fds: Vec<Option<Entry>>,
}

impl FdTable {
    pub fn stdio() -> FdTable {
        let e = |k| Some(Entry { file: File::new(k, 0), cloexec: false });
        FdTable { fds: vec![e(Kind::Stdin), e(Kind::Stdout), e(Kind::Stderr)] }
    }

    pub fn empty() -> FdTable {
        FdTable { fds: Vec::new() }
    }

    pub(super) fn get(&self, fd: i64) -> Result<Arc<File>, i64> {
        usize::try_from(fd).ok().and_then(|i| self.fds.get(i)).and_then(|e| e.as_ref()).map(|e| e.file.clone()).ok_or(EBADF)
    }

    fn entry_mut(&mut self, fd: i64) -> Result<&mut Entry, i64> {
        usize::try_from(fd).ok().and_then(|i| self.fds.get_mut(i)).and_then(|e| e.as_mut()).ok_or(EBADF)
    }

    pub(super) fn alloc(&mut self, file: Arc<File>, cloexec: bool, min: usize) -> Result<i64, i64> {
        let slot = (min..).find(|&i| self.fds.get(i).is_none_or(|s| s.is_none())).unwrap();
        if slot >= 1024 {
            return Err(EMFILE);
        }
        if self.fds.len() <= slot {
            self.fds.resize_with(slot + 1, || None);
        }
        self.fds[slot] = Some(Entry { file, cloexec });
        Ok(slot as i64)
    }

    pub(super) fn close(&mut self, fd: i64) {
        if let Some(slot) = usize::try_from(fd).ok().and_then(|i| self.fds.get_mut(i)) {
            *slot = None;
        }
    }

    fn put(&mut self, fd: usize, file: Arc<File>, cloexec: bool) {
        if self.fds.len() <= fd {
            self.fds.resize_with(fd + 1, || None);
        }
        self.fds[fd] = Some(Entry { file, cloexec });
    }

    /// Open descriptors, in order.
    pub(super) fn list(&self) -> Vec<(i64, Arc<File>)> {
        self.fds.iter().enumerate().filter_map(|(i, e)| e.as_ref().map(|e| (i as i64, e.file.clone()))).collect()
    }

    pub fn close_on_exec(&mut self) {
        for slot in &mut self.fds {
            if slot.as_ref().is_some_and(|e| e.cloexec) {
                *slot = None;
            }
        }
    }
}

// ---- pipes ----

pub struct Pipe {
    st: Mutex<PipeState>,
    cv: Condvar,
}

struct PipeState {
    buf: VecDeque<u8>,
    readers: usize,
    writers: usize,
}

pub struct PipeEnd {
    pipe: Arc<Pipe>,
    write: bool,
}

impl Drop for PipeEnd {
    fn drop(&mut self) {
        let mut st = self.pipe.st.lock().unwrap();
        if self.write {
            st.writers -= 1;
        } else {
            st.readers -= 1;
        }
        self.pipe.cv.notify_all();
        drop(st);
        EVENTS.bump();
    }
}

impl Pipe {
    fn read(&self, t: &Thread, max: usize, nonblock: bool) -> Result<Vec<u8>, i64> {
        let mut st = self.st.lock().unwrap();
        loop {
            if !st.buf.is_empty() {
                let n = max.min(st.buf.len());
                let out: Vec<u8> = st.buf.drain(..n).collect();
                self.cv.notify_all();
                drop(st);
                EVENTS.bump();
                return Ok(out);
            }
            if st.writers == 0 || max == 0 {
                return Ok(Vec::new());
            }
            if nonblock {
                return Err(EAGAIN);
            }
            if t.interrupted() {
                return Err(ERESTARTSYS);
            }
            st = self.cv.wait_timeout(st, POLL).unwrap().0;
        }
    }

    fn write(&self, t: &Thread, data: &[u8], nonblock: bool) -> Result<usize, i64> {
        let mut st = self.st.lock().unwrap();
        let mut done = 0;
        loop {
            if st.readers == 0 {
                return Err(EPIPE);
            }
            let room = PIPE_CAP.saturating_sub(st.buf.len());
            if room > 0 {
                let n = room.min(data.len() - done);
                st.buf.extend(&data[done..done + n]);
                done += n;
                self.cv.notify_all();
                EVENTS.bump();
                if done == data.len() {
                    return Ok(done);
                }
            }
            if nonblock {
                return if done > 0 { Ok(done) } else { Err(EAGAIN) };
            }
            if t.interrupted() {
                return if done > 0 { Ok(done) } else { Err(ERESTARTSYS) };
            }
            st = self.cv.wait_timeout(st, POLL).unwrap().0;
        }
    }
}

const POLLIN: u16 = 0x1;
const POLLOUT: u16 = 0x4;
const POLLERR: u16 = 0x8;
const POLLHUP: u16 = 0x10;
const POLLNVAL: u16 = 0x20;

/// Current poll(2) readiness of an open file. `depth` bounds nested epolls.
pub(super) fn poll_ready(f: &File, t: &Thread, depth: u32) -> u16 {
    match &f.kind {
        Kind::Event(e) => (if e.ready_in() { POLLIN } else { 0 }) | if e.ready_out() { POLLOUT } else { 0 },
        Kind::Timer(tf) => if tf.ready_in() { POLLIN } else { 0 },
        Kind::Signal(sf) => if sf.ready_in(t) { POLLIN } else { 0 },
        Kind::Epoll(ep) => if ep.is_ready(t, depth) { POLLIN } else { 0 },
        Kind::Socket(s) => s.poll(),
        Kind::Stdin => POLLIN,
        Kind::Stdout | Kind::Stderr => POLLOUT,
        Kind::Null | Kind::Zero | Kind::Random | Kind::Node(_) | Kind::Mem(_) => POLLIN | POLLOUT,
        Kind::Pipe(end) => {
            let st = end.pipe.st.lock().unwrap();
            if end.write {
                if st.readers == 0 { POLLERR } else if st.buf.len() < PIPE_CAP { POLLOUT } else { 0 }
            } else {
                let mut r = if st.buf.is_empty() { 0 } else { POLLIN };
                if st.writers == 0 {
                    r |= POLLHUP;
                }
                r
            }
        }
    }
}

// ---- syscalls ----

impl Kernel {
    pub(super) fn file_syscall(&self, no: Sysno, t: &Arc<Thread>, a: [u64; 6]) -> Result<i64, i64> {
        use Sysno::*;
        match no {
            openat => self.openat(t, int(a[0]), a[1], a[2], a[3]),
            close => {
                let mut files = t.proc.files.lock().unwrap();
                let slot = usize::try_from(int(a[0])).ok().and_then(|i| files.fds.get_mut(i)).ok_or(EBADF)?;
                slot.take().map(|_| 0).ok_or(EBADF)
            }
            read => self.read(t, int(a[0]), a[1], a[2], None),
            pread64 => self.read(t, int(a[0]), a[1], a[2], Some(a[3])),
            readv => {
                let mut total = 0;
                for i in 0..a[2].min(1024) {
                    let (base, len) = {
                        let mut mm = t.proc.mm();
                        (mm.read_u64(a[1] + i * 16)?, mm.read_u64(a[1] + i * 16 + 8)?)
                    };
                    match self.read(t, int(a[0]), base, len, None) {
                        Ok(n) => {
                            total += n;
                            if (n as u64) < len {
                                break;
                            }
                        }
                        Err(e) if total == 0 => return Err(e),
                        Err(_) => break,
                    }
                }
                Ok(total)
            }
            write => self.write(t, int(a[0]), a[1], a[2]),
            pwrite64 => self.write_at(t, int(a[0]), a[1], a[2], Some(a[3])),
            writev => {
                let mut total = 0;
                for i in 0..a[2].min(1024) {
                    let (base, len) = {
                        let mut mm = t.proc.mm();
                        (mm.read_u64(a[1] + i * 16)?, mm.read_u64(a[1] + i * 16 + 8)?)
                    };
                    match self.write(t, int(a[0]), base, len) {
                        Ok(n) => total += n,
                        Err(e) if total == 0 => return Err(e),
                        Err(_) => break,
                    }
                }
                Ok(total)
            }
            lseek => {
                let f = t.proc.files.lock().unwrap().get(int(a[0]))?;
                if let Kind::Mem(m) = &f.kind {
                    let mut pos = m.pos.lock().unwrap();
                    let base = match a[2] {
                        0 => 0,
                        1 => *pos as i64,
                        2 => m.file.size() as i64,
                        _ => return Err(EINVAL),
                    };
                    let new = base.checked_add(a[1] as i64).filter(|&n| n >= 0).ok_or(EINVAL)?;
                    *pos = new as u64;
                    return Ok(new);
                }
                let Kind::Node(nf) = &f.kind else { return Err(ESPIPE) };
                let mut nf = nf.lock().unwrap();
                let base = match a[2] {
                    0 => 0,
                    1 => nf.pos as i64,
                    2 => nf.stat.size as i64,
                    _ => return Err(EINVAL),
                };
                let new = base.checked_add(a[1] as i64).filter(|&n| n >= 0).ok_or(EINVAL)?;
                nf.pos = new as u64;
                Ok(new)
            }
            fstat => {
                let st = self.fd_stat(t, int(a[0]))?;
                t.proc.mm().write(a[1], &self.arch.encode_stat(&st))?;
                Ok(0)
            }
            newfstatat => {
                let st = self.path_stat(t, int(a[0]), a[1], a[3])?;
                t.proc.mm().write(a[2], &self.arch.encode_stat(&st))?;
                Ok(0)
            }
            statx => {
                let st = self.path_stat(t, int(a[0]), a[1], a[2])?;
                t.proc.mm().write(a[4], &statx_bytes(&st))?;
                Ok(0)
            }
            faccessat | faccessat2 => {
                let path = t.proc.mm().read_cstr(a[1])?;
                let node = self.resolve(t, int(a[0]), &path, true)?;
                if a[2] & 2 != 0 && !self.vfs()?.writable(&node) { Err(EROFS) } else { Ok(0) } // W_OK
            }
            readlinkat => self.readlinkat(t, int(a[0]), a[1], a[2], a[3]),
            getdents64 => self.getdents64(t, int(a[0]), a[1], a[2]),
            getcwd => {
                let mut s = t.proc.cwd.lock().unwrap().clone().into_bytes();
                s.push(0);
                if s.len() as u64 > a[1] {
                    return Err(ERANGE);
                }
                t.proc.mm().write(a[0], &s)?;
                Ok(s.len() as i64)
            }
            chdir => {
                let path = t.proc.mm().read_cstr(a[0])?;
                let node = self.resolve(t, AT_FDCWD, &path, true)?;
                if self.vfs()?.stat(&node)?.mode & S_IFMT != S_IFDIR {
                    return Err(ENOTDIR);
                }
                *t.proc.cwd.lock().unwrap() = node.path;
                Ok(0)
            }
            fchdir => {
                let dir = self.dir_path(t, int(a[0]))?;
                *t.proc.cwd.lock().unwrap() = dir;
                Ok(0)
            }
            dup => {
                let mut files = t.proc.files.lock().unwrap();
                let f = files.get(int(a[0]))?;
                files.alloc(f, false, 0)
            }
            dup2 | dup3 => {
                let (old, new) = (int(a[0]), int(a[1]));
                let flags = if no == dup3 { a[2] } else { 0 };
                let mut files = t.proc.files.lock().unwrap();
                let f = files.get(old)?;
                if old == new {
                    return if no == dup3 { Err(EINVAL) } else { Ok(new) };
                }
                if !(0..1024).contains(&new) {
                    return Err(EBADF);
                }
                files.put(new as usize, f, flags & O_CLOEXEC != 0);
                Ok(new)
            }
            fcntl => {
                let fd = int(a[0]);
                let mut files = t.proc.files.lock().unwrap();
                match a[1] {
                    F_DUPFD | F_DUPFD_CLOEXEC => {
                        let f = files.get(fd)?;
                        files.alloc(f, a[1] == F_DUPFD_CLOEXEC, a[2] as usize)
                    }
                    F_GETFD => Ok(if files.entry_mut(fd)?.cloexec { FD_CLOEXEC as i64 } else { 0 }),
                    F_SETFD => {
                        files.entry_mut(fd)?.cloexec = a[2] & FD_CLOEXEC != 0;
                        Ok(0)
                    }
                    F_GETFL => {
                        let f = files.get(fd)?;
                        let acc = match &f.kind {
                            Kind::Stdout | Kind::Stderr => O_WRONLY,
                            Kind::Pipe(p) if p.write => O_WRONLY,
                            _ => 0,
                        };
                        Ok((acc | f.flags.load(Ordering::Relaxed)) as i64)
                    }
                    F_SETFL => {
                        let f = files.get(fd)?;
                        f.flags.store(a[2] as u32 & (O_NONBLOCK | O_APPEND), Ordering::Relaxed);
                        Ok(0)
                    }
                    F_GETLK | F_SETLK | F_SETLKW => files.get(fd).map(|_| 0), // no locking: one writer can't exist on a read-only image
                    F_GETPIPE_SZ => files.get(fd).map(|_| PIPE_CAP as i64),
                    _ => Err(EINVAL),
                }
            }
            ioctl => {
                const FIONCLEX: u64 = 0x5450;
                const FIOCLEX: u64 = 0x5451;
                const FIONBIO: u64 = 0x5421;
                let fd = int(a[0]);
                let mut files = t.proc.files.lock().unwrap();
                match a[1] {
                    FIOCLEX | FIONCLEX => {
                        files.entry_mut(fd)?.cloexec = a[1] == FIOCLEX;
                        Ok(0)
                    }
                    FIONBIO => {
                        let f = files.get(fd)?;
                        let on = t.proc.mm().read_u32(a[2])? != 0;
                        if on { f.flags.fetch_or(O_NONBLOCK, Ordering::Relaxed) } else { f.flags.fetch_and(!O_NONBLOCK, Ordering::Relaxed) };
                        Ok(0)
                    }
                    _ => files.get(fd).and(Err(ENOTTY)), // nothing is a terminal yet
                }
            }
            fstatfs => {
                t.proc.files.lock().unwrap().get(int(a[0]))?;
                t.proc.mm().write(a[1], &statfs_bytes())?;
                Ok(0)
            }
            statfs => {
                let path = t.proc.mm().read_cstr(a[0])?;
                self.resolve(t, AT_FDCWD, &path, true)?;
                t.proc.mm().write(a[1], &statfs_bytes())?;
                Ok(0)
            }
            umask => Ok(0o022),
            pipe2 => {
                let shared = Arc::new(Pipe { st: Mutex::new(PipeState { buf: VecDeque::new(), readers: 1, writers: 1 }), cv: Condvar::new() });
                let flags = a[1] as u32 & O_NONBLOCK;
                let cloexec = a[1] & O_CLOEXEC != 0;
                let r = File::new(Kind::Pipe(PipeEnd { pipe: shared.clone(), write: false }), flags);
                let w = File::new(Kind::Pipe(PipeEnd { pipe: shared, write: true }), flags);
                let (rfd, wfd) = {
                    let mut files = t.proc.files.lock().unwrap();
                    let rfd = files.alloc(r, cloexec, 0)?;
                    match files.alloc(w, cloexec, 0) {
                        Ok(wfd) => (rfd, wfd),
                        Err(e) => {
                            files.fds[rfd as usize] = None;
                            return Err(e);
                        }
                    }
                };
                let mut fds = [0u8; 8];
                fds[..4].copy_from_slice(&(rfd as i32).to_le_bytes());
                fds[4..].copy_from_slice(&(wfd as i32).to_le_bytes());
                if let Err(e) = t.proc.mm().write(a[0], &fds) {
                    let mut files = t.proc.files.lock().unwrap();
                    files.fds[rfd as usize] = None;
                    files.fds[wfd as usize] = None;
                    return Err(e);
                }
                Ok(0)
            }
            ppoll => self.ppoll(t, a[0], a[1], a[2], a[3]),
            mknodat | mkdirat | unlinkat | symlinkat | linkat | renameat | renameat2 | truncate | ftruncate | fallocate | fchmod
            | fchmodat | fchown | fchownat | sync | fsync | fdatasync | utimensat | memfd_create => self.change_syscall(no, t, a),
            eventfd2 => {
                let f = File::new(Kind::Event(EventFd::new(a[0] as u32 as u64, a[1])), a[1] as u32 & O_NONBLOCK);
                t.proc.files.lock().unwrap().alloc(f, a[1] & O_CLOEXEC != 0, 0)
            }
            epoll_create1 => {
                if a[0] & !O_CLOEXEC != 0 {
                    return Err(EINVAL);
                }
                let f = File::new(Kind::Epoll(Epoll::default()), 0);
                t.proc.files.lock().unwrap().alloc(f, a[0] & O_CLOEXEC != 0, 0)
            }
            epoll_ctl => {
                let (ep, target) = {
                    let files = t.proc.files.lock().unwrap();
                    (files.get(int(a[0]))?, files.get(int(a[2]))?)
                };
                let Kind::Epoll(epoll) = &ep.kind else { return Err(EINVAL) };
                if Arc::ptr_eq(&ep, &target) {
                    return Err(EINVAL);
                }
                let (events, data) = if a[1] == 2 {
                    (0, 0) // EPOLL_CTL_DEL ignores the event
                } else {
                    let (size, data_off) = self.arch.epoll_event_layout();
                    let b = t.proc.mm().read_vec(a[3], size)?;
                    (u32::from_le_bytes(b[0..4].try_into().unwrap()), u64::from_le_bytes(b[data_off..data_off + 8].try_into().unwrap()))
                };
                epoll.ctl(a[1], int(a[2]) as i32, &target, events, data).map(|_| 0)
            }
            epoll_pwait => self.epoll_pwait(t, int(a[0]), a[1], int(a[2]), int(a[3]), a[4]),
            timerfd_create => {
                let tf = TimerFd::new(a[0], self.boot)?;
                let f = File::new(Kind::Timer(tf), a[1] as u32 & O_NONBLOCK);
                t.proc.files.lock().unwrap().alloc(f, a[1] & O_CLOEXEC != 0, 0)
            }
            timerfd_settime => {
                let f = t.proc.files.lock().unwrap().get(int(a[0]))?;
                let Kind::Timer(tf) = &f.kind else { return Err(EINVAL) };
                let new = t.proc.mm().read_vec(a[2], 32)?;
                let old = tf.settime(a[1], &new);
                if a[3] != 0 {
                    t.proc.mm().write(a[3], &old)?;
                }
                Ok(0)
            }
            timerfd_gettime => {
                let f = t.proc.files.lock().unwrap().get(int(a[0]))?;
                let Kind::Timer(tf) = &f.kind else { return Err(EINVAL) };
                t.proc.mm().write(a[1], &tf.gettime())?;
                Ok(0)
            }
            signalfd4 => {
                let mask = t.proc.mm().read_u64(a[1])? & !((1 << 8) | (1 << 18)); // never SIGKILL/SIGSTOP
                if int(a[0]) != -1 {
                    let f = t.proc.files.lock().unwrap().get(int(a[0]))?;
                    let Kind::Signal(sf) = &f.kind else { return Err(EINVAL) };
                    sf.mask.store(mask, Ordering::Relaxed);
                    return Ok(int(a[0]));
                }
                let f = File::new(Kind::Signal(SignalFd { mask: AtomicU64::new(mask) }), a[3] as u32 & O_NONBLOCK);
                t.proc.files.lock().unwrap().alloc(f, a[3] & O_CLOEXEC != 0, 0)
            }
            _ => Err(ENOSYS),
        }
    }

    fn vfs(&self) -> Result<&crate::vfs::Vfs, i64> {
        self.vfs.as_deref().ok_or(ENOENT)
    }

    fn dir_path(&self, t: &Thread, dirfd: i64) -> Result<String, i64> {
        if dirfd == AT_FDCWD {
            return Ok(t.proc.cwd.lock().unwrap().clone());
        }
        let f = t.proc.files.lock().unwrap().get(dirfd)?;
        let Kind::Node(nf) = &f.kind else { return Err(ENOTDIR) };
        let nf = nf.lock().unwrap();
        if nf.stat.mode & S_IFMT != S_IFDIR {
            return Err(ENOTDIR);
        }
        Ok(nf.node.path.clone())
    }

    pub(super) fn resolve(&self, t: &Thread, dirfd: i64, path: &str, follow: bool) -> Result<Node, i64> {
        // /proc/self and /proc/thread-self name the caller.
        let rewritten;
        let path = if let Some(rest) = path.strip_prefix("/proc/self").filter(|r| r.is_empty() || r.starts_with('/')) {
            rewritten = format!("/proc/{}{rest}", t.proc.pid);
            rewritten.as_str()
        } else if let Some(rest) = path.strip_prefix("/proc/thread-self").filter(|r| r.is_empty() || r.starts_with('/')) {
            rewritten = format!("/proc/{}/task/{}{rest}", t.proc.pid, t.tid);
            rewritten.as_str()
        } else {
            path
        };
        // Magic links: reopening the file itself, not its name.
        let self_pid = format!("/proc/{}/", t.proc.pid);
        let proc_rel = path.strip_prefix("/proc/self/").or_else(|| path.strip_prefix(self_pid.as_str()));
        if let Some(rel) = proc_rel.filter(|_| follow) {
            if rel == "exe" {
                let exe = t.proc.exe.lock().unwrap().clone();
                return self.vfs()?.resolve("/", &exe, true);
            }
            if let Some(fd) = rel.strip_prefix("fd/").and_then(|n| n.parse::<i64>().ok()) {
                let f = t.proc.files.lock().unwrap().get(fd).map_err(|_| ENOENT)?;
                return match &f.kind {
                    Kind::Node(nf) => Ok(nf.lock().unwrap().node.clone()),
                    Kind::Mem(m) => m.node.clone().ok_or(ENOENT),
                    _ => Err(ENOENT),
                };
            }
        }
        let base = if path.starts_with('/') { "/".to_string() } else { self.dir_path(t, dirfd)? };
        self.vfs()?.resolve(&base, path, follow)
    }

    fn openat(&self, t: &Arc<Thread>, dirfd: i64, path: u64, flags: u64, mode: u64) -> Result<i64, i64> {
        let path = t.proc.mm().read_cstr(path)?;
        let cloexec = flags & O_CLOEXEC != 0;
        let status = flags as u32 & (O_NONBLOCK | O_APPEND);
        let access = flags as u32 & O_ACCMODE;
        let of = self.arch.open_flags();
        if flags & O_TMPFILE == O_TMPFILE {
            return Err(EOPNOTSUPP);
        }
        let node = match self.resolve(t, dirfd, &path, flags & of.nofollow == 0) {
            Ok(_) if flags & O_CREAT != 0 && flags & O_EXCL != 0 => return Err(EEXIST),
            Ok(n) => n,
            Err(ENOENT) if flags & O_CREAT != 0 => {
                let (dir, name) = self.parent(t, dirfd, &path)?;
                self.vfs()?.create(&dir, &name, S_IFREG | (mode as u32 & 0o7777 & !0o022), 0)?
            }
            Err(e) => return Err(e),
        };
        let vfs = self.vfs()?;
        let stat = vfs.stat(&node)?;
        let kind = match stat.mode & S_IFMT {
            S_IFCHR => match stat.rdev {
                0x103 => Kind::Null,
                0x105 => Kind::Zero,
                0x108 | 0x109 => Kind::Random,
                _ => return Err(ENXIO),
            },
            S_IFDIR if access != 0 => return Err(EISDIR),
            _ if flags & of.directory != 0 && stat.mode & S_IFMT != S_IFDIR => return Err(ENOTDIR),
            S_IFREG if vfs.writable(&node) => {
                let file = vfs.mem_file(&node).ok_or(EIO)?;
                if flags & O_TRUNC != 0 && access != 0 {
                    file.truncate(0);
                }
                Kind::Mem(MemOpen {
                    name: node.path.clone(),
                    node: Some(node),
                    file,
                    pos: Mutex::new(0),
                    readable: access != O_WRONLY,
                    writable: access == O_WRONLY || access == O_RDWR,
                })
            }
            _ if access != 0 => return Err(EROFS),
            _ => Kind::Node(Mutex::new(NodeFile { node, stat, pos: 0, data: None, dents: None })),
        };
        t.proc.files.lock().unwrap().alloc(File::new(kind, status), cloexec, 0)
    }

    /// (directory, final name) of a path relative to `dirfd`.
    fn parent(&self, t: &Thread, dirfd: i64, path: &str) -> Result<(Node, String), i64> {
        let base = if path.starts_with('/') { "/".to_string() } else { self.dir_path(t, dirfd)? };
        self.vfs()?.resolve_parent(&base, path)
    }

    /// The node a path-or-fd syscall (fchmodat, utimensat…) refers to.
    fn target(&self, t: &Thread, dirfd: i64, path: u64, flags: u64) -> Result<Node, i64> {
        let p = if path == 0 { String::new() } else { t.proc.mm().read_cstr(path)? };
        if p.is_empty() && (path == 0 || flags & AT_EMPTY_PATH != 0) {
            let f = t.proc.files.lock().unwrap().get(dirfd)?;
            return match &f.kind {
                Kind::Node(nf) => Ok(nf.lock().unwrap().node.clone()),
                Kind::Mem(m) => m.node.clone().ok_or(EBADF),
                _ => Err(EBADF),
            };
        }
        self.resolve(t, dirfd, &p, flags & AT_SYMLINK_NOFOLLOW == 0)
    }

    fn mem(&self, t: &Thread, fd: i64) -> Result<Arc<File>, i64> {
        let f = t.proc.files.lock().unwrap().get(fd)?;
        match &f.kind {
            Kind::Mem(_) => Ok(f),
            Kind::Node(_) => Err(EINVAL),
            _ => Err(EINVAL),
        }
    }

    /// Namespace-changing and attribute syscalls over the writable mounts.
    fn change_syscall(&self, no: Sysno, t: &Arc<Thread>, a: [u64; 6]) -> Result<i64, i64> {
        use Sysno::*;
        let vfs = self.vfs()?;
        match no {
            mknodat | mkdirat => {
                let path = t.proc.mm().read_cstr(a[1])?;
                let (dir, name) = self.parent(t, int(a[0]), &path)?;
                if no == mkdirat {
                    vfs.mkdir(&dir, &name, a[2] as u32 & !0o022)?;
                } else {
                    vfs.create(&dir, &name, a[2] as u32, a[3])?;
                }
                Ok(0)
            }
            unlinkat => {
                let path = t.proc.mm().read_cstr(a[1])?;
                let (dir, name) = self.parent(t, int(a[0]), &path)?;
                vfs.unlink(&dir, &name, a[2] & AT_REMOVEDIR != 0)?;
                Ok(0)
            }
            symlinkat => {
                let target = t.proc.mm().read_cstr(a[0])?;
                let path = t.proc.mm().read_cstr(a[2])?;
                let (dir, name) = self.parent(t, int(a[1]), &path)?;
                vfs.symlink(&dir, &name, &target)?;
                Ok(0)
            }
            linkat => {
                let old = self.target(t, int(a[0]), a[1], a[4] ^ AT_SYMLINK_NOFOLLOW)?; // no-follow by default
                let path = t.proc.mm().read_cstr(a[3])?;
                let (dir, name) = self.parent(t, int(a[2]), &path)?;
                vfs.link(&old, &dir, &name)?;
                Ok(0)
            }
            renameat | renameat2 => {
                const RENAME_NOREPLACE: u64 = 1;
                let flags = if no == renameat2 { a[4] } else { 0 };
                if flags & !RENAME_NOREPLACE != 0 {
                    return Err(EINVAL);
                }
                let (op, np) = {
                    let mut mm = t.proc.mm();
                    (mm.read_cstr(a[1])?, mm.read_cstr(a[3])?)
                };
                let (odir, oname) = self.parent(t, int(a[0]), &op)?;
                let (ndir, nname) = self.parent(t, int(a[2]), &np)?;
                vfs.rename(&odir, &oname, &ndir, &nname, flags & RENAME_NOREPLACE != 0)?;
                Ok(0)
            }
            truncate => {
                let path = t.proc.mm().read_cstr(a[0])?;
                let node = self.resolve(t, AT_FDCWD, &path, true)?;
                vfs.mem_file(&node).ok_or(if vfs.writable(&node) { EISDIR } else { EROFS })?.truncate(a[1]);
                Ok(0)
            }
            ftruncate | fallocate => {
                let f = self.mem(t, int(a[0]))?;
                let Kind::Mem(m) = &f.kind else { unreachable!() };
                if !m.writable {
                    return Err(EINVAL);
                }
                if no == ftruncate {
                    m.file.truncate(a[1]);
                } else if a[2] + a[3] > m.file.size() && a[1] & 1 == 0 {
                    m.file.truncate(a[2] + a[3]); // FALLOC_FL_KEEP_SIZE (1) unset: extend
                }
                Ok(0)
            }
            fchmod | fchown => {
                let node = self.target(t, int(a[0]), 0, 0)?;
                if no == fchmod {
                    vfs.set_attr(&node, Some(a[1] as u32), None, None)?;
                } else {
                    vfs.set_attr(&node, None, Some((a[1] as u32, a[2] as u32)), None)?;
                }
                Ok(0)
            }
            fchmodat => {
                let node = self.target(t, int(a[0]), a[1], 0)?;
                vfs.set_attr(&node, Some(a[2] as u32), None, None)?;
                Ok(0)
            }
            fchownat => {
                let node = self.target(t, int(a[0]), a[1], a[4])?;
                vfs.set_attr(&node, None, Some((a[2] as u32, a[3] as u32)), None)?;
                Ok(0)
            }
            utimensat => {
                let node = self.target(t, int(a[0]), a[1], a[3])?;
                let mtime = if a[2] == 0 {
                    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs())
                } else {
                    t.proc.mm().read_u64(a[2] + 16)? // times[1].tv_sec
                };
                match vfs.set_attr(&node, None, None, Some(mtime)) {
                    Err(EROFS) => Ok(0), // touching image files: accepted, not recorded
                    r => r.map(|_| 0),
                }
            }
            sync | fsync | fdatasync => Ok(0),
            memfd_create => {
                const MFD_CLOEXEC: u64 = 1;
                let name = t.proc.mm().read_cstr(a[0])?;
                let file = MemFile::new(self.phys.clone());
                let m = MemOpen { node: None, name: format!("/memfd:{name} (deleted)"), file, pos: Mutex::new(0), readable: true, writable: true };
                t.proc.files.lock().unwrap().alloc(File::new(Kind::Mem(m), 0), a[1] & MFD_CLOEXEC != 0, 0)
            }
            _ => Err(ENOSYS),
        }
    }

    /// The path of a mapped file, for /proc/<pid>/maps.
    pub(super) fn fd_name(&self, t: &Thread, fd: i64) -> Option<String> {
        let f = t.proc.files.lock().unwrap().get(fd).ok()?;
        Some(file_name(&f))
    }

    /// For MAP_SHARED of a file: the shared pages behind a writable file.
    pub(super) fn fd_shared_object(&self, t: &Thread, fd: i64) -> Result<Option<Arc<SharedObject>>, i64> {
        let f = t.proc.files.lock().unwrap().get(fd)?;
        Ok(match &f.kind {
            Kind::Mem(m) => Some(m.file.obj.clone()),
            _ => None,
        })
    }

    fn node_data(&self, nf: &mut NodeFile) -> Result<Arc<[u8]>, i64> {
        if nf.stat.mode & S_IFMT == S_IFDIR {
            return Err(EISDIR);
        }
        if nf.data.is_none() {
            nf.data = Some(self.vfs()?.read_all(&nf.node)?);
        }
        Ok(nf.data.clone().unwrap())
    }

    /// Contents of a regular file behind `fd` (for file-backed mmap).
    pub(super) fn fd_file_data(&self, t: &Thread, fd: i64) -> Result<Arc<[u8]>, i64> {
        let f = t.proc.files.lock().unwrap().get(fd)?;
        if let Kind::Mem(m) = &f.kind {
            return Ok(m.file.read_at(0, usize::MAX).into()); // MAP_PRIVATE: a snapshot
        }
        let Kind::Node(nf) = &f.kind else { return Err(ENODEV) };
        let mut nf = nf.lock().unwrap();
        if nf.stat.mode & S_IFMT == S_IFDIR {
            return Err(ENODEV);
        }
        self.node_data(&mut nf)
    }

    fn read(&self, t: &Thread, fd: i64, buf: u64, count: u64, at: Option<u64>) -> Result<i64, i64> {
        let f = t.proc.files.lock().unwrap().get(fd)?;
        let count = count.min(IO_MAX) as usize;
        let data = match &f.kind {
            Kind::Stdin => {
                let mut v = vec![0; count.min(64 << 10)];
                let n = std::io::stdin().read(&mut v).map_err(|_| EIO)?;
                v.truncate(n);
                v
            }
            Kind::Null => Vec::new(),
            Kind::Zero => vec![0; count],
            Kind::Random => {
                let mut v = vec![0; count];
                phys::random_bytes(&mut v);
                v
            }
            Kind::Pipe(end) if !end.write => end.pipe.read(t, count, f.nonblock())?,
            Kind::Event(e) => {
                if count < 8 {
                    return Err(EINVAL);
                }
                e.read(t, f.nonblock())?.to_le_bytes().to_vec()
            }
            Kind::Timer(tf) => {
                if count < 8 {
                    return Err(EINVAL);
                }
                tf.read(t, f.nonblock())?.to_le_bytes().to_vec()
            }
            Kind::Signal(sf) => sf.read(t, count, f.nonblock())?,
            Kind::Mem(m) => {
                if !m.readable {
                    return Err(EBADF);
                }
                let mut pos = m.pos.lock().unwrap();
                let off = at.unwrap_or(*pos);
                let data = m.file.read_at(off, count);
                if at.is_none() {
                    *pos += data.len() as u64;
                }
                data
            }
            Kind::Socket(sock) => unix::read(sock, t, count, f.nonblock())?,
            Kind::Node(nf) => {
                let mut nf = nf.lock().unwrap();
                let data = self.node_data(&mut nf)?;
                let pos = at.unwrap_or(nf.pos) as usize;
                let n = data.len().saturating_sub(pos).min(count);
                if at.is_none() {
                    nf.pos += n as u64;
                }
                data[pos.min(data.len())..pos.min(data.len()) + n].to_vec()
            }
            _ => return Err(EBADF),
        };
        t.proc.mm().write(buf, &data)?;
        Ok(data.len() as i64)
    }

    fn write(&self, t: &Arc<Thread>, fd: i64, buf: u64, count: u64) -> Result<i64, i64> {
        self.write_at(t, fd, buf, count, None)
    }

    fn write_at(&self, t: &Arc<Thread>, fd: i64, buf: u64, count: u64, at: Option<u64>) -> Result<i64, i64> {
        let f = t.proc.files.lock().unwrap().get(fd)?;
        let data = t.proc.mm().read_vec(buf, count.min(IO_MAX) as usize)?;
        let n = match &f.kind {
            Kind::Stdout => std::io::stdout().write_all(&data).and_then(|_| std::io::stdout().flush()).map(|_| data.len()).map_err(|_| EIO)?,
            Kind::Stderr => std::io::stderr().write_all(&data).map(|_| data.len()).map_err(|_| EIO)?,
            Kind::Null | Kind::Zero | Kind::Random => data.len(),
            Kind::Pipe(end) if end.write => match end.pipe.write(t, &data, f.nonblock()) {
                Err(EPIPE) => {
                    self.send_thread_signal(t, super::signal::SIGPIPE, super::signal::SigInfo::user(super::signal::SIGPIPE, t.proc.pid));
                    return Err(EPIPE);
                }
                r => r?,
            },
            Kind::Event(e) => {
                if data.len() < 8 {
                    return Err(EINVAL);
                }
                e.write(t, u64::from_le_bytes(data[..8].try_into().unwrap()), f.nonblock())?;
                8
            }
            Kind::Socket(sock) => match unix::write(sock, t, data, f.nonblock()) {
                Err(EPIPE) => {
                    self.send_thread_signal(t, super::signal::SIGPIPE, super::signal::SigInfo::user(super::signal::SIGPIPE, t.proc.pid));
                    return Err(EPIPE);
                }
                r => r?,
            },
            Kind::Mem(m) => {
                if !m.writable {
                    return Err(EBADF);
                }
                let mut pos = m.pos.lock().unwrap();
                let append = f.flags.load(Ordering::Relaxed) & O_APPEND != 0;
                let off = match at {
                    Some(o) => o,
                    None if append => m.file.size(),
                    None => *pos,
                };
                m.file.write_at(off, &data)?;
                if at.is_none() {
                    *pos = off + data.len() as u64;
                }
                data.len()
            }
            Kind::Node(_) => return Err(EBADF), // opened read-only
            _ => return Err(EBADF),
        };
        Ok(n as i64)
    }

    fn fd_stat(&self, t: &Thread, fd: i64) -> Result<Stat, i64> {
        let chr = |rdev| Stat { mode: 0o020620, rdev, nlink: 1, ..Default::default() };
        let f = t.proc.files.lock().unwrap().get(fd)?;
        Ok(match &f.kind {
            Kind::Stdin | Kind::Stdout | Kind::Stderr => chr(0x8800), // /dev/pts/0
            Kind::Null => chr(0x0103),
            Kind::Zero => chr(0x0105),
            Kind::Random => chr(0x0109),
            Kind::Pipe(_) => Stat { mode: 0o010600, nlink: 1, ..Default::default() },
            Kind::Socket(_) => Stat { mode: 0o140777, nlink: 1, ..Default::default() },
            Kind::Event(_) | Kind::Timer(_) | Kind::Signal(_) | Kind::Epoll(_) => Stat { mode: 0o600, nlink: 1, ..Default::default() }, // anon_inode
            Kind::Node(nf) => nf.lock().unwrap().stat.clone(),
            Kind::Mem(m) => match &m.node {
                Some(n) => self.vfs()?.stat(n)?,
                None => Stat { mode: S_IFREG | 0o600, nlink: 1, size: m.file.size(), ..Default::default() },
            },
        })
    }

    fn path_stat(&self, t: &Thread, dirfd: i64, path: u64, flags: u64) -> Result<Stat, i64> {
        let path = t.proc.mm().read_cstr(path)?;
        if path.is_empty() && flags & AT_EMPTY_PATH != 0 {
            if dirfd == AT_FDCWD {
                let cwd = t.proc.cwd.lock().unwrap().clone();
                return self.vfs()?.stat(&self.vfs()?.resolve("/", &cwd, true)?);
            }
            return self.fd_stat(t, dirfd);
        }
        let node = self.resolve(t, dirfd, &path, flags & AT_SYMLINK_NOFOLLOW == 0)?;
        self.vfs()?.stat(&node)
    }

    fn readlinkat(&self, t: &Thread, dirfd: i64, path: u64, buf: u64, size: u64) -> Result<i64, i64> {
        let path = t.proc.mm().read_cstr(path)?;
        let self_fd = path.strip_prefix("/proc/self/fd/").and_then(|n| n.parse::<i64>().ok());
        let target = if path == "/proc/self/exe" {
            t.proc.exe.lock().unwrap().clone().into_bytes()
        } else if let Some(fd) = self_fd {
            let f = t.proc.files.lock().unwrap().get(fd).map_err(|_| ENOENT)?;
            file_name(&f).into_bytes()
        } else {
            let node = self.resolve(t, dirfd, &path, false)?;
            let vfs = self.vfs()?;
            if vfs.stat(&node)?.mode & S_IFMT != S_IFLNK {
                return Err(EINVAL);
            }
            vfs.read_all(&node)?.to_vec()
        };
        let n = target.len().min(size as usize);
        t.proc.mm().write(buf, &target[..n])?;
        Ok(n as i64)
    }

    fn getdents64(&self, t: &Thread, fd: i64, buf: u64, count: u64) -> Result<i64, i64> {
        let f = t.proc.files.lock().unwrap().get(fd)?;
        let Kind::Node(nf) = &f.kind else { return Err(ENOTDIR) };
        let mut guard = nf.lock().unwrap();
        if guard.stat.mode & S_IFMT != S_IFDIR {
            return Err(ENOTDIR);
        }
        if guard.dents.is_none() {
            // Listing may need this very file's lock (procfs names every open
            // descriptor, including this directory), so list without holding it.
            let node = guard.node.clone();
            drop(guard);
            let dents = self.vfs()?.readdir(&node)?;
            guard = nf.lock().unwrap();
            guard.dents.get_or_insert(dents);
        }
        let mut nf = guard;
        let mut out = Vec::new();
        let mut idx = nf.pos as usize;
        let dents = nf.dents.as_ref().unwrap();
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
            return Err(EINVAL); // buffer too small for one entry
        }
        nf.pos = idx as u64;
        drop(nf);
        t.proc.mm().write(buf, &out)?;
        Ok(out.len() as i64)
    }

    /// Applies a temporary signal mask for ppoll/epoll_pwait; returns the old one.
    fn swap_mask(&self, t: &Thread, sigmask: u64) -> Result<Option<u64>, i64> {
        if sigmask == 0 {
            return Ok(None);
        }
        let m = t.proc.mm().read_u64(sigmask)? & !((1 << 8) | (1 << 18));
        Ok(Some(t.mask.swap(m, Ordering::Relaxed)))
    }

    /// Ends a wait that ran under a temporary mask. On EINTR the handler runs
    /// first under that mask, then sigreturn restores the original.
    fn restore_mask(&self, t: &Thread, old: Option<u64>, r: &Result<i64, i64>) {
        if let Some(m) = old {
            if matches!(r, Err(EINTR)) {
                *t.saved_mask.lock().unwrap() = Some(m);
            } else {
                t.mask.store(m, Ordering::Relaxed);
            }
        }
    }

    fn ppoll(&self, t: &Thread, fds: u64, nfds: u64, timeout: u64, sigmask: u64) -> Result<i64, i64> {
        if nfds > 1024 {
            return Err(EINVAL);
        }
        let deadline = if timeout == 0 {
            None
        } else {
            let mut mm = t.proc.mm();
            let (s, ns) = (mm.read_u64(timeout)?, mm.read_u64(timeout + 8)?);
            Some(Instant::now() + Duration::new(s, ns.min(999_999_999) as u32))
        };
        let raw = t.proc.mm().read_vec(fds, nfds as usize * 8)?;
        let old = self.swap_mask(t, sigmask)?;
        let r = self.ppoll_wait(t, fds, raw, deadline);
        self.restore_mask(t, old, &r);
        r
    }

    fn ppoll_wait(&self, t: &Thread, fds: u64, mut raw: Vec<u8>, deadline: Option<Instant>) -> Result<i64, i64> {
        loop {
            let seen = EVENTS.current();
            let mut ready = 0;
            let mut timer: Option<Instant> = None;
            {
                let files = t.proc.files.lock().unwrap();
                for p in raw.chunks_exact_mut(8) {
                    let fd = i32::from_le_bytes(p[0..4].try_into().unwrap());
                    let events = u16::from_le_bytes(p[4..6].try_into().unwrap());
                    let revents = if fd < 0 {
                        0
                    } else {
                        match files.get(fd as i64) {
                            Ok(f) => {
                                if let Kind::Timer(tf) = &f.kind {
                                    timer = timer.into_iter().chain(tf.deadline()).min();
                                }
                                poll_ready(&f, t, 0) & (events | POLLERR | POLLHUP)
                            }
                            Err(_) => POLLNVAL,
                        }
                    };
                    p[6..8].copy_from_slice(&revents.to_le_bytes());
                    if revents != 0 {
                        ready += 1;
                    }
                }
            }
            if ready > 0 || deadline.is_some_and(|d| Instant::now() >= d) {
                t.proc.mm().write(fds, &raw)?;
                return Ok(ready);
            }
            if t.interrupted() {
                return Err(EINTR);
            }
            EVENTS.wait(seen, nap(deadline, timer));
        }
    }

    fn epoll_pwait(&self, t: &Thread, epfd: i64, events: u64, max: i64, timeout_ms: i64, sigmask: u64) -> Result<i64, i64> {
        if max <= 0 {
            return Err(EINVAL);
        }
        let f = t.proc.files.lock().unwrap().get(epfd)?;
        let Kind::Epoll(ep) = &f.kind else { return Err(EINVAL) };
        let deadline = (timeout_ms >= 0).then(|| Instant::now() + Duration::from_millis(timeout_ms as u64));
        let old = self.swap_mask(t, sigmask)?;
        let r = loop {
            let seen = EVENTS.current();
            let ready = ep.collect(t, max.min(1024) as usize, 0);
            if !ready.is_empty() {
                let (size, data_off) = self.arch.epoll_event_layout();
                let mut out = vec![0u8; ready.len() * size];
                for (i, (ev, data)) in ready.iter().enumerate() {
                    out[i * size..i * size + 4].copy_from_slice(&ev.to_le_bytes());
                    out[i * size + data_off..i * size + data_off + 8].copy_from_slice(&data.to_le_bytes());
                }
                break t.proc.mm().write(events, &out).map(|_| ready.len() as i64);
            }
            if deadline.is_some_and(|d| Instant::now() >= d) {
                break Ok(0);
            }
            if t.interrupted() {
                break Err(EINTR);
            }
            EVENTS.wait(seen, nap(deadline, ep.deadline()));
        };
        self.restore_mask(t, old, &r);
        r
    }
}

/// How long a poller may sleep: until its deadline or the next timer, and
/// never longer than POLL (signals and exits are noticed by polling).
fn nap(deadline: Option<Instant>, timer: Option<Instant>) -> Duration {
    let until = deadline.into_iter().chain(timer).min();
    until.map_or(POLL, |d| d.saturating_duration_since(Instant::now()).min(POLL)).max(Duration::from_micros(50))
}

/// What /proc/<pid>/fd/<n> points at.
pub(super) fn file_name(f: &File) -> String {
    match &f.kind {
        Kind::Node(nf) => nf.lock().unwrap().node.path.clone(),
        Kind::Mem(m) => m.name.clone(),
        Kind::Null => "/dev/null".into(),
        Kind::Zero => "/dev/zero".into(),
        Kind::Random => "/dev/urandom".into(),
        Kind::Pipe(p) => format!("pipe:[{}]", Arc::as_ptr(&p.pipe) as usize % 100_000),
        Kind::Socket(s) => format!("socket:[{}]", Arc::as_ptr(s) as usize % 100_000),
        Kind::Event(_) => "anon_inode:[eventfd]".into(),
        Kind::Timer(_) => "anon_inode:[timerfd]".into(),
        Kind::Signal(_) => "anon_inode:[signalfd]".into(),
        Kind::Epoll(_) => "anon_inode:[eventpoll]".into(),
        Kind::Stdin | Kind::Stdout | Kind::Stderr => "/dev/pts/0".into(),
    }
}

/// `struct statfs` (same 120-byte layout on arm64 and x86_64): a read-only ext4-like volume.
fn statfs_bytes() -> [u8; 120] {
    let mut b = [0u8; 120];
    b[0..8].copy_from_slice(&0xef53u64.to_le_bytes()); // f_type
    b[8..16].copy_from_slice(&4096u64.to_le_bytes()); // f_bsize
    b[64..72].copy_from_slice(&255u64.to_le_bytes()); // f_namelen
    b[72..80].copy_from_slice(&4096u64.to_le_bytes()); // f_frsize
    b[80..88].copy_from_slice(&1u64.to_le_bytes()); // f_flags = ST_RDONLY
    b
}

fn statx_bytes(st: &Stat) -> [u8; 256] {
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
    b
}

//! File descriptors: the open files of a process, pipes, and the file and
//! directory syscalls over the read-only VFS.

use super::binder::{self, BinderFile};
use super::block;
use super::epoll::Epoll;
use super::netlink::{self, Netlink};
use super::specialfd::{EventFd, SignalFd, TimerFd};
use super::unix::{self, Socket};
use super::wait::EVENTS;
use super::inotify;
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
const O_PATH: u64 = 0o10000000;
const AT_REMOVEDIR: u64 = 0x200;
const S_IFCHR: u32 = 0o020000;
const S_IFBLK: u32 = 0o060000;
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
const F_OFD_GETLK: u64 = 36;
const F_OFD_SETLK: u64 = 37;
const F_OFD_SETLKW: u64 = 38;
const F_RDLCK: i16 = 0;
const F_WRLCK: i16 = 1;
const F_UNLCK: i16 = 2;
const F_DUPFD_CLOEXEC: u64 = 1030;
const F_SETPIPE_SZ: u64 = 1031;
const F_GETPIPE_SZ: u64 = 1032;
const FD_CLOEXEC: u64 = 1;
/// A new pipe's capacity (F_SETPIPE_SZ changes it).
const PIPE_CAP: usize = 64 << 10;
/// Largest single read/write we copy at once (Linux caps at ~2 GiB).
const IO_MAX: u64 = 16 << 20;

pub fn handles(no: Sysno) -> bool {
    use Sysno::*;
    matches!(
        no,
        openat | close | read | pread64 | readv | write | writev | pwrite64 | lseek | fstat | newfstatat | statx | faccessat
            | faccessat2 | readlinkat | getdents64 | getcwd | chdir | fchdir | dup | dup2 | dup3 | fcntl | ioctl | statfs
            | fstatfs | umask | pipe2 | ppoll | eventfd2 | epoll_create1 | epoll_ctl | epoll_pwait | epoll_pwait2 | timerfd_create
            | timerfd_settime | timerfd_gettime | signalfd4 | mknodat | mkdirat | unlinkat | symlinkat | linkat | renameat
            | renameat2 | truncate | ftruncate | fallocate | fchmod | fchmodat | fchown | fchownat | sync | fsync | fdatasync
            | utimensat | memfd_create | flock | pselect6 | sendfile | copy_file_range | inotify_init1 | inotify_add_watch | inotify_rm_watch
    )
}

pub enum Kind {
    Stdin,
    Stdout,
    Stderr,
    Null,
    Zero,
    Random,
    /// The kernel log: writes go to the host's stderr.
    Kmsg,
    Node(Mutex<NodeFile>),
    /// A writable regular file (tmpfs or memfd): live contents.
    Mem(MemOpen),
    Pipe(PipeEnd),
    Event(EventFd),
    Timer(TimerFd),
    Signal(SignalFd),
    Epoll(Epoll),
    Socket(Arc<Socket>),
    Netlink(Arc<Netlink>),
    /// AF_INET / AF_INET6 (inet.rs): no network yet.
    Inet(Arc<super::inet::Inet>),
    /// An /dev/ashmem region (ashmem.rs).
    Ashmem(super::ashmem::Ashmem),
    Inotify(Arc<super::inotify::Inotify>),
    /// AF_VSOCK to the emulator's host services (vsock.rs).
    Vsock(Arc<super::vsock::Vsock>),
    /// /dev/tun (net.rs).
    Tun(super::net::Tun),
    Binder(BinderFile),
    /// A loop or device-mapper device (block.rs).
    Block(BlockOpen),
    LoopControl,
    DmControl,
    Special(SpecialOpen),
    /// A pseudo-terminal master or slave (pty.rs).
    Pty(super::pty::End),
    /// An eBPF map or program (bpf.rs).
    Bpf(Arc<super::bpf::BpfObj>),
    /// virtio-gpu card0 or renderD128 (drm.rs).
    Drm(super::drm::Open),
    /// A dma-buf exported from a GEM object.
    DmaBuf(super::drm::DmaBuf),
    /// A sync_file, the fd libsync waits on.
    Sync(super::drm::SyncFile),
}

/// A file whose contents a kernel subsystem computes (selinuxfs,
/// /proc/<pid>/attr). Reads see `contents` from the file position; writes
/// leave the position alone, so a selinuxfs transaction (write a request,
/// read the answer on the same fd) reads from offset 0.
pub trait SpecialFile: Send + Sync {
    fn contents(&self, t: &Thread) -> Result<Vec<u8>, i64>;
    fn write(&self, t: &Thread, data: &[u8]) -> Result<usize, i64>;
}

pub struct SpecialOpen {
    node: Node,
    file: Box<dyn SpecialFile>,
    pos: Mutex<u64>,
    readable: bool,
    writable: bool,
}

pub struct BlockOpen {
    devt: u64,
    pos: Mutex<u64>,
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

    /// The inode advisory locks are on. Every BPF fd shares one, as Linux's
    /// anon inode; pipes, sockets and the like stand alone.
    pub fn lock_key(self: &Arc<Self>) -> super::locks::Key {
        match &self.kind {
            Kind::Node(n) => {
                let n = n.lock().unwrap();
                (n.node.fs_id(), n.node.ino)
            }
            Kind::Mem(m) => (Arc::as_ptr(&m.file) as usize, 0),
            Kind::Bpf(_) => (1, 0),
            _ => (Arc::as_ptr(self) as usize, 0),
        }
    }

    /// The canonical path of an opened file or directory.
    pub fn node_path(&self) -> Option<String> {
        match &self.kind {
            Kind::Node(n) => Some(n.lock().unwrap().node.path.clone()),
            _ => None,
        }
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
    /// A kernel file (sysctl, cgroup control file) opened for writing.
    writable: bool,
    /// For files that report changes (/proc/mounts): the counter and the value last seen.
    event: Option<(Arc<std::sync::atomic::AtomicU64>, u64)>,
}

impl NodeFile {
    fn open(vfs: &crate::vfs::Vfs, node: Node, stat: Stat, writable: bool) -> Mutex<NodeFile> {
        let event = vfs.changes(&node).map(|c| {
            let seen = c.load(Ordering::Relaxed);
            (c, seen)
        });
        Mutex::new(NodeFile { node, stat, pos: 0, data: None, dents: None, writable, event })
    }

    /// Whether epoll may watch it (Linux refuses regular files).
    pub(super) fn pollable(&self) -> bool {
        self.event.is_some()
    }
}

#[derive(Clone)]
struct Entry {
    file: Arc<File>,
    cloexec: bool,
}

/// The open file description is gone: so are its OFD and flock locks, and
/// a written file's watchers hear IN_CLOSE_WRITE.
impl Drop for File {
    fn drop(&mut self) {
        super::locks::LOCKS.release(super::locks::Owner::File(self as *const File as usize));
        if let Kind::Mem(m) = &self.kind
            && m.writable
            && let Some(n) = &m.node
        {
            inotify::notify(&n.path, inotify::IN_CLOSE_WRITE, 0);
        }
    }
}

/// RLIMIT_NOFILE's initial soft limit.
pub const NOFILE_DEFAULT: usize = 1024;

#[derive(Clone)]
pub struct FdTable {
    fds: Vec<Option<Entry>>,
    /// The process's RLIMIT_NOFILE soft limit: fds must stay below it.
    limit: usize,
    /// DROIDRT_FD_TRACE: the pid whose table this is, when traced.
    traced: Option<i32>,
}

thread_local! {
    /// (pid, tid, syscall number) of the syscall this host thread runs, for fd traces.
    pub(super) static CURRENT: std::cell::Cell<(i32, i32, u64)> = const { std::cell::Cell::new((0, 0, 0)) };
}

/// DROIDRT_FD_TRACE=<name>: log every descriptor added to or removed from
/// the tables of programs whose path contains it (with who did it).
pub(super) fn fd_trace_wanted(exe: &str) -> bool {
    static NAME: std::sync::OnceLock<Option<String>> = std::sync::OnceLock::new();
    NAME.get_or_init(|| std::env::var("DROIDRT_FD_TRACE").ok().filter(|v| !v.is_empty())).as_deref().is_some_and(|n| exe.contains(n))
}

fn fd_log(owner: Option<i32>, what: &str, fd: usize, f: Option<&Arc<File>>) {
    if let Some(pid) = owner {
        let (by, tid, nr) = CURRENT.with(|c| c.get());
        eprintln!("[fd] {pid}: {what}{fd} {} (by {by}/{tid} syscall {nr})", f.map(|f| file_name(f)).unwrap_or_default());
    }
}

impl FdTable {
    pub fn stdio() -> FdTable {
        let e = |k| Some(Entry { file: File::new(k, 0), cloexec: false });
        FdTable { fds: vec![e(Kind::Stdin), e(Kind::Stdout), e(Kind::Stderr)], limit: NOFILE_DEFAULT, traced: None }
    }

    pub fn empty() -> FdTable {
        FdTable { fds: Vec::new(), limit: NOFILE_DEFAULT, traced: None }
    }

    pub(super) fn set_traced(&mut self, pid: Option<i32>) {
        self.traced = pid;
    }

    /// A forked child's copy: traced as the child, if the parent was.
    pub(super) fn fork_copy(&self, child: i32) -> FdTable {
        let mut t = self.clone();
        t.traced = self.traced.map(|_| child);
        t
    }

    pub(super) fn set_limit(&mut self, limit: usize) {
        self.limit = limit;
    }

    pub(super) fn get(&self, fd: i64) -> Result<Arc<File>, i64> {
        usize::try_from(fd).ok().and_then(|i| self.fds.get(i)).and_then(|e| e.as_ref()).map(|e| e.file.clone()).ok_or(EBADF)
    }

    fn entry_mut(&mut self, fd: i64) -> Result<&mut Entry, i64> {
        usize::try_from(fd).ok().and_then(|i| self.fds.get_mut(i)).and_then(|e| e.as_mut()).ok_or(EBADF)
    }

    pub(super) fn alloc(&mut self, file: Arc<File>, cloexec: bool, min: usize) -> Result<i64, i64> {
        let slot = (min..).find(|&i| self.fds.get(i).is_none_or(|s| s.is_none())).unwrap();
        if slot >= self.limit {
            return Err(EMFILE);
        }
        if self.fds.len() <= slot {
            self.fds.resize_with(slot + 1, || None);
        }
        fd_log(self.traced, "+", slot, Some(&file));
        self.fds[slot] = Some(Entry { file, cloexec });
        Ok(slot as i64)
    }

    pub(super) fn close(&mut self, fd: i64) {
        if let Some(slot) = usize::try_from(fd).ok().and_then(|i| self.fds.get_mut(i)) {
            fd_log(self.traced, "-", fd as usize, slot.as_ref().map(|e| &e.file));
            *slot = None;
        }
    }

    fn put(&mut self, fd: usize, file: Arc<File>, cloexec: bool) {
        if self.fds.len() <= fd {
            self.fds.resize_with(fd + 1, || None);
        }
        fd_log(self.traced, "=", fd, Some(&file));
        self.fds[fd] = Some(Entry { file, cloexec });
    }

    /// Open descriptors, in order.
    pub(super) fn list(&self) -> Vec<(i64, Arc<File>)> {
        self.fds.iter().enumerate().filter_map(|(i, e)| e.as_ref().map(|e| (i as i64, e.file.clone()))).collect()
    }

    pub fn close_on_exec(&mut self) {
        for (i, slot) in self.fds.iter_mut().enumerate() {
            if slot.as_ref().is_some_and(|e| e.cloexec) {
                fd_log(self.traced, "-exec ", i, slot.as_ref().map(|e| &e.file));
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
    cap: usize,
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
            super::vcpus::blocking();
            st = t.sleep(&self.cv, st, super::IDLE);
        }
    }

    fn write(&self, t: &Thread, data: &[u8], nonblock: bool) -> Result<usize, i64> {
        let mut st = self.st.lock().unwrap();
        let mut done = 0;
        loop {
            if st.readers == 0 {
                return Err(EPIPE);
            }
            let room = st.cap.saturating_sub(st.buf.len());
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
            super::vcpus::blocking();
            st = t.sleep(&self.cv, st, super::IDLE);
        }
    }
}

const POLLIN: u16 = 0x1;
const POLLPRI: u16 = 0x2;
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
        Kind::Pty(p) => p.poll(),
        Kind::Bpf(_) => 0,
        Kind::Netlink(n) => n.poll(),
        Kind::Inet(_) => POLLOUT,
        Kind::Inotify(i) => if i.pending() > 0 { POLLIN } else { 0 },
        Kind::Vsock(v) => POLLOUT | if v.readable() { POLLIN } else { 0 },
        Kind::Tun(_) => POLLOUT,
        Kind::Binder(b) => {
            (if binder::readable(b, t.tid) { POLLIN } else { 0 }) | POLLOUT
        }
        Kind::Stdin => POLLIN,
        Kind::Stdout | Kind::Stderr => POLLOUT,
        // /proc/mounts: POLLERR | POLLPRI once per change of the mount table.
        Kind::Node(nf) => match &mut nf.lock().unwrap().event {
            Some((counter, seen)) => {
                let now = counter.load(Ordering::Relaxed);
                if now == *seen {
                    POLLIN
                } else {
                    *seen = now;
                    POLLIN | POLLERR | POLLPRI
                }
            }
            None => POLLIN | POLLOUT,
        },
        Kind::Null | Kind::Zero | Kind::Random | Kind::Mem(_) | Kind::Block(_) | Kind::LoopControl | Kind::DmControl | Kind::Special(_) | Kind::DmaBuf(_) | Kind::Ashmem(_) => POLLIN | POLLOUT,
        Kind::Drm(d) => d.poll_bits(),
        Kind::Sync(s) => s.poll(),
        Kind::Kmsg => POLLOUT,
        Kind::Pipe(end) => {
            let st = end.pipe.st.lock().unwrap();
            if end.write {
                if st.readers == 0 { POLLERR } else if st.buf.len() < st.cap { POLLOUT } else { 0 }
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
    /// fcntl's record locks: struct flock in, a conflicting lock out (GETLK).
    fn record_lock(&self, t: &Arc<Thread>, fd: i64, f: &Arc<File>, cmd: u64, arg: u64) -> Result<i64, i64> {
        use super::locks::{LOCKS, Owner, Range};
        let mut raw = [0u8; 32]; // struct flock (LP64)
        t.proc.mm().read(arg, &mut raw)?;
        let ty = i16::from_le_bytes([raw[0], raw[1]]);
        let whence = i16::from_le_bytes([raw[2], raw[3]]);
        let start = i64::from_le_bytes(raw[8..16].try_into().unwrap());
        let len = i64::from_le_bytes(raw[16..24].try_into().unwrap());
        let ofd = matches!(cmd, F_OFD_GETLK | F_OFD_SETLK | F_OFD_SETLKW);
        if ofd && i32::from_le_bytes(raw[24..28].try_into().unwrap()) != 0 {
            return Err(EINVAL); // OFD requests must leave l_pid zero
        }
        if !matches!(ty, F_RDLCK | F_WRLCK | F_UNLCK) {
            return Err(EINVAL);
        }
        let base = match whence {
            0 => 0,
            1 => self.file_syscall(Sysno::lseek, t, [fd as u64, 0, 1, 0, 0, 0])?,
            2 => self.fd_stat(t, fd)?.size as i64,
            _ => return Err(EINVAL),
        };
        let from = base.checked_add(start).ok_or(EINVAL)?;
        let (lo, hi) = match len {
            0 => (from, u64::MAX),
            l if l > 0 => (from, from.checked_add(l).ok_or(EINVAL)? as u64),
            l => (from + l, from as u64),
        };
        if lo < 0 {
            return Err(EINVAL);
        }
        let owner = if ofd { Owner::File(Arc::as_ptr(f) as usize) } else { Owner::Process(t.proc.pid) };
        let want = Range { owner, write: ty == F_WRLCK, start: lo as u64, end: hi, pid: if ofd { -1 } else { t.proc.pid } };
        let key = f.lock_key();
        if matches!(cmd, F_GETLK | F_OFD_GETLK) {
            if ty == F_UNLCK {
                return Err(EINVAL);
            }
            let mut out = raw;
            match LOCKS.conflict(key, &want) {
                Some(l) => {
                    out[0..2].copy_from_slice(&(if l.write { F_WRLCK } else { F_RDLCK }).to_le_bytes());
                    out[2..4].copy_from_slice(&0i16.to_le_bytes());
                    out[8..16].copy_from_slice(&(l.start as i64).to_le_bytes());
                    out[16..24].copy_from_slice(&(if l.end == u64::MAX { 0 } else { (l.end - l.start) as i64 }).to_le_bytes());
                    out[24..28].copy_from_slice(&l.pid.to_le_bytes());
                }
                None => out[0..2].copy_from_slice(&F_UNLCK.to_le_bytes()),
            }
            t.proc.mm().write(arg, &out)?;
            return Ok(0);
        }
        LOCKS.set(t, key, want, ty == F_UNLCK, matches!(cmd, F_SETLKW | F_OFD_SETLKW))?;
        Ok(0)
    }

    pub(super) fn file_syscall(&self, no: Sysno, t: &Arc<Thread>, a: [u64; 6]) -> Result<i64, i64> {
        use Sysno::*;
        match no {
            openat => self.openat(t, int(a[0]), a[1], a[2], a[3]),
            close => {
                let entry = {
                    let mut files = t.files();
                    let traced = files.traced;
                    let slot = usize::try_from(int(a[0])).ok().and_then(|i| files.fds.get_mut(i));
                    match slot.and_then(|s| s.take()) {
                        Some(e) => {
                            fd_log(traced, "-", int(a[0]) as usize, Some(&e.file));
                            e
                        }
                        None => {
                            fd_log(traced, "EBADF close ", int(a[0]) as usize, None);
                            return Err(EBADF);
                        }
                    }
                };
                // POSIX record locks go with any close of the file.
                super::locks::LOCKS.release_on(entry.file.lock_key(), t.proc.pid);
                if let Kind::Binder(b) = &entry.file.kind {
                    super::binder::flush(b);
                }
                Ok(0)
            }
            flock => {
                let f = t.files().get(int(a[0]))?;
                const LOCK_SH: u64 = 1;
                const LOCK_EX: u64 = 2;
                const LOCK_NB: u64 = 4;
                const LOCK_UN: u64 = 8;
                let op = match a[1] & !LOCK_NB {
                    LOCK_SH => Some(false),
                    LOCK_EX => Some(true),
                    LOCK_UN => None,
                    _ => return Err(EINVAL),
                };
                super::locks::LOCKS.flock(t, f.lock_key(), Arc::as_ptr(&f) as usize, op, a[1] & LOCK_NB == 0)?;
                Ok(0)
            }
            read => self.read(t, int(a[0]), a[1], a[2], None),
            pread64 => self.read(t, int(a[0]), a[1], a[2], Some(a[3])),
            // One read (or write) for all the buffers, so a datagram or a
            // kmsg record stays one message.
            readv => {
                let iov = self.iovecs(t, a[1], a[2])?;
                let data = self.read_vec(t, int(a[0]), iov.iter().map(|v| v.1).sum(), None)?;
                let (mut mm, mut off) = (t.proc.mm(), 0);
                for (base, len) in iov {
                    let n = (len as usize).min(data.len() - off);
                    mm.write(base, &data[off..off + n])?;
                    off += n;
                }
                Ok(data.len() as i64)
            }
            write => self.write(t, int(a[0]), a[1], a[2]),
            pwrite64 => self.write_at(t, int(a[0]), a[1], a[2], Some(a[3])),
            writev => {
                let mut data = Vec::new();
                for (base, len) in self.iovecs(t, a[1], a[2])? {
                    data.extend(t.proc.mm().read_vec(base, len.min(IO_MAX - data.len() as u64) as usize)?);
                }
                self.write_vec(t, int(a[0]), data, None)
            }
            lseek => {
                let f = t.files().get(int(a[0]))?;
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
                // dma-buf: lseek(SEEK_END, 0) is how minigbm learns the size. No position is kept.
                if let Kind::DmaBuf(b) = &f.kind {
                    if a[1] != 0 {
                        return Err(EINVAL);
                    }
                    return match a[2] {
                        0 => Ok(0),
                        2 => Ok(b.size() as i64),
                        _ => Err(EINVAL),
                    };
                }
                if let Kind::Block(b) = &f.kind {
                    let len = self.blocks.device(b.devt).map_or(0, |d| d.len());
                    let mut pos = b.pos.lock().unwrap();
                    let base = match a[2] {
                        0 => 0,
                        1 => *pos as i64,
                        2 => len as i64,
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
                // A rewind re-lists a directory, and regenerates a generated
                // file (/proc, cgroups: size 0) like seq_file does.
                if new == 0 {
                    nf.dents = None;
                    if nf.stat.size == 0 {
                        nf.data = None;
                    }
                }
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
                let mut files = t.files();
                let f = files.get(int(a[0]))?;
                files.alloc(f, false, 0)
            }
            dup2 | dup3 => {
                let (old, new) = (int(a[0]), int(a[1]));
                let flags = if no == dup3 { a[2] } else { 0 };
                let mut files = t.files();
                let f = files.get(old)?;
                if old == new {
                    return if no == dup3 { Err(EINVAL) } else { Ok(new) };
                }
                if !(0..files.limit as i64).contains(&new) {
                    return Err(EBADF);
                }
                files.put(new as usize, f, flags & O_CLOEXEC != 0);
                Ok(new)
            }
            fcntl => {
                let fd = int(a[0]);
                let mut files = t.files();
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
                    F_GETLK | F_SETLK | F_SETLKW | F_OFD_GETLK | F_OFD_SETLK | F_OFD_SETLKW => {
                        let f = files.get(fd)?;
                        drop(files);
                        self.record_lock(t, fd, &f, a[1], a[2])
                    }
                    F_GETPIPE_SZ | F_SETPIPE_SZ => {
                        let f = files.get(fd)?;
                        drop(files);
                        let Kind::Pipe(end) = &f.kind else { return Err(EBADF) };
                        let mut st = end.pipe.st.lock().unwrap();
                        if a[1] == F_SETPIPE_SZ {
                            // A power-of-two number of pages, at least one.
                            let want = a[2] as u32 as usize;
                            if want > 1 << 31 {
                                return Err(EINVAL);
                            }
                            let size = want.max(phys::PAGE as usize).next_power_of_two();
                            if size > st.cap && size > self.sysctl.pipe_max_size() && !self.creds(t).capable(super::creds::CAP_SYS_RESOURCE) {
                                return Err(EPERM);
                            }
                            if size < st.buf.len() {
                                return Err(EBUSY);
                            }
                            st.cap = size;
                            end.pipe.cv.notify_all();
                        }
                        Ok(st.cap as i64)
                    }
                    _ => Err(EINVAL),
                }
            }
            ioctl => {
                let f = t.files().get(int(a[0]))?;
                let cmd = a[1] as u32 as u64;
                match &f.kind {
                    Kind::Drm(d) => return super::drm::ioctl(d, cmd, a[2], &mut DrmIo { t }),
                    Kind::DmaBuf(_) => return super::drm::dma_ioctl(cmd, a[2], &mut DrmIo { t }),
                    Kind::Sync(s) => return super::drm::sync_ioctl(s, cmd, a[2], &mut DrmIo { t }),
                    Kind::Binder(b) => return self.binder_ioctl(t, &f, b, cmd, a[2]),
                    Kind::Ashmem(m) => return m.ioctl(cmd, a[2], &mut AshmemIo { t }),
                    Kind::Tun(n) => return n.ioctl(cmd, a[2], &mut AshmemIo { t }),
                    Kind::Inotify(i) if cmd == 0x541b => {
                        t.proc.mm().write_u32(a[2], i.pending() as u32)?; // FIONREAD
                        return Ok(0);
                    }
                    Kind::Block(b) => return self.blocks.ioctl(b.devt, cmd, a[2], &mut BlockCaller { k: self, t }),
                    Kind::LoopControl => return self.blocks.loop_control(cmd, a[2]),
                    Kind::DmControl => return self.blocks.dm_ioctl(cmd, a[2], &mut BlockCaller { k: self, t }),
                    Kind::Pty(p) if cmd == super::pty::TIOCGPTPEER => {
                        let file = File::new(Kind::Pty(p.peer()?), (a[2] & O_NONBLOCK as u64) as u32);
                        return t.files().alloc(file, a[2] & O_CLOEXEC != 0, 0);
                    }
                    Kind::Pty(p) if !matches!(a[1], 0x5450 | 0x5451 | 0x5421) => return p.ioctl(t, cmd, a[2]),
                    // Socket ioctls (SIOC*): the interfaces.
                    Kind::Inet(_) if (0x8900..0x89ff).contains(&cmd) => return self.inet_ioctl(t, cmd, a[2]),
                    _ => {}
                }
                const FIONCLEX: u64 = 0x5450;
                const FIOCLEX: u64 = 0x5451;
                const FIONBIO: u64 = 0x5421;
                let fd = int(a[0]);
                let mut files = t.files();
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
                let f = t.files().get(int(a[0]))?;
                let node = match &f.kind {
                    Kind::Node(nf) => Some(nf.lock().unwrap().node.clone()),
                    Kind::Mem(m) => m.node.clone(),
                    Kind::Special(s) => Some(s.node.clone()),
                    _ => None,
                };
                let bytes = match node {
                    Some(n) => super::mount::statfs_node(self.vfs()?, &n),
                    None => super::mount::statfs_bytes(if matches!(f.kind, Kind::Mem(_)) { "tmpfs" } else { "pipefs" }, 0),
                };
                t.proc.mm().write(a[1], &bytes)?;
                Ok(0)
            }
            statfs => {
                let path = t.proc.mm().read_cstr(a[0])?;
                let node = self.resolve(t, AT_FDCWD, &path, true)?;
                t.proc.mm().write(a[1], &super::mount::statfs_node(self.vfs()?, &node))?;
                Ok(0)
            }
            umask => Ok(t.proc.umask.swap(a[0] as u32 & 0o777, Ordering::Relaxed) as i64),
            pipe2 => {
                let shared = Arc::new(Pipe { st: Mutex::new(PipeState { buf: VecDeque::new(), readers: 1, writers: 1, cap: PIPE_CAP }), cv: Condvar::new() });
                let flags = a[1] as u32 & O_NONBLOCK;
                let cloexec = a[1] & O_CLOEXEC != 0;
                let r = File::new(Kind::Pipe(PipeEnd { pipe: shared.clone(), write: false }), flags);
                let w = File::new(Kind::Pipe(PipeEnd { pipe: shared, write: true }), flags);
                let (rfd, wfd) = {
                    let mut files = t.files();
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
                    let mut files = t.files();
                    files.fds[rfd as usize] = None;
                    files.fds[wfd as usize] = None;
                    return Err(e);
                }
                Ok(0)
            }
            ppoll => self.ppoll(t, a[0], a[1], a[2], a[3]),
            pselect6 => self.pselect6(t, a),
            sendfile => {
                let (out_fd, in_fd, off, count) = (int(a[0]), int(a[1]), a[2], a[3]);
                let out = t.files().get(out_fd)?;
                if out.flags.load(Ordering::Relaxed) & O_APPEND != 0 {
                    return Err(EINVAL);
                }
                let at = if off == 0 { None } else { Some(t.proc.mm().read_u64(off)?) };
                self.copy_between(t, in_fd, at, out_fd, None, count, off)
            }
            copy_file_range => {
                if a[5] != 0 {
                    return Err(EINVAL);
                }
                let (in_off, out_off) = (a[1], a[3]);
                let at = if in_off == 0 { None } else { Some(t.proc.mm().read_u64(in_off)?) };
                let to = if out_off == 0 { None } else { Some(t.proc.mm().read_u64(out_off)?) };
                let n = self.copy_between(t, int(a[0]), at, int(a[2]), to, a[4], in_off)?;
                if let Some(o) = to {
                    t.proc.mm().write_u64(out_off, o + n as u64)?;
                }
                Ok(n)
            }
            mknodat | mkdirat | unlinkat | symlinkat | linkat | renameat | renameat2 | truncate | ftruncate | fallocate | fchmod
            | fchmodat | fchown | fchownat | sync | fsync | fdatasync | utimensat | memfd_create => self.change_syscall(no, t, a),
            inotify_init1 => {
                const IN_NONBLOCK: u64 = 0o4000;
                const IN_CLOEXEC: u64 = 0o2000000;
                if a[0] & !(IN_NONBLOCK | IN_CLOEXEC) != 0 {
                    return Err(EINVAL);
                }
                let f = File::new(Kind::Inotify(super::inotify::Inotify::new()), (a[0] & IN_NONBLOCK) as u32);
                t.files().alloc(f, a[0] & IN_CLOEXEC != 0, 0)
            }
            inotify_add_watch | inotify_rm_watch => {
                let f = t.files().get(int(a[0]))?;
                let Kind::Inotify(i) = &f.kind else { return Err(EINVAL) };
                if no == inotify_rm_watch {
                    return i.rm_watch(a[1] as i32);
                }
                let mask = a[2] as u32;
                let path = t.proc.mm().read_cstr(a[1])?;
                let node = self.resolve(t, AT_FDCWD, &path, super::inotify::follow(mask))?;
                let is_dir = self.vfs()?.stat(&node)?.mode & S_IFMT == S_IFDIR;
                i.add_watch(&node.path, is_dir, mask)
            }
            eventfd2 => {
                let f = File::new(Kind::Event(EventFd::new(a[0] as u32 as u64, a[1])), a[1] as u32 & O_NONBLOCK);
                t.files().alloc(f, a[1] & O_CLOEXEC != 0, 0)
            }
            epoll_create1 => {
                if a[0] & !O_CLOEXEC != 0 {
                    return Err(EINVAL);
                }
                let f = File::new(Kind::Epoll(Epoll::default()), 0);
                t.files().alloc(f, a[0] & O_CLOEXEC != 0, 0)
            }
            epoll_ctl => {
                let (ep, target) = {
                    let files = t.files();
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
            // Same wait as epoll_pwait; the timeout is a timespec (NULL blocks).
            // libgui's BLASTBufferQueue waits this way for a buffer release.
            epoll_pwait2 => {
                let ms = epoll_timespec_ms(t, a[3])?;
                self.epoll_pwait(t, int(a[0]), a[1], int(a[2]), ms, a[4])
            }
            timerfd_create => {
                let tf = TimerFd::new(a[0], self.boot)?;
                let f = File::new(Kind::Timer(tf), a[1] as u32 & O_NONBLOCK);
                t.files().alloc(f, a[1] & O_CLOEXEC != 0, 0)
            }
            timerfd_settime => {
                let f = t.files().get(int(a[0]))?;
                let Kind::Timer(tf) = &f.kind else { return Err(EINVAL) };
                let new = t.proc.mm().read_vec(a[2], 32)?;
                let old = tf.settime(a[1], &new);
                if a[3] != 0 {
                    t.proc.mm().write(a[3], &old)?;
                }
                Ok(0)
            }
            timerfd_gettime => {
                let f = t.files().get(int(a[0]))?;
                let Kind::Timer(tf) = &f.kind else { return Err(EINVAL) };
                t.proc.mm().write(a[1], &tf.gettime())?;
                Ok(0)
            }
            signalfd4 => {
                let mask = t.proc.mm().read_u64(a[1])? & !((1 << 8) | (1 << 18)); // never SIGKILL/SIGSTOP
                if int(a[0]) != -1 {
                    let f = t.files().get(int(a[0]))?;
                    let Kind::Signal(sf) = &f.kind else { return Err(EINVAL) };
                    sf.mask.store(mask, Ordering::Relaxed);
                    return Ok(int(a[0]));
                }
                let f = File::new(Kind::Signal(SignalFd { mask: AtomicU64::new(mask) }), a[3] as u32 & O_NONBLOCK);
                t.files().alloc(f, a[3] & O_CLOEXEC != 0, 0)
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
        let f = t.files().get(dirfd)?;
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
                let f = t.files().get(fd).map_err(|_| ENOENT)?;
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
        let creating = flags & O_CREAT != 0;
        let exclusive = creating && flags & O_EXCL != 0;
        let mut lost_races = 0;
        let node = loop {
            match self.resolve(t, dirfd, &path, flags & of.nofollow == 0) {
                Ok(_) if exclusive => return Err(EEXIST),
                Ok(n) => break n,
                Err(ENOENT) if creating => {
                    let (dir, name) = self.parent(t, dirfd, &path)?;
                    match self.vfs()?.create(&dir, &name, S_IFREG | (mode as u32 & 0o7777 & !t.proc.umask.load(Ordering::Relaxed)), 0) {
                        Ok(node) => {
                            inotify::notify(&inotify::join(&dir.path, &name), inotify::IN_CREATE, 0);
                            break node;
                        }
                        // Another thread made it since the lookup: without O_EXCL,
                        // open that one (SQLite falls back to read-only otherwise).
                        // Bounded, as a dangling symlink stays ENOENT, then EEXIST.
                        Err(EEXIST) if !exclusive && lost_races < 8 => lost_races += 1,
                        Err(e) => return Err(e),
                    }
                }
                Err(e) => return Err(e),
            }
        };
        let vfs = self.vfs()?;
        let stat = vfs.stat(&node)?;
        let kind = match stat.mode & S_IFMT {
            // A path-only descriptor: nothing behind it is opened.
            _ if flags & O_PATH != 0 => Kind::Node(NodeFile::open(vfs, node, stat, false)),
            S_IFCHR => match stat.rdev {
                0x103 => Kind::Null,
                0x105 => Kind::Zero,
                0x108 | 0x109 => Kind::Random,
                0x10b => Kind::Kmsg,
                super::pty::PTMX => Kind::Pty(super::pty::open_master(self.vfs.clone())?),
                r if super::pty::is_slave(r) => Kind::Pty(super::pty::open_slave(r)?),
                r if r == block::makedev(block::MISC_MAJOR, block::LOOP_CONTROL_MINOR) => Kind::LoopControl,
                r if r == block::makedev(block::MISC_MAJOR, block::DM_CONTROL_MINOR) => Kind::DmControl,
                r if super::drm::is_node(r) => Kind::Drm(self.drm.as_ref().ok_or(ENXIO)?.open(r)),
                r if r == super::ashmem::rdev() => Kind::Ashmem(super::ashmem::Ashmem::new()),
                r if r == super::net::tun_rdev() => Kind::Tun(super::net::Tun::new()),
                rdev => binder::file_for(t, rdev).ok_or(ENXIO)?,
            },
            S_IFBLK if self.blocks.device(stat.rdev).is_some() => Kind::Block(BlockOpen { devt: stat.rdev, pos: Mutex::new(0) }),
            S_IFBLK => return Err(ENXIO),
            unix::S_IFSOCK if flags & O_PATH == 0 => return Err(ENXIO),
            S_IFDIR if access != 0 => return Err(EISDIR),
            _ if flags & of.directory != 0 && stat.mode & S_IFMT != S_IFDIR => return Err(ENOTDIR),
            S_IFREG if super::selinux::is_special(vfs, &node) => Kind::Special(SpecialOpen {
                file: super::selinux::open(self, vfs, &node)?,
                node,
                pos: Mutex::new(0),
                readable: access != O_WRONLY,
                writable: access == O_WRONLY || access == O_RDWR,
            }),
            // Kernel files take each write as a value, so they keep no open contents.
            S_IFREG if vfs.write_ok(&node) => Kind::Node(NodeFile::open(vfs, node, stat, access != 0)),
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
            _ => Kind::Node(NodeFile::open(vfs, node, stat, false)),
        };
        t.files().alloc(File::new(kind, status), cloexec, 0)
    }

    /// (directory, final name) of a path relative to `dirfd`.
    fn parent(&self, t: &Thread, dirfd: i64, path: &str) -> Result<(Node, String), i64> {
        let base = if path.starts_with('/') { "/".to_string() } else { self.dir_path(t, dirfd)? };
        self.vfs()?.resolve_parent(&base, path)
    }

    /// The node a path-or-fd syscall (fchmodat, utimensat…) refers to.
    pub(super) fn target(&self, t: &Thread, dirfd: i64, path: u64, flags: u64) -> Result<Node, i64> {
        let p = if path == 0 { String::new() } else { t.proc.mm().read_cstr(path)? };
        if p.is_empty() && (path == 0 || flags & AT_EMPTY_PATH != 0) {
            let f = t.files().get(dirfd)?;
            return match &f.kind {
                Kind::Node(nf) => Ok(nf.lock().unwrap().node.clone()),
                Kind::Mem(m) => m.node.clone().ok_or(EBADF),
                _ => Err(EBADF),
            };
        }
        self.resolve(t, dirfd, &p, flags & AT_SYMLINK_NOFOLLOW == 0)
    }

    fn mem(&self, t: &Thread, fd: i64) -> Result<Arc<File>, i64> {
        let f = t.files().get(fd)?;
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
                let mask = t.proc.umask.load(Ordering::Relaxed);
                if no == mkdirat {
                    vfs.mkdir(&dir, &name, a[2] as u32 & !mask)?;
                } else {
                    vfs.create(&dir, &name, a[2] as u32 & !mask, a[3])?;
                }
                let isdir = if no == mkdirat { inotify::IN_ISDIR } else { 0 };
                inotify::notify(&inotify::join(&dir.path, &name), inotify::IN_CREATE | isdir, 0);
                Ok(0)
            }
            unlinkat => {
                let path = t.proc.mm().read_cstr(a[1])?;
                let (dir, name) = self.parent(t, int(a[0]), &path)?;
                let victim = vfs.resolve(&dir.path, &name, false);
                vfs.unlink(&dir, &name, a[2] & AT_REMOVEDIR != 0)?;
                if let Ok(v) = victim {
                    unix::unlinked(vfs, &v);
                }
                let isdir = if a[2] & AT_REMOVEDIR != 0 { inotify::IN_ISDIR } else { 0 };
                inotify::notify(&inotify::join(&dir.path, &name), inotify::IN_DELETE | isdir, 0);
                Ok(0)
            }
            symlinkat => {
                let target = t.proc.mm().read_cstr(a[0])?;
                let path = t.proc.mm().read_cstr(a[2])?;
                let (dir, name) = self.parent(t, int(a[1]), &path)?;
                vfs.symlink(&dir, &name, &target)?;
                inotify::notify(&inotify::join(&dir.path, &name), inotify::IN_CREATE, 0);
                Ok(0)
            }
            linkat => {
                let old = self.target(t, int(a[0]), a[1], a[4] ^ AT_SYMLINK_NOFOLLOW)?; // no-follow by default
                let path = t.proc.mm().read_cstr(a[3])?;
                let (dir, name) = self.parent(t, int(a[2]), &path)?;
                vfs.link(&old, &dir, &name)?;
                inotify::notify(&inotify::join(&dir.path, &name), inotify::IN_CREATE, 0);
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
                let victim = vfs.resolve(&ndir.path, &nname, false);
                vfs.rename(&odir, &oname, &ndir, &nname, flags & RENAME_NOREPLACE != 0)?;
                if let Ok(v) = victim {
                    unix::unlinked(vfs, &v);
                }
                let cookie = inotify::cookie();
                inotify::notify(&inotify::join(&odir.path, &oname), inotify::IN_MOVED_FROM, cookie);
                inotify::notify(&inotify::join(&ndir.path, &nname), inotify::IN_MOVED_TO, cookie);
                Ok(0)
            }
            truncate => {
                let path = t.proc.mm().read_cstr(a[0])?;
                let node = self.resolve(t, AT_FDCWD, &path, true)?;
                if vfs.write_ok(&node) {
                    return Ok(0); // kernel files have no length to change
                }
                if vfs.readonly(&node) {
                    return Err(EROFS);
                }
                vfs.mem_file(&node).ok_or(EISDIR)?.truncate(a[1]);
                inotify::notify(&node.path, inotify::IN_MODIFY, 0);
                Ok(0)
            }
            ftruncate | fallocate => {
                let f = self.mem(t, int(a[0]))?;
                let Kind::Mem(m) = &f.kind else { unreachable!() };
                if !m.writable {
                    return Err(EINVAL);
                }
                if let Some(n) = &m.node
                    && vfs.readonly(n)
                {
                    return Err(EROFS);
                }
                if no == ftruncate {
                    m.file.truncate(a[1]);
                } else if a[2] + a[3] > m.file.size() && a[1] & 1 == 0 {
                    m.file.truncate(a[2] + a[3]); // FALLOC_FL_KEEP_SIZE (1) unset: extend
                }
                if let Some(n) = &m.node {
                    inotify::notify(&n.path, inotify::IN_MODIFY, 0);
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
                inotify::notify(&node.path, inotify::IN_ATTRIB, 0);
                Ok(0)
            }
            fchmodat => {
                let node = self.target(t, int(a[0]), a[1], 0)?;
                vfs.set_attr(&node, Some(a[2] as u32), None, None)?;
                inotify::notify(&node.path, inotify::IN_ATTRIB, 0);
                Ok(0)
            }
            fchownat => {
                let node = self.target(t, int(a[0]), a[1], a[4])?;
                vfs.set_attr(&node, None, Some((a[2] as u32, a[3] as u32)), None)?;
                inotify::notify(&node.path, inotify::IN_ATTRIB, 0);
                Ok(0)
            }
            utimensat => {
                const UTIME_NOW: u64 = (1 << 30) - 1;
                const UTIME_OMIT: u64 = (1 << 30) - 2;
                let node = self.target(t, int(a[0]), a[1], a[3])?;
                let now = || std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs());
                // Only mtime is kept: times[1], unless it says UTIME_OMIT.
                let mtime = if a[2] == 0 {
                    now()
                } else {
                    let mut mm = t.proc.mm();
                    match mm.read_u64(a[2] + 24)? {
                        UTIME_OMIT => return Ok(0),
                        UTIME_NOW => now(),
                        _ => mm.read_u64(a[2] + 16)?,
                    }
                };
                match vfs.set_attr(&node, None, None, Some(mtime)) {
                    // The image readers have no timestamps to update; a remounted tmpfs does.
                    Err(EROFS) if matches!(vfs.fs_type(&node), "erofs" | "ext4") => Ok(0),
                    r => r.map(|_| 0),
                }
            }
            sync | fsync | fdatasync => Ok(0),
            memfd_create => {
                const MFD_CLOEXEC: u64 = 1;
                let name = t.proc.mm().read_cstr(a[0])?;
                let file = MemFile::new(self.phys.clone());
                let m = MemOpen { node: None, name: format!("/memfd:{name} (deleted)"), file, pos: Mutex::new(0), readable: true, writable: true };
                t.files().alloc(File::new(Kind::Mem(m), 0), a[1] & MFD_CLOEXEC != 0, 0)
            }
            _ => Err(ENOSYS),
        }
    }

    /// The path of a mapped file, for /proc/<pid>/maps.
    pub(super) fn fd_name(&self, t: &Thread, fd: i64) -> Option<String> {
        let f = t.files().get(fd).ok()?;
        Some(file_name(&f))
    }

    /// For MAP_SHARED of a file: the shared pages behind a writable file.
    pub(super) fn fd_shared_object(&self, t: &Thread, fd: i64) -> Result<Option<Arc<SharedObject>>, i64> {
        let f = t.files().get(fd)?;
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
        let f = t.files().get(fd)?;
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

    /// An iovec array, its total length capped at IO_MAX.
    fn iovecs(&self, t: &Thread, iov: u64, n: u64) -> Result<Vec<(u64, u64)>, i64> {
        let mut mm = t.proc.mm();
        let mut out = Vec::new();
        let mut total = 0;
        for i in 0..n.min(1024) {
            let (base, len) = (mm.read_u64(iov + i * 16)?, mm.read_u64(iov + i * 16 + 8)?);
            let len = len.min(IO_MAX - total);
            total += len;
            out.push((base, len));
        }
        Ok(out)
    }

    fn read(&self, t: &Thread, fd: i64, buf: u64, count: u64, at: Option<u64>) -> Result<i64, i64> {
        let data = self.read_vec(t, fd, count, at)?;
        t.proc.mm().write(buf, &data)?;
        Ok(data.len() as i64)
    }

    fn read_vec(&self, t: &Thread, fd: i64, count: u64, at: Option<u64>) -> Result<Vec<u8>, i64> {
        let f = t.files().get(fd)?;
        let count = count.min(IO_MAX) as usize;
        let data = match &f.kind {
            Kind::Stdin => {
                let mut v = vec![0; count.min(64 << 10)];
                let n = std::io::stdin().read(&mut v).map_err(|_| EIO)?;
                v.truncate(n);
                v
            }
            Kind::Null | Kind::Kmsg => Vec::new(),
            Kind::Zero => vec![0; count],
            Kind::Random => {
                let mut v = vec![0; count];
                phys::random_bytes(&mut v);
                v
            }
            Kind::Pipe(end) if !end.write => end.pipe.read(t, count, f.nonblock())?,
            Kind::Pty(p) => p.read(t, count, f.nonblock())?,
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
            Kind::Drm(d) => d.read_events(t, count, f.nonblock())?,
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
            Kind::Netlink(nl) => netlink::read(nl, t, count, f.nonblock())?,
            Kind::Inet(_) => return Err(ENOTCONN),
            Kind::Inotify(i) => i.read(t, count, f.nonblock())?,
            Kind::Vsock(v) => v.read(t, count, f.nonblock())?,
            // No packets ever come in.
            Kind::Tun(_) if f.nonblock() => return Err(EAGAIN),
            Kind::Tun(_) => loop {
                if t.interrupted() {
                    return Err(ERESTARTSYS);
                }
                super::vcpus::blocking();
                t.nap(super::IDLE);
            },
            Kind::Block(b) => {
                let dev = self.blocks.device(b.devt).ok_or(ENXIO)?;
                let mut pos = b.pos.lock().unwrap();
                let off = at.unwrap_or(*pos);
                let n = dev.len().saturating_sub(off).min(count as u64) as usize;
                let data = dev.read_vec(off, n).map_err(|_| EIO)?;
                if at.is_none() {
                    *pos += n as u64;
                }
                data
            }
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
            Kind::Special(s) if s.readable => {
                let data = s.file.contents(t)?;
                let mut pos = s.pos.lock().unwrap();
                let off = (at.unwrap_or(*pos) as usize).min(data.len());
                let n = (data.len() - off).min(count);
                if at.is_none() {
                    *pos += n as u64;
                }
                data[off..off + n].to_vec()
            }
            _ => return Err(EBADF),
        };
        Ok(data)
    }

    fn write(&self, t: &Arc<Thread>, fd: i64, buf: u64, count: u64) -> Result<i64, i64> {
        self.write_at(t, fd, buf, count, None)
    }

    fn write_at(&self, t: &Arc<Thread>, fd: i64, buf: u64, count: u64, at: Option<u64>) -> Result<i64, i64> {
        let data = t.proc.mm().read_vec(buf, count.min(IO_MAX) as usize)?;
        self.write_vec(t, fd, data, at)
    }

    fn write_vec(&self, t: &Arc<Thread>, fd: i64, data: Vec<u8>, at: Option<u64>) -> Result<i64, i64> {
        let f = t.files().get(fd)?;
        let n = match &f.kind {
            Kind::Stdout => std::io::stdout().write_all(&data).and_then(|_| std::io::stdout().flush()).map(|_| data.len()).map_err(|_| EIO)?,
            Kind::Stderr => std::io::stderr().write_all(&data).map(|_| data.len()).map_err(|_| EIO)?,
            Kind::Null | Kind::Zero | Kind::Random => data.len(),
            Kind::Kmsg => {
                // "<prio>tag: message" records, one per write.
                let text = String::from_utf8_lossy(&data);
                // Only a "<priority>" prefix: a message may itself start with digits.
                let text = match text.strip_prefix('<').and_then(|r| r.split_once('>')) {
                    Some((prio, rest)) if prio.chars().all(|c| c.is_ascii_digit()) => rest,
                    _ => &text,
                };
                eprintln!("[kmsg] {}", text.trim_end());
                data.len()
            }
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
            Kind::Netlink(nl) => netlink::write(nl, t, data, f.nonblock())?,
            Kind::Inet(_) => return Err(ENETUNREACH),
            Kind::Vsock(v) => v.write(&data)?,
            Kind::Tun(_) => data.len(), // sent nowhere
            Kind::Pty(p) => p.write(t, &data, f.nonblock())?,
            Kind::Mem(m) => {
                if !m.writable {
                    return Err(EBADF);
                }
                // Remount,ro applies to descriptors already open, as mnt_want_write does.
                if let Some(n) = &m.node
                    && self.vfs()?.readonly(n)
                {
                    return Err(EROFS);
                }
                let mut pos = m.pos.lock().unwrap();
                let append = f.flags.load(Ordering::Relaxed) & O_APPEND != 0;
                let off = match at {
                    Some(o) => o,
                    None if append => m.file.size(),
                    None => *pos,
                };
                let n = m.file.write_at(off, &data)?;
                if at.is_none() {
                    *pos = off + n as u64;
                }
                if let Some(node) = &m.node {
                    inotify::notify(&node.path, inotify::IN_MODIFY, 0);
                }
                n
            }
            Kind::Node(nf) => {
                let mut nf = nf.lock().unwrap();
                if !nf.writable {
                    return Err(EBADF); // opened read-only
                }
                nf.data = None;
                self.vfs()?.write(&nf.node, &data)?
            }
            Kind::Special(s) if s.writable => s.file.write(t, &data)?,
            _ => return Err(EBADF),
        };
        Ok(n as i64)
    }

    fn fd_stat(&self, t: &Thread, fd: i64) -> Result<Stat, i64> {
        let chr = |rdev| Stat { mode: 0o020620, rdev, nlink: 1, ..Default::default() };
        let f = t.files().get(fd)?;
        Ok(match &f.kind {
            Kind::Stdin | Kind::Stdout | Kind::Stderr => chr(0x8800), // /dev/pts/0
            Kind::Null => chr(0x0103),
            Kind::Zero => chr(0x0105),
            Kind::Random => chr(0x0109),
            Kind::Kmsg => chr(0x010b),
            Kind::Pipe(_) => Stat { mode: 0o010600, nlink: 1, ..Default::default() },
            Kind::Socket(_) | Kind::Netlink(_) | Kind::Inet(_) | Kind::Vsock(_) => Stat { mode: 0o140777, nlink: 1, ..Default::default() },
            Kind::Event(_) | Kind::Timer(_) | Kind::Signal(_) | Kind::Epoll(_) | Kind::Bpf(_) | Kind::Sync(_) | Kind::Inotify(_) => Stat { mode: 0o600, nlink: 1, ..Default::default() }, // anon_inode
            Kind::Drm(d) => Stat { mode: 0o020666, rdev: d.rdev(), nlink: 1, ..Default::default() },
            Kind::Ashmem(a) => Stat { mode: 0o020666, rdev: super::ashmem::rdev(), nlink: 1, size: a.size(), ..Default::default() },
            Kind::Tun(_) => Stat { mode: 0o020660, rdev: super::net::tun_rdev(), nlink: 1, ..Default::default() },
            Kind::DmaBuf(b) => Stat { mode: 0o600, nlink: 1, size: b.size(), ..Default::default() },
            Kind::Binder(_) => Stat { mode: 0o020666, nlink: 1, rdev: 0xa36, ..Default::default() },
            Kind::Block(b) => Stat { mode: S_IFBLK | 0o600, nlink: 1, rdev: b.devt, ..Default::default() },
            Kind::LoopControl => chr(block::makedev(block::MISC_MAJOR, block::LOOP_CONTROL_MINOR)),
            Kind::DmControl => chr(block::makedev(block::MISC_MAJOR, block::DM_CONTROL_MINOR)),
            Kind::Pty(p) => Stat { mode: if p.master { 0o020666 } else { 0o020620 }, rdev: p.rdev(), nlink: 1, ..Default::default() },
            Kind::Node(nf) => nf.lock().unwrap().stat.clone(),
            Kind::Special(s) => self.vfs()?.stat(&s.node)?,
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
            let f = t.files().get(fd).map_err(|_| ENOENT)?;
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
        let f = t.files().get(fd)?;
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
            Some(super::wait::instant_after(super::wait::guest_timespec(s, ns)?))
        };
        let raw = t.proc.mm().read_vec(fds, nfds as usize * 8)?;
        let old = self.swap_mask(t, sigmask)?;
        let r = self.ppoll_wait(t, fds, raw, deadline);
        self.restore_mask(t, old, &r);
        r
    }

    /// sendfile and copy_file_range: one read, one write. Short counts are
    /// legal and every caller loops. An explicit input offset is advanced
    /// in the caller's memory (`off_ptr`) by what was actually written.
    #[allow(clippy::too_many_arguments)]
    fn copy_between(&self, t: &Arc<Thread>, in_fd: i64, at: Option<u64>, out_fd: i64, to: Option<u64>, count: u64, off_ptr: u64) -> Result<i64, i64> {
        // Reading moves in_fd's position; note where it was, for a short write.
        let start = if at.is_none() { self.file_syscall(Sysno::lseek, t, [in_fd as u64, 0, 1, 0, 0, 0]).ok() } else { None };
        let data = self.read_vec(t, in_fd, count, at)?;
        if data.is_empty() {
            return Ok(0);
        }
        let want = data.len() as i64;
        let n = self.write_vec(t, out_fd, data, to)?;
        if let Some(o) = at {
            t.proc.mm().write_u64(off_ptr, o + n as u64)?;
        } else if let (Some(s), true) = (start, n < want) {
            self.file_syscall(Sysno::lseek, t, [in_fd as u64, (s + n) as u64, 0, 0, 0, 0])?;
        }
        Ok(n)
    }

    /// select(2) over ppoll's readiness: fd_set bitmaps in, the ready bits out.
    fn pselect6(&self, t: &Thread, a: [u64; 6]) -> Result<i64, i64> {
        const POLLPRI: u16 = 0x2;
        let nfds = a[0] as usize;
        if nfds > 1024 {
            return Err(EINVAL);
        }
        let words = nfds.div_ceil(64);
        let (sets, deadline, sigmask) = {
            let mut mm = t.proc.mm();
            let mut sets = [Vec::new(), Vec::new(), Vec::new()];
            for (i, &p) in [a[1], a[2], a[3]].iter().enumerate() {
                if p != 0 {
                    sets[i] = (0..words).map(|w| mm.read_u64(p + w as u64 * 8)).collect::<Result<_, _>>()?;
                }
            }
            let deadline = if a[4] == 0 {
                None
            } else {
                let (s, ns) = (mm.read_u64(a[4])?, mm.read_u64(a[4] + 8)?);
                Some(super::wait::instant_after(super::wait::guest_timespec(s, ns)?))
            };
            // The sixth argument points at { const sigset_t *ss; size_t ss_len }.
            let sigmask = if a[5] == 0 { 0 } else { mm.read_u64(a[5])? };
            (sets, deadline, sigmask)
        };
        let wanted = |fd: usize, s: &Vec<u64>| !s.is_empty() && s[fd / 64] & 1 << (fd % 64) != 0;
        let old = self.swap_mask(t, sigmask)?;
        let r = loop {
            let seen = EVENTS.current();
            let mut out = [vec![0u64; words], vec![0u64; words], vec![0u64; words]];
            let mut count = 0;
            let mut timer: Option<Instant> = None;
            {
                for fd in 0..nfds {
                    if !(0..3).any(|i| wanted(fd, &sets[i])) {
                        continue;
                    }
                    // Not held across the poll: a binder fd takes the binder lock,
                    // whose holder may be installing a descriptor in this table.
                    let f = t.files().get(fd as i64);
                    let f = match f {
                        Ok(f) => f,
                        Err(e) => break_with(e)?,
                    };
                    if let Kind::Timer(tf) = &f.kind {
                        timer = timer.into_iter().chain(tf.deadline()).min();
                    }
                    let r = poll_ready(&f, t, 0);
                    for (i, mask) in [POLLIN | POLLHUP | POLLERR, POLLOUT | POLLERR, POLLPRI].iter().enumerate() {
                        if wanted(fd, &sets[i]) && r & mask != 0 {
                            out[i][fd / 64] |= 1 << (fd % 64);
                            count += 1;
                        }
                    }
                }
            }
            if count > 0 || deadline.is_some_and(|d| Instant::now() >= d) {
                let mut mm = t.proc.mm();
                for (i, &p) in [a[1], a[2], a[3]].iter().enumerate() {
                    if p != 0 {
                        let bytes: Vec<u8> = out[i].iter().flat_map(|w| w.to_le_bytes()).collect();
                        mm.write(p, &bytes[..nfds.div_ceil(8)])?;
                    }
                }
                break Ok(count);
            }
            if t.interrupted() {
                break Err(EINTR);
            }
            EVENTS.wait(seen, nap(deadline, timer));
        };
        self.restore_mask(t, old, &r);
        r
    }

    fn ppoll_wait(&self, t: &Thread, fds: u64, mut raw: Vec<u8>, deadline: Option<Instant>) -> Result<i64, i64> {
        loop {
            let seen = EVENTS.current();
            let mut ready = 0;
            let mut timer: Option<Instant> = None;
            {
                for p in raw.chunks_exact_mut(8) {
                    let fd = i32::from_le_bytes(p[0..4].try_into().unwrap());
                    let events = u16::from_le_bytes(p[4..6].try_into().unwrap());
                    let revents = if fd < 0 {
                        0
                    } else {
                        // Not held across the poll, as in pselect6.
                        let f = t.files().get(fd as i64);
                        match f {
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
        let f = t.files().get(epfd)?;
        let Kind::Epoll(ep) = &f.kind else { return Err(EINVAL) };
        let deadline = (timeout_ms >= 0).then(|| Instant::now() + Duration::from_millis(timeout_ms as u64));
        let old = self.swap_mask(t, sigmask)?;
        let mut fell_back = false;
        let r = loop {
            let seen = EVENTS.current();
            let ready = ep.collect(t, max.min(1024) as usize, 0);
            if !ready.is_empty() {
                if fell_back && late_wake_log() {
                    eprintln!("[droidrt] late wake: tid {} epoll fd {epfd}: only the fallback timeout noticed {} ready events", t.tid, ready.len());
                }
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
            let nap = nap(deadline, ep.deadline());
            fell_back = EVENTS.wait(seen, nap) && nap == POLL;
        };
        self.restore_mask(t, old, &r);
        r
    }
}

/// `epoll_pwait2`'s timeout: NULL waits forever, and a positive timespec rounds
/// up to the next millisecond so a sub-millisecond wait does not become a poll.
fn epoll_timespec_ms(t: &Thread, ts: u64) -> Result<i64, i64> {
    if ts == 0 {
        return Ok(-1);
    }
    let b = t.proc.mm().read_vec(ts, 16)?;
    let sec = i64::from_le_bytes(b[0..8].try_into().unwrap());
    let nsec = i64::from_le_bytes(b[8..16].try_into().unwrap());
    if sec < 0 || !(0..1_000_000_000).contains(&nsec) {
        return Err(EINVAL);
    }
    Ok(sec.saturating_mul(1000).saturating_add((nsec + 999_999) / 1_000_000))
}

/// How long a poller may sleep: until its deadline or the next timer, and
/// never longer than POLL (signals and exits are noticed by polling).
fn nap(deadline: Option<Instant>, timer: Option<Instant>) -> Duration {
    let until = deadline.into_iter().chain(timer).min();
    until.map_or(POLL, |d| d.saturating_duration_since(Instant::now()).min(POLL)).max(Duration::from_micros(50))
}

/// DROIDRT_LATEWAKE=1: reports readiness nothing announced with EVENTS.bump.
/// Those files work, but only as fast as the fallback timeout.
fn late_wake_log() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| std::env::var_os("DROIDRT_LATEWAKE").is_some())
}

/// The namespace node behind an open file, if it keeps one.
pub(super) fn node_of(f: &File) -> Option<Node> {
    match &f.kind {
        Kind::Node(nf) => Some(nf.lock().unwrap().node.clone()),
        Kind::Mem(m) => m.node.clone(),
        _ => None,
    }
}

/// What /proc/<pid>/fd/<n> points at.
pub(super) fn file_name(f: &File) -> String {
    match &f.kind {
        Kind::Node(nf) => nf.lock().unwrap().node.path.clone(),
        Kind::Mem(m) => m.name.clone(),
        Kind::Special(s) => s.node.path.clone(),
        Kind::Null => "/dev/null".into(),
        Kind::Zero => "/dev/zero".into(),
        Kind::Random => "/dev/urandom".into(),
        Kind::Kmsg => "/dev/kmsg".into(),
        Kind::Pipe(p) => format!("pipe:[{}]", Arc::as_ptr(&p.pipe) as usize % 100_000),
        Kind::Socket(s) => format!("socket:[{}]", Arc::as_ptr(s) as usize % 100_000),
        Kind::Netlink(s) => format!("socket:[{}]", Arc::as_ptr(s) as usize % 100_000),
        Kind::Inet(s) => format!("socket:[{}]", Arc::as_ptr(s) as usize % 100_000),
        Kind::Ashmem(a) => a.map_name(),
        Kind::Inotify(_) => "anon_inode:inotify".into(),
        Kind::Tun(_) => "/dev/tun".into(),
        Kind::Vsock(v) => format!("socket:[{}]", Arc::as_ptr(v) as usize % 100_000),
        Kind::Event(_) => "anon_inode:[eventfd]".into(),
        Kind::Timer(_) => "anon_inode:[timerfd]".into(),
        Kind::Signal(_) => "anon_inode:[signalfd]".into(),
        Kind::Epoll(_) => "anon_inode:[eventpoll]".into(),
        Kind::Binder(_) => "/dev/binder".into(),
        Kind::Bpf(o) => super::bpf::file_name(o).into(),
        Kind::Pty(p) if p.master => "/dev/ptmx".into(),
        Kind::Pty(p) => format!("/dev/pts/{}", p.pty.index),
        Kind::Block(b) => format!("/dev/block/{}", block::name(b.devt)),
        Kind::LoopControl => "/dev/loop-control".into(),
        Kind::DmControl => "/dev/device-mapper".into(),
        Kind::Drm(d) => d.path().into(),
        Kind::DmaBuf(_) => "anon_inode:dmabuf".into(),
        Kind::Sync(_) => "anon_inode:sync_file".into(),
        Kind::Stdin | Kind::Stdout | Kind::Stderr => "/dev/pts/0".into(),
    }
}

struct DrmIo<'a> {
    t: &'a Thread,
}

impl super::drm::Io for DrmIo<'_> {
    fn read_mem(&mut self, addr: u64, n: usize) -> Result<Vec<u8>, i64> {
        self.t.proc.mm().read_vec(addr, n)
    }
    fn write_mem(&mut self, addr: u64, data: &[u8]) -> Result<(), i64> {
        self.t.proc.mm().write(addr, data)
    }
    fn add_sync(&mut self, sync: super::drm::SyncFile, cloexec: bool) -> Result<i64, i64> {
        self.t.files().alloc(File::new(Kind::Sync(sync), 0), cloexec, 0)
    }
    fn add_dma(&mut self, dma: super::drm::DmaBuf, cloexec: bool) -> Result<i64, i64> {
        self.t.files().alloc(File::new(Kind::DmaBuf(dma), 0), cloexec, 0)
    }
    fn sync_of(&mut self, fd: i64) -> Result<super::drm::SyncFile, i64> {
        match &self.t.files().get(fd)?.kind {
            Kind::Sync(s) => Ok(s.clone()),
            _ => Err(EINVAL),
        }
    }
    fn dma_of(&mut self, fd: i64) -> Result<super::drm::DmaBuf, i64> {
        match &self.t.files().get(fd)?.kind {
            Kind::DmaBuf(d) => Ok(d.clone()),
            _ => Err(EINVAL),
        }
    }
    fn comm(&self) -> String {
        let c = self.t.attrs.lock().unwrap().comm.clone();
        if c.is_empty() { self.t.proc.exe.lock().unwrap().rsplit('/').next().unwrap_or("?").to_string() } else { c }
    }
    fn wait_until(&mut self, pred: &mut dyn FnMut() -> bool) -> Result<(), i64> {
        loop {
            let seen = super::wait::EVENTS.current();
            if pred() {
                return Ok(());
            }
            if self.t.interrupted() {
                return Err(super::ERESTARTSYS);
            }
            super::wait::EVENTS.wait(seen, super::POLL);
        }
    }
}

/// Guest memory and open files, for block.rs's ioctls.
struct BlockCaller<'a> {
    k: &'a Kernel,
    t: &'a Thread,
}

impl block::Caller for BlockCaller<'_> {
    fn read(&mut self, addr: u64, len: usize) -> Result<Vec<u8>, i64> {
        self.t.proc.mm().read_vec(addr, len)
    }
    fn write(&mut self, addr: u64, data: &[u8]) -> Result<(), i64> {
        self.t.proc.mm().write(addr, data)
    }
    fn backing(&mut self, fd: i32) -> Result<(crate::image::Dev, String), i64> {
        let f = self.t.files().get(fd as i64)?;
        match &f.kind {
            Kind::Node(nf) => {
                let node = nf.lock().unwrap().node.clone();
                let data = self.k.vfs()?.read_all(&node)?;
                Ok((Arc::new(crate::image::MemDev(data)), node.path))
            }
            Kind::Mem(m) => Ok((Arc::new(block::MemFileDev(m.file.clone())), m.name.clone())),
            Kind::Block(b) => Ok((self.k.blocks.device(b.devt).ok_or(ENXIO)?, file_name(&f))),
            _ => Err(EINVAL),
        }
    }
    fn dev_of_path(&mut self, path: &str) -> Option<u64> {
        let node = self.k.resolve(self.t, AT_FDCWD, path, true).ok()?;
        let st = self.k.vfs().ok()?.stat(&node).ok()?;
        (st.mode & S_IFMT == S_IFBLK).then_some(st.rdev)
    }
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
    put(128, &block::major(st.rdev).to_le_bytes());
    put(132, &block::minor(st.rdev).to_le_bytes());
    put(136, &block::major(st.dev).to_le_bytes()); // stx_dev_major
    put(140, &block::minor(st.dev).to_le_bytes());
    b
}

struct AshmemIo<'a> {
    t: &'a Thread,
}

impl super::ashmem::Io for AshmemIo<'_> {
    fn read(&mut self, addr: u64, buf: &mut [u8]) -> Result<(), i64> {
        self.t.proc.mm().read(addr, buf)
    }
    fn write(&mut self, addr: u64, data: &[u8]) -> Result<(), i64> {
        self.t.proc.mm().write(addr, data)
    }
}

/// An error out of a loop body that returns Result.
fn break_with<T>(e: i64) -> Result<T, i64> {
    Err(e)
}

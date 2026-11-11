//! AF_UNIX sockets: socketpair and named stream, datagram, and seqpacket
//! sockets, with SCM_RIGHTS fd passing and SCM_CREDENTIALS. A path binding is
//! an S_IFSOCK node in the filesystem, as on Linux: connect finds the socket
//! through the node it resolves to, whatever name reached it. Abstract names
//! ("\0name") live in a kernel table.

use super::files::{File, Kind};
use super::signal::{SIGPIPE, SigInfo};
use super::wait::EVENTS;
use super::{ERESTARTSYS, IDLE, Kernel, Thread, int, logd, netlink};
use crate::arch::Sysno;
use crate::errno::*;
use crate::vfs::{FileSystem, Node, S_IFMT, Vfs};
use std::collections::{BTreeMap, VecDeque};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};

const AF_UNIX: u64 = 1;
pub use crate::vfs::S_IFSOCK;
const AT_FDCWD: i64 = -100;
pub const SOCK_STREAM: u32 = 1;
pub const SOCK_DGRAM: u32 = 2;
pub const SOCK_SEQPACKET: u32 = 5;
const SOCK_NONBLOCK: u64 = 0o4000;
const SOCK_CLOEXEC: u64 = 0o2000000;
const MSG_PEEK: u64 = 0x2;
const MSG_CTRUNC: u32 = 0x8;
const MSG_TRUNC: u64 = 0x20;
const MSG_DONTWAIT: u64 = 0x40;
const MSG_WAITALL: u64 = 0x100;
const MSG_NOSIGNAL: u64 = 0x4000;
const MSG_CMSG_CLOEXEC: u64 = 0x4000_0000;
const SOL_SOCKET: u64 = 1;
const SCM_RIGHTS: i32 = 1;
const SCM_CREDENTIALS: i32 = 2;
const SO_TYPE: u64 = 3;
const SO_ERROR: u64 = 4;
const SO_SNDBUF: u64 = 7;
const SO_RCVBUF: u64 = 8;
const SO_PASSCRED: u64 = 16;
const SO_PEERCRED: u64 = 17;
const SO_ACCEPTCONN: u64 = 30;
const SO_PEERSEC: u64 = 31;
const SO_PROTOCOL: u64 = 38;
const SO_DOMAIN: u64 = 39;
const SHUT_RD: u64 = 0;
const SHUT_WR: u64 = 1;
/// Bytes a receive queue holds before senders block.
const QUEUE_LIMIT: usize = 256 << 10;
const IO_MAX: u64 = 16 << 20;

pub const POLLIN: u16 = 0x1;
pub const POLLOUT: u16 = 0x4;
pub const POLLHUP: u16 = 0x10;
pub const POLLRDHUP: u16 = 0x2000;

pub fn handles(no: Sysno) -> bool {
    use Sysno::*;
    matches!(
        no,
        socket | socketpair | bind | listen | accept | accept4 | connect | getsockname | getpeername | sendto | recvfrom | setsockopt
            | getsockopt | shutdown | sendmsg | recvmsg | sendmmsg | recvmmsg
    )
}

#[derive(Clone, Copy, Default)]
struct Cred {
    pid: i32,
    uid: u32,
    gid: u32,
    /// SELinux label (selinux::sid); 0 for kernel-side services.
    sid: u32,
}

impl Cred {
    fn of(t: &Thread) -> Cred {
        let c = t.proc.creds.lock().unwrap();
        Cred { pid: t.proc.pid, uid: c.euid, gid: c.egid, sid: super::selinux::socket_sid(t) }
    }
    fn bytes(&self) -> [u8; 12] {
        let mut b = [0u8; 12];
        b[0..4].copy_from_slice(&self.pid.to_le_bytes());
        b[4..8].copy_from_slice(&self.uid.to_le_bytes());
        b[8..12].copy_from_slice(&self.gid.to_le_bytes());
        b
    }
}

struct Msg {
    data: Vec<u8>,
    /// Bytes of `data` already read (stream sockets read messages piecewise).
    off: usize,
    fds: Vec<Arc<File>>,
    from: Vec<u8>,
    cred: Cred,
}

#[derive(Default)]
struct Queue {
    msgs: VecDeque<Msg>,
    bytes: usize,
    /// The sending side shut down or went away: readers get EOF once drained.
    write_closed: bool,
}

/// SOL_SOCKET options that read back as they were set, whatever the family.
#[derive(Clone, Default)]
pub(super) struct SockOpts {
    pub(super) rcvtimeo: Option<Duration>,
    pub(super) sndtimeo: Option<Duration>,
    linger: [u8; 8],
    ints: BTreeMap<u64, u32>,
}

const SO_REUSEADDR: u64 = 2;
const SO_DONTROUTE: u64 = 5;
const SO_BROADCAST: u64 = 6;
const SO_KEEPALIVE: u64 = 9;
const SO_OOBINLINE: u64 = 10;
const SO_NO_CHECK: u64 = 11;
const SO_PRIORITY: u64 = 12;
const SO_LINGER: u64 = 13;
const SO_REUSEPORT: u64 = 15;
const SO_RCVLOWAT: u64 = 18;
const SO_SNDLOWAT: u64 = 19;
const SO_RCVTIMEO: u64 = 20;
const SO_SNDTIMEO: u64 = 21;
const SO_TIMESTAMP: u64 = 29;
const SO_MARK: u64 = 36;
const SO_PEEK_OFF: u64 = 42;
const SO_BUSY_POLL: u64 = 46;
const SO_RCVTIMEO_NEW: u64 = 66;
const SO_SNDTIMEO_NEW: u64 = 67;


impl SockOpts {
    fn int_default(opt: u64) -> Option<u32> {
        match opt {
            SO_RCVLOWAT | SO_SNDLOWAT => Some(1),
            SO_PEEK_OFF => Some(u32::MAX), // -1: off
            SO_REUSEADDR | SO_DONTROUTE | SO_BROADCAST | SO_KEEPALIVE | SO_OOBINLINE | SO_NO_CHECK | SO_PRIORITY | SO_REUSEPORT | SO_TIMESTAMP | SO_MARK | SO_BUSY_POLL => Some(0),
            _ => None,
        }
    }

    /// SO_LINGER on with no time at all: a close drops what's unsent.
    pub(super) fn closes_at_once(&self) -> bool {
        self.linger == [1, 0, 0, 0, 0, 0, 0, 0]
    }

    /// setsockopt: the option's raw value (Ok(false): not one of these).
    pub(super) fn set(&mut self, opt: u64, val: &[u8]) -> Result<bool, i64> {
        match opt {
            SO_RCVTIMEO | SO_SNDTIMEO | SO_RCVTIMEO_NEW | SO_SNDTIMEO_NEW => {
                if val.len() < 16 {
                    return Err(EINVAL);
                }
                let sec = i64::from_le_bytes(val[..8].try_into().unwrap());
                let usec = i64::from_le_bytes(val[8..16].try_into().unwrap());
                if !(0..1_000_000).contains(&usec) {
                    return Err(EDOM);
                }
                // As sock_set_timeout: {0, 0} blocks forever, a negative time not at all.
                let timeout = if sec < 0 {
                    Some(Duration::ZERO)
                } else if sec == 0 && usec == 0 {
                    None
                } else {
                    Some(Duration::new(sec as u64, usec as u32 * 1000))
                };
                if matches!(opt, SO_RCVTIMEO | SO_RCVTIMEO_NEW) {
                    self.rcvtimeo = timeout;
                } else {
                    self.sndtimeo = timeout;
                }
                Ok(true)
            }
            SO_LINGER => {
                self.linger.copy_from_slice(val.get(..8).ok_or(EINVAL)?);
                Ok(true)
            }
            _ if Self::int_default(opt).is_some() => {
                let v = val.get(..4).ok_or(EINVAL)?;
                self.ints.insert(opt, u32::from_le_bytes(v.try_into().unwrap()));
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    pub(super) fn get(&self, opt: u64) -> Option<Vec<u8>> {
        match opt {
            SO_RCVTIMEO | SO_SNDTIMEO | SO_RCVTIMEO_NEW | SO_SNDTIMEO_NEW => {
                let t = if matches!(opt, SO_RCVTIMEO | SO_RCVTIMEO_NEW) { self.rcvtimeo } else { self.sndtimeo };
                let (s, us) = t.map_or((0, 0), |d| (d.as_secs() as i64, d.subsec_micros() as i64));
                Some([s.to_le_bytes(), us.to_le_bytes()].concat())
            }
            SO_LINGER => Some(self.linger.to_vec()),
            _ => {
                let d = Self::int_default(opt)?;
                Some(self.ints.get(&opt).copied().unwrap_or(d).to_le_bytes().to_vec())
            }
        }
    }
}

/// An option's value as setsockopt was given it.
pub(super) fn sockopt_bytes(t: &Thread, val: u64, len: u64) -> Result<Vec<u8>, i64> {
    t.proc.mm().read_vec(val, len.min(64) as usize)
}

/// When a blocking call with this SO_RCVTIMEO / SO_SNDTIMEO gives up.
pub(super) fn deadline(timeout: Option<Duration>) -> Option<Instant> {
    timeout.map(super::wait::instant_after)
}

/// One sleep of a blocking socket call. A timeout ran out: EAGAIN. Signals
/// restart a call with no timeout, and end one that has (sock_intr_errno).
pub(super) fn wait_or_give_up(t: &Thread, seen: u64, until: Option<Instant>) -> Result<(), i64> {
    if t.interrupted() {
        return Err(if until.is_some() { EINTR } else { ERESTARTSYS });
    }
    let nap = match until {
        Some(at) => {
            let left = at.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Err(EAGAIN);
            }
            left.min(IDLE)
        }
        None => IDLE,
    };
    EVENTS.wait(seen, nap);
    Ok(())
}

#[derive(Default)]
struct State {
    /// The address as bound: sun_path bytes, a path or "\0name".
    name: Option<Vec<u8>>,
    /// The filesystem node of a path binding (only on the bound socket itself).
    node: Option<NodeKey>,
    /// A process's socket at /dev/socket/logdw (the real logd): what it
    /// receives is printed too, so logs stay on the terminal.
    log_tap: bool,
    connected: bool,
    peer: Option<Weak<Socket>>,
    peer_cred: Cred,
    backlog: Option<VecDeque<Arc<Socket>>>,
    listen_cred: Cred,
    passcred: bool,
    opts: SockOpts,
    shut_rd: bool,
    shut_wr: bool,
    /// For a client of a kernel-side service: keeps the server end alive.
    peer_server: Option<Arc<Socket>>,
}

pub struct Socket {
    ty: u32,
    /// The creator's credentials, taken at socket() (SO_PEERCRED for
    /// datagrams). Its sid is the socket's label (selinux_socket_post_create):
    /// init's CreateSocket clears setsockcreatecon before listen/connect, so
    /// later calls must not sample the task's label again. 0 for a kernel service.
    cred: Cred,
    rx: Mutex<Queue>,
    st: Mutex<State>,
    /// Answered inside the kernel (e.g. the property service), not by a process.
    service: Option<Arc<dyn Service>>,
    svc_buf: Mutex<Vec<u8>>,
}

/// A kernel-side socket server (what a daemon like init or logd would be).
pub trait Service: Send + Sync {
    /// Stream connections: consumes complete requests from the bytes received
    /// so far, returning one reply for each.
    fn handle(&self, _buf: &mut Vec<u8>) -> Option<Vec<u8>> {
        None
    }
    /// Datagram sockets: one message from process `pid`.
    fn datagram(&self, _data: &[u8], _pid: i32) {}
    /// Seqpacket connections: one packet; answer with `conn.push`/`conn.finish`.
    fn packet(&self, _conn: &Arc<Socket>, _data: &[u8]) {}
}

fn service_socket(vfs: &Vfs, path: &str, ty: u32, perm: u32, owner: (u32, u32), service: Arc<dyn Service>, listening: bool) -> Arc<Socket> {
    let sock = Arc::new(Socket { ty, cred: Cred { pid: 1, uid: 0, gid: 0, sid: 0 }, rx: Mutex::new(Queue::default()), st: Mutex::new(State::default()), service: Some(service), svc_buf: Mutex::new(Vec::new()) });
    {
        let mut st = sock.st.lock().unwrap();
        st.name = Some(path.as_bytes().to_vec());
        if listening {
            st.backlog = Some(VecDeque::new());
        }
        st.listen_cred = Cred { pid: 1, uid: 0, gid: 0, sid: 0 };
        match bind_node(vfs, "/", path, perm, &sock) {
            Ok(node) => {
                let _ = vfs.set_attr(&node, None, Some(owner), None);
                st.node = Some(node_key(&vfs.fs_arc(&node), node.ino));
            }
            Err(e) => eprintln!("[droidrt] {path}: cannot create the socket (errno {e})"),
        }
    }
    sock
}

/// Creates a kernel-side stream or seqpacket service as a socket node at
/// `path`, the way init would; the returned socket must be kept alive.
pub fn listen_service(vfs: &Vfs, path: &str, ty: u32, perm: u32, owner: (u32, u32), service: Arc<dyn Service>) -> Arc<Socket> {
    service_socket(vfs, path, ty, perm, owner, service, true)
}

/// A kernel-side datagram sink at `path`.
pub fn bind_service(vfs: &Vfs, path: &str, perm: u32, owner: (u32, u32), service: Arc<dyn Service>) -> Arc<Socket> {
    service_socket(vfs, path, SOCK_DGRAM, perm, owner, service, false)
}

/// A filesystem node: (the filesystem's address, inode).
type NodeKey = (usize, u64);

fn node_key(fs: &Arc<dyn FileSystem>, ino: u64) -> NodeKey {
    (Arc::as_ptr(fs) as *const () as usize, ino)
}

/// Path bindings by node. The weak filesystem reference keeps its address
/// from being reused by a later mount while the entry exists.
type Bound = BTreeMap<NodeKey, (Weak<dyn FileSystem>, Weak<Socket>)>;
static BOUND: Mutex<Bound> = Mutex::new(BTreeMap::new());

/// Abstract names: (type, "\0name") -> socket. Linux hashes the type in, so
/// each socket type has its own namespace.
type Abstract = BTreeMap<(u32, Vec<u8>), Weak<Socket>>;
static ABSTRACT: Mutex<Abstract> = Mutex::new(BTreeMap::new());

/// Creates the S_IFSOCK node for binding `sock` to `path` and records the
/// binding. EADDRINUSE if anything exists there (even a dangling symlink).
fn bind_node(vfs: &Vfs, cwd: &str, path: &str, perm: u32, sock: &Arc<Socket>) -> Result<Node, i64> {
    let (dir, name) = vfs.resolve_parent(cwd, path).map_err(|e| if e == EBUSY { EADDRINUSE } else { e })?;
    if vfs.resolve(&dir.path, &name, false).is_ok() {
        return Err(EADDRINUSE);
    }
    let node = vfs.create(&dir, &name, S_IFSOCK | perm, 0).map_err(|e| if e == EEXIST { EADDRINUSE } else { e })?;
    let fs = vfs.fs_arc(&node);
    BOUND.lock().unwrap().insert(node_key(&fs, node.ino), (Arc::downgrade(&fs), Arc::downgrade(sock)));
    Ok(node)
}

/// Called after `node` lost a name (unlink, rename over it): once its last
/// link is gone the socket bound there is unreachable, and a later node that
/// reuses the inode number must not lead back to it.
pub fn unlinked(vfs: &Vfs, node: &Node) {
    let key = node_key(&vfs.fs_arc(node), node.ino);
    if BOUND.lock().unwrap().contains_key(&key) && vfs.stat(node).is_err() {
        BOUND.lock().unwrap().remove(&key);
    }
}

impl Drop for Socket {
    fn drop(&mut self) {
        let st = self.st.get_mut().unwrap();
        // A datagram socket's peer is only where it sends. Its going means nothing to a
        // server with other clients, whose reads would all be EOF from then on.
        if self.ty != SOCK_DGRAM
            && let Some(peer) = st.peer.as_ref().and_then(Weak::upgrade)
        {
            peer.rx.lock().unwrap().write_closed = true;
        }
        if let Some(key) = st.node {
            let mut bound = BOUND.lock().unwrap();
            if bound.get(&key).is_some_and(|(_, s)| s.strong_count() == 0) {
                bound.remove(&key);
            }
        } else if let Some(name) = st.name.take().filter(|n| n.first() == Some(&0)) {
            let mut names = ABSTRACT.lock().unwrap();
            let key = (self.ty, name);
            if names.get(&key).is_some_and(|w| w.strong_count() == 0) {
                names.remove(&key);
            }
        }
        EVENTS.bump_key(self.key());
    }
}

impl Socket {
    fn new(ty: u32, cred: Cred) -> Arc<Socket> {
        Arc::new(Socket { ty, cred, rx: Mutex::new(Queue::default()), st: Mutex::new(State::default()), service: None, svc_buf: Mutex::new(Vec::new()) })
    }

    /// Sends a packet to the client of a kernel-service connection.
    pub fn push(&self, data: Vec<u8>) -> bool {
        let Some(client) = self.peer() else { return false };
        let mut q = client.rx.lock().unwrap();
        if q.bytes > 4 << 20 {
            return true; // a reader that stopped reading: drop rather than grow
        }
        q.bytes += data.len();
        q.msgs.push_back(Msg { data, off: 0, fds: Vec::new(), from: Vec::new(), cred: Cred { pid: 1, uid: 0, gid: 0, sid: 0 } });
        drop(q);
        EVENTS.bump_key(client.key());
        true
    }

    /// Ends a kernel-service connection: the client reads EOF after the data.
    pub fn finish(&self) {
        if let Some(client) = self.peer() {
            client.rx.lock().unwrap().write_closed = true;
            EVENTS.bump_key(client.key());
        }
    }

    /// Feeds what arrived on a kernel-service socket to its service,
    /// queueing the replies for the client.
    fn serve(self: &Arc<Self>) {
        let Some(svc) = &self.service else { return };
        if self.ty != SOCK_STREAM {
            let msgs: Vec<Msg> = {
                let mut q = self.rx.lock().unwrap();
                q.bytes = 0;
                q.msgs.drain(..).collect()
            };
            for m in msgs {
                if self.ty == SOCK_DGRAM {
                    svc.datagram(&m.data, m.cred.pid);
                } else {
                    svc.packet(self, &m.data);
                }
            }
            return;
        }
        let mut buf = self.svc_buf.lock().unwrap();
        {
            let mut q = self.rx.lock().unwrap();
            for m in q.msgs.drain(..) {
                buf.extend_from_slice(&m.data[m.off..]);
            }
            q.bytes = 0;
        }
        let Some(client) = self.peer() else { return };
        while let Some(reply) = svc.handle(&mut buf) {
            if !reply.is_empty() {
                let mut q = client.rx.lock().unwrap();
                q.bytes += reply.len();
                q.msgs.push_back(Msg { data: reply, off: 0, fds: Vec::new(), from: Vec::new(), cred: Cred { pid: 1, uid: 0, gid: 0, sid: 0 } });
            }
        }
        EVENTS.bump_key(client.key());
    }

    fn peer(&self) -> Option<Arc<Socket>> {
        self.st.lock().unwrap().peer.as_ref().and_then(Weak::upgrade)
    }

    fn connect_pair(a: &Arc<Socket>, b: &Arc<Socket>, a_cred: Cred, b_cred: Cred) {
        let mut sa = a.st.lock().unwrap();
        sa.connected = true;
        sa.peer = Some(Arc::downgrade(b));
        sa.peer_cred = b_cred;
        drop(sa);
        let mut sb = b.st.lock().unwrap();
        sb.connected = true;
        sb.peer = Some(Arc::downgrade(a));
        sb.peer_cred = a_cred;
    }

    /// What a waiter on this stands for in EVENTS.
    pub fn key(&self) -> usize {
        self as *const Self as usize
    }

    /// What a poller of this watches: its own queue and state, and whether its peer has
    /// gone or made room.
    pub fn mask(&self) -> super::wait::Mask {
        // A connected socket watches its peer's key too: what the peer reads makes room.
        let peer = self.st.lock().unwrap().peer.as_ref().and_then(Weak::upgrade);
        let own = super::wait::key_mask(self.key());
        peer.map_or(own, |p| own | super::wait::key_mask(p.key()))
    }

    pub fn poll(&self) -> u16 {
        let st = self.st.lock().unwrap();
        if let Some(backlog) = &st.backlog {
            return if backlog.is_empty() { 0 } else { POLLIN };
        }
        let peer = st.peer.as_ref().and_then(Weak::upgrade);
        let (connected, shut_rd, shut_wr) = (st.connected, st.shut_rd, st.shut_wr);
        drop(st);
        let rx = self.rx.lock().unwrap();
        let gone = connected && self.ty != SOCK_DGRAM && peer.is_none();
        let mut r = 0;
        if !rx.msgs.is_empty() || rx.write_closed || gone || shut_rd {
            r |= POLLIN;
        }
        if rx.write_closed || gone {
            r |= POLLRDHUP;
        }
        drop(rx);
        if gone {
            r |= POLLHUP;
        }
        let writable = match &peer {
            Some(p) => !shut_wr && p.rx.lock().unwrap().bytes < QUEUE_LIMIT,
            None => self.ty == SOCK_DGRAM, // a dead peer: the send reports ECONNREFUSED
        };
        if writable {
            r |= POLLOUT;
        }
        r
    }

    /// Queues a message for `target` (the peer, or a bound datagram socket).
    fn deliver(&self, t: &Thread, target: &Arc<Socket>, msg: Msg, nonblock: bool) -> Result<(), i64> {
        let until = deadline(self.st.lock().unwrap().opts.sndtimeo);
        loop {
            let seen = EVENTS.watch_key(target.key());
            {
                let mut q = target.rx.lock().unwrap();
                if q.bytes + msg.data.len() <= QUEUE_LIMIT || q.bytes == 0 {
                    q.bytes += msg.data.len();
                    q.msgs.push_back(msg);
                    drop(q);
                    target.serve();
                    EVENTS.bump_key(target.key());
                    return Ok(());
                }
            }
            if nonblock {
                return Err(EAGAIN);
            }
            wait_or_give_up(t, seen, until)?;
        }
    }

    /// Sends on a connection, or for datagrams to `dest` (already looked up)
    /// or the connected peer.
    fn send(self: &Arc<Self>, t: &Thread, data: Vec<u8>, fds: Vec<Arc<File>>, dest: Option<Arc<Socket>>, nonblock: bool) -> Result<usize, i64> {
        let (name, connected, shut_wr, peer) = {
            let st = self.st.lock().unwrap();
            (st.name.clone().unwrap_or_default(), st.connected, st.shut_wr, st.peer.clone())
        };
        if shut_wr {
            return Err(EPIPE);
        }
        let len = data.len();
        if self.ty == SOCK_DGRAM {
            let target = match dest {
                Some(d) => d,
                None if !connected => return Err(ENOTCONN),
                None => match peer.as_ref().and_then(Weak::upgrade) {
                    Some(p) => p,
                    None => {
                        // The peer is gone: report it once, then act unconnected.
                        let mut st = self.st.lock().unwrap();
                        st.connected = false;
                        st.peer = None;
                        st.peer_cred = Cred::default();
                        return Err(ECONNREFUSED);
                    }
                },
            };
            let tap = {
                let ts = target.st.lock().unwrap();
                // A datagram socket connected elsewhere only takes from its peer.
                if ts.peer.as_ref().is_some_and(|p| !std::ptr::eq(p.as_ptr(), Arc::as_ptr(self))) {
                    return Err(EPERM);
                }
                ts.log_tap
            };
            let copy = tap.then(|| data.clone());
            self.deliver(t, &target, Msg { data, off: 0, fds, from: name, cred: Cred::of(t) }, nonblock)?;
            if let Some(d) = copy {
                logd::tap(&d, t.proc.pid);
            }
            return Ok(len);
        }
        let peer = self.peer().ok_or(if connected { EPIPE } else { ENOTCONN })?;
        self.deliver(t, &peer, Msg { data, off: 0, fds, from: name, cred: Cred::of(t) }, nonblock)?;
        Ok(len)
    }

    /// Receives up to `max` bytes: data, passed files, sender address, sender
    /// credentials, and the real datagram length (the copied length, for a stream).
    fn recv(&self, t: &Thread, max: usize, flags: u64, nonblock: bool) -> Result<Received, i64> {
        let peek = flags & MSG_PEEK != 0;
        let mut out = Vec::new();
        let mut fds = Vec::new();
        let (mut from, mut cred) = (Vec::new(), Cred::default());
        let until = deadline(self.st.lock().unwrap().opts.rcvtimeo);
        loop {
            let seen = EVENTS.watch(&self.mask());
            let (connected, shut_rd, gone) = {
                let st = self.st.lock().unwrap();
                if st.backlog.is_some() {
                    return Err(EINVAL);
                }
                let gone = st.connected && self.ty != SOCK_DGRAM && st.peer.as_ref().and_then(Weak::upgrade).is_none();
                (st.connected, st.shut_rd, gone)
            };
            if self.ty != SOCK_DGRAM && !connected {
                return Err(ENOTCONN);
            }
            {
                let mut q = self.rx.lock().unwrap();
                if self.ty != SOCK_STREAM {
                    if let Some(m) = q.msgs.front() {
                        let real = m.data.len();
                        out.extend_from_slice(&m.data[..real.min(max)]);
                        from = m.from.clone();
                        cred = m.cred;
                        if !peek {
                            let m = q.msgs.pop_front().unwrap();
                            q.bytes -= m.data.len();
                            fds = m.fds;
                            drop(q);
                            EVENTS.bump_key(self.key());
                        }
                        return Ok((out, fds, from, cred, real));
                    }
                } else {
                    let mut consumed = false;
                    let mut i = 0;
                    while out.len() < max && i < q.msgs.len() {
                        let m = &q.msgs[i];
                        // Files ride on the first message read; don't merge past another batch.
                        if !m.fds.is_empty() && (consumed || !fds.is_empty()) {
                            break;
                        }
                        let n = (m.data.len() - m.off).min(max - out.len());
                        out.extend_from_slice(&m.data[m.off..m.off + n]);
                        if !consumed {
                            from = m.from.clone();
                            cred = m.cred;
                        }
                        consumed = true;
                        if peek {
                            i += 1;
                            continue;
                        }
                        let m = &mut q.msgs[i];
                        fds.append(&mut m.fds);
                        m.off += n;
                        if m.off == m.data.len() {
                            let m = q.msgs.remove(i).unwrap();
                            q.bytes -= m.data.len();
                        } else {
                            break;
                        }
                    }
                    let done = consumed && (flags & MSG_WAITALL == 0 || out.len() >= max);
                    if done || (consumed && (q.write_closed || gone)) {
                        drop(q);
                        if !peek {
                            EVENTS.bump_key(self.key());
                        }
                        let n = out.len();
                        return Ok((out, fds, from, cred, n));
                    }
                }
                if q.write_closed || gone || shut_rd {
                    let n = out.len();
                    return Ok((out, fds, from, cred, n)); // EOF
                }
            }
            if nonblock {
                let n = out.len();
                return if n == 0 { Err(EAGAIN) } else { Ok((out, fds, from, cred, n)) };
            }
            if let Err(e) = wait_or_give_up(t, seen, until) {
                let n = out.len();
                return if n == 0 { Err(e) } else { Ok((out, fds, from, cred, n)) };
            }
        }
    }
}

/// (data, passed files, sender address, sender credentials, real datagram length).
type Received = (Vec<u8>, Vec<Arc<File>>, Vec<u8>, Cred, usize);

/// Reads plain bytes and fds out of a socket file's read/write path.
pub fn read(sock: &Socket, t: &Thread, max: usize, nonblock: bool) -> Result<Vec<u8>, i64> {
    sock.recv(t, max, 0, nonblock).map(|r| r.0) // passed files are dropped by read(2), as on Linux
}

pub fn write(sock: &Arc<Socket>, t: &Thread, data: Vec<u8>, nonblock: bool) -> Result<usize, i64> {
    sock.send(t, data, Vec::new(), None, nonblock)
}

impl Kernel {
    /// sendmmsg and recvmmsg: sendmsg and recvmsg over an array of `struct mmsghdr`,
    /// each a msghdr and the length that came of it. An error after the first message
    /// isn't reported: what went through is.
    fn many_messages(&self, no: Sysno, t: &Arc<Thread>, a: [u64; 6]) -> Result<i64, i64> {
        const MMSGHDR: u64 = 64;
        const MSG_WAITFORONE: u64 = 0x10000;
        let receiving = no == Sysno::recvmmsg;
        let flags = a[3];
        // Checked after each message, as Linux does: the first can wait for ever.
        let until = if receiving && a[4] != 0 {
            let spec = t.proc.mm().read_vec(a[4], 16)?;
            let (s, ns) = (i64::from_le_bytes(spec[0..8].try_into().unwrap()), i64::from_le_bytes(spec[8..16].try_into().unwrap()));
            if s < 0 || !(0..1_000_000_000).contains(&ns) {
                return Err(EINVAL);
            }
            Some(super::wait::instant_after(Duration::new(s as u64, ns as u32)))
        } else {
            None
        };
        let mut done = 0;
        for i in 0..a[2].min(1024) {
            let msg = a[1] + i * MMSGHDR;
            let this = if receiving && i > 0 && flags & MSG_WAITFORONE != 0 { flags | MSG_DONTWAIT } else { flags } & !MSG_WAITFORONE;
            match self.socket_syscall(if receiving { Sysno::recvmsg } else { Sysno::sendmsg }, t, [a[0], msg, this, 0, 0, 0]) {
                Ok(n) => t.proc.mm().write_u32(msg + 56, n as u32)?,
                Err(e) if done == 0 => return Err(e),
                Err(e) => {
                    // Taken from the socket, and this call has something else to say. Its
                    // reader needn't wait for ever for what it would have been told.
                    if receiving
                        && !matches!(e, EAGAIN | EINTR | ERESTARTSYS)
                        && let Ok(f) = t.files().get(int(a[0]))
                        && let Kind::Inet(s) = &f.kind
                    {
                        s.put_back_err(e);
                    }
                    break;
                }
            }
            done += 1;
            if until.is_some_and(|at| Instant::now() >= at) {
                break;
            }
        }
        if let Some(at) = until {
            let left = at.saturating_duration_since(Instant::now());
            let spec = [(left.as_secs() as i64).to_le_bytes(), (left.subsec_nanos() as i64).to_le_bytes()].concat();
            t.proc.mm().write(a[4], &spec)?;
        }
        Ok(done)
    }

    pub(super) fn socket_syscall(&self, no: Sysno, t: &Arc<Thread>, a: [u64; 6]) -> Result<i64, i64> {
        use Sysno::*;
        if no == sendmmsg || no == recvmmsg {
            return self.many_messages(no, t, a);
        }
        if no != socket && no != socketpair {
            let f = t.files().get(int(a[0]))?;
            if let Kind::Netlink(nl) = &f.kind {
                return self.netlink_syscall(no, t, nl, &f, a);
            }
            if let Kind::Inet(s) = &f.kind {
                return self.inet_syscall(no, t, s, &f, a);
            }
            if let Kind::Vsock(v) = &f.kind {
                return self.vsock_syscall(no, t, &f, v, a);
            }
        }
        match no {
            socket if a[0] == netlink::AF_NETLINK => self.netlink_socket(t, a),
            socket if a[0] == super::inet::AF_INET || a[0] == super::inet::AF_INET6 => self.inet_socket(t, a),
            // Closing a PF_KEY socket waits for RCU on Linux; netd's stats map
            // swap opens and closes one for that alone. Nothing here needs it.
            socket if a[0] == super::inet::AF_KEY => {
                if a[1] & 0xf != 3 {
                    return Err(ESOCKTNOSUPPORT);
                }
                if a[2] != 2 {
                    return Err(EPROTONOSUPPORT); // PF_KEY_V2 only
                }
                self.inet_socket(t, a)
            }
            socket if a[0] == super::vsock::AF_VSOCK => {
                if a[1] & 0xf != SOCK_STREAM as u64 {
                    return Err(ESOCKTNOSUPPORT);
                }
                let file = File::new(Kind::Vsock(super::vsock::Vsock::new()), (a[1] & SOCK_NONBLOCK) as u32);
                t.files().alloc(file, a[1] & SOCK_CLOEXEC != 0, 0)
            }
            socket => {
                if a[0] != AF_UNIX {
                    return Err(EAFNOSUPPORT);
                }
                let ty = sock_type(a[1])?;
                let file = File::new(Kind::Socket(Socket::new(ty, Cred::of(t))), (a[1] & SOCK_NONBLOCK) as u32);
                t.files().alloc(file, a[1] & SOCK_CLOEXEC != 0, 0)
            }
            socketpair => {
                if a[0] != AF_UNIX {
                    return Err(if a[0] == netlink::AF_NETLINK { EOPNOTSUPP } else { EAFNOSUPPORT });
                }
                let ty = sock_type(a[1])?;
                let cred = Cred::of(t);
                let (x, y) = (Socket::new(ty, cred), Socket::new(ty, cred));
                Socket::connect_pair(&x, &y, Cred::of(t), Cred::of(t));
                let flags = (a[1] & SOCK_NONBLOCK) as u32;
                let cloexec = a[1] & SOCK_CLOEXEC != 0;
                let (fx, fy) = {
                    let mut files = t.files();
                    let fx = files.alloc(File::new(Kind::Socket(x), flags), cloexec, 0)?;
                    match files.alloc(File::new(Kind::Socket(y), flags), cloexec, 0) {
                        Ok(fy) => (fx, fy),
                        Err(e) => {
                            files.close(fx);
                            return Err(e);
                        }
                    }
                };
                let mut sv = [0u8; 8];
                sv[..4].copy_from_slice(&(fx as i32).to_le_bytes());
                sv[4..].copy_from_slice(&(fy as i32).to_le_bytes());
                t.proc.mm().write(a[3], &sv)?;
                Ok(0)
            }
            bind => {
                let (sock, _) = self.sock(t, int(a[0]))?;
                let name = match self.read_addr(t, a[1], a[2])? {
                    Some(n) => n,
                    None => return autobind(&sock).map(|_| 0),
                };
                let mut st = sock.st.lock().unwrap();
                if st.name.is_some() {
                    return Err(EINVAL);
                }
                if name[0] == 0 {
                    let mut names = ABSTRACT.lock().unwrap();
                    let key = (sock.ty, name.clone());
                    if names.get(&key).is_some_and(|w| w.strong_count() > 0) {
                        return Err(EADDRINUSE);
                    }
                    names.insert(key, Arc::downgrade(&sock));
                } else {
                    let vfs = self.vfs.as_deref().ok_or(ENOENT)?;
                    let path = String::from_utf8_lossy(&name).into_owned();
                    let cwd = t.proc.cwd.lock().unwrap().clone();
                    let node = bind_node(vfs, &cwd, &path, 0o777 & !t.proc.umask.load(Ordering::Relaxed), &sock)?;
                    st.node = Some(node_key(&vfs.fs_arc(&node), node.ino));
                    st.log_tap = node.path == "/dev/socket/logdw";
                }
                st.name = Some(name);
                Ok(0)
            }
            listen => {
                let (sock, _) = self.sock(t, int(a[0]))?;
                if sock.ty == SOCK_DGRAM {
                    return Err(EOPNOTSUPP);
                }
                let mut st = sock.st.lock().unwrap();
                if st.connected || st.name.is_none() {
                    return Err(EINVAL);
                }
                st.backlog.get_or_insert_with(VecDeque::new);
                let mut cred = Cred::of(t);
                cred.sid = sock.cred.sid;
                st.listen_cred = cred;
                Ok(0)
            }
            accept | accept4 => {
                let (sock, file) = self.sock(t, int(a[0]))?;
                let flags = if no == accept4 { a[3] } else { 0 };
                let until = deadline(sock.st.lock().unwrap().opts.rcvtimeo);
                let conn = loop {
                    let seen = EVENTS.watch_key(sock.key());
                    {
                        let mut st = sock.st.lock().unwrap();
                        let backlog = st.backlog.as_mut().ok_or(EINVAL)?;
                        if let Some(c) = backlog.pop_front() {
                            break c;
                        }
                    }
                    if file.nonblock() {
                        return Err(EAGAIN);
                    }
                    wait_or_give_up(t, seen, until)?;
                };
                EVENTS.bump_key(sock.key());
                // A connection takes SO_PASSCRED from its listener: init sets it
                // on sockets declared "passcred", and lmkd counts on it.
                if sock.st.lock().unwrap().passcred {
                    conn.st.lock().unwrap().passcred = true;
                }
                let peer_name = conn.peer().and_then(|p| p.st.lock().unwrap().name.clone());
                let f = File::new(Kind::Socket(conn.clone()), (flags & SOCK_NONBLOCK) as u32);
                let fd = match t.files().alloc(f, flags & SOCK_CLOEXEC != 0, 0) {
                    Ok(fd) => fd,
                    Err(e) => {
                        // No descriptor for it: it stays for when there is one.
                        if let Some(backlog) = sock.st.lock().unwrap().backlog.as_mut() {
                            backlog.push_front(conn);
                        }
                        EVENTS.bump_key(sock.key());
                        return Err(e);
                    }
                };
                if a[1] != 0 {
                    self.write_addr(t, a[1], a[2], peer_name.as_deref())?;
                }
                Ok(fd)
            }
            connect => {
                let (sock, _) = self.sock(t, int(a[0]))?;
                if sock.ty == SOCK_DGRAM && a[2] >= 2 && t.proc.mm().read_vec(a[1], 2)? == [0, 0] {
                    // AF_UNSPEC dissolves a datagram association.
                    let mut st = sock.st.lock().unwrap();
                    st.connected = false;
                    st.peer = None;
                    st.peer_cred = Cred::default();
                    return Ok(0);
                }
                let name = self.read_addr(t, a[1], a[2])?.ok_or(EINVAL)?;
                let target = self.find(t, &name, sock.ty)?;
                if sock.ty == SOCK_DGRAM {
                    let peer_cred = target.cred;
                    let mut st = sock.st.lock().unwrap();
                    st.peer = Some(Arc::downgrade(&target));
                    st.peer_cred = peer_cred;
                    st.connected = true;
                    return Ok(0);
                }
                if sock.st.lock().unwrap().connected {
                    return Err(EISCONN);
                }
                let listener = target;
                if let Some(svc) = &listener.service {
                    // A kernel-side service answers on its own; nothing to accept.
                    let server = Arc::new(Socket { ty: sock.ty, cred: Cred { pid: 1, uid: 0, gid: 0, sid: 0 }, rx: Mutex::new(Queue::default()), st: Mutex::new(State::default()), service: Some(svc.clone()), svc_buf: Mutex::new(Vec::new()) });
                    server.st.lock().unwrap().name = listener.st.lock().unwrap().name.clone();
                    let mut client = Cred::of(t);
                    client.sid = sock.cred.sid;
                    Socket::connect_pair(&sock, &server, client, Cred { pid: 1, uid: 0, gid: 0, sid: 0 });
                    sock.st.lock().unwrap().peer_server = Some(server);
                    return Ok(0);
                }
                let mut lst = listener.st.lock().unwrap();
                let (listen_cred, listen_name) = (lst.listen_cred, lst.name.clone());
                let server = Socket::new(sock.ty, listen_cred);
                let backlog = lst.backlog.as_mut().ok_or(ECONNREFUSED)?;
                if backlog.len() >= 4096 {
                    return Err(EAGAIN);
                }
                server.st.lock().unwrap().name = listen_name;
                let mut client = Cred::of(t);
                client.sid = sock.cred.sid;
                Socket::connect_pair(&sock, &server, client, listen_cred);
                backlog.push_back(server);
                drop(lst);
                EVENTS.bump_key(listener.key());
                EVENTS.bump_key(sock.key());
                Ok(0)
            }
            getsockname => {
                let (sock, _) = self.sock(t, int(a[0]))?;
                let name = sock.st.lock().unwrap().name.clone();
                self.write_addr(t, a[1], a[2], name.as_deref())?;
                Ok(0)
            }
            getpeername => {
                let (sock, _) = self.sock(t, int(a[0]))?;
                if !sock.st.lock().unwrap().connected {
                    return Err(ENOTCONN);
                }
                let name = sock.peer().and_then(|p| p.st.lock().unwrap().name.clone());
                self.write_addr(t, a[1], a[2], name.as_deref())?;
                Ok(0)
            }
            sendto => {
                let (sock, file) = self.sock(t, int(a[0]))?;
                let data = t.proc.mm().read_vec(a[1], a[2].min(IO_MAX) as usize)?;
                let dest = self.send_dest(t, &sock, a[4], a[5])?;
                let nonblock = file.nonblock() || a[3] & MSG_DONTWAIT != 0;
                self.finish_send(t, sock.send(t, data, Vec::new(), dest, nonblock), a[3])
            }
            recvfrom => {
                let (sock, file) = self.sock(t, int(a[0]))?;
                let nonblock = file.nonblock() || a[3] & MSG_DONTWAIT != 0;
                let (data, _fds, from, _cred, real) = sock.recv(t, a[2].min(IO_MAX) as usize, a[3], nonblock)?;
                t.proc.mm().write(a[1], &data)?;
                if a[4] != 0 {
                    self.write_addr(t, a[4], a[5], (!from.is_empty()).then_some(&from[..]))?;
                }
                // MSG_TRUNC: the return value is the real datagram length.
                Ok(if a[3] & MSG_TRUNC != 0 { real } else { data.len() } as i64)
            }
            sendmsg => self.sendmsg(t, int(a[0]), a[1], a[2]),
            recvmsg => self.recvmsg(t, int(a[0]), a[1], a[2]),
            shutdown => {
                let (sock, _) = self.sock(t, int(a[0]))?;
                let mut st = sock.st.lock().unwrap();
                if !st.connected {
                    return Err(ENOTCONN);
                }
                if a[1] != SHUT_WR {
                    st.shut_rd = true;
                }
                if a[1] != SHUT_RD {
                    st.shut_wr = true;
                    if sock.ty != SOCK_DGRAM
                        && let Some(p) = st.peer.as_ref().and_then(Weak::upgrade)
                    {
                        p.rx.lock().unwrap().write_closed = true;
                        EVENTS.bump_key(p.key());
                    }
                }
                drop(st);
                EVENTS.bump_key(sock.key());
                Ok(0)
            }
            setsockopt => {
                let (sock, _) = self.sock(t, int(a[0]))?;
                if a[1] == SOL_SOCKET && a[2] == SO_PASSCRED {
                    let on = t.proc.mm().read_u32(a[3])? != 0;
                    sock.st.lock().unwrap().passcred = on;
                } else if a[1] == SOL_SOCKET {
                    let val = sockopt_bytes(t, a[3], a[4])?;
                    sock.st.lock().unwrap().opts.set(a[2], &val)?;
                }
                Ok(0) // buffer sizes and the like: accepted
            }
            getsockopt => {
                let (sock, _) = self.sock(t, int(a[0]))?;
                if a[1] != SOL_SOCKET {
                    return Err(ENOPROTOOPT);
                }
                if a[2] == SO_PEERSEC {
                    // The peer socket's label from its socket(); ERANGE says how much room it needs.
                    let sid = if sock.ty == SOCK_DGRAM { 0 } else { sock.st.lock().unwrap().peer_cred.sid };
                    let ctx = super::selinux::context_bytes(sid).ok_or(ENOPROTOOPT)?;
                    let mut mm = t.proc.mm();
                    let cap = mm.read_u32(a[4])? as usize;
                    mm.write_u32(a[4], ctx.len() as u32)?;
                    if cap < ctx.len() {
                        return Err(ERANGE);
                    }
                    mm.write(a[3], &ctx)?;
                    return Ok(0);
                }
                let st = sock.st.lock().unwrap();
                let val: Vec<u8> = match a[2] {
                    SO_PEERCRED => st.peer_cred.bytes().to_vec(),
                    SO_TYPE => sock.ty.to_le_bytes().to_vec(),
                    SO_ERROR | SO_PROTOCOL => 0u32.to_le_bytes().to_vec(),
                    SO_DOMAIN => (AF_UNIX as u32).to_le_bytes().to_vec(),
                    SO_SNDBUF | SO_RCVBUF => (QUEUE_LIMIT as u32).to_le_bytes().to_vec(),
                    SO_PASSCRED => (st.passcred as u32).to_le_bytes().to_vec(),
                    SO_ACCEPTCONN => (st.backlog.is_some() as u32).to_le_bytes().to_vec(),
                    // The peer's SELinux context (libselinux's getpeercon; init's
                    // property service checks it). Every process runs in one
                    // domain, as /proc/<pid>/attr/current says.
                    SO_PEERSEC if st.connected => b"u:r:su:s0\0".to_vec(),
                    opt => st.opts.get(opt).ok_or_else(|| {
                        eprintln!("[droidrt] getsockopt(AF_UNIX, SOL_SOCKET, {opt}) unsupported");
                        ENOPROTOOPT
                    })?,
                };
                drop(st);
                let mut mm = t.proc.mm();
                let cap = mm.read_u32(a[4])? as usize;
                if a[2] == SO_PEERSEC && cap < val.len() {
                    mm.write_u32(a[4], val.len() as u32)?;
                    return Err(ERANGE);
                }
                let n = cap.min(val.len());
                mm.write(a[3], &val[..n])?;
                mm.write_u32(a[4], n as u32)?;
                Ok(0)
            }
            _ => Err(ENOSYS),
        }
    }

    fn sock(&self, t: &Thread, fd: i64) -> Result<(Arc<Socket>, Arc<File>), i64> {
        let f = t.files().get(fd)?;
        match &f.kind {
            Kind::Socket(s) => Ok((s.clone(), f.clone())),
            _ => Err(ENOTSOCK),
        }
    }

    fn finish_send(&self, t: &Arc<Thread>, r: Result<usize, i64>, flags: u64) -> Result<i64, i64> {
        match r {
            Err(EPIPE) => {
                if flags & MSG_NOSIGNAL == 0 {
                    self.send_thread_signal(t, SIGPIPE, SigInfo::user(SIGPIPE, t.proc.pid));
                }
                Err(EPIPE)
            }
            r => r.map(|n| n as i64),
        }
    }

    /// A `sockaddr_un`'s name: a path (up to its NUL, as given), or "\0name"
    /// for the abstract namespace. `None` for an unnamed address.
    fn read_addr(&self, t: &Thread, addr: u64, len: u64) -> Result<Option<Vec<u8>>, i64> {
        if !(2..=110).contains(&len) {
            return Err(EINVAL);
        }
        let b = t.proc.mm().read_vec(addr, len as usize)?;
        if u16::from_le_bytes([b[0], b[1]]) as u64 != AF_UNIX {
            return Err(EINVAL);
        }
        let path = &b[2..];
        match path.first() {
            None => Ok(None),
            Some(0) => Ok(Some(path.to_vec())),
            Some(_) => Ok(Some(path.split(|&c| c == 0).next().unwrap_or(path).to_vec())),
        }
    }

    /// The socket bound at a name (connect, sendto): the socket node a path
    /// resolves to (symlinks followed), or an abstract name.
    fn find(&self, t: &Thread, name: &[u8], ty: u32) -> Result<Arc<Socket>, i64> {
        let sock = if name[0] == 0 {
            ABSTRACT.lock().unwrap().get(&(ty, name.to_vec())).and_then(Weak::upgrade).ok_or(ECONNREFUSED)?
        } else {
            let vfs = self.vfs.as_deref().ok_or(ENOENT)?;
            let node = self.resolve(t, AT_FDCWD, &String::from_utf8_lossy(name), true)?;
            if vfs.stat(&node)?.mode & S_IFMT != S_IFSOCK {
                return Err(ECONNREFUSED);
            }
            let key = node_key(&vfs.fs_arc(&node), node.ino);
            BOUND.lock().unwrap().get(&key).and_then(|(_, s)| s.upgrade()).ok_or(ECONNREFUSED)?
        };
        if sock.ty != ty {
            return Err(EPROTOTYPE);
        }
        Ok(sock)
    }

    /// Where a sendto/sendmsg address sends to: datagram sockets look it up;
    /// stream sockets refuse one and seqpacket ignores it, as on Linux.
    fn send_dest(&self, t: &Thread, sock: &Socket, addr: u64, len: u64) -> Result<Option<Arc<Socket>>, i64> {
        if addr == 0 || len == 0 {
            return Ok(None);
        }
        match sock.ty {
            SOCK_DGRAM => {
                let name = self.read_addr(t, addr, len)?.ok_or(EINVAL)?;
                self.find(t, &name, SOCK_DGRAM).map(Some)
            }
            SOCK_STREAM => Err(if sock.st.lock().unwrap().connected { EISCONN } else { EOPNOTSUPP }),
            _ => Ok(None),
        }
    }

    fn write_addr(&self, t: &Thread, addr: u64, len_p: u64, name: Option<&[u8]>) -> Result<(), i64> {
        let mut sa = (AF_UNIX as u16).to_le_bytes().to_vec();
        if let Some(n) = name {
            sa.extend_from_slice(n);
            if n.first() != Some(&0) {
                sa.push(0); // paths are NUL-terminated
            }
        }
        let mut mm = t.proc.mm();
        let cap = mm.read_u32(len_p)? as usize;
        mm.write(addr, &sa[..cap.min(sa.len())])?;
        mm.write_u32(len_p, sa.len() as u32)
    }

    fn sendmsg(&self, t: &Arc<Thread>, fd: i64, msg: u64, flags: u64) -> Result<i64, i64> {
        let (sock, file) = self.sock(t, fd)?;
        let (name, namelen, iov, iovlen, control, controllen) = {
            let mut mm = t.proc.mm();
            (mm.read_u64(msg)?, mm.read_u32(msg + 8)? as u64, mm.read_u64(msg + 16)?, mm.read_u64(msg + 24)?, mm.read_u64(msg + 32)?, mm.read_u64(msg + 40)?)
        };
        let mut data = Vec::new();
        {
            let mut mm = t.proc.mm();
            for i in 0..iovlen.min(1024) {
                let (base, len) = (mm.read_u64(iov + i * 16)?, mm.read_u64(iov + i * 16 + 8)?);
                data.extend(mm.read_vec(base, len.min(IO_MAX) as usize)?);
            }
        }
        let mut fds = Vec::new();
        if control != 0 && controllen >= 16 {
            let ctl = t.proc.mm().read_vec(control, controllen.min(4096) as usize)?;
            let mut off = 0;
            while off + 16 <= ctl.len() {
                let len = u64::from_le_bytes(ctl[off..off + 8].try_into().unwrap()) as usize;
                let level = i32::from_le_bytes(ctl[off + 8..off + 12].try_into().unwrap());
                let ty = i32::from_le_bytes(ctl[off + 12..off + 16].try_into().unwrap());
                // A crafted length can wrap `off + len` and panic on the slice.
                let Some(end) = off.checked_add(len) else {
                    return Err(EINVAL);
                };
                if len < 16 || end > ctl.len() {
                    return Err(EINVAL);
                }
                if level as u64 == SOL_SOCKET && ty == SCM_RIGHTS {
                    let files = t.files();
                    for c in ctl[off + 16..off + len].chunks_exact(4) {
                        fds.push(files.get(i32::from_le_bytes(c.try_into().unwrap()) as i64)?);
                    }
                }
                off += len.next_multiple_of(8);
            }
        }
        let dest = self.send_dest(t, &sock, name, namelen)?;
        let nonblock = file.nonblock() || flags & MSG_DONTWAIT != 0;
        self.finish_send(t, sock.send(t, data, fds, dest, nonblock), flags)
    }

    fn recvmsg(&self, t: &Thread, fd: i64, msg: u64, flags: u64) -> Result<i64, i64> {
        let (sock, file) = self.sock(t, fd)?;
        let (name, iov, iovlen, control, controllen) = {
            let mut mm = t.proc.mm();
            (mm.read_u64(msg)?, mm.read_u64(msg + 16)?, mm.read_u64(msg + 24)?, mm.read_u64(msg + 32)?, mm.read_u64(msg + 40)?)
        };
        let mut iovs = Vec::new();
        {
            let mut mm = t.proc.mm();
            for i in 0..iovlen.min(1024) {
                iovs.push((mm.read_u64(iov + i * 16)?, mm.read_u64(iov + i * 16 + 8)?));
            }
        }
        let total: u64 = iovs.iter().map(|v| v.1).sum();
        let nonblock = file.nonblock() || flags & MSG_DONTWAIT != 0;
        let (data, fds, from, cred, real) = sock.recv(t, total.min(IO_MAX) as usize, flags, nonblock)?;

        // Scatter into the iovecs.
        {
            let mut mm = t.proc.mm();
            let mut off = 0;
            for (base, len) in iovs {
                if off >= data.len() {
                    break;
                }
                let n = (len as usize).min(data.len() - off);
                mm.write(base, &data[off..off + n])?;
                off += n;
            }
        }
        // Control messages: credentials if asked for, then passed files.
        let mut ctl = Vec::new();
        let mut msg_flags = if real > data.len() { MSG_TRUNC as u32 } else { 0 };
        if sock.st.lock().unwrap().passcred {
            push_cmsg(&mut ctl, SCM_CREDENTIALS, &cred.bytes());
        }
        if !fds.is_empty() {
            let need = 16 + fds.len() * 4;
            if (controllen as usize) < ctl.len() + need {
                msg_flags |= MSG_CTRUNC; // the files are dropped, as on Linux
            } else {
                let mut files = t.files();
                let mut raw = Vec::new();
                for f in fds {
                    let nfd = files.alloc(f, flags & MSG_CMSG_CLOEXEC != 0, 0)?;
                    raw.extend_from_slice(&(nfd as i32).to_le_bytes());
                }
                push_cmsg(&mut ctl, SCM_RIGHTS, &raw);
            }
        }
        if ctl.len() > controllen as usize {
            ctl.truncate(controllen as usize);
            msg_flags |= MSG_CTRUNC;
        }
        {
            let mut mm = t.proc.mm();
            if !ctl.is_empty() {
                mm.write(control, &ctl)?;
            }
            mm.write_u64(msg + 40, ctl.len() as u64)?;
            mm.write_u32(msg + 48, msg_flags)?;
        }
        if name != 0 {
            self.write_addr(t, name, msg + 8, (!from.is_empty()).then_some(&from[..]))?;
        }
        Ok(if flags & MSG_TRUNC != 0 { real as i64 } else { data.len() as i64 })
    }
}

/// Binds to a fresh abstract name, "\0" and five hex digits (Linux's autobind).
fn autobind(sock: &Arc<Socket>) -> Result<(), i64> {
    static NEXT: AtomicU32 = AtomicU32::new(0);
    let mut st = sock.st.lock().unwrap();
    if st.name.is_some() {
        return Ok(());
    }
    let mut names = ABSTRACT.lock().unwrap();
    for _ in 0..0x100000 {
        let name = format!("\0{:05x}", NEXT.fetch_add(1, Ordering::Relaxed) & 0xfffff).into_bytes();
        let key = (sock.ty, name.clone());
        if names.get(&key).is_none_or(|w| w.strong_count() == 0) {
            names.insert(key, Arc::downgrade(sock));
            st.name = Some(name);
            return Ok(());
        }
    }
    Err(ENOSPC)
}

fn sock_type(ty: u64) -> Result<u32, i64> {
    match (ty & 0xf) as u32 {
        t @ (SOCK_STREAM | SOCK_DGRAM | SOCK_SEQPACKET) => Ok(t),
        _ => Err(EPROTONOSUPPORT),
    }
}

/// Appends a `cmsghdr` (64-bit layout) with SOL_SOCKET level, padded to 8.
fn push_cmsg(out: &mut Vec<u8>, ty: i32, data: &[u8]) {
    out.extend_from_slice(&((16 + data.len()) as u64).to_le_bytes());
    out.extend_from_slice(&(SOL_SOCKET as i32).to_le_bytes());
    out.extend_from_slice(&ty.to_le_bytes());
    out.extend_from_slice(data);
    while !out.len().is_multiple_of(8) {
        out.push(0);
    }
}

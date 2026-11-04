//! AF_NETLINK sockets. The kernel end answers the way an idle Linux with only
//! loopback would: rtnetlink shows `lo` (net.rs), other dumps (sock_diag, …)
//! come back as a bare NLMSG_DONE, requests asking for an ack get NLMSG_ERROR 0, audit
//! keeps its status (logd registers as auditd), and uevents arrive only when
//! someone broadcasts one (`uevent`). Sockets of one protocol reach each
//! other by port id (unicast) and by group (multicast).

use super::files::{File, Kind};
use super::wait::EVENTS;
use super::{ERESTARTSYS, Kernel, POLL, Thread, int};
use crate::arch::Sysno;
use crate::errno::*;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::atomic::{AtomicI32, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Weak};

pub const AF_NETLINK: u64 = 16;
const SOCK_DGRAM: u32 = 2;
const SOCK_RAW: u32 = 3;
const SOCK_NONBLOCK: u64 = 0o4000;
const SOCK_CLOEXEC: u64 = 0o2000000;
const MSG_PEEK: u64 = 0x2;
const MSG_CTRUNC: u32 = 0x8;
const MSG_TRUNC: u64 = 0x20;
const MSG_DONTWAIT: u64 = 0x40;
const SOL_SOCKET: u64 = 1;
const SOL_NETLINK: u64 = 270;
const SCM_CREDENTIALS: i32 = 2;
const SO_TYPE: u64 = 3;
const SO_ERROR: u64 = 4;
const SO_SNDBUF: u64 = 7;
const SO_RCVBUF: u64 = 8;
const SO_PASSCRED: u64 = 16;
const SO_PEERCRED: u64 = 17;
const SO_BINDTODEVICE: u64 = 25;
const SO_ACCEPTCONN: u64 = 30;
const SO_SNDBUFFORCE: u64 = 32;
const SO_RCVBUFFORCE: u64 = 33;
const SO_PROTOCOL: u64 = 38;
const SO_DOMAIN: u64 = 39;
const NETLINK_ADD_MEMBERSHIP: u64 = 1;
const NETLINK_DROP_MEMBERSHIP: u64 = 2;
const NETLINK_PKTINFO: u64 = 3;
const NETLINK_LIST_MEMBERSHIPS: u64 = 9;
const NETLINK_NO_ENOBUFS: u64 = 5;
const NETLINK_CAP_ACK: u64 = 10;
/// The boolean SOL_NETLINK options (PKTINFO, BROADCAST_ERROR, NO_ENOBUFS,
/// LISTEN_ALL_NSID, CAP_ACK, EXT_ACK, GET_STRICT_CHK), by number.
const FLAG_OPTS: u32 = 1 << 3 | 1 << 4 | 1 << 5 | 1 << 8 | 1 << 10 | 1 << 11 | 1 << 12;
/// net.core.{r,w}mem_default and _max.
const BUF_DEFAULT: u32 = 212992;
const BUF_MIN: u32 = 4608;
const IO_MAX: u64 = 16 << 20;

pub const NETLINK_ROUTE: u32 = 0;
const NETLINK_SOCK_DIAG: u32 = 4;
const NETLINK_XFRM: u32 = 6;
const NETLINK_SELINUX: u32 = 7;
const NETLINK_AUDIT: u32 = 9;
const NETLINK_NETFILTER: u32 = 12;
pub const NETLINK_KOBJECT_UEVENT: u32 = 15;
const NETLINK_GENERIC: u32 = 16;

const NLM_F_REQUEST: u16 = 0x1;
const NLM_F_MULTI: u16 = 0x2;
const NLM_F_ACK: u16 = 0x4;
const NLM_F_CAPPED: u16 = 0x100;
const NLM_F_DUMP: u16 = 0x300;
const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;
const NLMSG_MIN_TYPE: u16 = 0x10;
const RTM_NEWLINK: u16 = 16;
const RTM_GETLINK: u16 = 18;
const RTM_NEWADDR: u16 = 20;
const RTM_GETADDR: u16 = 22;
const RTM_GETROUTE: u16 = 26;
const RTM_MAX: u16 = 127;
const AUDIT_GET: u16 = 1000;
const AUDIT_SET: u16 = 1001;
const AUDIT_LIST_RULES: u16 = 1013;
const AUDIT_TTY_GET: u16 = 1016;
const AUDIT_GET_FEATURE: u16 = 1019;

const POLLIN: u16 = 0x1;
const POLLOUT: u16 = 0x4;

/// Multicast groups a protocol has (Linux gives every one at least 32).
fn ngroups(proto: u32) -> Option<u32> {
    match proto {
        NETLINK_ROUTE => Some(36),
        NETLINK_GENERIC => Some(64),
        NETLINK_SOCK_DIAG | NETLINK_XFRM | NETLINK_SELINUX | NETLINK_AUDIT | NETLINK_NETFILTER | NETLINK_KOBJECT_UEVENT => Some(32),
        _ => None,
    }
}

#[derive(Clone)]
struct Packet {
    data: Vec<u8>,
    /// Sender's port id: 0 for the kernel.
    from: u32,
    /// Multicast group it was sent to (0: unicast).
    group: u32,
    /// Sender's (pid, uid, gid); zero for the kernel.
    cred: [u32; 3],
}

#[derive(Default)]
struct State {
    groups: BTreeSet<u32>,
    /// connect()'s default destination: (port id, group).
    dst: (u32, u32),
    connected: bool,
    rx: VecDeque<Packet>,
    rx_bytes: usize,
    /// Set when a kernel message was dropped for want of room (ENOBUFS).
    overrun: bool,
    rcvbuf: u32,
    sndbuf: u32,
    passcred: bool,
    /// FLAG_OPTS bits that are on.
    opts: u32,
}

pub struct Netlink {
    proto: u32,
    ty: u32,
    /// Port id once bound; 0 until then (the kernel's own port is 0).
    port: AtomicU32,
    st: Mutex<State>,
}

struct Registry {
    ports: BTreeMap<(u32, u32), Weak<Netlink>>,
    /// Every socket by address, for multicast (members need not be bound).
    all: BTreeMap<usize, Weak<Netlink>>,
}

static REG: Mutex<Registry> = Mutex::new(Registry { ports: BTreeMap::new(), all: BTreeMap::new() });
/// Next autobind port id when the process id is taken (Linux counts down from -4097).
static ROVER: AtomicI32 = AtomicI32::new(-4097);

impl Drop for Netlink {
    fn drop(&mut self) {
        let mut reg = REG.lock().unwrap();
        let key = (self.proto, *self.port.get_mut());
        if key.1 != 0 && reg.ports.get(&key).is_some_and(|w| w.strong_count() == 0) {
            reg.ports.remove(&key);
        }
        reg.all.remove(&(self as *const Netlink as usize));
        drop(reg);
        EVENTS.bump();
    }
}

impl Netlink {
    pub fn poll(&self) -> u16 {
        let st = self.st.lock().unwrap();
        (if st.rx.is_empty() && !st.overrun { 0 } else { POLLIN }) | POLLOUT
    }

    /// Binds to port `want`, or with 0 picks one: the process id if free,
    /// else negative ids counting down, as Linux's autobind does.
    fn bind_port(self: &Arc<Self>, pid: i32, want: u32) -> Result<u32, i64> {
        let mut reg = REG.lock().unwrap();
        let cur = self.port.load(Ordering::Relaxed);
        if cur != 0 {
            return if want == 0 || want == cur { Ok(cur) } else { Err(EINVAL) };
        }
        let taken = |reg: &Registry, p: u32| reg.ports.get(&(self.proto, p)).is_some_and(|w| w.strong_count() > 0);
        let port = if want != 0 {
            if taken(&reg, want) {
                return Err(EADDRINUSE);
            }
            want
        } else {
            let mut p = pid as u32;
            while p == 0 || taken(&reg, p) {
                p = ROVER.fetch_sub(1, Ordering::Relaxed) as u32;
            }
            p
        };
        reg.ports.insert((self.proto, port), Arc::downgrade(self));
        self.port.store(port, Ordering::Relaxed);
        Ok(port)
    }

    /// Queues a packet; `false` if the receive buffer is full.
    fn queue(&self, p: Packet) -> bool {
        let mut st = self.st.lock().unwrap();
        if st.rx_bytes > 0 && st.rx_bytes + p.data.len() > st.rcvbuf as usize {
            return false;
        }
        st.rx_bytes += p.data.len();
        st.rx.push_back(p);
        drop(st);
        EVENTS.bump();
        true
    }

    /// Kernel-originated packets are dropped when there is no room, and the
    /// next receive reports ENOBUFS (unless NETLINK_NO_ENOBUFS).
    fn queue_from_kernel(&self, p: Packet) {
        if !self.queue(p) {
            let mut st = self.st.lock().unwrap();
            st.overrun = st.opts & 1 << NETLINK_NO_ENOBUFS == 0;
        }
    }

    fn recv(&self, t: &Thread, flags: u64, nonblock: bool) -> Result<Packet, i64> {
        loop {
            let seen = EVENTS.current();
            {
                let mut st = self.st.lock().unwrap();
                if std::mem::take(&mut st.overrun) {
                    return Err(ENOBUFS);
                }
                if flags & MSG_PEEK != 0 {
                    if let Some(p) = st.rx.front() {
                        return Ok(p.clone());
                    }
                } else if let Some(p) = st.rx.pop_front() {
                    st.rx_bytes -= p.data.len();
                    drop(st);
                    EVENTS.bump();
                    return Ok(p);
                }
            }
            if nonblock {
                return Err(EAGAIN);
            }
            if t.interrupted() {
                return Err(ERESTARTSYS);
            }
            EVENTS.wait(seen, POLL);
        }
    }

    /// Sends to `dest` (port id, group) or the connected destination: the
    /// kernel at port 0, another socket's port, and the group's members.
    fn send(self: &Arc<Self>, t: &Thread, data: Vec<u8>, dest: Option<(u32, u32)>, nonblock: bool) -> Result<usize, i64> {
        let (dst, sndbuf) = {
            let st = self.st.lock().unwrap();
            (dest.unwrap_or(st.dst), st.sndbuf)
        };
        let port = self.bind_port(t.proc.pid, 0)?;
        if data.len() + 32 > sndbuf as usize {
            return Err(EMSGSIZE);
        }
        let len = data.len();
        let p = Packet { data, from: port, group: dst.1, cred: [t.proc.pid as u32, 0, 0] };
        if dst.1 != 0 {
            multicast(self.proto, &p, dst.0);
        }
        if dst.0 == 0 {
            self.kernel_input(&p.data, port)?;
            return Ok(len);
        }
        let target = REG.lock().unwrap().ports.get(&(self.proto, dst.0)).and_then(Weak::upgrade).ok_or(ECONNREFUSED)?;
        {
            let ts = target.st.lock().unwrap();
            if ts.connected && ts.dst.0 != port {
                return Err(ECONNREFUSED);
            }
        }
        let p = Packet { group: 0, ..p };
        loop {
            let seen = EVENTS.current();
            if target.queue(p.clone()) {
                return Ok(len);
            }
            if nonblock {
                return Err(EAGAIN);
            }
            if t.interrupted() {
                return Err(ERESTARTSYS);
            }
            EVENTS.wait(seen, POLL);
        }
    }

    /// The kernel's end: each request in the buffer is answered as Linux's
    /// netlink_rcv_skb would (requests only; an ack when asked or on error).
    fn kernel_input(&self, data: &[u8], port: u32) -> Result<(), i64> {
        if self.proto == NETLINK_SELINUX {
            return Err(ECONNREFUSED); // selinuxfs's netlink only multicasts
        }
        let cap = self.st.lock().unwrap().opts & 1 << NETLINK_CAP_ACK != 0;
        let mut off = 0;
        while data.len() - off >= 16 {
            let m = &data[off..];
            let len = u32::from_le_bytes(m[0..4].try_into().unwrap()) as usize;
            if len < 16 || len > m.len() {
                break;
            }
            let (ty, flags, seq) = (u16::from_le_bytes([m[4], m[5]]), u16::from_le_bytes([m[6], m[7]]), u32::from_le_bytes(m[8..12].try_into().unwrap()));
            let reply = if flags & NLM_F_REQUEST == 0 || ty < NLMSG_MIN_TYPE { Reply::Ok(Vec::new()) } else { self.request(ty, flags, seq, port, &m[16..len]) };
            let (msgs, err, ack) = match reply {
                Reply::Ok(msgs) => (msgs, 0, flags & NLM_F_ACK != 0),
                Reply::Dump(mut msgs) => {
                    msgs.push(nlmsg(NLMSG_DONE, NLM_F_MULTI, seq, port, &0i32.to_le_bytes()));
                    (msgs, 0, false)
                }
                Reply::Err(e) => (Vec::new(), e, true),
            };
            for data in msgs {
                self.queue_from_kernel(Packet { data, from: 0, group: 0, cred: [0; 3] });
            }
            if ack {
                // nlmsgerr: the error, the request's header, and (for errors) its payload.
                let mut body = (-err as i32).to_le_bytes().to_vec();
                body.extend_from_slice(&m[..if err != 0 && !cap { len } else { 16 }]);
                let data = nlmsg(NLMSG_ERROR, if err != 0 && !cap { 0 } else { NLM_F_CAPPED }, seq, port, &body);
                self.queue_from_kernel(Packet { data, from: 0, group: 0, cred: [0; 3] });
            }
            off += len.next_multiple_of(4).min(m.len());
        }
        Ok(())
    }

    fn request(&self, ty: u16, flags: u16, seq: u32, port: u32, body: &[u8]) -> Reply {
        let dump = flags & NLM_F_DUMP != 0;
        match self.proto {
            NETLINK_ROUTE => {
                if ty > RTM_MAX {
                    return Reply::Err(EOPNOTSUPP);
                }
                if body.is_empty() {
                    return Reply::Ok(Vec::new());
                }
                // rtnetlink kinds: NEW, DEL, GET, SET. Only `lo` and its
                // addresses exist, no routes; changes are accepted as if applied.
                match ((ty - 16) & 3, dump) {
                    (2, true) => Reply::Dump(match ty {
                        RTM_GETLINK => super::net::link_payloads().iter().map(|p| nlmsg(RTM_NEWLINK, NLM_F_MULTI, seq, port, p)).collect(),
                        RTM_GETADDR => super::net::addr_payloads(body[0]).iter().map(|p| nlmsg(RTM_NEWADDR, NLM_F_MULTI, seq, port, p)).collect(),
                        _ => Vec::new(),
                    }),
                    (2, false) => match ty {
                        RTM_GETLINK => match super::net::link_requested(body) {
                            Some(p) => Reply::Ok(vec![nlmsg(RTM_NEWLINK, 0, seq, port, &p)]),
                            None => Reply::Err(ENODEV),
                        },
                        RTM_GETROUTE => Reply::Err(ENETUNREACH),
                        _ => Reply::Err(EOPNOTSUPP),
                    },
                    _ => Reply::Ok(Vec::new()),
                }
            }
            NETLINK_AUDIT => audit(ty, seq, body),
            NETLINK_KOBJECT_UEVENT => {
                uevent(body); // re-broadcast, as Linux does for CAP_SYS_ADMIN senders
                Reply::Ok(Vec::new())
            }
            // No generic netlink families or diag handlers are registered.
            NETLINK_GENERIC | NETLINK_SOCK_DIAG if !dump => Reply::Err(ENOENT),
            _ if dump => Reply::Dump(Vec::new()),
            _ => Reply::Ok(Vec::new()),
        }
    }
}

/// What the kernel does with one request.
enum Reply {
    /// Handled; these messages precede the ack, if one was asked for.
    Ok(Vec<Vec<u8>>),
    /// A dump: these messages, then NLMSG_DONE, and no ack.
    Dump(Vec<Vec<u8>>),
    Err(i64),
}

/// An `nlmsghdr` and payload, padded to 4 bytes.
fn nlmsg(ty: u16, flags: u16, seq: u32, port: u32, payload: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(16 + payload.len() + 3);
    m.extend_from_slice(&(16 + payload.len() as u32).to_le_bytes());
    m.extend_from_slice(&ty.to_le_bytes());
    m.extend_from_slice(&flags.to_le_bytes());
    m.extend_from_slice(&seq.to_le_bytes());
    m.extend_from_slice(&port.to_le_bytes());
    m.extend_from_slice(payload);
    m.resize(m.len().next_multiple_of(4), 0);
    m
}

/// `struct audit_status`: mask, enabled, failure, pid, rate_limit,
/// backlog_limit, lost, backlog, feature_bitmap, backlog_wait_time(_actual).
static AUDIT: Mutex<[u32; 11]> = Mutex::new([0, 1, 1, 0, 0, 64, 0, 0, 0x7f, 15000, 0]);

fn audit(ty: u16, seq: u32, body: &[u8]) -> Reply {
    let mut s = AUDIT.lock().unwrap();
    match ty {
        AUDIT_GET => Reply::Ok(vec![nlmsg(AUDIT_GET, 0, seq, 0, &s.iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<u8>>())]),
        AUDIT_SET => {
            let mut req = [0u8; 44];
            req[..body.len().min(44)].copy_from_slice(&body[..body.len().min(44)]);
            let field = |i: usize| u32::from_le_bytes(req[i * 4..i * 4 + 4].try_into().unwrap());
            let mask = field(0);
            // AUDIT_STATUS_* bit -> field: enabled, failure, pid, rate_limit, backlog_limit, backlog_wait_time.
            for (bit, i) in [(1, 1), (2, 2), (4, 3), (8, 4), (0x10, 5), (0x20, 9)] {
                if mask & bit != 0 {
                    s[i] = field(i);
                }
            }
            if mask & 0x40 != 0 {
                s[6] = 0; // AUDIT_STATUS_LOST resets the count
            }
            Reply::Ok(Vec::new())
        }
        AUDIT_LIST_RULES => Reply::Ok(vec![nlmsg(NLMSG_DONE, NLM_F_MULTI, seq, 0, &[])]), // no rules
        AUDIT_GET_FEATURE => Reply::Ok(vec![nlmsg(AUDIT_GET_FEATURE, 0, seq, 0, &[1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])]),
        AUDIT_TTY_GET => Reply::Ok(vec![nlmsg(AUDIT_TTY_GET, 0, seq, 0, &[0; 8])]),
        1002..=1019 | 1100..=1199 | 2100..=2999 => Reply::Ok(Vec::new()),
        _ => Reply::Err(EINVAL),
    }
}

/// Delivers a copy of `p` to every socket of `proto` in its group, except
/// the one at port `skip` (it gets the unicast).
fn multicast(proto: u32, p: &Packet, skip: u32) {
    let socks: Vec<Arc<Netlink>> = REG.lock().unwrap().all.values().filter_map(Weak::upgrade).collect();
    for s in socks {
        if s.proto == proto && (skip == 0 || s.port.load(Ordering::Relaxed) != skip) && s.st.lock().unwrap().groups.contains(&p.group) {
            if p.from == 0 {
                s.queue_from_kernel(p.clone());
            } else {
                s.queue(p.clone());
            }
        }
    }
}

/// Broadcasts a uevent ("ACTION@DEVPATH\0KEY=VALUE\0…") from the kernel to
/// NETLINK_KOBJECT_UEVENT group 1, with a SEQNUM appended as Linux does.
pub fn uevent(event: &[u8]) {
    static SEQNUM: AtomicU64 = AtomicU64::new(0);
    let mut data = event.to_vec();
    data.extend_from_slice(format!("SEQNUM={}\0", SEQNUM.fetch_add(1, Ordering::Relaxed) + 1).as_bytes());
    multicast(NETLINK_KOBJECT_UEVENT, &Packet { data, from: 0, group: 1, cred: [0; 3] }, 0);
}

/// The group a `nl_groups` mask sends to: its lowest bit, numbered from 1.
fn ffs(groups: u32) -> u32 {
    if groups == 0 { 0 } else { groups.trailing_zeros() + 1 }
}

fn group_mask(group: u32) -> u32 {
    if (1..=32).contains(&group) { 1 << (group - 1) } else { 0 }
}

/// read(2) on a netlink socket: one message, truncated to `max`.
pub fn read(nl: &Netlink, t: &Thread, max: usize, nonblock: bool) -> Result<Vec<u8>, i64> {
    let mut p = nl.recv(t, 0, nonblock)?;
    p.data.truncate(max);
    Ok(p.data)
}

pub fn write(nl: &Arc<Netlink>, t: &Thread, data: Vec<u8>, nonblock: bool) -> Result<usize, i64> {
    nl.send(t, data, None, nonblock)
}

/// Appends a `cmsghdr` (64-bit layout), padded to 8.
fn push_cmsg(out: &mut Vec<u8>, level: u64, ty: i32, data: &[u8]) {
    out.extend_from_slice(&((16 + data.len()) as u64).to_le_bytes());
    out.extend_from_slice(&(level as i32).to_le_bytes());
    out.extend_from_slice(&ty.to_le_bytes());
    out.extend_from_slice(data);
    out.resize(out.len().next_multiple_of(8), 0);
}

impl Kernel {
    pub(super) fn netlink_socket(&self, t: &Thread, a: [u64; 6]) -> Result<i64, i64> {
        let ty = (a[1] & 0xf) as u32;
        if ty != SOCK_RAW && ty != SOCK_DGRAM {
            return Err(ESOCKTNOSUPPORT);
        }
        let proto = int(a[2]) as u32;
        ngroups(proto).ok_or(EPROTONOSUPPORT)?;
        let st = State { rcvbuf: BUF_DEFAULT, sndbuf: BUF_DEFAULT, ..State::default() };
        let nl = Arc::new(Netlink { proto, ty, port: AtomicU32::new(0), st: Mutex::new(st) });
        REG.lock().unwrap().all.insert(Arc::as_ptr(&nl) as usize, Arc::downgrade(&nl));
        let f = File::new(Kind::Netlink(nl), (a[1] & SOCK_NONBLOCK) as u32);
        t.proc.files.lock().unwrap().alloc(f, a[1] & SOCK_CLOEXEC != 0, 0)
    }

    /// The socket syscalls on a netlink descriptor.
    pub(super) fn netlink_syscall(&self, no: Sysno, t: &Arc<Thread>, nl: &Arc<Netlink>, f: &File, a: [u64; 6]) -> Result<i64, i64> {
        use Sysno::*;
        match no {
            bind => {
                let (port, groups) = read_nladdr(t, a[1], a[2])?;
                nl.bind_port(t.proc.pid, port)?;
                let n = ngroups(nl.proto).unwrap_or(32);
                let mut st = nl.st.lock().unwrap();
                st.groups.retain(|&g| g > 32);
                st.groups.extend((1..=32.min(n)).filter(|g| groups & 1 << (g - 1) != 0));
                Ok(0)
            }
            connect => {
                if a[2] < 2 {
                    return Err(EINVAL);
                }
                if t.proc.mm().read_vec(a[1], 2)? == [0, 0] {
                    let mut st = nl.st.lock().unwrap(); // AF_UNSPEC: back to the kernel
                    st.connected = false;
                    st.dst = (0, 0);
                    return Ok(0);
                }
                let (port, groups) = read_nladdr(t, a[1], a[2])?;
                nl.bind_port(t.proc.pid, 0)?;
                let mut st = nl.st.lock().unwrap();
                st.connected = true;
                st.dst = (port, ffs(groups));
                Ok(0)
            }
            getsockname => {
                let groups = nl.st.lock().unwrap().groups.iter().filter(|&&g| g <= 32).fold(0, |m, &g| m | group_mask(g));
                write_nladdr(t, a[1], a[2], nl.port.load(Ordering::Relaxed), groups)?;
                Ok(0)
            }
            getpeername => {
                let dst = nl.st.lock().unwrap().dst;
                write_nladdr(t, a[1], a[2], dst.0, group_mask(dst.1))?;
                Ok(0)
            }
            sendto => {
                let data = t.proc.mm().read_vec(a[1], a[2].min(IO_MAX) as usize)?;
                let dest = if a[4] != 0 && a[5] != 0 { Some(read_nladdr(t, a[4], a[5])?) } else { None };
                let nonblock = f.nonblock() || a[3] & MSG_DONTWAIT != 0;
                nl.send(t, data, dest.map(|(p, g)| (p, ffs(g))), nonblock).map(|n| n as i64)
            }
            sendmsg => {
                let (name, namelen, iov, iovlen) = {
                    let mut mm = t.proc.mm();
                    (mm.read_u64(a[1])?, mm.read_u32(a[1] + 8)? as u64, mm.read_u64(a[1] + 16)?, mm.read_u64(a[1] + 24)?)
                };
                let mut data = Vec::new();
                {
                    let mut mm = t.proc.mm();
                    for i in 0..iovlen.min(1024) {
                        let (base, len) = (mm.read_u64(iov + i * 16)?, mm.read_u64(iov + i * 16 + 8)?);
                        data.extend(mm.read_vec(base, len.min(IO_MAX) as usize)?);
                    }
                }
                let dest = if name != 0 && namelen != 0 { Some(read_nladdr(t, name, namelen)?) } else { None };
                let nonblock = f.nonblock() || a[2] & MSG_DONTWAIT != 0;
                nl.send(t, data, dest.map(|(p, g)| (p, ffs(g))), nonblock).map(|n| n as i64)
            }
            recvfrom => {
                let nonblock = f.nonblock() || a[3] & MSG_DONTWAIT != 0;
                let p = nl.recv(t, a[3], nonblock)?;
                let n = p.data.len().min(a[2] as usize);
                t.proc.mm().write(a[1], &p.data[..n])?;
                if a[4] != 0 {
                    write_nladdr(t, a[4], a[5], p.from, group_mask(p.group))?;
                }
                Ok(if a[3] & MSG_TRUNC != 0 { p.data.len() } else { n } as i64)
            }
            recvmsg => self.netlink_recvmsg(t, nl, f, a[1], a[2]),
            setsockopt => {
                if a[4] < 4 && !(a[1] == SOL_SOCKET && a[2] == SO_BINDTODEVICE) {
                    return Err(EINVAL);
                }
                let v = if a[4] >= 4 { t.proc.mm().read_u32(a[3])? } else { 0 };
                let mut st = nl.st.lock().unwrap();
                match (a[1], a[2]) {
                    // Linux stores twice what was asked (bookkeeping overhead), capped unless forced.
                    (SOL_SOCKET, SO_RCVBUF) => st.rcvbuf = (v.min(BUF_DEFAULT) * 2).max(BUF_MIN),
                    (SOL_SOCKET, SO_SNDBUF) => st.sndbuf = (v.min(BUF_DEFAULT) * 2).max(BUF_MIN),
                    (SOL_SOCKET, SO_RCVBUFFORCE) => st.rcvbuf = ((v as i32).clamp(0, i32::MAX / 2) as u32 * 2).max(BUF_MIN),
                    (SOL_SOCKET, SO_SNDBUFFORCE) => st.sndbuf = ((v as i32).clamp(0, i32::MAX / 2) as u32 * 2).max(BUF_MIN),
                    (SOL_SOCKET, SO_PASSCRED) => st.passcred = v != 0,
                    (SOL_SOCKET, _) => {} // filters, timestamps, priorities: accepted
                    (SOL_NETLINK, NETLINK_ADD_MEMBERSHIP | NETLINK_DROP_MEMBERSHIP) => {
                        if v == 0 || v > ngroups(nl.proto).unwrap_or(32) {
                            return Err(EINVAL);
                        }
                        if a[2] == NETLINK_ADD_MEMBERSHIP {
                            st.groups.insert(v);
                        } else {
                            st.groups.remove(&v);
                        }
                    }
                    (SOL_NETLINK, o) if o < 32 && FLAG_OPTS & 1 << o != 0 => {
                        if v != 0 { st.opts |= 1 << o } else { st.opts &= !(1 << o) }
                    }
                    _ => return Err(ENOPROTOOPT),
                }
                Ok(0)
            }
            getsockopt => {
                let st = nl.st.lock().unwrap();
                let word = |v: u32| v.to_le_bytes().to_vec();
                let n = ngroups(nl.proto).unwrap_or(32);
                let val = match (a[1], a[2]) {
                    (SOL_SOCKET, SO_TYPE) => word(nl.ty),
                    (SOL_SOCKET, SO_PROTOCOL) => word(nl.proto),
                    (SOL_SOCKET, SO_DOMAIN) => word(AF_NETLINK as u32),
                    (SOL_SOCKET, SO_RCVBUF) => word(st.rcvbuf),
                    (SOL_SOCKET, SO_SNDBUF) => word(st.sndbuf),
                    (SOL_SOCKET, SO_PASSCRED) => word(st.passcred as u32),
                    (SOL_SOCKET, SO_ERROR | SO_ACCEPTCONN) => word(0),
                    (SOL_SOCKET, SO_PEERCRED) => [0u32, 65534, 65534].iter().flat_map(|v| v.to_le_bytes()).collect(),
                    (SOL_NETLINK, NETLINK_LIST_MEMBERSHIPS) => {
                        let mut words = vec![0u32; n.div_ceil(32) as usize];
                        for &g in &st.groups {
                            words[(g as usize - 1) / 32] |= 1 << ((g - 1) % 32);
                        }
                        words.iter().flat_map(|w| w.to_le_bytes()).collect()
                    }
                    (SOL_NETLINK, o) if o < 32 && FLAG_OPTS & 1 << o != 0 => word((st.opts & 1 << o != 0) as u32),
                    _ => return Err(ENOPROTOOPT),
                };
                drop(st);
                let mut mm = t.proc.mm();
                let cap = mm.read_u32(a[4])? as usize;
                if a[1] == SOL_NETLINK && a[2] != NETLINK_LIST_MEMBERSHIPS && cap < 4 {
                    return Err(EINVAL);
                }
                let k = cap.min(val.len());
                mm.write(a[3], &val[..k])?;
                mm.write_u32(a[4], if a[2] == NETLINK_LIST_MEMBERSHIPS && a[1] == SOL_NETLINK { val.len() } else { k } as u32)?;
                Ok(0)
            }
            listen | accept | accept4 | shutdown => Err(EOPNOTSUPP),
            _ => Err(EINVAL),
        }
    }

    fn netlink_recvmsg(&self, t: &Thread, nl: &Netlink, f: &File, msg: u64, flags: u64) -> Result<i64, i64> {
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
        let total = iovs.iter().map(|v| v.1).sum::<u64>().min(IO_MAX) as usize;
        let p = nl.recv(t, flags, f.nonblock() || flags & MSG_DONTWAIT != 0)?;
        let n = p.data.len().min(total);
        let mut msg_flags = if n < p.data.len() { MSG_TRUNC as u32 } else { 0 };
        let mut ctl = Vec::new();
        let (pktinfo, passcred) = {
            let st = nl.st.lock().unwrap();
            (st.opts & 1 << NETLINK_PKTINFO != 0, st.passcred)
        };
        if pktinfo && p.group != 0 {
            push_cmsg(&mut ctl, SOL_NETLINK, NETLINK_PKTINFO as i32, &p.group.to_le_bytes());
        }
        if passcred {
            push_cmsg(&mut ctl, SOL_SOCKET, SCM_CREDENTIALS, &p.cred.iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<u8>>());
        }
        if ctl.len() > controllen as usize {
            ctl.truncate(controllen as usize);
            msg_flags |= MSG_CTRUNC;
        }
        let mut mm = t.proc.mm();
        let mut off = 0;
        for (base, len) in iovs {
            if off >= n {
                break;
            }
            let k = (len as usize).min(n - off);
            mm.write(base, &p.data[off..off + k])?;
            off += k;
        }
        if !ctl.is_empty() {
            mm.write(control, &ctl)?;
        }
        mm.write_u64(msg + 40, ctl.len() as u64)?;
        mm.write_u32(msg + 48, msg_flags)?;
        drop(mm);
        if name != 0 {
            write_nladdr(t, name, msg + 8, p.from, group_mask(p.group))?;
        }
        Ok(if flags & MSG_TRUNC != 0 { p.data.len() } else { n } as i64)
    }
}

/// A `sockaddr_nl` as (port id, groups).
fn read_nladdr(t: &Thread, addr: u64, len: u64) -> Result<(u32, u32), i64> {
    if len < 12 {
        return Err(EINVAL);
    }
    let b = t.proc.mm().read_vec(addr, 12)?;
    if u16::from_le_bytes([b[0], b[1]]) as u64 != AF_NETLINK {
        return Err(EINVAL);
    }
    Ok((u32::from_le_bytes(b[4..8].try_into().unwrap()), u32::from_le_bytes(b[8..12].try_into().unwrap())))
}

fn write_nladdr(t: &Thread, addr: u64, len_p: u64, port: u32, groups: u32) -> Result<(), i64> {
    let mut sa = [0u8; 12];
    sa[0..2].copy_from_slice(&(AF_NETLINK as u16).to_le_bytes());
    sa[4..8].copy_from_slice(&port.to_le_bytes());
    sa[8..12].copy_from_slice(&groups.to_le_bytes());
    let mut mm = t.proc.mm();
    let cap = mm.read_u32(len_p)? as usize;
    mm.write(addr, &sa[..cap.min(12)])?;
    mm.write_u32(len_p, 12)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn messages_carry_unpadded_lengths_and_are_padded() {
        let m = nlmsg(NLMSG_DONE, NLM_F_MULTI, 5, 77, &[1, 2, 3]);
        assert_eq!(m.len(), 20);
        assert_eq!(&m[..16], &[19, 0, 0, 0, 3, 0, 2, 0, 5, 0, 0, 0, 77, 0, 0, 0]);
        assert_eq!(&m[16..], &[1, 2, 3, 0]);
    }

    #[test]
    fn group_numbers_and_masks() {
        assert_eq!((ffs(0), ffs(1), ffs(0x18)), (0, 1, 4));
        assert_eq!((group_mask(0), group_mask(1), group_mask(32), group_mask(33)), (0, 1, 1 << 31, 0));
    }
}

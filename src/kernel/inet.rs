//! AF_INET and AF_INET6 sockets. A guest's socket is not a host's: binding, listening
//! and connecting a datagram socket stay in here, ports and addresses are the guest's,
//! and a host socket appears only for a connection that actually goes out. So the host
//! acts as a NAT, with no packets anywhere: Android's addresses are for show.
//!
//! Where things go is decided by `route`. Guest threads never block in a host call,
//! here or in `hostio`, which moves a TCP connection's bytes.
//!
//! Raw sockets and AF_KEY are something else, there for netd's iptables: legacy
//! ip_tables / ip6_tables get and replace whole tables through socket options on a raw
//! socket. droidrt keeps those tables (nothing filters).
//!
//! Known not to work yet: traffic between guest sockets (connecting gets ECONNREFUSED,
//! and datagrams vanish), UDP beyond this device (likewise), and ICMP replies. SO_MARK
//! is kept and has no effect, so per-network routing, VPNs and per-UID firewalls don't
//! apply to anything, and 10.0.2.2 is open to every app, as on the emulator.

use super::files::{File, Kind};
use super::hostio::{self, Io, Link};
use super::unix::{SockOpts, deadline, sockopt_bytes, wait_or_give_up};
use super::wait::EVENTS;
use super::{Kernel, Thread, dns, net};
use crate::arch::Sysno;
use crate::errno::*;
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, LazyLock, Mutex};
use std::time::Duration;

pub const AF_INET: u64 = 2;
pub const AF_INET6: u64 = 10;
pub const AF_KEY: u64 = 15;
const SOCK_STREAM: u32 = 1;
const SOCK_DGRAM: u32 = 2;
const SOCK_RAW: u32 = 3;
const SOCK_NONBLOCK: u64 = 0o4000;
const SOCK_CLOEXEC: u64 = 0o2000000;

const MSG_OOB: u64 = 0x1;
const MSG_PEEK: u64 = 0x2;
const MSG_TRUNC: u64 = 0x20;
const MSG_DONTWAIT: u64 = 0x40;
const MSG_WAITALL: u64 = 0x100;
const MSG_ERRQUEUE: u64 = 0x2000;
const MSG_NOSIGNAL: u64 = 0x4000;
const MSG_FASTOPEN: u64 = 0x2000_0000;

const POLLRDNORM: u16 = 0x40;
const POLLWRNORM: u16 = 0x100;

const IPPROTO_ICMP: u32 = 1;
const IPPROTO_TCP: u32 = 6;
const IPPROTO_UDP: u32 = 17;
const IPPROTO_ICMPV6: u32 = 58;

const SOL_IP: u64 = 0;
const SOL_SOCKET: u64 = 1;
const SOL_TCP: u64 = 6;
const SOL_UDP: u64 = 17;
const SOL_IPV6: u64 = 41;

const SO_TYPE: u64 = 3;
const SO_ERROR: u64 = 4;
const SO_SNDBUF: u64 = 7;
const SO_RCVBUF: u64 = 8;
const SO_REUSEADDR: u64 = 2;
const SO_BROADCAST: u64 = 6;
const SO_REUSEPORT: u64 = 15;
const SO_PEERCRED: u64 = 17;
const SO_BINDTODEVICE: u64 = 25;
const SO_ACCEPTCONN: u64 = 30;
const SO_SNDBUFFORCE: u64 = 32;
const SO_RCVBUFFORCE: u64 = 33;
const SO_PROTOCOL: u64 = 38;
const SO_DOMAIN: u64 = 39;
const SO_COOKIE: u64 = 57;
const SO_ZEROCOPY: u64 = 60;

const IP_MTU: u64 = 14;
const IPV6_MTU: u64 = 24;
const IPV6_V6ONLY: u64 = 26;
const TCP_NODELAY: u64 = 1;
const TCP_INFO: u64 = 11;
const TCP_CONGESTION: u64 = 13;
const TCP_REPAIR: u64 = 19;
const TCP_FASTOPEN_CONNECT: u64 = 30;
const TCP_ULP: u64 = 31;
const UDP_SEGMENT: u64 = 103;
const UDP_GRO: u64 = 104;

// ip_tables / ip6_tables socket options (same numbers at SOL_IP and SOL_IPV6).
const SO_SET_REPLACE: u64 = 64;
const SO_SET_ADD_COUNTERS: u64 = 65;
const SO_GET_INFO: u64 = 64;
const SO_GET_ENTRIES: u64 = 65;

const CAP_NET_BIND_SERVICE: u32 = 10;

const IO_MAX: u64 = 1 << 31;
/// As `ip_local_port_range`.
const FIRST_EPHEMERAL: u32 = 32768;
const LAST_EPHEMERAL: u32 = 60999;
/// Linux gives up on an unanswered connect after about this long.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(127);
/// Datagrams waiting on a socket, in bytes. Past this they are dropped. As rmem_default.
const UDP_QUEUE: usize = 212992;
/// `rmem_max` and `wmem_max`, as init.rc sets them.
const BUF_MAX: u32 = 262144;
const MTU: i32 = 1500;

/// DROIDRT_NET_TRACE=1: one line per route decision and per host connection.
fn tracing() -> bool {
    static ON: LazyLock<bool> = LazyLock::new(|| std::env::var("DROIDRT_NET_TRACE").as_deref() == Ok("1"));
    *ON
}

#[derive(Clone, Copy, PartialEq, Default, Debug)]
enum Phase {
    /// Nothing asked of it, or a connection ended: Linux's SS_UNCONNECTED.
    #[default]
    Idle,
    Listening,
    /// connect() has been called and hasn't yet returned success or failure, which
    /// doesn't mean the connection isn't up: SS_CONNECTING.
    Connecting,
    /// SS_CONNECTED, and for a datagram socket unused: it has `peer` for that.
    Connected,
}

struct Datagram {
    from: SocketAddr,
    data: Vec<u8>,
}

#[derive(Default)]
struct State {
    opts: SockOpts,
    /// Options with no effect here, kept to read back: (level, name) -> value.
    stored: BTreeMap<(u64, u64), Vec<u8>>,
    /// The address bound, its port the socket's in the port table. A wildcard stays one
    /// while `source` is what a connection shows.
    local: Option<SocketAddr>,
    source: Option<IpAddr>,
    /// As the guest named it. IPv4 for a v4-mapped address.
    peer: Option<SocketAddr>,
    phase: Phase,
    /// A stream's connection, from its first connect.
    io: Option<Arc<Io>>,
    /// A datagram socket's sk_err. A stream's is in `io`.
    err: i64,
    shut_rd: bool,
    shut_wr: bool,
    queue: VecDeque<Datagram>,
    queued: usize,
}

pub struct Inet {
    pub family: u64,
    pub ty: u32,
    pub proto: u32,
    /// What pollers watch in EVENTS, and SO_COOKIE: unique for the socket's life.
    key: usize,
    st: Mutex<State>,
}

impl Drop for Inet {
    fn drop(&mut self) {
        let st = self.st.get_mut().unwrap();
        if let Some(io) = &st.io {
            if st.opts.closes_at_once() {
                io.abort();
            } else {
                io.close();
            }
        }
        if let Some(local) = st.local {
            release_port(self.proto, local.port(), self.key);
        }
    }
}

/// Where a destination is.
#[derive(Debug, PartialEq)]
enum Route {
    /// On this device. Nothing leaves.
    Local,
    /// A host address.
    Host(SocketAddr),
    /// The name server, in `dns`.
    Dns,
    /// Nothing listens there, and something says so at once.
    Refused,
    /// A datagram that goes out to nobody in particular.
    Lost,
}

fn route(dest: SocketAddr, stream: bool, broadcast_ok: bool) -> Result<Route, i64> {
    let ip = match dest {
        SocketAddr::V6(a) => {
            let ip = a.ip();
            return if ip.is_loopback() || ip.is_unspecified() {
                Ok(Route::Local)
            } else if ip.is_multicast() && !stream {
                Ok(Route::Lost)
            } else {
                Err(ENETUNREACH) // there are no IPv6 addresses to send from
            };
        }
        SocketAddr::V4(a) => *a.ip(),
    };
    if ip.is_loopback() || ip.is_unspecified() || (ip.octets() == net::ETH_ADDRESS && net::ipv4_up()) {
        return Ok(Route::Local);
    }
    if ip.is_multicast() {
        return if stream { Err(ENETUNREACH) } else { Ok(Route::Lost) };
    }
    if ip.is_broadcast() || ip.octets() == [10, 0, 2, 255] {
        return match (stream, broadcast_ok) {
            (true, _) => Err(ENETUNREACH),
            (false, true) => Ok(Route::Lost),
            (false, false) => Err(EACCES),
        };
    }
    if !net::ipv4_up() {
        return Err(ENETUNREACH);
    }
    match ip.octets() {
        // The host's own loopback, as on the emulator, less what would let an app run
        // commands: the adb server has no authentication of its own.
        [10, 0, 2, 2] if super::adb::reserved_host_port(dest.port()) => Ok(Route::Refused),
        [10, 0, 2, 2] => Ok(Route::Host(SocketAddr::from(([127, 0, 0, 1], dest.port())))),
        ip @ [10, 0, 2, 3] if ip == dns::SERVER && !stream && dest.port() == dns::PORT => Ok(Route::Dns),
        [10, 0, 2, 3] => Ok(Route::Refused),
        // On the subnet, and nobody home: answering at once saves a long wait.
        [10, 0, 2, _] => Err(EHOSTUNREACH),
        _ => Ok(Route::Host(dest)),
    }
}

/// The address a connection to `dest` by way of `route` comes from.
fn source_for(route: &Route, dest: SocketAddr) -> IpAddr {
    match (route, dest) {
        (Route::Local, SocketAddr::V6(_)) => IpAddr::V6(Ipv6Addr::LOCALHOST),
        (Route::Local, SocketAddr::V4(a)) if a.ip().octets() == net::ETH_ADDRESS => IpAddr::V4(*a.ip()),
        (Route::Local, SocketAddr::V4(_)) => IpAddr::V4(Ipv4Addr::LOCALHOST),
        _ => IpAddr::from(net::ETH_ADDRESS),
    }
}

/// Who has which port, in the guest. No host port is involved.
#[derive(Clone)]
struct Binding {
    owner: usize,
    ip: IpAddr,
    v6only: bool,
    reuse_addr: bool,
    reuse_port: bool,
    uid: u32,
    listening: bool,
}

/// By protocol, then port.
static PORTS: LazyLock<Mutex<HashMap<(u32, u16), Vec<Binding>>>> = LazyLock::new(Mutex::default);

fn overlap(a: &Binding, b: &Binding) -> bool {
    match (a.ip, b.ip) {
        (IpAddr::V4(x), IpAddr::V4(y)) => x == y || x.is_unspecified() || y.is_unspecified(),
        (IpAddr::V6(x), IpAddr::V6(y)) => x == y || x.is_unspecified() || y.is_unspecified(),
        (IpAddr::V6(x), IpAddr::V4(_)) => x.is_unspecified() && !a.v6only,
        (IpAddr::V4(_), IpAddr::V6(y)) => y.is_unspecified() && !b.v6only,
    }
}

/// Whether `held` keeps `new` from an address too.
fn conflict(held: &Binding, new: &Binding, stream: bool) -> bool {
    if !overlap(held, new) {
        return false;
    }
    if held.reuse_port && new.reuse_port && held.uid == new.uid {
        return false;
    }
    // A listener has its port to itself, whatever the others say.
    !(held.reuse_addr && new.reuse_addr && !(stream && held.listening))
}

/// Takes `port`, or any free one if 0. The port it got.
fn take_port(proto: u32, port: u16, new: Binding) -> Result<u16, i64> {
    static NEXT: AtomicU32 = AtomicU32::new(0);
    let stream = proto == IPPROTO_TCP;
    let mut ports = PORTS.lock().unwrap();
    if port != 0 {
        let holders = ports.entry((proto, port)).or_default();
        if holders.iter().any(|b| conflict(b, &new, stream)) {
            return Err(EADDRINUSE);
        }
        holders.push(new);
        return Ok(port);
    }
    let span = LAST_EPHEMERAL - FIRST_EPHEMERAL + 1;
    for _ in 0..span {
        let port = (FIRST_EPHEMERAL + NEXT.fetch_add(1, Ordering::Relaxed) % span) as u16;
        if let std::collections::hash_map::Entry::Vacant(free) = ports.entry((proto, port)) {
            free.insert(vec![new]);
            return Ok(port);
        }
    }
    Err(EADDRINUSE)
}

fn release_port(proto: u32, port: u16, owner: usize) {
    let mut ports = PORTS.lock().unwrap();
    if let Some(holders) = ports.get_mut(&(proto, port)) {
        holders.retain(|b| b.owner != owner);
        if holders.is_empty() {
            ports.remove(&(proto, port));
        }
    }
}

/// What a socket is sending: still in guest memory, so that no more is copied out than
/// there's room for, or the bytes of a write(2).
enum Source<'a> {
    Guest(Vec<(u64, u64)>),
    Bytes(&'a [u8]),
}

impl Source<'_> {
    fn len(&self) -> usize {
        match self {
            Source::Guest(iov) => iov.iter().map(|v| v.1).sum::<u64>() as usize,
            Source::Bytes(b) => b.len(),
        }
    }

    fn read(&self, t: &Thread, mut at: usize, n: usize) -> Result<Vec<u8>, i64> {
        match self {
            Source::Bytes(b) => Ok(b[at..at + n].to_vec()),
            Source::Guest(iov) => {
                let mut out = Vec::with_capacity(n);
                let mut mm = t.proc.mm();
                for &(base, len) in iov {
                    let len = len as usize;
                    if at >= len {
                        at -= len;
                        continue;
                    }
                    let take = (len - at).min(n - out.len());
                    out.extend(mm.read_vec(base + at as u64, take)?);
                    at = 0;
                    if out.len() == n {
                        break;
                    }
                }
                Ok(out)
            }
        }
    }
}

/// An iovec array, cut to what one call can move.
fn read_iov(t: &Thread, iov: u64, count: u64) -> Result<Vec<(u64, u64)>, i64> {
    if count > 1024 {
        return Err(EMSGSIZE);
    }
    let mut mm = t.proc.mm();
    let mut out = Vec::with_capacity(count as usize);
    let mut left = IO_MAX;
    for i in 0..count {
        let (base, len) = (mm.read_u64(iov + i * 16)?, mm.read_u64(iov + i * 16 + 8)?);
        if len as i64 >= 0 {
            out.push((base, len.min(left)));
            left -= len.min(left);
        } else {
            return Err(EINVAL);
        }
    }
    Ok(out)
}

struct Received {
    data: Vec<u8>,
    /// What there was: a datagram can be longer than the room for it.
    real: usize,
    from: Option<SocketAddr>,
}

#[derive(Clone, Copy, PartialEq)]
enum AddrUse {
    Bind,
    TcpConnect,
    UdpConnect,
    UdpSend,
}

impl Inet {
    fn v6(&self) -> bool {
        self.family == AF_INET6
    }

    fn raw(&self) -> bool {
        self.ty == SOCK_RAW || self.family == AF_KEY
    }

    pub fn is_stream(&self) -> bool {
        self.ty == SOCK_STREAM
    }

    pub fn key(&self) -> usize {
        self.key
    }

    fn v6only(st: &State) -> bool {
        st.stored.get(&(SOL_IPV6, IPV6_V6ONLY)).is_some_and(|v| v.iter().any(|&b| b != 0))
    }

    fn v4_addr(raw: &[u8]) -> Result<SocketAddr, i64> {
        if raw.len() < 16 {
            return Err(EINVAL);
        }
        let port = u16::from_be_bytes([raw[2], raw[3]]);
        Ok(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(raw[4], raw[5], raw[6], raw[7])), port))
    }

    /// A sockaddr as this socket may be given it: an AF_INET socket offered an IPv6
    /// address must say EAFNOSUPPORT, the only thing libcore retries on. Addresses that
    /// are really IPv4 come back as that.
    fn parse_addr(&self, raw: &[u8], usage: AddrUse, v6only: bool) -> Result<SocketAddr, i64> {
        if raw.len() < 2 {
            return Err(EINVAL);
        }
        let family = u16::from_le_bytes([raw[0], raw[1]]) as u64;
        match (self.family, family) {
            (AF_INET, AF_INET) => Self::v4_addr(raw),
            // Compatibility games, says Linux: AF_UNSPEC can mean AF_INET.
            (AF_INET, 0) if usage == AddrUse::UdpSend => Self::v4_addr(raw),
            (AF_INET, 0) if usage == AddrUse::Bind => {
                let addr = Self::v4_addr(raw)?;
                if addr.ip().is_unspecified() { Ok(addr) } else { Err(EAFNOSUPPORT) }
            }
            (AF_INET6, AF_INET6) => {
                if raw.len() < 24 {
                    return Err(EINVAL);
                }
                let port = u16::from_be_bytes([raw[2], raw[3]]);
                let ip: [u8; 16] = raw[8..24].try_into().unwrap();
                let ip = Ipv6Addr::from(ip);
                match ip.to_ipv4_mapped() {
                    Some(_) if v6only => Err(if usage == AddrUse::Bind { EINVAL } else { ENETUNREACH }),
                    Some(v4) => Ok(SocketAddr::new(IpAddr::V4(v4), port)),
                    None => Ok(SocketAddr::new(IpAddr::V6(ip), port)),
                }
            }
            (AF_INET6, AF_INET) if matches!(usage, AddrUse::UdpConnect | AddrUse::UdpSend) => {
                if v6only {
                    return Err(if usage == AddrUse::UdpSend { ENETUNREACH } else { EAFNOSUPPORT });
                }
                Self::v4_addr(raw)
            }
            _ => Err(EAFNOSUPPORT),
        }
    }

    /// The sockaddr for an address, in this socket's family whatever the address's.
    fn sockaddr(&self, addr: Option<SocketAddr>) -> Vec<u8> {
        let port = addr.map_or(0, |a| a.port()).to_be_bytes();
        let mut out = if self.v6() { vec![0u8; 28] } else { vec![0u8; 16] };
        out[..2].copy_from_slice(&(self.family as u16).to_le_bytes());
        out[2..4].copy_from_slice(&port);
        match (self.v6(), addr.map(|a| a.ip())) {
            (false, Some(IpAddr::V4(ip))) => out[4..8].copy_from_slice(&ip.octets()),
            (true, Some(IpAddr::V4(ip))) => out[8..24].copy_from_slice(&ip.to_ipv6_mapped().octets()),
            (true, Some(IpAddr::V6(ip))) => out[8..24].copy_from_slice(&ip.octets()),
            _ => {}
        }
        out
    }

    fn binding(&self, st: &State, ip: IpAddr, uid: u32) -> Binding {
        let flag = |opt| st.opts.get(opt).is_some_and(|v| v.iter().any(|&b| b != 0));
        Binding { owner: self.key, ip, v6only: Self::v6only(st), reuse_addr: flag(SO_REUSEADDR), reuse_port: flag(SO_REUSEPORT), uid, listening: false }
    }

    fn wildcard(&self) -> IpAddr {
        if self.v6() { IpAddr::V6(Ipv6Addr::UNSPECIFIED) } else { IpAddr::V4(Ipv4Addr::UNSPECIFIED) }
    }

    /// Gives the socket a port if it has none yet.
    fn autobind(&self, st: &mut State, uid: u32) -> Result<(), i64> {
        if st.local.is_none() {
            let ip = self.wildcard();
            let port = take_port(self.proto, 0, self.binding(st, ip, uid))?;
            st.local = Some(SocketAddr::new(ip, port));
        }
        Ok(())
    }

    fn take_err(&self, st: &mut State) -> i64 {
        match &st.io {
            Some(io) => io.take_err(),
            None => std::mem::take(&mut st.err),
        }
    }

    /// poll(2)'s view, as tcp_poll and datagram_poll have it.
    pub fn poll(&self) -> u16 {
        use hostio::{POLLERR, POLLHUP, POLLIN, POLLOUT, POLLRDHUP};
        if self.raw() {
            return POLLOUT;
        }
        let st = self.st.lock().unwrap();
        let mut r = if self.is_stream() {
            match (&st.io, st.phase) {
                (_, Phase::Listening) => 0,
                (Some(io), _) => io.readiness(),
                (None, _) => POLLOUT | POLLHUP | if st.shut_rd { POLLIN | POLLRDHUP } else { 0 },
            }
        } else {
            let mut r = POLLOUT;
            if !st.queue.is_empty() {
                r |= POLLIN;
            }
            if st.err != 0 {
                r |= POLLERR;
            }
            if st.shut_rd {
                r |= POLLIN | POLLRDHUP;
            }
            if st.shut_rd && st.shut_wr {
                r |= POLLHUP;
            }
            r
        };
        if r & POLLIN != 0 {
            r |= POLLRDNORM;
        }
        if r & POLLOUT != 0 {
            r |= POLLWRNORM;
        }
        r
    }

    /// A datagram arrives. Too many waiting and it's dropped, as on any host.
    pub fn deliver(&self, from: SocketAddr, data: Vec<u8>) {
        let mut st = self.st.lock().unwrap();
        if st.queued + data.len() > UDP_QUEUE {
            return;
        }
        st.queued += data.len();
        st.queue.push_back(Datagram { from, data });
        drop(st);
        EVENTS.bump_key(self.key);
    }

    fn recv(&self, t: &Thread, max: usize, flags: u64, nonblock: bool) -> Result<Received, i64> {
        if flags & MSG_ERRQUEUE != 0 {
            return Err(EAGAIN); // nothing ever goes in it
        }
        if self.is_stream() {
            if flags & MSG_OOB != 0 {
                return Err(EINVAL);
            }
            self.stream_recv(t, max, flags, nonblock)
        } else {
            self.datagram_recv(t, max, flags, nonblock)
        }
    }

    fn stream_recv(&self, t: &Thread, max: usize, flags: u64, nonblock: bool) -> Result<Received, i64> {
        let (io, until) = {
            let st = self.st.lock().unwrap();
            if st.phase == Phase::Listening {
                return Err(ENOTCONN);
            }
            match &st.io {
                Some(io) => (io.clone(), deadline(st.opts.rcvtimeo)),
                None if st.shut_rd => return Ok(Received { data: Vec::new(), real: 0, from: None }),
                None => return Err(ENOTCONN),
            }
        };
        let peek = flags & MSG_PEEK != 0;
        let all = flags & MSG_WAITALL != 0 && !peek && !nonblock;
        let mut got = Vec::new();
        let result = loop {
            let seen = EVENTS.watch_key(self.key);
            let want = max - got.len();
            match if peek { io.peek(want) } else { io.read(want) } {
                Ok(data) if data.is_empty() && want > 0 => break Ok(()),
                Ok(data) => {
                    got.extend_from_slice(&data);
                    if !all || got.len() == max {
                        break Ok(());
                    }
                }
                Err(EAGAIN) if nonblock => break Err(EAGAIN),
                Err(EAGAIN) => {}
                Err(e) => break Err(e),
            }
            if let Err(e) = wait_or_give_up(t, seen, until) {
                break Err(e);
            }
        };
        // What is already here is returned, and whatever stopped it comes up next time.
        if let (Err(e), true) = (result, got.is_empty()) {
            return Err(e);
        }
        let real = got.len();
        if flags & MSG_TRUNC != 0 {
            got = Vec::new(); // on a stream this means throw them away
        }
        Ok(Received { data: got, real, from: None })
    }

    fn datagram_recv(&self, t: &Thread, max: usize, flags: u64, nonblock: bool) -> Result<Received, i64> {
        let until = deadline(self.st.lock().unwrap().opts.rcvtimeo);
        loop {
            let seen = EVENTS.watch_key(self.key);
            {
                let mut st = self.st.lock().unwrap();
                if st.err != 0 {
                    return Err(std::mem::take(&mut st.err));
                }
                if let Some(d) = st.queue.front() {
                    let (real, from) = (d.data.len(), d.from);
                    let data = d.data[..real.min(max)].to_vec();
                    if flags & MSG_PEEK == 0 {
                        st.queue.pop_front();
                        st.queued -= real;
                    }
                    return Ok(Received { data, real, from: Some(from) });
                }
                if st.shut_rd {
                    return Ok(Received { data: Vec::new(), real: 0, from: None });
                }
            }
            if nonblock {
                return Err(EAGAIN);
            }
            wait_or_give_up(t, seen, until)?;
        }
    }

    /// Queues what fits, sleeping for the rest unless `nonblock`. A partial count rather
    /// than an error if any of it went.
    fn stream_send(&self, t: &Thread, src: &Source, nonblock: bool) -> Result<usize, i64> {
        let (io, until) = {
            let st = self.st.lock().unwrap();
            match (&st.io, st.phase) {
                (Some(io), Phase::Connecting | Phase::Connected | Phase::Idle) => (io.clone(), deadline(st.opts.sndtimeo)),
                _ => return Err(EPIPE),
            }
        };
        let total = src.len();
        let mut done = 0;
        let stop = |done: usize, e: i64| if done > 0 { Ok(done) } else { Err(e) };
        loop {
            let seen = EVENTS.watch_key(self.key);
            match io.room() {
                Ok(room) => {
                    let n = room.min(total - done);
                    if n > 0 {
                        let data = match src.read(t, done, n) {
                            Ok(data) => data,
                            Err(e) => return stop(done, e),
                        };
                        match io.write(&data) {
                            Ok(sent) => done += sent,
                            Err(EAGAIN) => {}
                            Err(e) => return stop(done, e),
                        }
                    }
                    if done == total {
                        return Ok(done);
                    }
                }
                Err(EAGAIN) => {}
                Err(e) => return stop(done, e),
            }
            if nonblock {
                return stop(done, EAGAIN);
            }
            if let Err(e) = wait_or_give_up(t, seen, until) {
                return stop(done, e);
            }
        }
    }

    /// One datagram, to `dest` or the connected peer.
    fn datagram_send(self: &Arc<Self>, t: &Thread, uid: u32, src: &Source, dest: Option<&[u8]>) -> Result<usize, i64> {
        let total = src.len();
        if total > if self.v6() { 65527 } else { 65507 } {
            return Err(EMSGSIZE);
        }
        let ping = matches!(self.proto, IPPROTO_ICMP | IPPROTO_ICMPV6);
        let (route_to, connected) = {
            let mut st = self.st.lock().unwrap();
            let v6only = Self::v6only(&st);
            // An AF_INET6 socket can mean "the connected peer" by AF_UNSPEC.
            let dest = dest.filter(|d| !(self.v6() && d.len() >= 2 && d[..2] == [0, 0]));
            let (addr, connected) = match dest {
                Some(raw) => (self.parse_addr(raw, AddrUse::UdpSend, v6only)?, false),
                None => (st.peer.ok_or(EDESTADDRREQ)?, true),
            };
            if addr.port() == 0 && !ping {
                return Err(EINVAL);
            }
            let err = std::mem::take(&mut st.err);
            if err != 0 {
                return Err(err);
            }
            if st.shut_wr {
                return Err(EPIPE);
            }
            let broadcast = st.opts.get(SO_BROADCAST).is_some_and(|v| v.iter().any(|&b| b != 0));
            let to = route(addr, false, broadcast)?;
            self.autobind(&mut st, uid)?;
            (to, connected)
        };
        if tracing() {
            eprintln!("[net] send {total} bytes: {route_to:?}");
        }
        match route_to {
            Route::Dns => dns::query(&src.read(t, 0, total)?, Arc::downgrade(self)),
            Route::Refused if connected => {
                self.st.lock().unwrap().err = ECONNREFUSED;
                EVENTS.bump_key(self.key);
            }
            // Nobody to hear it yet.
            Route::Local | Route::Host(_) | Route::Lost | Route::Refused => {}
        }
        Ok(total)
    }
}

/// read(2).
pub fn read(s: &Inet, t: &Thread, count: usize, nonblock: bool) -> Result<Vec<u8>, i64> {
    if s.raw() {
        return Err(ENOTCONN);
    }
    s.recv(t, count, 0, nonblock).map(|r| r.data)
}

/// write(2). EPIPE from a stream is for the caller to raise SIGPIPE on.
pub fn write(k: &Kernel, s: &Arc<Inet>, t: &Thread, data: &[u8], nonblock: bool) -> Result<usize, i64> {
    if s.raw() {
        return Err(ENETUNREACH);
    }
    let src = Source::Bytes(data);
    if s.is_stream() { s.stream_send(t, &src, nonblock) } else { s.datagram_send(t, k.creds(t).euid, &src, None) }
}

/// One table as GET_INFO describes it, its rules as GET_ENTRIES returns them.
#[derive(Clone)]
struct Table {
    valid_hooks: u32,
    hook_entry: [u32; 5],
    underflow: [u32; 5],
    num_entries: u32,
    entries: Vec<u8>,
}

/// (IPv6?, table name) -> table.
static TABLES: LazyLock<Mutex<HashMap<(bool, String), Table>>> = LazyLock::new(Mutex::default);

/// A fresh table: the kernel's built-in chains, each an ACCEPT policy, then
/// the ERROR entry that ends every table.
fn initial(v6: bool, name: &str) -> Option<Table> {
    // NF_INET_PRE_ROUTING, LOCAL_IN, FORWARD, LOCAL_OUT, POST_ROUTING.
    let valid_hooks: u32 = match name {
        "filter" | "security" => 0b01110,
        "mangle" => 0b11111,
        "nat" => 0b11011,
        "raw" => 0b01001,
        _ => return None,
    };
    // sizeof(ipt_entry) / sizeof(ip6t_entry), and where their fields sit.
    let (entry, target_off, next_off) = if v6 { (168, 140, 142) } else { (112, 88, 90) };
    let rule = |target: &[u8]| {
        let mut e = vec![0u8; entry];
        e[target_off..target_off + 2].copy_from_slice(&(entry as u16).to_le_bytes());
        e[next_off..next_off + 2].copy_from_slice(&((entry + target.len()) as u16).to_le_bytes());
        e.extend_from_slice(target);
        e
    };
    // xt_standard_target: xt_entry_target (size, name "", revision) + verdict, 8-aligned.
    let mut accept = vec![0u8; 40];
    accept[0..2].copy_from_slice(&40u16.to_le_bytes());
    accept[32..36].copy_from_slice(&(-2i32).to_le_bytes()); // -NF_ACCEPT - 1
    // xt_error_target: xt_entry_target named "ERROR" + errorname "ERROR", 8-aligned.
    let mut error = vec![0u8; 64];
    error[0..2].copy_from_slice(&64u16.to_le_bytes());
    error[2..7].copy_from_slice(b"ERROR");
    error[32..37].copy_from_slice(b"ERROR");
    let mut t = Table { valid_hooks, hook_entry: [u32::MAX; 5], underflow: [u32::MAX; 5], num_entries: 0, entries: Vec::new() };
    for hook in 0..5 {
        if valid_hooks & 1 << hook != 0 {
            let at = t.entries.len() as u32;
            t.hook_entry[hook] = at;
            t.underflow[hook] = at;
            t.entries.extend(rule(&accept));
            t.num_entries += 1;
        }
    }
    t.entries.extend(rule(&error));
    t.num_entries += 1;
    Some(t)
}

fn table_name(raw: &[u8]) -> String {
    let end = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
    String::from_utf8_lossy(&raw[..end]).into_owned()
}

fn with_table<R>(v6: bool, name: &str, f: impl FnOnce(&mut Table) -> R) -> Result<R, i64> {
    let mut tables = TABLES.lock().unwrap();
    let key = (v6, name.to_string());
    if !tables.contains_key(&key) {
        tables.insert(key.clone(), initial(v6, name).ok_or(ENOENT)?);
    }
    Ok(f(tables.get_mut(&key).unwrap()))
}

impl Kernel {
    pub(super) fn inet_socket(&self, t: &Arc<Thread>, a: [u64; 6]) -> Result<i64, i64> {
        let ty = (a[1] & 0xf) as u32;
        let proto = a[2] as u32;
        let proto = match (a[0], ty, proto) {
            (AF_KEY, _, _) | (_, SOCK_RAW, _) => proto,
            (_, SOCK_STREAM, 0 | IPPROTO_TCP) => IPPROTO_TCP,
            (_, SOCK_DGRAM, 0 | IPPROTO_UDP) => IPPROTO_UDP,
            (AF_INET, SOCK_DGRAM, IPPROTO_ICMP) | (AF_INET6, SOCK_DGRAM, IPPROTO_ICMPV6) => proto,
            (_, SOCK_STREAM | SOCK_DGRAM, _) => return Err(EPROTONOSUPPORT),
            _ => return Err(ESOCKTNOSUPPORT),
        };
        let sock = Inet { family: a[0], ty, proto, key: hostio::fresh_key(), st: Mutex::default() };
        let file = File::new(Kind::Inet(Arc::new(sock)), (a[1] & SOCK_NONBLOCK) as u32);
        t.files().alloc(file, a[1] & SOCK_CLOEXEC != 0, 0)
    }

    /// What's left of a socket for netd's iptables, which only asks about tables.
    fn raw_syscall(&self, no: Sysno, t: &Arc<Thread>, s: &Inet, f: &File, a: [u64; 6]) -> Result<i64, i64> {
        use Sysno::*;
        match no {
            bind | shutdown | listen => Ok(0),
            connect | sendto | sendmsg => Err(ENETUNREACH),
            getsockname => {
                let name = s.sockaddr(None);
                self.write_name(t, a[1], a[2], &name)?;
                Ok(0)
            }
            getpeername => Err(ENOTCONN),
            accept | accept4 => Err(EINVAL),
            recvfrom | recvmsg => {
                let flags = if no == recvfrom { a[3] } else { a[2] };
                if f.nonblock() || flags & MSG_DONTWAIT != 0 {
                    return Err(EAGAIN);
                }
                let until = deadline(s.st.lock().unwrap().opts.rcvtimeo);
                loop {
                    let seen = EVENTS.current();
                    wait_or_give_up(t, seen, until)?;
                }
            }
            _ => Err(EOPNOTSUPP),
        }
    }

    pub(super) fn inet_syscall(&self, no: Sysno, t: &Arc<Thread>, s: &Arc<Inet>, f: &File, a: [u64; 6]) -> Result<i64, i64> {
        let result = self.inet_call(no, t, s, f, a);
        if tracing() && !matches!(result, Err(EAGAIN | EINPROGRESS)) {
            eprintln!("[net] pid {} {no:?} on {:#x}, type {}: args {:x?}: {result:?}", t.proc.pid, s.key, s.ty, &a[1..4]);
        }
        result
    }

    fn inet_call(&self, no: Sysno, t: &Arc<Thread>, s: &Arc<Inet>, f: &File, a: [u64; 6]) -> Result<i64, i64> {
        use Sysno::*;
        match no {
            getsockopt => return self.inet_getsockopt(t, s, a),
            setsockopt => return self.inet_setsockopt(t, s, a),
            _ => {}
        }
        if s.raw() {
            return self.raw_syscall(no, t, s, f, a);
        }
        match no {
            bind => self.inet_bind(t, s, a),
            connect if s.is_stream() => self.stream_connect(t, s, f, a),
            connect => self.datagram_connect(t, s, a),
            listen => self.inet_listen(t, s),
            accept | accept4 => self.inet_accept(t, s, f),
            shutdown => self.inet_shutdown(s, a[1]),
            getsockname => {
                let name = {
                    let st = s.st.lock().unwrap();
                    st.local.map(|l| match st.source {
                        Some(ip) if l.ip().is_unspecified() => SocketAddr::new(ip, l.port()),
                        _ => l,
                    })
                };
                self.write_name(t, a[1], a[2], &s.sockaddr(name))?;
                Ok(0)
            }
            getpeername => {
                let peer = {
                    let st = s.st.lock().unwrap();
                    let up = st.io.as_ref().is_none_or(|io| io.link() == Link::Up);
                    if up { st.peer } else { None }
                };
                self.write_name(t, a[1], a[2], &s.sockaddr(Some(peer.ok_or(ENOTCONN)?)))?;
                Ok(0)
            }
            sendto => {
                let src = Source::Guest(vec![(a[1], a[2].min(IO_MAX))]);
                let dest = if a[4] != 0 { Some(t.proc.mm().read_vec(a[4], a[5].min(128) as usize)?) } else { None };
                self.inet_send(t, s, f, &src, dest.as_deref(), a[3])
            }
            sendmsg => {
                let (name, namelen, iov, iovlen) = {
                    let mut mm = t.proc.mm();
                    (mm.read_u64(a[1])?, mm.read_u32(a[1] + 8)?, mm.read_u64(a[1] + 16)?, mm.read_u64(a[1] + 24)?)
                };
                let src = Source::Guest(read_iov(t, iov, iovlen)?);
                let dest = if name != 0 && namelen != 0 { Some(t.proc.mm().read_vec(name, namelen.min(128) as usize)?) } else { None };
                self.inet_send(t, s, f, &src, dest.as_deref(), a[2])
            }
            recvfrom => {
                let nonblock = f.nonblock() || a[3] & MSG_DONTWAIT != 0;
                let r = s.recv(t, a[2].min(IO_MAX) as usize, a[3], nonblock)?;
                t.proc.mm().write(a[1], &r.data)?;
                if a[4] != 0 {
                    let name = r.from.map_or(Vec::new(), |from| s.sockaddr(Some(from)));
                    self.write_name(t, a[4], a[5], &name)?;
                }
                Ok(if a[3] & MSG_TRUNC != 0 { r.real } else { r.data.len() } as i64)
            }
            recvmsg => self.inet_recvmsg(t, s, f, a[1], a[2]),
            _ => Err(EOPNOTSUPP),
        }
    }

    /// Copies a name out, cut to the room the caller gave and with its real length.
    fn write_name(&self, t: &Thread, name: u64, lenp: u64, addr: &[u8]) -> Result<(), i64> {
        let mut mm = t.proc.mm();
        let room = mm.read_u32(lenp)?;
        if (room as i32) < 0 {
            return Err(EINVAL);
        }
        mm.write(name, &addr[..addr.len().min(room as usize)])?;
        mm.write_u32(lenp, addr.len() as u32)
    }

    fn inet_recvmsg(&self, t: &Thread, s: &Inet, f: &File, msg: u64, flags: u64) -> Result<i64, i64> {
        let (name, iov, iovlen) = {
            let mut mm = t.proc.mm();
            (mm.read_u64(msg)?, mm.read_u64(msg + 16)?, mm.read_u64(msg + 24)?)
        };
        let iovs = read_iov(t, iov, iovlen)?;
        let total: u64 = iovs.iter().map(|v| v.1).sum();
        let nonblock = f.nonblock() || flags & MSG_DONTWAIT != 0;
        let r = s.recv(t, total as usize, flags, nonblock)?;
        let mut mm = t.proc.mm();
        let mut at = 0;
        for (base, len) in iovs {
            if at >= r.data.len() {
                break;
            }
            let n = (len as usize).min(r.data.len() - at);
            mm.write(base, &r.data[at..at + n])?;
            at += n;
        }
        // No control messages yet. A datagram that didn't fit says so.
        mm.write_u64(msg + 40, 0)?;
        let truncated = !s.is_stream() && r.real > r.data.len();
        mm.write_u32(msg + 48, if truncated { MSG_TRUNC as u32 } else { 0 })?;
        drop(mm);
        if name != 0 {
            let addr = r.from.map_or(Vec::new(), |from| s.sockaddr(Some(from)));
            self.write_name(t, name, msg + 8, &addr)?;
        } else {
            t.proc.mm().write_u32(msg + 8, 0)?;
        }
        Ok(if flags & MSG_TRUNC != 0 { r.real } else { r.data.len() } as i64)
    }

    fn inet_send(&self, t: &Arc<Thread>, s: &Arc<Inet>, f: &File, src: &Source, dest: Option<&[u8]>, flags: u64) -> Result<i64, i64> {
        let nonblock = f.nonblock() || flags & MSG_DONTWAIT != 0;
        let result = if s.is_stream() {
            if flags & (MSG_OOB | MSG_FASTOPEN) != 0 {
                return Err(EOPNOTSUPP);
            }
            let r = s.stream_send(t, src, nonblock);
            if r == Err(EPIPE) && flags & MSG_NOSIGNAL == 0 {
                self.send_thread_signal(t, super::signal::SIGPIPE, super::signal::SigInfo::user(super::signal::SIGPIPE, t.proc.pid));
            }
            r
        } else {
            s.datagram_send(t, self.creds(t).euid, src, dest)
        };
        result.map(|n| n as i64)
    }

    fn inet_bind(&self, t: &Thread, s: &Inet, a: [u64; 6]) -> Result<i64, i64> {
        let raw = t.proc.mm().read_vec(a[1], a[2].min(128) as usize)?;
        let creds = self.creds(t);
        let mut st = s.st.lock().unwrap();
        let addr = s.parse_addr(&raw, AddrUse::Bind, Inet::v6only(&st))?;
        let ours = match addr.ip() {
            IpAddr::V4(ip) => ip.is_unspecified() || ip.is_loopback() || ip.is_multicast() || (ip.octets() == net::ETH_ADDRESS && net::ipv4_up()),
            IpAddr::V6(ip) => ip.is_unspecified() || ip.is_loopback() || ip.is_multicast(),
        };
        if !ours {
            return Err(EADDRNOTAVAIL);
        }
        if st.local.is_some() || st.phase != Phase::Idle {
            return Err(EINVAL);
        }
        if addr.port() != 0 && addr.port() < 1024 && !creds.capable(CAP_NET_BIND_SERVICE) {
            return Err(EACCES);
        }
        let port = take_port(s.proto, addr.port(), s.binding(&st, addr.ip(), creds.euid))?;
        st.local = Some(SocketAddr::new(addr.ip(), port));
        Ok(0)
    }

    fn inet_listen(&self, t: &Thread, s: &Inet) -> Result<i64, i64> {
        if !s.is_stream() {
            return Err(EOPNOTSUPP);
        }
        let uid = self.creds(t).euid;
        let mut st = s.st.lock().unwrap();
        if !matches!(st.phase, Phase::Idle | Phase::Listening) {
            return Err(EINVAL);
        }
        s.autobind(&mut st, uid)?;
        let port = st.local.unwrap().port();
        {
            let mut ports = PORTS.lock().unwrap();
            let holders = ports.get_mut(&(s.proto, port)).ok_or(EINVAL)?;
            let me = holders.iter().position(|b| b.owner == s.key).ok_or(EINVAL)?;
            let mine = holders[me].clone();
            if holders.iter().any(|b| b.owner != s.key && conflict(b, &mine, true)) {
                return Err(EADDRINUSE);
            }
            holders[me].listening = true;
        }
        st.phase = Phase::Listening;
        Ok(0)
    }

    /// Nothing can arrive yet. A blocking call waits like any other for what won't come:
    /// until a signal, an exit or its timeout. Returning at once would have a server's
    /// accept loop spinning for the life of the device.
    fn inet_accept(&self, t: &Arc<Thread>, s: &Inet, f: &File) -> Result<i64, i64> {
        if !s.is_stream() {
            return Err(EOPNOTSUPP);
        }
        let until = deadline(s.st.lock().unwrap().opts.rcvtimeo);
        loop {
            let seen = EVENTS.watch_key(s.key);
            if s.st.lock().unwrap().phase != Phase::Listening {
                return Err(EINVAL);
            }
            if f.nonblock() {
                return Err(EAGAIN);
            }
            wait_or_give_up(t, seen, until)?;
        }
    }

    fn inet_shutdown(&self, s: &Inet, how: u64) -> Result<i64, i64> {
        if how > 2 {
            return Err(EINVAL);
        }
        let reading = how != 1;
        let writing = how != 0;
        let mut st = s.st.lock().unwrap();
        let result = if s.is_stream() {
            match (st.phase, st.io.clone()) {
                (Phase::Listening, _) => {
                    if reading {
                        st.phase = Phase::Idle;
                        if let Some(local) = st.local {
                            let mut ports = PORTS.lock().unwrap();
                            if let Some(me) = ports.get_mut(&(s.proto, local.port())).and_then(|h| h.iter_mut().find(|b| b.owner == s.key)) {
                                me.listening = false;
                            }
                        }
                    }
                    Ok(0)
                }
                (_, Some(io)) if io.link() == Link::Connecting => {
                    Inet::disconnect(&mut st);
                    Ok(0)
                }
                (_, Some(io)) => {
                    io.shutdown(how);
                    Ok(0)
                }
                (_, None) => {
                    st.shut_rd |= reading;
                    st.shut_wr |= writing;
                    Err(ENOTCONN)
                }
            }
        } else {
            st.shut_rd |= reading;
            st.shut_wr |= writing;
            if st.peer.is_some() { Ok(0) } else { Err(ENOTCONN) }
        };
        drop(st);
        EVENTS.bump_key(s.key);
        result
    }

    fn datagram_connect(&self, t: &Thread, s: &Inet, a: [u64; 6]) -> Result<i64, i64> {
        let raw = t.proc.mm().read_vec(a[1], a[2].min(128) as usize)?;
        if raw.len() < 2 {
            return Err(EINVAL);
        }
        let uid = self.creds(t).euid;
        let mut st = s.st.lock().unwrap();
        if raw[..2] == [0, 0] {
            st.peer = None;
            st.source = None;
            return Ok(0);
        }
        let addr = s.parse_addr(&raw, AddrUse::UdpConnect, Inet::v6only(&st))?;
        let broadcast = st.opts.get(SO_BROADCAST).is_some_and(|v| v.iter().any(|&b| b != 0));
        // No host socket: the resolver makes one of these per answer it sorts, to learn
        // the source address, and sends nothing on them. Port 0 is fine for that.
        let to = route(addr, false, broadcast)?;
        s.autobind(&mut st, uid)?;
        st.source = Some(source_for(&to, addr));
        st.peer = Some(addr);
        Ok(0)
    }

    /// As __inet_stream_connect: the first call starts it, later ones say how it's going
    /// and the one that sees the end reports that, so a call interrupted by a signal
    /// can simply be made again.
    fn stream_connect(&self, t: &Thread, s: &Inet, f: &File, a: [u64; 6]) -> Result<i64, i64> {
        let raw = t.proc.mm().read_vec(a[1], a[2].min(128) as usize)?;
        if raw.len() < 2 {
            return Err(EINVAL);
        }
        let uid = self.creds(t).euid;
        let mut st = s.st.lock().unwrap();
        if raw[..2] == [0, 0] {
            Inet::disconnect(&mut st);
            drop(st);
            EVENTS.bump_key(s.key);
            return Ok(0);
        }
        let waiting = match st.phase {
            Phase::Connected | Phase::Listening => return Err(EISCONN),
            Phase::Connecting => EALREADY,
            Phase::Idle => {
                let addr = s.parse_addr(&raw, AddrUse::TcpConnect, Inet::v6only(&st))?;
                let to = route(addr, true, false);
                if tracing() {
                    eprintln!("[net] connect {addr}: {to:?}");
                }
                let host = match to? {
                    Route::Host(host) => host,
                    Route::Local | Route::Refused | Route::Dns | Route::Lost => return Err(ECONNREFUSED),
                };
                s.autobind(&mut st, uid)?;
                st.source = Some(IpAddr::from(net::ETH_ADDRESS));
                let nodelay = st.stored.get(&(SOL_TCP, TCP_NODELAY)).is_some_and(|v| v.iter().any(|&b| b != 0));
                let io = Io::with_key(s.key);
                io.connect(host, CONNECT_TIMEOUT, nodelay).map_err(|_| ENOBUFS)?;
                st.io = Some(io);
                st.peer = Some(addr);
                st.phase = Phase::Connecting;
                EINPROGRESS
            }
        };
        let io = st.io.clone().ok_or(EINVAL)?;
        let until = deadline(st.opts.sndtimeo);
        drop(st);
        loop {
            let seen = EVENTS.watch_key(s.key);
            match io.link() {
                Link::Connecting => {}
                Link::Up => {
                    s.st.lock().unwrap().phase = Phase::Connected;
                    return Ok(0);
                }
                Link::Down => {
                    let e = io.take_err();
                    Inet::disconnect(&mut s.st.lock().unwrap());
                    return Err(if e != 0 { e } else { ECONNABORTED });
                }
            }
            if f.nonblock() {
                return Err(waiting);
            }
            match wait_or_give_up(t, seen, until) {
                Ok(()) => {}
                Err(EAGAIN) => return Err(waiting), // the connection goes on without us
                Err(e) => return Err(e),
            }
        }
    }

    pub(super) fn inet_ioctl(&self, t: &Arc<Thread>, cmd: u64, arg: u64) -> Result<i64, i64> {
        const SIOCGIFCONF: u64 = 0x8912;
        if cmd == SIOCGIFCONF {
            // struct ifconf: a length, then a buffer of ifreqs (none: the size wanted).
            let mut mm = t.proc.mm();
            let room = mm.read_u32(arg)? as usize;
            let buf = mm.read_u64(arg + 8)?;
            let addresses = super::net::ipv4_addresses();
            let mut used = 0;
            for (name, ip) in &addresses {
                if buf != 0 && used + 40 > room {
                    break;
                }
                if buf != 0 {
                    let mut req = [0u8; 40];
                    req[..name.len()].copy_from_slice(name.as_bytes());
                    req[16..18].copy_from_slice(&2u16.to_le_bytes()); // AF_INET
                    req[20..24].copy_from_slice(ip);
                    mm.write(buf + used as u64, &req)?;
                }
                used += 40;
            }
            mm.write_u32(arg, used as u32)?;
            return Ok(0);
        }
        let mut req = [0u8; 40];
        t.proc.mm().read(arg, &mut req)?;
        super::net::ifreq_ioctl(cmd, &mut req)?;
        t.proc.mm().write(arg, &req)?;
        Ok(0)
    }

    /// The ioctls about a socket's own queues, not the interfaces.
    pub(super) fn inet_queue_ioctl(&self, t: &Thread, s: &Inet, cmd: u64, arg: u64) -> Result<i64, i64> {
        const SIOCOUTQ: u64 = 0x5411;
        const SIOCATMARK: u64 = 0x8905;
        const SIOCGSTAMP: u64 = 0x8906;
        let value = {
            let st = s.st.lock().unwrap();
            let (rx, tx) = st.io.as_ref().map_or((0, 0), |io| io.queued());
            match cmd {
                SIOCOUTQ => tx,
                SIOCATMARK => 0, // no urgent data ever
                SIOCGSTAMP => return Err(ENOENT),
                // FIONREAD: a datagram socket's is the next datagram's size.
                _ if s.is_stream() => rx,
                _ => st.queue.front().map_or(0, |d| d.data.len()),
            }
        };
        t.proc.mm().write_u32(arg, value as u32)?;
        Ok(0)
    }

    fn inet_getsockopt(&self, t: &Arc<Thread>, s: &Inet, a: [u64; 6]) -> Result<i64, i64> {
        let (level, name, val, lenp) = (a[1], a[2], a[3], a[4]);
        let len = t.proc.mm().read_u32(lenp)? as i32;
        if len < 0 {
            return Err(EINVAL);
        }
        let len = len as usize;
        if s.raw() && level != SOL_SOCKET {
            return self.iptables_get(t, s, level, name, val, len);
        }
        let value = s.get_option(level, name)?;
        let n = len.min(value.len());
        let mut mm = t.proc.mm();
        mm.write(val, &value[..n])?;
        mm.write_u32(lenp, n as u32)?;
        Ok(0)
    }

    fn inet_setsockopt(&self, t: &Arc<Thread>, s: &Inet, a: [u64; 6]) -> Result<i64, i64> {
        let (level, name, val) = (a[1], a[2], a[3]);
        if s.raw() && level != SOL_SOCKET {
            return self.iptables_set(t, s, level, name, val, a[4] as usize);
        }
        let v = sockopt_bytes(t, val, a[4])?;
        s.set_option(level, name, &v)?;
        Ok(0)
    }

    /// netd's questions about its tables, on a raw socket.
    fn iptables_get(&self, t: &Thread, s: &Inet, level: u64, name: u64, val: u64, len: usize) -> Result<i64, i64> {
        if s.ty != SOCK_RAW || level != if s.v6() { SOL_IPV6 } else { SOL_IP } {
            return Err(ENOPROTOOPT);
        }
        // ip6_tables numbers its revision queries 68/69, ip_tables 66/67.
        let revision = if s.v6() { [68, 69] } else { [66, 67] };
        match name {
            SO_GET_INFO => {
                if len != 84 {
                    return Err(EINVAL);
                }
                let mut info = t.proc.mm().read_vec(val, 84)?;
                let tbl = with_table(s.v6(), &table_name(&info[..32]), |t| t.clone())?;
                info[32..36].copy_from_slice(&tbl.valid_hooks.to_le_bytes());
                for h in 0..5 {
                    info[36 + h * 4..40 + h * 4].copy_from_slice(&tbl.hook_entry[h].to_le_bytes());
                    info[56 + h * 4..60 + h * 4].copy_from_slice(&tbl.underflow[h].to_le_bytes());
                }
                info[76..80].copy_from_slice(&tbl.num_entries.to_le_bytes());
                info[80..84].copy_from_slice(&(tbl.entries.len() as u32).to_le_bytes());
                t.proc.mm().write(val, &info)?;
                Ok(0)
            }
            SO_GET_ENTRIES => {
                // struct ipt_get_entries: name, size, then the rules (8-aligned).
                if len < 40 {
                    return Err(EINVAL);
                }
                let head = t.proc.mm().read_vec(val, 40)?;
                let size = u32::from_le_bytes(head[32..36].try_into().unwrap()) as usize;
                if len != 40 + size {
                    return Err(EINVAL);
                }
                let entries = with_table(s.v6(), &table_name(&head[..32]), |t| t.entries.clone())?;
                if entries.len() != size {
                    return Err(EAGAIN); // the table changed since GET_INFO
                }
                t.proc.mm().write(val + 40, &entries)?;
                Ok(0)
            }
            // Every match and target is there, at any revision.
            n if revision.contains(&n) => Ok(1),
            _ => Err(ENOPROTOOPT),
        }
    }

    fn iptables_set(&self, t: &Thread, s: &Inet, level: u64, name: u64, val: u64, len: usize) -> Result<i64, i64> {
        if s.ty != SOCK_RAW || level != if s.v6() { SOL_IPV6 } else { SOL_IP } {
            return Ok(0); // TOS, TTL, buffer sizes...: accepted
        }
        match name {
            SO_SET_REPLACE => {
                // struct ipt_replace: name, valid_hooks, num_entries, size,
                // hook_entry[5], underflow[5], num_counters, counters, rules
                // (unlike ipt_getinfo, the counts come first).
                if len < 96 {
                    return Err(EINVAL);
                }
                let head = t.proc.mm().read_vec(val, 96)?;
                let u = |o: usize| u32::from_le_bytes(head[o..o + 4].try_into().unwrap());
                let size = u(40) as usize;
                if len < 96 + size || size > 64 << 20 {
                    return Err(EINVAL);
                }
                let mut tbl = Table { valid_hooks: u(32), hook_entry: [0; 5], underflow: [0; 5], num_entries: u(36), entries: t.proc.mm().read_vec(val + 96, size)? };
                for h in 0..5 {
                    tbl.hook_entry[h] = u(44 + h * 4);
                    tbl.underflow[h] = u(64 + h * 4);
                }
                let name = table_name(&head[..32]);
                with_table(s.v6(), &name, |t| *t = tbl)?;
                // The old rules' counters go back to the caller: none counted.
                let (num_counters, counters) = (u(84) as usize, u64::from_le_bytes(head[88..96].try_into().unwrap()));
                if counters != 0 && num_counters > 0 {
                    t.proc.mm().write(counters, &vec![0u8; num_counters.min(1 << 20) * 16])?;
                }
                Ok(0)
            }
            SO_SET_ADD_COUNTERS => Ok(0),
            _ => Err(ENOPROTOOPT),
        }
    }
}

impl Inet {
    /// Back to how a new socket is, as a connection failing or AF_UNSPEC leaves it.
    fn disconnect(st: &mut State) {
        if let Some(io) = st.io.take() {
            io.abort();
        }
        st.phase = Phase::Idle;
        st.peer = None;
        st.source = None;
        st.shut_rd = false;
        st.shut_wr = false;
    }

    fn level_applies(&self, level: u64) -> bool {
        match level {
            SOL_IP => true,
            SOL_IPV6 => self.v6(),
            SOL_TCP => self.is_stream(),
            SOL_UDP => self.proto == IPPROTO_UDP,
            _ => level == self.proto as u64, // a ping socket's own filter
        }
    }

    /// An option's value. Every real option exists, and programs don't look for a way
    /// out when one is missing, so setting always works apart from `set_option`'s few.
    /// Reading one nobody has set takes knowing what it would be.
    fn get_option(&self, level: u64, name: u64) -> Result<Vec<u8>, i64> {
        let int = |v: i32| v.to_le_bytes().to_vec();
        let mut st = self.st.lock().unwrap();
        if level == SOL_SOCKET {
            return match name {
                SO_TYPE => Ok(int(self.ty as i32)),
                SO_DOMAIN => Ok(int(self.family as i32)),
                SO_PROTOCOL => Ok(int(self.proto as i32)),
                SO_ERROR => Ok(int(self.take_err(&mut st) as i32)),
                SO_ACCEPTCONN => Ok(int((st.phase == Phase::Listening) as i32)),
                SO_COOKIE => Ok((self.key as u64).to_le_bytes().to_vec()),
                SO_PEERCRED => Ok([int(0), int(-1), int(-1)].concat()),
                SO_SNDBUF | SO_RCVBUF => {
                    let default = match (self.is_stream(), name) {
                        (true, SO_SNDBUF) => 16384,
                        (true, _) => 131072,
                        (false, _) => UDP_QUEUE as i32,
                    };
                    Ok(int(st.stored.get(&(level, name)).map_or(default, |v| i32::from_le_bytes(v[..4].try_into().unwrap()))))
                }
                _ => st.opts.get(name).or_else(|| st.stored.get(&(level, name)).cloned()).ok_or(ENOPROTOOPT),
            };
        }
        if !self.level_applies(level) {
            return Err(ENOPROTOOPT);
        }
        match (level, name) {
            (SOL_IP, IP_MTU) | (SOL_IPV6, IPV6_MTU) => return if st.peer.is_some() { Ok(int(MTU)) } else { Err(ENOTCONN) },
            (SOL_TCP, TCP_INFO) => {
                // All zero, which says no data; tcpi_state is ESTABLISHED or CLOSE.
                let mut info = vec![0u8; 232];
                info[0] = if st.io.as_ref().is_some_and(|io| io.link() == Link::Up) { 1 } else { 7 };
                return Ok(info);
            }
            _ => {}
        }
        if let Some(v) = st.stored.get(&(level, name)) {
            return Ok(v.clone());
        }
        match (level, name) {
            (SOL_TCP, TCP_CONGESTION) => {
                let mut v = vec![0u8; 16];
                v[..5].copy_from_slice(b"cubic");
                Ok(v)
            }
            _ => default_option(level, name).map(int).ok_or_else(|| {
                if tracing() {
                    eprintln!("[net] getsockopt: nothing known of level {level} option {name}");
                }
                ENOPROTOOPT
            }),
        }
    }

    fn set_option(&self, level: u64, name: u64, val: &[u8]) -> Result<(), i64> {
        // Saying no to these is what makes their users take another way: what they
        // want done can't be, and these are the ones that check.
        match (level, name) {
            (SOL_UDP, UDP_SEGMENT | UDP_GRO) | (SOL_SOCKET, SO_ZEROCOPY) | (SOL_TCP, TCP_ULP | TCP_FASTOPEN_CONNECT) => return Err(ENOPROTOOPT),
            (SOL_TCP, TCP_REPAIR) => return Err(EPERM),
            _ => {}
        }
        if level != SOL_SOCKET && !self.level_applies(level) {
            return Err(ENOPROTOOPT);
        }
        let as_int = || val.get(..4).map(|v| i32::from_le_bytes(v.try_into().unwrap())).ok_or(EINVAL);
        let mut st = self.st.lock().unwrap();
        match (level, name) {
            (SOL_SOCKET, SO_SNDBUF | SO_RCVBUF | SO_SNDBUFFORCE | SO_RCVBUFFORCE) => {
                // Linux doubles it, for its own bookkeeping, and that's what reads back.
                let forced = matches!(name, SO_SNDBUFFORCE | SO_RCVBUFFORCE);
                let v = (as_int()?.max(0) as u32).min(if forced { u32::MAX / 2 } else { BUF_MAX });
                let key = if matches!(name, SO_SNDBUF | SO_SNDBUFFORCE) { SO_SNDBUF } else { SO_RCVBUF };
                let least = if key == SO_SNDBUF { 4608 } else { 2304 };
                st.stored.insert((SOL_SOCKET, key), ((v * 2).max(least) as i32).to_le_bytes().to_vec());
                return Ok(());
            }
            (SOL_SOCKET, SO_BINDTODEVICE) => {
                let end = val.iter().position(|&b| b == 0).unwrap_or(val.len());
                let device = String::from_utf8_lossy(&val[..end]);
                if !device.is_empty() && !net::exists(&device) {
                    return Err(ENODEV);
                }
            }
            (SOL_IPV6, IPV6_V6ONLY) if st.local.is_some() => return Err(EINVAL),
            (SOL_TCP, TCP_NODELAY) => {
                let on = as_int()? != 0;
                if let Some(io) = &st.io {
                    io.set_nodelay(on);
                }
            }
            _ => {}
        }
        if level == SOL_SOCKET && st.opts.set(name, val)? {
            return Ok(());
        }
        if tracing() && !st.stored.contains_key(&(level, name)) && default_option(level, name).is_none() {
            eprintln!("[net] setsockopt: kept with no effect: level {level} option {name}");
        }
        // Someone can set an int by one byte, and read it as four.
        let mut stored = val.to_vec();
        if stored.len() < 4 {
            stored.resize(4, 0);
        }
        st.stored.insert((level, name), stored);
        Ok(())
    }
}

/// What the options Android's and Chromium's code reads are before anyone sets them.
fn default_option(level: u64, name: u64) -> Option<i32> {
    Some(match (level, name) {
        // IP_TOS, IP_TTL, IP_HDRINCL, IP_PKTINFO, IP_MTU_DISCOVER, IP_RECVERR, IP_RECVTTL,
        // IP_RECVTOS, IP_MULTICAST_TTL, IP_MULTICAST_LOOP
        (SOL_IP, 1) => 0,
        (SOL_IP, 2) => 64,
        (SOL_IP, 3 | 8 | 11 | 12 | 13) => 0,
        (SOL_IP, 10) => 1,
        (SOL_IP, 33 | 34) => 1,
        // IPV6_UNICAST_HOPS, IPV6_MULTICAST_HOPS, IPV6_MULTICAST_LOOP, IPV6_MTU_DISCOVER,
        // IPV6_RECVERR, IPV6_V6ONLY, IPV6_RECVPKTINFO, IPV6_RECVHOPLIMIT, IPV6_RECVTCLASS,
        // IPV6_TCLASS
        (SOL_IPV6, 16) => 64,
        (SOL_IPV6, 18 | 19) => 1,
        (SOL_IPV6, 23) => 1,
        (SOL_IPV6, 25 | 26 | 49 | 51 | 66 | 67) => 0,
        // TCP_NODELAY, TCP_MAXSEG, TCP_CORK, TCP_KEEPIDLE, TCP_KEEPINTVL, TCP_KEEPCNT,
        // TCP_SYNCNT, TCP_LINGER2, TCP_DEFER_ACCEPT, TCP_WINDOW_CLAMP, TCP_QUICKACK,
        // TCP_USER_TIMEOUT, TCP_FASTOPEN, TCP_NOTSENT_LOWAT
        (SOL_TCP, 1 | 3 | 9 | 10 | 18 | 23 | 25) => 0,
        (SOL_TCP, 2) => 1460,
        (SOL_TCP, 4) => 7200,
        (SOL_TCP, 5) => 75,
        (SOL_TCP, 6) => 9,
        (SOL_TCP, 7) => 6,
        (SOL_TCP, 8) => 60,
        (SOL_TCP, 12) => 1,
        // UDP_CORK
        (SOL_UDP, 1) => 0,
        _ => return None,
    })
}

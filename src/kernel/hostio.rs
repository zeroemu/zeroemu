//! A byte stream between a guest socket and a host TCP connection. A guest thread
//! never blocks in a host call, where neither a signal nor an exit could reach it: it
//! moves bytes to and from queues here and sleeps in EVENTS like any other socket.
//! Host threads make the connection and move bytes between the queues and it, the one
//! that writes starting only when there is something to write. They hold only this and
//! the connection, so the guest's last close is still noticed.

use super::wait::EVENTS;
use crate::errno::*;
use std::collections::{BTreeMap, VecDeque};
use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

/// A connect can't be cancelled, so a dropped SYN holds a thread for a minute or more,
/// whether or not the socket's still open. Without these an app connecting to somewhere
/// that doesn't answer could use up the host's threads, which everything needs.
const MAX_CONNECTING_PER_UID: usize = 512;
const MAX_CONNECTING: usize = 1024;
static CONNECTING: std::sync::Mutex<BTreeMap<u32, usize>> = std::sync::Mutex::new(BTreeMap::new());

/// How long a closed socket's queued bytes wait for a peer that isn't reading. Linux
/// bounds this too. A write timeout isn't an option: on Windows it leaves the socket
/// undefined, and write_all would lose count anyway.
const ORPHAN: Duration = Duration::from_secs(60);

/// Bytes queued each way. Past this the guest gets EAGAIN or sleeps, and the host's
/// sender finds the connection's window closed.
const LIMIT: usize = 1 << 20;
const CHUNK: usize = 64 << 10;
/// Under this much queued a socket polls writable: not for one free byte, as the kernel
/// doesn't either.
const WRITABLE: usize = LIMIT / 3 * 2;
/// The pumps call little and keep their buffers on the heap.
const STACK: usize = 256 << 10;

pub const POLLIN: u16 = 0x1;
pub const POLLOUT: u16 = 0x4;
pub const POLLERR: u16 = 0x8;
pub const POLLHUP: u16 = 0x10;
pub const POLLRDHUP: u16 = 0x2000;

/// A host error as the guest knows it: the numbers differ between hosts and Linux.
pub fn linux_errno(e: &std::io::Error) -> i64 {
    use std::io::ErrorKind::*;
    match e.kind() {
        ConnectionRefused => ECONNREFUSED,
        ConnectionReset => ECONNRESET,
        ConnectionAborted => ECONNABORTED,
        NotConnected => ENOTCONN,
        AddrInUse => EADDRINUSE,
        AddrNotAvailable => EADDRNOTAVAIL,
        BrokenPipe => EPIPE,
        TimedOut => ETIMEDOUT,
        HostUnreachable => EHOSTUNREACH,
        NetworkUnreachable => ENETUNREACH,
        NetworkDown => ENETDOWN,
        PermissionDenied => EACCES,
        _ => EIO,
    }
}

/// What a guest thread waiting on something watches in EVENTS: any number nothing
/// else uses. EVENTS drops the low bits, as of an address.
pub fn fresh_key() -> usize {
    static NEXT: AtomicUsize = AtomicUsize::new(1);
    NEXT.fetch_add(1, Ordering::Relaxed) << 4
}

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Link {
    Connecting,
    Up,
    /// It failed, or was reset.
    Down,
}

#[derive(Default)]
struct State {
    rx: VecDeque<u8>,
    tx: VecDeque<u8>,
    /// The host has no more to send, or the connection failed.
    rx_eof: bool,
    /// The connection is gone: nothing more can be sent.
    dead: bool,
    /// The guest's shutdown(2).
    shut_rd: bool,
    shut_wr: bool,
    /// The guest's last close.
    closed: bool,
    /// What went wrong, until the guest has been told: sk_err.
    err: i64,
    connecting: bool,
    nodelay: bool,
    stream: Option<Arc<TcpStream>>,
    /// The writing thread is running.
    writing: bool,
    /// It has bytes that aren't in `tx` any more, in a host call.
    sending: bool,
}

pub struct Io {
    key: usize,
    st: Mutex<State>,
    /// The host threads wait here for room or for something to send.
    pumps: Condvar,
}

impl Io {
    pub fn new() -> Arc<Io> {
        Io::with_key(fresh_key())
    }

    pub fn with_key(key: usize) -> Arc<Io> {
        Arc::new(Io { key, st: Mutex::default(), pumps: Condvar::new() })
    }

    /// What a guest thread waiting on this watches in EVENTS.
    pub fn key(&self) -> usize {
        self.key
    }

    fn changed(&self) {
        EVENTS.bump_key(self.key);
    }

    /// Up to `max` bytes; empty at the end of the stream; EAGAIN if there is nothing yet.
    /// `keep_err`: a call that's already got something to return leaves an error for
    /// the next, rather than clearing it for one that won't report it.
    pub fn read(self: &Arc<Self>, max: usize, keep_err: bool) -> Result<Vec<u8>, i64> {
        let mut st = self.st.lock().unwrap();
        if !st.rx.is_empty() {
            let n = max.min(st.rx.len());
            let out: Vec<u8> = st.rx.drain(..n).collect();
            drop(st);
            self.pumps.notify_all();
            return Ok(out);
        }
        Self::nothing_to_read(&mut st, keep_err)
    }

    /// As `read`, leaving the bytes where they are.
    pub fn peek(&self, max: usize) -> Result<Vec<u8>, i64> {
        let mut st = self.st.lock().unwrap();
        if !st.rx.is_empty() {
            return Ok(st.rx.iter().take(max).copied().collect());
        }
        Self::nothing_to_read(&mut st, false)
    }

    /// Nothing more will come: no reason for a reader who wants more than there is to wait.
    pub fn ended(&self) -> bool {
        let st = self.st.lock().unwrap();
        st.rx_eof || st.shut_rd || st.err != 0
    }

    /// With no data left: the error if there is one, once, then the end of the stream.
    /// Only at the end of it: a failed send mustn't hide what the reader thread has yet
    /// to bring in, like a reply sent before a reset.
    fn nothing_to_read(st: &mut State, keep_err: bool) -> Result<Vec<u8>, i64> {
        if st.err != 0 && st.rx_eof {
            return Err(if keep_err { st.err } else { std::mem::take(&mut st.err) });
        }
        if st.rx_eof || st.shut_rd {
            return Ok(Vec::new());
        }
        Err(EAGAIN)
    }

    /// How much `write` would take now; an error if none ever will; EAGAIN if it's not
    /// connected yet. No bytes need copying from the guest to find out.
    pub fn room(&self, keep_err: bool) -> Result<usize, i64> {
        Self::room_in(&mut self.st.lock().unwrap(), keep_err)
    }

    fn room_in(st: &mut State, keep_err: bool) -> Result<usize, i64> {
        if st.err != 0 {
            return Err(if keep_err { st.err } else { std::mem::take(&mut st.err) });
        }
        if st.dead || st.shut_wr {
            return Err(EPIPE);
        }
        if st.connecting {
            return Err(EAGAIN);
        }
        Ok(LIMIT.saturating_sub(st.tx.len()))
    }

    /// As many bytes as there is room for; EAGAIN for none; EPIPE if they can't go.
    pub fn write(self: &Arc<Self>, data: &[u8], keep_err: bool) -> Result<usize, i64> {
        let mut st = self.st.lock().unwrap();
        let n = data.len().min(Self::room_in(&mut st, keep_err)?);
        if n == 0 {
            return if data.is_empty() { Ok(0) } else { Err(EAGAIN) };
        }
        st.tx.extend(&data[..n]);
        self.ensure_writer(&mut st)?;
        drop(st);
        self.pumps.notify_all();
        Ok(n)
    }

    fn ensure_writer(self: &Arc<Self>, st: &mut State) -> Result<(), i64> {
        // With no connection yet, the bytes wait for it: `attach` looks.
        if st.writing || st.stream.is_none() {
            return Ok(());
        }
        let (io, stream) = (self.clone(), st.stream.clone().unwrap());
        match std::thread::Builder::new().name("hostio-write".into()).stack_size(STACK).spawn(move || io.pump_out(&stream)) {
            Ok(_) => {
                st.writing = true;
                Ok(())
            }
            Err(_) => Err(ENOBUFS),
        }
    }

    /// poll(2)'s view from the guest.
    pub fn readiness(&self) -> u16 {
        let st = self.st.lock().unwrap();
        // While connecting nothing at all, not even writable: to the callers that wait
        // for that and then look for an error, no error would mean connected.
        if st.connecting {
            return 0;
        }
        let mut r = 0;
        if !st.rx.is_empty() || st.rx_eof || st.shut_rd {
            r |= POLLIN;
        }
        if st.rx_eof || st.shut_rd {
            r |= POLLRDHUP;
        }
        // A send that will fail doesn't block, so it counts as writable.
        if st.tx.len() < WRITABLE || st.dead || st.shut_wr {
            r |= POLLOUT;
        }
        // Each way shut, by this end or the other.
        if st.dead || (st.shut_wr && (st.rx_eof || st.shut_rd)) {
            r |= POLLHUP;
        }
        if st.err != 0 {
            r |= POLLERR;
        }
        r
    }

    pub fn link(&self) -> Link {
        let st = self.st.lock().unwrap();
        if st.connecting {
            Link::Connecting
        } else if st.dead {
            Link::Down
        } else {
            Link::Up
        }
    }

    /// SO_ERROR: reading it clears it.
    pub fn take_err(&self) -> i64 {
        std::mem::take(&mut self.st.lock().unwrap().err)
    }

    /// Bytes ready for the guest (FIONREAD), and not yet sent (SIOCOUTQ).
    pub fn queued(&self) -> (usize, usize) {
        let st = self.st.lock().unwrap();
        (st.rx.len(), st.tx.len())
    }

    pub fn set_nodelay(&self, on: bool) {
        let mut st = self.st.lock().unwrap();
        st.nodelay = on;
        if let Some(stream) = &st.stream {
            let _ = stream.set_nodelay(on);
        }
    }

    /// The guest's shutdown(2): SHUT_RD 0, SHUT_WR 1, SHUT_RDWR 2. Unread bytes stay
    /// readable, and more can still arrive, as on Linux.
    pub fn shutdown(self: &Arc<Self>, how: u64) {
        let mut st = self.st.lock().unwrap();
        if how != 1 {
            st.shut_rd = true;
        }
        if how != 0 && !st.shut_wr {
            st.shut_wr = true;
            if st.writing {
                // It sends the FIN after what is queued.
            } else if let Some(stream) = &st.stream {
                let _ = stream.shutdown(Shutdown::Write);
            }
        }
        drop(st);
        self.pumps.notify_all();
        self.changed();
    }

    /// The guest's last close: what is queued goes out, then the connection closes.
    pub fn close(self: &Arc<Self>) {
        self.close_within(ORPHAN);
    }

    fn close_within(self: &Arc<Self>, limit: Duration) {
        let mut st = self.st.lock().unwrap();
        st.closed = true;
        if let Some(stream) = st.stream.clone() {
            if !st.writing {
                let _ = stream.shutdown(Shutdown::Both); // wakes the reader
            } else if st.sending || !st.tx.is_empty() {
                // The writing thread could be in a host call for as long as the peer
                // doesn't read. If it hasn't finished in time, cut it off. An idle one
                // is about to see `closed`, so this only costs a thread when it matters.
                let io = self.clone();
                let _ = std::thread::Builder::new().name("hostio-reap".into()).stack_size(STACK).spawn(move || {
                    let st = io.st.lock().unwrap();
                    let (_st, wait) = io.pumps.wait_timeout_while(st, limit, |st| st.writing).unwrap();
                    if wait.timed_out() {
                        let _ = stream.shutdown(Shutdown::Both);
                    }
                });
            }
        }
        drop(st);
        self.pumps.notify_all();
    }

    /// As `close`, dropping what is queued: SO_LINGER with no time, or a disconnect.
    pub fn abort(&self) {
        let mut st = self.st.lock().unwrap();
        st.closed = true;
        st.tx.clear();
        st.dead = true;
        st.rx_eof = true;
        // A thread sleeping in connect() on this hears now. The one making it is ignored.
        st.connecting = false;
        if let Some(stream) = &st.stream {
            let _ = stream.shutdown(Shutdown::Both);
        }
        drop(st);
        self.pumps.notify_all();
        self.changed();
    }

    /// Starts moving bytes over `stream`.
    pub fn attach(self: &Arc<Self>, stream: TcpStream) -> std::io::Result<()> {
        let stream = Arc::new(stream);
        {
            let mut st = self.st.lock().unwrap();
            st.stream = Some(stream.clone());
            // Sent before there was a connection to send it on.
            if !st.tx.is_empty() || st.shut_wr || st.closed {
                let _ = self.ensure_writer(&mut st);
            }
        }
        let io = self.clone();
        std::thread::Builder::new().name("hostio-read".into()).stack_size(STACK).spawn(move || io.pump_in(&stream))?;
        Ok(())
    }

    /// Connects to `to` in the background; link() says how it went. Nothing can cancel
    /// this: a socket closed meanwhile leaves the thread until the connect ends. ENOBUFS
    /// if `uid` or everybody has too many going.
    pub fn connect(self: &Arc<Self>, to: SocketAddr, timeout: Duration, nodelay: bool, uid: u32) -> Result<(), i64> {
        {
            let mut going = CONNECTING.lock().unwrap();
            if going.values().sum::<usize>() >= MAX_CONNECTING || going.get(&uid).is_some_and(|&n| n >= MAX_CONNECTING_PER_UID) {
                return Err(ENOBUFS);
            }
            *going.entry(uid).or_default() += 1;
        }
        let finished = move || {
            let mut going = CONNECTING.lock().unwrap();
            if let Some(n) = going.get_mut(&uid) {
                *n -= 1;
                if *n == 0 {
                    going.remove(&uid);
                }
            }
        };
        {
            let mut st = self.st.lock().unwrap();
            st.connecting = true;
            st.nodelay = nodelay;
        }
        let io = self.clone();
        let spawned = std::thread::Builder::new().name("hostio-connect".into()).stack_size(STACK).spawn(move || {
            let result = TcpStream::connect_timeout(&to, timeout);
            finished();
            io.connected(result);
        });
        if spawned.is_err() {
            finished();
            self.st.lock().unwrap().connecting = false;
            return Err(ENOBUFS);
        }
        Ok(())
    }

    fn connected(self: &Arc<Self>, result: std::io::Result<TcpStream>) {
        match result {
            Ok(stream) => {
                let stream = Arc::new(stream);
                {
                    let mut st = self.st.lock().unwrap();
                    st.connecting = false;
                    if st.closed {
                        let _ = stream.shutdown(Shutdown::Both);
                        return;
                    }
                    if st.nodelay {
                        let _ = stream.set_nodelay(true);
                    }
                    st.stream = Some(stream.clone());
                    if st.shut_wr {
                        let _ = stream.shutdown(Shutdown::Write);
                    }
                }
                self.changed();
                self.pump_in(&stream); // this thread goes on as the reader
            }
            Err(e) => {
                let mut st = self.st.lock().unwrap();
                st.connecting = false;
                st.err = linux_errno(&e);
                st.dead = true;
                st.rx_eof = true;
                drop(st);
                self.changed();
            }
        }
    }

    fn pump_in(self: &Arc<Self>, stream: &TcpStream) {
        let mut buf = vec![0; CHUNK];
        let failed = loop {
            {
                let mut st = self.st.lock().unwrap();
                while st.rx.len() >= LIMIT && !st.closed {
                    st = self.pumps.wait(st).unwrap();
                }
                if st.closed {
                    return;
                }
            }
            match (&mut &*stream).read(&mut buf) {
                Ok(0) => break None,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => break Some(e),
                Ok(n) => {
                    self.st.lock().unwrap().rx.extend(&buf[..n]);
                    // Every time, not only when it was empty. An edge-triggered reader
                    // is told of each arrival, as on Linux, and can leave some unread.
                    self.changed();
                }
            }
        };
        let mut st = self.st.lock().unwrap();
        st.rx_eof = true;
        if let Some(e) = failed {
            if !st.closed && !st.dead {
                st.err = linux_errno(&e);
            }
            st.dead = true;
            st.tx.clear();
        }
        drop(st);
        self.pumps.notify_all();
        self.changed();
    }

    fn pump_out(self: &Arc<Self>, stream: &TcpStream) {
        let mut sent_fin = false;
        loop {
            let chunk: Vec<u8> = {
                let mut st = self.st.lock().unwrap();
                while st.tx.is_empty() && !st.closed && (!st.shut_wr || sent_fin) && !st.dead {
                    st = self.pumps.wait(st).unwrap();
                }
                if st.dead {
                    st.writing = false;
                    drop(st);
                    self.pumps.notify_all();
                    return;
                }
                if st.tx.is_empty() {
                    if st.closed {
                        st.writing = false;
                        drop(st);
                        let _ = stream.shutdown(Shutdown::Both); // wakes the reader
                        self.pumps.notify_all();
                        return;
                    }
                    drop(st);
                    let _ = stream.shutdown(Shutdown::Write);
                    sent_fin = true;
                    continue;
                }
                let before = st.tx.len();
                let n = before.min(CHUNK);
                let chunk = st.tx.drain(..n).collect();
                st.sending = true;
                drop(st);
                // Only when it matters: a sender sleeps with the queue full, and poll
                // goes by the mark. Each wakeup costs a look at every guest thread.
                if before >= LIMIT || (before >= WRITABLE && before - n < WRITABLE) {
                    self.changed();
                }
                chunk
            };
            let sent = (&mut &*stream).write_all(&chunk);
            let mut st = self.st.lock().unwrap();
            st.sending = false;
            if let Err(e) = sent {
                if !st.closed && !st.dead {
                    st.err = linux_errno(&e);
                }
                // Not the end of the input: the reader thread may have a reply to bring
                // in, and it's the one to say so. A socket this broken wakes it.
                st.dead = true;
                st.tx.clear();
                st.writing = false;
                drop(st);
                self.pumps.notify_all();
                self.changed();
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    #[test]
    fn a_closed_socket_gives_up_on_a_peer_that_wont_read() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (_peer, _) = listener.accept().unwrap(); // never read
        let io = Io::new();
        io.attach(client).unwrap();
        // Enough to fill the host's buffers, then the queue.
        let chunk = vec![0u8; CHUNK];
        let start = std::time::Instant::now();
        loop {
            match io.write(&chunk, false) {
                Ok(_) => {}
                Err(EAGAIN) if io.st.lock().unwrap().sending => break,
                Err(EAGAIN) => std::thread::sleep(Duration::from_millis(1)),
                Err(e) => panic!("write: {e}"),
            }
            assert!(start.elapsed() < Duration::from_secs(20), "the writer never blocked");
        }
        io.close_within(Duration::from_millis(50));
        let start = std::time::Instant::now();
        while io.st.lock().unwrap().writing {
            assert!(start.elapsed() < Duration::from_secs(10), "the writer is still stuck");
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    #[test]
    fn connects_in_progress_are_limited() {
        // Nothing listens, but they all fail fast: what matters is the count, from a uid
        // nothing else here uses.
        const UID: u32 = 4_000_000;
        CONNECTING.lock().unwrap().insert(UID, MAX_CONNECTING_PER_UID);
        let refused = Io::new().connect(SocketAddr::from(([127, 0, 0, 1], 9)), Duration::from_secs(1), false, UID);
        CONNECTING.lock().unwrap().remove(&UID);
        assert_eq!(refused, Err(ENOBUFS));
    }
}

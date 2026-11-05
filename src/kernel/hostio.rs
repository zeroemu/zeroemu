//! A byte stream between a guest socket and a host TCP connection. A guest thread
//! never blocks in a host call, where neither a signal nor an exit could reach it: it
//! moves bytes to and from queues here and sleeps in EVENTS like any other socket.
//! Host threads make the connection and move bytes between the queues and it, the one
//! that writes starting only when there is something to write. They hold only this and
//! the connection, so the guest's last close is still noticed.

use super::wait::EVENTS;
use crate::errno::*;
use std::collections::VecDeque;
use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

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
    writing: bool,
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
    pub fn read(self: &Arc<Self>, max: usize) -> Result<Vec<u8>, i64> {
        let mut st = self.st.lock().unwrap();
        if !st.rx.is_empty() {
            let n = max.min(st.rx.len());
            let out: Vec<u8> = st.rx.drain(..n).collect();
            drop(st);
            self.pumps.notify_all();
            return Ok(out);
        }
        Self::nothing_to_read(&mut st)
    }

    /// As `read`, leaving the bytes where they are.
    pub fn peek(&self, max: usize) -> Result<Vec<u8>, i64> {
        let mut st = self.st.lock().unwrap();
        if !st.rx.is_empty() {
            return Ok(st.rx.iter().take(max).copied().collect());
        }
        Self::nothing_to_read(&mut st)
    }

    /// With no data left: the error if there is one, once, then the end of the stream.
    fn nothing_to_read(st: &mut State) -> Result<Vec<u8>, i64> {
        if st.err != 0 {
            return Err(std::mem::take(&mut st.err));
        }
        if st.rx_eof || st.shut_rd {
            return Ok(Vec::new());
        }
        Err(EAGAIN)
    }

    /// How much `write` would take now; an error if none ever will; EAGAIN if it's not
    /// connected yet. No bytes need copying from the guest to find out.
    pub fn room(&self) -> Result<usize, i64> {
        let mut st = self.st.lock().unwrap();
        if st.err != 0 {
            return Err(std::mem::take(&mut st.err));
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
    pub fn write(self: &Arc<Self>, data: &[u8]) -> Result<usize, i64> {
        let room = self.room()?;
        let n = data.len().min(room);
        if n == 0 {
            return if data.is_empty() { Ok(0) } else { Err(EAGAIN) };
        }
        let mut st = self.st.lock().unwrap();
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
        if st.dead || (st.rx_eof && st.shut_wr) {
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
    pub fn close(&self) {
        let mut st = self.st.lock().unwrap();
        st.closed = true;
        if !st.writing
            && let Some(stream) = &st.stream
        {
            let _ = stream.shutdown(Shutdown::Both); // wakes the reader
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
    /// this: a socket closed meanwhile leaves the thread until the connect ends.
    pub fn connect(self: &Arc<Self>, to: SocketAddr, timeout: Duration, nodelay: bool) -> std::io::Result<()> {
        {
            let mut st = self.st.lock().unwrap();
            st.connecting = true;
            st.nodelay = nodelay;
        }
        let io = self.clone();
        let spawned = std::thread::Builder::new().name("hostio-connect".into()).stack_size(STACK).spawn(move || {
            let result = TcpStream::connect_timeout(&to, timeout);
            io.connected(result);
        });
        if spawned.is_err() {
            self.st.lock().unwrap().connecting = false;
        }
        spawned.map(|_| ())
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
                    let mut st = self.st.lock().unwrap();
                    let was_empty = st.rx.is_empty();
                    st.rx.extend(&buf[..n]);
                    drop(st);
                    // Each guest waiting has seen an empty queue.
                    if was_empty {
                        self.changed();
                    }
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
                    return;
                }
                if st.tx.is_empty() {
                    if st.closed {
                        drop(st);
                        let _ = stream.shutdown(Shutdown::Both); // wakes the reader
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
                drop(st);
                // Only when it matters: a sender sleeps with the queue full, and poll
                // goes by the mark. Each wakeup costs a look at every guest thread.
                if before == LIMIT || (before >= WRITABLE && before - n < WRITABLE) {
                    self.changed();
                }
                chunk
            };
            if let Err(e) = (&mut &*stream).write_all(&chunk) {
                let mut st = self.st.lock().unwrap();
                if !st.closed && !st.dead {
                    st.err = linux_errno(&e);
                }
                st.dead = true;
                st.rx_eof = true;
                st.tx.clear();
                drop(st);
                self.changed();
                return;
            }
        }
    }
}

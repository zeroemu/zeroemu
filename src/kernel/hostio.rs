//! A byte stream between a guest socket and a host TCP connection. A guest thread
//! never blocks in a host call, where neither a signal nor an exit could reach it: it
//! moves bytes to and from queues here and sleeps in EVENTS like any other socket.
//! Two host threads move them between the queues and the connection. They hold only
//! this and the connection, so the guest's last close is still noticed.

use super::wait::EVENTS;
use crate::errno::*;
use std::collections::VecDeque;
use std::io::{Read, Write};
use std::net::{Shutdown, TcpStream};
use std::sync::{Arc, Condvar, Mutex};

/// Bytes queued each way. Past this the guest gets EAGAIN or sleeps, and the host's
/// sender finds the connection's window closed.
const LIMIT: usize = 1 << 20;
const CHUNK: usize = 64 << 10;

pub const POLLIN: u16 = 0x1;
pub const POLLOUT: u16 = 0x4;
pub const POLLHUP: u16 = 0x10;
pub const POLLRDHUP: u16 = 0x2000;

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
}

pub struct Io {
    st: Mutex<State>,
    /// The host threads wait here for room or for something to send.
    pumps: Condvar,
}

impl Io {
    pub fn new() -> Arc<Io> {
        Arc::new(Io { st: Mutex::default(), pumps: Condvar::new() })
    }

    /// What a guest thread waiting on this watches in EVENTS.
    pub fn key(self: &Arc<Self>) -> usize {
        Arc::as_ptr(self) as usize
    }

    fn changed(self: &Arc<Self>) {
        EVENTS.bump_key(self.key());
    }

    /// Up to `max` bytes; empty at the end of the stream; EAGAIN if there is nothing yet.
    pub fn read(self: &Arc<Self>, max: usize) -> Result<Vec<u8>, i64> {
        let mut st = self.st.lock().unwrap();
        if !st.rx.is_empty() && !st.shut_rd {
            let n = max.min(st.rx.len());
            let out: Vec<u8> = st.rx.drain(..n).collect();
            drop(st);
            self.pumps.notify_all();
            return Ok(out);
        }
        if st.rx_eof || st.shut_rd {
            return Ok(Vec::new());
        }
        Err(EAGAIN)
    }

    /// As many bytes as there is room for; EAGAIN for none; EPIPE if they can't go.
    pub fn write(self: &Arc<Self>, data: &[u8]) -> Result<usize, i64> {
        let mut st = self.st.lock().unwrap();
        if st.dead || st.shut_wr {
            return Err(EPIPE);
        }
        let n = data.len().min(LIMIT.saturating_sub(st.tx.len()));
        if n == 0 {
            return Err(EAGAIN);
        }
        st.tx.extend(&data[..n]);
        drop(st);
        self.pumps.notify_all();
        Ok(n)
    }

    /// poll(2)'s view from the guest.
    pub fn readiness(&self) -> u16 {
        let st = self.st.lock().unwrap();
        let mut r = 0;
        if !st.rx.is_empty() || st.rx_eof || st.shut_rd {
            r |= POLLIN;
        }
        if st.rx_eof || st.shut_rd {
            r |= POLLRDHUP;
        }
        // Not for one free byte, as the kernel doesn't either. A send that will
        // fail doesn't block, so it counts as writable.
        if st.tx.len() < LIMIT / 3 * 2 || st.dead || st.shut_wr {
            r |= POLLOUT;
        }
        if st.dead || (st.rx_eof && st.shut_wr) {
            r |= POLLHUP;
        }
        r
    }

    /// The guest's shutdown(2): SHUT_RD 0, SHUT_WR 1, SHUT_RDWR 2.
    pub fn shutdown(self: &Arc<Self>, how: u64) {
        let mut st = self.st.lock().unwrap();
        if how != 1 {
            st.shut_rd = true;
            st.rx.clear();
        }
        if how != 0 {
            st.shut_wr = true;
        }
        drop(st);
        self.pumps.notify_all();
        self.changed();
    }

    /// The guest's last close: what is queued goes out, then the connection closes.
    pub fn close(self: &Arc<Self>) {
        self.st.lock().unwrap().closed = true;
        self.pumps.notify_all();
    }

    /// Starts moving bytes over `stream`.
    pub fn attach(self: &Arc<Self>, stream: TcpStream) -> std::io::Result<()> {
        let stream = Arc::new(stream);
        let (io, s) = (self.clone(), stream.clone());
        std::thread::Builder::new().name("hostio-read".into()).spawn(move || io.pump_in(&s))?;
        let io = self.clone();
        std::thread::Builder::new().name("hostio-write".into()).spawn(move || io.pump_out(&stream))?;
        Ok(())
    }

    fn pump_in(self: &Arc<Self>, stream: &TcpStream) {
        let mut buf = vec![0; CHUNK];
        loop {
            {
                let mut st = self.st.lock().unwrap();
                while st.rx.len() >= LIMIT && !st.closed && !st.shut_rd {
                    st = self.pumps.wait(st).unwrap();
                }
                if st.closed {
                    return;
                }
            }
            match (&mut &*stream).read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    let mut st = self.st.lock().unwrap();
                    if !st.shut_rd {
                        st.rx.extend(&buf[..n]);
                    }
                    drop(st);
                    self.changed();
                }
            }
        }
        self.st.lock().unwrap().rx_eof = true;
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
                        let _ = stream.shutdown(Shutdown::Both); // wakes the other pump
                        return;
                    }
                    drop(st);
                    let _ = stream.shutdown(Shutdown::Write);
                    sent_fin = true;
                    continue;
                }
                let n = st.tx.len().min(CHUNK);
                st.tx.drain(..n).collect()
            };
            if (&mut &*stream).write_all(&chunk).is_err() {
                let mut st = self.st.lock().unwrap();
                st.dead = true;
                st.rx_eof = true;
                st.tx.clear();
                drop(st);
                self.changed();
                return;
            }
            self.changed(); // there may be room again
        }
    }
}

//! Unix98 pseudo-terminals: each open of /dev/ptmx (char 5:2) makes a
//! master, whose slave is /dev/pts/<n> (char 136:n). Bytes pass straight
//! through except for the slave's output processing (OPOST|ONLCR turns "\n"
//! into "\r\n", as every default termios does); there is no canonical-mode
//! line editing, echo or job-control signals yet.

use super::wait::EVENTS;
use super::{ERESTARTSYS, Thread};
use crate::errno::*;
use crate::vfs::Vfs;
use std::collections::{BTreeMap, VecDeque};
use std::sync::{Arc, Condvar, LazyLock, Mutex, Weak};

pub const PTMX: u64 = 0x502;
const PTS_MAJOR: u64 = 136;
const MAX_PTYS: u32 = 4096;
/// Bytes a direction holds before writers block (Linux's N_TTY_BUF_SIZE).
const BUF: usize = 4096;

const TCGETS: u64 = 0x5401;
const TCSETS: u64 = 0x5402;
const TCSETSW: u64 = 0x5403;
const TCSETSF: u64 = 0x5404;
const TCSBRK: u64 = 0x5409;
const TCXONC: u64 = 0x540a;
const TCFLSH: u64 = 0x540b;
const TIOCSCTTY: u64 = 0x540e;
const TIOCGPGRP: u64 = 0x540f;
const TIOCSPGRP: u64 = 0x5410;
const TIOCOUTQ: u64 = 0x5411;
const TIOCGWINSZ: u64 = 0x5413;
const TIOCSWINSZ: u64 = 0x5414;
const FIONREAD: u64 = 0x541b;
const TIOCNOTTY: u64 = 0x5422;
const TIOCGSID: u64 = 0x5429;
const TIOCGPTN: u64 = 0x8004_5430;
const TIOCSPTLCK: u64 = 0x4004_5431;
const TIOCGPTLCK: u64 = 0x8004_5439;
pub const TIOCGPTPEER: u64 = 0x5441;

const OPOST: u32 = 1;
const ONLCR: u32 = 4;
/// struct termios (asm-generic and x86_64 alike): four flag words, c_line, c_cc[19].
const TERMIOS: usize = 36;

/// The slave's initial termios: tty_std_termios with the pty driver's c_cflag.
fn slave_termios() -> [u8; TERMIOS] {
    termios(0o2400, 0o5, 0o277, 0o105073) // ICRNL|IXON; OPOST|ONLCR; B38400|CS8|CREAD; ISIG|ICANON|ECHO|ECHOE|ECHOK|ECHOCTL|ECHOKE|IEXTEN
}

/// The master's: raw.
fn master_termios() -> [u8; TERMIOS] {
    termios(0, 0, 0o277, 0)
}

fn termios(i: u32, o: u32, c: u32, l: u32) -> [u8; TERMIOS] {
    let mut t = [0u8; TERMIOS];
    for (k, v) in [i, o, c, l].iter().enumerate() {
        t[k * 4..k * 4 + 4].copy_from_slice(&v.to_le_bytes());
    }
    t[17..36].copy_from_slice(b"\x03\x1c\x7f\x15\x04\x00\x01\x00\x11\x13\x1a\x00\x12\x0f\x17\x16\x00\x00\x00");
    t
}

struct State {
    to_slave: VecDeque<u8>,
    to_master: VecDeque<u8>,
    slave_termios: [u8; TERMIOS],
    master_termios: [u8; TERMIOS],
    winsize: [u8; 8],
    locked: bool,
    master_open: bool,
    slaves: usize,
    /// A slave has been opened; once the last closes the master sees a hangup.
    slave_seen: bool,
    pgrp: i32,
    sid: i32,
}

pub struct Pty {
    pub index: u32,
    st: Mutex<State>,
    cv: Condvar,
}

static PTYS: LazyLock<Mutex<BTreeMap<u32, Weak<Pty>>>> = LazyLock::new(Mutex::default);

/// One side's open file description.
pub struct End {
    pub pty: Arc<Pty>,
    pub master: bool,
    /// The master unlinks /dev/pts/<n> when it goes.
    vfs: Option<Arc<Vfs>>,
}

impl Drop for End {
    fn drop(&mut self) {
        let mut st = self.pty.st.lock().unwrap();
        if self.master {
            st.master_open = false;
            drop(st);
            PTYS.lock().unwrap().remove(&self.pty.index);
            if let Some(vfs) = &self.vfs
                && let Ok(dir) = vfs.resolve("/", "/dev/pts", true)
            {
                let _ = vfs.unlink(&dir, &self.pty.index.to_string(), false);
            }
        } else {
            st.slaves -= 1;
            drop(st);
        }
        self.pty.cv.notify_all();
        EVENTS.bump_key(self.pty.key());
    }
}

pub fn is_slave(rdev: u64) -> bool {
    super::block::major(rdev) == PTS_MAJOR as u32
}

/// open("/dev/ptmx"): a new pair, its slave locked until TIOCSPTLCK(0).
pub fn open_master(vfs: Option<Arc<Vfs>>) -> Result<End, i64> {
    let mut ptys = PTYS.lock().unwrap();
    let index = (0..MAX_PTYS).find(|i| !ptys.contains_key(i)).ok_or(ENOSPC)?;
    let st = State {
        to_slave: VecDeque::new(),
        to_master: VecDeque::new(),
        slave_termios: slave_termios(),
        master_termios: master_termios(),
        winsize: [0; 8],
        locked: true,
        master_open: true,
        slaves: 0,
        slave_seen: false,
        pgrp: 0,
        sid: 0,
    };
    let pty = Arc::new(Pty { index, st: Mutex::new(st), cv: Condvar::new() });
    ptys.insert(index, Arc::downgrade(&pty));
    drop(ptys);
    if let Some(vfs) = &vfs
        && let Ok(dir) = vfs.resolve("/", "/dev/pts", true)
    {
        let rdev = (index as u64 & 0xff) | PTS_MAJOR << 8 | (index as u64 & !0xff) << 12;
        if let Ok(node) = vfs.create(&dir, &index.to_string(), 0o020620, rdev) {
            let _ = vfs.set_attr(&node, Some(0o620), None, None);
        }
    }
    Ok(End { pty, master: true, vfs })
}

/// open("/dev/pts/<n>"): EIO while its master is gone or the slave locked.
pub fn open_slave(rdev: u64) -> Result<End, i64> {
    let index = super::block::minor(rdev);
    let pty = PTYS.lock().unwrap().get(&index).and_then(Weak::upgrade).ok_or(EIO)?;
    slave_of(&pty)
}

fn slave_of(pty: &Arc<Pty>) -> Result<End, i64> {
    let mut st = pty.st.lock().unwrap();
    if st.locked || !st.master_open {
        return Err(EIO);
    }
    st.slaves += 1;
    st.slave_seen = true;
    drop(st);
    pty.cv.notify_all();
    EVENTS.bump_key(pty.key());
    Ok(End { pty: pty.clone(), master: false, vfs: None })
}

impl Pty {
    /// What both ends' readers and pollers watch in EVENTS.
    pub fn key(&self) -> usize {
        self as *const Pty as usize
    }
}

impl End {
    pub fn key(&self) -> usize {
        self.pty.key()
    }

    /// The slave of this master (TIOCGPTPEER).
    pub fn peer(&self) -> Result<End, i64> {
        if !self.master {
            return Err(ENOTTY);
        }
        slave_of(&self.pty)
    }

    pub fn rdev(&self) -> u64 {
        if self.master { PTMX } else { (self.pty.index as u64 & 0xff) | PTS_MAJOR << 8 | (self.pty.index as u64 & !0xff) << 12 }
    }

    pub fn read(&self, t: &Thread, max: usize, nonblock: bool) -> Result<Vec<u8>, i64> {
        let mut st = self.pty.st.lock().unwrap();
        loop {
            let hangup = if self.master { st.slave_seen && st.slaves == 0 } else { !st.master_open };
            let q = if self.master { &mut st.to_master } else { &mut st.to_slave };
            if !q.is_empty() {
                let out: Vec<u8> = q.drain(..max.min(q.len())).collect();
                drop(st);
                self.pty.cv.notify_all();
                EVENTS.bump_key(self.pty.key());
                return Ok(out);
            }
            if max == 0 {
                return Ok(Vec::new());
            }
            if hangup {
                return if self.master { Err(EIO) } else { Ok(Vec::new()) };
            }
            if nonblock {
                return Err(EAGAIN);
            }
            if t.interrupted() {
                return Err(ERESTARTSYS);
            }
            super::vcpus::blocking();
            st = t.sleep(&self.pty.cv, st, super::IDLE);
        }
    }

    pub fn write(&self, t: &Thread, data: &[u8], nonblock: bool) -> Result<usize, i64> {
        let mut st = self.pty.st.lock().unwrap();
        let oflag = u32::from_le_bytes(st.slave_termios[4..8].try_into().unwrap());
        let onlcr = !self.master && oflag & (OPOST | ONLCR) == OPOST | ONLCR;
        let mut done = 0;
        loop {
            if if self.master { st.slaves == 0 && st.slave_seen } else { !st.master_open } {
                return if done > 0 { Ok(done) } else { Err(EIO) };
            }
            let q = if self.master { &mut st.to_slave } else { &mut st.to_master };
            while done < data.len() && q.len() + 2 <= BUF {
                if onlcr && data[done] == b'\n' {
                    q.push_back(b'\r');
                }
                q.push_back(data[done]);
                done += 1;
            }
            if done > 0 {
                self.pty.cv.notify_all();
                EVENTS.bump_key(self.pty.key());
            }
            if done == data.len() {
                return Ok(done);
            }
            if nonblock {
                return if done > 0 { Ok(done) } else { Err(EAGAIN) };
            }
            if t.interrupted() {
                return if done > 0 { Ok(done) } else { Err(ERESTARTSYS) };
            }
            super::vcpus::blocking();
            st = t.sleep(&self.pty.cv, st, super::IDLE);
        }
    }

    /// poll(2) bits: POLLIN, POLLOUT, POLLHUP.
    pub fn poll(&self) -> u16 {
        let st = self.pty.st.lock().unwrap();
        let (rx, tx, hangup) = if self.master {
            (&st.to_master, &st.to_slave, st.slave_seen && st.slaves == 0)
        } else {
            (&st.to_slave, &st.to_master, !st.master_open)
        };
        (if rx.is_empty() { 0 } else { 0x1 }) | (if tx.len() < BUF { 0x4 } else { 0 }) | if hangup { 0x10 } else { 0 }
    }

    /// The terminal ioctls (TIOCGPTPEER needs the fd table: files.rs).
    pub fn ioctl(&self, t: &Thread, cmd: u64, arg: u64) -> Result<i64, i64> {
        let mut mm = t.proc.mm();
        let mut st = self.pty.st.lock().unwrap();
        match cmd {
            TCGETS => {
                let tio = if self.master { st.master_termios } else { st.slave_termios };
                mm.write(arg, &tio)?;
            }
            TCSETS | TCSETSW | TCSETSF => {
                let v: [u8; TERMIOS] = mm.read_vec(arg, TERMIOS)?.try_into().unwrap();
                if self.master { st.master_termios = v } else { st.slave_termios = v }
                if cmd == TCSETSF {
                    st.to_slave.clear();
                }
            }
            TIOCGWINSZ => mm.write(arg, &st.winsize)?,
            TIOCSWINSZ => st.winsize = mm.read_vec(arg, 8)?.try_into().unwrap(),
            FIONREAD => {
                let n = if self.master { st.to_master.len() } else { st.to_slave.len() };
                mm.write(arg, &(n as u32).to_le_bytes())?;
            }
            TIOCOUTQ => mm.write(arg, &0u32.to_le_bytes())?,
            TCFLSH => match arg {
                0 => (if self.master { &mut st.to_master } else { &mut st.to_slave }).clear(),
                1 => (if self.master { &mut st.to_slave } else { &mut st.to_master }).clear(),
                2 => {
                    st.to_master.clear();
                    st.to_slave.clear();
                }
                _ => return Err(EINVAL),
            },
            TCSBRK | TCXONC => {}
            TIOCSCTTY => st.sid = t.proc.attrs.lock().unwrap().sid,
            TIOCNOTTY => {}
            TIOCGPGRP => mm.write(arg, &st.pgrp.to_le_bytes())?,
            TIOCSPGRP => st.pgrp = mm.read_u32(arg)? as i32,
            TIOCGSID if st.sid == 0 => return Err(ENOTTY),
            TIOCGSID => mm.write(arg, &st.sid.to_le_bytes())?,
            TIOCGPTN if self.master => mm.write(arg, &self.pty.index.to_le_bytes())?,
            TIOCSPTLCK if self.master => st.locked = mm.read_u32(arg)? != 0,
            TIOCGPTLCK if self.master => mm.write(arg, &(st.locked as u32).to_le_bytes())?,
            _ => return Err(ENOTTY),
        }
        // A flush makes room, for writers and pollers waiting for it.
        if matches!(cmd, TCSETSF | TCFLSH) {
            drop(st);
            self.pty.cv.notify_all();
            EVENTS.bump_key(self.pty.key());
        }
        Ok(0)
    }
}

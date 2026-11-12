//! /dev/fuse and the "fuse" filesystem type, as a stand-in for the emulated
//! shared-storage volume (/sdcard, /storage/emulated).
//!
//! On a device vold opens /dev/fuse, mounts it at /mnt/user/<user>/emulated with
//! `fd=N,rootmode=40000,allow_other,user_id=0,group_id=0` (no default_permissions,
//! so the kernel checks nothing there), bind-mounts the lower filesystem, /data/media,
//! at /mnt/pass_through/<user>/emulated, and hands the descriptor through
//! StorageManagerService to MediaProvider, whose FuseDaemon (libfuse) answers every
//! request from /data/media and decides per app what each may see and do.
//!
//! droidrt keeps the device's side of that but not the round trips: the mount is a
//! second view of /data/media's directory in /data's tmpfs, served by droidrt
//! directly, and the daemon only ever hears FUSE_INIT. That is enough for vold,
//! StorageManagerService and MediaProvider to believe the volume is up (the daemon's
//! session counts as started once it has answered FUSE_INIT), the files are /data's
//! (saved with it), and nothing waits on a guest process for every file operation.
//! What is lost is the daemon's say: scoped storage's per-app rules, MediaProvider
//! learning of files as they are written, and its redaction and transcoding.
//!
//! What a mount without default_permissions does is kept: the kernel refuses nothing
//! on the view (perm.rs checks by the type the mount shows, "fuse"), chmod and chown
//! succeed and change nothing (FuseDaemon ignores them), and what is created there
//! belongs to the daemon, as it would on the lower filesystem where the daemon makes
//! it, so MediaProvider can read it through /mnt/pass_through as on a device.

use super::{ERESTARTSYS, Thread};
use super::wait::EVENTS;
use crate::errno::*;
use crate::vfs::{Node, Vfs};
use std::collections::{HashSet, VecDeque};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

pub const FUSE_MINOR: u32 = 229;

pub fn rdev() -> u64 {
    super::block::makedev(super::block::MISC_MAJOR, FUSE_MINOR)
}

/// The directory the emulated volume's files live in (vold's internal path for it).
pub const LOWER: &str = "/data/media";

const FUSE_INIT: u32 = 26;
const IN_HEADER: usize = 40;
const OUT_HEADER: usize = 16;
/// fs/fuse's FUSE_MIN_READ_BUFFER: a read with less room is refused.
const MIN_READ: usize = 8192;
/// _IOR(229, 0, uint32_t): attach this descriptor to another's connection.
const FUSE_DEV_IOC_CLONE: u64 = 0x8004_e500;
/// fuse_notify_code: FUSE_NOTIFY_POLL up to FUSE_NOTIFY_RESEND.
const NOTIFY_CODES: std::ops::RangeInclusive<i32> = 1..=7;

/// Protocol 7.31, Linux 5.4's, whose FUSE_INIT has no flags2: none of the later
/// features (passthrough among them) is offered.
const MINOR: u32 = 31;
/// What Linux 5.4 offers in FUSE_INIT's flags. None of it changes what droidrt does,
/// since nothing after FUSE_INIT is ever asked; it is what libfuse expects to see.
const INIT_FLAGS: u32 = 1 | 1 << 1 | 1 << 3 | 1 << 4 | 1 << 5 | 1 << 6 | 1 << 7 | 1 << 8 | 1 << 9 | 1 << 10 | 1 << 11 | 1 << 12 | 1 << 13 | 1 << 14 | 1 << 15 | 1 << 16 | 1 << 17 | 1 << 18 | 1 << 19 | 1 << 20 | 1 << 21 | 1 << 22 | 1 << 23 | 1 << 24 | 1 << 25;

/// One fuse connection: what a mount and its daemon's descriptors share.
pub struct Conn {
    st: Mutex<ConnState>,
    /// /dev/fuse descriptions attached to it (Linux's dev_count): when the last
    /// goes, the daemon has gone.
    devs: AtomicUsize,
}

#[derive(Default)]
struct ConnState {
    /// Requests no daemon thread has read yet.
    pending: VecDeque<Vec<u8>>,
    /// Requests read and not yet answered, by `unique`.
    processing: HashSet<u64>,
    next_unique: u64,
    /// Unmounted, or every descriptor closed: readers get ENODEV.
    aborted: bool,
    /// The daemon's FUSE_INIT answer: (major, minor, flags).
    init: Option<(u32, u32, u32)>,
    /// fsuid and fsgid of the thread that took FUSE_INIT: what the daemon's files
    /// on the lower filesystem would belong to.
    daemon: Option<(u32, u32)>,
}

impl Conn {
    fn key(self: &Arc<Self>) -> usize {
        Arc::as_ptr(self) as usize
    }

    fn change(self: &Arc<Self>, f: impl FnOnce(&mut ConnState)) {
        f(&mut self.st.lock().unwrap());
        EVENTS.bump_key(self.key());
    }

    /// Queues a request; returns its `unique`.
    fn send(self: &Arc<Self>, opcode: u32, nodeid: u64, ids: (u32, u32, u32), body: &[u8]) -> u64 {
        let mut unique = 0;
        self.change(|st| {
            // As fs/fuse numbers them: steps of two, the low bit marking interrupts.
            st.next_unique += 2;
            unique = st.next_unique;
            let mut m = Vec::with_capacity(IN_HEADER + body.len());
            m.extend(((IN_HEADER + body.len()) as u32).to_le_bytes());
            m.extend(opcode.to_le_bytes());
            m.extend(unique.to_le_bytes());
            m.extend(nodeid.to_le_bytes());
            m.extend(ids.0.to_le_bytes());
            m.extend(ids.1.to_le_bytes());
            m.extend(ids.2.to_le_bytes());
            m.extend(0u32.to_le_bytes()); // total_extlen, padding
            m.extend(body);
            st.pending.push_back(m);
        });
        unique
    }

    fn abort(self: &Arc<Self>) {
        self.change(|st| {
            st.aborted = true;
            st.pending.clear();
            st.processing.clear();
        });
    }

    /// Who what is created on the mount belongs to, once a daemon has answered.
    pub fn daemon(&self) -> Option<(u32, u32)> {
        let st = self.st.lock().unwrap();
        st.init.and(st.daemon)
    }
}

/// What a mount of the connection keeps in its superblock: when the superblock goes
/// (the last mount of it in any namespace, and the last file open on it), the
/// connection is aborted and the daemon's readers see ENODEV, as after umount on Linux.
pub struct Mounted {
    pub conn: Arc<Conn>,
}

impl Drop for Mounted {
    fn drop(&mut self) {
        self.conn.abort();
    }
}

/// An open /dev/fuse: unattached until a mount or FUSE_DEV_IOC_CLONE gives it a
/// connection.
pub struct Dev {
    conn: Mutex<Option<Arc<Conn>>>,
}

impl Dev {
    pub fn new() -> Dev {
        Dev { conn: Mutex::new(None) }
    }

    fn conn(&self) -> Option<Arc<Conn>> {
        self.conn.lock().unwrap().clone()
    }

    fn attach(&self, conn: &Arc<Conn>) -> Result<(), i64> {
        let mut c = self.conn.lock().unwrap();
        if c.is_some() {
            return Err(EINVAL);
        }
        conn.devs.fetch_add(1, Ordering::Relaxed);
        *c = Some(conn.clone());
        Ok(())
    }

    /// The key a waiter watches: the connection's, once there is one.
    pub fn key(&self) -> Option<usize> {
        self.conn().map(|c| c.key())
    }

    /// fuse_dev_poll: always writable; readable with a request waiting; an error once
    /// aborted or before any mount.
    pub fn poll(&self) -> u16 {
        const POLLIN: u16 = 1;
        const POLLOUT: u16 = 4;
        const POLLERR: u16 = 8;
        let Some(c) = self.conn() else { return POLLERR };
        let st = c.st.lock().unwrap();
        if st.aborted {
            return POLLERR;
        }
        POLLOUT | if st.pending.is_empty() { 0 } else { POLLIN }
    }

    /// One whole request; EINVAL for a buffer smaller than fs/fuse accepts.
    pub fn read(&self, t: &Thread, count: usize, nonblock: bool) -> Result<Vec<u8>, i64> {
        let c = self.conn().ok_or(EPERM)?;
        if count < MIN_READ {
            return Err(EINVAL);
        }
        loop {
            let seen = EVENTS.watch_key(c.key());
            {
                let mut st = c.st.lock().unwrap();
                if st.aborted {
                    return Err(ENODEV);
                }
                if let Some(m) = st.pending.pop_front() {
                    let unique = u64::from_le_bytes(m[8..16].try_into().unwrap());
                    let opcode = u32::from_le_bytes(m[4..8].try_into().unwrap());
                    st.processing.insert(unique);
                    if opcode == FUSE_INIT {
                        let cr = t.proc.creds.lock().unwrap();
                        st.daemon = Some((cr.fsuid, cr.fsgid));
                    }
                    return Ok(m);
                }
            }
            if nonblock {
                return Err(EAGAIN);
            }
            if t.interrupted() {
                return Err(ERESTARTSYS);
            }
            super::vcpus::blocking();
            EVENTS.wait(seen, super::IDLE);
        }
    }

    /// An answer (fuse_out_header, then the reply) or, with `unique` 0, a notification.
    pub fn write(&self, data: &[u8]) -> Result<usize, i64> {
        let c = self.conn().ok_or(EPERM)?;
        if data.len() < OUT_HEADER {
            return Err(EINVAL);
        }
        let len = u32::from_le_bytes(data[0..4].try_into().unwrap()) as usize;
        let error = i32::from_le_bytes(data[4..8].try_into().unwrap());
        let unique = u64::from_le_bytes(data[8..16].try_into().unwrap());
        if len != data.len() {
            return Err(EINVAL);
        }
        if unique == 0 {
            // Cache invalidations and the like: droidrt caches nothing for the daemon.
            return if NOTIFY_CODES.contains(&error) { Ok(len) } else { Err(EINVAL) };
        }
        if error > 0 || error <= -512 {
            return Err(EINVAL);
        }
        let mut st = c.st.lock().unwrap();
        if st.aborted {
            return Err(ENOENT);
        }
        if !st.processing.remove(&unique) {
            return Err(ENOENT);
        }
        // Only FUSE_INIT is ever sent, so this is its answer.
        let body = &data[OUT_HEADER..];
        if error == 0 && body.len() >= 8 {
            let major = u32::from_le_bytes(body[0..4].try_into().unwrap());
            let minor = u32::from_le_bytes(body[4..8].try_into().unwrap());
            let flags = if body.len() >= 16 { u32::from_le_bytes(body[12..16].try_into().unwrap()) } else { 0 };
            if major == 7 {
                st.init = Some((major, minor.min(MINOR), flags));
                return Ok(len);
            }
        }
        // A refused or malformed FUSE_INIT: Linux fails the connection.
        eprintln!("[droidrt] fuse: the daemon refused FUSE_INIT (error {error}, {} bytes)", body.len());
        drop(st);
        c.abort();
        Ok(len)
    }

    pub fn ioctl(&self, cmd: u64, other: Option<&Dev>) -> Result<i64, i64> {
        match cmd {
            FUSE_DEV_IOC_CLONE => {
                let conn = other.ok_or(EINVAL)?.conn().ok_or(EINVAL)?;
                self.attach(&conn)?;
                Ok(0)
            }
            _ => Err(ENOTTY),
        }
    }
}

impl Drop for Dev {
    fn drop(&mut self) {
        if let Some(c) = self.conn.get_mut().unwrap().take()
            && c.devs.fetch_sub(1, Ordering::Relaxed) == 1
        {
            c.abort();
        }
    }
}

impl Mounted {
    pub fn new() -> Arc<Mounted> {
        Arc::new(Mounted { conn: Arc::new(Conn { st: Mutex::new(ConnState::default()), devs: AtomicUsize::new(0) }) })
    }

    /// Once the mount is in place: `dev` (mount's fd=) joins the connection and the
    /// daemon's first request, FUSE_INIT, waits for it, from the mounting thread's
    /// fsuid, fsgid and pid as Linux sends it.
    pub fn start(&self, dev: &Dev, ids: (u32, u32, u32)) -> Result<(), i64> {
        dev.attach(&self.conn)?;
        let mut body = Vec::with_capacity(16);
        body.extend(7u32.to_le_bytes());
        body.extend(MINOR.to_le_bytes());
        body.extend((128u32 << 10).to_le_bytes()); // max_readahead
        body.extend(INIT_FLAGS.to_le_bytes());
        self.conn.send(FUSE_INIT, 0, ids, &body);
        Ok(())
    }
}

impl Dev {
    /// Whether a mount or a clone has already given it a connection.
    pub fn attached(&self) -> bool {
        self.conn.lock().unwrap().is_some()
    }
}

/// The connection behind the fuse mount `node` is on, if it is one.
pub fn conn_of(node: &Node) -> Option<Arc<Conn>> {
    node.mount().sb.private.as_ref()?.downcast_ref::<Mounted>().map(|m| m.conn.clone())
}

/// Whether `node` is on a fuse mount, where chmod and chown change nothing.
pub fn is_fuse(vfs: &Vfs, node: &Node) -> bool {
    vfs.fs_type(node) == "fuse"
}

//! The binder driver (/dev/binder, /dev/hwbinder, /dev/vndbinder), protocol
//! version 8: BINDER_WRITE_READ with transactions, replies, one-way calls,
//! object translation (binders, handles, fds, fd arrays, scatter-gather
//! buffers), the context manager, death notifications, and the looper
//! protocol.
//!
//! All binder state sits behind one lock (as Linux's binder once did);
//! blocking waits release it. Lock order: binder → address spaces → fd
//! tables. Simplification: references are never dropped, so nodes get
//! BR_INCREFS/BR_ACQUIRE once and are never released.

use super::files::{File, Kind};
use super::wait::EVENTS;
use super::{Kernel, POLL, Process, Thread};
use crate::errno::*;
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::sync::{Arc, Mutex, Weak};

// ioctls (_IOC(dir, 'b', nr, size)).
const BINDER_WRITE_READ: u64 = 0xc030_6201;
const BINDER_SET_IDLE_TIMEOUT: u64 = 0x4008_6203;
const BINDER_SET_MAX_THREADS: u64 = 0x4004_6205;
const BINDER_SET_IDLE_PRIORITY: u64 = 0x4004_6206;
const BINDER_SET_CONTEXT_MGR: u64 = 0x4004_6207;
const BINDER_THREAD_EXIT: u64 = 0x4004_6208;
const BINDER_VERSION: u64 = 0xc004_6209;
const BINDER_GET_NODE_INFO_FOR_REF: u64 = 0xc018_620c;
const BINDER_SET_CONTEXT_MGR_EXT: u64 = 0x4018_620d;
const BINDER_FREEZE: u64 = 0x400c_620e;
const BINDER_ENABLE_ONEWAY_SPAM_DETECTION: u64 = 0x4004_6210;
const BINDER_GET_EXTENDED_ERROR: u64 = 0xc00c_6211;

// Commands from user space.
const BC_TRANSACTION: u32 = 0x4040_6300;
const BC_REPLY: u32 = 0x4040_6301;
const BC_FREE_BUFFER: u32 = 0x4008_6303;
const BC_INCREFS: u32 = 0x4004_6304;
const BC_ACQUIRE: u32 = 0x4004_6305;
const BC_RELEASE: u32 = 0x4004_6306;
const BC_DECREFS: u32 = 0x4004_6307;
const BC_INCREFS_DONE: u32 = 0x4010_6308;
const BC_ACQUIRE_DONE: u32 = 0x4010_6309;
const BC_REGISTER_LOOPER: u32 = 0x630b;
const BC_ENTER_LOOPER: u32 = 0x630c;
const BC_EXIT_LOOPER: u32 = 0x630d;
const BC_REQUEST_DEATH_NOTIFICATION: u32 = 0x400c_630e;
const BC_CLEAR_DEATH_NOTIFICATION: u32 = 0x400c_630f;
const BC_DEAD_BINDER_DONE: u32 = 0x4008_6310;
const BC_TRANSACTION_SG: u32 = 0x4048_6311;
const BC_REPLY_SG: u32 = 0x4048_6312;

// Returns to user space.
const BR_TRANSACTION_SEC_CTX: u32 = 0x8048_7202;
const BR_TRANSACTION: u32 = 0x8040_7202;
const BR_REPLY: u32 = 0x8040_7203;
const BR_DEAD_REPLY: u32 = 0x7205;
const BR_TRANSACTION_COMPLETE: u32 = 0x7206;
const BR_INCREFS: u32 = 0x8010_7207;
const BR_ACQUIRE: u32 = 0x8010_7208;
const BR_NOOP: u32 = 0x720c;
const BR_SPAWN_LOOPER: u32 = 0x720d;
const BR_DEAD_BINDER: u32 = 0x8008_720f;
const BR_CLEAR_DEATH_NOTIFICATION_DONE: u32 = 0x8008_7210;
const BR_FAILED_REPLY: u32 = 0x7211;

// Object types (B_PACK_CHARS).
const TYPE_BINDER: u32 = 0x7362_2a85;
const TYPE_WEAK_BINDER: u32 = 0x7762_2a85;
const TYPE_HANDLE: u32 = 0x7368_2a85;
const TYPE_WEAK_HANDLE: u32 = 0x7768_2a85;
const TYPE_FD: u32 = 0x6664_2a85;
const TYPE_FDA: u32 = 0x6664_6185;
const TYPE_PTR: u32 = 0x7074_2a85;

const TF_ONE_WAY: u32 = 0x01;
const FLAT_BINDER_FLAG_TXN_SECURITY_CTX: u32 = 0x1000;
const BUFFER_FLAG_HAS_PARENT: u32 = 1;
const LOOPER_REGISTERED: u32 = 1;
const LOOPER_ENTERED: u32 = 2;
/// The security context servicemanager is handed with each call.
/// For a caller with no SELinux label yet.
const SECCTX_UNLABELED: &[u8] = b"u:r:kernel:s0\0";

/// /dev/binder, /dev/hwbinder, /dev/vndbinder (misc major 10).
pub const DEVICES: [(&str, u64); 3] = [("binder", 0xa36), ("hwbinder", 0xa37), ("vndbinder", 0xa38)];

type ProcId = u64;
type NodeId = u64;
type TxnId = u64;

enum Work {
    Txn(TxnId),
    Reply(TxnId),
    Complete,
    DeadReply,
    FailedReply,
    Acquire(NodeId),
    DeadBinder(u64),
    ClearDeathDone(u64),
}

struct Node {
    owner: ProcId,
    ptr: u64,
    cookie: u64,
    flags: u32,
    /// BR_INCREFS/BR_ACQUIRE sent to the owner.
    acquired: bool,
    async_busy: bool,
    async_todo: VecDeque<TxnId>,
    deaths: Vec<(ProcId, u64)>,
    dead: bool,
}

struct Ref {
    node: NodeId,
    strong: u32,
    weak: u32,
}

#[derive(Default)]
struct BThread {
    todo: VecDeque<Work>,
    /// Transactions this thread is in: incoming ones being handled, and the
    /// outgoing one it waits on (top).
    stack: Vec<TxnId>,
    looper: u32,
}

struct Txn {
    from: Option<(ProcId, i32)>,
    to: ProcId,
    node: Option<NodeId>,
    code: u32,
    flags: u32,
    /// 0 for one-way calls and replies, which have no one waiting.
    sender_pid: i32,
    sender_euid: u32,
    buffer: u64,
    data_size: u64,
    offsets_size: u64,
    secctx: u64,
    reply: bool,
}

struct BProc {
    ctx: usize,
    pid: i32,
    process: Weak<Process>,
    threads: HashMap<i32, BThread>,
    todo: VecDeque<Work>,
    refs: BTreeMap<u32, Ref>,
    node_refs: HashMap<NodeId, u32>,
    nodes: HashMap<u64, NodeId>,
    /// mmap'd receive area (user VA, size) and its allocations offset → (len, async node).
    area: Option<(u64, u64)>,
    allocs: BTreeMap<u64, (u64, Option<NodeId>)>,
    max_threads: u32,
    requested: u32,
    started: u32,
    dead: bool,
}

#[derive(Default)]
struct World {
    procs: HashMap<ProcId, BProc>,
    nodes: HashMap<NodeId, Node>,
    txns: HashMap<TxnId, Txn>,
    next: u64,
    mgr: [Option<NodeId>; 3],
}

static WORLD: Mutex<Option<World>> = Mutex::new(None);

fn world() -> std::sync::MutexGuard<'static, Option<World>> {
    let mut w = WORLD.lock().unwrap();
    w.get_or_insert_with(World::default);
    w
}

/// One open of a binder device (normally one per process).
pub struct BinderFile {
    id: ProcId,
}

impl Drop for BinderFile {
    /// The last reference can go anywhere, including under an address space or
    /// fd table lock. The binder lock is taken before those, never after, so
    /// the release happens on a thread of its own.
    fn drop(&mut self) {
        let id = self.id;
        let _ = std::thread::Builder::new().name("binder-release".into()).spawn(move || {
            let mut g = world();
            g.as_mut().unwrap().release(id);
            drop(g);
            EVENTS.bump();
        });
    }
}

pub fn open(t: &Thread, rdev: u64) -> Option<BinderFile> {
    let ctx = DEVICES.iter().position(|d| d.1 == rdev)?;
    let mut g = world();
    let w = g.as_mut().unwrap();
    w.next += 1;
    let id = w.next;
    w.procs.insert(
        id,
        BProc {
            ctx,
            pid: t.proc.pid,
            process: Arc::downgrade(&t.proc),
            threads: HashMap::new(),
            todo: VecDeque::new(),
            refs: BTreeMap::new(),
            node_refs: HashMap::new(),
            nodes: HashMap::new(),
            area: None,
            allocs: BTreeMap::new(),
            max_threads: 0,
            requested: 0,
            started: 0,
            dead: false,
        },
    );
    Some(BinderFile { id })
}

/// The receive area: called from mmap of the binder fd.
pub fn set_area(b: &BinderFile, start: u64, size: u64) -> Result<(), i64> {
    let mut g = world();
    let p = g.as_mut().unwrap().procs.get_mut(&b.id).ok_or(EBADF)?;
    if p.area.is_some() {
        return Err(EBUSY);
    }
    p.area = Some((start, size));
    Ok(())
}

pub fn readable(b: &BinderFile, tid: i32) -> bool {
    let g = world();
    let w = g.as_ref().unwrap();
    let Some(p) = w.procs.get(&b.id) else { return false };
    let th = p.threads.get(&tid);
    th.is_some_and(|t| !t.todo.is_empty()) || (th.is_none_or(|t| t.stack.is_empty()) && !p.todo.is_empty())
}

/// DROIDRT_BINDER_TRACE=1 logs every transaction.
fn tracing() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| std::env::var_os("DROIDRT_BINDER_TRACE").is_some())
}

fn align8(v: u64) -> u64 {
    (v + 7) & !7
}
fn u32_at(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes(b[o..o + 4].try_into().unwrap())
}
fn u64_at(b: &[u8], o: usize) -> u64 {
    u64::from_le_bytes(b[o..o + 8].try_into().unwrap())
}
fn put32(b: &mut Vec<u8>, v: u32) {
    b.extend_from_slice(&v.to_le_bytes());
}
fn put64(b: &mut Vec<u8>, v: u64) {
    b.extend_from_slice(&v.to_le_bytes());
}

/// A transaction as read from the sender, before translation.
struct Outgoing {
    reply: bool,
    target: u64,
    code: u32,
    flags: u32,
    data: Vec<u8>,
    offsets: Vec<u64>,
    /// BINDER_TYPE_PTR buffers, by object offset: their contents.
    sg: HashMap<u64, Vec<u8>>,
    sg_size: u64,
}

impl World {
    fn id(&mut self) -> u64 {
        self.next += 1;
        self.next
    }

    fn thread(&mut self, p: ProcId, tid: i32) -> &mut BThread {
        self.procs.get_mut(&p).unwrap().threads.entry(tid).or_default()
    }

    /// The node for `ptr` in process `p`, created on first use.
    fn node_for(&mut self, p: ProcId, ptr: u64, cookie: u64, flags: u32) -> NodeId {
        if let Some(&n) = self.procs[&p].nodes.get(&ptr) {
            return n;
        }
        let n = self.id();
        self.nodes.insert(n, Node { owner: p, ptr, cookie, flags, acquired: false, async_busy: false, async_todo: VecDeque::new(), deaths: Vec::new(), dead: false });
        self.procs.get_mut(&p).unwrap().nodes.insert(ptr, n);
        n
    }

    /// The handle process `p` uses for `node`, created (and the owner told) on
    /// first use. When the owner's thread `by` is the one handing the object
    /// out, BR_INCREFS/BR_ACQUIRE go on that thread's own list, as Linux's
    /// binder_translate_binder does: it reads them before its transaction
    /// completes, while its Parcel still holds the object alive. Queued on the
    /// process, another thread could get them after the object is gone.
    fn handle_for(&mut self, p: ProcId, node: NodeId, strong: bool, by: Option<(ProcId, i32)>) -> u32 {
        let proc = self.procs.get_mut(&p).unwrap();
        let h = match proc.node_refs.get(&node) {
            Some(&h) => h,
            None => {
                let is_mgr = self.mgr[proc.ctx] == Some(node);
                let h = if is_mgr { 0 } else { proc.refs.keys().next_back().map_or(1, |&k| k + 1) };
                proc.refs.insert(h, Ref { node, strong: 0, weak: 0 });
                proc.node_refs.insert(node, h);
                h
            }
        };
        let r = self.procs.get_mut(&p).unwrap().refs.get_mut(&h).unwrap();
        if strong { r.strong += 1 } else { r.weak += 1 }
        let n = self.nodes.get_mut(&node).unwrap();
        if !n.acquired && !n.dead {
            n.acquired = true;
            let owner = n.owner;
            match by {
                Some((bp, tid)) if bp == owner => self.thread(owner, tid).todo.push_back(Work::Acquire(node)),
                _ => {
                    if let Some(op) = self.procs.get_mut(&owner) {
                        op.todo.push_back(Work::Acquire(node));
                    }
                }
            }
        }
        h
    }

    /// Carves space for `size` bytes out of `p`'s receive area.
    fn alloc(&mut self, p: ProcId, size: u64) -> Option<u64> {
        let proc = self.procs.get_mut(&p)?;
        let (start, total) = proc.area?;
        let size = align8(size.max(8));
        let mut cursor = 0;
        for (&off, &(len, _)) in &proc.allocs {
            if off - cursor >= size {
                break;
            }
            cursor = off + len;
        }
        if cursor + size > total {
            return None;
        }
        proc.allocs.insert(cursor, (size, None));
        Some(start + cursor)
    }

    fn free(&mut self, p: ProcId, addr: u64) -> Option<NodeId> {
        let proc = self.procs.get_mut(&p)?;
        let (start, _) = proc.area?;
        proc.allocs.remove(&addr.checked_sub(start)?)?.1
    }

    /// A process (its binder fd) went away: fail what waits on it, tell death
    /// watchers, forget its threads and work.
    fn release(&mut self, id: ProcId) {
        let Some(mut p) = self.procs.remove(&id) else { return };
        p.dead = true;
        let owned: Vec<NodeId> = p.nodes.values().copied().collect();
        for n in owned {
            let Some(node) = self.nodes.get_mut(&n) else { continue };
            node.dead = true;
            for (watcher, cookie) in std::mem::take(&mut node.deaths) {
                if let Some(w) = self.procs.get_mut(&watcher) {
                    w.todo.push_back(Work::DeadBinder(cookie));
                }
            }
            if self.mgr[p.ctx] == Some(n) {
                self.mgr[p.ctx] = None;
            }
        }
        // Callers blocked on this process get BR_DEAD_REPLY.
        let pending: Vec<TxnId> = self.txns.iter().filter(|(_, t)| t.to == id && !t.reply && t.flags & TF_ONE_WAY == 0).map(|(&k, _)| k).collect();
        let stacks: Vec<TxnId> = p.threads.values().flat_map(|t| t.stack.iter().copied()).collect();
        for t in pending.into_iter().chain(stacks) {
            if let Some(txn) = self.txns.remove(&t)
                && !txn.reply
                && let Some((fp, ft)) = txn.from
                && fp != id
                && let Some(c) = self.procs.get_mut(&fp)
            {
                let th = c.threads.entry(ft).or_default();
                th.stack.retain(|&x| x != t);
                th.todo.push_back(Work::DeadReply);
            }
        }
    }
}

impl Kernel {
    pub(super) fn binder_ioctl(&self, t: &Arc<Thread>, file: &File, b: &BinderFile, cmd: u64, arg: u64) -> Result<i64, i64> {
        match cmd {
            BINDER_VERSION => {
                t.proc.mm().write_u32(arg, 8)?;
                Ok(0)
            }
            BINDER_SET_MAX_THREADS => {
                let n = t.proc.mm().read_u32(arg)?;
                let mut g = world();
                g.as_mut().unwrap().procs.get_mut(&b.id).ok_or(EBADF)?.max_threads = n;
                Ok(0)
            }
            BINDER_SET_CONTEXT_MGR | BINDER_SET_CONTEXT_MGR_EXT => {
                let flags = if cmd == BINDER_SET_CONTEXT_MGR_EXT { t.proc.mm().read_u32(arg + 4)? } else { 0 };
                let mut g = world();
                let w = g.as_mut().unwrap();
                let ctx = w.procs.get(&b.id).ok_or(EBADF)?.ctx;
                if w.mgr[ctx].is_some_and(|n| w.nodes.get(&n).is_some_and(|n| !n.dead)) {
                    return Err(EBUSY);
                }
                let n = w.node_for(b.id, 0, 0, flags);
                // Like Linux, the context manager's node starts out referenced:
                // its owner is never sent BR_INCREFS/BR_ACQUIRE (ptr 0 has no
                // RefBase behind it to take them).
                w.nodes.get_mut(&n).unwrap().acquired = true;
                w.mgr[ctx] = Some(n);
                Ok(0)
            }
            BINDER_THREAD_EXIT => {
                let mut g = world();
                if let Some(p) = g.as_mut().unwrap().procs.get_mut(&b.id) {
                    p.threads.remove(&t.tid);
                }
                Ok(0)
            }
            BINDER_GET_NODE_INFO_FOR_REF => {
                let handle = t.proc.mm().read_u32(arg)?;
                let (strong, weak) = {
                    let g = world();
                    let w = g.as_ref().unwrap();
                    let r = w.procs.get(&b.id).and_then(|p| p.refs.get(&handle)).ok_or(EINVAL)?;
                    (r.strong.max(1), r.weak.max(1))
                };
                let mut mm = t.proc.mm();
                mm.write_u32(arg + 4, strong)?;
                mm.write_u32(arg + 8, weak)?;
                Ok(0)
            }
            BINDER_GET_EXTENDED_ERROR => {
                t.proc.mm().write(arg, &[0u8; 12])?;
                Ok(0)
            }
            BINDER_SET_IDLE_TIMEOUT | BINDER_SET_IDLE_PRIORITY | BINDER_ENABLE_ONEWAY_SPAM_DETECTION | BINDER_FREEZE => Ok(0),
            BINDER_WRITE_READ => self.binder_write_read(t, file, b, arg),
            _ => Err(EINVAL),
        }
    }

    fn binder_write_read(&self, t: &Arc<Thread>, file: &File, b: &BinderFile, arg: u64) -> Result<i64, i64> {
        let bwr = t.proc.mm().read_vec(arg, 48)?;
        let (wsize, wcons, wbuf) = (u64_at(&bwr, 0), u64_at(&bwr, 8), u64_at(&bwr, 16));
        let (rsize, rcons, rbuf) = (u64_at(&bwr, 24), u64_at(&bwr, 32), u64_at(&bwr, 40));

        let mut consumed = wcons;
        if wsize > wcons {
            let cmds = t.proc.mm().read_vec(wbuf + wcons, (wsize - wcons).min(1 << 20) as usize)?;
            let mut off = 0usize;
            while off + 4 <= cmds.len() {
                let cmd = u32_at(&cmds, off);
                let size = ((cmd >> 16) & 0x3fff) as usize;
                if off + 4 + size > cmds.len() {
                    break;
                }
                let args = &cmds[off + 4..off + 4 + size];
                self.binder_command(t, b, cmd, args)?;
                off += 4 + size;
                consumed = wcons + off as u64;
            }
            t.proc.mm().write_u64(arg + 8, consumed)?;
        }

        if rsize > rcons {
            let out = self.binder_read(t, file, b, (rsize - rcons) as usize, rcons == 0)?;
            t.proc.mm().write(rbuf + rcons, &out)?;
            t.proc.mm().write_u64(arg + 32, rcons + out.len() as u64)?;
        }
        Ok(0)
    }

    fn binder_command(&self, t: &Arc<Thread>, b: &BinderFile, cmd: u32, a: &[u8]) -> Result<(), i64> {
        match cmd {
            BC_TRANSACTION | BC_REPLY | BC_TRANSACTION_SG | BC_REPLY_SG => {
                let sg = cmd == BC_TRANSACTION_SG || cmd == BC_REPLY_SG;
                let out = self.read_outgoing(t, cmd == BC_REPLY || cmd == BC_REPLY_SG, a, sg)?;
                self.binder_transact(t, b, out);
            }
            BC_FREE_BUFFER => {
                let mut g = world();
                let w = g.as_mut().unwrap();
                if let Some(node) = w.free(b.id, u64_at(a, 0)) {
                    // An async transaction finished: start the node's next one.
                    let n = w.nodes.get_mut(&node).unwrap();
                    n.async_busy = false;
                    if let Some(next) = n.async_todo.pop_front() {
                        n.async_busy = true;
                        let owner = n.owner;
                        if let Some(p) = w.procs.get_mut(&owner) {
                            p.todo.push_back(Work::Txn(next));
                        }
                    }
                    drop(g);
                    EVENTS.bump();
                }
            }
            BC_INCREFS | BC_ACQUIRE | BC_RELEASE | BC_DECREFS => {
                let handle = u32_at(a, 0);
                let mut g = world();
                let w = g.as_mut().unwrap();
                let ctx = w.procs.get(&b.id).ok_or(EBADF)?.ctx;
                if handle == 0 && !w.procs[&b.id].refs.contains_key(&0) {
                    // First use of the context manager's handle.
                    let Some(mgr) = w.mgr[ctx] else { return Ok(()) };
                    w.handle_for(b.id, mgr, false, None);
                }
                if let Some(r) = w.procs.get_mut(&b.id).unwrap().refs.get_mut(&handle) {
                    match cmd {
                        BC_INCREFS => r.weak += 1,
                        BC_ACQUIRE => r.strong += 1,
                        BC_RELEASE => r.strong = r.strong.saturating_sub(1),
                        _ => r.weak = r.weak.saturating_sub(1),
                    }
                }
            }
            BC_INCREFS_DONE | BC_ACQUIRE_DONE | BC_DEAD_BINDER_DONE => {}
            BC_REGISTER_LOOPER | BC_ENTER_LOOPER | BC_EXIT_LOOPER => {
                let mut g = world();
                let w = g.as_mut().unwrap();
                let th = w.thread(b.id, t.tid);
                match cmd {
                    BC_REGISTER_LOOPER => th.looper |= LOOPER_REGISTERED,
                    BC_ENTER_LOOPER => th.looper |= LOOPER_ENTERED,
                    _ => th.looper = 0,
                }
                let p = w.procs.get_mut(&b.id).unwrap();
                if cmd == BC_REGISTER_LOOPER {
                    p.requested = p.requested.saturating_sub(1);
                    p.started += 1;
                }
            }
            BC_REQUEST_DEATH_NOTIFICATION | BC_CLEAR_DEATH_NOTIFICATION => {
                let (handle, cookie) = (u32_at(a, 0), u64_at(a, 4));
                let mut g = world();
                let w = g.as_mut().unwrap();
                let Some(node) = w.procs.get(&b.id).and_then(|p| p.refs.get(&handle)).map(|r| r.node) else { return Ok(()) };
                let n = w.nodes.get_mut(&node).unwrap();
                if cmd == BC_REQUEST_DEATH_NOTIFICATION {
                    if n.dead {
                        w.procs.get_mut(&b.id).unwrap().todo.push_back(Work::DeadBinder(cookie));
                    } else {
                        n.deaths.push((b.id, cookie));
                    }
                } else {
                    n.deaths.retain(|&(p, c)| !(p == b.id && c == cookie));
                    w.thread(b.id, t.tid).todo.push_back(Work::ClearDeathDone(cookie));
                }
                drop(g);
                EVENTS.bump();
            }
            _ => {
                eprintln!("[droidrt] binder: unsupported command {cmd:#x}");
                return Err(EINVAL);
            }
        }
        Ok(())
    }

    /// Reads a binder_transaction_data(_sg) and everything it points to.
    fn read_outgoing(&self, t: &Thread, reply: bool, a: &[u8], sg: bool) -> Result<Outgoing, i64> {
        let mut mm = t.proc.mm();
        let (target, code, flags) = (u64_at(a, 0), u32_at(a, 16), u32_at(a, 20));
        let (data_size, offsets_size) = (u64_at(a, 32), u64_at(a, 40));
        let (data_ptr, offsets_ptr) = (u64_at(a, 48), u64_at(a, 56));
        if data_size > 1 << 20 || offsets_size > 1 << 16 {
            return Err(EINVAL);
        }
        let data = mm.read_vec(data_ptr, data_size as usize)?;
        let raw = mm.read_vec(offsets_ptr, offsets_size as usize)?;
        let offsets: Vec<u64> = raw.chunks_exact(8).map(|c| u64::from_le_bytes(c.try_into().unwrap())).collect();
        let mut sgmap = HashMap::new();
        let mut sg_size = 0;
        if sg {
            for &o in &offsets {
                let o = o as usize;
                if o + 40 <= data.len() && u32_at(&data, o) == TYPE_PTR {
                    let (buf, len) = (u64_at(&data, o + 8), u64_at(&data, o + 16));
                    if len > 1 << 20 {
                        return Err(EINVAL);
                    }
                    sgmap.insert(o as u64, mm.read_vec(buf, len as usize)?);
                    sg_size += align8(len);
                }
            }
        }
        Ok(Outgoing { reply, target, code, flags, data, offsets, sg: sgmap, sg_size })
    }

    fn binder_transact(&self, t: &Arc<Thread>, b: &BinderFile, mut out: Outgoing) {
        let mut g = world();
        let w = g.as_mut().unwrap();
        let me = b.id;
        let ctx = w.procs[&me].ctx;

        // Where is it going?
        let (to, to_thread, node) = if out.reply {
            let Some(&txn) = w.thread(me, t.tid).stack.last() else {
                w.thread(me, t.tid).todo.push_back(Work::FailedReply);
                return;
            };
            // The top must be a call to this thread, not its own outgoing one.
            if w.txns.get(&txn).is_some_and(|x| x.from == Some((me, t.tid))) {
                w.thread(me, t.tid).todo.push_back(Work::FailedReply);
                return;
            }
            w.thread(me, t.tid).stack.pop();
            match w.txns.remove(&txn).and_then(|x| x.from) {
                Some((fp, ft)) if w.procs.contains_key(&fp) => (fp, Some(ft), None),
                _ => {
                    w.thread(me, t.tid).todo.push_back(Work::Complete); // the caller is gone
                    return;
                }
            }
        } else {
            let handle = out.target as u32;
            let node = if handle == 0 {
                w.mgr[ctx]
            } else {
                w.procs[&me].refs.get(&handle).map(|r| r.node)
            };
            let Some(node) = node.filter(|n| w.nodes.get(n).is_some_and(|n| !n.dead && w.procs.contains_key(&n.owner))) else {
                if tracing() {
                    eprintln!("[binder] pid {} call to handle {handle}: dead or unknown", t.proc.pid);
                }
                w.thread(me, t.tid).todo.push_back(Work::DeadReply);
                drop(g);
                EVENTS.bump();
                return;
            };
            let owner = w.nodes[&node].owner;
            // A call back into a process that is calling us goes to the
            // thread that is waiting in that call.
            let stack = w.thread(me, t.tid).stack.clone();
            let back = stack.iter().rev().find_map(|x| w.txns.get(x).and_then(|x| x.from).filter(|(fp, _)| *fp == owner).map(|(_, ft)| ft));
            (owner, back, Some(node))
        };

        // Room in the receiver's buffer: data, offsets, sg buffers, secctx.
        let want_secctx = node.is_some_and(|n| w.nodes[&n].flags & FLAT_BINDER_FLAG_TXN_SECURITY_CTX != 0);
        let caller_ctx = if want_secctx { super::selinux::context_bytes(t.proc.sec.current()) } else { None };
        let caller_ctx = caller_ctx.as_deref().unwrap_or(SECCTX_UNLABELED);
        let data_len = align8(out.data.len() as u64);
        let offs_len = align8(out.offsets.len() as u64 * 8);
        let total = data_len + offs_len + out.sg_size + if want_secctx { align8(caller_ctx.len() as u64) } else { 0 };
        let Some(buffer) = w.alloc(to, total) else {
            eprintln!("[droidrt] binder: no receive buffer space in pid {}", w.procs[&to].pid);
            w.thread(me, t.tid).todo.push_back(Work::FailedReply);
            // The caller is waiting for this reply: it fails too, rather than hang.
            if let (true, Some(ft)) = (out.reply, to_thread) {
                w.thread(to, ft).todo.push_back(Work::FailedReply);
            }
            drop(g);
            EVENTS.bump();
            return;
        };

        // Translate objects for the receiver.
        let mut sg_cursor = buffer + data_len + offs_len;
        let mut sg_addr: HashMap<u64, u64> = HashMap::new();
        let mut patches: Vec<(u64, u64)> = Vec::new(); // (VA in receiver, value): parent pointer fixups
        let receiver = w.procs[&to].process.upgrade();
        let mut fd_work: Vec<(usize, Arc<File>)> = Vec::new();
        let mut fda_work: Vec<(u64, u64, usize)> = Vec::new(); // (parent object offset, byte offset in parent, count)
        let offsets = out.offsets.clone();
        let mut failed = false;
        for &o in &offsets {
            let o = o as usize;
            if o + 8 > out.data.len() {
                failed = true;
                break;
            }
            match u32_at(&out.data, o) {
                ty @ (TYPE_BINDER | TYPE_WEAK_BINDER) if o + 24 <= out.data.len() => {
                    let (flags, ptr, cookie) = (u32_at(&out.data, o + 4), u64_at(&out.data, o + 8), u64_at(&out.data, o + 16));
                    let n = w.node_for(me, ptr, cookie, flags);
                    let h = w.handle_for(to, n, ty == TYPE_BINDER, Some((me, t.tid)));
                    out.data[o..o + 4].copy_from_slice(&(if ty == TYPE_BINDER { TYPE_HANDLE } else { TYPE_WEAK_HANDLE }).to_le_bytes());
                    out.data[o + 8..o + 16].copy_from_slice(&(h as u64).to_le_bytes());
                    out.data[o + 16..o + 24].fill(0);
                }
                ty @ (TYPE_HANDLE | TYPE_WEAK_HANDLE) if o + 24 <= out.data.len() => {
                    let handle = u32_at(&out.data, o + 8);
                    let n = if handle == 0 { w.mgr[ctx] } else { w.procs[&me].refs.get(&handle).map(|r| r.node) };
                    let Some(n) = n else {
                        failed = true;
                        break;
                    };
                    let node = &w.nodes[&n];
                    if node.owner == to {
                        // Back home: the receiver sees its own object.
                        let (ptr, cookie) = (node.ptr, node.cookie);
                        out.data[o..o + 4].copy_from_slice(&(if ty == TYPE_HANDLE { TYPE_BINDER } else { TYPE_WEAK_BINDER }).to_le_bytes());
                        out.data[o + 8..o + 16].copy_from_slice(&ptr.to_le_bytes());
                        out.data[o + 16..o + 24].copy_from_slice(&cookie.to_le_bytes());
                    } else {
                        let h = w.handle_for(to, n, ty == TYPE_HANDLE, None);
                        out.data[o + 8..o + 16].copy_from_slice(&(h as u64).to_le_bytes());
                    }
                }
                TYPE_FD if o + 24 <= out.data.len() => match t.files().get(u32_at(&out.data, o + 8) as i64) {
                    Ok(f) => fd_work.push((o + 8, f)),
                    Err(_) => {
                        failed = true;
                        break;
                    }
                },
                TYPE_PTR if o + 40 <= out.data.len() => {
                    let flags = u32_at(&out.data, o + 4);
                    let len = u64_at(&out.data, o + 16);
                    sg_addr.insert(o as u64, sg_cursor);
                    out.data[o + 8..o + 16].copy_from_slice(&sg_cursor.to_le_bytes());
                    if flags & BUFFER_FLAG_HAS_PARENT != 0 {
                        let (parent, parent_off) = (u64_at(&out.data, o + 24), u64_at(&out.data, o + 32));
                        match offsets.get(parent as usize).and_then(|po| sg_addr.get(po)) {
                            Some(&pa) => patches.push((pa + parent_off, sg_cursor)),
                            None => {
                                failed = true;
                                break;
                            }
                        }
                    }
                    sg_cursor += align8(len);
                }
                TYPE_FDA if o + 32 <= out.data.len() => {
                    let (n, parent, parent_off) = (u64_at(&out.data, o + 8), u64_at(&out.data, o + 16), u64_at(&out.data, o + 24));
                    match offsets.get(parent as usize) {
                        Some(&po) if out.sg.contains_key(&po) => fda_work.push((po, parent_off, n as usize)),
                        _ => {
                            failed = true;
                            break;
                        }
                    }
                }
                _ => {
                    failed = true;
                    break;
                }
            }
        }
        let receiver = match receiver {
            Some(r) if !failed => r,
            _ => {
                w.free(to, buffer);
                w.thread(me, t.tid).todo.push_back(Work::FailedReply);
                // The caller is waiting for this reply: it fails too, rather than hang.
                if let (true, Some(ft)) = (out.reply, to_thread) {
                    w.thread(to, ft).todo.push_back(Work::FailedReply);
                }
                drop(g);
                EVENTS.bump();
                return;
            }
        };
        // File descriptors land in the receiver's table. The sender's are looked
        // up first: a process may be sending to itself.
        let mut fda_files = Vec::new();
        {
            let senders = t.files();
            for &(po, off, n) in &fda_work {
                let buf = &out.sg[&po];
                for i in 0..n {
                    let at = off as usize + i * 4;
                    if at + 4 > buf.len() {
                        failed = true;
                        break;
                    }
                    match senders.get(u32_at(buf, at) as i64) {
                        Ok(f) => fda_files.push((po, at, f)),
                        Err(_) => failed = true,
                    }
                }
            }
        }
        {
            let mut files = receiver.files.lock().unwrap();
            for (at, f) in fd_work {
                match files.alloc(f, true, 0) {
                    Ok(fd) => out.data[at..at + 4].copy_from_slice(&(fd as u32).to_le_bytes()),
                    Err(_) => failed = true,
                }
            }
            for (po, at, f) in fda_files {
                match files.alloc(f, true, 0) {
                    Ok(fd) => out.sg.get_mut(&po).unwrap()[at..at + 4].copy_from_slice(&(fd as u32).to_le_bytes()),
                    Err(_) => failed = true,
                }
            }
        }
        // Copy everything into the receiver's (read-only to it) buffer.
        let secctx = if want_secctx { buffer + data_len + offs_len + out.sg_size } else { 0 };
        let copied = (|| -> Result<(), i64> {
            let mut mm = receiver.mm();
            mm.write_force(buffer, &out.data)?;
            let offs: Vec<u8> = out.offsets.iter().flat_map(|o| o.to_le_bytes()).collect();
            mm.write_force(buffer + data_len, &offs)?;
            for (o, bytes) in &out.sg {
                mm.write_force(sg_addr[o], bytes)?;
            }
            for (at, v) in &patches {
                mm.write_force(*at, &v.to_le_bytes())?;
            }
            if want_secctx {
                mm.write_force(secctx, caller_ctx)?;
            }
            Ok(())
        })();
        if copied.is_err() || failed {
            w.free(to, buffer);
            w.thread(me, t.tid).todo.push_back(Work::FailedReply);
            // The caller is waiting for this reply: it fails too, rather than hang.
            if let (true, Some(ft)) = (out.reply, to_thread) {
                w.thread(to, ft).todo.push_back(Work::FailedReply);
            }
            drop(g);
            EVENTS.bump();
            return;
        }

        let txn = w.id();
        let oneway = out.flags & TF_ONE_WAY != 0 && !out.reply;
        if tracing() {
            let kinds: Vec<String> = out
                .offsets
                .iter()
                .map(|&o| match u32_at(&out.data, o as usize) {
                    TYPE_BINDER => "binder".into(),
                    TYPE_WEAK_BINDER => "weak-binder".into(),
                    TYPE_HANDLE => format!("handle {}", u32_at(&out.data, o as usize + 8)),
                    TYPE_WEAK_HANDLE => "weak-handle".into(),
                    TYPE_FD => "fd".into(),
                    TYPE_FDA => "fd[]".into(),
                    TYPE_PTR => "ptr".into(),
                    t => format!("{t:#x}"),
                })
                .collect();
            eprintln!(
                "[binder] pid {} tid {} {} code={:#x} flags={:#x} -> pid {}{} data={} objs={:?}",
                t.proc.pid,
                t.tid,
                if out.reply { "REPLY" } else if oneway { "ONEWAY" } else { "CALL" },
                out.code,
                out.flags,
                w.procs[&to].pid,
                to_thread.map_or(String::new(), |th| format!(" tid {th}")),
                out.data.len(),
                kinds
            );
        }
        w.txns.insert(
            txn,
            Txn {
                from: (!out.reply && !oneway).then_some((me, t.tid)),
                to,
                node,
                code: out.code,
                flags: out.flags,
                sender_pid: if out.reply || oneway { 0 } else { t.proc.pid },
                sender_euid: t.proc.creds.lock().unwrap().euid,
                buffer,
                data_size: out.data.len() as u64,
                offsets_size: out.offsets.len() as u64 * 8,
                secctx,
                reply: out.reply,
            },
        );
        w.thread(me, t.tid).todo.push_back(Work::Complete);
        if out.reply {
            w.thread(to, to_thread.unwrap()).todo.push_back(Work::Reply(txn));
        } else if oneway {
            // One async call per node at a time; BC_FREE_BUFFER of this
            // buffer starts the next.
            let p = w.procs.get_mut(&to).unwrap();
            if let Some(a) = p.allocs.get_mut(&(buffer - p.area.unwrap().0)) {
                a.1 = node;
            }
            let n = w.nodes.get_mut(&node.unwrap()).unwrap();
            if n.async_busy {
                n.async_todo.push_back(txn);
            } else {
                n.async_busy = true;
                w.procs.get_mut(&to).unwrap().todo.push_back(Work::Txn(txn));
            }
        } else {
            w.thread(me, t.tid).stack.push(txn);
            match to_thread {
                Some(th) => w.thread(to, th).todo.push_back(Work::Txn(txn)),
                None => w.procs.get_mut(&to).unwrap().todo.push_back(Work::Txn(txn)),
            }
        }
        drop(g);
        EVENTS.bump();
    }

    /// Fills the read buffer, blocking until there is something to say.
    fn binder_read(&self, t: &Arc<Thread>, file: &File, b: &BinderFile, max: usize, at_start: bool) -> Result<Vec<u8>, i64> {
        let mut out = Vec::new();
        if at_start {
            put32(&mut out, BR_NOOP);
        }
        loop {
            let seen = EVENTS.current();
            {
                let mut g = world();
                let w = g.as_mut().unwrap();
                if !w.procs.contains_key(&b.id) {
                    return Err(EBADF);
                }
                let th = w.thread(b.id, t.tid);
                let looper = th.looper != 0;
                // As Linux's binder_available_for_proc_work_ilocked: a thread
                // still in a transaction, or with work of its own, takes nothing
                // for the process. Nested incoming calls would make its replies
                // pop the wrong transaction and reach the wrong callers.
                let idle = th.stack.is_empty() && th.todo.is_empty();
                while out.len() + 80 <= max {
                    let work = match w.thread(b.id, t.tid).todo.pop_front() {
                        Some(x) => x,
                        None if idle && (looper || w.procs[&b.id].threads.len() <= 1) => match w.procs.get_mut(&b.id).unwrap().todo.pop_front() {
                            Some(x) => x,
                            None => break,
                        },
                        None => break,
                    };
                    let stop = self.emit(w, b.id, t.tid, work, &mut out);
                    if stop {
                        break;
                    }
                }
                // Ask for another looper thread when none is free.
                let p = w.procs.get_mut(&b.id).unwrap();
                if !p.todo.is_empty() && p.requested == 0 && p.started < p.max_threads && out.len() + 4 <= max && looper {
                    p.requested += 1;
                    put32(&mut out, BR_SPAWN_LOOPER);
                }
            }
            if out.len() > if at_start { 4 } else { 0 } {
                return Ok(out);
            }
            if file.nonblock() {
                return if at_start { Ok(out) } else { Err(EAGAIN) };
            }
            if t.interrupted() {
                return Err(EINTR);
            }
            EVENTS.wait(seen, POLL);
        }
    }

    /// Writes one work item; returns true when the read should end here
    /// (after a transaction or reply, so the thread can act on it).
    fn emit(&self, w: &mut World, me: ProcId, tid: i32, work: Work, out: &mut Vec<u8>) -> bool {
        match work {
            Work::Complete => put32(out, BR_TRANSACTION_COMPLETE),
            Work::DeadReply => {
                // Whoever queued this already took the call off our stack.
                put32(out, BR_DEAD_REPLY);
                return true;
            }
            Work::FailedReply => {
                put32(out, BR_FAILED_REPLY);
                return true;
            }
            Work::Acquire(n) => {
                if let Some(node) = w.nodes.get(&n) {
                    for cmd in [BR_INCREFS, BR_ACQUIRE] {
                        put32(out, cmd);
                        put64(out, node.ptr);
                        put64(out, node.cookie);
                    }
                }
            }
            Work::DeadBinder(cookie) => {
                put32(out, BR_DEAD_BINDER);
                put64(out, cookie);
            }
            Work::ClearDeathDone(cookie) => {
                put32(out, BR_CLEAR_DEATH_NOTIFICATION_DONE);
                put64(out, cookie);
            }
            Work::Txn(id) | Work::Reply(id) => {
                let Some(x) = w.txns.get(&id) else { return false };
                let (ptr, cookie) = x.node.and_then(|n| w.nodes.get(&n)).map_or((0, 0), |n| (n.ptr, n.cookie));
                let reply = x.reply;
                let sec = !reply && x.secctx != 0;
                put32(out, if reply { BR_REPLY } else if sec { BR_TRANSACTION_SEC_CTX } else { BR_TRANSACTION });
                put64(out, if reply { 0 } else { ptr });
                put64(out, if reply { 0 } else { cookie });
                put32(out, x.code);
                put32(out, x.flags);
                put32(out, x.sender_pid as u32);
                put32(out, x.sender_euid);
                put64(out, x.data_size);
                put64(out, x.offsets_size);
                put64(out, x.buffer);
                put64(out, x.buffer + align8(x.data_size));
                if sec {
                    put64(out, x.secctx);
                }
                let (sync, oneway) = (x.from.is_some(), x.flags & TF_ONE_WAY != 0);
                if reply {
                    // The caller's wait is over.
                    w.txns.remove(&id);
                    let th = w.thread(me, tid);
                    th.stack.pop();
                } else if sync && !oneway {
                    w.thread(me, tid).stack.push(id); // answered by this thread's BC_REPLY
                } else {
                    w.txns.remove(&id);
                }
                return true;
            }
        }
        false
    }
}

/// Opens a binder device node for `t`'s process.
pub fn file_for(t: &Thread, rdev: u64) -> Option<Kind> {
    open(t, rdev).map(Kind::Binder)
}

/// A binder fd's receive area: mmap'd read-only, written by the driver.
pub fn mmap_area(file: &File) -> Option<&BinderFile> {
    match &file.kind {
        Kind::Binder(b) => Some(b),
        _ => None,
    }
}

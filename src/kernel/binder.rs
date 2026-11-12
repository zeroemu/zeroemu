//! The binder driver (/dev/binder, /dev/hwbinder, /dev/vndbinder), protocol
//! version 8: BINDER_WRITE_READ with transactions, replies, one-way calls,
//! object translation (binders, handles, fds, fd arrays, scatter-gather
//! buffers), the context manager, death notifications, and the looper
//! protocol.
//!
//! All binder state sits behind one lock (as Linux's binder once did);
//! blocking waits release it. Lock order: binder → address spaces → fd
//! tables.
//!
//! References follow Linux's driver. A node counts the references other
//! processes hold and those held locally: by buffers in flight, and by its owner
//! between BR_ACQUIRE and BC_ACQUIRE_DONE. The owner hears BR_INCREFS/BR_ACQUIRE
//! when the first appears and BR_RELEASE/BR_DECREFS when the last goes, which is
//! when its object can be destroyed. A receive buffer holds what its transaction
//! carried until BC_FREE_BUFFER, and a dying process lets go of everything.

use super::files::{File, Kind};
use super::wait::EVENTS;
use super::{Kernel, Process, Thread};
use crate::errno::*;
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::sync::{Arc, Condvar, Mutex, Weak};

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
const BR_RELEASE: u32 = 0x8010_7209;
const BR_DECREFS: u32 = 0x8010_720a;
const BR_NOOP: u32 = 0x720c;
const BR_SPAWN_LOOPER: u32 = 0x720d;
const BR_DEAD_BINDER: u32 = 0x8008_720f;
const BR_CLEAR_DEATH_NOTIFICATION_DONE: u32 = 0x8008_7210;
const BR_FAILED_REPLY: u32 = 0x7211;
/// mmap_area keeps receive areas to this size.
pub(super) const MAX_AREA: u64 = 4 << 20;

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
    /// Tell the owner what changed about this node.
    Node(NodeId),
    DeadBinder(u64),
    ClearDeathDone(u64),
}

/// What a receive buffer holds until it is freed.
enum Held {
    Ref { handle: u32, strong: bool },
    Node { node: NodeId, strong: bool },
}

/// One allocation in a process's receive area.
struct Alloc {
    size: u64,
    /// The node whose next one-way call starts when this is freed.
    async_node: Option<NodeId>,
    /// The node this transaction was sent to: held strong while it is in flight.
    target: Option<NodeId>,
    held: Vec<Held>,
    /// Descriptors from fd arrays. They live as long as the buffer.
    fda_fds: Vec<i32>,
}

struct Node {
    owner: ProcId,
    ptr: u64,
    cookie: u64,
    flags: u32,
    /// References from other processes: those with a strong count, and all.
    refs_strong: u32,
    refs: u32,
    /// Held by buffers, and by the owner until it acknowledges.
    local_strong: u32,
    local_weak: u32,
    /// What the owner has been told it holds.
    has_strong: bool,
    has_weak: bool,
    /// A Work::Node is on the process's list.
    queued: bool,
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
    /// Asleep in binder_read, waiting for `cv`.
    parked: bool,
    cv: Arc<Condvar>,
    /// The fd was closed: its next read returns to the guest with nothing.
    need_return: bool,
    todo: VecDeque<Work>,
    /// Transactions this thread is in: incoming ones being handled, and the
    /// outgoing one it waits on (top).
    stack: Vec<TxnId>,
    looper: u32,
    /// ZEROEMU_BINDER_RING=1: what's happened lately, for when a process aborts.
    ring: VecDeque<String>,
}

/// ZEROEMU_BINDER_RING=1: keeps each thread's last binder events, and prints them when
/// its process is killed by a signal. A thread given a reply it isn't waiting for has
/// aborted long after whatever went wrong.
fn ring_on() -> bool {
    static ON: std::sync::LazyLock<bool> = std::sync::LazyLock::new(|| std::env::var("ZEROEMU_BINDER_RING").as_deref() == Ok("1"));
    *ON
}

impl BThread {
    fn note(&mut self, event: std::fmt::Arguments) {
        if ring_on() {
            if self.ring.len() >= 64 {
                self.ring.pop_front();
            }
            self.ring.push_back(format!("{event} stack {:?} todo {}", self.stack, self.todo.len()));
        }
    }
}

/// Prints what the threads of process `pid` last did.
pub fn dump_rings(pid: i32) {
    if !ring_on() {
        return;
    }
    let mut g = world();
    let Some(w) = g.as_mut() else { return };
    for p in w.procs.values().filter(|p| p.pid == pid) {
        for (tid, th) in &p.threads {
            eprintln!("[binder-ring] tid {tid}: stack {:?}", th.stack);
            for event in &th.ring {
                eprintln!("[binder-ring]   {tid}: {event}");
            }
        }
    }
}

struct Txn {
    from: Option<(ProcId, i32)>,
    /// What the calling thread was itself answering, when it made this call.
    from_parent: Option<TxnId>,
    /// The caller's nice, which a sync call runs at if that's higher than the handler's.
    caller_nice: i32,
    /// The handler's own, while it handles this.
    saved_nice: i32,
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
    allocs: BTreeMap<u64, Alloc>,
    max_threads: u32,
    /// The opener's nice: what its idle threads go back to.
    default_nice: i32,
    requested: u32,
    started: u32,
    dead: bool,
    /// Somebody polled this binder fd, so new work must also wake pollers.
    polled: bool,
    /// Who opened the device: what its calls report, as Linux's proc->cred.
    euid: u32,
    sid: u32,
    /// BR_DEAD_BINDERs not yet acknowledged, by cookie; true once a clear asked for
    /// its DONE. That must wait: libbinder frees the proxy when it reads the DONE,
    /// and the obituary still names it.
    deaths_pending: HashMap<u64, bool>,
}

#[derive(Default)]
struct World {
    procs: HashMap<ProcId, BProc>,
    nodes: HashMap<NodeId, Node>,
    txns: HashMap<TxnId, Txn>,
    next: u64,
    mgr: [Option<NodeId>; 3],
}

/// Lock order: this lock, then address spaces and fd tables. A transaction copies
/// into the receiver and installs descriptors in its table with this held, so
/// nothing may hold either of those while taking it: poll_ready can take it, and
/// the last reference to a BinderFile can go away anywhere (see its Drop).
static WORLD: Mutex<Option<World>> = Mutex::new(None);

static WORLD_TAKER: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(0);

/// For the thread dump: who holds the binder lock, if anyone does.
pub(super) fn lock_taker() -> Option<i32> {
    WORLD.try_lock().is_err().then(|| WORLD_TAKER.load(std::sync::atomic::Ordering::Relaxed))
}

fn world() -> std::sync::MutexGuard<'static, Option<World>> {
    let mut w = WORLD.lock().unwrap();
    WORLD_TAKER.store(super::guest_tid(), std::sync::atomic::Ordering::Relaxed);
    w.get_or_insert_with(World::default);
    w
}

/// One open of a binder device (normally one per process).
pub struct BinderFile {
    pub(super) id: ProcId,
}

impl World {
    /// After queueing work for process `id`: wakes threads that can take it.
    /// A thread asleep in binder_read is woken by name; waking everything on
    /// EVENTS would stampede every binder thread in the system per transaction.
    fn wake(&mut self, id: ProcId) {
        let Some(p) = self.procs.get_mut(&id) else { return };
        let single = p.threads.len() <= 1;
        let mut process_work = p.todo.len();
        for th in p.threads.values_mut().filter(|th| th.parked) {
            let takes_process_work = process_work > 0 && th.stack.is_empty() && (th.looper != 0 || single);
            if th.todo.is_empty() && !takes_process_work {
                continue;
            }
            if th.todo.is_empty() {
                process_work -= 1;
            }
            th.parked = false;
            th.cv.notify_one();
        }
        if p.polled {
            EVENTS.bump_key(poll_key(id));
        }
    }
}

impl Drop for BinderFile {
    /// The last reference can go anywhere, including under an address space or
    /// fd table lock. The binder lock is taken before those, never after, so
    /// the release happens on a thread of its own.
    fn drop(&mut self) {
        let id = self.id;
        let _ = std::thread::Builder::new().name("binder-release".into()).spawn(move || {
            let mut g = world();
            let w = g.as_mut().unwrap();
            w.release(id);
            // Callers and death watchers anywhere may have new work.
            let ids: Vec<ProcId> = w.procs.keys().copied().collect();
            for p in ids {
                w.wake(p);
            }
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
            default_nice: t.nice(),
            requested: 0,
            started: 0,
            dead: false,
            polled: false,
            euid: t.proc.creds.lock().unwrap().euid,
            sid: t.proc.sec.current(),
            deaths_pending: HashMap::new(),
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

/// close() of a binder fd, as Linux's binder_flush: threads in a read go back to
/// the guest, where they find the fd gone. bootanimation ends this way, its render
/// thread closing the driver under a main thread asleep in joinThreadPool.
pub fn flush(b: &BinderFile) {
    let mut g = world();
    let Some(p) = g.as_mut().unwrap().procs.get_mut(&b.id) else { return };
    for th in p.threads.values_mut() {
        th.need_return = true;
        if th.parked {
            th.parked = false;
            th.cv.notify_one();
        }
    }
}

/// What a poller of this binder fd watches.
pub fn poll_key(id: ProcId) -> usize {
    (id as usize) << 6
}

pub fn readable(b: &BinderFile, tid: i32) -> bool {
    let mut g = world();
    let w = g.as_mut().unwrap();
    let Some(p) = w.procs.get_mut(&b.id) else { return false };
    p.polled = true;
    let th = p.threads.get(&tid);
    th.is_some_and(|t| !t.todo.is_empty()) || (th.is_none_or(|t| t.stack.is_empty()) && !p.todo.is_empty())
}

/// ZEROEMU_BINDER_TRACE=1 logs every transaction.
fn tracing() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| std::env::var_os("ZEROEMU_BINDER_TRACE").is_some())
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
    /// More than any receive area holds: fails like a full one.
    too_big: bool,
}

impl World {
    fn id(&mut self) -> u64 {
        self.next += 1;
        self.next
    }

    fn thread(&mut self, p: ProcId, tid: i32) -> &mut BThread {
        self.procs.get_mut(&p).unwrap().threads.entry(tid).or_default()
    }

    /// A transaction from `me` could not go through. As in Linux, if it was a reply
    /// then that is the caller's failure: the replier has done all it can.
    fn transaction_failed(&mut self, me: ProcId, tid: i32, answering: Option<TxnId>, to: ProcId, to_thread: Option<i32>) {
        match (answering, to_thread) {
            (Some(call), Some(caller)) => {
                self.thread(me, tid).todo.push_back(Work::Complete);
                let th = self.thread(to, caller);
                th.note(format_args!("failed reply queued: answer to {call} couldn't be delivered"));
                th.stack.retain(|&x| x != call);
                th.todo.push_back(Work::FailedReply);
            }
            _ => {
                let th = self.thread(me, tid);
                th.note(format_args!("failed reply queued: couldn't send"));
                th.todo.push_back(Work::FailedReply);
            }
        }
        self.wake(to);
    }

    /// As binder_send_failed_reply: `call` will never be answered. Its caller is told,
    /// or if it has gone too, whoever called it, up the chain.
    ///
    /// Every caller of this is sure the call is on top of its caller's stack, or that
    /// there is no caller. A call lower down can't be failed yet: the thread is answering a
    /// callback above it, and BR_DEAD_REPLY would end whichever wait it is in now, whose
    /// own reply would then reach a thread waiting for nothing. libbinder takes that
    /// as fatal.
    fn send_dead_reply(&mut self, mut call: TxnId) {
        while let Some(txn) = self.txns.remove(&call) {
            if let Some((p, tid)) = txn.from
                && let Some(th) = self.procs.get_mut(&p).and_then(|x| x.threads.get_mut(&tid))
            {
                th.note(format_args!("dead reply queued for {call}"));
                th.stack.retain(|&x| x != call);
                th.todo.push_back(Work::DeadReply);
                self.wake(p);
                return;
            }
            let Some(next) = txn.from_parent else { return };
            call = next;
        }
    }

    /// As binder_thread_release, for a thread that has already left its process: its own
    /// calls have no one to answer, the call it was handling fails now, and what it
    /// never read fails too. Calls below an outgoing one on its stack wait for that
    /// one's reply to find no one here, and walk up from it.
    fn release_thread(&mut self, id: ProcId, tid: i32, th: BThread) {
        let me = Some((id, tid));
        let top = th.stack.last().copied().filter(|c| self.txns.get(c).is_some_and(|x| x.from != me));
        for c in &th.stack {
            if let Some(x) = self.txns.get_mut(c)
                && x.from == me
            {
                x.from = None;
                x.sender_pid = 0;
            }
        }
        if let Some(call) = top {
            self.send_dead_reply(call);
        }
        self.release_work(th.todo);
    }

    /// As binder_release_work: what was queued for a thread or process that is gone.
    fn release_work(&mut self, todo: VecDeque<Work>) {
        for w in todo {
            match w {
                Work::Txn(c) => {
                    if self.txns.get(&c).is_some_and(|x| x.flags & TF_ONE_WAY == 0) {
                        self.send_dead_reply(c);
                    } else {
                        self.txns.remove(&c);
                    }
                }
                Work::Reply(r) => {
                    self.txns.remove(&r);
                }
                _ => {}
            }
        }
    }

    /// The node for `ptr` in process `p`, created on first use.
    fn node_for(&mut self, p: ProcId, ptr: u64, cookie: u64, flags: u32) -> NodeId {
        if let Some(&n) = self.procs[&p].nodes.get(&ptr) {
            return n;
        }
        let n = self.id();
        self.nodes.insert(
            n,
            Node {
                owner: p,
                ptr,
                cookie,
                flags,
                refs_strong: 0,
                refs: 0,
                local_strong: 0,
                local_weak: 0,
                has_strong: false,
                has_weak: false,
                queued: false,
                async_busy: false,
                async_todo: VecDeque::new(),
                deaths: Vec::new(),
                dead: false,
            },
        );
        self.procs.get_mut(&p).unwrap().nodes.insert(ptr, n);
        n
    }

    /// Process `p`'s handle for `node`, created on first use with no counts.
    fn ref_for(&mut self, p: ProcId, node: NodeId) -> u32 {
        let proc = self.procs.get_mut(&p).unwrap();
        if let Some(&h) = proc.node_refs.get(&node) {
            return h;
        }
        let is_mgr = self.mgr[proc.ctx] == Some(node);
        let h = if is_mgr { 0 } else { proc.refs.keys().next_back().map_or(1, |&k| (k + 1).max(1)) };
        proc.refs.insert(h, Ref { node, strong: 0, weak: 0 });
        proc.node_refs.insert(node, h);
        self.nodes.get_mut(&node).unwrap().refs += 1;
        h
    }

    /// A counted handle for `node` in process `p`, if it can have one (see inc_node).
    /// When the owner's thread `by` is the one handing the object out,
    /// BR_INCREFS/BR_ACQUIRE go on that thread's own list, as Linux's
    /// binder_translate_binder does: it reads them before its transaction completes,
    /// while its Parcel still holds the object alive. Queued on the process, another
    /// thread could get them after the object is gone.
    fn handle_for(&mut self, p: ProcId, node: NodeId, strong: bool, by: Option<(ProcId, i32)>) -> Option<u32> {
        let h = self.ref_for(p, node);
        if self.inc_ref(p, h, strong, by) {
            return Some(h);
        }
        // A reference this call just made, with nothing counted on it, goes again.
        let proc = self.procs.get_mut(&p).unwrap();
        if proc.refs.get(&h).is_some_and(|r| r.strong == 0 && r.weak == 0) {
            proc.refs.remove(&h);
            proc.node_refs.remove(&node);
            self.drop_ref(p, node);
        }
        None
    }

    fn inc_ref(&mut self, p: ProcId, handle: u32, strong: bool, by: Option<(ProcId, i32)>) -> bool {
        let Some(r) = self.procs.get_mut(&p).and_then(|proc| proc.refs.get_mut(&handle)) else { return false };
        let node = r.node;
        let first = if strong { r.strong == 0 } else { r.weak == 0 };
        if first && !self.inc_node(node, strong, true, by) {
            return false;
        }
        let r = self.procs.get_mut(&p).unwrap().refs.get_mut(&handle).unwrap();
        if strong {
            r.strong += 1;
        } else {
            r.weak += 1;
        }
        true
    }

    /// binder_dec_ref: the last count on a handle gives it up.
    fn dec_ref(&mut self, p: ProcId, handle: u32, strong: bool) {
        let Some(proc) = self.procs.get_mut(&p) else { return };
        let Some(r) = proc.refs.get_mut(&handle) else { return };
        let node = r.node;
        let count = if strong { &mut r.strong } else { &mut r.weak };
        if *count == 0 {
            return;
        }
        *count -= 1;
        let (now, gone) = (*count, r.strong == 0 && r.weak == 0);
        if gone {
            proc.refs.remove(&handle);
            proc.node_refs.remove(&node);
        }
        if strong && now == 0 {
            self.dec_node(node, true, true);
        }
        if gone {
            self.drop_ref(p, node);
        }
    }

    /// A reference of process `p` to `node` no longer exists.
    fn drop_ref(&mut self, p: ProcId, node: NodeId) {
        if let Some(n) = self.nodes.get_mut(&node) {
            n.refs = n.refs.saturating_sub(1);
            n.deaths.retain(|&(watcher, _)| watcher != p);
        }
        self.dec_node(node, false, true);
    }

    /// binder_inc_node. `internal`: for a reference in another process, which `refs`
    /// already counts when weak. False if the reference may not be had: with nobody
    /// holding the object strongly and no owner's thread vouching for it, its owner
    /// may have destroyed it, and BR_ACQUIRE would touch freed memory. A handle held
    /// only weakly cannot become strong this way.
    fn inc_node(&mut self, node: NodeId, strong: bool, internal: bool, by: Option<(ProcId, i32)>) -> bool {
        let owner_ctx = self.nodes.get(&node).and_then(|n| self.procs.get(&n.owner)).map(|p| p.ctx);
        let is_mgr = owner_ctx.is_some_and(|ctx| self.mgr[ctx] == Some(node));
        let Some(n) = self.nodes.get_mut(&node) else { return false };
        if strong {
            if internal {
                if by.is_none() && n.refs_strong == 0 && !(is_mgr && n.has_strong) {
                    return false;
                }
                n.refs_strong += 1;
            } else {
                n.local_strong += 1;
            }
        } else if !internal {
            n.local_weak += 1;
        }
        let unannounced = if strong { !n.has_strong } else { !n.has_weak };
        if !unannounced || n.dead {
            return true;
        }
        let owner = n.owner;
        match by {
            Some((bp, tid)) if bp == owner => {
                n.queued = true;
                self.thread(owner, tid).todo.push_back(Work::Node(node));
                true
            }
            // Already on its way to the owner, or a strong reference with no thread
            // to tell: a local one, which only lasts as long as what holds it.
            _ if n.queued || strong => true,
            _ => false,
        }
    }

    /// binder_dec_node: when nothing of a kind is left, the owner hears of it; a
    /// node nobody holds and nobody has been told about is gone.
    fn dec_node(&mut self, node: NodeId, strong: bool, internal: bool) {
        let Some(n) = self.nodes.get_mut(&node) else { return };
        if strong {
            if internal {
                n.refs_strong = n.refs_strong.saturating_sub(1);
            } else {
                n.local_strong = n.local_strong.saturating_sub(1);
            }
            if n.local_strong > 0 || n.refs_strong > 0 {
                return;
            }
        } else {
            if !internal {
                n.local_weak = n.local_weak.saturating_sub(1);
            }
            if n.local_weak > 0 || n.refs > 0 {
                return;
            }
        }
        if !n.dead && (n.has_strong || n.has_weak) {
            self.queue_node(node);
        } else if n.refs == 0 && n.local_strong == 0 && n.local_weak == 0 {
            self.remove_node(node);
        }
    }

    /// Puts a node's news on its owner's list, once.
    fn queue_node(&mut self, node: NodeId) {
        let Some(n) = self.nodes.get_mut(&node) else { return };
        if n.queued {
            return;
        }
        n.queued = true;
        let owner = n.owner;
        if let Some(p) = self.procs.get_mut(&owner) {
            p.todo.push_back(Work::Node(node));
        }
        self.wake(owner);
    }

    fn remove_node(&mut self, node: NodeId) {
        let Some(n) = self.nodes.remove(&node) else { return };
        if let Some(p) = self.procs.get_mut(&n.owner)
            && p.nodes.get(&n.ptr) == Some(&node)
        {
            p.nodes.remove(&n.ptr);
        }
    }

    /// What a freed buffer held, or a failed transaction had taken.
    fn release_held(&mut self, p: ProcId, held: Vec<Held>) {
        for h in held {
            match h {
                Held::Ref { handle, strong } => self.dec_ref(p, handle, strong),
                Held::Node { node, strong } => self.dec_node(node, strong, false),
            }
        }
    }

    /// Carves space for `size` bytes out of `p`'s receive area.
    fn alloc(&mut self, p: ProcId, size: u64) -> Option<u64> {
        let proc = self.procs.get_mut(&p)?;
        let (start, total) = proc.area?;
        let size = align8(size.max(8));
        let mut cursor = 0;
        for (&off, a) in &proc.allocs {
            if off - cursor >= size {
                break;
            }
            cursor = off + a.size;
        }
        if cursor + size > total {
            return None;
        }
        proc.allocs.insert(cursor, Alloc { size, async_node: None, target: None, held: Vec::new(), fda_fds: Vec::new() });
        Some(start + cursor)
    }

    fn free(&mut self, p: ProcId, addr: u64) -> Option<Alloc> {
        let proc = self.procs.get_mut(&p)?;
        let (start, _) = proc.area?;
        proc.allocs.remove(&addr.checked_sub(start)?)
    }

    /// A process (its binder fd) went away: fail what waits on it, tell death
    /// watchers, forget its threads and work.
    fn release(&mut self, id: ProcId) {
        let Some(mut p) = self.procs.remove(&id) else { return };
        p.dead = true;
        for th in p.threads.values() {
            th.cv.notify_all(); // they wake to find the process gone
        }
        let owned: Vec<NodeId> = p.nodes.values().copied().collect();
        for n in owned {
            let Some(node) = self.nodes.get_mut(&n) else { continue };
            node.dead = true;
            let unreferenced = node.refs == 0;
            for (watcher, cookie) in std::mem::take(&mut node.deaths) {
                if let Some(w) = self.procs.get_mut(&watcher) {
                    w.deaths_pending.insert(cookie, false);
                    w.todo.push_back(Work::DeadBinder(cookie));
                }
            }
            if self.mgr[p.ctx] == Some(n) {
                self.mgr[p.ctx] = None;
            }
            // Whatever it held locally went with it. Others' references keep the
            // node, dead, until they let go.
            if unreferenced {
                self.remove_node(n);
            }
        }
        // Everything it held of others: their owners can now destroy those objects.
        for r in p.refs.values() {
            if r.strong > 0 {
                self.dec_node(r.node, true, true);
            }
            self.drop_ref(id, r.node);
        }
        // Callers blocked on this process get BR_DEAD_REPLY, each in its turn. Its own
        // calls to live processes are still delivered, as only the receiver can free that
        // buffer; their replies will find no one here.
        for (tid, th) in std::mem::take(&mut p.threads) {
            self.release_thread(id, tid, th);
        }
        self.release_work(std::mem::take(&mut p.todo));
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
                let node = w.nodes.get_mut(&n).unwrap();
                (node.has_strong, node.has_weak, node.local_strong, node.local_weak) = (true, true, 1, 1);
                w.mgr[ctx] = Some(n);
                Ok(0)
            }
            BINDER_THREAD_EXIT => {
                let mut g = world();
                let w = g.as_mut().unwrap();
                if let Some(th) = w.procs.get_mut(&b.id).and_then(|p| p.threads.remove(&t.tid)) {
                    w.release_thread(b.id, t.tid, th);
                }
                Ok(0)
            }
            BINDER_GET_NODE_INFO_FOR_REF => {
                let handle = t.proc.mm().read_u32(arg)?;
                // The node's counts, not this reference's: servicemanager reads them
                // to tell a lazy service whether it has clients. If its own reference
                // were all it saw, the service would keep being told it has none and
                // shut down under the clients it has.
                let (strong, weak) = {
                    let g = world();
                    let w = g.as_ref().unwrap();
                    let r = w.procs.get(&b.id).and_then(|p| p.refs.get(&handle)).ok_or(EINVAL)?;
                    let n = w.nodes.get(&r.node).ok_or(EINVAL)?;
                    (n.local_strong + n.refs_strong, n.local_weak)
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
        if !ring_on() {
            return self.binder_write_read_inner(t, file, b, arg);
        }
        let bwr = t.proc.mm().read_vec(arg, 48)?;
        let note = |what: String| {
            if let Some(th) = world().as_mut().and_then(|w| w.procs.get_mut(&b.id)).and_then(|p| p.threads.get_mut(&t.tid)) {
                th.note(format_args!("{what}"));
            }
        };
        note(format!("ioctl in: write {} consumed {} read {} consumed {}", u64_at(&bwr, 0), u64_at(&bwr, 8), u64_at(&bwr, 24), u64_at(&bwr, 32)));
        let result = self.binder_write_read_inner(t, file, b, arg);
        let after = t.proc.mm().read_vec(arg, 48).unwrap_or_default();
        if after.len() == 48 {
            note(format!("ioctl out: {result:?}, wrote {} read {}", u64_at(&after, 8), u64_at(&after, 32)));
        }
        result
    }

    fn binder_write_read_inner(&self, t: &Arc<Thread>, file: &File, b: &BinderFile, arg: u64) -> Result<i64, i64> {
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
                if let Err(e) = self.binder_command(t, b, cmd, args) {
                    if ring_on() {
                        if let Some(th) = world().as_mut().and_then(|w| w.procs.get_mut(&b.id)).and_then(|p| p.threads.get_mut(&t.tid)) {
                            th.note(format_args!("command {cmd:#x} failed: {e}"));
                        }
                    }
                    return Err(e);
                }
                off += 4 + size;
                consumed = wcons + off as u64;
            }
            t.proc.mm().write_u64(arg + 8, consumed)?;
        }

        if rsize > rcons {
            let out = match self.binder_read(t, file, b, (rsize - rcons) as usize, rcons == 0) {
                Ok(out) => out,
                Err(e) => {
                    if ring_on() && e != EINTR {
                        if let Some(th) = world().as_mut().and_then(|w| w.procs.get_mut(&b.id)).and_then(|p| p.threads.get_mut(&t.tid)) {
                            th.note(format_args!("read failed: {e}"));
                        }
                    }
                    return Err(e);
                }
            };
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
                if let Some(alloc) = w.free(b.id, u64_at(a, 0)) {
                    // An async transaction finished: start the node's next one.
                    if let Some(n) = alloc.async_node.and_then(|node| w.nodes.get_mut(&node)) {
                        n.async_busy = false;
                        if let Some(next) = n.async_todo.pop_front() {
                            n.async_busy = true;
                            let owner = n.owner;
                            if let Some(p) = w.procs.get_mut(&owner) {
                                p.todo.push_back(Work::Txn(next));
                            }
                            w.wake(owner);
                        }
                    }
                    w.release_held(b.id, alloc.held);
                    if let Some(target) = alloc.target {
                        w.dec_node(target, true, false);
                    }
                    drop(g);
                    let mut files = t.files();
                    for fd in alloc.fda_fds {
                        files.close(fd as i64);
                    }
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
                    w.ref_for(b.id, mgr);
                }
                match cmd {
                    BC_INCREFS => {
                        w.inc_ref(b.id, handle, false, None);
                    }
                    BC_ACQUIRE => {
                        w.inc_ref(b.id, handle, true, None);
                    }
                    BC_RELEASE => w.dec_ref(b.id, handle, true),
                    _ => w.dec_ref(b.id, handle, false),
                }
            }
            BC_INCREFS_DONE | BC_ACQUIRE_DONE => {
                // The owner has taken the reference it was told about, so the one
                // standing in for it until now can go.
                let ptr = u64_at(a, 0);
                let mut g = world();
                let w = g.as_mut().unwrap();
                if let Some(&n) = w.procs.get(&b.id).and_then(|p| p.nodes.get(&ptr)) {
                    w.dec_node(n, cmd == BC_ACQUIRE_DONE, false);
                }
            }
            BC_DEAD_BINDER_DONE => {
                let cookie = u64_at(a, 0);
                let mut g = world();
                let w = g.as_mut().unwrap();
                let cleared = w.procs.get_mut(&b.id).and_then(|p| p.deaths_pending.remove(&cookie));
                if cleared == Some(true) {
                    w.thread(b.id, t.tid).todo.push_back(Work::ClearDeathDone(cookie));
                    w.wake(b.id);
                }
            }
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
                        let p = w.procs.get_mut(&b.id).unwrap();
                        p.deaths_pending.insert(cookie, false);
                        p.todo.push_back(Work::DeadBinder(cookie));
                    } else {
                        n.deaths.push((b.id, cookie));
                    }
                } else {
                    n.deaths.retain(|&(p, c)| !(p == b.id && c == cookie));
                    let p = w.procs.get_mut(&b.id).unwrap();
                    if let Some(clear) = p.deaths_pending.get_mut(&cookie) {
                        *clear = true;
                    } else {
                        // A thread outside the pool may never read again, and
                        // BINDER_THREAD_EXIT discards its list. libbinder holds a
                        // weak count on the proxy until this arrives.
                        match p.threads.get_mut(&t.tid) {
                            Some(th) if th.looper != 0 => th.todo.push_back(Work::ClearDeathDone(cookie)),
                            _ => p.todo.push_back(Work::ClearDeathDone(cookie)),
                        }
                    }
                }
                w.wake(b.id);
                drop(g);
            }
            _ => {
                if super::verbose() {
                    eprintln!("[zeroemu] binder: unsupported command {cmd:#x}");
                }
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
        let too_big = Outgoing { reply, target, code, flags, data: Vec::new(), offsets: Vec::new(), sg: HashMap::new(), sg_size: 0, too_big: true };
        if data_size > MAX_AREA || offsets_size > MAX_AREA {
            return Ok(too_big);
        }
        let data = mm.read_vec(data_ptr, data_size as usize)?;
        let raw = mm.read_vec(offsets_ptr, offsets_size as usize)?;
        let offsets: Vec<u64> = raw.chunks_exact(8).map(|c| u64::from_le_bytes(c.try_into().unwrap())).collect();
        let mut sgmap = HashMap::new();
        let mut sg_size = 0;
        if sg {
            for &o in &offsets {
                let o = o as usize;
                if o.saturating_add(40) <= data.len() && u32_at(&data, o) == TYPE_PTR && !sgmap.contains_key(&(o as u64)) {
                    let (buf, len) = (u64_at(&data, o + 8), u64_at(&data, o + 16));
                    // All of them together, before any is read: no receive area holds
                    // more, and each is this process's memory to hold meanwhile.
                    if len > MAX_AREA || sg_size + align8(len) > MAX_AREA {
                        return Ok(too_big);
                    }
                    sgmap.insert(o as u64, mm.read_vec(buf, len as usize)?);
                    sg_size += align8(len);
                }
            }
        }
        Ok(Outgoing { reply, target, code, flags, data, offsets, sg: sgmap, sg_size, too_big: false })
    }

    fn binder_transact(&self, t: &Arc<Thread>, b: &BinderFile, mut out: Outgoing) {
        let mut g = world();
        let w = g.as_mut().unwrap();
        let me = b.id;
        let ctx = w.procs[&me].ctx;

        // Where is it going?
        let mut answering: Option<TxnId> = None;
        let (to, to_thread, node) = if out.reply {
            let Some(&txn) = w.thread(me, t.tid).stack.last() else {
                w.thread(me, t.tid).note(format_args!("BC_REPLY with nothing to answer"));
                w.thread(me, t.tid).todo.push_back(Work::FailedReply);
                return;
            };
            // The top must be a call to this thread, not its own outgoing one.
            if w.txns.get(&txn).is_some_and(|x| x.from == Some((me, t.tid))) {
                w.thread(me, t.tid).note(format_args!("BC_REPLY with its own call {txn} on top"));
                w.thread(me, t.tid).todo.push_back(Work::FailedReply);
                return;
            }
            w.thread(me, t.tid).note(format_args!("BC_REPLY to {txn}"));
            w.thread(me, t.tid).stack.pop();
            answering = Some(txn);
            if let Some(x) = w.txns.get(&txn) {
                t.set_nice(x.saved_nice);
            }
            match w.txns.get(&txn).and_then(|x| x.from).filter(|(fp, _)| w.procs.contains_key(fp)) {
                Some((fp, ft)) => {
                    // Whoever waits for this has it on top of its stack, or something is
                    // badly wrong, and nothing good would come of answering it.
                    if w.procs[&fp].threads.get(&ft).and_then(|th| th.stack.last()) != Some(&txn) {
                        let waiting = w.procs[&fp].threads.get(&ft).map(|th| th.stack.clone());
                        w.thread(me, t.tid).note(format_args!("BC_REPLY to {txn}: caller {ft} isn't waiting for it: {waiting:?}"));
                        w.thread(me, t.tid).todo.push_back(Work::FailedReply);
                        return;
                    }
                    w.txns.remove(&txn);
                    (fp, Some(ft), None)
                }
                None => {
                    // The caller is gone. The replier is done, and whoever is waiting up
                    // the chain has been kept waiting only for this.
                    w.thread(me, t.tid).todo.push_back(Work::Complete);
                    w.send_dead_reply(txn);
                    return;
                }
            }
        } else {
            let handle = out.target as u32;
            // As Linux: only a strong reference can be called. Holding the target for
            // the call on the strength of a weak one could revive a node whose object
            // its owner has already destroyed, and BR_ACQUIRE would touch freed memory.
            let node = if handle == 0 {
                w.mgr[ctx]
            } else {
                w.procs[&me].refs.get(&handle).filter(|r| r.strong > 0).map(|r| r.node)
            };
            let Some(node) = node.filter(|n| w.nodes.get(n).is_some_and(|n| !n.dead && w.procs.contains_key(&n.owner))) else {
                if tracing() {
                    eprintln!("[binder] pid {} call to handle {handle}: dead or unknown", t.proc.pid);
                }
                w.thread(me, t.tid).note(format_args!("call to dead handle {handle}: dead reply queued"));
                w.thread(me, t.tid).todo.push_back(Work::DeadReply);
                drop(g);
                return;
            };
            let owner = w.nodes[&node].owner;
            let mut back = None;
            if out.flags & TF_ONE_WAY == 0 {
                // As Linux: a thread can only call when it is not already waiting
                // for an answer, and never into its own process.
                let top = w.thread(me, t.tid).stack.last().copied();
                if owner == me || top.and_then(|x| w.txns.get(&x)).is_some_and(|x| x.from == Some((me, t.tid))) {
                    w.thread(me, t.tid).note(format_args!("call refused: own process {}, code {}", owner == me, out.code));
                    w.thread(me, t.tid).todo.push_back(Work::FailedReply);
                    return;
                }
                // A call back into a process somewhere up the chain of calls that led
                // here goes to the thread waiting in that chain, which may hold locks
                // the call will need. The chain runs through other threads' stacks.
                let mut at = top;
                while let Some(x) = at.and_then(|c| w.txns.get(&c)) {
                    if let Some((fp, ft)) = x.from
                        && fp == owner
                    {
                        back = Some(ft);
                        break;
                    }
                    at = x.from_parent;
                }
            }
            (owner, back, Some(node))
        };

        // Room in the receiver's buffer: data, offsets, sg buffers, secctx.
        let want_secctx = node.is_some_and(|n| w.nodes[&n].flags & FLAT_BINDER_FLAG_TXN_SECURITY_CTX != 0);
        let caller_ctx = if want_secctx { super::selinux::context_bytes(w.procs[&me].sid) } else { None };
        let caller_ctx = caller_ctx.as_deref().unwrap_or(SECCTX_UNLABELED);
        let data_len = align8(out.data.len() as u64);
        let offs_len = align8(out.offsets.len() as u64 * 8);
        let total = data_len + offs_len + out.sg_size + if want_secctx { align8(caller_ctx.len() as u64) } else { 0 };
        let buffer = if out.too_big { None } else { w.alloc(to, total) };
        let Some(buffer) = buffer else {
            if super::verbose() {
                eprintln!("[zeroemu] binder: no receive buffer space in pid {}", w.procs[&to].pid);
            }
            w.transaction_failed(me, t.tid, answering, to, to_thread);
            drop(g);
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
        let mut held: Vec<Held> = Vec::new();
        // Where the next object may start: past the last one, as Linux requires. One
        // translated in place can't then rewrite the fields of another that overlaps
        // it, after the space for that one was counted.
        let mut floor = 0usize;
        for (index, &o) in offsets.iter().enumerate() {
            let o = o as usize;
            // Offsets come from the guest, and may be anything.
            if o.saturating_add(8) > out.data.len() || o < floor || !o.is_multiple_of(4) {
                failed = true;
                break;
            }
            floor = o + match u32_at(&out.data, o) {
                TYPE_PTR => 40,
                TYPE_FDA => 32,
                _ => 24,
            };
            match u32_at(&out.data, o) {
                ty @ (TYPE_BINDER | TYPE_WEAK_BINDER) if o + 24 <= out.data.len() => {
                    let (flags, ptr, cookie) = (u32_at(&out.data, o + 4), u64_at(&out.data, o + 8), u64_at(&out.data, o + 16));
                    let n = w.node_for(me, ptr, cookie, flags);
                    let Some(h) = w.handle_for(to, n, ty == TYPE_BINDER, Some((me, t.tid))) else {
                        failed = true;
                        break;
                    };
                    held.push(Held::Ref { handle: h, strong: ty == TYPE_BINDER });
                    out.data[o..o + 4].copy_from_slice(&(if ty == TYPE_BINDER { TYPE_HANDLE } else { TYPE_WEAK_HANDLE }).to_le_bytes());
                    out.data[o + 8..o + 16].copy_from_slice(&(h as u64).to_le_bytes());
                    out.data[o + 16..o + 24].fill(0);
                }
                ty @ (TYPE_HANDLE | TYPE_WEAK_HANDLE) if o + 24 <= out.data.len() => {
                    let handle = u32_at(&out.data, o + 8);
                    // A weak reference cannot be passed on as a strong one.
                    let n = if handle == 0 { w.mgr[ctx] } else { w.procs[&me].refs.get(&handle).filter(|r| ty == TYPE_WEAK_HANDLE || r.strong > 0).map(|r| r.node) };
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
                        w.inc_node(n, ty == TYPE_HANDLE, false, None);
                        held.push(Held::Node { node: n, strong: ty == TYPE_HANDLE });
                    } else {
                        let Some(h) = w.handle_for(to, n, ty == TYPE_HANDLE, None) else {
                            failed = true;
                            break;
                        };
                        out.data[o + 8..o + 16].copy_from_slice(&(h as u64).to_le_bytes());
                        held.push(Held::Ref { handle: h, strong: ty == TYPE_HANDLE });
                    }
                }
                TYPE_FD if o + 24 <= out.data.len() => match t.files().get(u32_at(&out.data, o + 8) as i64) {
                    Ok(f) => fd_work.push((o + 8, f)),
                    Err(_) => {
                        failed = true;
                        break;
                    }
                },
                // Only one whose buffer came with it (BC_TRANSACTION_SG): room was made
                // for those and for nothing else.
                TYPE_PTR if o + 40 <= out.data.len() && out.sg.contains_key(&(o as u64)) => {
                    let flags = u32_at(&out.data, o + 4);
                    let len = out.sg[&(o as u64)].len() as u64;
                    sg_addr.insert(o as u64, sg_cursor);
                    out.data[o + 8..o + 16].copy_from_slice(&sg_cursor.to_le_bytes());
                    if flags & BUFFER_FLAG_HAS_PARENT != 0 {
                        let (parent, parent_off) = (u64_at(&out.data, o + 24), u64_at(&out.data, o + 32));
                        // The pointer to this buffer goes into its parent's: an earlier
                        // buffer, and a place inside it (binder_fixup_parent). The sender
                        // names both, and what's written lands in the receiver's memory.
                        let parent = offsets.get(..index).and_then(|earlier| earlier.get(parent as usize)).and_then(|po| Some((*sg_addr.get(po)?, out.sg.get(po)?.len() as u64)));
                        match parent {
                            Some((pa, parent_len)) if parent_off.is_multiple_of(4) && parent_off.checked_add(8).is_some_and(|end| end <= parent_len) => patches.push((pa + parent_off, sg_cursor)),
                            _ => {
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
                w.release_held(to, held);
                w.transaction_failed(me, t.tid, answering, to, to_thread);
                drop(g);
                return;
            }
        };
        // File descriptors land in the receiver's table. The sender's are looked
        // up first: a process may be sending to itself.
        let mut fda_files = Vec::new();
        let mut fda_fds = Vec::new();
        {
            let senders = t.files();
            for &(po, off, n) in &fda_work {
                let buf = &out.sg[&po];
                for i in 0..n {
                    let at = (off as usize).saturating_add(i * 4);
                    if at.saturating_add(4) > buf.len() {
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
        // Descriptors put in the receiver's table, to take out again if this fails.
        let mut installed: Vec<i64> = Vec::new();
        if !failed {
            let mut files = receiver.files.lock().unwrap();
            for (at, f) in fd_work {
                match files.alloc(f, true, 0) {
                    Ok(fd) => {
                        out.data[at..at + 4].copy_from_slice(&(fd as u32).to_le_bytes());
                        installed.push(fd);
                    }
                    Err(_) => failed = true,
                }
            }
            for (po, at, f) in fda_files {
                match files.alloc(f, true, 0) {
                    Ok(fd) => {
                        out.sg.get_mut(&po).unwrap()[at..at + 4].copy_from_slice(&(fd as u32).to_le_bytes());
                        fda_fds.push(fd as i32);
                        installed.push(fd);
                    }
                    Err(_) => failed = true,
                }
            }
        }
        // Copy everything into the receiver's (read-only to it) buffer.
        let secctx = if want_secctx { buffer + data_len + offs_len + out.sg_size } else { 0 };
        let copied = (|| -> Result<(), i64> {
            // It may be on its way out: its address space goes before the release
            // of its binder fd has run.
            let mut guard = receiver.mm.lock().unwrap();
            let mm = guard.as_mut().ok_or(ESRCH)?;
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
            // The receiver never hears of them: they'd stay open in its table for good.
            {
                let mut files = receiver.files.lock().unwrap();
                for fd in installed {
                    files.close(fd);
                }
            }
            w.free(to, buffer);
            w.release_held(to, held);
            w.transaction_failed(me, t.tid, answering, to, to_thread);
            drop(g);
            return;
        }

        // From here the buffer holds what it carries, and the node it is for.
        if let Some(n) = node {
            w.inc_node(n, true, false, None);
        }
        if let Some(p) = w.procs.get_mut(&to)
            && let Some(area) = p.area
            && let Some(a) = p.allocs.get_mut(&(buffer - area.0))
        {
            a.held = held;
            a.target = node;
            a.fda_fds = fda_fds;
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
        let from_parent = if out.reply || oneway { None } else { w.thread(me, t.tid).stack.last().copied() };
        w.txns.insert(
            txn,
            Txn {
                from: (!out.reply && !oneway).then_some((me, t.tid)),
                from_parent,
                caller_nice: t.nice(),
                saved_nice: 0,
                node,
                code: out.code,
                flags: out.flags,
                sender_pid: if out.reply || oneway { 0 } else { t.proc.pid },
                sender_euid: w.procs[&me].euid,
                buffer,
                data_size: out.data.len() as u64,
                offsets_size: out.offsets.len() as u64 * 8,
                secctx,
                reply: out.reply,
            },
        );
        w.thread(me, t.tid).note(format_args!("sent {txn} to proc {to} thread {to_thread:?} code {} flags {:#x}: {}", out.code, out.flags, if out.reply { "reply" } else { "call" }));
        w.thread(me, t.tid).todo.push_back(Work::Complete);
        if out.reply {
            // The caller's wait is over from here, whenever it reads this.
            let caller = w.thread(to, to_thread.unwrap());
            caller.note(format_args!("reply {txn} queued, for {answering:?}"));
            caller.stack.retain(|&x| Some(x) != answering);
            caller.todo.push_back(Work::Reply(txn));
        } else if oneway {
            // One async call per node at a time; BC_FREE_BUFFER of this
            // buffer starts the next.
            let p = w.procs.get_mut(&to).unwrap();
            if let Some(a) = p.allocs.get_mut(&(buffer - p.area.unwrap().0)) {
                a.async_node = node;
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
        w.wake(to);
        drop(g);
    }

    /// Fills the read buffer, blocking until there is something to say.
    fn binder_read(&self, t: &Arc<Thread>, file: &File, b: &BinderFile, max: usize, at_start: bool) -> Result<Vec<u8>, i64> {
        let mut out = Vec::new();
        if at_start {
            put32(&mut out, BR_NOOP);
        }
        let mut yielded = false;
        let mut asked_for_looper = false;
        loop {
            let mut g = world();
            {
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
                // Waiting for the process's work, a thread is at the process's priority:
                // a one-way call leaves its mark, with no reply to put it back.
                if idle && looper {
                    t.set_nice(w.procs[&b.id].default_nice);
                }
                while out.len() + 80 <= max {
                    let work = match w.thread(b.id, t.tid).todo.pop_front() {
                        Some(x) => x,
                        None if idle && (looper || w.procs[&b.id].threads.len() <= 1) => match w.procs.get_mut(&b.id).unwrap().todo.pop_front() {
                            Some(x) => x,
                            None => break,
                        },
                        None => break,
                    };
                    let stop = self.emit(w, t, b.id, work, &mut out);
                    if stop {
                        break;
                    }
                }
                // Ask for another looper thread when none is free.
                let p = w.procs.get_mut(&b.id).unwrap();
                if !p.todo.is_empty() && p.requested == 0 && p.started < p.max_threads && out.len() + 4 <= max && looper {
                    p.requested += 1;
                    asked_for_looper = true;
                    // In place of the leading BR_NOOP, as Linux: first. What comes after
                    // a transaction waits until its handler next talks to the driver.
                    if at_start {
                        out[..4].copy_from_slice(&BR_SPAWN_LOOPER.to_le_bytes());
                    } else {
                        put32(&mut out, BR_SPAWN_LOOPER);
                    }
                    w.thread(b.id, t.tid).note(format_args!("read: spawn looper"));
                }
                // This thread took one piece of process work; another may take the rest.
                if !w.procs[&b.id].todo.is_empty() {
                    w.wake(b.id);
                }
            }
            if asked_for_looper || out.len() > if at_start { 4 } else { 0 } {
                return Ok(out);
            }
            let th = g.as_mut().unwrap().thread(b.id, t.tid);
            if std::mem::take(&mut th.need_return) {
                return Ok(out);
            }
            if file.nonblock() {
                return if at_start { Ok(out) } else { Err(EAGAIN) };
            }
            if t.interrupted() {
                return Err(EINTR);
            }
            // Give up the vCPU without the binder lock, then look once more.
            if !yielded {
                yielded = true;
                drop(g);
                super::vcpus::blocking();
                continue;
            }
            let th = g.as_mut().unwrap().thread(b.id, t.tid);
            th.parked = true;
            let cv = th.cv.clone();
            let mut g = t.sleep(&cv, g, super::IDLE);
            if let Some(th) = g.as_mut().unwrap().procs.get_mut(&b.id).and_then(|p| p.threads.get_mut(&t.tid)) {
                th.parked = false;
            }
            yielded = false; // others may be waiting for a vCPU by now
        }
    }

    /// Writes one work item; returns true when the read should end here
    /// (after a transaction or reply, so the thread can act on it).
    fn emit(&self, w: &mut World, t: &Thread, me: ProcId, work: Work, out: &mut Vec<u8>) -> bool {
        let tid = t.tid;
        match work {
            Work::Complete => {
                w.thread(me, tid).note(format_args!("read: complete"));
                put32(out, BR_TRANSACTION_COMPLETE);
            }
            Work::DeadReply => {
                // Whoever queued this already took the call off our stack.
                w.thread(me, tid).note(format_args!("read: dead reply"));
                put32(out, BR_DEAD_REPLY);
                return true;
            }
            Work::FailedReply => {
                w.thread(me, tid).note(format_args!("read: failed reply"));
                put32(out, BR_FAILED_REPLY);
                return true;
            }
            Work::Node(n) => {
                // As Linux's BINDER_WORK_NODE: say what changed since last time. A
                // reference announced is held locally until BC_*_DONE.
                let Some(node) = w.nodes.get_mut(&n) else { return false };
                node.queued = false;
                let strong = node.refs_strong > 0 || node.local_strong > 0;
                let weak = strong || node.refs > 0 || node.local_weak > 0;
                let (had_strong, had_weak, ptr, cookie) = (node.has_strong, node.has_weak, node.ptr, node.cookie);
                if weak && !had_weak {
                    node.local_weak += 1;
                }
                if strong && !had_strong {
                    // Telling an owner about an object it was told to let go of is only
                    // sound if it still has it, as when it sends it out again itself.
                    if had_weak && tracing() {
                        eprintln!("[binder] node {n} ptr {:#x} announced again: refs {} strong {} local {}", node.ptr, node.refs, node.refs_strong, node.local_strong);
                    }
                    node.local_strong += 1;
                }
                (node.has_strong, node.has_weak) = (strong, weak);
                if !weak {
                    w.remove_node(n);
                }
                let mut say = |cmd| {
                    put32(out, cmd);
                    put64(out, ptr);
                    put64(out, cookie);
                };
                if weak && !had_weak {
                    say(BR_INCREFS);
                }
                if strong && !had_strong {
                    say(BR_ACQUIRE);
                }
                if !strong && had_strong {
                    say(BR_RELEASE);
                }
                if !weak && had_weak {
                    say(BR_DECREFS);
                }
            }
            Work::DeadBinder(cookie) => {
                w.thread(me, tid).note(format_args!("read: dead binder {cookie:#x}"));
                put32(out, BR_DEAD_BINDER);
                put64(out, cookie);
                // Nothing after it in this read, as Linux: an obituary can cause calls,
                // and libbinder sends nothing while it has anything unread. It would take
                // a transaction read with this as nested in that call, with the call
                // still unsent, and send it and the reply together, in the wrong order.
                return true;
            }
            Work::ClearDeathDone(cookie) => {
                put32(out, BR_CLEAR_DEATH_NOTIFICATION_DONE);
                put64(out, cookie);
            }
            Work::Txn(id) | Work::Reply(id) => {
                if ring_on() {
                    let what = w.txns.get(&id).map(|x| (x.reply, x.code, x.flags, x.from));
                    w.thread(me, tid).note(format_args!("read: {id} (reply, code, flags, from) {what:?}"));
                }
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
                let oneway = x.flags & TF_ONE_WAY != 0;
                if reply {
                    w.txns.remove(&id);
                    return true;
                }
                // As Linux: a call runs at its caller's priority if that is higher, and
                // at least at what the object asks for. A UI thread waiting on a binder
                // thread would otherwise wait on whatever that thread happens to be.
                let (caller_nice, min) = (x.caller_nice, x.node.and_then(|n| w.nodes.get(&n)).map_or(0, |n| n.flags as u8 as i8 as i32));
                let saved = t.nice();
                if !oneway && caller_nice < min {
                    t.set_nice(caller_nice);
                } else if !oneway || saved > min {
                    t.set_nice(min);
                }
                if oneway {
                    w.txns.remove(&id);
                } else {
                    if let Some(x) = w.txns.get_mut(&id) {
                        x.saved_nice = saved;
                    }
                    w.thread(me, tid).stack.push(id); // answered by this thread's BC_REPLY
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

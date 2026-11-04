//! SELinux as libselinux sees it: selinuxfs (/sys/fs/selinux) generated from
//! the CIL policy the image ships, security contexts for processes, threads
//! and sockets, and the exec-time domain transitions. Nothing is enforced:
//! every access is allowed, so `enforce` is only reported back. Contexts are
//! interned as SIDs so threads and socket credentials carry plain integers.

mod policy;

use super::files::SpecialFile;
use super::{Kernel, Process, Thread};
use crate::errno::*;
use crate::phys::PhysMem;
use crate::tmpfs::MemFile;
use crate::vfs::{Dirent, FileSystem, Node, S_IFDIR, S_IFMT, Stat, Vfs};
use policy::Policy;
use std::collections::HashMap;
use std::io;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, LazyLock, Mutex, Weak};

/// Interned contexts; SID 0 means "none" (an unset exec/fscreate attribute).
#[derive(Default)]
struct Sids {
    contexts: Vec<Arc<str>>,
    ids: HashMap<Arc<str>, u32>,
}

static SIDS: LazyLock<Mutex<Sids>> = LazyLock::new(Default::default);

pub fn sid(ctx: &str) -> u32 {
    let mut t = SIDS.lock().unwrap();
    if let Some(&s) = t.ids.get(ctx) {
        return s;
    }
    let s: Arc<str> = ctx.into();
    t.contexts.push(s.clone());
    let n = t.contexts.len() as u32;
    t.ids.insert(s, n);
    n
}

pub fn context(sid: u32) -> Option<Arc<str>> {
    SIDS.lock().unwrap().contexts.get((sid as usize).checked_sub(1)?).cloned()
}

/// /proc/<pid>/attr files: current and prev are per process here (Linux
/// keeps them per thread but changes them for the whole process), the rest
/// per thread.
pub const ATTRS: [&str; 6] = ["current", "prev", "exec", "fscreate", "keycreate", "sockcreate"];
const EXEC: usize = 2;
const FSCREATE: usize = 3;
const SOCKCREATE: usize = 5;

/// A process's context, and the one it had before its last execve.
pub struct ProcSec {
    current: AtomicU32,
    prev: AtomicU32,
}

impl ProcSec {
    pub fn current(&self) -> u32 {
        self.current.load(Ordering::Relaxed)
    }
}

impl Clone for ProcSec {
    fn clone(&self) -> ProcSec {
        ProcSec { current: AtomicU32::new(self.current()), prev: AtomicU32::new(self.prev.load(Ordering::Relaxed)) }
    }
}

/// What a thread's next exec, files, keys and sockets get (exec, fscreate,
/// keycreate, sockcreate; 0 = the default).
#[derive(Default)]
pub struct ThreadSec([AtomicU32; 4]);

impl ThreadSec {
    /// clone and fork copy the creating thread's attributes, as Linux copies its cred.
    pub fn inherit(&self, from: &ThreadSec) {
        for (a, b) in self.0.iter().zip(&from.0) {
            a.store(b.load(Ordering::Relaxed), Ordering::Relaxed);
        }
    }
    fn get(&self, which: usize) -> u32 {
        self.0[which - EXEC].load(Ordering::Relaxed)
    }
}

/// The label of a file. Labels (security.selinux xattrs) belong to the VFS;
/// until it has them every file is system_file, so no execve changes domain
/// by itself (an exec context set by setexeccon still applies).
pub fn file_context(_vfs: &Vfs, _node: &Node) -> String {
    // With xattrs: vfs.getxattr(node, "security.selinux"), trailing NUL trimmed.
    "u:object_r:system_file:s0".into()
}

/// The label a socket created by `t` now gets: its sockcreate context, or its own.
pub fn socket_sid(t: &Thread) -> u32 {
    match t.sec.get(SOCKCREATE) {
        0 => t.proc.sec.current(),
        s => s,
    }
}

/// A context as the kernel hands it out (SO_PEERSEC, /proc attr files): NUL-terminated.
pub fn context_bytes(sid: u32) -> Option<Vec<u8>> {
    context(sid).map(|c| [c.as_bytes(), b"\0"].concat())
}

/// An attribute as /proc/<pid>/attr/<name> reads: NUL-terminated, or empty if unset.
pub fn attr(p: &Process, tid: i32, which: usize) -> Vec<u8> {
    let sid = match which {
        0 => p.sec.current(),
        1 => p.sec.prev.load(Ordering::Relaxed),
        _ => p.threads.lock().unwrap().iter().find(|t| t.tid == tid).map_or(0, |t| t.sec.get(which)),
    };
    context_bytes(sid).unwrap_or_default()
}

/// The kernel-side SELinux state; also the selinuxfs mounted at /sys/fs/selinux.
pub struct Selinux {
    kernel: Weak<Kernel>,
    /// Parsed on first use; dropped by a policy load so the next use re-reads it.
    policy: Mutex<Option<Arc<Policy>>>,
    enforcing: AtomicBool,
    /// struct selinux_kernel_status, mapped by libselinux's selinux_status_open.
    status: Arc<MemFile>,
    /// The status page's (sequence, policyload).
    seq: Mutex<(u32, u32)>,
    /// Booleans changed since the policy loaded: name -> (current, pending).
    bools: Mutex<HashMap<String, (bool, bool)>>,
    /// The first process's (current, prev): init's in --boot mode (it came
    /// from the kernel domain by first-stage init's exec), else a shell's.
    initial: (u32, u32),
}

// selinuxfs's fixed nodes as (name, parent directory, mode); inode = index + 2.
const ROOT: u64 = 1;
const FIXED: &[(&str, &str, u32)] = &[
    ("load", "", 0o100600),
    ("enforce", "", 0o100644),
    ("context", "", 0o100666),
    ("access", "", 0o100666),
    ("create", "", 0o100666),
    ("relabel", "", 0o100666),
    ("user", "", 0o100666),
    ("member", "", 0o100666),
    ("policyvers", "", 0o100444),
    ("commit_pending_bools", "", 0o100200),
    ("mls", "", 0o100444),
    ("disable", "", 0o100200),
    ("checkreqprot", "", 0o100644),
    ("reject_unknown", "", 0o100444),
    ("deny_unknown", "", 0o100444),
    ("status", "", 0o100444),
    ("validatetrans", "", 0o100200),
    ("null", "", 0o020666),
    ("avc", "", 0o040555),
    ("cache_threshold", "avc", 0o100644),
    ("hash_stats", "avc", 0o100444),
    ("cache_stats", "avc", 0o100444),
    ("class", "", 0o040555),
    ("booleans", "", 0o040555),
    ("initial_contexts", "", 0o040555),
    ("policy_capabilities", "", 0o040555),
];
/// Write-then-read files: the answer to a request is read back on the same fd.
const TRANSACTIONS: [&str; 6] = ["access", "create", "relabel", "user", "member", "context"];
/// Policy capabilities a 6.6 kernel knows (it lists them whether or not the policy sets them).
const KERNEL_CAPS: [&str; 9] = [
    "network_peer_controls", "open_perms", "extended_socket_class", "always_check_network", "cgroup_seclabel", "nnp_nosuid_transition",
    "genfs_seclabel_symlinks", "ioctl_skip_cloexec", "userspace_initial_context",
];

// Policy-generated nodes: a kind in the low byte, then two 16-bit indices.
const K_CLASS: u64 = 0x40;
const K_INDEX: u64 = 0x41;
const K_PERMS: u64 = 0x42;
const K_PERM: u64 = 0x43;
const K_BOOL: u64 = 0x44;
const K_INITCON: u64 = 0x45;
const K_CAP: u64 = 0x46;

fn ino(kind: u64, a: usize, b: usize) -> u64 {
    kind | (a as u64) << 8 | (b as u64) << 24
}

fn fixed(name: &str) -> u64 {
    FIXED.iter().position(|f| f.0 == name).unwrap() as u64 + 2
}

fn fixed_name(ino: u64) -> Option<&'static str> {
    FIXED.get((ino as usize).checked_sub(2)?).map(|f| f.0)
}

fn err(e: i64) -> io::Error {
    io_err(e)
}

/// Parses an integer the way the kernel's sscanf("%d") does: leading
/// whitespace, then digits; anything after is ignored.
fn int_arg(data: &[u8]) -> Result<i64, i64> {
    let s = String::from_utf8_lossy(data);
    let s = s.trim_start();
    let end = s.char_indices().find(|&(i, c)| !(c.is_ascii_digit() || i == 0 && (c == '-' || c == '+'))).map_or(s.len(), |(i, _)| i);
    s[..end].parse().map_err(|_| EINVAL)
}

/// An MLS level range in canonical form: "s0-s0" is "s0".
fn canonical_level(l: &str) -> Result<String, i64> {
    let (lo, hi) = l.split_once('-').unwrap_or((l, l));
    for part in [lo, hi] {
        let (sens, cats) = part.split_once(':').unwrap_or((part, ""));
        let number = |s: &str, prefix| s.strip_prefix(prefix).is_some_and(|n| n.parse::<u32>().is_ok());
        if !number(sens, 's') || !(cats.is_empty() || cats.split([',', '.']).all(|c| number(c, 'c'))) {
            return Err(EINVAL);
        }
    }
    Ok(if lo == hi { lo.to_string() } else { format!("{lo}-{hi}") })
}

/// Checks a context against the policy; returns its canonical form
/// (aliases resolved, "s0-s0" shortened). Without a policy only the shape
/// user:role:type:level is checked.
fn canonical(p: &Policy, ctx: &str) -> Result<String, i64> {
    let ctx = ctx.trim_end_matches('\0');
    let mut f = ctx.splitn(4, ':');
    let (Some(u), Some(r), Some(t), Some(l)) = (f.next(), f.next(), f.next(), f.next()) else { return Err(EINVAL) };
    if [u, r, t, l].iter().any(|s| s.is_empty() || s.contains(|c: char| c.is_whitespace() || c == '\0')) {
        return Err(EINVAL);
    }
    let level = canonical_level(l)?;
    if p.is_empty() {
        return Ok(format!("{u}:{r}:{t}:{level}"));
    }
    if !p.valid(u, r, t) {
        return Err(EINVAL);
    }
    Ok(format!("{u}:{r}:{}:{level}", p.type_name(t).unwrap_or(t)))
}

/// security_compute_create: the context of an object of `class` that `scon`
/// creates with `tcon` as its parent (or, for class process, of the domain
/// `scon` enters by executing a `tcon` file). As the kernel's
/// security_compute_sid with no default_* statements: processes and sockets
/// keep the creator's role, type and level unless a type transition applies;
/// other objects take object_r, the parent's type and the creator's low level.
fn compute_create(p: &Policy, scon: &str, tcon: &str, class: u16, name: Option<&str>) -> Result<String, i64> {
    let (s, t) = (canonical(p, scon)?, canonical(p, tcon)?);
    let s: Vec<&str> = s.splitn(4, ':').collect();
    let t: Vec<&str> = t.splitn(4, ':').collect();
    let cname = p.class(class).map_or("", |c| c.name.as_str());
    let subject = cname == "process" || cname.ends_with("socket");
    let (role, ty, level) = if subject { (s[1], s[2], s[3]) } else { ("object_r", t[2], s[3].split('-').next().unwrap()) };
    let ty = p.transition(s[2], t[2], class, name).unwrap_or(ty);
    Ok(format!("{}:{role}:{ty}:{level}", s[0]))
}

/// The policy files init's first stage would compile, in secilc's order.
fn load(vfs: Option<&Vfs>) -> Policy {
    let Some(vfs) = vfs else { return Policy::default() };
    let read = |p: &str| vfs.resolve("/", p, true).and_then(|n| vfs.read_all(&n)).ok();
    let ver = read("/vendor/etc/selinux/plat_sepolicy_vers.txt").map(|v| String::from_utf8_lossy(&v).trim().to_string()).unwrap_or_default();
    let files = [
        "/system/etc/selinux/plat_sepolicy.cil".to_string(),
        format!("/system/etc/selinux/mapping/{ver}.cil"),
        format!("/system/etc/selinux/mapping/{ver}.compat.cil"),
        "/system_ext/etc/selinux/system_ext_sepolicy.cil".into(),
        format!("/system_ext/etc/selinux/mapping/{ver}.cil"),
        format!("/system_ext/etc/selinux/mapping/{ver}.compat.cil"),
        "/product/etc/selinux/product_sepolicy.cil".into(),
        format!("/product/etc/selinux/mapping/{ver}.cil"),
        "/vendor/etc/selinux/plat_pub_versioned.cil".into(),
        "/vendor/etc/selinux/vendor_sepolicy.cil".into(),
        "/odm/etc/selinux/odm_sepolicy.cil".into(),
    ];
    let data: Vec<_> = files.iter().filter_map(|f| read(f)).collect();
    Policy::parse(&data.iter().filter_map(|d| std::str::from_utf8(d).ok()).collect::<Vec<_>>())
}

impl Selinux {
    pub fn new(kernel: Weak<Kernel>, phys: Arc<PhysMem>, boot: bool) -> Arc<Selinux> {
        let se = Selinux {
            kernel,
            policy: Mutex::new(None),
            enforcing: AtomicBool::new(false),
            status: MemFile::new(phys),
            seq: Mutex::new((0, 0)),
            bools: Mutex::new(HashMap::new()),
            initial: if boot { (sid("u:r:init:s0"), sid("u:r:kernel:s0")) } else { (sid("u:r:shell:s0"), sid("u:r:shell:s0")) },
        };
        se.update_status(|_| {});
        Arc::new(se)
    }

    fn policy(&self) -> Arc<Policy> {
        let mut p = self.policy.lock().unwrap();
        if let Some(p) = &*p {
            return p.clone();
        }
        let Some(k) = self.kernel.upgrade() else { return Arc::new(Policy::default()) };
        let loaded = Arc::new(load(k.vfs.as_deref()));
        *p = Some(loaded.clone());
        loaded
    }

    /// Rewrites the status page around `f`, with an odd sequence number
    /// while it changes (libselinux retries reads until the number is even
    /// and unchanged).
    fn update_status(&self, f: impl FnOnce(&mut (u32, u32))) {
        let mut seq = self.seq.lock().unwrap();
        seq.0 += 1;
        let _ = self.status.write_at(4, &seq.0.to_le_bytes());
        f(&mut seq);
        seq.0 += 1;
        let fields = [1, seq.0, self.enforcing.load(Ordering::Relaxed) as u32, seq.1, 0]; // version .. deny_unknown
        let _ = self.status.write_at(0, &fields.iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<u8>>());
    }

    pub fn initial_sec(&self) -> ProcSec {
        ProcSec { current: AtomicU32::new(self.initial.0), prev: AtomicU32::new(self.initial.1) }
    }

    pub fn canonical(&self, ctx: &str) -> Result<String, i64> {
        canonical(&self.policy(), ctx)
    }

    pub fn compute_create(&self, scon: &str, tcon: &str, class: u16, name: Option<&str>) -> Result<String, i64> {
        compute_create(&self.policy(), scon, tcon, class, name)
    }

    /// The label a file that `t` creates as `name` in a directory labelled
    /// `dir` gets, as Linux's selinux_inode_init_security: the thread's
    /// fscreate context, else the policy's type transition for `class`
    /// ("file", "dir", "sock_file", …), else the directory's type.
    #[allow(dead_code)] // for tmpfs labels once the VFS has xattrs
    pub fn new_file_context(&self, t: &Thread, dir: &str, class: &str, name: &str) -> String {
        if let Some(c) = context(t.sec.get(FSCREATE)) {
            return c.to_string();
        }
        let p = self.policy();
        let scon = context(t.proc.sec.current()).unwrap_or_default();
        p.class_index(class).and_then(|c| compute_create(&p, &scon, dir, c, Some(name)).ok()).unwrap_or_else(|| dir.to_string())
    }

    /// Applies an execve's transition to the calling thread: its exec
    /// context if one is set, else the policy's type transition for the
    /// executable's label. fscreate, keycreate and sockcreate reset.
    pub(super) fn exec(&self, t: &Thread, vfs: &Vfs, cwd: &str, path: &str) {
        let cur = t.proc.sec.current();
        let new = match t.sec.0[0].swap(0, Ordering::Relaxed) {
            0 => {
                let file = vfs.resolve(cwd, path, true).map(|n| file_context(vfs, &n)).unwrap_or_else(|_| "u:object_r:system_file:s0".into());
                let (p, scon) = (self.policy(), context(cur).unwrap_or_default());
                let process = p.class_index("process");
                process.and_then(|c| compute_create(&p, &scon, &file, c, None).ok()).map_or(cur, |c| sid(&c))
            }
            s => s,
        };
        t.proc.sec.prev.store(cur, Ordering::Relaxed);
        t.proc.sec.current.store(new, Ordering::Relaxed);
        for a in &t.sec.0[1..] {
            a.store(0, Ordering::Relaxed);
        }
    }

    /// Answers a selinuxfs transaction (`name` is the file).
    fn transact(&self, name: &str, req: &[u8]) -> Result<Vec<u8>, i64> {
        let req = String::from_utf8_lossy(req);
        let req = req.trim_end_matches('\0');
        let a: Vec<&str> = req.split_ascii_whitespace().collect();
        let class = || a.get(2).and_then(|c| c.parse::<u16>().ok()).ok_or(EINVAL);
        let nul = |s: String| [s.as_bytes(), b"\0"].concat();
        Ok(match name {
            "context" => nul(self.canonical(req)?),
            "access" if a.len() >= 3 => {
                self.canonical(a[0])?;
                self.canonical(a[1])?;
                class()?;
                // allowed decided auditallow auditdeny seqno flags: everything is allowed.
                format!("ffffffff ffffffff 0 ffffffff {} 0", self.seq.lock().unwrap().1).into_bytes()
            }
            "create" if (3..=4).contains(&a.len()) => {
                let objname = a.get(3).map(|n| decode_name(n)).transpose()?;
                nul(self.compute_create(a[0], a[1], class()?, objname.as_deref())?)
            }
            "member" | "relabel" if a.len() >= 3 => {
                self.canonical(a[0])?;
                class()?;
                nul(self.canonical(a[1])?)
            }
            "user" if a.len() >= 2 => {
                self.canonical(a[0])?;
                b"0\0".to_vec() // no reachable contexts listed
            }
            _ => return Err(EINVAL),
        })
    }

    fn bool_state(&self, p: &Policy, i: usize) -> Option<(bool, bool)> {
        let (name, default) = p.bools.get(i)?;
        Some(self.bools.lock().unwrap().get(name).copied().unwrap_or((*default, *default)))
    }

    fn caps(p: &Policy) -> Vec<&str> {
        let mut caps: Vec<&str> = KERNEL_CAPS.to_vec();
        caps.extend(p.caps.iter().map(String::as_str).filter(|c| !KERNEL_CAPS.contains(c)));
        caps
    }

    /// Initial SIDs selinuxfs names (the kernel has no name for CIL's UNKNOWN<n> placeholders).
    fn initial_sids(p: &Policy) -> impl Iterator<Item = (usize, &(String, String))> {
        p.sids.iter().enumerate().filter(|(_, (n, _))| !n.starts_with("UNKNOWN"))
    }

    /// (name, inode) of a directory's entries.
    fn children(&self, dir: u64) -> Option<Vec<(String, u64)>> {
        let fixed_in = |parent: &str| -> Vec<(String, u64)> { FIXED.iter().enumerate().filter(|f| f.1.1 == parent).map(|(i, f)| (f.0.to_string(), i as u64 + 2)).collect() };
        if dir == ROOT {
            return Some(fixed_in(""));
        }
        let (kind, a) = (dir & 0xff, (dir >> 8 & 0xffff) as usize);
        let p = self.policy();
        Some(match (fixed_name(dir), kind) {
            (Some("avc"), _) => fixed_in("avc"),
            (Some("class"), _) => p.classes.iter().enumerate().map(|(i, c)| (c.name.clone(), ino(K_CLASS, i + 1, 0))).collect(),
            (Some("booleans"), _) => p.bools.iter().enumerate().map(|(i, b)| (b.0.clone(), ino(K_BOOL, i, 0))).collect(),
            (Some("initial_contexts"), _) => Self::initial_sids(&p).map(|(i, s)| (s.0.clone(), ino(K_INITCON, i, 0))).collect(),
            (Some("policy_capabilities"), _) => Self::caps(&p).iter().enumerate().map(|(i, c)| (c.to_string(), ino(K_CAP, i, 0))).collect(),
            (None, K_CLASS) if p.class(a as u16).is_some() => vec![("index".into(), ino(K_INDEX, a, 0)), ("perms".into(), ino(K_PERMS, a, 0))],
            (None, K_PERMS) => p.class(a as u16)?.perms.iter().enumerate().map(|(b, n)| (n.clone(), ino(K_PERM, a, b))).collect(),
            _ => return None,
        })
    }

    /// The parent of a directory, for "..".
    fn parent(dir: u64) -> u64 {
        match (fixed_name(dir), dir & 0xff) {
            (None, K_CLASS) => fixed("class"),
            (None, K_PERMS) => ino(K_CLASS, (dir >> 8 & 0xffff) as usize, 0),
            _ => ROOT,
        }
    }

    fn mode(&self, ino: u64) -> Option<u32> {
        if ino == ROOT {
            return Some(S_IFDIR | 0o555);
        }
        if let Some(name) = fixed_name(ino) {
            return FIXED.iter().find(|f| f.0 == name).map(|f| f.2);
        }
        let (kind, a, b) = (ino & 0xff, (ino >> 8 & 0xffff) as usize, (ino >> 24 & 0xffff) as usize);
        let p = self.policy();
        let class = || p.class(a as u16);
        match kind {
            K_CLASS | K_PERMS if class().is_some() => Some(S_IFDIR | 0o555),
            K_INDEX if class().is_some() => Some(0o100444),
            K_PERM if class().is_some_and(|c| b < c.perms.len()) => Some(0o100444),
            K_BOOL if a < p.bools.len() => Some(0o100644),
            K_INITCON if a < p.sids.len() => Some(0o100444),
            K_CAP if a < Self::caps(&p).len() => Some(0o100444),
            _ => None,
        }
    }

    /// A file's contents as a read sees them.
    fn read(&self, ino: u64) -> Result<Vec<u8>, i64> {
        let text = |s: &str| Ok(s.as_bytes().to_vec());
        if let Some(name) = fixed_name(ino) {
            return match name {
                "enforce" => text(if self.enforcing.load(Ordering::Relaxed) { "1" } else { "0" }),
                "deny_unknown" | "reject_unknown" | "checkreqprot" => text("0"),
                "policyvers" => text("33"),
                "mls" => text("1"),
                "cache_threshold" => text("512"),
                "hash_stats" => text("entries: 0\nbuckets used: 0/512\nlongest chain: 0\n"),
                "cache_stats" => text("lookups hits misses allocations reclaims frees\n0 0 0 0 0 0\n"),
                "status" => Ok(self.status.read_at(0, 20)),
                n if TRANSACTIONS.contains(&n) => Ok(Vec::new()),
                _ => Err(EINVAL), // write-only
            };
        }
        let (kind, a, b) = (ino & 0xff, (ino >> 8 & 0xffff) as usize, (ino >> 24 & 0xffff) as usize);
        let p = self.policy();
        match kind {
            K_INDEX => text(&a.to_string()),
            K_PERM => text(&(b + 1).to_string()),
            K_BOOL => {
                let (cur, pending) = self.bool_state(&p, a).ok_or(ENOENT)?;
                text(&format!("{} {}", cur as u8, pending as u8))
            }
            K_INITCON => Ok(p.sids.get(a).map(|s| [s.1.as_bytes(), b"\0"].concat()).ok_or(ENOENT)?),
            K_CAP => text(if Self::caps(&p).get(a).is_some_and(|c| p.caps.iter().any(|x| x == c)) { "1" } else { "0" }),
            _ => Err(EISDIR),
        }
    }

    fn write(&self, ino: u64, data: &[u8]) -> Result<usize, i64> {
        match fixed_name(ino) {
            Some("enforce") => {
                let on = int_arg(data)? != 0;
                if self.enforcing.swap(on, Ordering::Relaxed) != on {
                    self.update_status(|_| {});
                }
            }
            Some("checkreqprot" | "disable" | "cache_threshold") => {
                int_arg(data)?;
            }
            // A binary policy (init's selinux_setup stage, load_policy):
            // accepted, while the model keeps coming from the CIL, re-read now.
            Some("load") => {
                *self.policy.lock().unwrap() = None;
                self.bools.lock().unwrap().clear();
                self.update_status(|s| s.1 += 1);
            }
            Some("commit_pending_bools") => {
                if int_arg(data)? != 0 {
                    for v in self.bools.lock().unwrap().values_mut() {
                        v.0 = v.1;
                    }
                }
            }
            Some("validatetrans") => {}
            None if ino & 0xff == K_BOOL => {
                let on = int_arg(data)? != 0;
                let p = self.policy();
                let (name, default) = p.bools.get((ino >> 8 & 0xffff) as usize).ok_or(ENOENT)?;
                self.bools.lock().unwrap().entry(name.clone()).or_insert((*default, *default)).1 = on;
            }
            _ => return Err(EINVAL),
        }
        Ok(data.len())
    }
}

/// Undoes libselinux's encoding of an object name in a create request:
/// '+' is a space, %XX a byte.
fn decode_name(s: &str) -> Result<String, i64> {
    let b = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'+' => out.push(b' '),
            b'%' => {
                let hex = s.get(i + 1..i + 3).and_then(|h| u8::from_str_radix(h, 16).ok()).ok_or(EINVAL)?;
                out.push(hex);
                i += 2;
            }
            c => out.push(c),
        }
        i += 1;
    }
    Ok(String::from_utf8_lossy(&out).into_owned())
}

impl FileSystem for Selinux {
    fn fs_type(&self) -> &'static str {
        "selinuxfs"
    }
    fn root(&self) -> io::Result<u64> {
        Ok(ROOT)
    }
    fn stat(&self, ino: u64) -> io::Result<Stat> {
        let mode = self.mode(ino).ok_or_else(|| err(ENOENT))?;
        let rdev = if mode & S_IFMT == 0o020000 { 0x103 } else { 0 }; // null is /dev/null's 1:3
        Ok(Stat { dev: 0, ino, mode, nlink: if mode & S_IFMT == S_IFDIR { 2 } else { 1 }, uid: 0, gid: 0, rdev, size: 0, mtime: 0 })
    }
    fn lookup(&self, dir: u64, name: &str) -> io::Result<Option<u64>> {
        match name {
            "." => Ok(Some(dir)),
            ".." => Ok(Some(Self::parent(dir))),
            _ => Ok(self.children(dir).ok_or_else(|| err(ENOTDIR))?.into_iter().find(|(n, _)| n == name).map(|(_, i)| i)),
        }
    }
    fn readdir(&self, dir: u64) -> io::Result<Vec<Dirent>> {
        let entries = self.children(dir).ok_or_else(|| err(ENOTDIR))?;
        let mut out = vec![Dirent { name: ".".into(), ino: dir, dtype: 4 }, Dirent { name: "..".into(), ino: Self::parent(dir), dtype: 4 }];
        for (name, ino) in entries {
            let dtype = match self.mode(ino).unwrap_or(0) & S_IFMT {
                S_IFDIR => 4,
                0o020000 => 2,
                _ => 8,
            };
            out.push(Dirent { name, ino, dtype });
        }
        Ok(out)
    }
    fn read_all(&self, ino: u64) -> io::Result<Arc<[u8]>> {
        self.read(ino).map(Into::into).map_err(err)
    }
    fn writable(&self) -> bool {
        true
    }
    /// The status page is a plain shared file, so mappings see updates.
    fn mem_file(&self, ino: u64) -> Option<Arc<MemFile>> {
        (fixed_name(ino) == Some("status")).then(|| self.status.clone())
    }
}

/// An open selinuxfs file; transaction files keep their answer per open.
struct FsFile {
    se: Arc<Selinux>,
    ino: u64,
    reply: Mutex<Vec<u8>>,
}

impl SpecialFile for FsFile {
    fn contents(&self, _t: &Thread) -> Result<Vec<u8>, i64> {
        match fixed_name(self.ino) {
            Some(n) if TRANSACTIONS.contains(&n) => Ok(self.reply.lock().unwrap().clone()),
            _ => self.se.read(self.ino),
        }
    }
    fn write(&self, _t: &Thread, data: &[u8]) -> Result<usize, i64> {
        match fixed_name(self.ino) {
            Some(n) if TRANSACTIONS.contains(&n) => {
                *self.reply.lock().unwrap() = self.se.transact(n, data)?;
                Ok(data.len())
            }
            _ => self.se.write(self.ino, data),
        }
    }
}

/// An open /proc/<pid>[/task/<tid>]/attr/<name>.
struct AttrFile {
    se: Arc<Selinux>,
    proc: Arc<Process>,
    tid: i32,
    which: usize,
}

impl SpecialFile for AttrFile {
    fn contents(&self, _t: &Thread) -> Result<Vec<u8>, i64> {
        Ok(attr(&self.proc, self.tid, self.which))
    }
    /// As Linux's proc_pid_attr_write and selinux_setprocattr: only the
    /// thread itself writes; an empty value (or a lone NUL or newline)
    /// clears; a trailing newline is dropped.
    fn write(&self, t: &Thread, data: &[u8]) -> Result<usize, i64> {
        if t.tid != self.tid || !Arc::ptr_eq(&t.proc, &self.proc) {
            return Err(EACCES);
        }
        let sid = match data {
            [] | [0, ..] | [b'\n', ..] => 0,
            _ => {
                let v = data.strip_suffix(b"\n").unwrap_or(data);
                sid(&self.se.canonical(&String::from_utf8_lossy(v))?)
            }
        };
        match self.which {
            0 if sid != 0 => self.proc.sec.current.store(sid, Ordering::Relaxed), // setcon: a dyntransition
            0 | 1 => return Err(EINVAL),
            w => t.sec.0[w - EXEC].store(sid, Ordering::Relaxed),
        }
        Ok(data.len())
    }
}

/// Whether opening `node` must go through `open`: selinuxfs files other than
/// the mappable status page, and /proc attr files.
pub(super) fn is_special(vfs: &Vfs, node: &Node) -> bool {
    match vfs.fs_type(node) {
        "selinuxfs" => fixed_name(node.ino) != Some("status"),
        "proc" => super::procfs::attr_node(node.ino).is_some(),
        _ => false,
    }
}

pub(super) fn open(k: &Kernel, vfs: &Vfs, node: &Node) -> Result<Box<dyn SpecialFile>, i64> {
    if vfs.fs_type(node) == "proc" {
        let (pid, tid, which) = super::procfs::attr_node(node.ino).ok_or(ENOENT)?;
        let proc = k.process(pid).ok_or(ENOENT)?;
        return Ok(Box::new(AttrFile { se: k.selinux.clone(), proc, tid, which }));
    }
    Ok(Box::new(FsFile { se: k.selinux.clone(), ino: node.ino, reply: Mutex::new(Vec::new()) }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mini() -> Policy {
        let domains = "(typeattribute domain) (typeattributeset domain (init kernel shell logd toolbox hal_audio_default))";
        Policy::parse(&[include_str!("../../testdata/sepolicy_mini.cil"), domains])
    }

    #[test]
    fn contexts() {
        let p = mini();
        assert_eq!(canonical(&p, "u:r:init:s0\0"), Ok("u:r:init:s0".into()));
        assert_eq!(canonical(&p, "u:r:init:s0-s0"), Ok("u:r:init:s0".into()));
        assert_eq!(canonical(&p, "u:object_r:rs_data_file:s0"), Ok("u:object_r:app_exec_data_file:s0".into()));
        assert_eq!(canonical(&p, "u:r:shell:s0:c512,c768"), Ok("u:r:shell:s0:c512,c768".into()));
        assert_eq!(canonical(&p, "u:r:shell:s0-s0:c0.c1023"), Ok("u:r:shell:s0-s0:c0.c1023".into()));
        for bad in ["u:r:init", "u:r:nope:s0", "u:r:system_file:s0", "u:r:init:x0", "u:r:init:s0 ", "u:r:init:s0:d1"] {
            assert_eq!(canonical(&p, bad), Err(EINVAL), "{bad}");
        }
        // Without a policy, only the shape counts.
        assert_eq!(canonical(&Policy::default(), "u:r:anything:s0"), Ok("u:r:anything:s0".into()));
    }

    #[test]
    fn create() {
        let p = mini();
        let class = |n| p.class_index(n).unwrap();
        // init's ComputeContextFromExecutable for logd.
        assert_eq!(compute_create(&p, "u:r:init:s0", "u:object_r:logd_exec:s0", class("process"), None), Ok("u:r:logd:s0".into()));
        // No rule: a process keeps its context (init refuses such services).
        assert_eq!(compute_create(&p, "u:r:init:s0", "u:object_r:system_file:s0", class("process"), None), Ok("u:r:init:s0".into()));
        assert_eq!(compute_create(&p, "u:r:shell:s0", "u:object_r:tmpfs:s0", class("file"), None), Ok("u:object_r:appdomain_tmpfs:s0".into()));
        // Objects take the parent's type and the creator's low level.
        assert_eq!(compute_create(&p, "u:r:shell:s0-s0:c0.c1023", "u:object_r:system_file:s0", class("dir"), None), Ok("u:object_r:system_file:s0".into()));
        assert_eq!(compute_create(&p, "u:r:shell:s0", "u:r:shell:s0", class("anon_inode"), Some("[userfaultfd]")), Ok("u:object_r:shell_userfaultfd:s0".into()));
        assert_eq!(compute_create(&p, "u:r:shell:s0", "u:r:shell:s0", class("unix_stream_socket"), None), Ok("u:r:shell:s0".into()));
        assert_eq!(compute_create(&p, "u:r:bogus:s0", "u:r:shell:s0", class("process"), None), Err(EINVAL));
    }

    #[test]
    fn request_helpers() {
        assert_eq!(decode_name("%5Buserfaultfd%5D"), Ok("[userfaultfd]".into()));
        assert_eq!(decode_name("a+b"), Ok("a b".into()));
        assert_eq!(decode_name("%zz"), Err(EINVAL));
        assert_eq!(int_arg(b"1\0"), Ok(1));
        assert_eq!(int_arg(b" 0\n"), Ok(0));
        assert_eq!(int_arg(b"x"), Err(EINVAL));
    }

    /// The real policy, when the SDK image the end-to-end tests use is installed.
    #[test]
    fn image_policy() {
        let Some(home) = std::env::var_os("HOME") else { return };
        let img = std::path::Path::new(&home).join("Library/Android/sdk/system-images/android-36.1/google_apis_playstore/arm64-v8a/system.img");
        let Ok(vfs) = crate::android::open_system_image(&img) else { return };
        let p = load(Some(&vfs));
        let process = p.class_index("process").unwrap();
        assert_eq!(p.class_index("property_service"), Some(99));
        assert_eq!(p.transition("init", "logd_exec", process, None), Some("logd"));
        assert_eq!(p.transition("init", "hal_audio_default_exec", process, None), Some("hal_audio_default"));
        assert_eq!(p.transition("init", "system_file", process, None), None);
        assert!(p.valid("u", "r", "untrusted_app"));
        assert_eq!(compute_create(&p, "u:r:init:s0", "u:object_r:apexd_exec:s0", process, None), Ok("u:r:apexd:s0".into()));
    }
}

//! cgroup (v1) and cgroup2 filesystems: directories are cgroups, each with
//! its controllers' control files. Values written read back (nothing is
//! enforced); cgroup.procs and tasks list the processes and threads moved
//! there, and the children of those that were not moved themselves, which
//! is what libprocessgroup and init rely on. cgroup.kill kills the members.

use super::Kernel;
use super::signal::{SIGKILL, SigInfo};
use crate::errno::*;
use crate::vfs::{Dirent, FileSystem, S_IFDIR, S_IFREG, Stat};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::io;
use std::sync::{Arc, Mutex, Weak};
use std::time::{SystemTime, UNIX_EPOCH};

const ROOT: u64 = 1;

/// v1 controllers in the kernel's order (as /proc/mounts lists them).
pub const V1_CONTROLLERS: [&str; 12] = ["cpuset", "cpu", "cpuacct", "blkio", "memory", "devices", "freezer", "net_cls", "perf_event", "net_prio", "hugetlb", "pids"];
const V2_CONTROLLERS: &str = "cpuset cpu io memory hugetlb pids rdma misc";

#[derive(Clone, Copy, PartialEq, Eq)]
enum Ctl {
    /// A value that reads back what was written.
    Value,
    /// Generated, read-only.
    Text,
    /// Accepts writes, reads nothing (cgroup.event_control, memory.force_empty).
    WriteOnly,
    Procs,
    Tasks,
    Kill,
    SubtreeControl,
    Controllers,
}

/// (name, default, kind, also in the root cgroup).
type Spec = (&'static str, &'static str, Ctl, bool);

const V1_CORE: &[Spec] = &[
    ("cgroup.procs", "", Ctl::Procs, true),
    ("tasks", "", Ctl::Tasks, true),
    ("cgroup.clone_children", "0", Ctl::Value, true),
    ("notify_on_release", "0", Ctl::Value, true),
    ("cgroup.sane_behavior", "0", Ctl::Text, true),
];

const PSI: &str = "some avg10=0.00 avg60=0.00 avg300=0.00 total=0\nfull avg10=0.00 avg60=0.00 avg300=0.00 total=0";
const MAX_BYTES: &str = "9223372036854771712";

fn v1_controller(c: &str) -> &'static [Spec] {
    match c {
        "cpu" => &[
            ("cpu.shares", "1024", Ctl::Value, true),
            ("cpu.cfs_period_us", "100000", Ctl::Value, true),
            ("cpu.cfs_quota_us", "-1", Ctl::Value, true),
            ("cpu.rt_period_us", "1000000", Ctl::Value, true),
            ("cpu.rt_runtime_us", "0", Ctl::Value, true),
            ("cpu.stat", "nr_periods 0\nnr_throttled 0\nthrottled_time 0", Ctl::Text, true),
            ("cpu.uclamp.min", "0.00", Ctl::Value, false),
            ("cpu.uclamp.max", "max", Ctl::Value, false),
            ("cpu.uclamp.latency_sensitive", "0", Ctl::Value, false),
            ("cpu.idle", "0", Ctl::Value, false),
        ],
        "cpuacct" => &[("cpuacct.usage", "0", Ctl::Value, true), ("cpuacct.stat", "user 0\nsystem 0", Ctl::Text, true)],
        // Prefixed with "cpuset." unless mounted as the legacy "cpuset" type.
        "cpuset" => &[
            ("cpus", "", Ctl::Value, true),
            ("mems", "", Ctl::Value, true),
            ("effective_cpus", "", Ctl::Text, true),
            ("effective_mems", "", Ctl::Text, true),
            ("cpu_exclusive", "0", Ctl::Value, true),
            ("mem_exclusive", "0", Ctl::Value, true),
            ("mem_hardwall", "0", Ctl::Value, true),
            ("sched_load_balance", "1", Ctl::Value, true),
            ("sched_relax_domain_level", "-1", Ctl::Value, true),
            ("memory_migrate", "0", Ctl::Value, true),
            ("memory_pressure", "0", Ctl::Text, true),
            ("memory_spread_page", "0", Ctl::Value, true),
            ("memory_spread_slab", "0", Ctl::Value, true),
        ],
        "memory" => &[
            ("memory.limit_in_bytes", MAX_BYTES, Ctl::Value, true),
            ("memory.soft_limit_in_bytes", MAX_BYTES, Ctl::Value, true),
            ("memory.memsw.limit_in_bytes", MAX_BYTES, Ctl::Value, true),
            ("memory.usage_in_bytes", "0", Ctl::Text, true),
            ("memory.memsw.usage_in_bytes", "0", Ctl::Text, true),
            ("memory.max_usage_in_bytes", "0", Ctl::Value, true),
            ("memory.swappiness", "60", Ctl::Value, true),
            ("memory.move_charge_at_immigrate", "0", Ctl::Value, true),
            ("memory.use_hierarchy", "1", Ctl::Value, true),
            ("memory.oom_control", "oom_kill_disable 0\nunder_oom 0\noom_kill 0", Ctl::Text, true),
            ("memory.stat", "cache 0\nrss 0\nswap 0", Ctl::Text, true),
            ("memory.pressure_level", "", Ctl::WriteOnly, true),
            ("memory.force_empty", "", Ctl::WriteOnly, true),
            ("cgroup.event_control", "", Ctl::WriteOnly, true),
        ],
        "blkio" => &[
            ("blkio.weight", "500", Ctl::Value, true),
            ("blkio.leaf_weight", "500", Ctl::Value, true),
            ("blkio.bfq.weight", "100", Ctl::Value, true),
            ("blkio.group_idle", "0", Ctl::Value, true),
        ],
        "freezer" => &[("freezer.state", "THAWED", Ctl::Value, false), ("freezer.self_freezing", "0", Ctl::Text, false), ("freezer.parent_freezing", "0", Ctl::Text, false)],
        "pids" => &[("pids.max", "max", Ctl::Value, false), ("pids.current", "0", Ctl::Text, false)],
        _ => &[],
    }
}

const V2_CORE: &[Spec] = &[
    ("cgroup.procs", "", Ctl::Procs, true),
    ("cgroup.threads", "", Ctl::Tasks, true),
    ("cgroup.controllers", "", Ctl::Controllers, true),
    ("cgroup.subtree_control", "", Ctl::SubtreeControl, true),
    ("cgroup.max.depth", "max", Ctl::Value, true),
    ("cgroup.max.descendants", "max", Ctl::Value, true),
    ("cgroup.stat", "nr_descendants 0\nnr_dying_descendants 0", Ctl::Text, true),
    ("cgroup.pressure", "1", Ctl::Value, true),
    ("cpu.stat", "usage_usec 0\nuser_usec 0\nsystem_usec 0", Ctl::Text, true),
    ("cpu.pressure", PSI, Ctl::Text, true),
    ("memory.pressure", PSI, Ctl::Text, true),
    ("io.pressure", PSI, Ctl::Text, true),
    ("cgroup.type", "domain", Ctl::Value, false),
    ("cgroup.events", "populated 0\nfrozen 0", Ctl::Text, false),
    ("cgroup.freeze", "0", Ctl::Value, false),
    ("cgroup.kill", "", Ctl::Kill, false),
];

/// Files a v2 cgroup gets for a controller its parent enabled.
fn v2_controller(c: &str) -> &'static [Spec] {
    match c {
        "memory" => &[
            ("memory.current", "0", Ctl::Text, false),
            ("memory.peak", "0", Ctl::Text, false),
            ("memory.min", "0", Ctl::Value, false),
            ("memory.low", "0", Ctl::Value, false),
            ("memory.high", "max", Ctl::Value, false),
            ("memory.max", "max", Ctl::Value, false),
            ("memory.swap.current", "0", Ctl::Text, false),
            ("memory.swap.max", "max", Ctl::Value, false),
            ("memory.oom.group", "0", Ctl::Value, false),
            ("memory.events", "low 0\nhigh 0\nmax 0\noom 0\noom_kill 0", Ctl::Text, false),
            ("memory.stat", "anon 0\nfile 0", Ctl::Text, false),
        ],
        "cpu" => &[
            ("cpu.weight", "100", Ctl::Value, false),
            ("cpu.weight.nice", "0", Ctl::Value, false),
            ("cpu.max", "max 100000", Ctl::Value, false),
            ("cpu.uclamp.min", "0.00", Ctl::Value, false),
            ("cpu.uclamp.max", "max", Ctl::Value, false),
            ("cpu.idle", "0", Ctl::Value, false),
        ],
        "io" => &[("io.weight", "default 100", Ctl::Value, false)],
        "cpuset" => &[("cpuset.cpus", "", Ctl::Value, false), ("cpuset.mems", "", Ctl::Value, false), ("cpuset.cpus.effective", "", Ctl::Text, false), ("cpuset.mems.effective", "0", Ctl::Text, false)],
        "pids" => &[("pids.max", "max", Ctl::Value, false), ("pids.current", "0", Ctl::Text, false)],
        _ => &[],
    }
}

enum Kind {
    Dir { entries: BTreeMap<String, u64>, parent: u64 },
    /// A control file of cgroup `dir`.
    File { ctl: Ctl, value: String, dir: u64 },
}

struct Node {
    mode: u32,
    uid: u32,
    gid: u32,
    mtime: u64,
    kind: Kind,
}

struct State {
    nodes: HashMap<u64, Node>,
    next: u64,
    /// Process or thread id → the cgroup (directory) it was moved to.
    /// Everything else is where its parent process is.
    member: HashMap<i32, u64>,
    /// v2: each cgroup's cgroup.subtree_control.
    subtree: HashMap<u64, BTreeSet<String>>,
}

/// Every hierarchy, for /proc/cgroups and /proc/<pid>/cgroup.
static HIERARCHIES: Mutex<Vec<Weak<CgroupFs>>> = Mutex::new(Vec::new());

pub struct CgroupFs {
    kernel: Weak<Kernel>,
    v2: bool,
    controllers: Vec<&'static str>,
    /// The legacy "cpuset" filesystem type: control files without "cpuset.".
    noprefix: bool,
    st: Mutex<State>,
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

fn cpus() -> String {
    let n = std::thread::available_parallelism().map_or(1, |n| n.get()).min(64);
    if n == 1 { "0".into() } else { format!("0-{}", n - 1) }
}

impl CgroupFs {
    pub fn new(kernel: Weak<Kernel>, v2: bool, controllers: Vec<&'static str>, noprefix: bool) -> Arc<CgroupFs> {
        let fs = Arc::new(CgroupFs {
            kernel,
            v2,
            controllers,
            noprefix,
            st: Mutex::new(State { nodes: HashMap::new(), next: ROOT + 1, member: HashMap::new(), subtree: HashMap::new() }),
        });
        let mut st = fs.st.lock().unwrap();
        st.nodes.insert(ROOT, Node { mode: S_IFDIR | 0o755, uid: 0, gid: 0, mtime: now(), kind: Kind::Dir { entries: BTreeMap::new(), parent: ROOT } });
        fs.populate(&mut st, ROOT, true);
        drop(st);
        let mut all = HIERARCHIES.lock().unwrap();
        all.retain(|h| h.strong_count() > 0);
        all.push(Arc::downgrade(&fs));
        fs
    }

    /// The path of cgroup `dir` from the hierarchy's root ("/" for the root).
    fn path(st: &State, mut dir: u64) -> String {
        let mut parts = Vec::new();
        while dir != ROOT {
            let Some(Kind::Dir { parent, .. }) = st.nodes.get(&dir).map(|n| &n.kind) else { break };
            let name = match st.nodes.get(parent).map(|n| &n.kind) {
                Some(Kind::Dir { entries, .. }) => entries.iter().find(|e| *e.1 == dir).map(|e| e.0.clone()).unwrap_or_default(),
                _ => String::new(),
            };
            parts.push(name);
            dir = *parent;
        }
        parts.reverse();
        format!("/{}", parts.join("/"))
    }

    /// The control files of a new cgroup `dir`.
    fn populate(&self, st: &mut State, dir: u64, root: bool) {
        // The root cgroup has only the files marked so; children have all.
        let keep = |s: &&Spec| !root || s.3;
        let mut specs: Vec<(String, Spec)> = Vec::new();
        if self.v2 {
            let parent = match &st.nodes[&dir].kind {
                Kind::Dir { parent, .. } => *parent,
                _ => ROOT,
            };
            let enabled = if root { BTreeSet::new() } else { st.subtree.get(&parent).cloned().unwrap_or_default() };
            specs.extend(V2_CORE.iter().filter(keep).map(|s| (s.0.to_string(), *s)));
            for c in &enabled {
                specs.extend(v2_controller(c).iter().map(|s| (s.0.to_string(), *s)));
            }
        } else {
            specs.extend(V1_CORE.iter().filter(|s| root || s.0 != "cgroup.sane_behavior").map(|s| (s.0.to_string(), *s)));
            if root {
                specs.push(("release_agent".into(), ("release_agent", "", Ctl::Value, true)));
            }
            for c in &self.controllers {
                for s in v1_controller(c).iter().filter(keep) {
                    let name = if *c == "cpuset" && !self.noprefix { format!("cpuset.{}", s.0) } else { s.0.to_string() };
                    specs.push((name, *s));
                }
            }
        }
        for (name, (_, default, ctl, _)) in specs {
            let value = match (name.as_str(), root) {
                ("cpus" | "cpuset.cpus" | "effective_cpus" | "cpuset.effective_cpus" | "cpuset.cpus.effective", true) => cpus(),
                ("mems" | "cpuset.mems" | "effective_mems" | "cpuset.effective_mems", true) => "0".into(),
                ("cpu.rt_runtime_us", true) => "950000".into(),
                _ => default.to_string(),
            };
            let mode = match ctl {
                Ctl::Text | Ctl::Controllers => 0o444,
                Ctl::WriteOnly | Ctl::Kill => 0o200,
                _ => 0o644,
            };
            let ino = st.next;
            st.next += 1;
            st.nodes.insert(ino, Node { mode: S_IFREG | mode, uid: 0, gid: 0, mtime: now(), kind: Kind::File { ctl, value, dir } });
            if let Some(Kind::Dir { entries, .. }) = st.nodes.get_mut(&dir).map(|n| &mut n.kind) {
                entries.insert(name, ino);
            }
        }
    }

    fn dir_of(st: &State, ino: u64) -> u64 {
        match st.nodes.get(&ino).map(|n| &n.kind) {
            Some(Kind::File { dir, .. }) => *dir,
            _ => ino,
        }
    }

    /// The cgroup a process is in: where it was moved, else its parent's.
    fn cgroup_of(&self, k: &Kernel, st: &State, pid: i32) -> u64 {
        let mut p = pid;
        for _ in 0..64 {
            if let Some(&g) = st.member.get(&p).filter(|g| st.nodes.contains_key(g)) {
                return g;
            }
            match k.process(p) {
                Some(proc) if p != 1 => p = proc.ppid.load(std::sync::atomic::Ordering::Relaxed),
                _ => break,
            }
        }
        ROOT
    }

    /// Live (pid, tids) of the kernel.
    fn live(k: &Kernel) -> Vec<(i32, Vec<i32>)> {
        let procs: Vec<_> = k.procs.lock().unwrap().values().filter(|p| p.status.lock().unwrap().is_none()).cloned().collect();
        let mut v: Vec<(i32, Vec<i32>)> = procs.iter().map(|p| (p.pid, p.threads.lock().unwrap().iter().map(|t| t.tid).collect())).collect();
        v.sort();
        v
    }

    fn members(&self, st: &State, dir: u64, threads: bool) -> Vec<i32> {
        let Some(k) = self.kernel.upgrade() else { return Vec::new() };
        let mut out = Vec::new();
        for (pid, tids) in Self::live(&k) {
            let proc_group = self.cgroup_of(&k, st, pid);
            if threads {
                out.extend(tids.into_iter().filter(|t| st.member.get(t).filter(|_| *t != pid).copied().unwrap_or(proc_group) == dir));
            } else if proc_group == dir || tids.iter().any(|t| *t != pid && st.member.get(t) == Some(&dir)) {
                out.push(pid);
            }
        }
        out
    }

    fn content(&self, st: &State, ino: u64) -> Result<String, i64> {
        let Kind::File { ctl, value, .. } = &st.nodes.get(&ino).ok_or(ENOENT)?.kind else { return Err(EISDIR) };
        let dir = Self::dir_of(st, ino);
        let lines = |v: Vec<i32>| v.iter().map(|p| format!("{p}\n")).collect::<String>();
        Ok(match ctl {
            Ctl::Procs => lines(self.members(st, dir, false)),
            Ctl::Tasks => lines(self.members(st, dir, true)),
            Ctl::Controllers => {
                let avail = if dir == ROOT {
                    V2_CONTROLLERS.to_string()
                } else {
                    let parent = match &st.nodes[&dir].kind {
                        Kind::Dir { parent, .. } => *parent,
                        _ => ROOT,
                    };
                    st.subtree.get(&parent).map(|s| s.iter().cloned().collect::<Vec<_>>().join(" ")).unwrap_or_default()
                };
                format!("{avail}\n")
            }
            Ctl::SubtreeControl => format!("{}\n", st.subtree.get(&dir).map(|s| s.iter().cloned().collect::<Vec<_>>().join(" ")).unwrap_or_default()),
            Ctl::WriteOnly | Ctl::Kill => return Err(EINVAL),
            Ctl::Value | Ctl::Text if value.is_empty() => "\n".into(),
            Ctl::Value | Ctl::Text => format!("{value}\n"),
        })
    }

    fn move_to(&self, st: &mut State, dir: u64, data: &[u8], thread: bool) -> Result<(), i64> {
        let k = self.kernel.upgrade().ok_or(ESRCH)?;
        let text = std::str::from_utf8(data).map_err(|_| EINVAL)?;
        for word in text.split_whitespace() {
            let id: i32 = word.parse().map_err(|_| EINVAL)?;
            let live = Self::live(&k);
            let Some((pid, tids)) = live.iter().find(|(p, t)| *p == id || (thread && t.contains(&id))) else { return Err(ESRCH) };
            if thread && id != *pid {
                st.member.insert(id, dir);
            } else {
                // The whole process moves, its threads with it.
                for t in tids {
                    st.member.remove(t);
                }
                st.member.insert(*pid, dir);
            }
        }
        Ok(())
    }

    /// The cgroup and all cgroups beneath it.
    fn subtree(st: &State, dir: u64) -> Vec<u64> {
        let mut out = vec![dir];
        let mut i = 0;
        while i < out.len() {
            if let Some(Kind::Dir { entries, .. }) = st.nodes.get(&out[i]).map(|n| &n.kind) {
                out.extend(entries.values().filter(|e| matches!(st.nodes.get(e).map(|n| &n.kind), Some(Kind::Dir { .. }))));
            }
            i += 1;
        }
        out
    }
}

fn err(e: i64) -> io::Error {
    io_err(e)
}

/// `k`'s hierarchies: v1 ones numbered from 1, in mount order; cgroup2 is 0.
fn hierarchies(k: &Kernel) -> Vec<(u32, Arc<CgroupFs>)> {
    let all: Vec<Arc<CgroupFs>> = HIERARCHIES.lock().unwrap().iter().filter_map(Weak::upgrade).filter(|h| std::ptr::eq(h.kernel.as_ptr(), k)).collect();
    let mut n = 0;
    all.into_iter().map(|h| (if h.v2 { 0 } else { n += 1; n }, h)).collect()
}

/// /proc/<pid>/cgroup: "<hierarchy>:<controllers>:<path>" per hierarchy.
pub fn proc_pid_cgroup(k: &Kernel, pid: i32) -> String {
    let mut hs = hierarchies(k);
    hs.sort_by_key(|(id, _)| std::cmp::Reverse(*id));
    hs.into_iter()
        .map(|(id, h)| {
            let st = h.st.lock().unwrap();
            let path = CgroupFs::path(&st, h.cgroup_of(k, &st, pid));
            format!("{id}:{}:{path}\n", h.controllers.join(","))
        })
        .collect()
}

/// /proc/cgroups: the v1 controllers and the hierarchy each is mounted in.
pub fn proc_cgroups(k: &Kernel) -> String {
    let hs = hierarchies(k);
    let mut s = String::from("#subsys_name\thierarchy\tnum_cgroups\tenabled\n");
    for c in V1_CONTROLLERS {
        let (id, n) = hs.iter().find(|(_, h)| h.controllers.contains(&c)).map_or((0, 1), |(id, h)| {
            let st = h.st.lock().unwrap();
            (*id, st.nodes.values().filter(|n| matches!(n.kind, Kind::Dir { .. })).count())
        });
        s += &format!("{c}\t{id}\t{n}\t1\n");
    }
    s
}

impl FileSystem for CgroupFs {
    fn fs_type(&self) -> &'static str {
        if self.v2 { "cgroup2" } else { "cgroup" }
    }

    fn root(&self) -> io::Result<u64> {
        Ok(ROOT)
    }

    fn stat(&self, ino: u64) -> io::Result<Stat> {
        let st = self.st.lock().unwrap();
        let n = st.nodes.get(&ino).ok_or_else(|| err(ENOENT))?;
        let nlink = match &n.kind {
            Kind::Dir { entries, .. } => 2 + entries.values().filter(|e| matches!(st.nodes.get(e).map(|n| &n.kind), Some(Kind::Dir { .. }))).count() as u32,
            Kind::File { .. } => 1,
        };
        Ok(Stat { dev: 0, ino, mode: n.mode, nlink, uid: n.uid, gid: n.gid, rdev: 0, size: 0, mtime: n.mtime })
    }

    fn lookup(&self, dir: u64, name: &str) -> io::Result<Option<u64>> {
        let st = self.st.lock().unwrap();
        match &st.nodes.get(&dir).ok_or_else(|| err(ENOENT))?.kind {
            Kind::Dir { entries, parent } => Ok(match name {
                "." => Some(dir),
                ".." => Some(*parent),
                _ => entries.get(name).copied(),
            }),
            Kind::File { .. } => Err(err(ENOTDIR)),
        }
    }

    fn readdir(&self, dir: u64) -> io::Result<Vec<Dirent>> {
        let st = self.st.lock().unwrap();
        let Some(Kind::Dir { entries, parent }) = st.nodes.get(&dir).map(|n| &n.kind) else { return Err(err(ENOTDIR)) };
        let mut out = vec![Dirent { name: ".".into(), ino: dir, dtype: 4 }, Dirent { name: "..".into(), ino: *parent, dtype: 4 }];
        for (name, &ino) in entries {
            let dtype = if matches!(st.nodes.get(&ino).map(|n| &n.kind), Some(Kind::Dir { .. })) { 4 } else { 8 };
            out.push(Dirent { name: name.clone(), ino, dtype });
        }
        Ok(out)
    }

    fn read_all(&self, ino: u64) -> io::Result<Arc<[u8]>> {
        let st = self.st.lock().unwrap();
        self.content(&st, ino).map(|s| s.into_bytes().into()).map_err(err)
    }

    fn write_ok(&self, ino: u64) -> bool {
        let st = self.st.lock().unwrap();
        match st.nodes.get(&ino).map(|n| &n.kind) {
            Some(Kind::Dir { .. }) => true,
            Some(Kind::File { ctl, .. }) => !matches!(ctl, Ctl::Text | Ctl::Controllers),
            None => false,
        }
    }

    fn write(&self, ino: u64, data: &[u8]) -> Result<usize, i64> {
        let mut st = self.st.lock().unwrap();
        let dir = Self::dir_of(&st, ino);
        let (ctl, default_is_int) = match &st.nodes.get(&ino).ok_or(ENOENT)?.kind {
            Kind::File { ctl, value, .. } => (*ctl, value.parse::<i64>().is_ok()),
            Kind::Dir { .. } => return Err(EISDIR),
        };
        let text = String::from_utf8_lossy(data);
        let value = text.trim_end_matches(['\n', '\0']).trim();
        match ctl {
            Ctl::Procs => self.move_to(&mut st, dir, data, false)?,
            Ctl::Tasks => self.move_to(&mut st, dir, data, true)?,
            Ctl::Kill => {
                if value != "1" {
                    return Err(EINVAL);
                }
                let k = self.kernel.upgrade().ok_or(ESRCH)?;
                let groups = Self::subtree(&st, dir);
                let victims: Vec<i32> = Self::live(&k).into_iter().map(|(p, _)| p).filter(|&p| groups.contains(&self.cgroup_of(&k, &st, p))).collect();
                drop(st);
                for pid in victims {
                    if let Some(p) = k.process(pid) {
                        k.send_process_signal(&p, SIGKILL, SigInfo::user(SIGKILL, 0));
                    }
                }
                return Ok(data.len());
            }
            Ctl::SubtreeControl => {
                let mut set = st.subtree.get(&dir).cloned().unwrap_or_default();
                for w in value.split_whitespace() {
                    let (on, c) = match (w.strip_prefix('+'), w.strip_prefix('-')) {
                        (Some(c), _) => (true, c),
                        (_, Some(c)) => (false, c),
                        _ => return Err(EINVAL),
                    };
                    if !V2_CONTROLLERS.split(' ').any(|x| x == c) {
                        return Err(EINVAL);
                    }
                    if on {
                        set.insert(c.to_string());
                    } else {
                        set.remove(c);
                    }
                }
                st.subtree.insert(dir, set);
            }
            Ctl::WriteOnly => {}
            Ctl::Value => {
                if default_is_int && value != "max" && value.parse::<i64>().is_err() {
                    return Err(EINVAL);
                }
                if let Some(Kind::File { value: v, .. }) = st.nodes.get_mut(&ino).map(|n| &mut n.kind) {
                    *v = value.to_string();
                }
            }
            Ctl::Text | Ctl::Controllers => return Err(EACCES),
        }
        Ok(data.len())
    }

    fn mkdir(&self, dir: u64, name: &str, mode: u32) -> Result<u64, i64> {
        if name.is_empty() || name.contains('/') || name == "." || name == ".." {
            return Err(EINVAL);
        }
        let mut st = self.st.lock().unwrap();
        let ino = st.next;
        st.next += 1;
        match st.nodes.get_mut(&dir).map(|n| &mut n.kind) {
            Some(Kind::Dir { entries, .. }) => {
                if entries.contains_key(name) {
                    return Err(EEXIST);
                }
                entries.insert(name.to_string(), ino);
            }
            Some(_) => return Err(ENOTDIR),
            None => return Err(ENOENT),
        }
        st.nodes.insert(ino, Node { mode: S_IFDIR | (mode & 0o7777), uid: 0, gid: 0, mtime: now(), kind: Kind::Dir { entries: BTreeMap::new(), parent: dir } });
        self.populate(&mut st, ino, false);
        Ok(ino)
    }

    fn create(&self, _dir: u64, _name: &str, _mode: u32, _rdev: u64) -> Result<u64, i64> {
        Err(EPERM)
    }

    fn symlink(&self, _dir: u64, _name: &str, _target: &str) -> Result<u64, i64> {
        Err(EPERM)
    }

    fn link(&self, _ino: u64, _dir: u64, _name: &str) -> Result<(), i64> {
        Err(EPERM)
    }

    fn rename(&self, _odir: u64, _oname: &str, _ndir: u64, _nname: &str, _noreplace: bool) -> Result<(), i64> {
        Err(EPERM)
    }

    /// rmdir removes an empty cgroup (control files go with it); files cannot be unlinked.
    fn unlink(&self, dir: u64, name: &str, rmdir: bool) -> Result<(), i64> {
        let mut st = self.st.lock().unwrap();
        let ino = match st.nodes.get(&dir).map(|n| &n.kind) {
            Some(Kind::Dir { entries, .. }) => *entries.get(name).ok_or(ENOENT)?,
            _ => return Err(ENOTDIR),
        };
        let files = match &st.nodes[&ino].kind {
            Kind::Dir { entries, .. } => {
                if entries.values().any(|e| matches!(st.nodes.get(e).map(|n| &n.kind), Some(Kind::Dir { .. }))) {
                    return Err(EBUSY);
                }
                entries.values().copied().collect::<Vec<_>>()
            }
            Kind::File { .. } if rmdir => return Err(ENOTDIR),
            Kind::File { .. } => return Err(EPERM),
        };
        if !rmdir {
            return Err(EISDIR);
        }
        if !self.members(&st, ino, true).is_empty() {
            return Err(EBUSY);
        }
        for f in files {
            st.nodes.remove(&f);
        }
        st.nodes.remove(&ino);
        st.subtree.remove(&ino);
        st.member.retain(|_, g| *g != ino);
        if let Some(Kind::Dir { entries, .. }) = st.nodes.get_mut(&dir).map(|n| &mut n.kind) {
            entries.remove(name);
        }
        Ok(())
    }

    fn set_attr(&self, ino: u64, mode: Option<u32>, owner: Option<(u32, u32)>, mtime: Option<u64>) -> Result<(), i64> {
        let mut st = self.st.lock().unwrap();
        let n = st.nodes.get_mut(&ino).ok_or(ENOENT)?;
        if let Some(m) = mode {
            n.mode = (n.mode & 0o170000) | (m & 0o7777);
        }
        if let Some((uid, gid)) = owner {
            if uid != u32::MAX {
                n.uid = uid;
            }
            if gid != u32::MAX {
                n.gid = gid;
            }
        }
        if let Some(t) = mtime {
            n.mtime = t;
        }
        Ok(())
    }
}

//! /proc, generated on demand from kernel state. `/proc/self` and
//! `/proc/thread-self` are rewritten to the caller's pid/tid during path
//! resolution, so this filesystem never needs to know who is asking.
//!
//! Inode numbers encode what a node is: kind (low 16 bits), pid (bits
//! 16..48), and an extra field (bits 48..64: an fd, a tid, or a table index).

use super::files::file_name;
use super::mount;
use super::sysctl::{self, Sysctl};
use super::{Kernel, Process};
use crate::errno::*;
use crate::paging::{PROT_EXEC, PROT_READ, PROT_WRITE};
use crate::phys::{PAGE, PHYS_MAX};
use crate::vfs::{Dirent, FileSystem, S_IFDIR, S_IFLNK, S_IFREG, Stat};
use std::io;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Weak};
use std::time::{SystemTime, UNIX_EPOCH};

const ROOT: u64 = 1;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum K {
    Root,
    Self_,
    ThreadSelf,
    Meminfo,
    Cpuinfo,
    Stat,
    Uptime,
    Loadavg,
    Version,
    Filesystems,
    Cmdline,
    Mounts,
    /// /proc/sys and everything in it (extra: the sysctl.rs index).
    Sysctl,
    // per process (pid in the inode)
    Pid,
    PCmdline,
    PComm,
    PExe,
    PCwd,
    PFd,
    PFdLink,
    PMaps,
    PStatus,
    PStat,
    PStatm,
    PTask,
    PAttr,
    PMounts,
    POom,
    PEnviron,
    // per thread (pid = tgid, extra = tid)
    Task,
    PMountinfo,
    POomAdj,
    POomScore,
    PTimerslack,
    /// /proc/<pid>/ns, its magic links, and the nsfs inodes they lead to (extra: index into NAMESPACES).
    PNs,
    PNsLink,
    NsFile,
    Cgroups,
    PCgroup,
    // SELinux attributes, in selinux::ATTRS order (extra = tid, or 0 for the main thread)
    AttrCurrent,
    AttrPrev,
    AttrExec,
    AttrFscreate,
    AttrKeycreate,
    AttrSockcreate,
}

const ALL: [K; 45] = [
    K::Root, K::Self_, K::ThreadSelf, K::Meminfo, K::Cpuinfo, K::Stat, K::Uptime, K::Loadavg, K::Version, K::Filesystems,
    K::Cmdline, K::Mounts, K::Sysctl, K::Pid, K::PCmdline, K::PComm, K::PExe, K::PCwd, K::PFd, K::PFdLink,
    K::PMaps, K::PStatus, K::PStat, K::PStatm, K::PTask, K::PAttr, K::PMounts, K::POom, K::PEnviron,
    K::Task, K::PMountinfo, K::POomAdj, K::POomScore, K::PTimerslack, K::PNs, K::PNsLink, K::NsFile,
    K::Cgroups, K::PCgroup,
    K::AttrCurrent, K::AttrPrev, K::AttrExec, K::AttrFscreate, K::AttrKeycreate, K::AttrSockcreate,
];
const ATTR_K: [K; 6] = [K::AttrCurrent, K::AttrPrev, K::AttrExec, K::AttrFscreate, K::AttrKeycreate, K::AttrSockcreate];

/// (pid, tid, index into selinux::ATTRS) of an attr file.
pub(super) fn attr_node(ino: u64) -> Option<(i32, i32, usize)> {
    let (k, pid, extra) = decode(ino)?;
    let which = ATTR_K.iter().position(|&x| x == k)?;
    Some((pid, if extra == 0 { pid } else { extra as i32 }, which))
}

/// One namespace of each kind, shared by every process: (name, kind, the inode
/// number Linux gives the initial one). The *_for_children links name the
/// same namespaces.
const NAMESPACES: [(&str, &str, u64); 10] = [
    ("cgroup", "cgroup", 4026531835),
    ("ipc", "ipc", 4026531839),
    ("mnt", "mnt", 4026531841),
    ("net", "net", 4026531840),
    ("pid", "pid", 4026531836),
    ("pid_for_children", "pid", 4026531836),
    ("time", "time", 4026531834),
    ("time_for_children", "time", 4026531834),
    ("user", "user", 4026531837),
    ("uts", "uts", 4026531838),
];

/// NAMESPACES' index of "mnt": the one kind with more than one namespace.
const MNT: u64 = 2;

/// An nsfs inode's `extra`: the NAMESPACES index, and for "mnt" which mount
/// namespace (captured when the link is followed, so an open fd keeps it).
fn ns_extra(i: u64, mnt_ns: u32) -> u64 {
    i | if i == MNT { (mnt_ns as u64) << 4 } else { 0 }
}

/// The namespace's inode number, as readlink and stat show it.
fn ns_inum(extra: u64) -> u64 {
    let (i, ns) = (extra & 0xf, extra >> 4);
    let base = NAMESPACES[i as usize % NAMESPACES.len()].2;
    if i == MNT && ns != 0 { 4026532000 + ns } else { base }
}

/// The kind ("mnt", "net", ...) of a namespace file opened through /proc/<pid>/ns.
pub(super) fn ns_kind(ino: u64) -> Option<&'static str> {
    match decode(ino)? {
        (K::NsFile, _, i) => NAMESPACES.get((i & 0xf) as usize).map(|n| n.1),
        _ => None,
    }
}

/// The mount namespace behind an open /proc/<pid>/ns/mnt.
pub(super) fn ns_mnt(ino: u64) -> Option<u32> {
    match decode(ino)? {
        (K::NsFile, _, i) if i & 0xf == MNT => Some((i >> 4) as u32),
        _ => None,
    }
}

/// Per-process values behind /proc/<pid>/{oom_score_adj,oom_adj}. comm and
/// timerslack_ns are per thread (control::ThreadAttrs).
#[derive(Clone, Default)]
pub struct Knobs {
    pub oom_score_adj: i32,
}

fn mk(k: K, pid: i32, extra: u64) -> u64 {
    (ALL.iter().position(|&x| x == k).unwrap() as u64 + 1) | (pid as u64) << 16 | extra << 48
}

fn decode(ino: u64) -> Option<(K, i32, u64)> {
    let k = *ALL.get(((ino & 0xffff) as usize).checked_sub(1)?)?;
    Some((k, ((ino >> 16) & 0xffff_ffff) as i32, ino >> 48))
}

enum Content {
    Dir(Vec<(String, u64)>),
    File(Vec<u8>),
    Link(String),
}

pub struct ProcFs {
    kernel: Weak<Kernel>,
}

fn err(e: i64) -> io::Error {
    io_err(e)
}

/// The androidboot.* parameters the Android Emulator passes, in its
/// virtio-gpu mode: the image's own ranchu vendor init then sets up gfxstream
/// over virtio-gpu (minigbm gralloc, emulation EGL, ranchu Vulkan), which
/// droidrt's DRM device and the emulator's host renderer serve.
const BOOT_ARGS: &str = "androidboot.hardware=ranchu androidboot.selinux=permissive androidboot.qemu=1 \
androidboot.hardware.gralloc=minigbm androidboot.hardware.gltransport=virtio-gpu-asg \
androidboot.qemu.gltransport.name=virtio-gpu-asg androidboot.qemu.gltransport.drawFlushInterval=800 \
androidboot.hardware.vulkan=ranchu androidboot.opengles.version=196609 androidboot.qemu.vsync=60 \
androidboot.debug.hwui.renderer=skiagl \
androidboot.hardware.cpu.pagesize=4096 androidboot.qemu.avd_name=droidrt";

impl ProcFs {
    pub fn new(kernel: Weak<Kernel>) -> Arc<ProcFs> {
        Arc::new(ProcFs { kernel })
    }

    fn kernel(&self) -> io::Result<Arc<Kernel>> {
        self.kernel.upgrade().ok_or_else(|| err(ENOENT))
    }

    fn proc(&self, pid: i32) -> io::Result<Arc<Process>> {
        self.kernel()?.process(pid).filter(|p| p.status.lock().unwrap().is_none()).ok_or_else(|| err(ENOENT))
    }

    fn content(&self, ino: u64) -> io::Result<Content> {
        let (k, pid, extra) = decode(ino).ok_or_else(|| err(ENOENT))?;
        let kernel = self.kernel()?;
        let text = |s: String| Ok(Content::File(s.into_bytes()));
        let d = |items: &[(&str, K)]| Ok(Content::Dir(items.iter().map(|(n, k)| (n.to_string(), mk(*k, pid, extra))).collect()));
        match k {
            K::Root => {
                let mut v: Vec<(String, u64)> = [
                    ("self", K::Self_),
                    ("thread-self", K::ThreadSelf),
                    ("meminfo", K::Meminfo),
                    ("cpuinfo", K::Cpuinfo),
                    ("stat", K::Stat),
                    ("uptime", K::Uptime),
                    ("loadavg", K::Loadavg),
                    ("version", K::Version),
                    ("filesystems", K::Filesystems),
                    ("cmdline", K::Cmdline),
                    ("mounts", K::Mounts),
                    ("cgroups", K::Cgroups),
                ]
                .iter()
                .map(|(n, k)| (n.to_string(), mk(*k, 0, 0)))
                .collect();
                v.push(("sys".into(), mk(K::Sysctl, 0, Sysctl::root() as u64)));
                let mut pids: Vec<i32> = kernel.procs.lock().unwrap().values().filter(|p| p.status.lock().unwrap().is_none()).map(|p| p.pid).collect();
                pids.sort();
                v.extend(pids.into_iter().map(|p| (p.to_string(), mk(K::Pid, p, 0))));
                Ok(Content::Dir(v))
            }
            // Rewritten to the caller during resolution; only seen by readdir/stat.
            K::Self_ | K::ThreadSelf => Ok(Content::Link(kernel.root_pid.load(Ordering::Relaxed).to_string())),
            K::Meminfo => {
                let total = PHYS_MAX / 1024;
                let used = kernel.phys.frames_in_use() * PAGE / 1024;
                text(format!(
                    "MemTotal:       {total:8} kB\nMemFree:        {:8} kB\nMemAvailable:   {:8} kB\nBuffers:               0 kB\nCached:                0 kB\nSwapCached:            0 kB\nSwapTotal:             0 kB\nSwapFree:              0 kB\nShmem:                 0 kB\n",
                    total - used,
                    total - used
                ))
            }
            K::Cpuinfo => text(cpuinfo()),
            K::Stat => {
                let n = cpus();
                let mut s = String::from("cpu  0 0 0 0 0 0 0 0 0 0\n");
                for i in 0..n {
                    s += &format!("cpu{i} 0 0 0 0 0 0 0 0 0 0\n");
                }
                let btime = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs()) - kernel.boot.elapsed().as_secs();
                s += &format!("intr 0\nctxt 0\nbtime {btime}\nprocesses {}\nprocs_running 1\nprocs_blocked 0\n", kernel.next_id.load(Ordering::Relaxed));
                text(s)
            }
            K::Uptime => {
                let up = kernel.boot.elapsed().as_secs_f64();
                text(format!("{up:.2} {:.2}\n", up * cpus() as f64))
            }
            K::Loadavg => text(format!("0.00 0.00 0.00 1/{} {}\n", kernel.procs.lock().unwrap().len(), kernel.next_id.load(Ordering::Relaxed) - 1)),
            K::Version => text("Linux version 6.6.0-droidrt (droidrt) #1 SMP PREEMPT\n".into()),
            K::Filesystems => text(mount::filesystems()),
            K::Cmdline => text(format!("{BOOT_ARGS}\n")),
            K::Mounts | K::PMounts | K::PMountinfo => {
                if pid != 0 {
                    self.proc(pid)?;
                }
                let vfs = kernel.vfs.as_deref().ok_or_else(|| err(ENOENT))?;
                text(if k == K::PMountinfo { mount::mountinfo(vfs) } else { mount::proc_mounts(vfs) })
            }
            K::Sysctl => match kernel.sysctl.entry(extra as u16).ok_or_else(|| err(ENOENT))? {
                sysctl::Entry::Dir(v) => Ok(Content::Dir(v.into_iter().map(|(n, i)| (n, mk(K::Sysctl, 0, i as u64))).collect())),
                sysctl::Entry::File(v) => text(format!("{v}\n")),
            },

            K::Pid => {
                self.proc(pid)?;
                d(&[
                    ("cmdline", K::PCmdline),
                    ("comm", K::PComm),
                    ("exe", K::PExe),
                    ("cwd", K::PCwd),
                    ("fd", K::PFd),
                    ("maps", K::PMaps),
                    ("status", K::PStatus),
                    ("stat", K::PStat),
                    ("statm", K::PStatm),
                    ("task", K::PTask),
                    ("attr", K::PAttr),
                    ("mounts", K::PMounts),
                    ("mountinfo", K::PMountinfo),
                    ("oom_score_adj", K::POom),
                    ("oom_adj", K::POomAdj),
                    ("oom_score", K::POomScore),
                    ("timerslack_ns", K::PTimerslack),
                    ("ns", K::PNs),
                    ("cgroup", K::PCgroup),
                    ("environ", K::PEnviron),
                ])
            }
            K::PCmdline => Ok(Content::File(self.proc(pid)?.cmdline.lock().unwrap().clone())),
            K::PComm => text(format!("{}\n", comm(&*self.proc(pid)?, extra as i32))),
            K::PExe => Ok(Content::Link(self.proc(pid)?.exe.lock().unwrap().clone())),
            K::PCwd => Ok(Content::Link(self.proc(pid)?.cwd.lock().unwrap().clone())),
            K::PFd => {
                let p = self.proc(pid)?;
                let list = p.files.lock().unwrap().list();
                Ok(Content::Dir(list.into_iter().map(|(fd, _)| (fd.to_string(), mk(K::PFdLink, pid, fd as u64))).collect()))
            }
            K::PFdLink => {
                let p = self.proc(pid)?;
                let f = p.files.lock().unwrap().get(extra as i64).map_err(err)?;
                Ok(Content::Link(file_name(&f)))
            }
            K::PMaps => {
                let p = self.proc(pid)?;
                let mm = p.mm.lock().unwrap();
                let mm = mm.as_ref().ok_or_else(|| err(ENOENT))?;
                let mut s = String::new();
                for (start, end, prot, shared, off, name) in mm.maps() {
                    let perms = format!(
                        "{}{}{}{}",
                        if prot & PROT_READ != 0 { 'r' } else { '-' },
                        if prot & PROT_WRITE != 0 { 'w' } else { '-' },
                        if prot & PROT_EXEC != 0 { 'x' } else { '-' },
                        if shared { 's' } else { 'p' }
                    );
                    let line = format!("{start:08x}-{end:08x} {perms} {off:08x} 00:00 0");
                    s += &match name {
                        Some(n) => format!("{line:<73}{n}\n"),
                        None => format!("{line}\n"),
                    };
                }
                text(s)
            }
            K::PStatus | K::PStat | K::PStatm => {
                let p = self.proc(pid)?;
                let threads = p.threads.lock().unwrap().len().max(1);
                let (virt, rss) = p.mm.lock().unwrap().as_ref().map_or((0, 0), |m| m.usage());
                let ppid = p.ppid.load(Ordering::Relaxed);
                let name = comm(&p, extra as i32);
                let c = p.creds.lock().unwrap().clone();
                let (pgid, sid) = {
                    let a = p.attrs.lock().unwrap();
                    (a.pgid, a.sid)
                };
                let ta = thread_of(&p, extra as i32).map(|t| t.attrs.lock().unwrap().clone()).unwrap_or_default();
                match k {
                    K::PStatus => {
                        let groups: Vec<String> = c.groups.iter().map(|g| g.to_string()).collect();
                        text(format!(
                            "Name:\t{name}\nUmask:\t0022\nState:\tR (running)\nTgid:\t{pid}\nNgid:\t0\nPid:\t{pid}\nPPid:\t{ppid}\nTracerPid:\t0\nUid:\t{}\t{}\t{}\t{}\nGid:\t{}\t{}\t{}\t{}\nFDSize:\t64\nGroups:\t{}\nVmPeak:\t{} kB\nVmSize:\t{} kB\nVmRSS:\t{} kB\nThreads:\t{threads}\nSigQ:\t0/0\nSigPnd:\t0000000000000000\nShdPnd:\t0000000000000000\nCapInh:\t{:016x}\nCapPrm:\t{:016x}\nCapEff:\t{:016x}\nCapBnd:\t{:016x}\nCapAmb:\t{:016x}\nNoNewPrivs:\t{}\nSeccomp:\t{}\nSeccomp_filters:\t{}\nCpus_allowed_list:\t0-{}\n",
                            c.uid, c.euid, c.suid, c.fsuid, c.gid, c.egid, c.sgid, c.fsgid,
                            groups.join(" "),
                            virt / 1024,
                            virt / 1024,
                            rss / 1024,
                            c.inh, c.prm, c.eff, c.bnd, c.amb,
                            ta.no_new_privs as u32, ta.seccomp, ta.filters,
                            cpus() - 1
                        ))
                    }
                    K::PStat => text(format!(
                        "{pid} ({name}) R {ppid} {pgid} {sid} 0 -1 4194560 0 0 0 0 0 0 0 0 {} {} {threads} 0 0 {virt} {} 18446744073709551615 0 0 0 0 0 0 0 0 0 0 0 0 17 0 {} {} 0 0 0 0 0 0 0 0 0 0 0\n",
                        ta.sched.proc_priority(),
                        ta.sched.nice,
                        rss / PAGE,
                        ta.sched.prio,
                        ta.sched.policy
                    )),
                    _ => text(format!("{} {} 0 0 0 0 0\n", virt / PAGE, rss / PAGE)),
                }
            }
            K::PTask => {
                let p = self.proc(pid)?;
                let tids: Vec<i32> = p.threads.lock().unwrap().iter().map(|t| t.tid).collect();
                Ok(Content::Dir(tids.into_iter().map(|t| (t.to_string(), mk(K::Task, pid, t as u64))).collect()))
            }
            // A thread directory: the process's view, with the thread's comm and attributes.
            K::Task => Ok(Content::Dir([("comm", K::PComm), ("stat", K::PStat), ("status", K::PStatus), ("attr", K::PAttr), ("cgroup", K::PCgroup), ("ns", K::PNs)].iter().map(|(n, k)| (n.to_string(), mk(*k, pid, extra))).collect())),
            K::PAttr => Ok(Content::Dir(super::selinux::ATTRS.iter().zip(ATTR_K).map(|(n, k)| (n.to_string(), mk(k, pid, extra))).collect())),
            K::AttrCurrent | K::AttrPrev | K::AttrExec | K::AttrFscreate | K::AttrKeycreate | K::AttrSockcreate => {
                let (_, tid, which) = attr_node(ino).ok_or_else(|| err(ENOENT))?;
                Ok(Content::File(super::selinux::attr(&*self.proc(pid)?, tid, which)))
            }
            K::POom => text(format!("{}\n", self.proc(pid)?.knobs.lock().unwrap().oom_score_adj)),
            K::POomAdj => {
                // Linux's legacy scale: -17 (OOM_DISABLE) ..= 15.
                let adj = self.proc(pid)?.knobs.lock().unwrap().oom_score_adj;
                text(format!("{}\n", if adj == 1000 { 15 } else { adj * 17 / 1000 }))
            }
            K::POomScore => {
                let p = self.proc(pid)?;
                let rss = p.mm.lock().unwrap().as_ref().map_or(0, |m| m.usage().1);
                let adj = p.knobs.lock().unwrap().oom_score_adj as i64;
                text(format!("{}\n", ((rss as u128 * 1000 / PHYS_MAX as u128) as i64 + adj).clamp(0, 2000)))
            }
            K::PTimerslack => text(format!("{}\n", thread_of(&*self.proc(pid)?, extra as i32).ok_or_else(|| err(ESRCH))?.attrs.lock().unwrap().timer_slack())),
            K::PNs => {
                self.proc(pid)?;
                Ok(Content::Dir(NAMESPACES.iter().enumerate().map(|(i, n)| (n.0.to_string(), mk(K::PNsLink, pid, i as u64))).collect()))
            }
            K::PNsLink => {
                let p = self.proc(pid)?;
                let kind = NAMESPACES[extra as usize % NAMESPACES.len()].1;
                Ok(Content::Link(format!("{kind}:[{}]", ns_inum(ns_extra(extra, p.mnt_ns.load(Ordering::Relaxed))))))
            }
            K::NsFile => Ok(Content::File(Vec::new())),
            K::Cgroups => text(super::cgroup::proc_cgroups(&kernel)),
            K::PCgroup => {
                self.proc(pid)?;
                text(super::cgroup::proc_pid_cgroup(&kernel, pid))
            }
            K::PEnviron => Ok(Content::File(Vec::new())),
        }
    }
}

/// Thread `tid` of `p`, or its main thread for 0 (any thread if that one is gone).
fn thread_of(p: &Process, tid: i32) -> Option<Arc<super::Thread>> {
    let threads = p.threads.lock().unwrap();
    let want = if tid == 0 { p.pid } else { tid };
    threads.iter().find(|t| t.tid == want).or(threads.first()).cloned()
}

fn comm(p: &Process, tid: i32) -> String {
    match thread_of(p, tid).map(|t| t.attrs.lock().unwrap().comm.clone()) {
        Some(c) if !c.is_empty() => c,
        _ => super::control::comm_of(&p.exe.lock().unwrap()),
    }
}

/// An integer written to a /proc file (kstrtoint after strstrip; base 0).
fn parse_int(data: &[u8]) -> Result<i64, i64> {
    let s = std::str::from_utf8(data).map_err(|_| EINVAL)?.trim();
    let (neg, s) = s.strip_prefix('-').map_or((false, s), |r| (true, r));
    let v = match s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        Some(h) => i64::from_str_radix(h, 16),
        None if s.len() > 1 && s.starts_with('0') => i64::from_str_radix(&s[1..], 8),
        None => s.parse(),
    }
    .map_err(|_| EINVAL)?;
    Ok(if neg { -v } else { v })
}

fn cpus() -> usize {
    std::thread::available_parallelism().map_or(1, |n| n.get()).min(64)
}

fn cpuinfo() -> String {
    let mut s = String::new();
    for i in 0..cpus() {
        if cfg!(target_arch = "aarch64") {
            s += &format!(
                "processor\t: {i}\nBogoMIPS\t: 48.00\nFeatures\t: fp asimd evtstrm aes pmull sha1 sha2 crc32 atomics fphp asimdhp cpuid asimdrdm lrcpc dcpop asimddp\nCPU implementer\t: 0x61\nCPU architecture: 8\nCPU variant\t: 0x0\nCPU part\t: 0x000\nCPU revision\t: 0\n\n"
            );
        } else {
            s += &format!("processor\t: {i}\nvendor_id\t: droidrt\nmodel name\t: droidrt virtual CPU\nflags\t\t: fpu sse sse2 ssse3 sse4_1 sse4_2 popcnt avx avx2\n\n");
        }
    }
    s
}

impl FileSystem for ProcFs {
    fn fs_type(&self) -> &'static str {
        "proc"
    }

    fn root(&self) -> io::Result<u64> {
        Ok(mk(K::Root, 0, 0))
    }

    fn stat(&self, ino: u64) -> io::Result<Stat> {
        let (mode, size) = match self.content(ino)? {
            Content::Dir(_) if matches!(decode(ino), Some((K::PNs, _, _))) => (S_IFDIR | 0o511, 0),
            Content::Dir(_) => (S_IFDIR | 0o555, 0),
            Content::Link(t) => (S_IFLNK | 0o777, t.len() as u64),
            Content::File(_) if matches!(decode(ino), Some((K::PTimerslack, _, _))) => (S_IFREG | 0o666, 0),
            Content::File(_) if self.write_ok(ino) => (S_IFREG | 0o644, 0),
            Content::File(_) => (S_IFREG | 0o444, 0), // like Linux, procfs files report size 0
        };
        let mtime = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs());
        // An nsfs inode's number is the namespace's id.
        let st_ino = match decode(ino) {
            Some((K::NsFile, _, i)) => ns_inum(i),
            _ => ino,
        };
        Ok(Stat { dev: 0, ino: st_ino, mode, nlink: 1, uid: 0, gid: 0, rdev: 0, size, mtime })
    }

    fn write_ok(&self, ino: u64) -> bool {
        match decode(ino) {
            Some((K::Sysctl, _, i)) => Sysctl::writable(i as u16),
            Some((K::POom | K::POomAdj | K::PComm | K::PTimerslack, _, _)) => true,
            _ => false,
        }
    }

    fn write(&self, ino: u64, data: &[u8]) -> Result<usize, i64> {
        let (k, pid, extra) = decode(ino).ok_or(ENOENT)?;
        let kernel = self.kernel().map_err(|_| ENOENT)?;
        if k == K::Sysctl {
            return kernel.sysctl.write(extra as u16, data);
        }
        let p = self.proc(pid).map_err(|_| ESRCH)?;
        match k {
            // Like Linux: the first 15 bytes, newline and all.
            K::PComm => {
                let t = thread_of(&p, extra as i32).ok_or(ESRCH)?;
                t.attrs.lock().unwrap().comm = String::from_utf8_lossy(&data[..data.len().min(15)]).into_owned();
                return Ok(data.len());
            }
            K::PTimerslack => {
                let v = parse_int(data).ok().and_then(|v| u64::try_from(v).ok()).ok_or(EINVAL)?;
                thread_of(&p, extra as i32).ok_or(ESRCH)?.attrs.lock().unwrap().set_timer_slack(v);
                return Ok(data.len());
            }
            _ => {}
        }
        let mut knobs = p.knobs.lock().unwrap();
        match k {
            K::POom => {
                let v = parse_int(&data[..data.len().min(23)])?;
                knobs.oom_score_adj = i32::try_from(v).ok().filter(|v| (-1000..=1000).contains(v)).ok_or(EINVAL)?;
            }
            K::POomAdj => {
                let v = parse_int(&data[..data.len().min(23)])?;
                if !(-17..=15).contains(&v) {
                    return Err(EINVAL);
                }
                knobs.oom_score_adj = if v == 15 { 1000 } else { (v * 1000 / 17) as i32 };
            }
            _ => return Err(EINVAL),
        }
        Ok(data.len())
    }

    fn changes(&self, ino: u64) -> Option<Arc<std::sync::atomic::AtomicU64>> {
        match decode(ino)? {
            (K::Mounts | K::PMounts | K::PMountinfo, _, _) => Some(self.kernel.upgrade()?.vfs.as_ref()?.events()),
            _ => None,
        }
    }

    fn magic_link(&self, ino: u64) -> Option<u64> {
        match decode(ino)? {
            (K::PNsLink, pid, i) => Some(mk(K::NsFile, pid, ns_extra(i, self.proc(pid).ok()?.mnt_ns.load(Ordering::Relaxed)))),
            _ => None,
        }
    }

    fn lookup(&self, dir: u64, name: &str) -> io::Result<Option<u64>> {
        if name == "." {
            return Ok(Some(dir));
        }
        if name == ".." {
            return Ok(Some(match decode(dir) {
                Some((K::PAttr, pid, tid)) if tid != 0 => mk(K::Task, pid, tid),
                Some((K::PAttr | K::PFd | K::PTask, pid, _)) => mk(K::Pid, pid, 0),
                Some((K::Task, pid, _)) => mk(K::PTask, pid, 0),
                Some((K::PNs, pid, _)) => mk(K::Pid, pid, 0),
                Some((K::Sysctl, _, i)) if i as u16 != Sysctl::root() => mk(K::Sysctl, 0, Sysctl::parent(i as u16) as u64),
                _ => ROOT,
            }));
        }
        match self.content(dir)? {
            Content::Dir(entries) => Ok(entries.into_iter().find(|(n, _)| n == name).map(|(_, i)| i)),
            _ => Err(err(ENOTDIR)),
        }
    }

    fn readdir(&self, dir: u64) -> io::Result<Vec<Dirent>> {
        let Content::Dir(entries) = self.content(dir)? else { return Err(err(ENOTDIR)) };
        let mut out = vec![Dirent { name: ".".into(), ino: dir, dtype: 4 }, Dirent { name: "..".into(), ino: ROOT, dtype: 4 }];
        for (name, i) in entries {
            let dtype = match self.content(i) {
                Ok(Content::Dir(_)) => 4,
                Ok(Content::Link(_)) => 10,
                _ => 8,
            };
            out.push(Dirent { name, ino: i, dtype });
        }
        Ok(out)
    }

    fn read_all(&self, ino: u64) -> io::Result<Arc<[u8]>> {
        match self.content(ino)? {
            Content::Link(t) => Ok(t.into_bytes().into()),
            Content::Dir(_) => Err(err(EISDIR)),
            Content::File(_) if matches!(decode(ino), Some((K::NsFile, _, _))) => Err(err(EINVAL)),
            Content::File(b) => Ok(b.into()),
        }
    }
}

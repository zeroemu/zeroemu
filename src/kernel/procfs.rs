//! /proc, generated on demand from kernel state. `/proc/self` and
//! `/proc/thread-self` are rewritten to the caller's pid/tid during path
//! resolution, so this filesystem never needs to know who is asking.
//!
//! Inode numbers encode what a node is: kind (low 16 bits), pid (bits
//! 16..48), and an extra field (bits 48..64: an fd or a tid).

use super::files::file_name;
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
    Sys,
    SysKernel,
    SysVm,
    SysRandom,
    Osrelease,
    Ostype,
    Hostname,
    PidMax,
    BootId,
    Uuid,
    Entropy,
    Overcommit,
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
    PAttrCurrent,
    PMounts,
    POom,
    PEnviron,
    // per thread (pid = tgid, extra = tid)
    Task,
}

const ALL: [K; 42] = [
    K::Root, K::Self_, K::ThreadSelf, K::Meminfo, K::Cpuinfo, K::Stat, K::Uptime, K::Loadavg, K::Version, K::Filesystems,
    K::Cmdline, K::Mounts, K::Sys, K::SysKernel, K::SysVm, K::SysRandom, K::Osrelease, K::Ostype, K::Hostname, K::PidMax,
    K::BootId, K::Uuid, K::Entropy, K::Overcommit, K::Pid, K::PCmdline, K::PComm, K::PExe, K::PCwd, K::PFd, K::PFdLink,
    K::PMaps, K::PStatus, K::PStat, K::PStatm, K::PTask, K::PAttr, K::PAttrCurrent, K::PMounts, K::POom, K::PEnviron,
    K::Task,
];

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
    boot_id: String,
}

fn err(e: i64) -> io::Error {
    io_err(e)
}

impl ProcFs {
    pub fn new(kernel: Weak<Kernel>) -> Arc<ProcFs> {
        let mut r = [0u8; 16];
        crate::phys::random_bytes(&mut r);
        let h: String = r.iter().map(|b| format!("{b:02x}")).collect();
        let boot_id = format!("{}-{}-{}-{}-{}", &h[0..8], &h[8..12], &h[12..16], &h[16..20], &h[20..32]);
        Arc::new(ProcFs { kernel, boot_id })
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
        let d = |items: &[(&str, K)]| Ok(Content::Dir(items.iter().map(|(n, k)| (n.to_string(), mk(*k, pid, 0))).collect()));
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
                    ("sys", K::Sys),
                ]
                .iter()
                .map(|(n, k)| (n.to_string(), mk(*k, 0, 0)))
                .collect();
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
            K::Filesystems => text("nodev\tproc\nnodev\ttmpfs\nnodev\tsysfs\nnodev\tselinuxfs\n\terofs\n\text4\n".into()),
            K::Cmdline => text("androidboot.hardware=droidrt androidboot.selinux=permissive\n".into()),
            K::Mounts | K::PMounts => {
                let vfs = kernel.vfs.as_deref().ok_or_else(|| err(ENOENT))?;
                let mut s = String::new();
                for (path, ty) in vfs.mounts() {
                    let virtual_fs = matches!(ty, "tmpfs" | "proc" | "sysfs" | "selinuxfs");
                    let src = if virtual_fs { ty } else { "/dev/block/droidrt" };
                    let opts = if matches!(ty, "tmpfs" | "selinuxfs" | "sysfs") { "rw" } else { "ro" };
                    s += &format!("{src} {path} {ty} {opts},relatime 0 0\n");
                }
                text(s)
            }
            K::Sys => d(&[("kernel", K::SysKernel), ("vm", K::SysVm)]),
            K::SysKernel => d(&[("osrelease", K::Osrelease), ("ostype", K::Ostype), ("hostname", K::Hostname), ("pid_max", K::PidMax), ("random", K::SysRandom)]),
            K::SysVm => d(&[("overcommit_memory", K::Overcommit)]),
            K::SysRandom => d(&[("boot_id", K::BootId), ("uuid", K::Uuid), ("entropy_avail", K::Entropy)]),
            K::Osrelease => text("6.6.0-droidrt\n".into()),
            K::Ostype => text("Linux\n".into()),
            K::Hostname => text("localhost\n".into()),
            K::PidMax => text("32768\n".into()),
            K::BootId => text(format!("{}\n", self.boot_id)),
            K::Uuid => {
                let mut r = [0u8; 16];
                crate::phys::random_bytes(&mut r);
                let h: String = r.iter().map(|b| format!("{b:02x}")).collect();
                text(format!("{}-{}-4{}-{}-{}\n", &h[0..8], &h[8..12], &h[13..16], &h[16..20], &h[20..32]))
            }
            K::Entropy => text("256\n".into()),
            K::Overcommit => text("1\n".into()),

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
                    ("oom_score_adj", K::POom),
                    ("environ", K::PEnviron),
                ])
            }
            K::PCmdline => Ok(Content::File(self.proc(pid)?.cmdline.lock().unwrap().clone())),
            K::PComm => text(format!("{}\n", comm(&*self.proc(pid)?))),
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
                let name = comm(&p);
                match k {
                    K::PStatus => text(format!(
                        "Name:\t{name}\nUmask:\t0022\nState:\tR (running)\nTgid:\t{pid}\nNgid:\t0\nPid:\t{pid}\nPPid:\t{ppid}\nTracerPid:\t0\nUid:\t0\t0\t0\t0\nGid:\t0\t0\t0\t0\nFDSize:\t64\nGroups:\t\nVmPeak:\t{} kB\nVmSize:\t{} kB\nVmRSS:\t{} kB\nThreads:\t{threads}\nSigQ:\t0/0\nSigPnd:\t0000000000000000\nShdPnd:\t0000000000000000\nCapInh:\t0000000000000000\nCapPrm:\t000001ffffffffff\nCapEff:\t000001ffffffffff\nCapBnd:\t000001ffffffffff\nSeccomp:\t0\nCpus_allowed_list:\t0-{}\n",
                        virt / 1024,
                        virt / 1024,
                        rss / 1024,
                        cpus() - 1
                    )),
                    K::PStat => text(format!(
                        "{pid} ({name}) R {ppid} {pid} {pid} 0 -1 4194560 0 0 0 0 0 0 0 0 20 0 {threads} 0 0 {virt} {} 18446744073709551615 0 0 0 0 0 0 0 0 0 0 0 0 17 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n",
                        rss / PAGE
                    )),
                    _ => text(format!("{} {} 0 0 0 0 0\n", virt / PAGE, rss / PAGE)),
                }
            }
            K::PTask => {
                let p = self.proc(pid)?;
                let tids: Vec<i32> = p.threads.lock().unwrap().iter().map(|t| t.tid).collect();
                Ok(Content::Dir(tids.into_iter().map(|t| (t.to_string(), mk(K::Task, pid, t as u64))).collect()))
            }
            // A thread directory: the process's view (good enough for comm/stat/status).
            K::Task => d(&[("comm", K::PComm), ("stat", K::PStat), ("status", K::PStatus), ("attr", K::PAttr)]),
            K::PAttr => d(&[("current", K::PAttrCurrent)]),
            K::PAttrCurrent => Ok(Content::File(b"u:r:su:s0\0".to_vec())),
            K::POom => text("0\n".into()),
            K::PEnviron => Ok(Content::File(Vec::new())),
        }
    }
}

fn comm(p: &Process) -> String {
    let exe = p.exe.lock().unwrap();
    exe.rsplit('/').next().unwrap_or("").chars().take(15).collect()
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
            Content::Dir(_) => (S_IFDIR | 0o555, 0),
            Content::Link(t) => (S_IFLNK | 0o777, t.len() as u64),
            Content::File(_) => (S_IFREG | 0o444, 0), // like Linux, procfs files report size 0
        };
        let mtime = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs());
        Ok(Stat { dev: 0, ino, mode, nlink: 1, uid: 0, gid: 0, rdev: 0, size, mtime })
    }

    fn lookup(&self, dir: u64, name: &str) -> io::Result<Option<u64>> {
        if name == "." {
            return Ok(Some(dir));
        }
        if name == ".." {
            return Ok(Some(match decode(dir) {
                Some((K::PAttr | K::PFd | K::PTask, pid, _)) => mk(K::Pid, pid, 0),
                Some((K::Task, pid, _)) => mk(K::PTask, pid, 0),
                Some((K::SysKernel | K::SysVm, _, _)) => mk(K::Sys, 0, 0),
                Some((K::SysRandom, _, _)) => mk(K::SysKernel, 0, 0),
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
            Content::File(b) => Ok(b.into()),
            Content::Link(t) => Ok(t.into_bytes().into()),
            Content::Dir(_) => Err(err(EISDIR)),
        }
    }
}

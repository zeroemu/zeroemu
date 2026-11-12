//! mount(2), umount2(2), unshare(2) and setns(2), plus the text of
//! /proc/mounts and /proc/<pid>/mountinfo.
//!
//! unshare(CLONE_NEWNS) gives the caller a copy of its mount namespace and
//! setns() moves it to the one behind a /proc/<pid>/ns/mnt fd (vfs.rs keeps
//! the tables). Every other namespace kind has a single instance.

use super::cgroup::{CgroupFs, V1_CONTROLLERS};
use super::{Kernel, Thread, block, int};
use crate::arch::Sysno;
use crate::errno::*;
use crate::tmpfs::Tmpfs;
use crate::vfs::*;
use std::fmt::Write;
use std::sync::Arc;
use std::sync::atomic::Ordering;

const AT_FDCWD: i64 = -100;
const S_IFBLK: u32 = 0o060000;
const S_IFDIR: u32 = 0o040000;
const ENOTBLK: i64 = 15;

const MS_REMOUNT: u64 = 32;
const MS_BIND: u64 = 4096;
const MS_MOVE: u64 = 8192;
const MS_REC: u64 = 16384;
const MS_SILENT: u64 = 32768;
const MS_UNBINDABLE: u64 = 1 << 17;
const MS_PRIVATE: u64 = 1 << 18;
const MS_SLAVE: u64 = 1 << 19;
const MS_SHARED: u64 = 1 << 20;
const MS_KERNMOUNT: u64 = 1 << 22;
const MS_STRICTATIME: u64 = 1 << 24;
const MS_MGC_MSK: u64 = 0xffff_0000;
const MS_MGC_VAL: u64 = 0xc0ed_0000;
const MNT_ATIME_MASK: u64 = MS_NOATIME | MS_NODIRATIME | MS_RELATIME;
const PROPAGATION: u64 = MS_SHARED | MS_PRIVATE | MS_SLAVE | MS_UNBINDABLE;

const MNT_FORCE: u64 = 1;
const MNT_DETACH: u64 = 2;
const MNT_EXPIRE: u64 = 4;
const UMOUNT_NOFOLLOW: u64 = 8;

const CLONE_VM: u64 = 0x100;
const CLONE_FS: u64 = 0x200;
const CLONE_FILES: u64 = 0x400;
const CLONE_SIGHAND: u64 = 0x800;
const CLONE_THREAD: u64 = 0x10000;
const CLONE_NEWNS: u64 = 0x20000;
const CLONE_SYSVSEM: u64 = 0x40000;

/// Filesystem types mount(2) knows, in /proc/filesystems order: (name, needs a block device).
const FILESYSTEMS: [(&str, bool); 21] = [
    ("sysfs", false),
    ("tmpfs", false),
    ("proc", false),
    ("cgroup", false),
    ("cgroup2", false),
    ("cpuset", false),
    ("devpts", false),
    ("configfs", false),
    ("debugfs", false),
    ("tracefs", false),
    ("securityfs", false),
    ("bpf", false),
    ("ramfs", false),
    ("pstore", false),
    ("ext4", true),
    ("fuse", false),
    ("fusectl", false),
    ("selinuxfs", false),
    ("binder", false),
    ("functionfs", false),
    ("erofs", true),
];

/// Kernel-wide filesystems: mounting one again shows the same instance.
const SINGLE_INSTANCE: [&str; 9] = ["sysfs", "selinuxfs", "debugfs", "tracefs", "securityfs", "pstore", "configfs", "bpf", "fusectl"];

pub fn handles(no: Sysno) -> bool {
    use Sysno::*;
    matches!(no, mount | umount2 | unshare | setns)
}

/// /proc/filesystems.
pub fn filesystems() -> String {
    FILESYSTEMS.iter().map(|(n, block)| format!("{}\t{n}\n", if *block { "" } else { "nodev" })).collect()
}

/// mount(2)'s comma-separated options as (key, value).
fn parse_options(data: &str) -> Vec<(&str, Option<&str>)> {
    data.split(',').filter(|o| !o.is_empty()).map(|o| match o.split_once('=') {
        Some((k, v)) => (k, Some(v)),
        None => (o, None),
    }).collect()
}

/// Options SELinux consumes before the filesystem sees them.
fn is_security_option(key: &str) -> bool {
    matches!(key, "context" | "fscontext" | "defcontext" | "rootcontext" | "seclabel")
}

/// A size with an optional k/m/g/t suffix (the kernel's memparse), or a percentage of RAM.
fn memparse(v: &str) -> Result<u64, i64> {
    if let Some(p) = v.strip_suffix('%') {
        let p: u64 = p.parse().map_err(|_| EINVAL)?;
        return (crate::phys::ram() / 100).checked_mul(p).ok_or(EINVAL);
    }
    let (num, shift) = match v.as_bytes().last() {
        Some(b'k' | b'K') => (&v[..v.len() - 1], 10),
        Some(b'm' | b'M') => (&v[..v.len() - 1], 20),
        Some(b'g' | b'G') => (&v[..v.len() - 1], 30),
        Some(b't' | b'T') => (&v[..v.len() - 1], 40),
        _ => (v, 0),
    };
    let n: u64 = num.parse().map_err(|_| EINVAL)?;
    n.checked_shl(shift).ok_or(EINVAL)
}

fn octal(v: Option<&str>) -> Result<u32, i64> {
    u32::from_str_radix(v.ok_or(EINVAL)?, 8).map(|m| m & 0o7777).map_err(|_| EINVAL)
}

fn number(v: Option<&str>) -> Result<u32, i64> {
    v.ok_or(EINVAL)?.parse().map_err(|_| EINVAL)
}

/// /proc/mounts escapes: space, tab, newline and backslash as octal.
fn mangle(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            ' ' => out.push_str("\\040"),
            '\t' => out.push_str("\\011"),
            '\n' => out.push_str("\\012"),
            '\\' => out.push_str("\\134"),
            c => out.push(c),
        }
    }
    out
}

/// Whether SELinux labels files of this type (Linux then shows "seclabel").
fn seclabel(ty: &str) -> bool {
    !matches!(ty, "proc" | "selinuxfs" | "cgroup" | "cgroup2" | "fuse" | "fusectl" | "securityfs")
}

/// Superblock options as show_sb_opts and the filesystem print them.
fn super_options(m: &Mount) -> String {
    let flags = m.sb.flags.load(Ordering::Relaxed);
    let mut s = String::new();
    for (bit, name) in [(MS_SYNCHRONOUS, ",sync"), (MS_DIRSYNC, ",dirsync"), (MS_MANDLOCK, ",mand"), (MS_LAZYTIME, ",lazytime")] {
        if flags & bit != 0 {
            s += name;
        }
    }
    if seclabel(m.sb.fs_type()) {
        s += ",seclabel";
    }
    s
}

fn mount_options(m: &Mount) -> String {
    let flags = m.flags.load(Ordering::Relaxed);
    let mut s = String::new();
    for (bit, name) in [(MS_NOSUID, ",nosuid"), (MS_NODEV, ",nodev"), (MS_NOEXEC, ",noexec"), (MS_NOATIME, ",noatime"), (MS_NODIRATIME, ",nodiratime"), (MS_RELATIME, ",relatime"), (MS_NOSYMFOLLOW, ",nosymfollow")] {
        if flags & bit != 0 {
            s += name;
        }
    }
    s
}

fn fs_options(m: &Mount) -> String {
    let o = m.sb.options.lock().unwrap();
    if o.is_empty() { String::new() } else { format!(",{o}") }
}

fn rw(ro: bool) -> &'static str {
    if ro { "ro" } else { "rw" }
}

/// /proc/mounts (and /proc/<pid>/mounts), as show_vfsmnt prints it.
pub fn proc_mounts(vfs: &Vfs) -> String {
    let mut s = String::new();
    for m in vfs.mount_list() {
        let _ = writeln!(s, "{} {} {} {}{}{}{} 0 0", mangle(&m.sb.source), mangle(&m.path), m.sb.fs_type(), rw(m.readonly()), super_options(&m), mount_options(&m), fs_options(&m));
    }
    s
}

/// /proc/<pid>/mountinfo, as show_mountinfo prints it.
pub fn mountinfo(vfs: &Vfs) -> String {
    let mut s = String::new();
    for m in vfs.mount_list() {
        let p = *m.propagation.lock().unwrap();
        let mut tags = String::new();
        if p.shared != 0 {
            let _ = write!(tags, " shared:{}", p.shared);
        }
        if p.master != 0 {
            let _ = write!(tags, " master:{}", p.master);
        }
        if p.unbindable {
            tags += " unbindable";
        }
        let mnt_ro = m.flags.load(Ordering::Relaxed) & MS_RDONLY != 0;
        let sb_ro = m.sb.flags.load(Ordering::Relaxed) & MS_RDONLY != 0;
        let _ = writeln!(
            s,
            "{} {} {}:{} {} {} {}{}{tags} - {} {} {}{}{}",
            m.id,
            m.parent,
            block::major(m.sb.dev),
            block::minor(m.sb.dev),
            mangle(&m.root_path),
            mangle(&m.path),
            rw(mnt_ro),
            mount_options(&m),
            m.sb.fs_type(),
            mangle(&m.sb.source),
            rw(sb_ro),
            super_options(&m),
            fs_options(&m)
        );
    }
    s
}

/// f_type of statfs(2).
fn magic(fs_type: &str) -> u64 {
    match fs_type {
        "erofs" => 0xe0f5_e1e2,
        "ext4" => 0xef53,
        "tmpfs" => 0x0102_1994,
        "ramfs" => 0x8584_58f6,
        "proc" => 0x9fa0,
        "sysfs" => 0x6265_6572,
        "selinuxfs" => 0xf97c_ff8c,
        "devpts" => 0x1cd1,
        "cgroup" => 0x0027_e0eb,
        "cgroup2" => 0x6367_7270,
        "bpf" => 0xcafe_4a11,
        "tracefs" => 0x7472_6163,
        "debugfs" => 0x6462_6720,
        "securityfs" => 0x7363_6673,
        "pstore" => 0x6165_676c,
        "configfs" => 0x6265_6570,
        "functionfs" => 0x0a64_7361,
        "binder" => 0x6c6f_6f70,
        "fuse" => 0x6573_5546,
        "fusectl" => 0x6573_5543,
        _ => 0x5049_5045, // pipefs
    }
}

/// `struct statfs` (same 120-byte layout on arm64 and x86_64). `flags` are
/// the mount's MS_* flags; libselinux finds selinuxfs by its magic number.
pub fn statfs_bytes(fs_type: &str, flags: u64) -> [u8; 120] {
    statfs_with(fs_type, flags, None)
}

fn statfs_with(fs_type: &str, flags: u64, space: Option<(u64, u64)>) -> [u8; 120] {
    // ST_* values: the mount flags renumbered, plus ST_VALID.
    let mut st = 0x20;
    for (ms, bit) in [(MS_RDONLY, 1), (MS_NOSUID, 2), (MS_NODEV, 4), (MS_NOEXEC, 8), (MS_SYNCHRONOUS, 16), (MS_MANDLOCK, 64), (MS_NOATIME, 1024), (MS_NODIRATIME, 2048), (MS_RELATIME, 4096), (MS_NOSYMFOLLOW, 0x2000)] {
        if flags & ms != 0 {
            st |= bit;
        }
    }
    let mut b = [0u8; 120];
    b[0..8].copy_from_slice(&magic(fs_type).to_le_bytes()); // f_type
    b[8..16].copy_from_slice(&4096u64.to_le_bytes()); // f_bsize
    b[64..72].copy_from_slice(&255u64.to_le_bytes()); // f_namelen
    b[72..80].copy_from_slice(&4096u64.to_le_bytes()); // f_frsize
    b[80..88].copy_from_slice(&(st as u64).to_le_bytes()); // f_flags
    if let Some((total, free)) = space {
        for (off, v) in [(16, total / 4096), (24, free / 4096), (32, free / 4096)] {
            b[off..off + 8].copy_from_slice(&v.to_le_bytes()); // f_blocks, f_bfree, f_bavail
        }
    }
    b
}

/// statfs(2) of the filesystem `node` is on.
pub fn statfs_node(vfs: &Vfs, node: &Node) -> [u8; 120] {
    let m = node.mount();
    let flags = m.flags.load(Ordering::Relaxed) | m.sb.flags.load(Ordering::Relaxed);
    statfs_with(vfs.fs_type(node), flags, vfs.space(node))
}

impl Kernel {
    pub(super) fn mount_syscall(self: &Arc<Self>, no: Sysno, t: &Arc<Thread>, a: [u64; 6]) -> Result<i64, i64> {
        match no {
            Sysno::mount => self.sys_mount(t, a),
            Sysno::umount2 => self.sys_umount2(t, a[0], a[1]),
            Sysno::unshare => {
                let flags = a[0];
                // Trivial for a single-threaded caller: nothing is shared to begin with.
                let single = t.proc.threads.lock().unwrap().len() == 1;
                let ok = CLONE_NEWNS | CLONE_SYSVSEM | if single { CLONE_FS | CLONE_FILES | CLONE_VM | CLONE_SIGHAND | CLONE_THREAD } else { 0 };
                if flags & !ok != 0 {
                    return Err(EINVAL);
                }
                if flags & CLONE_NEWNS != 0 {
                    if !self.creds(t).capable(super::creds::CAP_SYS_ADMIN) {
                        return Err(EPERM);
                    }
                    let vfs = self.vfs.as_deref().ok_or(EINVAL)?;
                    let ns = vfs.clone_ns(t.proc.pid == 1);
                    vfs.ns_enter(ns);
                    vfs.ns_leave(t.proc.mnt_ns.swap(ns, Ordering::Relaxed));
                    crate::vfs::set_current_ns(ns);
                }
                Ok(0)
            }
            Sysno::setns => {
                let fd = int(a[0]);
                t.files().get(fd)?;
                let node = self.target(t, fd, 0, 0).map_err(|_| EINVAL)?;
                let vfs = self.vfs.as_deref().ok_or(EINVAL)?;
                let kind = (vfs.fs_type(&node) == "proc").then(|| super::procfs::ns_kind(node.ino)).flatten().ok_or(EINVAL)?;
                let want = match kind {
                    "mnt" => CLONE_NEWNS,
                    "cgroup" => 0x0200_0000,
                    "uts" => 0x0400_0000,
                    "ipc" => 0x0800_0000,
                    "user" => 0x1000_0000,
                    "pid" => 0x2000_0000,
                    "net" => 0x4000_0000,
                    _ => 0x80, // time
                };
                if a[1] != 0 && a[1] != want {
                    return Err(EINVAL);
                }
                if !self.creds(t).capable(super::creds::CAP_SYS_ADMIN) {
                    return Err(EPERM);
                }
                // One namespace of every other kind: already in it.
                if let Some(ns) = super::procfs::ns_mnt(node.ino) {
                    if !vfs.has_ns(ns) {
                        return Err(EINVAL);
                    }
                    vfs.ns_enter(ns);
                    vfs.ns_leave(t.proc.mnt_ns.swap(ns, Ordering::Relaxed));
                    crate::vfs::set_current_ns(ns);
                }
                Ok(0)
            }
            _ => Err(ENOSYS),
        }
    }

    fn sys_mount(self: &Arc<Self>, t: &Arc<Thread>, a: [u64; 6]) -> Result<i64, i64> {
        let vfs = self.vfs.as_deref().ok_or(ENOENT)?;
        let (source, target, fstype, data) = {
            let mut mm = t.proc.mm();
            let source = if a[0] == 0 { None } else { Some(mm.read_cstr(a[0])?) };
            let target = mm.read_cstr(a[1])?;
            let fstype = if a[2] == 0 { None } else { Some(mm.read_cstr(a[2])?) };
            let data = if a[4] == 0 { String::new() } else { mm.read_cstr(a[4])? };
            (source, target, fstype, data)
        };
        let mut flags = a[3];
        if flags & MS_MGC_MSK == MS_MGC_VAL {
            flags &= !MS_MGC_MSK;
        }
        let target = self.resolve(t, AT_FDCWD, &target, true)?;
        if !self.creds(t).capable(super::creds::CAP_SYS_ADMIN) {
            return Err(EPERM);
        }

        // Per-mount flags, as Linux's path_mount separates them.
        let mut mnt_flags = flags & (MS_RDONLY | MS_NOSUID | MS_NODEV | MS_NOEXEC | MS_NOATIME | MS_NODIRATIME | MS_NOSYMFOLLOW);
        if flags & MS_NOATIME == 0 {
            mnt_flags |= MS_RELATIME;
        }
        if flags & MS_STRICTATIME != 0 {
            mnt_flags &= !(MS_RELATIME | MS_NOATIME);
        }
        if flags & MS_REMOUNT != 0 && flags & (MNT_ATIME_MASK | MS_STRICTATIME) == 0 {
            // A remount keeps the atime behaviour unless it names one.
            let old = target.mount().flags.load(Ordering::Relaxed);
            mnt_flags = (mnt_flags & !MNT_ATIME_MASK) | (old & MNT_ATIME_MASK);
        }
        let sb_flags = flags & (MS_RDONLY | MS_SYNCHRONOUS | MS_MANDLOCK | MS_DIRSYNC | MS_LAZYTIME);
        let flags = flags & !(MS_NOSUID | MS_NOEXEC | MS_NODEV | MS_NOATIME | MS_NODIRATIME | MS_RELATIME | MS_KERNMOUNT | MS_STRICTATIME | MS_NOSYMFOLLOW);

        if flags & (MS_REMOUNT | MS_BIND) == MS_REMOUNT | MS_BIND {
            vfs.mount_root(&target)?.flags.store(mnt_flags, Ordering::Relaxed);
            vfs.touch();
        } else if flags & MS_REMOUNT != 0 {
            let m = vfs.mount_root(&target)?;
            // The image readers cannot write: their superblocks stay read-only.
            let image = matches!(m.sb.fs_type(), "erofs" | "ext4");
            m.sb.flags.store(sb_flags | if image { MS_RDONLY } else { 0 }, Ordering::Relaxed);
            m.flags.store(mnt_flags, Ordering::Relaxed);
            if m.sb.fs_type() == "tmpfs" && !data.is_empty() {
                let mut o = m.sb.options.lock().unwrap();
                *o = remount_tmpfs_options(&o, &data)?;
                if let Some((_, Some(size))) = parse_options(&data).into_iter().find(|(k, _)| *k == "size") {
                    m.sb.fs.set_size_limit(memparse(size)?);
                }
            }
            vfs.touch();
        } else if flags & MS_BIND != 0 {
            let src = source.filter(|s| !s.is_empty()).ok_or(EINVAL)?;
            let src = self.resolve(t, AT_FDCWD, &src, true)?;
            vfs.bind(&src, &target, flags & MS_REC != 0)?;
        } else if flags & PROPAGATION != 0 {
            let change = match flags & !(MS_REC | MS_SILENT) {
                MS_SHARED => PropagationChange::Shared,
                MS_PRIVATE => PropagationChange::Private,
                MS_SLAVE => PropagationChange::Slave,
                MS_UNBINDABLE => PropagationChange::Unbindable,
                _ => return Err(EINVAL),
            };
            vfs.set_propagation(&target, change, flags & MS_REC != 0)?;
        } else if flags & MS_MOVE != 0 {
            let src = source.filter(|s| !s.is_empty()).ok_or(EINVAL)?;
            let src = self.resolve(t, AT_FDCWD, &src, true)?;
            vfs.move_mount(&src, &target)?;
        } else if fstype.as_deref() == Some("fuse") {
            self.mount_fuse(t, vfs, &target, source.as_deref(), sb_flags, mnt_flags, &data)?;
        } else {
            let sb = self.new_super(t, vfs, source.as_deref(), fstype.as_deref().ok_or(EINVAL)?, sb_flags, &data)?;
            vfs.mount_at(&target, sb, mnt_flags)?;
        }
        super::wait::EVENTS.bump(); // wakes pollers of /proc/mounts
        Ok(0)
    }

    /// The filesystem instance a new mount of `fstype` gets.
    fn new_super(self: &Arc<Self>, t: &Thread, vfs: &Vfs, source: Option<&str>, fstype: &str, sb_flags: u64, data: &str) -> Result<Arc<Super>, i64> {
        let ty: &'static str = FILESYSTEMS.iter().map(|f| f.0).find(|f| *f == fstype).ok_or(ENODEV)?;
        let opts: Vec<_> = parse_options(data).into_iter().filter(|(k, _)| !is_security_option(k)).collect();
        let src = source.unwrap_or("none");
        if FILESYSTEMS.iter().any(|f| f.0 == ty && f.1) {
            return self.block_super(t, vfs, source, ty, sb_flags);
        }
        if SINGLE_INSTANCE.contains(&ty)
            && let Some(sb) = vfs.find_super(|sb| sb.fs_type() == ty)
        {
            return Ok(sb);
        }
        let tmpfs = |mode| Tmpfs::with_type(self.phys.clone(), mode, ty);
        let (fs, options): (Arc<dyn FileSystem>, String) = match ty {
            "tmpfs" | "ramfs" => {
                let (mut mode, mut uid, mut gid, mut size, mut inodes) = (0o1777, 0, 0, None, None);
                for (k, v) in &opts {
                    match *k {
                        "mode" => mode = octal(*v)?,
                        "uid" => uid = number(*v)?,
                        "gid" => gid = number(*v)?,
                        "size" if ty == "tmpfs" => size = Some(memparse(v.ok_or(EINVAL)?)?),
                        "nr_inodes" if ty == "tmpfs" => inodes = Some(memparse(v.ok_or(EINVAL)?)?),
                        _ => {} // huge=, mpol=, inode64, noswap…: accepted, no effect here
                    }
                }
                let fs = tmpfs(mode);
                fs.set_attr(fs.root().map_err(|_| EIO)?, None, Some((uid, gid)), None)?;
                fs.set_size_limit(size.unwrap_or(0));
                let mut o = Vec::new();
                if let Some(s) = size {
                    o.push(format!("size={}k", s.div_ceil(4096) * 4));
                }
                if let Some(n) = inodes {
                    o.push(format!("nr_inodes={n}"));
                }
                if mode != 0o1777 {
                    o.push(format!("mode={mode:03o}"));
                }
                if uid != 0 {
                    o.push(format!("uid={uid}"));
                }
                if gid != 0 {
                    o.push(format!("gid={gid}"));
                }
                (fs, o.join(","))
            }
            "proc" => {
                let fs = vfs.find_super(|sb| sb.fs_type() == "proc").map(|sb| sb.fs.clone()).unwrap_or_else(|| super::procfs::ProcFs::new(Arc::downgrade(self)));
                let mut o = Vec::new();
                if let Some((_, Some(g))) = opts.iter().find(|(k, _)| *k == "gid") {
                    o.push(format!("gid={g}"));
                }
                if let Some((_, Some(h))) = opts.iter().find(|(k, _)| *k == "hidepid") {
                    o.push(format!("hidepid={}", match *h {
                        "1" => "noaccess",
                        "2" => "invisible",
                        "4" => "ptraceable",
                        h => h,
                    }));
                }
                if opts.iter().any(|(k, v)| *k == "subset" && *v == Some("pid")) {
                    o.push("subset=pid".into());
                }
                (fs, o.join(","))
            }
            "devpts" => {
                let (mut mode, mut ptmx) = (0o600, 0);
                for (k, v) in &opts {
                    match *k {
                        "mode" => mode = octal(*v)?,
                        "ptmxmode" => ptmx = octal(*v)?,
                        _ => {}
                    }
                }
                let fs = tmpfs(0o755);
                fs.create(fs.root().map_err(|_| EIO)?, "ptmx", 0o020000 | ptmx, block::makedev(5, 2))?;
                (fs, format!("mode={mode:03o},ptmxmode={ptmx:03o}"))
            }
            "binder" => {
                // binderfs: the default devices, the same ones /dev has.
                let fs = tmpfs(0o755);
                for (name, rdev) in super::binder::DEVICES {
                    fs.create(fs.root().map_err(|_| EIO)?, name, 0o020600, rdev)?;
                }
                let o: Vec<String> = opts.iter().filter(|(k, _)| matches!(*k, "max" | "stats")).map(|(k, v)| format!("{k}={}", v.unwrap_or(""))).collect();
                (fs, o.join(","))
            }
            "cgroup" | "cpuset" => {
                let legacy_cpuset = ty == "cpuset";
                let mut ctl: Vec<&'static str> = if legacy_cpuset {
                    vec!["cpuset"]
                } else {
                    V1_CONTROLLERS.iter().copied().filter(|c| opts.iter().any(|(k, _)| k == c)).collect()
                };
                let name = opts.iter().find(|(k, _)| *k == "name").and_then(|(_, v)| *v);
                if ctl.is_empty() && name.is_none() && !opts.iter().any(|(k, _)| *k == "none") {
                    ctl = V1_CONTROLLERS.to_vec(); // no controllers named: all of them
                }
                let noprefix = legacy_cpuset || opts.iter().any(|(k, _)| *k == "noprefix");
                let mut o: Vec<String> = ctl.iter().map(|c| c.to_string()).collect();
                if noprefix {
                    o.push("noprefix".into());
                }
                if legacy_cpuset {
                    o.push("release_agent=/sbin/cpuset_release_agent".into());
                }
                if let Some(n) = name {
                    o.push(format!("name={n}"));
                }
                let key = o.join(",");
                // A hierarchy with these controllers already exists: mounting shows it again.
                if let Some(sb) = vfs.find_super(|sb| sb.fs_type() == "cgroup" && *sb.options.lock().unwrap() == key) {
                    return Ok(sb);
                }
                (CgroupFs::new(Arc::downgrade(self), false, ctl, noprefix) as Arc<dyn FileSystem>, key)
            }
            "cgroup2" => {
                const KNOWN: [&str; 6] = ["nsdelegate", "favordynmods", "memory_localevents", "memory_recursiveprot", "memory_hugetlb_accounting", "pids_localevents"];
                if let Some((k, _)) = opts.iter().find(|(k, _)| !KNOWN.contains(k)) {
                    eprintln!("[zeroemu] cgroup2: unknown option {k}");
                    return Err(EINVAL);
                }
                if let Some(sb) = vfs.find_super(|sb| sb.fs_type() == "cgroup2") {
                    return Ok(sb);
                }
                let o: Vec<&str> = opts.iter().map(|(k, _)| *k).collect();
                (CgroupFs::new(Arc::downgrade(self), true, Vec::new(), false) as Arc<dyn FileSystem>, o.join(","))
            }
            "sysfs" | "selinuxfs" => return Err(ENODEV), // single instances, always mounted at boot
            // bpffs: a sticky, world-writable root unless mode= says otherwise (bpf_fill_super).
            "bpf" => {
                let mode = match opts.iter().find(|(k, _)| *k == "mode") { Some((_, v)) => octal(*v)?, None => 0o1777 };
                let o: Vec<String> = opts.iter().map(|(k, v)| v.map_or(k.to_string(), |v| format!("{k}={v}"))).collect();
                (tmpfs(mode) as Arc<dyn FileSystem>, o.join(","))
            }
            // tracefs: only trace_marker, which ZEROEMU_TRACE keeps (trace.rs).
            "tracefs" => {
                let fs = tmpfs(0o755);
                fs.create(1, "trace_marker", 0o020222, super::trace::MARKER_RDEV)?;
                let o: Vec<String> = opts.iter().map(|(k, v)| v.map_or(k.to_string(), |v| format!("{k}={v}"))).collect();
                (fs as Arc<dyn FileSystem>, o.join(","))
            }
            // Stand-ins: empty directories of the right type (a fuse daemon is never asked anything).
            _ => {
                let o: Vec<String> = opts.iter().filter(|(k, _)| !matches!(*k, "fd" | "rootmode" | "user_id" | "group_id")).map(|(k, v)| v.map_or(k.to_string(), |v| format!("{k}={v}"))).collect();
                (tmpfs(0o755) as Arc<dyn FileSystem>, o.join(","))
            }
        };
        Ok(vfs.new_super(fs, src, None, sb_flags, &options))
    }

    /// A fuse mount (fuse.rs): the caller's /dev/fuse, fd=, gets a connection and the
    /// daemon its FUSE_INIT, and the mount shows the emulated volume's files in
    /// /data/media, served by zeroemu itself (an empty directory where there is no
    /// /data/media, as in the test guests' world without an image).
    #[allow(clippy::too_many_arguments)]
    fn mount_fuse(&self, t: &Thread, vfs: &Vfs, target: &Node, source: Option<&str>, sb_flags: u64, mnt_flags: u64, data: &str) -> Result<(), i64> {
        let (mut fd, mut rootmode, mut uid, mut gid) = (None, None, None, None);
        let mut shown = Vec::new();
        for (k, v) in parse_options(data).into_iter().filter(|(k, _)| !is_security_option(k)) {
            match k {
                "fd" => fd = Some(number(v)?),
                "rootmode" => rootmode = Some(u32::from_str_radix(v.ok_or(EINVAL)?, 8).map_err(|_| EINVAL)?),
                "user_id" => uid = Some(number(v)?),
                "group_id" => gid = Some(number(v)?),
                "default_permissions" | "allow_other" => shown.push(k.to_string()),
                "max_read" => shown.push(format!("max_read={}", number(v)?)),
                "blksize" | "subtype" | "source" => {}
                _ => return Err(EINVAL), // fs/fuse knows no other
            }
        }
        // fuse_fill_super: these four must be given.
        let (Some(fd), Some(rootmode), Some(uid), Some(gid)) = (fd, rootmode, uid, gid) else { return Err(EINVAL) };
        if rootmode & 0o170000 != S_IFDIR {
            return Err(EINVAL); // a file as the root: nothing here serves one
        }
        let file = t.files().get(fd as i64)?;
        let super::files::Kind::Fuse(dev) = &file.kind else { return Err(EINVAL) };
        if dev.attached() {
            return Err(EINVAL);
        }
        let lower = self.resolve(t, AT_FDCWD, super::fuse::LOWER, true).ok().filter(|n| vfs.stat(n).is_ok_and(|st| st.mode & 0o170000 == S_IFDIR));
        let (fs, root) = match &lower {
            Some(n) => (vfs.fs_arc(n), n.ino),
            None => {
                let fs = Tmpfs::new(self.phys.clone(), 0o755);
                let root = fs.root().map_err(|_| EIO)?;
                (fs as Arc<dyn FileSystem>, root)
            }
        };
        // As fuse_show_options prints them.
        let options = [format!("user_id={uid}"), format!("group_id={gid}")].into_iter().chain(shown).collect::<Vec<_>>().join(",");
        let mounted = super::fuse::Mounted::new();
        let sb = vfs.new_super_as(fs, Some("fuse"), Some(mounted.clone()), source.unwrap_or("none"), None, sb_flags, &options);
        vfs.mount_at_root(target, sb, root, mnt_flags)?;
        let c = self.creds(t);
        mounted.start(dev, (c.fsuid, c.fsgid, t.proc.pid as u32))
    }

    /// An ext4 or EROFS mount of a loop or device-mapper device, read by
    /// zeroemu's own image readers (read-only).
    fn block_super(&self, t: &Thread, vfs: &Vfs, source: Option<&str>, ty: &'static str, sb_flags: u64) -> Result<Arc<Super>, i64> {
        let src = source.ok_or(EINVAL)?;
        let node = self.resolve(t, AT_FDCWD, src, true)?;
        let st = vfs.stat(&node)?;
        if st.mode & 0o170000 != S_IFBLK {
            return Err(ENOTBLK);
        }
        let dev = self.blocks.device(st.rdev).ok_or(ENXIO)?;
        // Already mounted: Linux hands out the same superblock.
        if let Some(sb) = vfs.find_super(|sb| sb.dev == st.rdev && sb.fs_type() == ty) {
            return Ok(sb);
        }
        if dev.len() == 0 {
            return Err(ENXIO); // an unbound loop device
        }
        let fs = open_fs_as(super::block::pin(&dev), ty).map_err(|_| EINVAL)?; // not that filesystem
        let options = if ty == "erofs" { "user_xattr,acl,cache_strategy=readaround" } else { "" };
        Ok(vfs.new_super(fs, src, Some(st.rdev), sb_flags | MS_RDONLY, options))
    }

    fn sys_umount2(&self, t: &Thread, path: u64, flags: u64) -> Result<i64, i64> {
        let vfs = self.vfs.as_deref().ok_or(ENOENT)?;
        if flags & !(MNT_FORCE | MNT_DETACH | MNT_EXPIRE | UMOUNT_NOFOLLOW) != 0 || (flags & MNT_EXPIRE != 0 && flags & (MNT_FORCE | MNT_DETACH) != 0) {
            return Err(EINVAL);
        }
        let path = t.proc.mm().read_cstr(path)?;
        let node = self.resolve(t, AT_FDCWD, &path, flags & UMOUNT_NOFOLLOW == 0)?;
        if !self.creds(t).capable(super::creds::CAP_SYS_ADMIN) {
            return Err(EPERM);
        }
        if flags & MNT_EXPIRE != 0 {
            vfs.mount_root(&node)?;
            return Err(EAGAIN); // marked for expiry; nothing ever expires it
        }
        for m in vfs.umount(&node, flags & MNT_DETACH != 0)? {
            let ty = m.sb.fs_type();
            if SINGLE_INSTANCE.contains(&ty) || ty.starts_with("cgroup") {
                vfs.keep(&m.sb);
            }
        }
        super::wait::EVENTS.bump();
        Ok(0)
    }
}

/// tmpfs options after `mount -o remount,...`: size and nr_inodes may change.
fn remount_tmpfs_options(old: &str, data: &str) -> Result<String, i64> {
    let mut o: Vec<String> = old.split(',').filter(|s| !s.is_empty()).map(String::from).collect();
    for (k, v) in parse_options(data) {
        let new = match k {
            "size" => format!("size={}k", memparse(v.ok_or(EINVAL)?)?.div_ceil(4096) * 4),
            "nr_inodes" => format!("nr_inodes={}", memparse(v.ok_or(EINVAL)?)?),
            _ => continue,
        };
        o.retain(|x| !x.starts_with(&format!("{k}=")));
        o.insert(0, new);
    }
    Ok(o.join(","))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn option_parsing() {
        assert_eq!(parse_options("mode=0755,uid=0,ro"), vec![("mode", Some("0755")), ("uid", Some("0")), ("ro", None)]);
        assert_eq!(memparse("16k"), Ok(16384));
        assert_eq!(memparse("2M"), Ok(2 << 20));
        assert_eq!(memparse("50%"), Ok(crate::phys::ram() / 100 * 50));
        assert_eq!(memparse("1000000000000%"), Err(EINVAL));
        assert_eq!(memparse("x"), Err(EINVAL));
        assert_eq!(octal(Some("0755")), Ok(0o755));
        assert_eq!(mangle("a b\\c"), "a\\040b\\134c");
        assert_eq!(remount_tmpfs_options("size=4k,mode=755", "size=8k").unwrap(), "size=8k,mode=755");
    }

    /// Enough of a hypervisor for tmpfs: memory, no vCPUs.
    use crate::hv::NoHv;

    #[test]
    fn mount_table() {
        let phys = crate::phys::PhysMem::new(Arc::new(NoHv));
        let tmpfs = || Tmpfs::new(phys.clone(), 0o755);
        let vfs = Vfs::default();
        vfs.mount("/", tmpfs());
        let root = vfs.resolve("/", "/", true).unwrap();
        for d in ["a", "b", "c"] {
            vfs.mkdir(&root, d, 0o755).unwrap();
        }
        let at = |p: &str| vfs.resolve("/", p, true);
        let sb = |fs: Arc<Tmpfs>| vfs.new_super(fs, "tmpfs", None, 0, "");
        vfs.mount_at(&at("/a").unwrap(), sb(tmpfs()), MS_RELATIME).unwrap();
        vfs.create(&at("/a").unwrap(), "f", 0o644, 0).unwrap();
        assert_eq!(vfs.mkdir(&root, "a", 0o755), Err(EEXIST));
        assert_eq!(vfs.unlink(&root, "a", true), Err(EBUSY));
        // A bind shows the same files; a mount stacked on /a hides them until unmounted.
        vfs.bind(&at("/a").unwrap(), &at("/b").unwrap(), false).unwrap();
        assert!(at("/b/f").is_ok());
        vfs.mount_at(&at("/a").unwrap(), sb(tmpfs()), MS_RELATIME).unwrap();
        assert_eq!(at("/a/f").err(), Some(ENOENT));
        vfs.umount(&at("/a").unwrap(), false).unwrap();
        assert!(at("/a/f").is_ok());
        assert_eq!(vfs.umount(&at("/a/f").unwrap(), false).err(), Some(EINVAL));
        // Moving /b (with a mount beneath it) to /c.
        vfs.mkdir(&at("/b").unwrap(), "sub", 0o755).unwrap();
        vfs.mount_at(&at("/b/sub").unwrap(), sb(tmpfs()), 0).unwrap();
        assert_eq!(vfs.umount(&at("/b").unwrap(), false).err(), Some(EBUSY));
        let held = at("/b/f").unwrap();
        vfs.move_mount(&at("/b").unwrap(), &at("/c").unwrap()).unwrap();
        assert!(at("/c/f").is_ok() && at("/c/sub").unwrap().is_mount_root() && at("/b/f").is_err());
        // MS_MOVE publishes a new mount arc; a remount must still reach a node resolved before it.
        let live = vfs.mount_root(&at("/c").unwrap()).unwrap();
        let saved = live.flags.load(Ordering::Relaxed);
        live.flags.store(saved | MS_RDONLY, Ordering::Relaxed);
        assert!(vfs.readonly(&held));
        live.flags.store(saved, Ordering::Relaxed);
        assert_eq!(vfs.move_mount(&at("/c").unwrap(), &at("/c/sub").unwrap()).err(), Some(ELOOP));
        let info = mountinfo(&vfs);
        assert!(info.contains(" / /a rw,relatime - tmpfs tmpfs rw,seclabel\n"), "{info}");
        assert!(info.contains(" / /c rw,relatime - tmpfs tmpfs rw,seclabel\n"), "{info}");
        vfs.umount(&at("/c").unwrap(), true).unwrap(); // MNT_DETACH takes /c/sub too
        assert!(!mountinfo(&vfs).contains("/c"));
        assert_eq!(proc_mounts(&vfs).lines().count(), 2);
    }

    /// init's bootstrap namespace: /apex is a bind of the shared
    /// /bootstrap-apex, so what apexd mounts under one shows under the other.
    #[test]
    fn shared_subtrees_propagate() {
        let phys = crate::phys::PhysMem::new(Arc::new(NoHv));
        let tmpfs = || Tmpfs::new(phys.clone(), 0o755);
        let vfs = Vfs::default();
        vfs.mount("/", tmpfs());
        let root = vfs.resolve("/", "/", true).unwrap();
        for d in ["apex", "bootstrap-apex", "img"] {
            vfs.mkdir(&root, d, 0o755).unwrap();
        }
        let at = |p: &str| vfs.resolve("/", p, true);
        let sb = |fs: Arc<Tmpfs>| vfs.new_super(fs, "tmpfs", None, 0, "");
        vfs.mount_at(&at("/bootstrap-apex").unwrap(), sb(tmpfs()), 0).unwrap();
        vfs.set_propagation(&at("/bootstrap-apex").unwrap(), PropagationChange::Shared, false).unwrap();
        vfs.bind(&at("/bootstrap-apex").unwrap(), &at("/apex").unwrap(), false).unwrap();
        let img = tmpfs();
        img.mkdir_p("etc/vintf", 0o755);
        vfs.mkdir(&at("/apex").unwrap(), "m@1", 0o755).unwrap();
        vfs.mount_at(&at("/apex/m@1").unwrap(), sb(img), 0).unwrap();
        assert!(at("/bootstrap-apex/m@1/etc/vintf").is_ok());
        // A bind of the new mount propagates too, then both go on umount.
        vfs.mkdir(&at("/apex").unwrap(), "m", 0o755).unwrap();
        vfs.bind(&at("/apex/m@1").unwrap(), &at("/apex/m").unwrap(), false).unwrap();
        assert!(at("/bootstrap-apex/m/etc/vintf").is_ok());
        vfs.umount(&at("/apex/m").unwrap(), false).unwrap();
        assert!(at("/bootstrap-apex/m/etc").is_err() && at("/bootstrap-apex/m@1/etc").is_ok());
        // A private mount receives nothing.
        vfs.mount_at(&at("/img").unwrap(), sb(tmpfs()), 0).unwrap();
        vfs.bind(&at("/img").unwrap(), &at("/apex/m").unwrap(), false).unwrap();
        vfs.mkdir(&at("/img").unwrap(), "x", 0o755).unwrap();
        vfs.mount_at(&at("/img/x").unwrap(), sb(tmpfs()), 0).unwrap();
        assert!(!at("/apex/m/x").unwrap().is_mount_root());
    }

    /// zygote binds /mnt/user/0 on an app's /storage from a slave of init's /mnt; vold
    /// mounts the volume at /mnt/user/0/emulated later, and the app sees it there.
    #[test]
    fn a_bind_of_a_slave_receives_its_masters_mounts() {
        let phys = crate::phys::PhysMem::new(Arc::new(NoHv));
        let tmpfs = || Tmpfs::new(phys.clone(), 0o755);
        let vfs = Vfs::default();
        vfs.mount("/", tmpfs());
        let root = vfs.resolve("/", "/", true).unwrap();
        for d in ["mnt", "app", "storage"] {
            vfs.mkdir(&root, d, 0o755).unwrap();
        }
        let at = |p: &str| vfs.resolve("/", p, true);
        let sb = |fs: Arc<Tmpfs>| vfs.new_super(fs, "tmpfs", None, 0, "");
        let mnt = tmpfs();
        mnt.mkdir_p("user/0", 0o755);
        vfs.mount_at(&at("/mnt").unwrap(), sb(mnt), 0).unwrap();
        vfs.set_propagation(&at("/mnt").unwrap(), PropagationChange::Shared, false).unwrap();
        // The app's copy of /mnt is a slave, and its /storage a bind from that copy.
        vfs.bind(&at("/mnt").unwrap(), &at("/app").unwrap(), false).unwrap();
        vfs.set_propagation(&at("/app").unwrap(), PropagationChange::Slave, false).unwrap();
        vfs.bind(&at("/app/user/0").unwrap(), &at("/storage").unwrap(), false).unwrap();
        let volume = tmpfs();
        volume.mkdir_p("0/Download", 0o755);
        vfs.mkdir(&at("/mnt/user/0").unwrap(), "emulated", 0o755).unwrap();
        vfs.mount_at(&at("/mnt/user/0/emulated").unwrap(), sb(volume), 0).unwrap();
        assert!(at("/storage/emulated/0/Download").is_ok());
        // And nothing flows back from a slave.
        vfs.mkdir(&at("/storage").unwrap(), "x", 0o755).unwrap();
        vfs.mount_at(&at("/storage/x").unwrap(), sb(tmpfs()), 0).unwrap();
        assert!(!at("/mnt/user/0/x").unwrap().is_mount_root());
    }

    /// vold binds /mnt/user on /mnt/installer, a slave made shared again; zygote's copy
    /// of that is a slave, and an installer's /storage is bound from it. A volume
    /// mounted under /mnt/user reaches that /storage through both, and goes again.
    #[test]
    fn events_pass_through_shared_slaves() {
        let phys = crate::phys::PhysMem::new(Arc::new(NoHv));
        let tmpfs = || Tmpfs::new(phys.clone(), 0o755);
        let vfs = Vfs::default();
        vfs.mount("/", tmpfs());
        let root = vfs.resolve("/", "/", true).unwrap();
        for d in ["mnt", "zygote", "storage"] {
            vfs.mkdir(&root, d, 0o755).unwrap();
        }
        let at = |p: &str| vfs.resolve("/", p, true);
        let sb = |fs: Arc<Tmpfs>| vfs.new_super(fs, "tmpfs", None, 0, "");
        let mnt = tmpfs();
        mnt.mkdir_p("user/0/emulated", 0o755);
        mnt.mkdir_p("installer", 0o755);
        vfs.mount_at(&at("/mnt").unwrap(), sb(mnt), 0).unwrap();
        vfs.set_propagation(&at("/mnt").unwrap(), PropagationChange::Shared, false).unwrap();
        vfs.bind(&at("/mnt/user").unwrap(), &at("/mnt/installer").unwrap(), true).unwrap();
        vfs.set_propagation(&at("/mnt/installer").unwrap(), PropagationChange::Slave, true).unwrap();
        vfs.set_propagation(&at("/mnt/installer").unwrap(), PropagationChange::Shared, false).unwrap();
        vfs.bind(&at("/mnt/installer").unwrap(), &at("/zygote").unwrap(), false).unwrap();
        vfs.set_propagation(&at("/zygote").unwrap(), PropagationChange::Slave, false).unwrap();
        vfs.bind(&at("/zygote/0").unwrap(), &at("/storage").unwrap(), false).unwrap();
        let volume = tmpfs();
        volume.mkdir_p("0/Download", 0o755);
        vfs.mount_at(&at("/mnt/user/0/emulated").unwrap(), sb(volume), 0).unwrap();
        for p in ["/mnt/installer/0/emulated/0/Download", "/zygote/0/emulated/0/Download", "/storage/emulated/0/Download"] {
            assert!(at(p).is_ok(), "{p}");
        }
        vfs.umount(&at("/mnt/user/0/emulated").unwrap(), false).unwrap();
        for p in ["/mnt/installer/0/emulated/0", "/zygote/0/emulated/0", "/storage/emulated/0"] {
            assert!(at(p).is_err(), "{p}");
        }
    }

    /// A trailing slash follows a link and wants a directory.
    #[test]
    fn a_trailing_slash_follows_the_last_link() {
        let phys = crate::phys::PhysMem::new(Arc::new(NoHv));
        let vfs = Vfs::default();
        vfs.mount("/", Tmpfs::new(phys.clone(), 0o755));
        let root = vfs.resolve("/", "/", true).unwrap();
        vfs.mkdir(&root, "d", 0o755).unwrap();
        vfs.symlink(&root, "l", "/d").unwrap();
        vfs.create(&root, "f", 0o644, 0).unwrap();
        assert_eq!(vfs.resolve("/", "/l", false).unwrap().path, "/l");
        assert_eq!(vfs.resolve("/", "/l/", false).unwrap().path, "/d");
        assert_eq!(vfs.resolve("/", "/f/", false).err(), Some(ENOTDIR));
    }

    #[test]
    fn statfs_flags() {
        let b = statfs_bytes("tmpfs", MS_RDONLY | MS_NOSUID | MS_RELATIME);
        assert_eq!(u64::from_le_bytes(b[0..8].try_into().unwrap()), 0x0102_1994);
        assert_eq!(u64::from_le_bytes(b[80..88].try_into().unwrap()), 0x20 | 1 | 2 | 4096);
    }
}

//! Extended attributes: the *xattr syscalls over the VFS (fs/xattr.c's
//! checks and their order), and the SELinux labels the kernel-made tmpfs
//! mounts start with.

use super::files::{Kind, file_name, node_of};
use super::{Kernel, Thread, int};
use crate::arch::Sysno;
use crate::errno::*;
use crate::phys::PAGE;
use crate::tmpfs::{MemFile, XATTR_SELINUX};
use crate::vfs::{Node, S_IFDIR, S_IFMT, S_IFREG, Vfs, XATTR_CREATE, XATTR_REPLACE};
use std::sync::Arc;

const AT_FDCWD: i64 = -100;
const XATTR_NAME_MAX: u64 = 255;
const XATTR_SIZE_MAX: u64 = 1 << 16;
const XATTR_LIST_MAX: u64 = 1 << 16;

pub fn handles(no: Sysno) -> bool {
    use Sysno::*;
    matches!(
        no,
        setxattr | lsetxattr | fsetxattr | getxattr | lgetxattr | fgetxattr | listxattr | llistxattr | flistxattr | removexattr
            | lremovexattr | fremovexattr
    )
}

/// What an xattr syscall operates on.
enum Target {
    Node(Node),
    Memfd(Arc<MemFile>),
    /// sockfs: Linux lets the LSM label sockets; the label is accepted and dropped.
    Socket,
    /// pipefs, anon_inodes, the host terminal: no xattr handlers.
    Anon,
}

enum Op {
    Set,
    Get,
    List,
    Remove,
}

/// xattr_resolve_name: a known namespace with a non-empty suffix.
fn check_namespace(name: &str) -> Result<(), i64> {
    match ["security.", "system.", "trusted.", "user."].into_iter().find(|p| name.starts_with(p)) {
        Some(p) if name.len() == p.len() && p != "system." => Err(EINVAL),
        Some(_) => Ok(()),
        None => Err(EOPNOTSUPP),
    }
}

/// user.* lives only on regular files and directories (xattr_permission).
fn user_allowed(vfs: &Vfs, node: &Node, name: &str) -> Result<bool, i64> {
    Ok(!name.starts_with("user.") || matches!(vfs.stat(node)?.mode & S_IFMT, S_IFREG | S_IFDIR))
}

/// A value or name list copied out under getxattr/listxattr's size rules.
fn copy_out(t: &Thread, buf: u64, size: u64, max: u64, data: &[u8]) -> Result<i64, i64> {
    if size == 0 {
        return Ok(data.len() as i64);
    }
    if data.len() as u64 > size.min(max) {
        return Err(if size >= max { E2BIG } else { ERANGE });
    }
    t.proc.mm().write(buf, data)?;
    Ok(data.len() as i64)
}

impl Kernel {
    pub(super) fn xattr_syscall(&self, no: Sysno, t: &Thread, a: [u64; 6]) -> Result<i64, i64> {
        use Sysno::*;
        let op = match no {
            setxattr | lsetxattr | fsetxattr => Op::Set,
            getxattr | lgetxattr | fgetxattr => Op::Get,
            listxattr | llistxattr | flistxattr => Op::List,
            _ => Op::Remove,
        };
        // Flags, name and value are checked and copied in before the path is looked up.
        if matches!(op, Op::Set) && a[4] as u32 & !(XATTR_CREATE | XATTR_REPLACE) != 0 {
            return Err(EINVAL);
        }
        let name = if matches!(op, Op::List) { String::new() } else { self.xattr_name(t, a[1])? };
        let value = match op {
            Op::Set if a[3] > XATTR_SIZE_MAX => return Err(E2BIG),
            Op::Set => t.proc.mm().read_vec(a[2], a[3] as usize)?,
            _ => Vec::new(),
        };
        let target = match no {
            fsetxattr | fgetxattr | flistxattr | fremovexattr => self.fd_xattr_target(t, int(a[0]))?,
            _ => {
                let path = t.proc.mm().read_cstr(a[0])?;
                Target::Node(self.resolve(t, AT_FDCWD, &path, matches!(no, setxattr | getxattr | listxattr | removexattr))?)
            }
        };
        let vfs = self.vfs.as_deref().ok_or(ENOENT)?;
        match (op, target) {
            (Op::Set, Target::Node(n)) => {
                // A read-only mount fails before the name is looked at (mnt_want_write).
                if vfs.writable(&n) {
                    check_namespace(&name)?;
                    if !user_allowed(vfs, &n, &name)? {
                        return Err(EPERM);
                    }
                }
                vfs.setxattr(&n, &name, &value, a[4] as u32).map(|_| 0)
            }
            (Op::Set, Target::Memfd(f)) => {
                check_namespace(&name)?;
                f.xattrs.lock().unwrap().set(&name, &value, a[4] as u32).map(|_| 0)
            }
            (Op::Set, Target::Socket) if name.starts_with("security.") => Ok(0),
            (Op::Get, Target::Node(n)) => {
                check_namespace(&name)?;
                if !user_allowed(vfs, &n, &name)? {
                    return Err(ENODATA);
                }
                let mut v = vfs.getxattr(&n, &name)?;
                // SELinux reports a context NUL-terminated, however the filesystem stored it.
                if name == XATTR_SELINUX && v.last().is_some_and(|&c| c != 0) {
                    v.push(0);
                }
                copy_out(t, a[2], a[3], XATTR_SIZE_MAX, &v)
            }
            (Op::Get, Target::Memfd(f)) => {
                check_namespace(&name)?;
                copy_out(t, a[2], a[3], XATTR_SIZE_MAX, &f.xattrs.lock().unwrap().get(&name)?)
            }
            (Op::List, target) => {
                let names = match target {
                    Target::Node(n) => vfs.listxattr(&n)?,
                    Target::Memfd(f) => f.xattrs.lock().unwrap().list(),
                    Target::Socket | Target::Anon => Vec::new(),
                };
                let list: Vec<u8> = names.iter().flat_map(|n| n.bytes().chain([0])).collect();
                copy_out(t, a[1], a[2], XATTR_LIST_MAX, &list)
            }
            (Op::Remove, Target::Node(n)) => {
                if vfs.writable(&n) {
                    check_namespace(&name)?;
                    if !user_allowed(vfs, &n, &name)? {
                        return Err(EPERM);
                    }
                }
                vfs.removexattr(&n, &name).map(|_| 0)
            }
            (Op::Remove, Target::Memfd(f)) => {
                check_namespace(&name)?;
                f.xattrs.lock().unwrap().remove(&name).map(|_| 0)
            }
            _ => Err(EOPNOTSUPP),
        }
    }

    /// An attribute name: 1..=255 bytes, else ERANGE (as strncpy_from_user
    /// into a 256-byte buffer reports it). Reads no further than needed.
    fn xattr_name(&self, t: &Thread, addr: u64) -> Result<String, i64> {
        let mut mm = t.proc.mm();
        let first = (PAGE - addr % PAGE).min(XATTR_NAME_MAX + 1);
        let mut b = mm.read_vec(addr, first as usize)?;
        if !b.contains(&0) && first <= XATTR_NAME_MAX {
            b.extend(mm.read_vec(addr + first, (XATTR_NAME_MAX + 1 - first) as usize)?);
        }
        match b.iter().position(|&c| c == 0) {
            Some(n) if n > 0 => Ok(String::from_utf8_lossy(&b[..n]).into_owned()),
            _ => Err(ERANGE),
        }
    }

    fn fd_xattr_target(&self, t: &Thread, fd: i64) -> Result<Target, i64> {
        let f = t.proc.files.lock().unwrap().get(fd)?;
        if let Some(n) = node_of(&f) {
            return Ok(Target::Node(n));
        }
        Ok(match &f.kind {
            Kind::Mem(m) => Target::Memfd(m.file.clone()),
            Kind::Socket(_) => Target::Socket,
            // Opened devices keep no node; their path names the same inode.
            Kind::Null | Kind::Zero | Kind::Random | Kind::Kmsg | Kind::Binder(_) | Kind::Block(_) | Kind::LoopControl | Kind::DmControl => {
                let vfs = self.vfs.as_deref().ok_or(ENOENT)?;
                vfs.resolve("/", &file_name(&f), true).map_or(Target::Anon, Target::Node)
            }
            _ => Target::Anon,
        })
    }
}

/// Labels of the kernel-made mounts, as first-stage init and restorecon
/// leave them on a device (plat_file_contexts, genfs_contexts for sysfs and
/// selinuxfs): (path, type, whole subtree). Later entries override earlier
/// ones; nodes created afterwards inherit their directory's label.
const LABELS: &[(&str, &str, bool)] = &[
    ("/dev", "device", true),
    ("/dev/socket", "socket_device", true),
    ("/dev/pts", "devpts", true),
    ("/dev/block", "block_device", true),
    ("/dev/__properties__", "properties_device", true),
    ("/dev/null", "null_device", false),
    ("/dev/zero", "zero_device", false),
    ("/dev/random", "random_device", false),
    ("/dev/urandom", "random_device", false),
    ("/dev/kmsg", "kmsg_device", false),
    ("/dev/binder", "binder_device", false),
    ("/dev/hwbinder", "hwbinder_device", false),
    ("/dev/vndbinder", "vndbinder_device", false),
    ("/dev/loop-control", "loop_control_device", false),
    ("/dev/device-mapper", "dm_device", false),
    ("/data", "system_data_file", true),
    ("/data", "system_data_root_file", false),
    ("/data/local/tmp", "shell_data_file", true),
    // A fresh tmpfs mount, before init's restorecon.
    ("/tmp", "tmpfs", true),
    ("/mnt", "tmpfs", true),
    ("/cache", "cache_file", true),
    ("/sys", "sysfs", true),
    ("/sys/devices/system/cpu", "sysfs_devices_system_cpu", true),
    ("/sys/fs/selinux", "selinuxfs", true),
];

pub fn label_mounts(vfs: &Vfs) {
    for &(path, ty, subtree) in LABELS {
        if let Ok(node) = vfs.resolve("/", path, false) {
            // As the kernel reports a context: NUL-terminated.
            label_tree(vfs, &node, format!("u:object_r:{ty}:s0\0").as_bytes(), subtree);
        }
    }
}

fn label_tree(vfs: &Vfs, node: &Node, label: &[u8], subtree: bool) {
    let _ = vfs.setxattr(node, XATTR_SELINUX, label, 0);
    if !subtree || vfs.stat(node).map_or(true, |st| st.mode & S_IFMT != S_IFDIR) {
        return;
    }
    // ino 0 marks mount points listed from the mount table: other filesystems.
    for d in vfs.readdir(node).unwrap_or_default().into_iter().filter(|d| d.ino != 0 && d.name != "." && d.name != "..") {
        label_tree(vfs, &vfs.child(node, &d.name, d.ino), label, true);
    }
}

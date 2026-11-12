//! File permissions (Linux's discretionary access control): generic_permission
//! and the rules fs/namei.c builds on it (may_lookup, may_open, may_create,
//! may_delete), fs/attr.c's for chmod, chown and utimes, and the switches that
//! turn them off or log them. The checks themselves sit where each syscall does
//! its work; this module is what they share.
//!
//! Only files whose owner and mode are real are checked: tmpfs (init and its
//! daemons chown and chmod it as on a device, and droidrt makes its device nodes
//! with ueventd's modes), binderfs, and the read-only images. procfs, sysfs, the
//! cgroup hierarchies, selinuxfs, devpts, tracefs, bpffs and the stand-in
//! filesystems have modes droidrt made up and owners nobody set, so they stay
//! permissive, as their directories do for path walks. A fuse mount (the
//! shared-storage volume, fuse.rs) shows /data's files with their real owners, and
//! still nothing is checked there: vold mounts it without default_permissions, so
//! on Linux the kernel leaves every decision to the daemon.

use super::creds::Creds;
use super::{Kernel, Thread};
use crate::errno::*;
use crate::vfs::{MS_NODEV, MS_NOEXEC, Node, S_IFDIR, S_IFLNK, S_IFMT, S_IFREG, Stat, Vfs};
use std::sync::LazyLock;

pub const MAY_EXEC: u32 = 1;
pub const MAY_WRITE: u32 = 2;
pub const MAY_READ: u32 = 4;

pub const CAP_CHOWN: u32 = 0;
pub const CAP_DAC_OVERRIDE: u32 = 1;
pub const CAP_DAC_READ_SEARCH: u32 = 2;
pub const CAP_FOWNER: u32 = 3;
pub const CAP_FSETID: u32 = 4;
pub const CAP_MKNOD: u32 = 27;

pub const S_ISUID: u32 = 0o4000;
pub const S_ISGID: u32 = 0o2000;
pub const S_ISVTX: u32 = 0o1000;
const S_IXGRP: u32 = 0o010;
const S_IFCHR: u32 = 0o020000;
const S_IFBLK: u32 = 0o060000;

// Android ids (android_filesystem_config.h) that device nodes belong to.
pub const AID_SYSTEM: u32 = 1000;
pub const AID_GRAPHICS: u32 = 1003;
pub const AID_INPUT: u32 = 1004;
pub const AID_VPN: u32 = 1016;

/// Makes a device node droidrt provides as ueventd would leave it: the mode and
/// owner /system/etc/ueventd.rc (or the vendor's) gives it, or ueventd's own
/// default, 0600 root root, where no line names it. Returns its inode.
pub fn device_node(fs: &dyn crate::vfs::FileSystem, dir: u64, name: &str, mode: u32, rdev: u64, owner: (u32, u32)) -> Result<u64, i64> {
    let ino = fs.create(dir, name, mode, rdev)?;
    if owner != (0, 0) {
        fs.set_attr(ino, None, Some(owner), None)?;
    }
    Ok(ino)
}

/// DROIDRT_DAC=0: nothing in this module refuses anything, as before droidrt had it.
pub fn enforcing() -> bool {
    static ON: LazyLock<bool> = LazyLock::new(|| std::env::var("DROIDRT_DAC").as_deref() != Ok("0"));
    *ON
}

/// DROIDRT_DAC_LOG=1: every refusal is logged, with who asked and what refused.
fn logging() -> bool {
    static ON: LazyLock<bool> = LazyLock::new(|| std::env::var("DROIDRT_DAC_LOG").as_deref() == Ok("1"));
    *ON
}

/// Whether `node`'s owner and mode mean something (see the module comment).
pub fn applies(vfs: &Vfs, node: &Node) -> bool {
    enforcing() && matches!(vfs.fs_type(node), "tmpfs" | "ramfs" | "ext4" | "erofs" | "binder")
}

fn mask_name(mask: u32) -> String {
    [(MAY_READ, 'r'), (MAY_WRITE, 'w'), (MAY_EXEC, 'x')].iter().map(|&(b, c)| if mask & b != 0 { c } else { '-' }).collect()
}

impl Creds {
    /// in_group_p: the fs group or a supplementary one.
    pub fn in_group(&self, gid: u32) -> bool {
        self.fsgid == gid || self.groups.contains(&gid)
    }

    /// inode_owner_or_capable: what changing a file's attributes takes.
    pub fn owns(&self, st: &Stat) -> bool {
        self.fsuid == st.uid || self.capable(CAP_FOWNER)
    }
}

impl Kernel {
    /// Logs a refusal when asked to, and returns its errno.
    pub(super) fn denied(&self, t: &Thread, c: &Creds, path: &str, st: &Stat, what: &str, err: i64) -> i64 {
        if logging() {
            let nr = super::files::CURRENT.with(|x| x.get().2);
            let call = self.arch.sysno(nr).map_or_else(|| nr.to_string(), |s| format!("{s:?}"));
            let exe = t.proc.exe.lock().unwrap().clone();
            eprintln!(
                "[droidrt] dac: pid {} ({exe}) uid {} gid {} groups {:?} {call} {path}: {what} refused by {:o} {}:{} ({})",
                t.proc.pid,
                c.fsuid,
                c.fsgid,
                c.groups,
                st.mode,
                st.uid,
                st.gid,
                if err == EACCES { "EACCES" } else { "EPERM" }
            );
        }
        err
    }

    /// inode_permission: `mask` (MAY_*) on `node`. Writing a file, directory or
    /// link on a read-only mount is EROFS first, as sb_permission has it.
    pub(super) fn permission(&self, t: &Thread, c: &Creds, node: &Node, st: &Stat, mask: u32) -> Result<(), i64> {
        let Some(vfs) = self.vfs.as_deref() else { return Ok(()) };
        if !applies(vfs, node) {
            return Ok(());
        }
        if mask & MAY_WRITE != 0 && matches!(st.mode & S_IFMT, S_IFREG | S_IFDIR | S_IFLNK) && vfs.readonly(node) {
            return Err(EROFS);
        }
        if c.may_access(st, mask, true) {
            return Ok(());
        }
        Err(self.denied(t, c, &node.path, st, &mask_name(mask), EACCES))
    }

    /// permission(), statting `node` first.
    pub(super) fn node_permission(&self, t: &Thread, c: &Creds, node: &Node, mask: u32) -> Result<(), i64> {
        let Some(vfs) = self.vfs.as_deref() else { return Ok(()) };
        if !applies(vfs, node) {
            return Ok(());
        }
        let st = vfs.stat(node)?;
        self.permission(t, c, node, &st, mask)
    }

    /// The check a caller's path walk makes of each directory it looks in, or None
    /// when there is nothing to check: CAP_DAC_OVERRIDE and CAP_DAC_READ_SEARCH
    /// each search any directory.
    pub(super) fn searcher<'a>(&'a self, t: &'a Thread) -> Option<impl Fn(&Node, &Stat) -> Result<(), i64> + 'a> {
        if !enforcing() {
            return None;
        }
        let c = self.creds(t);
        if c.capable(CAP_DAC_OVERRIDE) || c.capable(CAP_DAC_READ_SEARCH) {
            return None;
        }
        Some(move |n: &Node, st: &Stat| self.permission(t, &c, n, st, MAY_EXEC))
    }

    /// may_create: write and search on the directory a name goes in.
    pub(super) fn may_create(&self, t: &Thread, c: &Creds, dir: &Node) -> Result<(), i64> {
        self.node_permission(t, c, dir, MAY_WRITE | MAY_EXEC)
    }

    /// may_delete's permission checks: write and search on the directory, then
    /// the sticky bit, which leaves a name to the file's owner, the directory's
    /// owner, and CAP_FOWNER.
    pub(super) fn may_delete(&self, t: &Thread, c: &Creds, dir: &Node, victim: &Node) -> Result<(), i64> {
        let Some(vfs) = self.vfs.as_deref() else { return Ok(()) };
        if !applies(vfs, dir) {
            return Ok(());
        }
        let dst = vfs.stat(dir)?;
        self.permission(t, c, dir, &dst, MAY_WRITE | MAY_EXEC)?;
        let vst = vfs.stat(victim)?;
        if dst.mode & S_ISVTX != 0 && vst.uid != c.fsuid && dst.uid != c.fsuid && !c.capable(CAP_FOWNER) {
            return Err(self.denied(t, c, &victim.path, &vst, "removal from a sticky directory", EPERM));
        }
        Ok(())
    }

    /// may_open's checks on an existing file (one open() didn't just create):
    /// read and/or write by the access mode, write for O_TRUNC, and no device
    /// nodes from a nodev mount. `access` is O_ACCMODE's value: 3 asks for both,
    /// as Linux's ACC_MODE has it.
    pub(super) fn may_open(&self, t: &Thread, node: &Node, st: &Stat, access: u32, trunc: bool) -> Result<(), i64> {
        if !enforcing() {
            return Ok(());
        }
        let Some(vfs) = self.vfs.as_deref() else { return Ok(()) };
        let c = self.creds(t);
        if matches!(st.mode & S_IFMT, S_IFCHR | S_IFBLK) && vfs.mount_flags(node) & MS_NODEV != 0 {
            return Err(self.denied(t, &c, &node.path, st, "a device on a nodev mount", EACCES));
        }
        let mut mask = [MAY_READ, MAY_WRITE, MAY_READ | MAY_WRITE, MAY_READ | MAY_WRITE][access as usize & 3];
        if trunc {
            mask |= MAY_WRITE;
        }
        self.permission(t, &c, node, st, mask)
    }

    /// What execve and an ELF interpreter need of a file: a regular file (EACCES
    /// otherwise, checked by the loader), not on a noexec mount, and an x bit the
    /// caller may use (root's CAP_DAC_OVERRIDE only runs what something could run).
    pub(super) fn may_exec(&self, t: &Thread, node: &Node, st: &Stat) -> Result<(), i64> {
        if !enforcing() {
            return Ok(());
        }
        let Some(vfs) = self.vfs.as_deref() else { return Ok(()) };
        let c = self.creds(t);
        if vfs.mount_flags(node) & MS_NOEXEC != 0 {
            return Err(self.denied(t, &c, &node.path, st, "execution from a noexec mount", EACCES));
        }
        self.permission(t, &c, node, st, MAY_EXEC)
    }

    /// chmod's rules (setattr_prepare): the owner or CAP_FOWNER, and set-gid
    /// dropped unless the caller is in the file's group or has CAP_FSETID.
    /// Returns the mode to store.
    pub(super) fn chmod_mode(&self, t: &Thread, node: &Node, mode: u32) -> Result<u32, i64> {
        let mut mode = mode & 0o7777;
        let Some(vfs) = self.vfs.as_deref().filter(|v| applies(v, node)) else { return Ok(mode) };
        let st = vfs.stat(node)?;
        let c = self.creds(t);
        if !c.owns(&st) {
            return Err(self.denied(t, &c, &node.path, &st, "chmod by a non-owner", EPERM));
        }
        if mode & S_ISGID != 0 && !c.in_group(st.gid) && !c.capable(CAP_FSETID) {
            mode &= !S_ISGID;
        }
        Ok(mode)
    }

    /// chown's rules (chown_ok, chgrp_ok): CAP_CHOWN, or the owner keeping its
    /// uid and choosing a group it is in. u32::MAX leaves an id as it is.
    /// Returns the mode the file is left with when that changes: a non-directory
    /// loses set-uid, and set-gid if it is group-executable or the caller could
    /// not set it (notify_change's ATTR_KILL_SUID and ATTR_KILL_SGID, which apply
    /// to root too).
    pub(super) fn chown_check(&self, t: &Thread, node: &Node, uid: u32, gid: u32) -> Result<Option<u32>, i64> {
        if !enforcing() {
            return Ok(None);
        }
        let Some(vfs) = self.vfs.as_deref() else { return Ok(None) };
        let st = vfs.stat(node)?;
        let c = self.creds(t);
        if applies(vfs, node) {
            let mine = c.fsuid == st.uid;
            if uid != u32::MAX && !(mine && uid == st.uid) && !c.capable(CAP_CHOWN) {
                return Err(self.denied(t, &c, &node.path, &st, "change of owner", EPERM));
            }
            if gid != u32::MAX && !(mine && (gid == st.gid || c.in_group(gid))) && !c.capable(CAP_CHOWN) {
                return Err(self.denied(t, &c, &node.path, &st, "change of group", EPERM));
            }
        }
        if st.mode & S_IFMT == S_IFDIR {
            return Ok(None);
        }
        let old = st.mode & 0o7777;
        let mut mode = old & !S_ISUID;
        if mode & S_ISGID != 0 && (mode & S_IXGRP != 0 || !(c.in_group(st.gid) || c.capable(CAP_FSETID))) {
            mode &= !S_ISGID;
        }
        Ok((mode != old).then_some(mode))
    }

    /// utimensat's rules: setting explicit times takes the owner or CAP_FOWNER;
    /// setting them to now (`explicit` false) takes that or write permission.
    pub(super) fn may_set_times(&self, t: &Thread, node: &Node, explicit: bool) -> Result<(), i64> {
        let Some(vfs) = self.vfs.as_deref().filter(|v| applies(v, node)) else { return Ok(()) };
        let st = vfs.stat(node)?;
        let c = self.creds(t);
        if c.owns(&st) {
            return Ok(());
        }
        if explicit {
            return Err(self.denied(t, &c, &node.path, &st, "setting times by a non-owner", EPERM));
        }
        self.permission(t, &c, node, &st, MAY_WRITE)
    }

    /// mknod of a device node takes CAP_MKNOD (vfs_mknod, after may_create).
    pub(super) fn may_mknod(&self, t: &Thread, mode: u32) -> Result<(), i64> {
        if enforcing() && matches!(mode & S_IFMT, S_IFCHR | S_IFBLK) && !self.creds(t).capable(CAP_MKNOD) {
            if logging() {
                eprintln!("[droidrt] dac: pid {} mknod of a device without CAP_MKNOD (EPERM)", t.proc.pid);
            }
            return Err(EPERM);
        }
        Ok(())
    }

    /// A capability a device's ioctls want (device-mapper's CAP_SYS_ADMIN), else `err`.
    pub(super) fn need_cap(&self, t: &Thread, cap: u32, what: &str, err: i64) -> Result<(), i64> {
        if !enforcing() || self.creds(t).capable(cap) {
            return Ok(());
        }
        if logging() {
            eprintln!("[droidrt] dac: pid {} ({}) {what} without capability {cap} ({})", t.proc.pid, t.proc.exe.lock().unwrap(), if err == EACCES { "EACCES" } else { "EPERM" });
        }
        Err(err)
    }
}

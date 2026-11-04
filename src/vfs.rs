//! The guest's file namespace: a mount table over filesystems, with Linux
//! path resolution (symlinks, "..", mount crossings).
//!
//! The table is an immutable snapshot behind an `RwLock<Arc<_>>`: resolution
//! clones the `Arc` and never holds a lock while it calls into filesystems,
//! and mount/umount build a new snapshot and publish it. There is one mount
//! namespace, shared by every process.

use crate::errno::*;
use crate::image::erofs::Erofs;
use crate::image::ext4::Ext4;
use crate::tmpfs::MemFile;
use std::collections::{HashMap, HashSet};
use std::io;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock, RwLock};

pub const S_IFMT: u32 = 0o170000;
pub const S_IFDIR: u32 = 0o040000;
pub const S_IFREG: u32 = 0o100000;
pub const S_IFLNK: u32 = 0o120000;

#[derive(Clone, Debug, Default)]
pub struct Stat {
    pub dev: u64,
    pub ino: u64,
    pub mode: u32,
    pub nlink: u32,
    pub uid: u32,
    pub gid: u32,
    pub rdev: u64,
    pub size: u64,
    pub mtime: u64,
}

pub struct Dirent {
    pub name: String,
    pub ino: u64,
    /// Linux DT_* value.
    pub dtype: u8,
}

pub trait FileSystem: Send + Sync {
    fn root(&self) -> io::Result<u64>;
    fn stat(&self, ino: u64) -> io::Result<Stat>;
    fn lookup(&self, dir: u64, name: &str) -> io::Result<Option<u64>>;
    fn readdir(&self, dir: u64) -> io::Result<Vec<Dirent>>;
    fn read_all(&self, ino: u64) -> io::Result<Arc<[u8]>>;

    /// For /proc/mounts.
    fn fs_type(&self) -> &'static str {
        "unknown"
    }

    // Writable filesystems (tmpfs) override these; images are read-only.
    fn writable(&self) -> bool {
        false
    }
    /// Live contents of a regular file, for read/write/MAP_SHARED.
    fn mem_file(&self, _ino: u64) -> Option<Arc<MemFile>> {
        None
    }
    /// Creates a regular file, or a special node when `mode` says so.
    fn create(&self, _dir: u64, _name: &str, _mode: u32, _rdev: u64) -> Result<u64, i64> {
        Err(EROFS)
    }
    fn mkdir(&self, _dir: u64, _name: &str, _mode: u32) -> Result<u64, i64> {
        Err(EROFS)
    }
    fn symlink(&self, _dir: u64, _name: &str, _target: &str) -> Result<u64, i64> {
        Err(EROFS)
    }
    fn link(&self, _ino: u64, _dir: u64, _name: &str) -> Result<(), i64> {
        Err(EROFS)
    }
    fn unlink(&self, _dir: u64, _name: &str, _rmdir: bool) -> Result<(), i64> {
        Err(EROFS)
    }
    fn rename(&self, _odir: u64, _oname: &str, _ndir: u64, _nname: &str, _noreplace: bool) -> Result<(), i64> {
        Err(EROFS)
    }
    fn set_attr(&self, _ino: u64, _mode: Option<u32>, _owner: Option<(u32, u32)>, _mtime: Option<u64>) -> Result<(), i64> {
        Err(EROFS)
    }

    /// Kernel files that take each write(2) as a value (sysctls, cgroup
    /// control files) instead of storing bytes; reads regenerate them.
    fn write_ok(&self, _ino: u64) -> bool {
        false
    }
    fn write(&self, _ino: u64, _data: &[u8]) -> Result<usize, i64> {
        Err(EINVAL)
    }
    /// A magic symlink (/proc/<pid>/ns/*): following it lands on this inode
    /// of the same filesystem rather than on its text.
    fn magic_link(&self, _ino: u64) -> Option<u64> {
        None
    }
    /// (total, free) bytes, for statfs.
    fn space(&self) -> Option<(u64, u64)> {
        None
    }
    /// tmpfs's size= (at mount and remount); 0 is no limit.
    fn set_size_limit(&self, _bytes: u64) {}
    /// A counter bumped whenever this file's contents change, for poll's
    /// POLLPRI (/proc/mounts reports mount table changes so).
    fn changes(&self, _ino: u64) -> Option<Arc<AtomicU64>> {
        None
    }
    // Extended attributes, by full name ("security.selinux"); `flags` takes
    // XATTR_CREATE / XATTR_REPLACE. Name syntax and per-namespace rules are
    // checked by the syscall layer; a filesystem refuses what it can't store.
    fn getxattr(&self, _ino: u64, _name: &str) -> Result<Vec<u8>, i64> {
        Err(ENODATA)
    }
    fn setxattr(&self, _ino: u64, _name: &str, _value: &[u8], _flags: u32) -> Result<(), i64> {
        Err(if self.writable() { EOPNOTSUPP } else { EROFS })
    }
    fn listxattr(&self, _ino: u64) -> Result<Vec<String>, i64> {
        Ok(vec![])
    }
    fn removexattr(&self, _ino: u64, _name: &str) -> Result<(), i64> {
        Err(if self.writable() { EOPNOTSUPP } else { EROFS })
    }
}

pub const XATTR_CREATE: u32 = 1;
pub const XATTR_REPLACE: u32 = 2;
pub const XATTR_SELINUX: &str = "security.selinux";

/// getxattr over a parsed attribute list (the read-only images).
fn find_xattr(attrs: io::Result<Vec<(String, Vec<u8>)>>, name: &str) -> Result<Vec<u8>, i64> {
    attrs.map_err(io_errno)?.into_iter().find(|(n, _)| n == name).map(|(_, v)| v).ok_or(ENODATA)
}

fn xattr_names(attrs: io::Result<Vec<(String, Vec<u8>)>>) -> Result<Vec<String>, i64> {
    Ok(attrs.map_err(io_errno)?.into_iter().map(|(n, _)| n).collect())
}

impl FileSystem for Erofs {
    fn fs_type(&self) -> &'static str {
        "erofs"
    }
    fn root(&self) -> io::Result<u64> {
        Ok(self.root_nid())
    }
    fn stat(&self, ino: u64) -> io::Result<Stat> {
        let i = self.inode(ino)?;
        let is_dev = matches!(i.mode & S_IFMT, 0o020000 | 0o060000);
        Ok(Stat {
            dev: 0,
            ino,
            mode: i.mode,
            nlink: i.nlink,
            uid: i.uid,
            gid: i.gid,
            rdev: if is_dev { i.raw as u64 } else { 0 },
            size: i.size,
            mtime: i.mtime,
        })
    }
    fn lookup(&self, dir: u64, name: &str) -> io::Result<Option<u64>> {
        self.lookup(&self.inode(dir)?, name)
    }
    fn readdir(&self, dir: u64) -> io::Result<Vec<Dirent>> {
        Ok(self
            .readdir(&self.inode(dir)?)?
            .into_iter()
            .map(|e| Dirent {
                name: e.name,
                ino: e.nid,
                dtype: ft_to_dt(e.file_type),
            })
            .collect())
    }
    fn read_all(&self, ino: u64) -> io::Result<Arc<[u8]>> {
        self.read(&self.inode(ino)?)
    }
    fn getxattr(&self, ino: u64, name: &str) -> Result<Vec<u8>, i64> {
        find_xattr(self.inode(ino).and_then(|i| self.xattrs(&i)), name)
    }
    fn listxattr(&self, ino: u64) -> Result<Vec<String>, i64> {
        xattr_names(self.inode(ino).and_then(|i| self.xattrs(&i)))
    }
}

/// EROFS and ext4 share the dirent file-type numbering (1 file … 7 symlink).
const FT_TO_DT: [u8; 8] = [0, 8, 4, 2, 6, 1, 12, 10];

fn ft_to_dt(ft: u8) -> u8 {
    FT_TO_DT.get(ft as usize).copied().unwrap_or(0)
}

impl FileSystem for Ext4 {
    fn fs_type(&self) -> &'static str {
        "ext4"
    }
    fn root(&self) -> io::Result<u64> {
        Ok(self.root_ino())
    }
    fn stat(&self, ino: u64) -> io::Result<Stat> {
        let i = self.inode(ino)?;
        Ok(Stat {
            dev: 0,
            ino,
            mode: i.mode,
            nlink: i.nlink,
            uid: i.uid,
            gid: i.gid,
            rdev: 0,
            size: i.size,
            mtime: i.mtime,
        })
    }
    fn lookup(&self, dir: u64, name: &str) -> io::Result<Option<u64>> {
        self.lookup(&self.inode(dir)?, name)
    }
    fn readdir(&self, dir: u64) -> io::Result<Vec<Dirent>> {
        Ok(self
            .readdir(&self.inode(dir)?)?
            .into_iter()
            .map(|e| Dirent {
                name: e.name,
                ino: e.ino,
                dtype: ft_to_dt(e.file_type),
            })
            .collect())
    }
    fn read_all(&self, ino: u64) -> io::Result<Arc<[u8]>> {
        self.read(&self.inode(ino)?)
    }
    fn getxattr(&self, ino: u64, name: &str) -> Result<Vec<u8>, i64> {
        find_xattr(self.xattrs(ino), name)
    }
    fn listxattr(&self, ino: u64) -> Result<Vec<String>, i64> {
        xattr_names(self.xattrs(ino))
    }
}

/// Opens whichever read-only filesystem `dev` holds.
pub fn open_fs(dev: crate::image::Dev) -> io::Result<Arc<dyn FileSystem>> {
    match Erofs::open(dev.clone()) {
        Ok(fs) => Ok(fs),
        Err(_) => Ok(Ext4::open(dev)? as Arc<dyn FileSystem>),
    }
}

/// Opens `dev` as `fstype` ("ext4" or "erofs"), for mount(2).
pub fn open_fs_as(dev: crate::image::Dev, fstype: &str) -> io::Result<Arc<dyn FileSystem>> {
    match fstype {
        "erofs" => Ok(Erofs::open(dev)?),
        _ => Ok(Ext4::open(dev)?),
    }
}

/// A filesystem that is only opened on first use (APEX payloads are big).
type Opener = Box<dyn FnOnce() -> io::Result<Arc<dyn FileSystem>> + Send>;

pub struct LazyFs {
    open: Mutex<Option<Opener>>,
    fs: OnceLock<Result<Arc<dyn FileSystem>, String>>,
}

impl LazyFs {
    pub fn new(
        open: impl FnOnce() -> io::Result<Arc<dyn FileSystem>> + Send + 'static,
    ) -> Arc<LazyFs> {
        Arc::new(LazyFs {
            open: Mutex::new(Some(Box::new(open))),
            fs: OnceLock::new(),
        })
    }

    fn get(&self) -> io::Result<&Arc<dyn FileSystem>> {
        let r = self.fs.get_or_init(|| {
            let f = self
                .open
                .lock()
                .unwrap()
                .take()
                .expect("LazyFs opened twice");
            f().map_err(|e| e.to_string())
        });
        r.as_ref().map_err(|e| io::Error::other(e.clone()))
    }
}

/// The root of a LazyFs: stat-able without opening the filesystem (tools
/// that stat every mount point, like `mount -o remount`, would otherwise
/// open every APEX).
const LAZY_ROOT: u64 = u64::MAX;

impl LazyFs {
    fn real(&self, ino: u64) -> io::Result<(&Arc<dyn FileSystem>, u64)> {
        let fs = self.get()?;
        Ok((fs, if ino == LAZY_ROOT { fs.root()? } else { ino }))
    }
}

impl FileSystem for LazyFs {
    fn fs_type(&self) -> &'static str {
        self.fs.get().and_then(|r| r.as_ref().ok()).map_or("ext4", |f| f.fs_type())
    }
    fn root(&self) -> io::Result<u64> {
        Ok(LAZY_ROOT)
    }
    fn stat(&self, ino: u64) -> io::Result<Stat> {
        if ino == LAZY_ROOT && self.fs.get().is_none() {
            return Ok(Stat { ino: 2, mode: S_IFDIR | 0o755, nlink: 2, size: 4096, ..Default::default() });
        }
        let (fs, ino) = self.real(ino)?;
        fs.stat(ino)
    }
    fn lookup(&self, dir: u64, name: &str) -> io::Result<Option<u64>> {
        let (fs, dir) = self.real(dir)?;
        fs.lookup(dir, name)
    }
    fn readdir(&self, dir: u64) -> io::Result<Vec<Dirent>> {
        let (fs, dir) = self.real(dir)?;
        fs.readdir(dir)
    }
    fn read_all(&self, ino: u64) -> io::Result<Arc<[u8]>> {
        let (fs, ino) = self.real(ino)?;
        fs.read_all(ino)
    }
    fn getxattr(&self, ino: u64, name: &str) -> Result<Vec<u8>, i64> {
        let (fs, ino) = self.real(ino).map_err(io_errno)?;
        fs.getxattr(ino, name)
    }
    fn setxattr(&self, ino: u64, name: &str, value: &[u8], flags: u32) -> Result<(), i64> {
        let (fs, ino) = self.real(ino).map_err(io_errno)?;
        fs.setxattr(ino, name, value, flags)
    }
    fn listxattr(&self, ino: u64) -> Result<Vec<String>, i64> {
        let (fs, ino) = self.real(ino).map_err(io_errno)?;
        fs.listxattr(ino)
    }
    fn removexattr(&self, ino: u64, name: &str) -> Result<(), i64> {
        let (fs, ino) = self.real(ino).map_err(io_errno)?;
        fs.removexattr(ino, name)
    }
}

// Mount flags (mount(2)'s MS_*) that a mount or a superblock keeps.
pub const MS_RDONLY: u64 = 1;
pub const MS_NOSUID: u64 = 2;
pub const MS_NODEV: u64 = 4;
pub const MS_NOEXEC: u64 = 8;
pub const MS_SYNCHRONOUS: u64 = 16;
pub const MS_MANDLOCK: u64 = 64;
pub const MS_DIRSYNC: u64 = 128;
pub const MS_NOSYMFOLLOW: u64 = 256;
pub const MS_NOATIME: u64 = 1024;
pub const MS_NODIRATIME: u64 = 2048;
pub const MS_RELATIME: u64 = 1 << 21;
pub const MS_LAZYTIME: u64 = 1 << 25;

/// The parent id shown for the root mount (Linux's hidden rootfs).
const ROOT_PARENT: u32 = 1;

/// A filesystem instance (Linux's superblock), shared by its bind mounts.
pub struct Super {
    pub fs: Arc<dyn FileSystem>,
    /// st_dev of its files.
    pub dev: u64,
    /// The mount(2) source, as /proc/mounts shows it.
    pub source: String,
    /// MS_RDONLY, MS_SYNCHRONOUS, MS_MANDLOCK, MS_DIRSYNC, MS_LAZYTIME.
    pub flags: AtomicU64,
    /// Filesystem-specific options for /proc/mounts ("mode=755").
    pub options: Mutex<String>,
}

/// Mount propagation as /proc/<pid>/mountinfo shows it: peer group ids, 0 for none.
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
pub struct Propagation {
    pub shared: u32,
    pub master: u32,
    pub unbindable: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PropagationChange {
    Shared,
    Private,
    Slave,
    Unbindable,
}

pub struct Mount {
    pub id: u32,
    pub parent: u32,
    /// Where it is attached: a canonical absolute path.
    pub path: String,
    pub sb: Arc<Super>,
    /// The mount's root in `sb.fs` (None: the filesystem's own root, looked
    /// up on first use so lazily opened APEXes stay unopened), and its path
    /// there ("/" unless this is a bind mount of a subtree).
    root: Option<u64>,
    pub root_path: String,
    /// MS_RDONLY, MS_NOSUID, MS_NODEV, MS_NOEXEC, MS_NOATIME, MS_NODIRATIME,
    /// MS_RELATIME, MS_NOSYMFOLLOW.
    pub flags: AtomicU64,
    pub propagation: Mutex<Propagation>,
}

impl Mount {
    pub fn readonly(&self) -> bool {
        (self.flags.load(Ordering::Relaxed) | self.sb.flags.load(Ordering::Relaxed)) & MS_RDONLY != 0
    }

    fn root_ino(&self) -> Result<u64, i64> {
        match self.root {
            Some(i) => Ok(i),
            None => self.sb.fs.root().map_err(io_errno),
        }
    }

    /// A copy at another place (MS_MOVE keeps the id, so children still find it).
    fn moved(&self, parent: u32, path: String) -> Arc<Mount> {
        Arc::new(Mount {
            id: self.id,
            parent,
            path,
            sb: self.sb.clone(),
            root: self.root,
            root_path: self.root_path.clone(),
            flags: AtomicU64::new(self.flags.load(Ordering::Relaxed)),
            propagation: Mutex::new(*self.propagation.lock().unwrap()),
        })
    }
}

#[derive(Clone)]
pub struct Node {
    mnt: Arc<Mount>,
    pub ino: u64,
    /// Canonical absolute path (no symlinks, "." or "..").
    pub path: String,
}

impl std::fmt::Debug for Node {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Node({} ino {} on mount {})", self.path, self.ino, self.mnt.id)
    }
}

impl Node {
    pub fn mount(&self) -> &Arc<Mount> {
        &self.mnt
    }
    /// Whether this is the root of its mount (a mount point).
    pub fn is_mount_root(&self) -> bool {
        self.path == self.mnt.path
    }
}

/// An immutable snapshot of the mount table.
#[derive(Default)]
struct Table {
    /// In mount order.
    mounts: Vec<Arc<Mount>>,
    /// Mount point → indices of the mounts attached there.
    at: HashMap<String, Vec<usize>>,
}

impl Table {
    fn new(mounts: Vec<Arc<Mount>>) -> Table {
        let mut at: HashMap<String, Vec<usize>> = HashMap::new();
        for (i, m) in mounts.iter().enumerate() {
            at.entry(m.path.clone()).or_default().push(i);
        }
        Table { mounts, at }
    }

    /// What `path`, reached on mount `parent`, shows: the mount attached
    /// there and then whatever is stacked on top of it.
    fn covering(&self, parent: &Mount, path: &str) -> Option<&Arc<Mount>> {
        let at = self.at.get(path)?;
        let (mut top, mut id) = (None, parent.id);
        for _ in 0..at.len() {
            let Some(&i) = at.iter().find(|&&i| self.mounts[i].parent == id) else { break };
            top = Some(&self.mounts[i]);
            id = self.mounts[i].id;
        }
        top
    }

    fn root(&self) -> Result<Node, i64> {
        let first = self.mounts.first().ok_or(ENOENT)?;
        let m = self.covering(first, "/").unwrap_or(first);
        Ok(Node { mnt: m.clone(), ino: m.root_ino()?, path: "/".into() })
    }

    /// `m` and every mount beneath it.
    fn subtree(&self, m: &Mount) -> HashSet<u32> {
        let mut set = HashSet::from([m.id]);
        // A fixpoint: MS_MOVE can leave a child before its new parent in mount order.
        loop {
            let n = set.len();
            for x in &self.mounts {
                if set.contains(&x.parent) {
                    set.insert(x.id);
                }
            }
            if set.len() == n {
                return set;
            }
        }
    }
}

#[derive(Default)]
pub struct Vfs {
    table: RwLock<Arc<Table>>,
    /// Serializes changes: copy the table, edit it, publish it.
    edit: Mutex<()>,
    ids: AtomicU32,
    anon: AtomicU32,
    groups: AtomicU32,
    /// Single-instance filesystems (proc, sysfs, cgroup hierarchies) that
    /// mount(2) reuses, also once unmounted.
    kept: Mutex<Vec<Arc<Super>>>,
    /// Bumped on every change to the table (Linux's mnt_namespace event).
    events: Arc<AtomicU64>,
}

fn io_errno(e: io::Error) -> i64 {
    if let Some(Errno(n)) = e.get_ref().and_then(|i| i.downcast_ref::<Errno>()) {
        return *n;
    }
    eprintln!("[droidrt] vfs I/O error: {e}");
    EIO
}

fn join(dir: &str, name: &str) -> String {
    if dir == "/" {
        format!("/{name}")
    } else {
        format!("{dir}/{name}")
    }
}

/// `path` (at or under `from`) moved to under `to`.
fn rebase(path: &str, from: &str, to: &str) -> String {
    let rest = if from == "/" { path } else { &path[from.len()..] };
    match (to, rest) {
        (_, "" | "/") => to.to_string(),
        ("/", r) => r.to_string(),
        (t, r) => format!("{t}{r}"),
    }
}

fn under(path: &str, dir: &str) -> bool {
    dir == "/" || path == dir || path.strip_prefix(dir).is_some_and(|r| r.starts_with('/'))
}

impl Vfs {
    fn table(&self) -> Arc<Table> {
        self.table.read().unwrap().clone()
    }

    /// Applies `f` to a copy of the mount list and publishes the result.
    fn edit<R>(&self, f: impl FnOnce(&Table, &mut Vec<Arc<Mount>>) -> Result<R, i64>) -> Result<R, i64> {
        let _g = self.edit.lock().unwrap();
        let tab = self.table();
        let mut mounts = tab.mounts.clone();
        let r = f(&tab, &mut mounts)?;
        *self.table.write().unwrap() = Arc::new(Table::new(mounts));
        self.touch();
        Ok(r)
    }

    /// Notes a change to the mount table (or a mount's flags) for pollers of /proc/mounts.
    pub fn touch(&self) {
        self.events.fetch_add(1, Ordering::Relaxed);
    }

    pub fn events(&self) -> Arc<AtomicU64> {
        self.events.clone()
    }

    fn new_group(&self) -> u32 {
        self.groups.fetch_add(1, Ordering::Relaxed) + 1
    }

    /// An anonymous device number (major 0), as Linux gives virtual filesystems.
    pub fn anon_dev(&self) -> u64 {
        let n = self.anon.fetch_add(1, Ordering::Relaxed) as u64 + 1;
        (n & 0xff) | (n & !0xff) << 12
    }

    pub fn new_super(&self, fs: Arc<dyn FileSystem>, source: &str, dev: Option<u64>, flags: u64, options: &str) -> Arc<Super> {
        let dev = dev.unwrap_or_else(|| self.anon_dev());
        Arc::new(Super { fs, dev, source: source.to_string(), flags: AtomicU64::new(flags), options: Mutex::new(options.to_string()) })
    }

    /// A mount of `sb` (its subtree at `root`) attached on `parent` at `path`.
    /// Under a shared mount it is shared too: in the bind source's peer group
    /// (`peer`) or a new one, as in Linux.
    #[allow(clippy::too_many_arguments)]
    fn new_mount(&self, parent: &Mount, path: String, sb: Arc<Super>, root: Option<u64>, root_path: String, flags: u64, peer: u32) -> Arc<Mount> {
        let shared = if peer != 0 {
            peer
        } else if parent.propagation.lock().unwrap().shared != 0 {
            self.new_group()
        } else {
            0
        };
        Arc::new(Mount {
            id: self.ids.fetch_add(1, Ordering::Relaxed) + ROOT_PARENT + 1,
            parent: parent.id,
            path,
            sb,
            root,
            root_path,
            flags: AtomicU64::new(flags),
            propagation: Mutex::new(Propagation { shared, ..Default::default() }),
        })
    }

    /// Linux's propagate_mnt: `tree` (its first mount just attached on
    /// `dest`, the rest beneath it) is copied onto every other mount that
    /// receives events from `dest`'s peer group (its peers and slaves) where
    /// the mount point is visible. Copies are peers of what they copy, so
    /// later mounts on them propagate too.
    fn propagate(&self, mounts: &mut Vec<Arc<Mount>>, dest: &Mount, tree: &[Arc<Mount>]) {
        let group = dest.propagation.lock().unwrap().shared;
        let Some(top) = tree.first() else { return };
        if group == 0 {
            return;
        }
        let inner = rebase(&top.path, &dest.path, &dest.root_path);
        let receivers: Vec<(Arc<Mount>, bool)> = mounts
            .iter()
            .filter(|r| r.id != dest.id && !tree.iter().any(|t| t.id == r.id) && Arc::ptr_eq(&r.sb, &dest.sb))
            .filter_map(|r| {
                let p = *r.propagation.lock().unwrap();
                (p.shared == group || p.master == group).then(|| (r.clone(), p.shared != group))
            })
            .collect();
        for (r, slave) in receivers {
            if !under(&inner, &r.root_path) {
                continue;
            }
            let at = rebase(&inner, &r.root_path, &r.path);
            let mut copies: HashMap<u32, u32> = HashMap::new();
            for (i, m) in tree.iter().enumerate() {
                let (parent, path) = match (i, copies.get(&m.parent)) {
                    (0, _) => (r.id, at.clone()),
                    (_, Some(&p)) => (p, rebase(&m.path, &top.path, &at)),
                    _ => continue,
                };
                let shared = m.propagation.lock().unwrap().shared;
                let propagation = if slave { Propagation { master: shared, ..Default::default() } } else { Propagation { shared, ..Default::default() } };
                let c = Arc::new(Mount {
                    id: self.ids.fetch_add(1, Ordering::Relaxed) + ROOT_PARENT + 1,
                    parent,
                    path,
                    sb: m.sb.clone(),
                    root: m.root,
                    root_path: m.root_path.clone(),
                    flags: AtomicU64::new(m.flags.load(Ordering::Relaxed)),
                    propagation: Mutex::new(propagation),
                });
                copies.insert(m.id, c.id);
                mounts.push(c);
            }
        }
    }

    /// Mounts `fs` at `path` while assembling the namespace (the mount point
    /// need not exist); the first mount must be "/".
    pub fn mount(&self, path: &str, fs: Arc<dyn FileSystem>) {
        let image = matches!(fs.fs_type(), "erofs" | "ext4");
        let source = if image { "/dev/block/droidrt" } else { fs.fs_type() };
        let ro = if image { MS_RDONLY } else { 0 };
        // What Linux would show for these mounts' options.
        let options = match fs.fs_type() {
            "tmpfs" => fs.root().and_then(|r| fs.stat(r)).map(|st| st.mode & 0o7777).ok().filter(|&m| m != 0o1777).map(|m| format!("mode={m:03o}")).unwrap_or_default(),
            "devpts" => "mode=600,ptmxmode=000".into(),
            _ => String::new(),
        };
        let sb = self.new_super(fs, source, None, ro, &options);
        if self.table().mounts.is_empty() {
            assert!(path == "/", "mount / first");
            let root = Arc::new(Mount {
                id: self.ids.fetch_add(1, Ordering::Relaxed) + ROOT_PARENT + 1,
                parent: ROOT_PARENT,
                path: "/".into(),
                sb,
                root: None,
                root_path: "/".into(),
                flags: AtomicU64::new(ro | MS_RELATIME),
                propagation: Mutex::default(),
            });
            self.edit(|_, mounts| {
                mounts.push(root);
                Ok(())
            })
            .unwrap();
            return;
        }
        // On what the path shows now; a missing mount point hangs off its parent directory.
        let (parent, path) = match self.resolve("/", path, true) {
            Ok(n) => (n.mnt, n.path),
            Err(_) => {
                let (dir, name) = path.trim_end_matches('/').rsplit_once('/').unwrap_or(("", path));
                let d = self.resolve("/", if dir.is_empty() { "/" } else { dir }, true).expect("mount point's parent directory");
                let p = join(&d.path, name);
                (d.mnt, p)
            }
        };
        let m = self.new_mount(&parent, path, sb, None, "/".into(), ro | MS_RELATIME, 0);
        self.edit(|_, mounts| {
            mounts.push(m);
            Ok(())
        })
        .unwrap();
    }

    /// Mounts a new filesystem instance on `target` (mount(2) without MS_BIND).
    pub fn mount_at(&self, target: &Node, sb: Arc<Super>, flags: u64) -> Result<(), i64> {
        let root = sb.fs.root().map_err(io_errno)?;
        if sb.fs.stat(root).map_err(io_errno)?.mode & S_IFMT == S_IFDIR && self.stat(target)?.mode & S_IFMT != S_IFDIR {
            return Err(ENOTDIR);
        }
        self.edit(|tab, mounts| {
            let dest = tab.mounts.iter().find(|m| m.id == target.mnt.id).cloned().ok_or(ENOENT)?; // ENOENT: its mount went away meanwhile
            let m = self.new_mount(&dest, target.path.clone(), sb, Some(root), "/".into(), flags, 0);
            mounts.push(m.clone());
            self.propagate(mounts, &dest, &[m]);
            Ok(())
        })
    }

    /// Bind-mounts `src` (a directory subtree or one file) on `target`;
    /// `recursive` (MS_REC) brings along the mounts beneath `src`.
    pub fn bind(&self, src: &Node, target: &Node, recursive: bool) -> Result<(), i64> {
        let sp = *src.mnt.propagation.lock().unwrap();
        if sp.unbindable {
            return Err(EINVAL);
        }
        let is_dir = |n: &Node| self.stat(n).map(|s| s.mode & S_IFMT == S_IFDIR);
        if is_dir(src)? != is_dir(target)? {
            return Err(ENOTDIR);
        }
        let root_path = rebase(&src.path, &src.mnt.path, &src.mnt.root_path);
        self.edit(|tab, mounts| {
            let dest = tab.mounts.iter().find(|m| m.id == target.mnt.id).cloned().ok_or(ENOENT)?;
            let flags = src.mnt.flags.load(Ordering::Relaxed);
            let top = self.new_mount(&dest, target.path.clone(), src.mnt.sb.clone(), Some(src.ino), root_path, flags, sp.shared);
            let first = mounts.len();
            mounts.push(top.clone());
            if recursive {
                // Copies of the mounts under `src`, in mount order so parents come first.
                let mut copies = HashMap::from([(src.mnt.id, top)]);
                let inside = tab.subtree(&src.mnt);
                for m in &tab.mounts {
                    if m.id == src.mnt.id || !inside.contains(&m.id) || !under(&m.path, &src.path) || m.path == src.path {
                        continue;
                    }
                    let Some(parent) = copies.get(&m.parent).cloned() else { continue };
                    let peer = m.propagation.lock().unwrap().shared;
                    let c = self.new_mount(&parent, rebase(&m.path, &src.path, &target.path), m.sb.clone(), m.root, m.root_path.clone(), m.flags.load(Ordering::Relaxed), peer);
                    mounts.push(c.clone());
                    copies.insert(m.id, c);
                }
            }
            let tree = mounts[first..].to_vec();
            self.propagate(mounts, &dest, &tree);
            Ok(())
        })
    }

    /// The live mount `node` is the root of: EINVAL if it is not a mount point.
    pub fn mount_root(&self, node: &Node) -> Result<Arc<Mount>, i64> {
        if !node.is_mount_root() {
            return Err(EINVAL);
        }
        self.table().mounts.iter().find(|m| m.id == node.mnt.id).cloned().ok_or(EINVAL)
    }

    /// Unmounts the mount whose root is `node`; returns what was removed.
    /// `detach` (MNT_DETACH) takes the mounts beneath it too, which otherwise
    /// make it EBUSY. Open files keep their filesystems alive.
    pub fn umount(&self, node: &Node, detach: bool) -> Result<Vec<Arc<Mount>>, i64> {
        let m = self.mount_root(node)?;
        if m.parent == ROOT_PARENT {
            return Err(EBUSY);
        }
        self.edit(|tab, mounts| {
            let mut gone = tab.subtree(&m);
            if gone.len() > 1 && !detach {
                return Err(EBUSY);
            }
            // propagate_umount: the copies on the parent's peers and slaves go too (busy ones stay).
            if let Some(dest) = tab.mounts.iter().find(|x| x.id == m.parent) {
                let group = dest.propagation.lock().unwrap().shared;
                let inner = rebase(&m.path, &dest.path, &dest.root_path);
                for r in tab.mounts.iter().filter(|r| r.id != dest.id && group != 0 && Arc::ptr_eq(&r.sb, &dest.sb)) {
                    let p = *r.propagation.lock().unwrap();
                    if (p.shared != group && p.master != group) || !under(&inner, &r.root_path) {
                        continue;
                    }
                    let at = rebase(&inner, &r.root_path, &r.path);
                    for c in tab.mounts.iter().filter(|c| c.parent == r.id && c.path == at && Arc::ptr_eq(&c.sb, &m.sb) && c.root == m.root) {
                        let sub = tab.subtree(c);
                        if sub.len() == 1 || detach {
                            gone.extend(sub);
                        }
                    }
                }
            }
            let removed = mounts.iter().filter(|x| gone.contains(&x.id)).cloned().collect();
            mounts.retain(|x| !gone.contains(&x.id));
            Ok(removed)
        })
    }

    /// MS_MOVE: re-attaches the mount at `src`, and everything beneath it, on `target`.
    pub fn move_mount(&self, src: &Node, target: &Node) -> Result<(), i64> {
        let m = self.mount_root(src)?;
        if m.parent == ROOT_PARENT {
            return Err(EINVAL);
        }
        if under(&target.path, &m.path) {
            return Err(ELOOP);
        }
        let is_dir = |n: &Node| self.stat(n).map(|s| s.mode & S_IFMT == S_IFDIR);
        if is_dir(src)? != is_dir(target)? {
            return Err(ENOTDIR);
        }
        self.edit(|tab, mounts| {
            let moving = tab.subtree(&m);
            for slot in mounts.iter_mut().filter(|x| moving.contains(&x.id)) {
                let parent = if slot.id == m.id { target.mnt.id } else { slot.parent };
                *slot = slot.moved(parent, rebase(&slot.path, &m.path, &target.path));
            }
            Ok(())
        })
    }

    /// MS_SHARED / MS_PRIVATE / MS_SLAVE / MS_UNBINDABLE on the mount at
    /// `node`; `recursive` (MS_REC) also on every mount beneath it.
    pub fn set_propagation(&self, node: &Node, change: PropagationChange, recursive: bool) -> Result<(), i64> {
        let m = self.mount_root(node)?;
        let tab = self.table();
        let ids = if recursive { tab.subtree(&m) } else { HashSet::from([m.id]) };
        for x in tab.mounts.iter().filter(|x| ids.contains(&x.id)) {
            let mut p = x.propagation.lock().unwrap();
            match change {
                PropagationChange::Shared if p.shared == 0 => p.shared = self.new_group(),
                PropagationChange::Shared => {}
                PropagationChange::Private => *p = Propagation::default(),
                PropagationChange::Slave if p.shared != 0 => *p = Propagation { master: p.shared, ..Default::default() },
                PropagationChange::Slave => p.unbindable = false,
                PropagationChange::Unbindable => *p = Propagation { unbindable: true, ..Default::default() },
            }
        }
        Ok(())
    }

    /// Every mount, in mount order (for /proc/mounts).
    pub fn mount_list(&self) -> Vec<Arc<Mount>> {
        self.table().mounts.clone()
    }

    /// An existing instance of a single-instance filesystem, mounted or kept.
    pub fn find_super(&self, pred: impl Fn(&Super) -> bool) -> Option<Arc<Super>> {
        let mounted = self.table().mounts.iter().map(|m| m.sb.clone()).find(|sb| pred(sb));
        mounted.or_else(|| self.kept.lock().unwrap().iter().find(|sb| pred(sb)).cloned())
    }

    /// Remembers `sb` for find_super after it is unmounted.
    pub fn keep(&self, sb: &Arc<Super>) {
        let mut kept = self.kept.lock().unwrap();
        if !kept.iter().any(|k| Arc::ptr_eq(k, sb)) {
            kept.push(sb.clone());
        }
    }

    fn fs<'a>(&self, node: &'a Node) -> &'a dyn FileSystem {
        &*node.mnt.sb.fs
    }

    /// The mount `node` is on, as the table has it now. An open file keeps the
    /// arc it was resolved with, and MS_MOVE publishes a replacement, so flag
    /// changes (a remount) are read from the table.
    fn live(&self, node: &Node) -> Arc<Mount> {
        self.table().mounts.iter().find(|m| m.id == node.mnt.id).cloned().unwrap_or_else(|| node.mnt.clone())
    }

    pub fn readonly(&self, node: &Node) -> bool {
        self.live(node).readonly()
    }

    pub fn fs_arc(&self, node: &Node) -> Arc<dyn FileSystem> {
        node.mnt.sb.fs.clone()
    }

    pub fn resolve(&self, cwd: &str, path: &str, follow_last: bool) -> Result<Node, i64> {
        if path.is_empty() {
            return Err(ENOENT);
        }
        let full = if path.starts_with('/') {
            path.to_string()
        } else {
            format!("{cwd}/{path}")
        };
        let mut todo: Vec<String> = full
            .split('/')
            .rev()
            .filter(|c| !c.is_empty())
            .map(String::from)
            .collect();
        let tab = self.table();
        let mut stack = vec![tab.root()?];
        let mut links = 0;

        while let Some(c) = todo.pop() {
            if c == "." {
                continue;
            }
            if c == ".." {
                if stack.len() > 1 {
                    stack.pop();
                }
                continue;
            }
            let cur = stack.last().unwrap();
            if self.stat(cur)?.mode & S_IFMT != S_IFDIR {
                return Err(ENOTDIR);
            }
            let child_path = join(&cur.path, &c);
            let node = match tab.covering(&cur.mnt, &child_path) {
                Some(m) => Node {
                    mnt: m.clone(),
                    ino: m.root_ino()?,
                    path: child_path,
                },
                None => match self.fs(cur).lookup(cur.ino, &c).map_err(io_errno)? {
                    Some(ino) => Node {
                        mnt: cur.mnt.clone(),
                        ino,
                        path: child_path,
                    },
                    None => return Err(ENOENT),
                },
            };
            let st = self.stat(&node)?;
            if st.mode & S_IFMT == S_IFLNK && (follow_last || !todo.is_empty()) {
                if let Some(ino) = self.fs(&node).magic_link(node.ino) {
                    stack.push(Node { ino, ..node });
                    continue;
                }
                links += 1;
                if links > 40 || node.mnt.flags.load(Ordering::Relaxed) & MS_NOSYMFOLLOW != 0 {
                    return Err(ELOOP);
                }
                let target = self.read_all(&node)?;
                let target = String::from_utf8_lossy(&target).into_owned();
                if target.starts_with('/') {
                    stack.truncate(1);
                }
                todo.extend(
                    target
                        .split('/')
                        .rev()
                        .filter(|c| !c.is_empty())
                        .map(String::from),
                );
                continue;
            }
            stack.push(node);
        }
        Ok(stack.pop().unwrap())
    }

    pub fn stat(&self, node: &Node) -> Result<Stat, i64> {
        let mut st = self.fs(node).stat(node.ino).map_err(io_errno)?;
        st.dev = node.mnt.sb.dev;
        Ok(st)
    }

    pub fn read_all(&self, node: &Node) -> Result<Arc<[u8]>, i64> {
        self.fs(node).read_all(node.ino).map_err(io_errno)
    }

    pub fn fs_type(&self, node: &Node) -> &'static str {
        self.fs(node).fs_type()
    }

    /// Whether writes can land: a writable filesystem or kernel file, on a read-write mount.
    pub fn writable(&self, node: &Node) -> bool {
        !self.readonly(node) && (self.fs(node).writable() || self.fs(node).write_ok(node.ino))
    }

    /// A kernel file that interprets writes (see FileSystem::write_ok).
    pub fn write_ok(&self, node: &Node) -> bool {
        !self.readonly(node) && self.fs(node).write_ok(node.ino)
    }

    pub fn write(&self, node: &Node, data: &[u8]) -> Result<usize, i64> {
        if self.readonly(node) {
            return Err(EROFS);
        }
        self.fs(node).write(node.ino, data)
    }

    pub fn mem_file(&self, node: &Node) -> Option<Arc<MemFile>> {
        self.fs(node).mem_file(node.ino)
    }

    pub fn space(&self, node: &Node) -> Option<(u64, u64)> {
        self.fs(node).space()
    }

    pub fn changes(&self, node: &Node) -> Option<Arc<AtomicU64>> {
        self.fs(node).changes(node.ino)
    }

    /// Resolves everything but the last component: (directory, name).
    pub fn resolve_parent(&self, cwd: &str, path: &str) -> Result<(Node, String), i64> {
        let trimmed = path.trim_end_matches('/');
        let (dir, name) = match trimmed.rsplit_once('/') {
            Some(("", name)) => ("/", name),
            Some((dir, name)) => (dir, name),
            None if path.starts_with('/') => return Err(EBUSY), // "/" itself
            None => (".", trimmed),
        };
        if name.is_empty() || name == "." || name == ".." {
            return Err(EINVAL);
        }
        let dir_node = self.resolve(cwd, dir, true)?;
        if self.stat(&dir_node)?.mode & S_IFMT != S_IFDIR {
            return Err(ENOTDIR);
        }
        Ok((dir_node, name.to_string()))
    }

    fn is_mount_point(&self, dir: &Node, name: &str) -> bool {
        self.table().covering(&dir.mnt, &join(&dir.path, name)).is_some()
    }

    /// Linux's order for creating `name`: EEXIST if it is taken (a mount
    /// point counts), then EROFS.
    fn creatable(&self, dir: &Node, name: &str) -> Result<(), i64> {
        if self.is_mount_point(dir, name) || self.fs(dir).lookup(dir.ino, name).map_err(io_errno)?.is_some() {
            return Err(EEXIST);
        }
        if self.readonly(dir) {
            return Err(EROFS);
        }
        Ok(())
    }

    /// For unlink, rmdir and rename: mount points are EBUSY.
    fn removable(&self, dir: &Node, name: &str) -> Result<(), i64> {
        if self.readonly(dir) {
            return Err(EROFS);
        }
        if self.is_mount_point(dir, name) {
            return Err(EBUSY);
        }
        Ok(())
    }

    /// A child of `dir`, looked up afresh (after creating it).
    pub fn child(&self, dir: &Node, name: &str, ino: u64) -> Node {
        Node { mnt: dir.mnt.clone(), ino, path: join(&dir.path, name) }
    }

    pub fn create(&self, dir: &Node, name: &str, mode: u32, rdev: u64) -> Result<Node, i64> {
        self.creatable(dir, name)?;
        let ino = self.fs(dir).create(dir.ino, name, mode, rdev)?;
        Ok(self.child(dir, name, ino))
    }

    pub fn mkdir(&self, dir: &Node, name: &str, mode: u32) -> Result<(), i64> {
        self.creatable(dir, name)?;
        self.fs(dir).mkdir(dir.ino, name, mode).map(|_| ())
    }

    pub fn symlink(&self, dir: &Node, name: &str, target: &str) -> Result<(), i64> {
        self.creatable(dir, name)?;
        self.fs(dir).symlink(dir.ino, name, target).map(|_| ())
    }

    pub fn link(&self, node: &Node, dir: &Node, name: &str) -> Result<(), i64> {
        self.creatable(dir, name)?;
        if node.mnt.id != dir.mnt.id {
            return Err(EXDEV);
        }
        self.fs(dir).link(node.ino, dir.ino, name)
    }

    pub fn unlink(&self, dir: &Node, name: &str, rmdir: bool) -> Result<(), i64> {
        self.removable(dir, name)?;
        self.fs(dir).unlink(dir.ino, name, rmdir)
    }

    pub fn rename(&self, odir: &Node, oname: &str, ndir: &Node, nname: &str, noreplace: bool) -> Result<(), i64> {
        if odir.mnt.id != ndir.mnt.id {
            return Err(EXDEV);
        }
        self.removable(odir, oname)?;
        self.removable(ndir, nname)?;
        self.fs(odir).rename(odir.ino, oname, ndir.ino, nname, noreplace)
    }

    pub fn set_attr(&self, node: &Node, mode: Option<u32>, owner: Option<(u32, u32)>, mtime: Option<u64>) -> Result<(), i64> {
        if self.readonly(node) {
            return Err(EROFS);
        }
        self.fs(node).set_attr(node.ino, mode, owner, mtime)
    }

    pub fn getxattr(&self, node: &Node, name: &str) -> Result<Vec<u8>, i64> {
        self.fs(node).getxattr(node.ino, name)
    }

    pub fn setxattr(&self, node: &Node, name: &str, value: &[u8], flags: u32) -> Result<(), i64> {
        self.fs(node).setxattr(node.ino, name, value, flags)
    }

    pub fn listxattr(&self, node: &Node) -> Result<Vec<String>, i64> {
        self.fs(node).listxattr(node.ino)
    }

    pub fn removexattr(&self, node: &Node, name: &str) -> Result<(), i64> {
        self.fs(node).removexattr(node.ino, name)
    }

    pub fn readdir(&self, node: &Node) -> Result<Vec<Dirent>, i64> {
        let mut out = self.fs(node).readdir(node.ino).map_err(io_errno)?;
        // Mount points directly under this directory, even if not in its filesystem.
        for m in self.table().mounts.iter().filter(|m| m.parent == node.mnt.id) {
            if let Some((parent, name)) = m.path.rsplit_once('/') {
                let parent = if parent.is_empty() { "/" } else { parent };
                if parent == node.path && !name.is_empty() && !out.iter().any(|d| d.name == name) {
                    out.push(Dirent {
                        name: name.to_string(),
                        ino: 0,
                        dtype: 4,
                    });
                }
            }
        }
        Ok(out)
    }
}

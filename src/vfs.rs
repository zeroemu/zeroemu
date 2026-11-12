//! The guest's file namespace: a mount table over filesystems, with Linux
//! path resolution (symlinks, "..", mount crossings).
//!
//! The table is an immutable snapshot behind an `RwLock<Arc<_>>`: resolution
//! clones the `Arc` and never holds a lock while it calls into filesystems,
//! and mount/umount build a new snapshot and publish it. Each mount
//! namespace has its own table; a host thread resolves paths in the
//! namespace of the guest process it runs (`set_current_ns`), so callers
//! need not pass it around.

use crate::errno::*;
use crate::image::erofs::Erofs;
use crate::image::ext4::Ext4;
use crate::tmpfs::MemFile;
use std::collections::{HashMap, HashSet};
use std::io;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::cell::Cell;
use std::sync::{Arc, Mutex, OnceLock, RwLock};

pub const S_IFMT: u32 = 0o170000;
pub const S_IFDIR: u32 = 0o040000;
pub const S_IFREG: u32 = 0o100000;
pub const S_IFLNK: u32 = 0o120000;
pub const S_IFSOCK: u32 = 0o140000;

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

/// Asked about each directory a caller's path walk looks a name up in.
pub type Search<'a> = &'a dyn Fn(&Node, &Stat) -> Result<(), i64>;

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

    /// Bytes of a file from `off`: as many as `buf` holds, unless it ends first.
    fn read_at(&self, ino: u64, off: u64, buf: &mut [u8]) -> io::Result<usize> {
        let data = self.read_all(ino)?;
        let from = usize::try_from(off).unwrap_or(usize::MAX).min(data.len());
        let n = (data.len() - from).min(buf.len());
        buf[..n].copy_from_slice(&data[from..from + n]);
        Ok(n)
    }

    /// Whether its files never change, so that the page cache can hold them
    /// (the read-only images, as opposed to what is generated on each read).
    fn paged(&self) -> bool {
        false
    }

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
    /// A counter for what was just written to set up, if it asks for events (a PSI
    /// trigger): the file written through then reports those instead of `changes`.
    fn trigger(&self, _ino: u64, _data: &[u8]) -> Option<Arc<AtomicU64>> {
        None
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
    fn read_at(&self, ino: u64, off: u64, buf: &mut [u8]) -> io::Result<usize> {
        self.read_range(&self.inode(ino)?, off, buf)
    }
    fn paged(&self) -> bool {
        true
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
    fn read_at(&self, ino: u64, off: u64, buf: &mut [u8]) -> io::Result<usize> {
        self.read_range(&self.inode(ino)?, off, buf)
    }
    fn paged(&self) -> bool {
        true
    }
    fn getxattr(&self, ino: u64, name: &str) -> Result<Vec<u8>, i64> {
        find_xattr(self.xattrs(ino), name)
    }
    fn listxattr(&self, ino: u64) -> Result<Vec<String>, i64> {
        xattr_names(self.xattrs(ino))
    }
}

/// A file in a filesystem as a device, read straight through.
pub struct FileAsDev {
    pub fs: Arc<dyn FileSystem>,
    pub ino: u64,
    pub size: u64,
}

impl crate::image::ReadAt for FileAsDev {
    fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        if self.fs.read_at(self.ino, offset, buf)? != buf.len() {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        Ok(())
    }
    fn len(&self) -> u64 {
        self.size
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
    fn read_at(&self, ino: u64, off: u64, buf: &mut [u8]) -> io::Result<usize> {
        let (fs, ino) = self.real(ino)?;
        fs.read_at(ino, off, buf)
    }
    fn paged(&self) -> bool {
        true // it only ever opens one of the images
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
    /// What it is mounted as when that isn't the filesystem's own type: the fuse
    /// stand-in serves /data/media's tmpfs as "fuse". See `fs_type`.
    pub ty: Option<&'static str>,
    /// What the kernel keeps with this instance (a fuse connection). It goes when
    /// the superblock does: with the last mount of it and the last file open on it.
    pub private: Option<Arc<dyn std::any::Any + Send + Sync>>,
    /// st_dev of its files.
    pub dev: u64,
    /// The mount(2) source, as /proc/mounts shows it.
    pub source: String,
    /// MS_RDONLY, MS_SYNCHRONOUS, MS_MANDLOCK, MS_DIRSYNC, MS_LAZYTIME.
    pub flags: AtomicU64,
    /// Filesystem-specific options for /proc/mounts ("mode=755").
    pub options: Mutex<String>,
}

impl Super {
    /// For /proc/mounts, statfs and permissions: what it is mounted as. (Asked of the
    /// filesystem each time: a lazily opened image only knows once it is open.)
    pub fn fs_type(&self) -> &'static str {
        self.ty.unwrap_or_else(|| self.fs.fs_type())
    }
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

impl Node {
    /// Which filesystem the inode number belongs to.
    pub fn fs_id(&self) -> usize {
        Arc::as_ptr(&self.mnt.sb.fs) as *const () as usize
    }
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

/// The first mount namespace, which the kernel itself and the first process use.
pub const INIT_NS: u32 = 0;

thread_local! {
    static CURRENT_NS: Cell<u32> = const { Cell::new(INIT_NS) };
}

/// The mount namespace this host thread resolves paths in.
pub fn current_ns() -> u32 {
    CURRENT_NS.with(Cell::get)
}

pub fn set_current_ns(ns: u32) {
    CURRENT_NS.with(|c| c.set(ns));
}

type Space = Arc<RwLock<Arc<Table>>>;

#[derive(Default)]
pub struct Vfs {
    /// Mount namespaces by id.
    spaces: RwLock<HashMap<u32, Space>>,
    ns_ids: AtomicU32,
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
    /// Holds the read-only images' pages, once there is guest memory to hold them in.
    cache: OnceLock<Arc<crate::pagecache::PageCache>>,
    /// How many processes are in each namespace that goes when they do. Every app
    /// starts with one of its own, holding a copy of the whole mount table.
    ns_users: Mutex<HashMap<u32, u32>>,
}

pub(crate) fn io_errno(e: io::Error) -> i64 {
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

/// The mounts in `tab` that propagate_umount takes with `m` (attached on
/// `dest`): its copies on `dest`'s peers and slaves, with what is beneath them
/// if `detach`, and only unbusy ones otherwise.
fn propagated_copies(tab: &Table, dest: &Mount, m: &Mount, detach: bool) -> HashSet<u32> {
    let mut out = HashSet::new();
    let group = dest.propagation.lock().unwrap().shared;
    if group == 0 {
        return out;
    }
    let inner = rebase(&m.path, &dest.path, &dest.root_path);
    for r in tab.mounts.iter().filter(|r| r.id != dest.id && Arc::ptr_eq(&r.sb, &dest.sb)) {
        let p = *r.propagation.lock().unwrap();
        if (p.shared != group && p.master != group) || !under(&inner, &r.root_path) {
            continue;
        }
        let at = rebase(&inner, &r.root_path, &r.path);
        for c in tab.mounts.iter().filter(|c| c.parent == r.id && c.path == at && Arc::ptr_eq(&c.sb, &m.sb) && c.root == m.root) {
            let sub = tab.subtree(c);
            if sub.len() == 1 || detach {
                out.extend(sub);
            }
        }
    }
    out
}

impl Vfs {
    /// Namespace `ns`'s table (the first namespace's if `ns` is gone).
    fn ns_space(&self, ns: u32) -> Space {
        if let Some(s) = self.spaces.read().unwrap().get(&ns) {
            return s.clone();
        }
        self.spaces.write().unwrap().entry(INIT_NS).or_default().clone()
    }

    fn table(&self) -> Arc<Table> {
        self.ns_space(current_ns()).read().unwrap().clone()
    }

    /// Applies `f` to a copy of the current namespace's mount list and
    /// publishes the result. `f` may also change other namespaces through
    /// `elsewhere` (propagation), under the same lock.
    fn edit<R>(&self, f: impl FnOnce(&Table, &mut Vec<Arc<Mount>>) -> Result<R, i64>) -> Result<R, i64> {
        let _g = self.edit.lock().unwrap();
        let space = self.ns_space(current_ns());
        let tab = space.read().unwrap().clone();
        let mut mounts = tab.mounts.clone();
        let r = f(&tab, &mut mounts)?;
        *space.write().unwrap() = Arc::new(Table::new(mounts));
        self.touch();
        Ok(r)
    }

    /// Runs `f` on every namespace but the current one (with `edit`'s lock held).
    fn elsewhere(&self, mut f: impl FnMut(&Table, &mut Vec<Arc<Mount>>)) {
        let me = current_ns();
        let spaces: Vec<Space> = self.spaces.read().unwrap().iter().filter(|(id, _)| **id != me).map(|(_, s)| s.clone()).collect();
        for space in spaces {
            let tab = space.read().unwrap().clone();
            let mut mounts = tab.mounts.clone();
            f(&tab, &mut mounts);
            if mounts.len() != tab.mounts.len() {
                *space.write().unwrap() = Arc::new(Table::new(mounts));
            }
        }
    }

    /// A process joins a namespace.
    pub fn ns_enter(&self, ns: u32) {
        if let Some(n) = self.ns_users.lock().unwrap().get_mut(&ns) {
            *n += 1;
        }
    }

    /// A process leaves a namespace, which goes with the last. Linux keeps one for as long
    /// as a descriptor names it, too; those here only ever name init's, which stay.
    pub fn ns_leave(&self, ns: u32) {
        let mut users = self.ns_users.lock().unwrap();
        let Some(n) = users.get_mut(&ns) else { return };
        *n = n.saturating_sub(1);
        if *n > 0 {
            return;
        }
        users.remove(&ns);
        drop(users);
        let gone = self.spaces.write().unwrap().remove(&ns);
        drop(gone); // with no lock held: what it held may be the last of a filesystem
    }

    /// unshare(CLONE_NEWNS): a new namespace holding a copy of the current
    /// one's mounts. Copies of shared mounts are their peers, so mount events
    /// keep propagating between the namespaces (init's /bootstrap-apex). A `lasting`
    /// one stays when nobody's in it: init keeps descriptors to go back to its own.
    pub fn clone_ns(&self, lasting: bool) -> u32 {
        let _g = self.edit.lock().unwrap();
        let tab = self.table();
        let mut ids: HashMap<u32, u32> = HashMap::new();
        let mut mounts = Vec::with_capacity(tab.mounts.len());
        for m in &tab.mounts {
            let id = self.ids.fetch_add(1, Ordering::Relaxed) + ROOT_PARENT + 1;
            ids.insert(m.id, id);
            mounts.push((m, id));
        }
        let copies = mounts
            .into_iter()
            .map(|(m, id)| {
                Arc::new(Mount {
                    id,
                    parent: ids.get(&m.parent).copied().unwrap_or(m.parent),
                    path: m.path.clone(),
                    sb: m.sb.clone(),
                    root: m.root,
                    root_path: m.root_path.clone(),
                    flags: AtomicU64::new(m.flags.load(Ordering::Relaxed)),
                    propagation: Mutex::new(*m.propagation.lock().unwrap()),
                })
            })
            .collect();
        let ns = self.ns_ids.fetch_add(1, Ordering::Relaxed) + 1;
        self.spaces.write().unwrap().insert(ns, Arc::new(RwLock::new(Arc::new(Table::new(copies)))));
        if !lasting {
            self.ns_users.lock().unwrap().insert(ns, 0);
        }
        ns
    }

    pub fn has_ns(&self, ns: u32) -> bool {
        ns == INIT_NS || self.spaces.read().unwrap().contains_key(&ns)
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
        self.new_super_as(fs, None, None, source, dev, flags, options)
    }

    /// A superblock that shows `fs` as type `ty`, with what the kernel keeps for it.
    #[allow(clippy::too_many_arguments)]
    pub fn new_super_as(&self, fs: Arc<dyn FileSystem>, ty: Option<&'static str>, private: Option<Arc<dyn std::any::Any + Send + Sync>>, source: &str, dev: Option<u64>, flags: u64, options: &str) -> Arc<Super> {
        let dev = dev.unwrap_or_else(|| self.anon_dev());
        Arc::new(Super { fs, ty, private, dev, source: source.to_string(), flags: AtomicU64::new(flags), options: Mutex::new(options.to_string()) })
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
        self.mount_at_root(target, sb, root, flags)
    }

    /// Mounts a new instance whose root is the directory `root` of its filesystem
    /// rather than the filesystem's own root (the fuse stand-in's /data/media).
    pub fn mount_at_root(&self, target: &Node, sb: Arc<Super>, root: u64, flags: u64) -> Result<(), i64> {
        if sb.fs.stat(root).map_err(io_errno)?.mode & S_IFMT == S_IFDIR && self.stat(target)?.mode & S_IFMT != S_IFDIR {
            return Err(ENOTDIR);
        }
        self.edit(|tab, mounts| {
            let dest = tab.mounts.iter().find(|m| m.id == target.mnt.id).cloned().ok_or(ENOENT)?; // ENOENT: its mount went away meanwhile
            let m = self.new_mount(&dest, target.path.clone(), sb, Some(root), "/".into(), flags, 0);
            mounts.push(m.clone());
            self.propagate(mounts, &dest, std::slice::from_ref(&m));
            self.elsewhere(|_, ms| self.propagate(ms, &dest, std::slice::from_ref(&m)));
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
            // A copy of a slave is a slave of the same master (clone_mnt), so mounts made
            // later where it was bound from still show (vold's volume in the /storage
            // zygote bound from /mnt/user/0 before it was mounted).
            top.propagation.lock().unwrap().master = sp.master;
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
                    let p = *m.propagation.lock().unwrap();
                    let c = self.new_mount(&parent, rebase(&m.path, &src.path, &target.path), m.sb.clone(), m.root, m.root_path.clone(), m.flags.load(Ordering::Relaxed), p.shared);
                    c.propagation.lock().unwrap().master = p.master;
                    mounts.push(c.clone());
                    copies.insert(m.id, c);
                }
            }
            let tree = mounts[first..].to_vec();
            self.propagate(mounts, &dest, &tree);
            self.elsewhere(|_, ms| self.propagate(ms, &dest, &tree));
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
            if let Some(dest) = tab.mounts.iter().find(|x| x.id == m.parent).cloned() {
                gone.extend(propagated_copies(tab, &dest, &m, detach));
                self.elsewhere(|t, ms| {
                    let ids = propagated_copies(t, &dest, &m, detach);
                    ms.retain(|x| !ids.contains(&x.id));
                });
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

    /// The MS_* flags of the mount `node` is on, its filesystem's included.
    pub fn mount_flags(&self, node: &Node) -> u64 {
        let m = self.live(node);
        m.flags.load(Ordering::Relaxed) | m.sb.flags.load(Ordering::Relaxed)
    }

    pub fn fs_arc(&self, node: &Node) -> Arc<dyn FileSystem> {
        node.mnt.sb.fs.clone()
    }

    /// Path resolution for droidrt's own use, which no permission applies to.
    pub fn resolve(&self, cwd: &str, path: &str, follow_last: bool) -> Result<Node, i64> {
        self.resolve_as(cwd, path, follow_last, None)
    }

    /// Path resolution for a caller: `search`, if given, is asked about each directory
    /// a component is looked up in (Linux's may_lookup), and its error ends the walk.
    /// Relative paths start at `cwd` as Linux starts at the working directory: the
    /// directories above it aren't asked about, only `cwd` itself and what follows.
    pub fn resolve_as(&self, cwd: &str, path: &str, follow_last: bool, search: Option<Search>) -> Result<Node, i64> {
        if path.is_empty() {
            return Err(ENOENT);
        }
        // A trailing slash names a directory: a link there is followed, whatever
        // the caller asked (Linux's LOOKUP_FOLLOW | LOOKUP_DIRECTORY), so
        // `ls -l /sdcard/` lists what the link leads to.
        let trailing = path.ends_with('/');
        let follow_last = follow_last || trailing;
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
        // The working directory's own components: canonical, so the first ones popped.
        let mut base = if path.starts_with('/') { 0 } else { cwd.split('/').filter(|c| !c.is_empty()).count() };
        let tab = self.table();
        let mut stack = vec![tab.root()?];
        let mut links = 0;

        while let Some(c) = todo.pop() {
            let in_base = base > 0;
            base = base.saturating_sub(1);
            if let Some(check) = search.filter(|_| !in_base) {
                let cur = stack.last().unwrap();
                let st = self.stat(cur)?;
                if st.mode & S_IFMT != S_IFDIR {
                    return Err(ENOTDIR);
                }
                check(cur, &st)?;
            }
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
        let node = stack.pop().unwrap();
        if trailing && self.stat(&node)?.mode & S_IFMT != S_IFDIR {
            return Err(ENOTDIR);
        }
        Ok(node)
    }

    pub fn stat(&self, node: &Node) -> Result<Stat, i64> {
        let mut st = self.fs(node).stat(node.ino).map_err(io_errno)?;
        st.dev = node.mnt.sb.dev;
        Ok(st)
    }

    pub fn read_all(&self, node: &Node) -> Result<Arc<[u8]>, i64> {
        self.fs(node).read_all(node.ino).map_err(io_errno)
    }

    pub fn set_page_cache(&self, cache: Arc<crate::pagecache::PageCache>) {
        let _ = self.cache.set(cache);
    }

    pub fn page_cache(&self) -> Option<&Arc<crate::pagecache::PageCache>> {
        self.cache.get()
    }

    /// A file's pages in the page cache, if it is a file the cache holds.
    pub fn cached(&self, node: &Node) -> Result<Option<Arc<crate::pagecache::CachedFile>>, i64> {
        let Some(cache) = self.cache.get().filter(|_| self.fs(node).paged()) else { return Ok(None) };
        let st = self.stat(node)?;
        if st.mode & S_IFMT != S_IFREG {
            return Ok(None);
        }
        Ok(Some(cache.file(&node.mnt.sb.fs, node.ino, st.size, &node.path)))
    }

    /// Where a private mapping of a file gets its pages.
    pub fn page_source(&self, node: &Node) -> Result<Arc<dyn crate::pagecache::PageSource>, i64> {
        if let Some(f) = self.mem_file(node) {
            return Ok(f.obj.clone());
        }
        if let Some(f) = self.cached(node)? {
            return Ok(f);
        }
        let cache = self.cache.get().ok_or(ENOMEM)?;
        Ok(Arc::new(crate::pagecache::Bytes::new(cache.phys.clone(), self.read_all(node)?)))
    }

    pub fn fs_type(&self, node: &Node) -> &'static str {
        node.mnt.sb.fs_type()
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

    pub fn trigger(&self, node: &Node, data: &[u8]) -> Option<Arc<AtomicU64>> {
        self.fs(node).trigger(node.ino, data)
    }

    /// Resolves everything but the last component: (directory, name).
    pub fn resolve_parent(&self, cwd: &str, path: &str) -> Result<(Node, String), i64> {
        self.resolve_parent_as(cwd, path, None)
    }

    /// resolve_parent for a caller (see resolve_as). The directory is searched too:
    /// Linux looks the last name up in it, whatever is then done with it.
    pub fn resolve_parent_as(&self, cwd: &str, path: &str, search: Option<Search>) -> Result<(Node, String), i64> {
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
        let dir_node = self.resolve_as(cwd, dir, true, search)?;
        let st = self.stat(&dir_node)?;
        if st.mode & S_IFMT != S_IFDIR {
            return Err(ENOTDIR);
        }
        if let Some(check) = search {
            check(&dir_node, &st)?;
        }
        Ok((dir_node, name.to_string()))
    }

    pub fn is_mount_point(&self, dir: &Node, name: &str) -> bool {
        self.table().covering(&dir.mnt, &join(&dir.path, name)).is_some()
    }

    /// Linux's order for creating `name`: EEXIST if it is taken (a mount
    /// point counts), then EROFS.
    pub fn creatable(&self, dir: &Node, name: &str) -> Result<(), i64> {
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

/// DROIDRT_MEMSTAT=1: thread dumps also say where memory has gone.
pub fn memstat_on() -> bool {
    static ON: std::sync::LazyLock<bool> = std::sync::LazyLock::new(|| std::env::var("DROIDRT_MEMSTAT").as_deref() == Ok("1"));
    *ON
}

#[cfg(test)]
mod ns_tests {
    use super::*;

    #[test]
    fn a_namespace_goes_with_its_last_process_unless_it_lasts() {
        let vfs = Vfs::default();
        vfs.mount("/", crate::tmpfs::Tmpfs::new(crate::phys::PhysMem::new(Arc::new(crate::hv::NoHv)), 0o755));
        let ns = vfs.clone_ns(false);
        vfs.ns_enter(ns);
        vfs.ns_enter(ns);
        vfs.ns_leave(ns);
        assert!(vfs.has_ns(ns));
        vfs.ns_leave(ns);
        assert!(!vfs.has_ns(ns));
        // Leaving again does nothing, and neither does anything to the first namespace.
        vfs.ns_leave(ns);
        vfs.ns_leave(INIT_NS);
        assert!(vfs.has_ns(INIT_NS));
        let kept = vfs.clone_ns(true);
        vfs.ns_enter(kept);
        vfs.ns_leave(kept);
        assert!(vfs.has_ns(kept));
    }
}

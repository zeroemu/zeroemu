//! tmpfs: a writable in-memory filesystem (for /dev, /data, /tmp, …). Regular
//! file contents live in guest RAM as `SharedObject`s, so read/write and
//! MAP_SHARED mappings see the same bytes — as with Linux's tmpfs.

use crate::errno::*;
use crate::mm::SharedObject;
use crate::phys::PhysMem;
use crate::vfs::{Dirent, FileSystem, S_IFDIR, S_IFLNK, S_IFMT, S_IFREG, Stat, XATTR_CREATE, XATTR_REPLACE, XATTR_SELINUX};
use std::collections::{BTreeMap, HashMap};
use std::io;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

const ROOT: u64 = 1;

/// A tmpfs's size= limit: pages its files' contents may use.
#[derive(Default)]
pub struct Quota {
    /// In pages; 0 is unlimited.
    limit: AtomicU64,
    used: AtomicU64,
}

impl Quota {
    fn charge(&self, pages: u64) -> Result<(), i64> {
        let limit = self.limit.load(Ordering::Relaxed);
        self.used.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |u| (limit == 0 || u + pages <= limit).then_some(u + pages)).map(|_| ()).map_err(|_| ENOSPC)
    }
    /// Pages still free.
    fn room(&self) -> u64 {
        match self.limit.load(Ordering::Relaxed) {
            0 => u64::MAX,
            l => l.saturating_sub(self.used.load(Ordering::Relaxed)),
        }
    }
    fn release(&self, pages: u64) {
        self.used.fetch_sub(pages, Ordering::Relaxed);
    }
}

fn pages(bytes: u64) -> u64 {
    bytes.div_ceil(4096)
}

/// A regular file's contents: shared pages plus a length.
pub struct MemFile {
    pub obj: Arc<SharedObject>,
    size: Mutex<u64>,
    /// The filesystem's limit, and the pages charged to it (up to the furthest write).
    quota: Option<(Arc<Quota>, AtomicU64)>,
    /// A memfd's extended attributes (it has no tmpfs node to hold them).
    pub xattrs: Mutex<Xattrs>,
}

impl Drop for MemFile {
    fn drop(&mut self) {
        if let Some((q, charged)) = &self.quota {
            q.release(charged.load(Ordering::Relaxed));
        }
    }
}

impl MemFile {
    pub fn new(phys: Arc<PhysMem>) -> Arc<MemFile> {
        Arc::new(MemFile { obj: SharedObject::new(phys), size: Mutex::new(0), quota: None, xattrs: Mutex::default() })
    }

    fn with_quota(phys: Arc<PhysMem>, quota: Arc<Quota>) -> Arc<MemFile> {
        Arc::new(MemFile { obj: SharedObject::new(phys), size: Mutex::new(0), quota: Some((quota, AtomicU64::new(0))), xattrs: Mutex::default() })
    }

    pub fn size(&self) -> u64 {
        *self.size.lock().unwrap()
    }

    pub fn read_at(&self, off: u64, max: usize) -> Vec<u8> {
        let size = self.size();
        let n = size.saturating_sub(off).min(max as u64) as usize;
        let mut buf = vec![0; n];
        self.obj.read(off, &mut buf);
        buf
    }

    /// Writes `data` at `off`. Under a size= limit only the pages that fit
    /// are written, as Linux's tmpfs does: a short count, or ENOSPC for none.
    pub fn write_at(&self, off: u64, data: &[u8]) -> Result<usize, i64> {
        let end = off.checked_add(data.len() as u64).ok_or(EFBIG)?;
        if end > 1 << 40 {
            return Err(EFBIG);
        }
        let mut size = self.size.lock().unwrap();
        let mut data = data;
        if let Some((q, charged)) = &self.quota {
            let had = charged.load(Ordering::Relaxed);
            if pages(end) > had {
                let grant = (pages(end) - had).min(q.room());
                let fit = ((had + grant) * 4096).min(end);
                if fit <= off {
                    return Err(ENOSPC);
                }
                q.charge(grant)?;
                charged.store(had + grant, Ordering::Relaxed);
                data = &data[..(fit - off) as usize];
            }
        }
        self.obj.write(off, data)?;
        *size = (*size).max(off + data.len() as u64);
        Ok(data.len())
    }

    pub fn truncate(&self, len: u64) {
        let mut size = self.size.lock().unwrap();
        if len < *size {
            self.obj.zero_from(len);
        }
        if let Some((q, charged)) = &self.quota {
            let had = charged.load(Ordering::Relaxed);
            if pages(len) < had {
                q.release(had - pages(len));
                charged.store(pages(len), Ordering::Relaxed);
            }
        }
        *size = len;
    }
}

enum Kind {
    Dir { entries: BTreeMap<String, u64>, parent: u64 },
    File(Arc<MemFile>),
    Symlink(String),
    /// Device, FIFO, or socket node (identified by mode and rdev).
    Special { rdev: u64 },
}

struct Node {
    mode: u32,
    uid: u32,
    gid: u32,
    nlink: u32,
    mtime: u64,
    kind: Kind,
    xattrs: Xattrs,
}

/// An inode's extended attributes, by full name. Like Linux's tmpfs, only
/// the security.*, trusted.* and user.* namespaces are stored.
#[derive(Clone, Default)]
pub struct Xattrs(BTreeMap<String, Vec<u8>>);

const ACL_NAMES: [&str; 2] = ["system.posix_acl_access", "system.posix_acl_default"];

/// tmpfs stores security.*, trusted.*, user.* and POSIX ACLs, as with
/// CONFIG_TMPFS_POSIX_ACL: /data lives here and Android expects ext4's ACLs.
/// Anything else is EOPNOTSUPP on get, set and remove. ACLs are stored, not
/// enforced, and new files do not inherit a default ACL.
fn tmpfs_xattr(name: &str) -> bool {
    ACL_NAMES.contains(&name) || ["security.", "trusted.", "user."].iter().any(|p| name.starts_with(p))
}

/// posix_acl_from_xattr: a little-endian version 2 header and 8-byte entries.
fn valid_acl(value: &[u8]) -> bool {
    value.len() >= 4 && value[0..4] == 2u32.to_le_bytes() && (value.len() - 4).is_multiple_of(8)
}

impl Xattrs {
    pub fn get(&self, name: &str) -> Result<Vec<u8>, i64> {
        if !tmpfs_xattr(name) {
            return Err(EOPNOTSUPP);
        }
        self.0.get(name).cloned().ok_or(ENODATA)
    }

    pub fn set(&mut self, name: &str, value: &[u8], flags: u32) -> Result<(), i64> {
        if !tmpfs_xattr(name) {
            return Err(EOPNOTSUPP);
        }
        if ACL_NAMES.contains(&name) && !valid_acl(value) {
            return Err(EINVAL);
        }
        match self.0.contains_key(name) {
            true if flags & XATTR_CREATE != 0 => return Err(EEXIST),
            false if flags & XATTR_REPLACE != 0 => return Err(ENODATA),
            _ => {}
        }
        self.0.insert(name.to_string(), value.to_vec());
        Ok(())
    }

    pub fn list(&self) -> Vec<String> {
        self.0.keys().cloned().collect()
    }

    pub fn remove(&mut self, name: &str) -> Result<(), i64> {
        if !tmpfs_xattr(name) {
            return Err(EOPNOTSUPP);
        }
        self.0.remove(name).map(|_| ()).ok_or(ENODATA)
    }

    /// What a new child of a directory with these attributes starts with.
    fn inherited(&self) -> Xattrs {
        Xattrs(self.0.get_key_value(XATTR_SELINUX).map(|(k, v)| (k.clone(), v.clone())).into_iter().collect())
    }
}

pub struct Tmpfs {
    phys: Arc<PhysMem>,
    /// What statfs and /proc/mounts call it ("tmpfs", "sysfs", "selinuxfs").
    type_name: &'static str,
    nodes: Mutex<HashMap<u64, Node>>,
    next: AtomicU64,
    quota: Arc<Quota>,
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

fn errno(e: i64) -> io::Error {
    io_err(e)
}

fn valid_name(name: &str) -> Result<(), i64> {
    if name.is_empty() || name == "." || name == ".." || name.contains('/') {
        return Err(EINVAL);
    }
    if name.len() > 255 {
        return Err(ENAMETOOLONG);
    }
    Ok(())
}

impl Tmpfs {
    pub fn new(phys: Arc<PhysMem>, mode: u32) -> Arc<Tmpfs> {
        Tmpfs::with_type(phys, mode, "tmpfs")
    }

    /// An in-memory filesystem presenting itself as another type.
    pub fn with_type(phys: Arc<PhysMem>, mode: u32, type_name: &'static str) -> Arc<Tmpfs> {
        let mut nodes = HashMap::new();
        nodes.insert(ROOT, Node { mode: S_IFDIR | mode, uid: 0, gid: 0, nlink: 2, mtime: now(), kind: Kind::Dir { entries: BTreeMap::new(), parent: ROOT }, xattrs: Xattrs::default() });
        Arc::new(Tmpfs { phys, type_name, nodes: Mutex::new(nodes), next: AtomicU64::new(ROOT + 1), quota: Arc::default() })
    }

    fn add(&self, dir: u64, name: &str, mode: u32, kind: Kind) -> Result<u64, i64> {
        valid_name(name)?;
        let mut nodes = self.nodes.lock().unwrap();
        let ino = self.next.fetch_add(1, Ordering::Relaxed);
        let is_dir = matches!(kind, Kind::Dir { .. });
        match nodes.get_mut(&dir).map(|n| &mut n.kind) {
            Some(Kind::Dir { entries, .. }) => {
                if entries.contains_key(name) {
                    return Err(EEXIST);
                }
                entries.insert(name.to_string(), ino);
            }
            Some(_) => return Err(ENOTDIR),
            None => return Err(ENOENT),
        }
        let parent = nodes.get_mut(&dir).unwrap();
        if is_dir {
            parent.nlink += 1;
        }
        // New nodes take their directory's label, until policy-driven labeling exists.
        let xattrs = parent.xattrs.inherited();
        nodes.insert(ino, Node { mode, uid: 0, gid: 0, nlink: if is_dir { 2 } else { 1 }, mtime: now(), kind, xattrs });
        Ok(ino)
    }

    /// Convenience for populating a fresh tree: mkdir -p.
    pub fn mkdir_p(&self, path: &str, mode: u32) -> u64 {
        let mut dir = ROOT;
        for part in path.split('/').filter(|p| !p.is_empty()) {
            dir = match self.lookup_ino(dir, part) {
                Some(i) => i,
                None => self.add(dir, part, S_IFDIR | mode, Kind::Dir { entries: BTreeMap::new(), parent: dir }).expect("tmpfs mkdir_p"),
            };
        }
        dir
    }

    /// Places an existing file's contents at `path` (e.g. the property area).
    pub fn add_file(&self, path: &str, mode: u32, file: Arc<MemFile>) {
        let (dir, name) = path.rsplit_once('/').unwrap_or(("", path));
        let d = self.mkdir_p(dir, 0o755);
        self.add(d, name, S_IFREG | mode, Kind::File(file)).expect("tmpfs add_file");
    }

    /// Convenience for populating a fresh tree: a file with `content`.
    pub fn write_file(&self, path: &str, mode: u32, content: &str) {
        let (dir, name) = path.rsplit_once('/').unwrap_or(("", path));
        let d = self.mkdir_p(dir, 0o755);
        let ino = self.add(d, name, S_IFREG | mode, Kind::File(MemFile::with_quota(self.phys.clone(), self.quota.clone()))).expect("tmpfs write_file");
        if let Some(Kind::File(f)) = self.nodes.lock().unwrap().get(&ino).map(|n| &n.kind) {
            f.write_at(0, content.as_bytes()).expect("tmpfs write_file");
        }
    }

    fn lookup_ino(&self, dir: u64, name: &str) -> Option<u64> {
        let nodes = self.nodes.lock().unwrap();
        match &nodes.get(&dir)?.kind {
            Kind::Dir { entries, parent } => match name {
                "." => Some(dir),
                ".." => Some(*parent),
                _ => entries.get(name).copied(),
            },
            _ => None,
        }
    }
}

impl FileSystem for Tmpfs {
    fn fs_type(&self) -> &'static str {
        self.type_name
    }
    fn root(&self) -> io::Result<u64> {
        Ok(ROOT)
    }

    fn stat(&self, ino: u64) -> io::Result<Stat> {
        let nodes = self.nodes.lock().unwrap();
        let n = nodes.get(&ino).ok_or_else(|| errno(ENOENT))?;
        let (size, rdev) = match &n.kind {
            Kind::File(f) => (f.size(), 0),
            Kind::Symlink(t) => (t.len() as u64, 0),
            Kind::Dir { entries, .. } => (entries.len() as u64 * 32, 0),
            Kind::Special { rdev } => (0, *rdev),
        };
        Ok(Stat { dev: 0, ino, mode: n.mode, nlink: n.nlink, uid: n.uid, gid: n.gid, rdev, size, mtime: n.mtime })
    }

    fn lookup(&self, dir: u64, name: &str) -> io::Result<Option<u64>> {
        Ok(self.lookup_ino(dir, name))
    }

    fn readdir(&self, dir: u64) -> io::Result<Vec<Dirent>> {
        let nodes = self.nodes.lock().unwrap();
        let Some(Kind::Dir { entries, parent }) = nodes.get(&dir).map(|n| &n.kind) else { return Err(errno(ENOTDIR)) };
        let mut out = vec![Dirent { name: ".".into(), ino: dir, dtype: 4 }, Dirent { name: "..".into(), ino: *parent, dtype: 4 }];
        for (name, &ino) in entries {
            let dtype = nodes.get(&ino).map_or(0, |n| match n.mode & S_IFMT {
                0o040000 => 4,
                0o100000 => 8,
                0o120000 => 10,
                0o020000 => 2,
                0o060000 => 6,
                0o010000 => 1,
                0o140000 => 12,
                _ => 0,
            });
            out.push(Dirent { name: name.clone(), ino, dtype });
        }
        Ok(out)
    }

    fn read_all(&self, ino: u64) -> io::Result<Arc<[u8]>> {
        let nodes = self.nodes.lock().unwrap();
        match &nodes.get(&ino).ok_or_else(|| errno(ENOENT))?.kind {
            Kind::File(f) => Ok(f.read_at(0, usize::MAX).into()),
            Kind::Symlink(t) => Ok(t.as_bytes().into()),
            Kind::Dir { .. } => Err(errno(EISDIR)),
            Kind::Special { .. } => Ok(Arc::from(&[][..])),
        }
    }

    fn writable(&self) -> bool {
        true
    }

    fn set_size_limit(&self, bytes: u64) {
        self.quota.limit.store(pages(bytes), Ordering::Relaxed);
    }

    fn space(&self) -> Option<(u64, u64)> {
        // Unlimited tmpfs reports half of RAM, Linux's default size.
        let total = match self.quota.limit.load(Ordering::Relaxed) {
            0 => crate::phys::PHYS_MAX / 2,
            l => l * 4096,
        };
        Some((total, total.saturating_sub(self.quota.used.load(Ordering::Relaxed) * 4096)))
    }

    fn mem_file(&self, ino: u64) -> Option<Arc<MemFile>> {
        match &self.nodes.lock().unwrap().get(&ino)?.kind {
            Kind::File(f) => Some(f.clone()),
            _ => None,
        }
    }

    fn create(&self, dir: u64, name: &str, mode: u32, rdev: u64) -> Result<u64, i64> {
        let kind = match mode & S_IFMT {
            0 | S_IFREG => Kind::File(MemFile::with_quota(self.phys.clone(), self.quota.clone())),
            S_IFDIR => return Err(EINVAL),
            _ => Kind::Special { rdev },
        };
        let mode = if mode & S_IFMT == 0 { mode | S_IFREG } else { mode };
        self.add(dir, name, mode, kind)
    }

    fn mkdir(&self, dir: u64, name: &str, mode: u32) -> Result<u64, i64> {
        self.add(dir, name, S_IFDIR | (mode & 0o7777), Kind::Dir { entries: BTreeMap::new(), parent: dir })
    }

    fn symlink(&self, dir: u64, name: &str, target: &str) -> Result<u64, i64> {
        self.add(dir, name, S_IFLNK | 0o777, Kind::Symlink(target.to_string()))
    }

    fn link(&self, ino: u64, dir: u64, name: &str) -> Result<(), i64> {
        valid_name(name)?;
        let mut nodes = self.nodes.lock().unwrap();
        if matches!(nodes.get(&ino).map(|n| &n.kind), Some(Kind::Dir { .. }) | None) {
            return Err(EPERM);
        }
        match nodes.get_mut(&dir).map(|n| &mut n.kind) {
            Some(Kind::Dir { entries, .. }) => {
                if entries.contains_key(name) {
                    return Err(EEXIST);
                }
                entries.insert(name.to_string(), ino);
            }
            _ => return Err(ENOTDIR),
        }
        nodes.get_mut(&ino).unwrap().nlink += 1;
        Ok(())
    }

    fn unlink(&self, dir: u64, name: &str, rmdir: bool) -> Result<(), i64> {
        let mut nodes = self.nodes.lock().unwrap();
        let ino = match nodes.get(&dir).map(|n| &n.kind) {
            Some(Kind::Dir { entries, .. }) => *entries.get(name).ok_or(ENOENT)?,
            _ => return Err(ENOTDIR),
        };
        match (&nodes[&ino].kind, rmdir) {
            (Kind::Dir { entries, .. }, true) if !entries.is_empty() => return Err(ENOTEMPTY),
            (Kind::Dir { .. }, false) => return Err(EISDIR),
            (Kind::Dir { .. }, true) => {}
            (_, true) => return Err(ENOTDIR),
            (_, false) => {}
        }
        if let Some(Kind::Dir { entries, .. }) = nodes.get_mut(&dir).map(|n| &mut n.kind) {
            entries.remove(name);
        }
        if rmdir {
            nodes.get_mut(&dir).unwrap().nlink -= 1;
            nodes.remove(&ino);
        } else {
            let n = nodes.get_mut(&ino).unwrap();
            n.nlink -= 1;
            if n.nlink == 0 {
                nodes.remove(&ino); // open descriptors keep the contents alive
            }
        }
        Ok(())
    }

    fn rename(&self, odir: u64, oname: &str, ndir: u64, nname: &str, noreplace: bool) -> Result<(), i64> {
        valid_name(nname)?;
        let mut nodes = self.nodes.lock().unwrap();
        let ino = match nodes.get(&odir).map(|n| &n.kind) {
            Some(Kind::Dir { entries, .. }) => *entries.get(oname).ok_or(ENOENT)?,
            _ => return Err(ENOTDIR),
        };
        // Refuse to move a directory into itself.
        let mut d = ndir;
        while d != ROOT {
            if d == ino {
                return Err(EINVAL);
            }
            d = match &nodes[&d].kind {
                Kind::Dir { parent, .. } => *parent,
                _ => ROOT,
            };
        }
        let existing = match nodes.get(&ndir).map(|n| &n.kind) {
            Some(Kind::Dir { entries, .. }) => entries.get(nname).copied(),
            _ => return Err(ENOTDIR),
        };
        if let Some(old) = existing {
            if old == ino {
                return Ok(());
            }
            if noreplace {
                return Err(EEXIST);
            }
            if let Kind::Dir { entries, .. } = &nodes[&old].kind
                && !entries.is_empty()
            {
                return Err(ENOTEMPTY);
            }
            // The replaced name is one link. A socket (or any other inode)
            // with another name must stay reachable; only the last link goes.
            if matches!(&nodes[&old].kind, Kind::Dir { .. }) {
                nodes.remove(&old);
            } else {
                let n = nodes.get_mut(&old).unwrap();
                n.nlink -= 1;
                if n.nlink == 0 {
                    nodes.remove(&old);
                }
            }
        }
        if let Some(Kind::Dir { entries, .. }) = nodes.get_mut(&odir).map(|n| &mut n.kind) {
            entries.remove(oname);
        }
        if let Some(Kind::Dir { entries, .. }) = nodes.get_mut(&ndir).map(|n| &mut n.kind) {
            entries.insert(nname.to_string(), ino);
        }
        if let Some(Kind::Dir { parent, .. }) = nodes.get_mut(&ino).map(|n| &mut n.kind) {
            *parent = ndir;
        }
        Ok(())
    }

    fn set_attr(&self, ino: u64, mode: Option<u32>, owner: Option<(u32, u32)>, mtime: Option<u64>) -> Result<(), i64> {
        let mut nodes = self.nodes.lock().unwrap();
        let n = nodes.get_mut(&ino).ok_or(ENOENT)?;
        if let Some(m) = mode {
            n.mode = (n.mode & S_IFMT) | (m & 0o7777);
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

    fn getxattr(&self, ino: u64, name: &str) -> Result<Vec<u8>, i64> {
        self.nodes.lock().unwrap().get(&ino).ok_or(ENOENT)?.xattrs.get(name)
    }

    fn setxattr(&self, ino: u64, name: &str, value: &[u8], flags: u32) -> Result<(), i64> {
        self.nodes.lock().unwrap().get_mut(&ino).ok_or(ENOENT)?.xattrs.set(name, value, flags)
    }

    fn listxattr(&self, ino: u64) -> Result<Vec<String>, i64> {
        Ok(self.nodes.lock().unwrap().get(&ino).ok_or(ENOENT)?.xattrs.list())
    }

    fn removexattr(&self, ino: u64, name: &str) -> Result<(), i64> {
        self.nodes.lock().unwrap().get_mut(&ino).ok_or(ENOENT)?.xattrs.remove(name)
    }
}

// ---- a whole tree to and from a host file (persistent /data) ----

/// Longest name, link target or attribute a saved tree can hold: more is a bad file.
const SAVED_MAX: u64 = 1 << 24;

fn put_u64(w: &mut impl io::Write, v: u64) -> io::Result<()> {
    w.write_all(&v.to_le_bytes())
}

fn put_bytes(w: &mut impl io::Write, b: &[u8]) -> io::Result<()> {
    put_u64(w, b.len() as u64)?;
    w.write_all(b)
}

fn get_u64(r: &mut impl io::Read) -> io::Result<u64> {
    let mut b = [0; 8];
    r.read_exact(&mut b)?;
    Ok(u64::from_le_bytes(b))
}

fn get_bytes(r: &mut impl io::Read) -> io::Result<Vec<u8>> {
    let n = get_u64(r)?;
    if n > SAVED_MAX {
        return Err(io::Error::other("a saved name is too long"));
    }
    let mut b = vec![0; n as usize];
    r.read_exact(&mut b)?;
    Ok(b)
}

fn get_string(r: &mut impl io::Read) -> io::Result<String> {
    String::from_utf8(get_bytes(r)?).map_err(|_| io::Error::other("a saved name isn't text"))
}

/// A tree read from a file, ready to go in.
pub struct SavedTree {
    nodes: HashMap<u64, Node>,
    next: u64,
}

impl Tmpfs {
    /// Writes the tree; returns the bytes of file contents. Sockets stay behind: what
    /// was listening on them is gone. Files keep their holes.
    pub fn save(&self, w: &mut impl io::Write) -> io::Result<u64> {
        const NO_MORE_PAGES: u64 = u64::MAX;
        enum Saved {
            Dir(u64, Vec<(String, u64)>),
            File(Arc<MemFile>),
            Symlink(String),
            Special(u64),
        }
        // The structure at one moment, and then the contents with the lock free.
        let (saved, next) = {
            let nodes = self.nodes.lock().unwrap();
            let socket = |ino: &u64| nodes.get(ino).is_some_and(|n| n.mode & S_IFMT == crate::vfs::S_IFSOCK);
            let mut saved = Vec::with_capacity(nodes.len());
            for (&ino, n) in nodes.iter().filter(|(ino, _)| !socket(ino)) {
                let kind = match &n.kind {
                    Kind::Dir { entries, parent } => Saved::Dir(*parent, entries.iter().filter(|(_, c)| !socket(c)).map(|(k, &c)| (k.clone(), c)).collect()),
                    Kind::File(f) => Saved::File(f.clone()),
                    Kind::Symlink(t) => Saved::Symlink(t.clone()),
                    Kind::Special { rdev } => Saved::Special(*rdev),
                };
                saved.push((ino, n.mode, n.uid, n.gid, n.nlink, n.mtime, n.xattrs.clone(), kind));
            }
            (saved, self.next.load(Ordering::Relaxed))
        };
        put_u64(w, next)?;
        put_u64(w, saved.len() as u64)?;
        let mut contents = 0;
        let mut page = [0u8; 4096];
        for (ino, mode, uid, gid, nlink, mtime, xattrs, kind) in saved {
            for v in [ino, mode as u64, uid as u64, gid as u64, nlink as u64, mtime, xattrs.0.len() as u64] {
                put_u64(w, v)?;
            }
            for (name, value) in &xattrs.0 {
                put_bytes(w, name.as_bytes())?;
                put_bytes(w, value)?;
            }
            match kind {
                Saved::Dir(parent, entries) => {
                    put_u64(w, 0)?;
                    put_u64(w, parent)?;
                    put_u64(w, entries.len() as u64)?;
                    for (name, child) in entries {
                        put_bytes(w, name.as_bytes())?;
                        put_u64(w, child)?;
                    }
                }
                Saved::File(f) => {
                    put_u64(w, 1)?;
                    let size = f.size();
                    put_u64(w, size)?;
                    for off in (0..size).step_by(page.len()) {
                        if f.obj.has_frame(off) {
                            f.obj.read(off, &mut page);
                            put_u64(w, off)?;
                            w.write_all(&page)?;
                            contents += page.len() as u64;
                        }
                    }
                    put_u64(w, NO_MORE_PAGES)?;
                }
                Saved::Symlink(t) => {
                    put_u64(w, 2)?;
                    put_bytes(w, t.as_bytes())?;
                }
                Saved::Special(rdev) => {
                    put_u64(w, 3)?;
                    put_u64(w, rdev)?;
                }
            }
        }
        Ok(contents)
    }

    /// Reads a tree written by `save`. Nothing changes until `install`.
    pub fn read_saved(&self, r: &mut impl io::Read) -> io::Result<SavedTree> {
        const NO_MORE_PAGES: u64 = u64::MAX;
        let bad = |what: &str| io::Error::other(format!("a saved tree has {what}"));
        let next = get_u64(r)?;
        let count = get_u64(r)?;
        let mut nodes = HashMap::new();
        let mut page = [0u8; 4096];
        for _ in 0..count {
            let (ino, mode, uid, gid, nlink, mtime, attrs) = (get_u64(r)?, get_u64(r)?, get_u64(r)?, get_u64(r)?, get_u64(r)?, get_u64(r)?, get_u64(r)?);
            let mut xattrs = BTreeMap::new();
            for _ in 0..attrs {
                let name = get_string(r)?;
                xattrs.insert(name, get_bytes(r)?);
            }
            let kind = match get_u64(r)? {
                0 => {
                    let parent = get_u64(r)?;
                    let mut entries = BTreeMap::new();
                    for _ in 0..get_u64(r)? {
                        let name = get_string(r)?;
                        entries.insert(name, get_u64(r)?);
                    }
                    Kind::Dir { entries, parent }
                }
                1 => {
                    let f = MemFile::with_quota(self.phys.clone(), self.quota.clone());
                    let size = get_u64(r)?;
                    loop {
                        let off = get_u64(r)?;
                        if off == NO_MORE_PAGES {
                            break;
                        }
                        r.read_exact(&mut page)?;
                        if off >= size || !off.is_multiple_of(page.len() as u64) {
                            return Err(bad("a page outside its file"));
                        }
                        let n = (size - off).min(page.len() as u64) as usize;
                        f.write_at(off, &page[..n]).map_err(|e| io::Error::other(format!("restoring a file: errno {e}")))?;
                    }
                    // Holes at the end have no pages to say how far the file goes.
                    if f.size() < size {
                        f.write_at(size - 1, &[0]).map_err(|e| io::Error::other(format!("restoring a file: errno {e}")))?;
                    }
                    Kind::File(f)
                }
                2 => Kind::Symlink(get_string(r)?),
                3 => Kind::Special { rdev: get_u64(r)? },
                _ => return Err(bad("an unknown kind of node")),
            };
            nodes.insert(ino, Node { mode: mode as u32, uid: uid as u32, gid: gid as u32, nlink: nlink as u32, mtime, kind, xattrs: Xattrs(xattrs) });
        }
        if !matches!(nodes.get(&ROOT).map(|n| &n.kind), Some(Kind::Dir { .. })) {
            return Err(bad("no root"));
        }
        Ok(SavedTree { nodes, next })
    }

    /// Replaces the tree. Only before anything has it open.
    pub fn install(&self, tree: SavedTree) {
        *self.nodes.lock().unwrap() = tree.nodes;
        self.next.store(tree.next, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod saved_tests {
    use super::*;
    use crate::vfs::S_IFSOCK;

    fn phys() -> Arc<PhysMem> {
        PhysMem::new(Arc::new(crate::hv::NoHv))
    }

    #[test]
    fn a_saved_tree_comes_back_the_same() {
        let phys = phys();
        let a = Tmpfs::new(phys.clone(), 0o771);
        a.write_file("system/packages.xml", 0o640, "hello");
        let dir = a.mkdir_p("user/0", 0o700);
        let link = a.symlink(dir, "here", "/data/user/0").unwrap();
        a.set_attr(link, None, Some((1000, 1000)), Some(1234)).unwrap();
        a.setxattr(dir, "security.selinux", b"u:object_r:x:s0", 0).unwrap();
        let hole = a.create(dir, "hole", S_IFREG | 0o600, 0).unwrap();
        let f = a.mem_file(hole).unwrap();
        f.write_at(3 * 4096 + 10, b"end").unwrap();
        let tail = a.create(dir, "tail", S_IFREG | 0o600, 0).unwrap();
        a.mem_file(tail).unwrap().truncate(9000);
        a.link(hole, 1, "again").unwrap();
        a.create(dir, "sock", S_IFSOCK | 0o600, 0).unwrap();

        let mut bytes = Vec::new();
        let contents = a.save(&mut bytes).unwrap();
        assert_eq!(contents, 4096 + 4096, "packages.xml and hole's one page, not its gap");

        let b = Tmpfs::new(phys, 0o755);
        let tree = b.read_saved(&mut &bytes[..]).unwrap();
        b.install(tree);
        let at = |path: &[&str]| path.iter().fold(ROOT, |d, n| b.lookup_ino(d, n).unwrap());
        let xml = at(&["system", "packages.xml"]);
        assert_eq!(&*b.read_all(xml).unwrap(), b"hello");
        assert_eq!(b.stat(xml).unwrap().mode, S_IFREG | 0o640);
        assert_eq!(b.stat(ROOT).unwrap().mode, S_IFDIR | 0o771);
        let dir = at(&["user", "0"]);
        assert_eq!(b.getxattr(dir, "security.selinux").unwrap(), b"u:object_r:x:s0");
        let link = at(&["user", "0", "here"]);
        let st = b.stat(link).unwrap();
        assert_eq!((st.uid, st.gid, st.mtime), (1000, 1000, 1234));
        assert_eq!(&*b.read_all(link).unwrap(), b"/data/user/0");
        let hole = at(&["user", "0", "hole"]);
        let f = b.mem_file(hole).unwrap();
        assert_eq!(f.size(), 3 * 4096 + 13);
        assert_eq!(f.read_at(3 * 4096 + 10, 3), b"end");
        assert!(!f.obj.has_frame(0), "the gap stays a gap");
        assert_eq!(at(&["again"]), hole, "hard links stay one file");
        assert_eq!(b.stat(hole).unwrap().nlink, 2);
        assert_eq!(b.mem_file(at(&["user", "0", "tail"])).unwrap().size(), 9000);
        assert!(b.lookup_ino(dir, "sock").is_none(), "sockets stay behind");
        let fresh = b.create(dir, "new", S_IFREG | 0o600, 0).unwrap();
        assert!(fresh > link && fresh > hole, "new files don't reuse numbers");
    }

    #[test]
    fn a_damaged_file_is_refused_and_changes_nothing() {
        let phys = phys();
        let a = Tmpfs::new(phys.clone(), 0o771);
        a.write_file("x/y", 0o640, "hello");
        let mut bytes = Vec::new();
        a.save(&mut bytes).unwrap();
        let b = Tmpfs::new(phys, 0o755);
        b.write_file("mine", 0o600, "kept");
        for cut in [0, 8, 20, bytes.len() / 2, bytes.len() - 1] {
            assert!(b.read_saved(&mut &bytes[..cut]).is_err(), "cut at {cut}");
        }
        assert!(b.lookup_ino(ROOT, "mine").is_some());
    }
}

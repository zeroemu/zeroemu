//! tmpfs: a writable in-memory filesystem (for /dev, /data, /tmp, …). Regular
//! file contents live in guest RAM as `SharedObject`s, so read/write and
//! MAP_SHARED mappings see the same bytes — as with Linux's tmpfs.

use crate::errno::*;
use crate::mm::SharedObject;
use crate::phys::PhysMem;
use crate::vfs::{Dirent, FileSystem, S_IFDIR, S_IFLNK, S_IFMT, S_IFREG, Stat};
use std::collections::{BTreeMap, HashMap};
use std::io;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

const ROOT: u64 = 1;

/// A regular file's contents: shared pages plus a length.
pub struct MemFile {
    pub obj: Arc<SharedObject>,
    size: Mutex<u64>,
}

impl MemFile {
    pub fn new(phys: Arc<PhysMem>) -> Arc<MemFile> {
        Arc::new(MemFile { obj: SharedObject::new(phys), size: Mutex::new(0) })
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

    pub fn write_at(&self, off: u64, data: &[u8]) -> Result<(), i64> {
        let end = off.checked_add(data.len() as u64).ok_or(EFBIG)?;
        if end > 1 << 40 {
            return Err(EFBIG);
        }
        let mut size = self.size.lock().unwrap();
        self.obj.write(off, data)?;
        *size = (*size).max(end);
        Ok(())
    }

    pub fn truncate(&self, len: u64) {
        let mut size = self.size.lock().unwrap();
        if len < *size {
            self.obj.zero_from(len);
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
}

pub struct Tmpfs {
    phys: Arc<PhysMem>,
    /// What statfs and /proc/mounts call it ("tmpfs", "sysfs", "selinuxfs").
    type_name: &'static str,
    nodes: Mutex<HashMap<u64, Node>>,
    next: AtomicU64,
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
        nodes.insert(ROOT, Node { mode: S_IFDIR | mode, uid: 0, gid: 0, nlink: 2, mtime: now(), kind: Kind::Dir { entries: BTreeMap::new(), parent: ROOT } });
        Arc::new(Tmpfs { phys, type_name, nodes: Mutex::new(nodes), next: AtomicU64::new(ROOT + 1) })
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
        if is_dir {
            nodes.get_mut(&dir).unwrap().nlink += 1;
        }
        nodes.insert(ino, Node { mode, uid: 0, gid: 0, nlink: if is_dir { 2 } else { 1 }, mtime: now(), kind });
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
        let ino = self.add(d, name, S_IFREG | mode, Kind::File(MemFile::new(self.phys.clone()))).expect("tmpfs write_file");
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

    fn mem_file(&self, ino: u64) -> Option<Arc<MemFile>> {
        match &self.nodes.lock().unwrap().get(&ino)?.kind {
            Kind::File(f) => Some(f.clone()),
            _ => None,
        }
    }

    fn create(&self, dir: u64, name: &str, mode: u32, rdev: u64) -> Result<u64, i64> {
        let kind = match mode & S_IFMT {
            0 | S_IFREG => Kind::File(MemFile::new(self.phys.clone())),
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
            nodes.remove(&old);
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
}

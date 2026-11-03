//! The guest's file namespace: a mount table over read-only filesystems, with
//! Linux path resolution (symlinks, "..", mount crossings).

use crate::errno::*;
use crate::image::erofs::Erofs;
use crate::image::ext4::Ext4;
use std::io;
use std::sync::{Arc, Mutex, OnceLock};

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
}

impl FileSystem for Erofs {
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
}

/// EROFS and ext4 share the dirent file-type numbering (1 file … 7 symlink).
const FT_TO_DT: [u8; 8] = [0, 8, 4, 2, 6, 1, 12, 10];

fn ft_to_dt(ft: u8) -> u8 {
    FT_TO_DT.get(ft as usize).copied().unwrap_or(0)
}

impl FileSystem for Ext4 {
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
}

/// Opens whichever read-only filesystem `dev` holds.
pub fn open_fs(dev: crate::image::Dev) -> io::Result<Arc<dyn FileSystem>> {
    match Erofs::open(dev.clone()) {
        Ok(fs) => Ok(fs),
        Err(_) => Ok(Ext4::open(dev)? as Arc<dyn FileSystem>),
    }
}

/// A filesystem that is only opened on first use (APEX payloads are big).
pub struct LazyFs {
    open: Mutex<Option<Box<dyn FnOnce() -> io::Result<Arc<dyn FileSystem>> + Send>>>,
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

impl FileSystem for LazyFs {
    fn root(&self) -> io::Result<u64> {
        self.get()?.root()
    }
    fn stat(&self, ino: u64) -> io::Result<Stat> {
        self.get()?.stat(ino)
    }
    fn lookup(&self, dir: u64, name: &str) -> io::Result<Option<u64>> {
        self.get()?.lookup(dir, name)
    }
    fn readdir(&self, dir: u64) -> io::Result<Vec<Dirent>> {
        self.get()?.readdir(dir)
    }
    fn read_all(&self, ino: u64) -> io::Result<Arc<[u8]>> {
        self.get()?.read_all(ino)
    }
}

struct Mount {
    path: String,
    fs: Arc<dyn FileSystem>,
}

#[derive(Clone, Debug)]
pub struct Node {
    mount: usize,
    pub ino: u64,
    /// Canonical absolute path (no symlinks, "." or "..").
    pub path: String,
}

#[derive(Default)]
pub struct Vfs {
    mounts: Vec<Mount>,
}

fn io_errno(e: io::Error) -> i64 {
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

impl Vfs {
    /// Mounts `fs` at `path`; the first mount must be "/".
    pub fn mount(&mut self, path: &str, fs: Arc<dyn FileSystem>) {
        assert!(!self.mounts.is_empty() || path == "/", "mount / first");
        self.mounts.push(Mount {
            path: path.to_string(),
            fs,
        });
    }

    fn mount_at(&self, path: &str) -> Option<usize> {
        // Later mounts shadow earlier ones, as in Linux.
        self.mounts.iter().rposition(|m| m.path == path)
    }

    fn fs(&self, node: &Node) -> &dyn FileSystem {
        &*self.mounts[node.mount].fs
    }

    pub fn fs_arc(&self, node: &Node) -> Arc<dyn FileSystem> {
        self.mounts[node.mount].fs.clone()
    }

    fn root_node(&self) -> Result<Node, i64> {
        let ino = self.mounts[0].fs.root().map_err(io_errno)?;
        Ok(Node {
            mount: 0,
            ino,
            path: "/".into(),
        })
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
        let mut stack = vec![self.root_node()?];
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
            let node = match self.mount_at(&child_path) {
                Some(m) => Node {
                    mount: m,
                    ino: self.mounts[m].fs.root().map_err(io_errno)?,
                    path: child_path,
                },
                None => match self.fs(cur).lookup(cur.ino, &c).map_err(io_errno)? {
                    Some(ino) => Node {
                        mount: cur.mount,
                        ino,
                        path: child_path,
                    },
                    None => return Err(ENOENT),
                },
            };
            let st = self.stat(&node)?;
            if st.mode & S_IFMT == S_IFLNK && (follow_last || !todo.is_empty()) {
                links += 1;
                if links > 40 {
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
        st.dev = node.mount as u64 + 1;
        Ok(st)
    }

    pub fn read_all(&self, node: &Node) -> Result<Arc<[u8]>, i64> {
        self.fs(node).read_all(node.ino).map_err(io_errno)
    }

    pub fn readdir(&self, node: &Node) -> Result<Vec<Dirent>, i64> {
        let mut out = self.fs(node).readdir(node.ino).map_err(io_errno)?;
        // Mount points directly under this directory, even if not in the parent fs.
        for m in &self.mounts[1..] {
            if let Some((parent, name)) = m.path.rsplit_once('/') {
                let parent = if parent.is_empty() { "/" } else { parent };
                if parent == node.path && !out.iter().any(|d| d.name == name) {
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

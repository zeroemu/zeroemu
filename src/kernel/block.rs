//! Block devices: loop devices and device-mapper, so Android's apexd can
//! activate APEXes itself, as on a phone: a loop device over the .apex file
//! at the payload's offset, dm-verity on top, then mount("/dev/block/dm-N",
//! "/apex/<name>@<version>", "ext4"), which opens droidrt's own ext4/EROFS
//! reader on the device.
//!
//! dm-verity maps reads straight through to its data device: the image
//! readers validate structure, and droidrt is not a security boundary.
//! The kernel also does ueventd's part for these devices: /dev/block nodes,
//! /dev/block/mapper/{<name>,by-uuid/<uuid>} links, and /sys/block entries.

use crate::errno::*;
use crate::image::{Dev, ReadAt};
use crate::tmpfs::MemFile;
use crate::vfs::{FileSystem, S_IFDIR, S_IFMT, S_IFREG};
use std::collections::BTreeMap;
use std::io;
use std::sync::{Arc, Mutex};

pub const LOOP_MAJOR: u32 = 7;
/// Linux picks device-mapper's major dynamically; 253 is the usual result.
pub const DM_MAJOR: u32 = 253;
pub const MISC_MAJOR: u32 = 10;
pub const LOOP_CONTROL_MINOR: u32 = 237;
pub const DM_CONTROL_MINOR: u32 = 236;
/// Loop devices that exist from boot (CONFIG_BLK_DEV_LOOP_MIN_COUNT).
const LOOP_MIN_COUNT: u32 = 8;
const SECTOR: u64 = 512;
const S_IFCHR: u32 = 0o020000;
const S_IFBLK: u32 = 0o060000;

/// Userspace dev_t encoding (bionic/glibc makedev).
pub fn makedev(major: u32, minor: u32) -> u64 {
    let (ma, mi) = (major as u64, minor as u64);
    ((ma & 0xffff_f000) << 32) | ((ma & 0xfff) << 8) | ((mi & 0xffff_ff00) << 12) | (mi & 0xff)
}

/// The /dev/block name of a device.
pub fn name(devt: u64) -> String {
    match major(devt) {
        LOOP_MAJOR => format!("loop{}", minor(devt)),
        DM_MAJOR => format!("dm-{}", minor(devt)),
        ma => format!("{ma}:{}", minor(devt)),
    }
}

pub fn major(dev: u64) -> u32 {
    (((dev >> 32) & 0xffff_f000) | ((dev >> 8) & 0xfff)) as u32
}

pub fn minor(dev: u64) -> u32 {
    (((dev >> 12) & 0xffff_ff00) | (dev & 0xff)) as u32
}

/// What an ioctl needs from the calling process.
pub trait Caller {
    fn read(&mut self, addr: u64, len: usize) -> Result<Vec<u8>, i64>;
    fn write(&mut self, addr: u64, data: &[u8]) -> Result<(), i64>;
    /// The contents of open file `fd` as a device, with the file's path.
    fn backing(&mut self, fd: i32) -> Result<(Dev, String), i64>;
    /// The block device (dev_t) a path names, for dm table references.
    fn dev_of_path(&mut self, path: &str) -> Option<u64>;
}

/// A tmpfs file as a device (e.g. an APEX decompressed into /data).
pub struct MemFileDev(pub Arc<MemFile>);

impl ReadAt for MemFileDev {
    fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        let data = self.0.read_at(offset, buf.len());
        if data.len() != buf.len() {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        buf.copy_from_slice(&data);
        Ok(())
    }
    fn len(&self) -> u64 {
        self.0.size()
    }
}

// ---- loop devices ----

const LOOP_SET_FD: u64 = 0x4C00;
const LOOP_CLR_FD: u64 = 0x4C01;
const LOOP_SET_STATUS64: u64 = 0x4C04;
const LOOP_GET_STATUS64: u64 = 0x4C05;
const LOOP_SET_CAPACITY: u64 = 0x4C07;
const LOOP_SET_DIRECT_IO: u64 = 0x4C08;
const LOOP_SET_BLOCK_SIZE: u64 = 0x4C09;
const LOOP_CONFIGURE: u64 = 0x4C0A;
const LOOP_CTL_ADD: u64 = 0x4C80;
const LOOP_CTL_REMOVE: u64 = 0x4C81;
const LOOP_CTL_GET_FREE: u64 = 0x4C82;
const LO_FLAGS_READ_ONLY: u32 = 1;
const LO_FLAGS_AUTOCLEAR: u32 = 4;
const LO_FLAGS_PARTSCAN: u32 = 8;
const LO_FLAGS_DIRECT_IO: u32 = 16;
/// sizeof(struct loop_info64) and sizeof(struct loop_config).
const LOOP_INFO64: usize = 232;
const LOOP_CONFIG: usize = 304;

struct Bound {
    dev: Dev,
    name: String,
    offset: u64,
    sizelimit: u64,
    flags: u32,
    block_size: u32,
}

impl Bound {
    fn size(&self) -> u64 {
        let avail = self.dev.len().saturating_sub(self.offset);
        if self.sizelimit != 0 { avail.min(self.sizelimit) } else { avail }
    }
}

struct Loop {
    number: u32,
    st: Mutex<Option<Bound>>,
}

struct LoopDev(Arc<Loop>);

impl ReadAt for LoopDev {
    fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        let (dev, base, size) = match &*self.0.st.lock().unwrap() {
            Some(b) => (b.dev.clone(), b.offset, b.size()),
            None => return Err(io::ErrorKind::UnexpectedEof.into()),
        };
        if offset + buf.len() as u64 > size {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        dev.read_exact_at(base + offset, buf)
    }
    fn len(&self) -> u64 {
        self.0.st.lock().unwrap().as_ref().map_or(0, Bound::size)
    }
}

fn cstr_field(b: &[u8]) -> String {
    let end = b.iter().position(|&c| c == 0).unwrap_or(b.len());
    String::from_utf8_lossy(&b[..end]).into_owned()
}

fn le32(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes(b[o..o + 4].try_into().unwrap())
}

fn le64(b: &[u8], o: usize) -> u64 {
    u64::from_le_bytes(b[o..o + 8].try_into().unwrap())
}

// ---- device-mapper ----

/// sizeof(struct dm_ioctl): version[3], data_size, data_start, target_count,
/// open_count, flags, event_nr, padding, dev, name[128], uuid[129], data[7].
const DM_IOCTL: usize = 312;
/// sizeof(struct dm_target_spec): sector_start, length, status, next, target_type[16].
const DM_SPEC: usize = 40;
const DM_NAME_LEN: usize = 128;
const DM_UUID_LEN: usize = 129;
const DM_VERSION: [u32; 3] = [4, 48, 0];

const DM_READONLY_FLAG: u32 = 1 << 0;
const DM_SUSPEND_FLAG: u32 = 1 << 1;
const DM_STATUS_TABLE_FLAG: u32 = 1 << 4;
const DM_ACTIVE_PRESENT_FLAG: u32 = 1 << 5;
const DM_INACTIVE_PRESENT_FLAG: u32 = 1 << 6;
const DM_BUFFER_FULL_FLAG: u32 = 1 << 8;
const DM_QUERY_INACTIVE_TABLE_FLAG: u32 = 1 << 12;
const DM_UUID_FLAG: u32 = 1 << 14;

/// Command numbers (the low byte of _IOWR(0xfd, nr, struct dm_ioctl)).
mod dm {
    pub const VERSION: u64 = 0;
    pub const REMOVE_ALL: u64 = 1;
    pub const LIST_DEVICES: u64 = 2;
    pub const DEV_CREATE: u64 = 3;
    pub const DEV_REMOVE: u64 = 4;
    pub const DEV_RENAME: u64 = 5;
    pub const DEV_SUSPEND: u64 = 6;
    pub const DEV_STATUS: u64 = 7;
    pub const DEV_WAIT: u64 = 8;
    pub const TABLE_LOAD: u64 = 9;
    pub const TABLE_CLEAR: u64 = 10;
    pub const TABLE_DEPS: u64 = 11;
    pub const TABLE_STATUS: u64 = 12;
    pub const LIST_VERSIONS: u64 = 13;
    pub const TARGET_MSG: u64 = 14;
    pub const DEV_ARM_POLL: u64 = 16;
    pub const GET_TARGET_VERSION: u64 = 17;
}

/// The targets droidrt implements, with the versions Linux 6.6 reports.
const TARGETS: [(&str, [u32; 3]); 4] = [("linear", [1, 4, 0]), ("verity", [1, 9, 0]), ("zero", [1, 2, 0]), ("error", [1, 6, 0])];

enum Map {
    /// Sector `s` of the target reads `dev` at byte `offset + s * 512`.
    Linear { dev: Dev, devt: u64, offset: u64 },
    Zero,
    Error,
}

struct Target {
    start: u64,
    len: u64,
    ty: String,
    params: String,
    map: Map,
}

type Table = Arc<Vec<Target>>;

#[derive(Default)]
struct DmState {
    active: Option<Table>,
    inactive: Option<Table>,
    suspended: bool,
    readonly: bool,
    event_nr: u32,
}

struct DmDevice {
    minor: u32,
    ids: Mutex<(String, String)>, // name, uuid
    st: Mutex<DmState>,
}

struct DmDev(Arc<DmDevice>);

impl ReadAt for DmDev {
    fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        let Some(table) = self.0.st.lock().unwrap().active.clone() else {
            return Err(io::ErrorKind::UnexpectedEof.into());
        };
        let size = table.last().map_or(0, |t| (t.start + t.len) * SECTOR);
        if offset + buf.len() as u64 > size {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        let mut done = 0;
        while done < buf.len() {
            let pos = offset + done as u64;
            let i = table.partition_point(|t| (t.start + t.len) * SECTOR <= pos);
            let t = &table[i];
            let rel = pos - t.start * SECTOR;
            let n = (((t.start + t.len) * SECTOR - pos) as usize).min(buf.len() - done);
            let dst = &mut buf[done..done + n];
            match &t.map {
                Map::Linear { dev, offset, .. } => dev.read_exact_at(offset + rel, dst)?,
                Map::Zero => dst.fill(0),
                Map::Error => return Err(io::Error::other("dm-error target")),
            }
            done += n;
        }
        Ok(())
    }
    fn len(&self) -> u64 {
        self.0.st.lock().unwrap().active.as_ref().and_then(|t| t.last()).map_or(0, |t| (t.start + t.len) * SECTOR)
    }
}

// ---- the registry ----

#[derive(Default)]
struct Devices {
    loops: BTreeMap<u32, Arc<Loop>>,
    dms: Vec<Arc<DmDevice>>,
}

pub struct Blocks {
    devs: Mutex<Devices>,
    /// /dev and /sys, where the device nodes and attributes appear.
    dev: Arc<dyn FileSystem>,
    sys: Arc<dyn FileSystem>,
}

/// mkdir -p on any writable filesystem; returns the directory's inode.
fn mkdir_p(fs: &dyn FileSystem, path: &str) -> u64 {
    let mut d = fs.root().unwrap_or(1);
    for part in path.split('/').filter(|p| !p.is_empty()) {
        d = match fs.lookup(d, part).ok().flatten() {
            Some(i) => i,
            None => match fs.mkdir(d, part, 0o755) {
                Ok(i) => i,
                Err(_) => return d,
            },
        };
    }
    d
}

/// The inode at `path`, if it exists.
fn walk(fs: &dyn FileSystem, path: &str) -> Option<u64> {
    let mut d = fs.root().ok()?;
    for part in path.split('/').filter(|p| !p.is_empty()) {
        d = fs.lookup(d, part).ok().flatten()?;
    }
    Some(d)
}

/// Creates or replaces a small attribute file.
pub(super) fn put_file(fs: &dyn FileSystem, path: &str, content: &str) {
    let (dir, name) = path.rsplit_once('/').unwrap_or(("", path));
    let d = mkdir_p(fs, dir);
    let ino = match fs.lookup(d, name).ok().flatten() {
        Some(i) => i,
        None => match fs.create(d, name, S_IFREG | 0o644, 0) {
            Ok(i) => i,
            Err(_) => return,
        },
    };
    if let Some(f) = fs.mem_file(ino) {
        f.truncate(0);
        let _ = f.write_at(0, content.as_bytes());
    }
}

fn remove(fs: &dyn FileSystem, path: &str) {
    let (dir, name) = path.rsplit_once('/').unwrap_or(("", path));
    if let Some(d) = walk(fs, dir) {
        let _ = fs.unlink(d, name, false);
    }
}

fn remove_tree(fs: &dyn FileSystem, path: &str) {
    fn rm(fs: &dyn FileSystem, dir: u64) {
        for e in fs.readdir(dir).unwrap_or_default() {
            if e.name == "." || e.name == ".." {
                continue;
            }
            if let Ok(Some(ino)) = fs.lookup(dir, &e.name) {
                let is_dir = fs.stat(ino).is_ok_and(|s| s.mode & S_IFMT == S_IFDIR);
                if is_dir {
                    rm(fs, ino);
                }
                let _ = fs.unlink(dir, &e.name, is_dir);
            }
        }
    }
    let Some(d) = walk(fs, path) else { return };
    rm(fs, d);
    let (parent, name) = path.rsplit_once('/').unwrap_or(("", path));
    if let Some(p) = walk(fs, parent) {
        let _ = fs.unlink(p, name, true);
    }
}

impl Blocks {
    /// `dev` and `sys` are the writable filesystems mounted at /dev and /sys.
    pub fn new(dev: Arc<dyn FileSystem>, sys: Arc<dyn FileSystem>) -> Arc<Blocks> {
        let b = Arc::new(Blocks { devs: Mutex::default(), dev, sys });
        let root = b.dev.root().unwrap_or(1);
        let _ = b.dev.create(root, "loop-control", S_IFCHR | 0o660, makedev(MISC_MAJOR, LOOP_CONTROL_MINOR));
        let _ = b.dev.create(root, "device-mapper", S_IFCHR | 0o600, makedev(MISC_MAJOR, DM_CONTROL_MINOR));
        mkdir_p(&*b.dev, "block/mapper/by-uuid");
        let mut devs = b.devs.lock().unwrap();
        for n in 0..LOOP_MIN_COUNT {
            b.add_loop(&mut devs, n);
        }
        drop(devs);
        b
    }

    /// The device behind a dev_t, for reads and for mount(2).
    pub fn device(&self, devt: u64) -> Option<Dev> {
        let devs = self.devs.lock().unwrap();
        match major(devt) {
            LOOP_MAJOR => devs.loops.get(&minor(devt)).map(|l| Arc::new(LoopDev(l.clone())) as Dev),
            DM_MAJOR => devs.dms.iter().find(|d| d.minor == minor(devt)).map(|d| Arc::new(DmDev(d.clone())) as Dev),
            _ => None,
        }
    }

    fn add_loop(&self, devs: &mut Devices, n: u32) -> Arc<Loop> {
        let lp = Arc::new(Loop { number: n, st: Mutex::new(None) });
        devs.loops.insert(n, lp.clone());
        let block = mkdir_p(&*self.dev, "block");
        let _ = self.dev.create(block, &format!("loop{n}"), S_IFBLK | 0o600, makedev(LOOP_MAJOR, n));
        self.loop_sysfs(&lp, None);
        lp
    }

    fn loop_sysfs(&self, lp: &Loop, b: Option<&Bound>) {
        let base = format!("block/loop{}", lp.number);
        put_file(&*self.sys, &format!("{base}/size"), &format!("{}\n", b.map_or(0, |b| b.size() / SECTOR)));
        put_file(&*self.sys, &format!("{base}/ro"), if b.is_some_and(|b| b.flags & LO_FLAGS_READ_ONLY != 0) { "1\n" } else { "0\n" });
        put_file(&*self.sys, &format!("{base}/dev"), &format!("{LOOP_MAJOR}:{}\n", lp.number));
        put_file(&*self.sys, &format!("{base}/queue/read_ahead_kb"), "128\n");
        put_file(&*self.sys, &format!("{base}/queue/logical_block_size"), &format!("{}\n", b.map_or(512, |b| b.block_size)));
        put_file(&*self.sys, &format!("{base}/queue/nr_requests"), "128\n");
        put_file(&*self.sys, &format!("{base}/queue/scheduler"), "[none]\n");
        match b {
            Some(b) => {
                put_file(&*self.sys, &format!("{base}/loop/backing_file"), &format!("{}\n", b.name));
                put_file(&*self.sys, &format!("{base}/loop/offset"), &format!("{}\n", b.offset));
                put_file(&*self.sys, &format!("{base}/loop/sizelimit"), &format!("{}\n", b.sizelimit));
                put_file(&*self.sys, &format!("{base}/loop/autoclear"), if b.flags & LO_FLAGS_AUTOCLEAR != 0 { "1\n" } else { "0\n" });
                put_file(&*self.sys, &format!("{base}/loop/dio"), if b.flags & LO_FLAGS_DIRECT_IO != 0 { "1\n" } else { "0\n" });
            }
            None => remove_tree(&*self.sys, &format!("{base}/loop")),
        }
    }

    /// ioctls on /dev/loop-control.
    pub fn loop_control(&self, cmd: u64, arg: u64) -> Result<i64, i64> {
        let mut devs = self.devs.lock().unwrap();
        match cmd {
            LOOP_CTL_GET_FREE => {
                if let Some(l) = devs.loops.values().find(|l| l.st.lock().unwrap().is_none()) {
                    return Ok(l.number as i64);
                }
                let n = devs.loops.keys().next_back().map_or(0, |n| n + 1);
                Ok(self.add_loop(&mut devs, n).number as i64)
            }
            LOOP_CTL_ADD => {
                let n = arg as i64;
                if n < 0 {
                    // -1: the first free number
                    let n = (0..).find(|n| !devs.loops.contains_key(n)).unwrap();
                    return Ok(self.add_loop(&mut devs, n).number as i64);
                }
                let n = u32::try_from(n).map_err(|_| EINVAL)?;
                if n >= 1 << 20 {
                    return Err(EINVAL);
                }
                if devs.loops.contains_key(&n) {
                    return Err(EEXIST);
                }
                Ok(self.add_loop(&mut devs, n).number as i64)
            }
            LOOP_CTL_REMOVE => {
                let n = u32::try_from(arg).map_err(|_| EINVAL)?;
                let lp = devs.loops.get(&n).ok_or(ENODEV)?;
                if lp.st.lock().unwrap().is_some() {
                    return Err(EBUSY);
                }
                devs.loops.remove(&n);
                remove(&*self.dev, &format!("block/loop{n}"));
                remove_tree(&*self.sys, &format!("block/loop{n}"));
                Ok(n as i64)
            }
            _ => Err(ENOTTY),
        }
    }

    fn loop_dev(&self, devt: u64) -> Result<Arc<Loop>, i64> {
        self.devs.lock().unwrap().loops.get(&minor(devt)).cloned().ok_or(ENXIO)
    }

    fn info64(b: &Bound, number: u32) -> Vec<u8> {
        let mut info = vec![0u8; LOOP_INFO64];
        info[24..32].copy_from_slice(&b.offset.to_le_bytes());
        info[32..40].copy_from_slice(&b.sizelimit.to_le_bytes());
        info[40..44].copy_from_slice(&number.to_le_bytes());
        info[52..56].copy_from_slice(&b.flags.to_le_bytes());
        let name = b.name.as_bytes();
        let n = name.len().min(63);
        info[56..56 + n].copy_from_slice(&name[..n]);
        info
    }

    /// ioctls on a block device node.
    pub fn ioctl(&self, devt: u64, cmd: u64, arg: u64, c: &mut dyn Caller) -> Result<i64, i64> {
        const BLKROSET: u64 = 0x125d;
        const BLKROGET: u64 = 0x125e;
        const BLKGETSIZE: u64 = 0x1260;
        const BLKFLSBUF: u64 = 0x1261;
        const BLKRASET: u64 = 0x1262;
        const BLKRAGET: u64 = 0x1263;
        const BLKSSZGET: u64 = 0x1268;
        const BLKBSZGET: u64 = 0x8008_1270;
        const BLKBSZSET: u64 = 0x4008_1271;
        const BLKGETSIZE64: u64 = 0x8008_1272;
        const BLKIOMIN: u64 = 0x1278;
        const BLKIOOPT: u64 = 0x1279;
        const BLKALIGNOFF: u64 = 0x127a;
        const BLKPBSZGET: u64 = 0x127b;
        const BLKROTATIONAL: u64 = 0x127e;
        let dev = self.device(devt).ok_or(ENXIO)?;
        let lp = if major(devt) == LOOP_MAJOR { Some(self.loop_dev(devt)?) } else { None };
        let block_size = lp.as_ref().and_then(|l| l.st.lock().unwrap().as_ref().map(|b| b.block_size)).unwrap_or(4096);
        let put32 = |c: &mut dyn Caller, v: u32| c.write(arg, &v.to_le_bytes()).map(|_| 0);
        let put64 = |c: &mut dyn Caller, v: u64| c.write(arg, &v.to_le_bytes()).map(|_| 0);
        match cmd {
            BLKGETSIZE64 => put64(c, dev.len()),
            BLKGETSIZE => put64(c, dev.len() / SECTOR),
            BLKSSZGET => put32(c, if lp.is_some() { block_size.min(4096) } else { 512 }),
            BLKBSZGET | BLKPBSZGET | BLKIOMIN | BLKIOOPT => put32(c, if cmd == BLKIOOPT { 0 } else { block_size }),
            BLKALIGNOFF | BLKROTATIONAL => put32(c, 0),
            BLKROGET => {
                let ro = match &lp {
                    Some(l) => l.st.lock().unwrap().as_ref().is_some_and(|b| b.flags & LO_FLAGS_READ_ONLY != 0),
                    None => self.dm_by_minor(minor(devt)).is_some_and(|d| d.st.lock().unwrap().readonly),
                };
                put32(c, ro as u32)
            }
            BLKRAGET => put64(c, 256),
            BLKFLSBUF | BLKROSET | BLKRASET | BLKBSZSET => Ok(0),
            _ => match lp {
                Some(lp) => self.loop_ioctl(&lp, cmd, arg, c),
                None => Err(ENOTTY),
            },
        }
    }

    fn loop_ioctl(&self, lp: &Arc<Loop>, cmd: u64, arg: u64, c: &mut dyn Caller) -> Result<i64, i64> {
        match cmd {
            LOOP_SET_FD | LOOP_CONFIGURE => {
                let (fd, block_size, info) = if cmd == LOOP_CONFIGURE {
                    let cfg = c.read(arg, LOOP_CONFIG)?;
                    if cfg[240..].iter().any(|&b| b != 0) {
                        return Err(EINVAL); // __reserved must be zero
                    }
                    (le32(&cfg, 0) as i32, le32(&cfg, 4), Some(cfg[8..8 + LOOP_INFO64].to_vec()))
                } else {
                    (arg as i32, 0, None)
                };
                let block_size = match block_size {
                    0 => 512,
                    s if (512..=4096).contains(&s) && s.is_power_of_two() => s,
                    _ => return Err(EINVAL),
                };
                let (dev, name) = c.backing(fd)?;
                let mut b = Bound { dev, name, offset: 0, sizelimit: 0, flags: 0, block_size };
                if let Some(info) = &info {
                    let flags = le32(info, 52);
                    if flags & !(LO_FLAGS_READ_ONLY | LO_FLAGS_AUTOCLEAR | LO_FLAGS_PARTSCAN | LO_FLAGS_DIRECT_IO) != 0 {
                        return Err(EINVAL);
                    }
                    b.offset = le64(info, 24);
                    b.sizelimit = le64(info, 32);
                    // Everything droidrt can back a loop device with is read-only.
                    b.flags = flags | LO_FLAGS_READ_ONLY;
                    let fname = cstr_field(&info[56..120]);
                    if !fname.is_empty() {
                        b.name = fname;
                    }
                } else {
                    b.flags = LO_FLAGS_READ_ONLY;
                }
                if b.offset > b.dev.len() {
                    return Err(EINVAL);
                }
                let mut st = lp.st.lock().unwrap();
                if st.is_some() {
                    return Err(EBUSY);
                }
                self.loop_sysfs(lp, Some(&b));
                *st = Some(b);
                Ok(0)
            }
            LOOP_CLR_FD => {
                let mut st = lp.st.lock().unwrap();
                if st.take().is_none() {
                    return Err(ENXIO);
                }
                self.loop_sysfs(lp, None);
                Ok(0)
            }
            LOOP_SET_STATUS64 => {
                let info = c.read(arg, LOOP_INFO64)?;
                let mut st = lp.st.lock().unwrap();
                let b = st.as_mut().ok_or(ENXIO)?;
                let flags = le32(&info, 52);
                // Only AUTOCLEAR and PARTSCAN can be changed after binding.
                let settable = LO_FLAGS_AUTOCLEAR | LO_FLAGS_PARTSCAN;
                b.flags = (b.flags & !LO_FLAGS_AUTOCLEAR) | (flags & settable);
                b.offset = le64(&info, 24);
                b.sizelimit = le64(&info, 32);
                let fname = cstr_field(&info[56..120]);
                if !fname.is_empty() {
                    b.name = fname;
                }
                self.loop_sysfs(lp, Some(b));
                Ok(0)
            }
            LOOP_GET_STATUS64 => {
                let info = match &*lp.st.lock().unwrap() {
                    Some(b) => Blocks::info64(b, lp.number),
                    None => return Err(ENXIO),
                };
                c.write(arg, &info).map(|_| 0)
            }
            LOOP_SET_BLOCK_SIZE => {
                let mut st = lp.st.lock().unwrap();
                let b = st.as_mut().ok_or(ENXIO)?;
                if !(512..=4096).contains(&arg) || !arg.is_power_of_two() {
                    return Err(EINVAL);
                }
                b.block_size = arg as u32;
                self.loop_sysfs(lp, Some(b));
                Ok(0)
            }
            LOOP_SET_DIRECT_IO => {
                let mut st = lp.st.lock().unwrap();
                let b = st.as_mut().ok_or(ENXIO)?;
                if arg != 0 { b.flags |= LO_FLAGS_DIRECT_IO } else { b.flags &= !LO_FLAGS_DIRECT_IO }
                self.loop_sysfs(lp, Some(b));
                Ok(0)
            }
            LOOP_SET_CAPACITY => lp.st.lock().unwrap().as_ref().map(|_| 0).ok_or(ENXIO),
            _ => Err(ENOTTY),
        }
    }

    // ---- device-mapper control (/dev/device-mapper) ----

    fn dm_by_minor(&self, minor: u32) -> Option<Arc<DmDevice>> {
        self.devs.lock().unwrap().dms.iter().find(|d| d.minor == minor).cloned()
    }

    /// Linux's lookup order: uuid, then name, then dev.
    fn dm_find(devs: &Devices, name: &str, uuid: &str, devt: u64) -> Option<Arc<DmDevice>> {
        devs.dms
            .iter()
            .find(|d| {
                let ids = d.ids.lock().unwrap();
                if !uuid.is_empty() {
                    ids.1 == uuid
                } else if !name.is_empty() {
                    ids.0 == name
                } else {
                    devt != 0 && makedev(DM_MAJOR, d.minor) == devt
                }
            })
            .cloned()
    }

    fn dm_links(&self, d: &DmDevice, add: bool) {
        let (name, uuid) = d.ids.lock().unwrap().clone();
        let target = format!("dm-{}", d.minor);
        let mapper = mkdir_p(&*self.dev, "block/mapper");
        let by_uuid = mkdir_p(&*self.dev, "block/mapper/by-uuid");
        if add {
            let _ = self.dev.symlink(mapper, &name, &format!("../{target}"));
            if !uuid.is_empty() {
                let _ = self.dev.symlink(by_uuid, &uuid, &format!("../../{target}"));
            }
            put_file(&*self.sys, &format!("block/{target}/dm/name"), &format!("{name}\n"));
            put_file(&*self.sys, &format!("block/{target}/dm/uuid"), &format!("{uuid}\n"));
        } else {
            let _ = self.dev.unlink(mapper, &name, false);
            if !uuid.is_empty() {
                let _ = self.dev.unlink(by_uuid, &uuid, false);
            }
        }
    }

    /// A read-only device-mapper device over `dev`, as first-stage init
    /// creates for each logical partition in `super`.
    pub fn add_static(&self, name: &str, dev: Dev) {
        let sectors = dev.len() / SECTOR;
        if sectors == 0 {
            return;
        }
        let mut devs = self.devs.lock().unwrap();
        if devs.dms.iter().any(|d| d.ids.lock().unwrap().0 == name) {
            return;
        }
        let minor = (0..).find(|m| !devs.dms.iter().any(|d| d.minor == *m)).unwrap();
        let table = vec![Target { start: 0, len: sectors, ty: "linear".into(), params: "super 0".into(), map: Map::Linear { dev, devt: 0, offset: 0 } }];
        let st = DmState { active: Some(Arc::new(table)), readonly: true, ..Default::default() };
        let d = Arc::new(DmDevice { minor, ids: Mutex::new((name.into(), String::new())), st: Mutex::new(st) });
        devs.dms.push(d.clone());
        drop(devs);
        let block = mkdir_p(&*self.dev, "block");
        let _ = self.dev.create(block, &format!("dm-{minor}"), S_IFBLK | 0o600, makedev(DM_MAJOR, minor));
        self.dm_links(&d, true);
        self.dm_sysfs(&d);
    }

    fn dm_sysfs(&self, d: &DmDevice) {
        let base = format!("block/dm-{}", d.minor);
        let st = d.st.lock().unwrap();
        let size = st.active.as_ref().and_then(|t| t.last()).map_or(0, |t| t.start + t.len);
        put_file(&*self.sys, &format!("{base}/size"), &format!("{size}\n"));
        put_file(&*self.sys, &format!("{base}/ro"), if st.readonly { "1\n" } else { "0\n" });
        put_file(&*self.sys, &format!("{base}/dev"), &format!("{DM_MAJOR}:{}\n", d.minor));
        put_file(&*self.sys, &format!("{base}/dm/suspended"), if st.suspended { "1\n" } else { "0\n" });
        put_file(&*self.sys, &format!("{base}/queue/read_ahead_kb"), "128\n");
        put_file(&*self.sys, &format!("{base}/queue/logical_block_size"), "512\n");
    }

    /// Resolves a table's device reference: "major:minor" or a path.
    fn dm_dev_ref(&self, s: &str, c: &mut dyn Caller) -> Result<(Dev, u64), i64> {
        let devt = match s.split_once(':') {
            Some((ma, mi)) => makedev(ma.parse().map_err(|_| EINVAL)?, mi.parse().map_err(|_| EINVAL)?),
            None => c.dev_of_path(s).ok_or(ENXIO)?,
        };
        Ok((self.device(devt).ok_or(ENXIO)?, devt))
    }

    fn dm_target(&self, start: u64, len: u64, ty: &str, params: &str, c: &mut dyn Caller) -> Result<Target, i64> {
        let words: Vec<&str> = params.split_whitespace().collect();
        let map = match ty {
            "linear" => {
                let [dev, off] = words[..] else { return Err(EINVAL) };
                let (dev, devt) = self.dm_dev_ref(dev, c)?;
                Map::Linear { dev, devt, offset: off.parse::<u64>().map_err(|_| EINVAL)? * SECTOR }
            }
            // <version> <data dev> <hash dev> <data block size> <hash block size>
            // <#data blocks> <hash start block> <algorithm> <digest> <salt> [opts]
            "verity" => {
                if words.len() < 10 {
                    return Err(EINVAL);
                }
                let (dev, devt) = self.dm_dev_ref(words[1], c)?;
                let block: u64 = words[3].parse().map_err(|_| EINVAL)?;
                let blocks: u64 = words[5].parse().map_err(|_| EINVAL)?;
                if !block.is_power_of_two() || block < 512 || blocks.checked_mul(block).is_none_or(|b| b < len * SECTOR) {
                    return Err(EINVAL);
                }
                Map::Linear { dev, devt, offset: 0 }
            }
            "zero" => Map::Zero,
            "error" => Map::Error,
            _ => return Err(EINVAL),
        };
        Ok(Target { start, len, ty: ty.into(), params: params.into(), map })
    }

    /// One ioctl on /dev/device-mapper.
    pub fn dm_ioctl(&self, cmd: u64, arg: u64, c: &mut dyn Caller) -> Result<i64, i64> {
        if (cmd >> 8) & 0xff != 0xfd {
            return Err(ENOTTY);
        }
        let nr = cmd & 0xff;
        let hdr = c.read(arg, DM_IOCTL)?;
        let data_size = le32(&hdr, 12) as usize;
        if !(DM_IOCTL..=16 << 20).contains(&data_size) {
            return Err(EINVAL);
        }
        if le32(&hdr, 0) != DM_VERSION[0] {
            return Err(EINVAL);
        }
        let mut p = c.read(arg, data_size)?;
        let data_start = (le32(&p, 16) as usize).clamp(DM_IOCTL, data_size);
        let flags_in = le32(&p, 28);
        let name = cstr_field(&p[48..48 + DM_NAME_LEN]);
        let uuid = cstr_field(&p[176..176 + DM_UUID_LEN]);
        let devt = le64(&p, 40);
        // Output: the header (status fields) and a result area at data_start.
        let mut out: Vec<u8> = Vec::new();
        let mut flags = flags_in & !(DM_BUFFER_FULL_FLAG | DM_ACTIVE_PRESENT_FLAG | DM_INACTIVE_PRESENT_FLAG | DM_SUSPEND_FLAG | DM_READONLY_FLAG);
        let mut status_of: Option<Arc<DmDevice>> = None;
        match nr {
            dm::VERSION | dm::DEV_ARM_POLL | dm::LIST_VERSIONS | dm::GET_TARGET_VERSION => {}
            dm::REMOVE_ALL => {
                let all: Vec<Arc<DmDevice>> = std::mem::take(&mut self.devs.lock().unwrap().dms);
                for d in all {
                    self.dm_unregister(&d);
                }
            }
            dm::LIST_DEVICES => {
                let devs = self.devs.lock().unwrap();
                let n = devs.dms.len();
                for (i, d) in devs.dms.iter().enumerate() {
                    let start = out.len();
                    let (dname, _) = d.ids.lock().unwrap().clone();
                    out.extend_from_slice(&makedev(DM_MAJOR, d.minor).to_le_bytes());
                    out.extend_from_slice(&0u32.to_le_bytes()); // next, patched below
                    out.extend_from_slice(dname.as_bytes());
                    out.push(0);
                    while !out.len().is_multiple_of(8) {
                        out.push(0);
                    }
                    // event_nr and flags follow the aligned name (dm 4.37+).
                    out.extend_from_slice(&d.st.lock().unwrap().event_nr.to_le_bytes());
                    out.extend_from_slice(&0u32.to_le_bytes());
                    if i + 1 < n {
                        let next = (out.len() - start) as u32;
                        out[start + 8..start + 12].copy_from_slice(&next.to_le_bytes());
                    }
                }
            }
            dm::DEV_CREATE => {
                if name.is_empty() || name.contains('/') {
                    return Err(EINVAL);
                }
                let mut devs = self.devs.lock().unwrap();
                if devs.dms.iter().any(|d| {
                    let ids = d.ids.lock().unwrap();
                    ids.0 == name || (!uuid.is_empty() && ids.1 == uuid)
                }) {
                    return Err(EBUSY);
                }
                let minor = (0..).find(|m| !devs.dms.iter().any(|d| d.minor == *m)).unwrap();
                let d = Arc::new(DmDevice { minor, ids: Mutex::new((name.clone(), uuid.clone())), st: Mutex::default() });
                devs.dms.push(d.clone());
                drop(devs);
                let block = mkdir_p(&*self.dev, "block");
                let _ = self.dev.create(block, &format!("dm-{minor}"), S_IFBLK | 0o600, makedev(DM_MAJOR, minor));
                self.dm_links(&d, true);
                self.dm_sysfs(&d);
                status_of = Some(d);
            }
            _ => {
                let d = Blocks::dm_find(&self.devs.lock().unwrap(), &name, &uuid, devt).ok_or(ENXIO)?;
                match nr {
                    dm::DEV_REMOVE => {
                        self.devs.lock().unwrap().dms.retain(|x| !Arc::ptr_eq(x, &d));
                        self.dm_unregister(&d);
                        // The result still describes the removed device.
                        let ids = d.ids.lock().unwrap();
                        put_cstr(&mut p[48..48 + DM_NAME_LEN], &ids.0);
                        put_cstr(&mut p[176..176 + DM_UUID_LEN], &ids.1);
                    }
                    dm::DEV_RENAME => {
                        let new = cstr_field(&p[data_start..]);
                        if new.is_empty() || (flags_in & DM_UUID_FLAG == 0 && new.contains('/')) {
                            return Err(EINVAL);
                        }
                        let devs = self.devs.lock().unwrap();
                        let taken = devs.dms.iter().any(|x| {
                            let ids = x.ids.lock().unwrap();
                            if flags_in & DM_UUID_FLAG != 0 { ids.1 == new } else { ids.0 == new }
                        });
                        if taken {
                            return Err(EBUSY);
                        }
                        drop(devs);
                        if flags_in & DM_UUID_FLAG != 0 && !d.ids.lock().unwrap().1.is_empty() {
                            return Err(EINVAL); // a uuid can only be set once
                        }
                        self.dm_links(&d, false);
                        {
                            let mut ids = d.ids.lock().unwrap();
                            if flags_in & DM_UUID_FLAG != 0 { ids.1 = new } else { ids.0 = new }
                        }
                        self.dm_links(&d, true);
                        status_of = Some(d);
                    }
                    dm::DEV_SUSPEND => {
                        {
                            let mut st = d.st.lock().unwrap();
                            if flags_in & DM_SUSPEND_FLAG != 0 {
                                st.suspended = true;
                            } else {
                                if let Some(t) = st.inactive.take() {
                                    st.active = Some(t);
                                    st.readonly = flags_in & DM_READONLY_FLAG != 0;
                                    st.event_nr += 1;
                                }
                                st.suspended = false;
                            }
                        }
                        self.dm_sysfs(&d);
                        status_of = Some(d);
                    }
                    dm::DEV_STATUS | dm::DEV_WAIT => status_of = Some(d),
                    dm::TABLE_LOAD => {
                        let count = le32(&p, 20);
                        let mut targets = Vec::new();
                        let mut off = data_start;
                        for i in 0..count {
                            if off + DM_SPEC > p.len() {
                                return Err(EINVAL);
                            }
                            let spec = &p[off..off + DM_SPEC];
                            let (start, len, next) = (le64(spec, 0), le64(spec, 8), le32(spec, 20) as usize);
                            let ty = cstr_field(&spec[24..40]);
                            let params = cstr_field(&p[off + DM_SPEC..]);
                            let expect = targets.last().map_or(0, |t: &Target| t.start + t.len);
                            if len == 0 || start != expect {
                                return Err(EINVAL); // targets must tile the device from sector 0
                            }
                            targets.push(self.dm_target(start, len, &ty, &params, c)?);
                            if i + 1 < count {
                                if next < DM_SPEC {
                                    return Err(EINVAL);
                                }
                                off += next;
                            }
                        }
                        if targets.is_empty() {
                            return Err(EINVAL);
                        }
                        d.st.lock().unwrap().inactive = Some(Arc::new(targets));
                        status_of = Some(d);
                    }
                    dm::TABLE_CLEAR => {
                        d.st.lock().unwrap().inactive = None;
                        status_of = Some(d);
                    }
                    dm::TABLE_DEPS | dm::TABLE_STATUS => {
                        let table = {
                            let st = d.st.lock().unwrap();
                            if flags_in & DM_QUERY_INACTIVE_TABLE_FLAG != 0 { st.inactive.clone() } else { st.active.clone() }
                        };
                        let table = table.unwrap_or_default();
                        if nr == dm::TABLE_DEPS {
                            // struct dm_target_deps { count, padding, dev[] }
                            let mut deps: Vec<u64> = table.iter().filter_map(|t| match t.map { Map::Linear { devt, .. } => Some(devt), _ => None }).collect();
                            deps.sort();
                            deps.dedup();
                            out.extend_from_slice(&(deps.len() as u32).to_le_bytes());
                            out.extend_from_slice(&0u32.to_le_bytes());
                            for dv in deps {
                                out.extend_from_slice(&dv.to_le_bytes());
                            }
                        } else {
                            for t in table.iter() {
                                let start = out.len();
                                let text = if flags_in & DM_STATUS_TABLE_FLAG != 0 {
                                    t.params.clone()
                                } else if t.ty == "verity" {
                                    "V".into() // verified, no corruption seen
                                } else {
                                    String::new()
                                };
                                out.extend_from_slice(&t.start.to_le_bytes());
                                out.extend_from_slice(&t.len.to_le_bytes());
                                out.extend_from_slice(&0i32.to_le_bytes());
                                out.extend_from_slice(&0u32.to_le_bytes()); // next, patched below
                                let mut ty = [0u8; 16];
                                put_cstr(&mut ty, &t.ty);
                                out.extend_from_slice(&ty);
                                out.extend_from_slice(text.as_bytes());
                                out.push(0);
                                while !out.len().is_multiple_of(8) {
                                    out.push(0);
                                }
                                let next = (out.len() - start) as u32;
                                out[start + 20..start + 24].copy_from_slice(&next.to_le_bytes());
                            }
                        }
                        status_of = Some(d);
                    }
                    dm::TARGET_MSG => return Err(EINVAL),
                    _ => return Err(ENOTTY),
                }
            }
        }
        if nr == dm::LIST_VERSIONS || nr == dm::GET_TARGET_VERSION {
            let want = cstr_field(&p[data_start..]);
            let list: Vec<_> = TARGETS.iter().filter(|(n, _)| nr == dm::LIST_VERSIONS || *n == want).collect();
            if list.is_empty() {
                return Err(EINVAL);
            }
            for (i, (n, v)) in list.iter().enumerate() {
                let start = out.len();
                out.extend_from_slice(&0u32.to_le_bytes()); // next
                for x in v {
                    out.extend_from_slice(&x.to_le_bytes());
                }
                out.extend_from_slice(n.as_bytes());
                out.push(0);
                while !out.len().is_multiple_of(8) {
                    out.push(0);
                }
                if i + 1 < list.len() {
                    let next = (out.len() - start) as u32;
                    out[start..start + 4].copy_from_slice(&next.to_le_bytes());
                }
            }
        }
        // dev_status: what the device looks like after the command.
        if let Some(d) = &status_of {
            let st = d.st.lock().unwrap();
            if st.active.is_some() {
                flags |= DM_ACTIVE_PRESENT_FLAG;
            }
            if st.inactive.is_some() {
                flags |= DM_INACTIVE_PRESENT_FLAG;
            }
            if st.suspended {
                flags |= DM_SUSPEND_FLAG;
            }
            if st.readonly {
                flags |= DM_READONLY_FLAG;
            }
            let table = if flags_in & DM_QUERY_INACTIVE_TABLE_FLAG != 0 { &st.inactive } else { &st.active };
            p[20..24].copy_from_slice(&(table.as_ref().map_or(0, |t| t.len()) as u32).to_le_bytes());
            p[24..28].copy_from_slice(&0i32.to_le_bytes()); // open_count
            p[32..36].copy_from_slice(&st.event_nr.to_le_bytes());
            p[40..48].copy_from_slice(&makedev(DM_MAJOR, d.minor).to_le_bytes());
            let ids = d.ids.lock().unwrap();
            put_cstr(&mut p[48..48 + DM_NAME_LEN], &ids.0);
            put_cstr(&mut p[176..176 + DM_UUID_LEN], &ids.1);
        }
        for (i, v) in DM_VERSION.iter().enumerate() {
            p[i * 4..i * 4 + 4].copy_from_slice(&v.to_le_bytes());
        }
        let room = data_size - data_start;
        let used = if out.len() > room {
            flags |= DM_BUFFER_FULL_FLAG;
            0
        } else {
            p[data_start..data_start + out.len()].copy_from_slice(&out);
            out.len()
        };
        p[28..32].copy_from_slice(&flags.to_le_bytes());
        // The kernel reports how much of the buffer holds results.
        p[12..16].copy_from_slice(&((data_start + used) as u32).to_le_bytes());
        p[16..20].copy_from_slice(&(data_start as u32).to_le_bytes());
        c.write(arg, &p[..data_start + used])?;
        Ok(0)
    }

    fn dm_unregister(&self, d: &DmDevice) {
        self.dm_links(d, false);
        remove(&*self.dev, &format!("block/dm-{}", d.minor));
        remove_tree(&*self.sys, &format!("block/dm-{}", d.minor));
    }
}

fn put_cstr(dst: &mut [u8], s: &str) {
    dst.fill(0);
    let n = s.len().min(dst.len() - 1);
    dst[..n].copy_from_slice(&s.as_bytes()[..n]);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hv::{CpuState, Hypervisor, KernelPage, PageTableRoot, Vcpu};
    use crate::image::MemDev;
    use crate::phys::PhysMem;
    use crate::tmpfs::Tmpfs;

    /// Enough of a hypervisor for tmpfs: memory, no vCPUs.
    struct NoHv;
    impl Hypervisor for NoHv {
        fn map_ram(&self, _: *mut u8, _: u64, _: u64) -> Result<(), String> {
            Ok(())
        }
        fn unmap_ram(&self, _: u64, _: u64) -> Result<(), String> {
            Ok(())
        }
        fn kernel_pages(&self, _: &mut dyn FnMut() -> (u64, *mut u8)) -> Vec<KernelPage> {
            Vec::new()
        }
        fn create_vcpu(&self, _: PageTableRoot, _: &CpuState) -> Result<Box<dyn Vcpu>, String> {
            Err("no vCPUs in tests".into())
        }
        fn max_vcpus(&self) -> usize {
            0
        }
    }

    /// A process with a flat memory and one open file (fd 3).
    struct Fake {
        mem: Vec<u8>,
        file: Dev,
    }

    impl Caller for Fake {
        fn read(&mut self, addr: u64, len: usize) -> Result<Vec<u8>, i64> {
            self.mem.get(addr as usize..addr as usize + len).map(|s| s.to_vec()).ok_or(EFAULT)
        }
        fn write(&mut self, addr: u64, data: &[u8]) -> Result<(), i64> {
            self.mem.get_mut(addr as usize..addr as usize + data.len()).ok_or(EFAULT)?.copy_from_slice(data);
            Ok(())
        }
        fn backing(&mut self, fd: i32) -> Result<(Dev, String), i64> {
            if fd == 3 { Ok((self.file.clone(), "/system/apex/test.apex".into())) } else { Err(EBADF) }
        }
        fn dev_of_path(&mut self, path: &str) -> Option<u64> {
            path.strip_prefix("/dev/block/loop").and_then(|n| n.parse().ok()).map(|n| makedev(LOOP_MAJOR, n))
        }
    }

    fn setup() -> (Arc<Blocks>, Fake) {
        let phys = PhysMem::new(Arc::new(NoHv));
        let blocks = Blocks::new(Tmpfs::new(phys.clone(), 0o755), Tmpfs::with_type(phys, 0o755, "sysfs"));
        // A "file" whose bytes are their own offset / 512 (so reads are checkable).
        let data: Vec<u8> = (0..64 * 1024).map(|i| (i / 512) as u8).collect();
        (blocks, Fake { mem: vec![0; 1 << 16], file: Arc::new(MemDev(data.into())) })
    }

    fn dm_header(name: &str, uuid: &str, size: usize) -> Vec<u8> {
        let mut h = vec![0u8; size];
        h[0..4].copy_from_slice(&4u32.to_le_bytes());
        h[12..16].copy_from_slice(&(size as u32).to_le_bytes());
        h[16..20].copy_from_slice(&(DM_IOCTL as u32).to_le_bytes());
        put_cstr(&mut h[48..176], name);
        put_cstr(&mut h[176..305], uuid);
        h
    }

    fn dm_cmd(nr: u64) -> u64 {
        0xC138_FD00 | nr
    }

    #[test]
    fn makedev_round_trips() {
        for (ma, mi) in [(7, 3), (253, 0), (10, 237), (259, 70000)] {
            let d = makedev(ma, mi);
            assert_eq!((major(d), minor(d)), (ma, mi));
        }
        assert_eq!(makedev(1, 3), 0x103);
    }

    #[test]
    fn loop_configure_with_offset() {
        let (b, mut c) = setup();
        let n = b.loop_control(LOOP_CTL_GET_FREE, 0).unwrap();
        assert_eq!(n, 0);
        let mut cfg = vec![0u8; LOOP_CONFIG];
        cfg[0..4].copy_from_slice(&3u32.to_le_bytes());
        cfg[4..8].copy_from_slice(&4096u32.to_le_bytes());
        cfg[8 + 24..8 + 32].copy_from_slice(&4096u64.to_le_bytes()); // lo_offset
        cfg[8 + 32..8 + 40].copy_from_slice(&8192u64.to_le_bytes()); // lo_sizelimit
        c.mem[0x100..0x100 + LOOP_CONFIG].copy_from_slice(&cfg);
        let devt = makedev(LOOP_MAJOR, 0);
        assert_eq!(b.ioctl(devt, LOOP_CONFIGURE, 0x100, &mut c), Ok(0));
        assert_eq!(b.ioctl(devt, LOOP_CONFIGURE, 0x100, &mut c), Err(EBUSY));
        let dev = b.device(devt).unwrap();
        assert_eq!(dev.len(), 8192);
        assert_eq!(dev.read_vec(0, 1).unwrap(), [8]); // byte 4096 of the file
        assert_eq!(b.ioctl(devt, 0x8008_1272, 0x200, &mut c), Ok(0)); // BLKGETSIZE64
        assert_eq!(le64(&c.mem, 0x200), 8192);
        // The next free device is now loop1; status reads back.
        assert_eq!(b.loop_control(LOOP_CTL_GET_FREE, 0), Ok(1));
        assert_eq!(b.ioctl(devt, LOOP_GET_STATUS64, 0x300, &mut c), Ok(0));
        assert_eq!(le64(&c.mem, 0x300 + 24), 4096);
        assert_eq!(cstr_field(&c.mem[0x300 + 56..0x300 + 120]), "/system/apex/test.apex");
        assert_eq!(b.loop_control(LOOP_CTL_REMOVE, 0), Err(EBUSY));
        assert_eq!(b.ioctl(devt, LOOP_CLR_FD, 0, &mut c), Ok(0));
        assert_eq!(b.ioctl(devt, LOOP_GET_STATUS64, 0x300, &mut c), Err(ENXIO));
        assert_eq!(b.loop_control(LOOP_CTL_REMOVE, 0), Ok(0));
        assert!(b.device(devt).is_none());
    }

    #[test]
    fn dm_verity_over_loop_reads_through() {
        let (b, mut c) = setup();
        let mut cfg = vec![0u8; LOOP_CONFIG];
        cfg[0..4].copy_from_slice(&3u32.to_le_bytes());
        c.mem[0x100..0x100 + LOOP_CONFIG].copy_from_slice(&cfg);
        b.ioctl(makedev(LOOP_MAJOR, 2), LOOP_CONFIGURE, 0x100, &mut c).unwrap();

        // DM_DEV_CREATE
        let h = dm_header("com.android.test", "uuid-1", 16 * 1024);
        c.mem[0x1000..0x1000 + h.len()].copy_from_slice(&h);
        assert_eq!(b.dm_ioctl(dm_cmd(dm::DEV_CREATE), 0x1000, &mut c), Ok(0));
        let devt = le64(&c.mem, 0x1000 + 40);
        assert_eq!((major(devt), minor(devt)), (DM_MAJOR, 0));
        assert_eq!(b.dm_ioctl(dm_cmd(dm::DEV_CREATE), 0x1000, &mut c), Err(EBUSY));

        // DM_TABLE_LOAD: one verity target over 64 sectors of loop2.
        let mut h = dm_header("com.android.test", "", 16 * 1024);
        h[20..24].copy_from_slice(&1u32.to_le_bytes());
        let mut spec = vec![0u8; DM_SPEC];
        spec[8..16].copy_from_slice(&64u64.to_le_bytes());
        put_cstr(&mut spec[24..40], "verity");
        h[DM_IOCTL..DM_IOCTL + DM_SPEC].copy_from_slice(&spec);
        let params = "1 /dev/block/loop2 /dev/block/loop2 4096 4096 8 9 sha256 00 00\0";
        h[DM_IOCTL + DM_SPEC..DM_IOCTL + DM_SPEC + params.len()].copy_from_slice(params.as_bytes());
        c.mem[0x1000..0x1000 + h.len()].copy_from_slice(&h);
        assert_eq!(b.dm_ioctl(dm_cmd(dm::TABLE_LOAD), 0x1000, &mut c), Ok(0));
        assert_ne!(le32(&c.mem, 0x1000 + 28) & DM_INACTIVE_PRESENT_FLAG, 0);
        assert_eq!(b.device(devt).unwrap().len(), 0); // not active until resumed

        // DM_DEV_SUSPEND without DM_SUSPEND_FLAG = resume: the table goes live.
        let h = dm_header("com.android.test", "", 16 * 1024);
        c.mem[0x1000..0x1000 + h.len()].copy_from_slice(&h);
        assert_eq!(b.dm_ioctl(dm_cmd(dm::DEV_SUSPEND), 0x1000, &mut c), Ok(0));
        let flags = le32(&c.mem, 0x1000 + 28);
        assert_ne!(flags & DM_ACTIVE_PRESENT_FLAG, 0);
        assert_eq!(flags & DM_INACTIVE_PRESENT_FLAG, 0);
        let dev = b.device(devt).unwrap();
        assert_eq!(dev.len(), 64 * 512);
        assert_eq!(dev.read_vec(512 * 5, 2).unwrap(), [5, 5]);

        // DM_DEV_STATUS by uuid reports the name; TABLE_STATUS reports "V".
        let h = dm_header("", "uuid-1", 16 * 1024);
        c.mem[0x1000..0x1000 + h.len()].copy_from_slice(&h);
        assert_eq!(b.dm_ioctl(dm_cmd(dm::DEV_STATUS), 0x1000, &mut c), Ok(0));
        assert_eq!(cstr_field(&c.mem[0x1000 + 48..0x1000 + 176]), "com.android.test");
        let h = dm_header("com.android.test", "", 16 * 1024);
        c.mem[0x1000..0x1000 + h.len()].copy_from_slice(&h);
        assert_eq!(b.dm_ioctl(dm_cmd(dm::TABLE_STATUS), 0x1000, &mut c), Ok(0));
        assert_eq!(le32(&c.mem, 0x1000 + 20), 1);
        let spec = 0x1000 + DM_IOCTL;
        assert_eq!(cstr_field(&c.mem[spec + 24..spec + 40]), "verity");
        assert_eq!(cstr_field(&c.mem[spec + DM_SPEC..spec + DM_SPEC + 8]), "V");

        // The mapper links exist, then go away with the device.
        let mapper = mkdir_p(&*b.dev, "block/mapper");
        assert!(b.dev.lookup(mapper, "com.android.test").unwrap().is_some());
        assert_eq!(b.dm_ioctl(dm_cmd(dm::DEV_REMOVE), 0x1000, &mut c), Ok(0));
        assert!(b.dev.lookup(mapper, "com.android.test").unwrap().is_none());
        assert!(b.device(devt).is_none());
    }

    #[test]
    fn dm_rejects_gaps_and_unknown_targets() {
        let (b, mut c) = setup();
        let h = dm_header("x", "", 4096);
        c.mem[0x1000..0x1000 + h.len()].copy_from_slice(&h);
        b.dm_ioctl(dm_cmd(dm::DEV_CREATE), 0x1000, &mut c).unwrap();
        for (start, ty) in [(8u64, "zero"), (0, "crypt")] {
            let mut h = dm_header("x", "", 4096);
            h[20..24].copy_from_slice(&1u32.to_le_bytes());
            h[DM_IOCTL..DM_IOCTL + 8].copy_from_slice(&start.to_le_bytes());
            h[DM_IOCTL + 8..DM_IOCTL + 16].copy_from_slice(&8u64.to_le_bytes());
            put_cstr(&mut h[DM_IOCTL + 24..DM_IOCTL + 40], ty);
            c.mem[0x1000..0x1000 + h.len()].copy_from_slice(&h);
            assert_eq!(b.dm_ioctl(dm_cmd(dm::TABLE_LOAD), 0x1000, &mut c), Err(EINVAL), "{ty} at {start}");
        }
        // Versions: verity is listed, an unknown target is EINVAL.
        let mut h = dm_header("", "", 4096);
        put_cstr(&mut h[DM_IOCTL..DM_IOCTL + 16], "verity");
        c.mem[0x1000..0x1000 + h.len()].copy_from_slice(&h);
        assert_eq!(b.dm_ioctl(dm_cmd(dm::GET_TARGET_VERSION), 0x1000, &mut c), Ok(0));
        assert_eq!(le32(&c.mem, 0x1000 + DM_IOCTL + 4), 1);
    }
}

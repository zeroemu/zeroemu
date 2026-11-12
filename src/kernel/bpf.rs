//! bpf(2) without an eBPF machine. Maps are real tables that userspace reads
//! and writes (array, hash, LRU, per-CPU, LPM-trie and map-of-maps kinds);
//! programs are accepted and kept but never run, so socket filters, cgroup
//! hooks and tracepoints do not fire; both can be pinned in bpffs and looked
//! up by id. That is what Android's netbpfload and netd need to boot.

use super::files::{File, Kind};
use super::{Kernel, Thread};
use crate::errno::*;
use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, LazyLock, Mutex, Weak};

const MAP_CREATE: u64 = 0;
const MAP_LOOKUP_ELEM: u64 = 1;
const MAP_UPDATE_ELEM: u64 = 2;
const MAP_DELETE_ELEM: u64 = 3;
const MAP_GET_NEXT_KEY: u64 = 4;
const PROG_LOAD: u64 = 5;
const OBJ_PIN: u64 = 6;
const OBJ_GET: u64 = 7;
const PROG_ATTACH: u64 = 8;
const PROG_DETACH: u64 = 9;
const PROG_GET_NEXT_ID: u64 = 11;
const MAP_GET_NEXT_ID: u64 = 12;
const PROG_GET_FD_BY_ID: u64 = 13;
const MAP_GET_FD_BY_ID: u64 = 14;
const OBJ_GET_INFO_BY_FD: u64 = 15;
const PROG_QUERY: u64 = 16;
const MAP_LOOKUP_AND_DELETE_ELEM: u64 = 21;
const MAP_FREEZE: u64 = 22;
const BTF_LOAD: u64 = 18;
const BTF_GET_FD_BY_ID: u64 = 19;
const BTF_GET_NEXT_ID: u64 = 23;

const ARRAY: u32 = 2;
const PROG_ARRAY: u32 = 3;
const PERCPU_HASH: u32 = 5;
const PERCPU_ARRAY: u32 = 6;
const CGROUP_ARRAY: u32 = 8;
const LRU_HASH: u32 = 9;
const LRU_PERCPU_HASH: u32 = 10;
const LPM_TRIE: u32 = 11;
const ARRAY_OF_MAPS: u32 = 12;
const DEVMAP: u32 = 14;
const DEVMAP_HASH: u32 = 25;
const CPUMAP: u32 = 16;
const XSKMAP: u32 = 17;
const PERCPU_CGROUP_STORAGE: u32 = 21;
const RINGBUF: u32 = 27;

const BPF_NOEXIST: u64 = 1;
const BPF_EXIST: u64 = 2;
const BPF_F_RDONLY_PROG: u32 = 128;
/// bpf_attr is 144 bytes in Linux 6.6; larger structs must be zero past that.
const ATTR: usize = 144;
const MAX_INSNS: u64 = 1 << 20;

pub struct BpfObj {
    pub id: u32,
    kind: Obj,
}

enum Obj {
    Map(Map),
    Prog(Prog),
    /// Type information (libbpf loads it before the maps that refer to it).
    Btf(Vec<u8>),
}

struct Map {
    ty: u32,
    key_size: u32,
    /// What userspace passes per element (per-CPU maps: one 8-aligned slot per CPU).
    value_size: u32,
    raw_value_size: u32,
    max: u32,
    flags: u32,
    name: [u8; 16],
    data: Mutex<BTreeMap<Vec<u8>, Vec<u8>>>,
}

struct Prog {
    ty: u32,
    name: [u8; 16],
    insns: Vec<u8>,
    uid: u32,
}

#[derive(Default)]
struct Registry {
    maps: BTreeMap<u32, Weak<BpfObj>>,
    progs: BTreeMap<u32, Weak<BpfObj>>,
    btfs: BTreeMap<u32, Weak<BpfObj>>,
    /// Pinned objects, by bpffs node (filesystem, inode): pinning keeps them alive.
    pins: HashMap<(usize, u64), Arc<BpfObj>>,
    /// Programs attached to a cgroup (by path) for an attach type, with
    /// their attach flags. Attaching keeps a program alive.
    attached: HashMap<(String, u32), Vec<Attached>>,
}

/// An attached program and its attach flags.
type Attached = (Arc<BpfObj>, u32);

/// BPF_F_ALLOW_MULTI: more than one program per cgroup and attach type.
const ALLOW_MULTI: u32 = 2;

static REG: LazyLock<Mutex<Registry>> = LazyLock::new(Mutex::default);
static NEXT_ID: AtomicU32 = AtomicU32::new(1);

fn ncpus() -> u32 {
    std::thread::available_parallelism().map_or(1, |n| n.get()).min(64) as u32
}

fn is_array(ty: u32) -> bool {
    matches!(ty, ARRAY | PROG_ARRAY | PERCPU_ARRAY | CGROUP_ARRAY | ARRAY_OF_MAPS | DEVMAP | CPUMAP | XSKMAP)
}

fn u32_at(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes(b[o..o + 4].try_into().unwrap())
}

fn u64_at(b: &[u8], o: usize) -> u64 {
    u64::from_le_bytes(b[o..o + 8].try_into().unwrap())
}

impl Map {
    fn index(&self, key: &[u8]) -> Option<u32> {
        is_array(self.ty).then(|| u32_at(key, 0))
    }

    fn lookup(&self, key: &[u8]) -> Result<Vec<u8>, i64> {
        let data = self.data.lock().unwrap();
        if let Some(i) = self.index(key) {
            if i >= self.max {
                return Err(ENOENT);
            }
            return Ok(data.get(key).cloned().unwrap_or_else(|| vec![0; self.value_size as usize]));
        }
        if self.ty == LPM_TRIE {
            return lpm_match(&data, key).ok_or(ENOENT);
        }
        data.get(key).cloned().ok_or(ENOENT)
    }

    fn update(&self, key: &[u8], value: &[u8], flags: u64) -> Result<(), i64> {
        if flags & 3 == 3 {
            return Err(EINVAL);
        }
        let mut data = self.data.lock().unwrap();
        if let Some(i) = self.index(key) {
            if i >= self.max {
                return Err(E2BIG);
            }
            if flags & 3 == BPF_NOEXIST {
                return Err(EEXIST); // array elements always exist
            }
        } else {
            let exists = data.contains_key(key);
            match flags & 3 {
                BPF_NOEXIST if exists => return Err(EEXIST),
                BPF_EXIST if !exists => return Err(ENOENT),
                _ => {}
            }
            if !exists && data.len() >= self.max as usize {
                if !matches!(self.ty, LRU_HASH | LRU_PERCPU_HASH) {
                    return Err(E2BIG);
                }
                let victim = data.keys().next().cloned().unwrap();
                data.remove(&victim);
            }
        }
        data.insert(key.to_vec(), value.to_vec());
        Ok(())
    }

    fn delete(&self, key: &[u8]) -> Result<(), i64> {
        if self.index(key).is_some() {
            return Err(EINVAL);
        }
        self.data.lock().unwrap().remove(key).map(|_| ()).ok_or(ENOENT)
    }

    fn next_key(&self, key: Option<&[u8]>) -> Result<Vec<u8>, i64> {
        if is_array(self.ty) {
            let next = match key.map(|k| u32_at(k, 0)) {
                Some(i) if i < self.max => i + 1,
                _ => 0,
            };
            return if next < self.max { Ok(next.to_le_bytes().to_vec()) } else { Err(ENOENT) };
        }
        let data = self.data.lock().unwrap();
        let next = match key.filter(|k| data.contains_key(*k)) {
            Some(k) => data.range::<[u8], _>((std::ops::Bound::Excluded(k), std::ops::Bound::Unbounded)).next(),
            None => data.iter().next(),
        };
        next.map(|(k, _)| k.clone()).ok_or(ENOENT)
    }
}

/// An LPM-trie lookup: the stored key with the longest prefix covering the
/// query (keys are a u32 prefix length followed by the data).
fn lpm_match(data: &BTreeMap<Vec<u8>, Vec<u8>>, key: &[u8]) -> Option<Vec<u8>> {
    let want = u32_at(key, 0) as usize;
    let bit = |b: &[u8], i: usize| b[4 + i / 8] >> (7 - i % 8) & 1;
    data.iter()
        .filter(|(k, _)| {
            let len = u32_at(k, 0) as usize;
            len <= want && len <= (k.len() - 4) * 8 && (0..len).all(|i| bit(k, i) == bit(key, i))
        })
        .max_by_key(|(k, _)| u32_at(k, 0))
        .map(|(_, v)| v.clone())
}

fn register(kind: Obj) -> Arc<BpfObj> {
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    let obj = Arc::new(BpfObj { id, kind });
    let mut reg = REG.lock().unwrap();
    let table = match obj.kind {
        Obj::Map(_) => &mut reg.maps,
        Obj::Prog(_) => &mut reg.progs,
        Obj::Btf(_) => &mut reg.btfs,
    };
    table.retain(|_, w| w.strong_count() > 0);
    table.insert(id, Arc::downgrade(&obj));
    obj
}

impl BpfObj {
    fn map(&self) -> Result<&Map, i64> {
        match &self.kind {
            Obj::Map(m) => Ok(m),
            _ => Err(EINVAL),
        }
    }
}

impl Kernel {
    fn bpf_fd(&self, t: &Thread, obj: Arc<BpfObj>) -> Result<i64, i64> {
        t.files().alloc(File::new(Kind::Bpf(obj), 0), true, 0)
    }

    /// What a program attaches to: a cgroup directory, by its path.
    fn attach_target(&self, t: &Thread, fd: u32) -> Result<String, i64> {
        let file = t.files().get(fd as i64)?;
        file.node_path().ok_or(EINVAL)
    }

    fn bpf_obj(&self, t: &Thread, fd: u32) -> Result<Arc<BpfObj>, i64> {
        match &t.files().get(fd as i64)?.kind {
            Kind::Bpf(o) => Ok(o.clone()),
            _ => Err(EINVAL),
        }
    }

    /// The path in a pin or get request (bpf_attr.pathname).
    fn bpf_path(&self, t: &Thread, attr: &[u8]) -> Result<String, i64> {
        let path = t.proc.mm().read_cstr(u64_at(attr, 0))?;
        if path.is_empty() {
            return Err(ENOENT);
        }
        Ok(path)
    }

    pub(super) fn sys_bpf(&self, t: &Arc<Thread>, cmd: u64, uattr: u64, size: u64) -> Result<i64, i64> {
        let size = (size as usize).min(4096);
        let mut attr = t.proc.mm().read_vec(uattr, size)?;
        if attr[ATTR.min(size)..].iter().any(|&b| b != 0) {
            return Err(E2BIG);
        }
        attr.resize(ATTR, 0);
        let mm = || t.proc.mm();
        match cmd {
            MAP_CREATE => {
                let (ty, key_size, value_size, max, flags) = (u32_at(&attr, 0), u32_at(&attr, 4), u32_at(&attr, 8), u32_at(&attr, 12), u32_at(&attr, 16));
                // Local storage (cgroup, socket, inode, task) has no max_entries; a ring buffer only a size.
                let storage = matches!(ty, 19 | 21 | 24 | 28 | 29 | 32);
                if ty == 0 || (ty != RINGBUF && (key_size == 0 || value_size == 0 || (max == 0) != storage)) || (is_array(ty) && key_size != 4) || key_size > 512 || value_size > 1 << 20 {
                    return Err(EINVAL);
                }
                // dev_map_alloc_check: programs may only read device maps.
                let flags = if matches!(ty, DEVMAP | DEVMAP_HASH) { flags | BPF_F_RDONLY_PROG } else { flags };
                let percpu = matches!(ty, PERCPU_HASH | PERCPU_ARRAY | LRU_PERCPU_HASH | PERCPU_CGROUP_STORAGE);
                let user_value = if percpu { value_size.div_ceil(8) * 8 * ncpus() } else { value_size };
                let mut name = [0u8; 16];
                name.copy_from_slice(&attr[28..44]);
                let obj = register(Obj::Map(Map { ty, key_size, value_size: user_value, raw_value_size: value_size, max, flags, name, data: Mutex::default() }));
                self.bpf_fd(t, obj)
            }
            MAP_LOOKUP_ELEM | MAP_UPDATE_ELEM | MAP_DELETE_ELEM | MAP_GET_NEXT_KEY | MAP_LOOKUP_AND_DELETE_ELEM => {
                let obj = self.bpf_obj(t, u32_at(&attr, 0))?;
                let m = obj.map()?;
                let (kp, vp, flags) = (u64_at(&attr, 8), u64_at(&attr, 16), u64_at(&attr, 24));
                let key = if kp == 0 { None } else { Some(mm().read_vec(kp, m.key_size as usize)?) };
                match cmd {
                    MAP_LOOKUP_ELEM => {
                        let v = m.lookup(key.as_deref().ok_or(EFAULT)?)?;
                        mm().write(vp, &v)?;
                    }
                    MAP_LOOKUP_AND_DELETE_ELEM => {
                        let k = key.ok_or(EFAULT)?;
                        let v = m.lookup(&k)?;
                        m.delete(&k)?;
                        mm().write(vp, &v)?;
                    }
                    MAP_UPDATE_ELEM => {
                        let v = mm().read_vec(vp, m.value_size as usize)?;
                        m.update(key.as_deref().ok_or(EFAULT)?, &v, flags)?;
                    }
                    MAP_DELETE_ELEM => m.delete(key.as_deref().ok_or(EFAULT)?)?,
                    _ => {
                        let next = m.next_key(key.as_deref())?;
                        mm().write(vp, &next)?;
                    }
                }
                Ok(0)
            }
            PROG_LOAD => {
                let (ty, cnt, insns) = (u32_at(&attr, 0), u32_at(&attr, 4) as u64, u64_at(&attr, 8));
                if cnt == 0 || cnt > MAX_INSNS {
                    return Err(if cnt == 0 { EINVAL } else { E2BIG });
                }
                let insns = mm().read_vec(insns, (cnt * 8) as usize)?;
                let (log_size, log_buf) = (u32_at(&attr, 28), u64_at(&attr, 32));
                if u32_at(&attr, 24) != 0 && log_size > 0 && log_buf != 0 {
                    mm().write(log_buf, &[0])?;
                }
                let mut name = [0u8; 16];
                name.copy_from_slice(&attr[48..64]);
                let uid = self.creds(t).euid;
                let obj = register(Obj::Prog(Prog { ty, name, insns, uid }));
                self.bpf_fd(t, obj)
            }
            OBJ_PIN => {
                let obj = self.bpf_obj(t, u32_at(&attr, 8))?;
                let path = self.bpf_path(t, &attr)?;
                let vfs = self.vfs.as_deref().ok_or(ENOENT)?;
                let cwd = t.proc.cwd.lock().unwrap().clone();
                let (dir, name) = vfs.resolve_parent(&cwd, &path)?;
                if vfs.fs_type(&dir) != "bpf" {
                    return Err(EPERM);
                }
                let node = vfs.create(&dir, &name, 0o100600, 0)?;
                REG.lock().unwrap().pins.insert((Arc::as_ptr(&vfs.fs_arc(&node)) as *const () as usize, node.ino), obj);
                Ok(0)
            }
            OBJ_GET => {
                let path = self.bpf_path(t, &attr)?;
                let vfs = self.vfs.as_deref().ok_or(ENOENT)?;
                let cwd = t.proc.cwd.lock().unwrap().clone();
                let node = vfs.resolve(&cwd, &path, true)?;
                let key = (Arc::as_ptr(&vfs.fs_arc(&node)) as *const () as usize, node.ino);
                let obj = REG.lock().unwrap().pins.get(&key).cloned().ok_or(if vfs.fs_type(&node) == "bpf" { EINVAL } else { EPERM })?;
                self.bpf_fd(t, obj)
            }
            PROG_ATTACH => {
                let target = self.attach_target(t, u32_at(&attr, 0))?;
                let prog = self.bpf_obj(t, u32_at(&attr, 4))?;
                if !matches!(prog.kind, Obj::Prog(_)) {
                    return Err(EINVAL);
                }
                let (ty, flags) = (u32_at(&attr, 8), u32_at(&attr, 12));
                let mut reg = REG.lock().unwrap();
                let list = reg.attached.entry((target, ty)).or_default();
                if flags & ALLOW_MULTI == 0 {
                    list.clear(); // one program per type: attaching replaces it
                } else if list.iter().any(|(p, _)| p.id == prog.id) {
                    return Err(EEXIST);
                }
                list.push((prog, flags));
                Ok(0)
            }
            PROG_DETACH => {
                let target = self.attach_target(t, u32_at(&attr, 0))?;
                let ty = u32_at(&attr, 8);
                // A program fd picks one of several; none detaches them all.
                let prog = self.bpf_obj(t, u32_at(&attr, 4)).ok().map(|p| p.id);
                let mut reg = REG.lock().unwrap();
                let list = reg.attached.get_mut(&(target, ty)).ok_or(ENOENT)?;
                let before = list.len();
                list.retain(|(p, _)| prog.is_some_and(|id| id != p.id));
                if list.len() == before {
                    return Err(ENOENT);
                }
                Ok(0)
            }
            PROG_QUERY => {
                let target = self.attach_target(t, u32_at(&attr, 0))?;
                let ty = u32_at(&attr, 4);
                let (ids, flags): (Vec<u32>, u32) = match REG.lock().unwrap().attached.get(&(target, ty)) {
                    Some(list) => (list.iter().map(|(p, _)| p.id).collect(), list.first().map_or(0, |(_, f)| *f)),
                    None => (Vec::new(), 0),
                };
                let (ptr, room) = (u64_at(&attr, 16), u32_at(&attr, 24) as usize);
                mm().write(uattr + 12, &flags.to_le_bytes())?; // attach_flags
                mm().write(uattr + 24, &(ids.len() as u32).to_le_bytes())?; // prog_cnt
                if ptr != 0 && room > 0 {
                    let bytes: Vec<u8> = ids.iter().take(room).flat_map(|id| id.to_le_bytes()).collect();
                    mm().write(ptr, &bytes)?;
                    if room < ids.len() {
                        return Err(ENOSPC);
                    }
                }
                Ok(0)
            }
            BTF_LOAD => {
                let (data, size) = (u64_at(&attr, 0), u32_at(&attr, 16) as usize);
                if !(24..=16 << 20).contains(&size) {
                    return Err(EINVAL);
                }
                let blob = mm().read_vec(data, size)?;
                if blob[..2] != [0x9f, 0xeb] {
                    return Err(EINVAL); // BTF_MAGIC
                }
                self.bpf_fd(t, register(Obj::Btf(blob)))
            }
            PROG_GET_NEXT_ID | MAP_GET_NEXT_ID | BTF_GET_NEXT_ID => {
                let start = u32_at(&attr, 0);
                let reg = REG.lock().unwrap();
                let table = match cmd {
                    MAP_GET_NEXT_ID => &reg.maps,
                    PROG_GET_NEXT_ID => &reg.progs,
                    _ => &reg.btfs,
                };
                let next = table.range(start + 1..).find(|(_, w)| w.strong_count() > 0).map(|(&id, _)| id).ok_or(ENOENT)?;
                drop(reg);
                mm().write(uattr + 4, &next.to_le_bytes())?;
                Ok(0)
            }
            PROG_GET_FD_BY_ID | MAP_GET_FD_BY_ID | BTF_GET_FD_BY_ID => {
                let id = u32_at(&attr, 0);
                let reg = REG.lock().unwrap();
                let table = match cmd {
                    MAP_GET_FD_BY_ID => &reg.maps,
                    PROG_GET_FD_BY_ID => &reg.progs,
                    _ => &reg.btfs,
                };
                let obj = table.get(&id).and_then(Weak::upgrade).ok_or(ENOENT)?;
                drop(reg);
                self.bpf_fd(t, obj)
            }
            OBJ_GET_INFO_BY_FD => {
                let obj = self.bpf_obj(t, u32_at(&attr, 0))?;
                let (len, info) = (u32_at(&attr, 4) as usize, u64_at(&attr, 8));
                let mut out = vec![0u8; 232];
                let put = |b: &mut Vec<u8>, o: usize, v: u32| b[o..o + 4].copy_from_slice(&v.to_le_bytes());
                let n = match &obj.kind {
                    Obj::Map(m) => {
                        for (o, v) in [(0, m.ty), (4, obj.id), (8, m.key_size), (12, m.raw_value_size), (16, m.max), (20, m.flags)] {
                            put(&mut out, o, v);
                        }
                        out[24..40].copy_from_slice(&m.name);
                        88
                    }
                    Obj::Prog(p) => {
                        put(&mut out, 0, p.ty);
                        put(&mut out, 4, obj.id);
                        out[8..16].copy_from_slice(&p.insns.iter().fold(0u64, |h, &b| h.rotate_left(5) ^ b as u64).to_le_bytes());
                        // Android requires a JIT; report the code as if compiled one-to-one.
                        put(&mut out, 16, p.insns.len() as u32);
                        put(&mut out, 20, p.insns.len() as u32);
                        put(&mut out, 48, p.uid);
                        out[64..80].copy_from_slice(&p.name);
                        put(&mut out, 84, 1); // gpl_compatible
                        232
                    }
                    // bpf_btf_info: btf (copied out if room), btf_size, id.
                    Obj::Btf(b) => {
                        let mut req = mm().read_vec(info, len.min(32))?;
                        req.resize(32, 0);
                        let (ptr, room) = (u64_at(&req, 0), u32_at(&req, 8) as usize);
                        if ptr != 0 && room >= b.len() {
                            mm().write(ptr, b)?;
                        }
                        out[0..8].copy_from_slice(&ptr.to_le_bytes());
                        put(&mut out, 8, b.len() as u32);
                        put(&mut out, 12, obj.id);
                        32
                    }
                };
                let n = n.min(len);
                mm().write(info, &out[..n])?;
                mm().write(uattr + 4, &(n as u32).to_le_bytes())?;
                Ok(0)
            }
            MAP_FREEZE => {
                self.bpf_obj(t, u32_at(&attr, 0))?.map()?;
                Ok(0)
            }
            // BPF_TOKEN_CREATE (Linux 6.9): libbpf probes for it.
            36 => Err(EINVAL),
            _ => {
                if super::verbose() {
                    eprintln!("[zeroemu] unimplemented bpf command {cmd}");
                }
                Err(EINVAL)
            }
        }
    }
}

/// /proc/<pid>/fd's name for an open bpf object.
pub fn file_name(o: &BpfObj) -> &'static str {
    match o.kind {
        Obj::Map(_) => "anon_inode:bpf-map",
        Obj::Prog(_) => "anon_inode:bpf-prog",
        Obj::Btf(_) => "anon_inode:btf",
    }
}

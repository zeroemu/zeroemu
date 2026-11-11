//! /dev/ashmem: Android's named shared memory. libcutils opens
//! /dev/ashmem<boot id>, names and sizes a region with ioctls, then maps it;
//! the fd travels over binder and every mapping shares the same pages. The
//! memory is a memfd's, created at the first mmap (the size is fixed then).

use super::block::{MISC_MAJOR, makedev};
use crate::errno::*;
use crate::mm::Backing;
use crate::phys::PhysMem;
use crate::tmpfs::MemFile;
use std::sync::{Arc, Mutex};

pub const ASHMEM_MINOR: u32 = 61;

pub fn rdev() -> u64 {
    makedev(MISC_MAJOR, ASHMEM_MINOR)
}

const ASHMEM_SET_NAME: u64 = 0x4100_7701;
const ASHMEM_GET_NAME: u64 = 0x8100_7702;
const ASHMEM_SET_SIZE: u64 = 0x4008_7703;
const ASHMEM_GET_SIZE: u64 = 0x7704;
const ASHMEM_SET_PROT_MASK: u64 = 0x4008_7705;
const ASHMEM_GET_PROT_MASK: u64 = 0x7706;
const ASHMEM_PIN: u64 = 0x4008_7707;
const ASHMEM_UNPIN: u64 = 0x4008_7708;
const ASHMEM_GET_PIN_STATUS: u64 = 0x7709;
const ASHMEM_PURGE_ALL_CACHES: u64 = 0x770a;
const ASHMEM_GET_FILE_ID: u64 = 0x8008_770b;
const NAME_LEN: usize = 256;
/// PROT_READ | PROT_WRITE | PROT_EXEC.
const PROT_ALL: u32 = 7;

pub struct Ashmem {
    st: Mutex<State>,
}

struct State {
    name: String,
    size: u64,
    prot_mask: u32,
    /// The pages, once mapped.
    file: Option<Arc<MemFile>>,
}

/// What an ioctl needs from the caller's memory.
pub trait Io {
    fn read(&mut self, addr: u64, buf: &mut [u8]) -> Result<(), i64>;
    fn write(&mut self, addr: u64, data: &[u8]) -> Result<(), i64>;
}

impl Ashmem {
    pub fn new() -> Ashmem {
        Ashmem { st: Mutex::new(State { name: String::new(), size: 0, prot_mask: PROT_ALL, file: None }) }
    }

    pub fn size(&self) -> u64 {
        self.st.lock().unwrap().size
    }

    /// As /proc/<pid>/maps names a mapping of it.
    pub fn map_name(&self) -> String {
        let st = self.st.lock().unwrap();
        format!("/dev/ashmem/{} (deleted)", if st.name.is_empty() { "dev/ashmem" } else { &st.name })
    }

    pub fn ioctl(&self, cmd: u64, arg: u64, io: &mut dyn Io) -> Result<i64, i64> {
        let mut st = self.st.lock().unwrap();
        match cmd {
            ASHMEM_SET_NAME => {
                if st.file.is_some() {
                    return Err(EINVAL); // fixed once mapped
                }
                let mut raw = [0u8; NAME_LEN];
                io.read(arg, &mut raw)?;
                let end = raw.iter().position(|&b| b == 0).unwrap_or(NAME_LEN - 1);
                st.name = String::from_utf8_lossy(&raw[..end]).into_owned();
                Ok(0)
            }
            ASHMEM_GET_NAME => {
                let mut raw = [0u8; NAME_LEN];
                let name = if st.name.is_empty() { "dev/ashmem" } else { &st.name };
                raw[..name.len().min(NAME_LEN - 1)].copy_from_slice(&name.as_bytes()[..name.len().min(NAME_LEN - 1)]);
                io.write(arg, &raw)?;
                Ok(0)
            }
            ASHMEM_SET_SIZE => {
                if st.file.is_some() {
                    return Err(EINVAL);
                }
                st.size = arg; // the argument itself, not a pointer
                Ok(0)
            }
            ASHMEM_GET_SIZE => Ok(st.size as i64),
            ASHMEM_SET_PROT_MASK => {
                let want = arg as u32;
                if want & !st.prot_mask != 0 {
                    return Err(EINVAL); // bits can only be taken away
                }
                st.prot_mask = want;
                Ok(0)
            }
            ASHMEM_GET_PROT_MASK => Ok(st.prot_mask as i64),
            // Nothing is ever purged: unpinned ranges keep their contents.
            ASHMEM_PIN | ASHMEM_UNPIN => Ok(0),
            ASHMEM_GET_PIN_STATUS => Ok(1), // ASHMEM_IS_PINNED
            ASHMEM_PURGE_ALL_CACHES => Ok(0),
            ASHMEM_GET_FILE_ID => {
                let id = self as *const Ashmem as u64;
                io.write(arg, &id.to_le_bytes())?;
                Ok(0)
            }
            _ => Err(ENOTTY),
        }
    }

    /// mmap: the region's pages, shared (or a private copy). The size must
    /// be set and cover the mapping, and `prot` stay within the mask.
    /// ASHMEM_GET_PROT_MASK: what mappings made from now on may have.
    pub fn prot_mask(&self) -> u32 {
        self.st.lock().unwrap().prot_mask
    }

    pub fn mmap(&self, phys: &Arc<PhysMem>, offset: u64, len: u64, prot: u32, shared: bool) -> Result<Backing, i64> {
        let mut st = self.st.lock().unwrap();
        if st.size == 0 {
            return Err(EINVAL);
        }
        if offset.checked_add(len).is_none_or(|end| end > st.size.next_multiple_of(4096)) {
            return Err(EINVAL);
        }
        if prot & PROT_ALL & !st.prot_mask != 0 {
            return Err(EPERM);
        }
        let size = st.size;
        let file = st.file.get_or_insert_with(|| {
            let f = MemFile::new(phys.clone());
            // It holds its pages in memory, so nothing about this can fail, short of
            // a size no ashmem region can have, and those were refused when it was set.
            let _ = f.truncate(size);
            f
        });
        Ok(if shared {
            Backing::Shared { obj: file.obj.clone(), offset }
        } else {
            Backing::File { src: file.obj.clone(), offset }
        })
    }
}

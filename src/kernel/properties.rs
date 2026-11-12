//! Android system properties, served the way init serves them: one shared
//! `prop_area` (bionic's format: a trie of `prop_bt` nodes and `prop_info`
//! records) in /dev/__properties__, mapped read-only by every process, plus a
//! property service on /dev/socket/property_service that updates it.
//!
//! Writes follow bionic's protocol so readers never need a lock: new nodes
//! are linked only after they are written, and value updates go through the
//! serial's dirty bit with a backup copy of the old value.

use super::futex::{Futexes, SHARED};
use crate::phys::{PAGE, PhysMem};
use crate::tmpfs::MemFile;
use crate::vfs::Vfs;
use std::collections::HashMap;
use std::sync::atomic::{Ordering, fence};
use std::sync::{Arc, Mutex};

const AREA_SIZE: u64 = 1 << 20;
const HEADER: u64 = 128;
const MAGIC: u32 = 0x504f_5250;
const VERSION: u32 = 0xfc6e_d0ab;
const PROP_VALUE_MAX: usize = 92;
/// sizeof(prop_bt): namelen, prop, left, right, children.
const BT: u32 = 20;
/// sizeof(prop_info) without the name: serial + value.
const INFO: u32 = 4 + PROP_VALUE_MAX as u32;
const LONG_FLAG: u32 = 1 << 16;
const LONG_ERROR: &[u8] = b"Must use __system_property_read_callback() to read\0";

pub const PROP_SUCCESS: u32 = 0;
pub const PROP_ERROR_READ_ONLY: u32 = 0x0b;
pub const PROP_ERROR_INVALID_NAME: u32 = 0x10;
pub const PROP_ERROR_INVALID_VALUE: u32 = 0x14;

fn align4(v: u32) -> u32 {
    (v + 3) & !3
}

pub struct Properties {
    pub file: Arc<MemFile>,
    /// name → offset (within data) of its prop_info. Writers are serialised here.
    index: Mutex<HashMap<String, u32>>,
}

impl Properties {
    pub fn new(phys: Arc<PhysMem>) -> Arc<Properties> {
        let file = MemFile::new(phys);
        file.truncate(AREA_SIZE).expect("property area");
        let p = Properties { file, index: Mutex::new(HashMap::new()) };
        // Root node, then a PROP_VALUE_MAX "dirty backup area".
        p.w32(0, BT + align4(PROP_VALUE_MAX as u32)); // bytes_used_
        p.w32(4, 0); // serial_
        p.w32(8, MAGIC);
        p.w32(12, VERSION);
        Arc::new(p)
    }

    // Raw accessors, by offset in the file (the header occupies the first 128 bytes).
    fn r32(&self, off: u64) -> u32 {
        let mut b = [0u8; 4];
        self.file.obj.read(off, &mut b);
        u32::from_le_bytes(b)
    }
    fn w32(&self, off: u64, v: u32) {
        self.file.obj.write(off, &v.to_le_bytes()).expect("property area");
    }
    fn wbytes(&self, off: u64, b: &[u8]) {
        self.file.obj.write(off, b).expect("property area");
    }
    fn data(off: u32) -> u64 {
        HEADER + off as u64
    }

    fn alloc(&self, size: u32) -> Option<u32> {
        let used = self.r32(0);
        let aligned = align4(size);
        if used as u64 + aligned as u64 > AREA_SIZE - HEADER {
            return None;
        }
        self.w32(0, used + aligned);
        Some(used)
    }

    fn new_bt(&self, name: &[u8]) -> Option<u32> {
        let off = self.alloc(BT + name.len() as u32 + 1)?;
        self.w32(Self::data(off), name.len() as u32);
        self.wbytes(Self::data(off + BT), name);
        Some(off)
    }

    fn bt_name(&self, off: u32) -> Vec<u8> {
        let len = self.r32(Self::data(off)) as usize;
        let mut b = vec![0u8; len];
        self.file.obj.read(Self::data(off + BT), &mut b);
        b
    }

    /// bionic's cmp_prop_name: shorter names sort first, then bytes.
    fn cmp(a: &[u8], b: &[u8]) -> std::cmp::Ordering {
        a.len().cmp(&b.len()).then_with(|| a.cmp(b))
    }

    /// Links a freshly written node at `slot` (offset of a link field).
    fn link(&self, slot: u64, target: u32) {
        fence(Ordering::Release);
        self.w32(slot, target);
    }

    fn find_bt(&self, mut cur: u32, name: &[u8], alloc: bool) -> Option<u32> {
        loop {
            match Self::cmp(name, &self.bt_name(cur)) {
                std::cmp::Ordering::Equal => return Some(cur),
                ord => {
                    let slot = Self::data(cur) + if ord == std::cmp::Ordering::Less { 8 } else { 12 };
                    match self.r32(slot) {
                        0 if alloc => {
                            let n = self.new_bt(name)?;
                            self.link(slot, n);
                            return Some(n);
                        }
                        0 => return None,
                        next => cur = next,
                    }
                }
            }
        }
    }

    /// bionic's find_property: one trie level per dot-separated component.
    fn find(&self, name: &str, value: &[u8], alloc: bool) -> Option<u32> {
        let mut cur = 0u32; // the root node
        for part in name.split('.') {
            if part.is_empty() {
                return None;
            }
            let children = Self::data(cur) + 16;
            let root = match self.r32(children) {
                0 if alloc => {
                    let n = self.new_bt(part.as_bytes())?;
                    self.link(children, n);
                    n
                }
                0 => return None,
                r => r,
            };
            cur = self.find_bt(root, part.as_bytes(), alloc)?;
        }
        let slot = Self::data(cur) + 4;
        match self.r32(slot) {
            0 if alloc => {
                let info = self.new_info(name.as_bytes(), value)?;
                self.link(slot, info);
                Some(info)
            }
            0 => None,
            off => Some(off),
        }
    }

    fn new_info(&self, name: &[u8], value: &[u8]) -> Option<u32> {
        if value.len() >= PROP_VALUE_MAX {
            // A long (read-only) value lives after its record, which points to
            // it with a (positive) offset relative to itself — bionic's order.
            let info = self.alloc(INFO + name.len() as u32 + 1)?;
            let long = self.alloc(value.len() as u32 + 1)?;
            self.wbytes(Self::data(long), value);
            self.w32(Self::data(info), ((LONG_ERROR.len() as u32 - 1) << 24) | LONG_FLAG);
            self.wbytes(Self::data(info + 4), LONG_ERROR);
            self.w32(Self::data(info + 4 + 56), long.wrapping_sub(info));
            self.wbytes(Self::data(info + INFO), name);
            return Some(info);
        }
        let info = self.alloc(INFO + name.len() as u32 + 1)?;
        self.w32(Self::data(info), (value.len() as u32) << 24);
        self.wbytes(Self::data(info + 4), value);
        self.wbytes(Self::data(info + INFO), name);
        Some(info)
    }

    fn wake(&self, futex: &Futexes, off: u64) {
        if let Ok(frame) = self.file.obj.frame((off / PAGE) as usize) {
            futex.wake((SHARED, frame + off % PAGE), u32::MAX, u32::MAX);
        }
    }

    /// Sets a property, as init's property service does.
    pub fn set(&self, futex: Option<&Futexes>, name: &str, value: &str) -> u32 {
        let valid_name = !name.is_empty()
            && !name.starts_with('.')
            && !name.ends_with('.')
            && !name.contains("..")
            && name.bytes().all(|c| c.is_ascii_alphanumeric() || b"._-@:".contains(&c));
        if !valid_name {
            return PROP_ERROR_INVALID_NAME;
        }
        let ro = name.starts_with("ro.");
        if value.len() >= PROP_VALUE_MAX && !ro {
            return PROP_ERROR_INVALID_VALUE;
        }
        let mut index = self.index.lock().unwrap();
        match index.get(name) {
            Some(_) if ro => return PROP_ERROR_READ_ONLY,
            Some(&info) => {
                // In-place update, as bionic's SystemProperties::Update: back up
                // the old value, then mark dirty, write, and publish.
                let serial_off = Self::data(info);
                let mut old = vec![0u8; PROP_VALUE_MAX];
                self.file.obj.read(Self::data(info + 4), &mut old);
                self.wbytes(Self::data(BT), &old); // dirty backup area
                fence(Ordering::SeqCst);
                let serial = self.r32(serial_off) | 1;
                self.w32(serial_off, serial);
                let mut v = value.as_bytes().to_vec();
                v.resize(PROP_VALUE_MAX, 0);
                self.wbytes(Self::data(info + 4), &v);
                fence(Ordering::SeqCst);
                self.w32(serial_off, ((value.len() as u32) << 24) | ((serial + 1) & 0xff_ffff));
                if let Some(f) = futex {
                    self.wake(f, serial_off);
                }
            }
            None => match self.find(name, value.as_bytes(), true) {
                Some(info) => {
                    index.insert(name.to_string(), info);
                }
                None => return PROP_ERROR_INVALID_VALUE, // the area is full
            },
        }
        // Bump the area serial so __system_property_wait(nullptr) wakes up.
        fence(Ordering::SeqCst);
        self.w32(4, self.r32(4).wrapping_add(1));
        if let Some(f) = futex {
            self.wake(f, 4);
        }
        PROP_SUCCESS
    }

    /// A property's value, as readers would see it.
    pub fn get(&self, name: &str) -> Option<String> {
        let info = *self.index.lock().unwrap().get(name)?;
        let serial = self.r32(Self::data(info));
        let bytes = if serial & LONG_FLAG != 0 {
            let rel = self.r32(Self::data(info + 4 + 56));
            let mut v = Vec::new();
            let mut at = Self::data(info.wrapping_add(rel));
            loop {
                let mut b = [0u8; 1];
                self.file.obj.read(at, &mut b);
                if b[0] == 0 || v.len() > 4096 {
                    break;
                }
                v.push(b[0]);
                at += 1;
            }
            v
        } else {
            let mut v = vec![0u8; (serial >> 24) as usize];
            self.file.obj.read(Self::data(info + 4), &mut v);
            v
        };
        Some(String::from_utf8_lossy(&bytes).into_owned())
    }

    /// Loads build.prop files the way init does at boot, plus zeroemu's own.
    pub fn load_defaults(&self, vfs: &Vfs) {
        const FILES: [&str; 8] = [
            "/system/etc/prop.default",
            "/system/build.prop",
            "/system_ext/etc/build.prop",
            "/vendor/default.prop",
            "/vendor/build.prop",
            "/odm/etc/build.prop",
            "/product/etc/build.prop",
            "/system_dlkm/etc/build.prop",
        ];
        for path in FILES {
            let Ok(node) = vfs.resolve("/", path, true) else { continue };
            let Ok(data) = vfs.read_all(&node) else { continue };
            for line in String::from_utf8_lossy(&data).lines() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') || line.starts_with("import ") {
                    continue;
                }
                if let Some((k, v)) = line.split_once('=') {
                    let _ = self.set(None, k.trim(), v.trim()); // first ro.* wins, as with init
                }
            }
        }
        // What init derives (property_initialize_ro_product_props and
        // ConstructBuildFingerprint): ro.product.* from the first partition
        // that defines it, then the build fingerprint from those.
        for prop in ["brand", "device", "manufacturer", "model", "name"] {
            let key = format!("ro.product.{prop}");
            if self.get(&key).is_none()
                && let Some(v) = ["product", "odm", "vendor", "system_ext", "system"].iter().find_map(|p| self.get(&format!("ro.product.{p}.{prop}")))
            {
                let _ = self.set(None, &key, &v);
            }
        }
        if self.get("ro.build.fingerprint").is_none() {
            let g = |k: &str| self.get(k).unwrap_or_else(|| "unknown".into());
            let release = self.get("ro.build.version.release_or_codename").unwrap_or_else(|| g("ro.build.version.release"));
            let fp = format!(
                "{}/{}/{}:{}/{}/{}:{}/{}",
                g("ro.product.brand"),
                g("ro.product.name"),
                g("ro.product.device"),
                release,
                g("ro.build.id"),
                g("ro.build.version.incremental"),
                g("ro.build.type"),
                g("ro.build.tags")
            );
            let _ = self.set(None, "ro.build.fingerprint", &fp);
        }
        for (k, v) in [
            ("ro.property_service.version", "2"),
            ("ro.hardware", "zeroemu"),
            ("ro.boot.hardware", "zeroemu"),
            ("ro.boot.selinux", "permissive"),
            ("ro.debuggable", "1"),
            ("ro.secure", "0"),
            ("ro.adb.secure", "0"),
            ("ro.kernel.zeroemu", "1"),
            ("persist.sys.timezone", "UTC"),
        ] {
            let _ = self.set(None, k, v);
        }
    }

}

/// The property service protocol (bionic's system_property_set.cpp):
/// v2 = u32 0x20001, then name and value as (u32 length, bytes), answered
/// with a u32 status; v1 = a 128-byte prop_msg with no answer.
pub fn handle_request(props: &Properties, futex: &Futexes, buf: &mut Vec<u8>) -> Option<Vec<u8>> {
    const PROP_MSG_SETPROP: u32 = 1;
    const PROP_MSG_SETPROP2: u32 = 0x0002_0001;
    if buf.len() < 4 {
        return None;
    }
    let u32_at = |b: &[u8], o: usize| u32::from_le_bytes(b[o..o + 4].try_into().unwrap());
    match u32_at(buf, 0) {
        PROP_MSG_SETPROP2 => {
            let take_str = |b: &[u8], at: usize| -> Option<(String, usize)> {
                let len = u32_at(b.get(at..at + 4)?, 0) as usize;
                let s = b.get(at + 4..at + 4 + len)?;
                Some((String::from_utf8_lossy(s).into_owned(), at + 4 + len))
            };
            let (name, at) = take_str(buf, 4)?;
            let (value, end) = take_str(buf, at)?;
            buf.drain(..end);
            let status = props.set(Some(futex), &name, &value);
            Some(status.to_le_bytes().to_vec())
        }
        PROP_MSG_SETPROP if buf.len() >= 128 => {
            let field = |b: &[u8]| String::from_utf8_lossy(b.split(|&c| c == 0).next().unwrap_or(b)).into_owned();
            let (name, value) = (field(&buf[4..36]), field(&buf[36..128]));
            buf.drain(..128);
            props.set(Some(futex), &name, &value);
            Some(Vec::new())
        }
        PROP_MSG_SETPROP => None, // wait for the rest
        _ => {
            buf.clear();
            Some((PROP_ERROR_INVALID_NAME).to_le_bytes().to_vec())
        }
    }
}

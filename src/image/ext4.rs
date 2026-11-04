//! Read-only ext4 (APEX payloads and older system images): extent trees and
//! indirect block maps, linear and htree directories, fast symlinks, and
//! extended attributes (in-inode and block, as fs/ext4/xattr.c lays them out).

use super::{Dev, invalid, le16, le32};
use std::collections::HashMap;
use std::io;
use std::sync::{Arc, Mutex};

const MAGIC: u16 = 0xef53;
const ROOT_INO: u64 = 2;
const INCOMPAT_FILETYPE: u32 = 0x2;
const INCOMPAT_EXTENTS: u32 = 0x40;
const INCOMPAT_64BIT: u32 = 0x80;
const INCOMPAT_FLEX_BG: u32 = 0x200;
const INCOMPAT_SUPPORTED: u32 = INCOMPAT_FILETYPE | INCOMPAT_EXTENTS | INCOMPAT_64BIT | INCOMPAT_FLEX_BG
    | 0x10 /* meta_bg */ | 0x1000 /* csum_seed */ | 0x4 /* recover: read-only, ignore journal */;
const EXTENTS_FL: u32 = 0x80000;
const INLINE_DATA_FL: u32 = 0x1000_0000;
const EXTENT_MAGIC: u16 = 0xf30a;
const XATTR_MAGIC: u32 = 0xea02_0000;
/// Name prefixes by EXT4_XATTR_INDEX_* that Linux exposes.
const XATTR_PREFIXES: [&str; 11] = ["", "user.", "system.posix_acl_access", "system.posix_acl_default", "trusted.", "", "security.", "", "", "", "gnu."];

pub struct Ext4 {
    dev: Dev,
    bs: u64,
    inodes_per_group: u64,
    inode_size: u64,
    desc_size: u64,
    desc_table: u64,
    has_64bit: bool,
    cache: Mutex<HashMap<u64, Arc<[u8]>>>,
}

#[derive(Clone, Debug)]
pub struct Inode {
    pub ino: u64,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub size: u64,
    pub nlink: u32,
    pub mtime: u64,
    flags: u32,
    block: [u8; 60],
}

pub struct DirEntry {
    pub name: String,
    pub ino: u64,
    /// EXT4_FT_*: same numbering as EROFS_FT_* (1 file, 2 dir, … 7 symlink).
    pub file_type: u8,
}

impl Ext4 {
    pub fn open(dev: Dev) -> io::Result<Arc<Ext4>> {
        let sb = dev.read_vec(1024, 1024)?;
        if le16(&sb, 56) != MAGIC {
            return Err(invalid("not an ext4 filesystem"));
        }
        let incompat = le32(&sb, 96);
        if incompat & !INCOMPAT_SUPPORTED != 0 {
            return Err(invalid(format!(
                "ext4: unsupported incompat features {:#x}",
                incompat & !INCOMPAT_SUPPORTED
            )));
        }
        let bs = 1024u64 << le32(&sb, 24);
        let has_64bit = incompat & INCOMPAT_64BIT != 0;
        let rev = le32(&sb, 76);
        Ok(Arc::new(Ext4 {
            bs,
            inodes_per_group: le32(&sb, 40) as u64,
            inode_size: if rev >= 1 { le16(&sb, 88) as u64 } else { 128 },
            desc_size: if has_64bit {
                (le16(&sb, 254) as u64).max(32)
            } else {
                32
            },
            desc_table: (le32(&sb, 20) as u64 + 1) * bs,
            has_64bit,
            dev,
            cache: Mutex::new(HashMap::new()),
        }))
    }

    pub fn root_ino(&self) -> u64 {
        ROOT_INO
    }

    /// The first `len` bytes of an on-disk inode.
    fn raw_inode(&self, ino: u64, len: u64) -> io::Result<Vec<u8>> {
        if ino == 0 {
            return Err(invalid("ext4: inode 0"));
        }
        let group = (ino - 1) / self.inodes_per_group;
        let index = (ino - 1) % self.inodes_per_group;
        let desc = self.dev.read_vec(
            self.desc_table + group * self.desc_size,
            self.desc_size as usize,
        )?;
        let mut table = le32(&desc, 8) as u64;
        if self.has_64bit && self.desc_size >= 64 {
            table |= (le32(&desc, 0x28) as u64) << 32;
        }
        self.dev.read_vec(table * self.bs + index * self.inode_size, len as usize)
    }

    pub fn inode(&self, ino: u64) -> io::Result<Inode> {
        let raw = self.raw_inode(ino, 128)?;
        let mut block = [0u8; 60];
        block.copy_from_slice(&raw[40..100]);
        Ok(Inode {
            ino,
            mode: le16(&raw, 0) as u32,
            uid: le16(&raw, 2) as u32 | (le16(&raw, 120) as u32) << 16,
            gid: le16(&raw, 24) as u32 | (le16(&raw, 122) as u32) << 16,
            size: le32(&raw, 4) as u64 | (le32(&raw, 108) as u64) << 32,
            nlink: le16(&raw, 26) as u32,
            mtime: le32(&raw, 16) as u64,
            flags: le32(&raw, 32),
            block,
        })
    }

    /// An inode's extended attributes as (full name, value): those in the
    /// inode body after i_extra_isize, then those in its xattr block.
    pub fn xattrs(&self, ino: u64) -> io::Result<Vec<(String, Vec<u8>)>> {
        let mut out = Vec::new();
        let raw = self.raw_inode(ino, self.inode_size.max(128))?;
        if raw.len() > 132 {
            let start = 128 + le16(&raw, 128) as usize;
            if start + 4 <= raw.len() && le32(&raw, start) == XATTR_MAGIC {
                // In-inode value offsets count from the first entry.
                self.parse_xattrs(&raw[start + 4..], 0, ino, &mut out)?;
            }
        }
        let block = le32(&raw, 104) as u64 | (le16(&raw, 118) as u64) << 32; // i_file_acl
        if block != 0 {
            let b = self.dev.read_vec(block * self.bs, self.bs as usize)?;
            if le32(&b, 0) != XATTR_MAGIC || le32(&b, 8) != 1 {
                return Err(invalid(format!("ext4: bad xattr block (inode {ino})")));
            }
            self.parse_xattrs(&b, 32, ino, &mut out)?;
        }
        Ok(out)
    }

    /// struct ext4_xattr_entry records from `first` up to a zero word;
    /// values sit at offsets into `area`, or in an EA inode.
    fn parse_xattrs(&self, area: &[u8], first: usize, ino: u64, out: &mut Vec<(String, Vec<u8>)>) -> io::Result<()> {
        let bad = || invalid(format!("ext4: corrupt xattrs (inode {ino})"));
        let mut p = first;
        while p + 4 <= area.len() && le32(area, p) != 0 {
            let e = area.get(p..p + 16).ok_or_else(bad)?;
            let (nlen, index, voff, inum, vsize) = (e[0] as usize, e[1], le16(e, 2) as usize, le32(e, 4) as u64, le32(e, 8) as usize);
            let name = area.get(p + 16..p + 16 + nlen).ok_or_else(bad)?;
            let value = if inum != 0 {
                self.read(&self.inode(inum)?)?.get(..vsize).ok_or_else(bad)?.to_vec()
            } else {
                area.get(voff..voff + vsize).ok_or_else(bad)?.to_vec()
            };
            // Namespaces Linux hides (system.data, encryption) are skipped.
            if let Some(prefix) = XATTR_PREFIXES.get(index as usize).filter(|p| !p.is_empty()) {
                out.push((format!("{prefix}{}", String::from_utf8_lossy(name)), value));
            }
            p += (16 + nlen).next_multiple_of(4);
        }
        Ok(())
    }

    /// Whole file contents (holes read as zeros), cached.
    pub fn read(&self, ino: &Inode) -> io::Result<Arc<[u8]>> {
        if let Some(d) = self.cache.lock().unwrap().get(&ino.ino) {
            return Ok(d.clone());
        }
        let is_symlink = ino.mode & 0o170000 == 0o120000;
        let data: Arc<[u8]> = if is_symlink && ino.size < 60 && ino.flags & EXTENTS_FL == 0 {
            ino.block[..ino.size as usize].into() // fast symlink: target stored in i_block
        } else if ino.flags & INLINE_DATA_FL != 0 {
            return Err(invalid(format!(
                "ext4: inline data not supported (inode {})",
                ino.ino
            )));
        } else {
            let mut out = vec![0u8; ino.size as usize];
            let mut runs = Vec::new();
            if ino.flags & EXTENTS_FL != 0 {
                self.extent_runs(&ino.block, &mut runs, 0)?;
            } else {
                self.indirect_runs(&ino.block, ino.size.div_ceil(self.bs), &mut runs)?;
            }
            for (logical, phys, count) in runs {
                let start = logical * self.bs;
                if start >= ino.size {
                    continue;
                }
                let len = (count * self.bs).min(ino.size - start) as usize;
                self.dev.read_exact_at(
                    phys * self.bs,
                    &mut out[start as usize..start as usize + len],
                )?;
            }
            out.into()
        };
        self.cache.lock().unwrap().insert(ino.ino, data.clone());
        Ok(data)
    }

    /// Collects (logical block, physical block, block count) from an extent tree node.
    fn extent_runs(
        &self,
        node: &[u8],
        runs: &mut Vec<(u64, u64, u64)>,
        depth_guard: u32,
    ) -> io::Result<()> {
        if le16(node, 0) != EXTENT_MAGIC || depth_guard > 8 {
            return Err(invalid("ext4: bad extent header"));
        }
        let entries = le16(node, 2) as usize;
        let depth = le16(node, 6);
        for i in 0..entries {
            let e = &node[12 + i * 12..24 + i * 12];
            if depth == 0 {
                let mut len = le16(e, 4) as u64;
                let uninit = len > 32768;
                if uninit {
                    len -= 32768; // preallocated: reads as zeros
                }
                let phys = (le16(e, 6) as u64) << 32 | le32(e, 8) as u64;
                if !uninit {
                    runs.push((le32(e, 0) as u64, phys, len));
                }
            } else {
                let leaf = (le16(e, 8) as u64) << 32 | le32(e, 4) as u64;
                let child = self.dev.read_vec(leaf * self.bs, self.bs as usize)?;
                self.extent_runs(&child, runs, depth_guard + 1)?;
            }
        }
        Ok(())
    }

    /// Classic block map: 12 direct, then single/double/triple indirect blocks.
    fn indirect_runs(
        &self,
        block: &[u8],
        nblocks: u64,
        runs: &mut Vec<(u64, u64, u64)>,
    ) -> io::Result<()> {
        let mut logical = 0u64;
        for i in 0..12 {
            if logical >= nblocks {
                return Ok(());
            }
            let p = le32(block, i * 4) as u64;
            if p != 0 {
                runs.push((logical, p, 1));
            }
            logical += 1;
        }
        for level in 1..=3 {
            let p = le32(block, (11 + level) * 4) as u64;
            self.indirect_level(p, level, &mut logical, nblocks, runs)?;
        }
        Ok(())
    }

    fn indirect_level(
        &self,
        p: u64,
        level: usize,
        logical: &mut u64,
        nblocks: u64,
        runs: &mut Vec<(u64, u64, u64)>,
    ) -> io::Result<()> {
        let per = self.bs / 4;
        if *logical >= nblocks {
            return Ok(());
        }
        if p == 0 {
            *logical += per.pow(level as u32);
            return Ok(());
        }
        let table = self.dev.read_vec(p * self.bs, self.bs as usize)?;
        for i in 0..per as usize {
            let child = le32(&table, i * 4) as u64;
            if level == 1 {
                if *logical >= nblocks {
                    break;
                }
                if child != 0 {
                    runs.push((*logical, child, 1));
                }
                *logical += 1;
            } else {
                self.indirect_level(child, level - 1, logical, nblocks, runs)?;
            }
        }
        Ok(())
    }

    pub fn readdir(&self, dir: &Inode) -> io::Result<Vec<DirEntry>> {
        let data = self.read(dir)?;
        let mut out = Vec::new();
        let mut p = 0usize;
        while p + 8 <= data.len() {
            let ino = le32(&data, p) as u64;
            let rec_len = le16(&data, p + 4) as usize;
            let name_len = data[p + 6] as usize;
            if rec_len < 8 || p + rec_len > data.len() {
                return Err(invalid(format!(
                    "ext4: corrupt directory (inode {})",
                    dir.ino
                )));
            }
            if ino != 0 && p + 8 + name_len <= data.len() {
                out.push(DirEntry {
                    name: String::from_utf8_lossy(&data[p + 8..p + 8 + name_len]).into_owned(),
                    ino,
                    file_type: data[p + 7],
                });
            }
            p += rec_len;
        }
        Ok(out)
    }

    pub fn lookup(&self, dir: &Inode, name: &str) -> io::Result<Option<u64>> {
        Ok(self
            .readdir(dir)?
            .into_iter()
            .find(|e| e.name == name)
            .map(|e| e.ino))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::errno::{ENODATA, EROFS};
    use crate::image::MemDev;
    use crate::vfs::FileSystem;

    fn put(img: &mut [u8], at: usize, b: &[u8]) {
        img[at..at + b.len()].copy_from_slice(b);
    }

    /// struct ext4_xattr_entry with its name, padded to 4 bytes.
    fn entry(index: u8, name: &str, value_offs: u16, inum: u32, size: u32) -> Vec<u8> {
        let mut e = vec![name.len() as u8, index];
        e.extend(value_offs.to_le_bytes());
        e.extend(inum.to_le_bytes());
        e.extend(size.to_le_bytes());
        e.extend([0; 4]); // e_hash
        e.extend(name.as_bytes());
        e.resize(e.len().next_multiple_of(4), 0);
        e
    }

    /// 1 KiB blocks, 256-byte inodes in a table at block 4. Inode 12 has an
    /// in-inode label and an xattr block (block 9); 13 has none; 14 keeps its
    /// value in EA inode 15, whose data is block 10.
    fn fixture() -> Arc<Ext4> {
        let mut img = vec![0u8; 12 * 1024];
        let sb = 1024;
        put(&mut img, sb + 20, &1u32.to_le_bytes()); // s_first_data_block
        put(&mut img, sb + 40, &16u32.to_le_bytes()); // s_inodes_per_group
        put(&mut img, sb + 56, &MAGIC.to_le_bytes());
        put(&mut img, sb + 76, &1u32.to_le_bytes()); // s_rev_level
        put(&mut img, sb + 88, &256u16.to_le_bytes()); // s_inode_size
        put(&mut img, 2048 + 8, &4u32.to_le_bytes()); // bg_inode_table
        let inode = |img: &mut Vec<u8>, ino: usize| {
            let at = 4096 + (ino - 1) * 256;
            put(img, at, &0o100644u16.to_le_bytes());
            put(img, at + 26, &1u16.to_le_bytes());
            put(img, at + 128, &32u16.to_le_bytes()); // i_extra_isize
            at
        };
        // Inode 12: in-inode security.selinux (value at the end of the inode), then block 9.
        let at = inode(&mut img, 12);
        put(&mut img, at + 104, &9u32.to_le_bytes()); // i_file_acl
        put(&mut img, at + 160, &XATTR_MAGIC.to_le_bytes());
        put(&mut img, at + 164, &entry(6, "selinux", 68, 0, 24));
        put(&mut img, at + 164 + 68, b"u:object_r:adbd_exec:s0\0");
        let blk = 9 * 1024;
        put(&mut img, blk, &XATTR_MAGIC.to_le_bytes());
        put(&mut img, blk + 4, &1u32.to_le_bytes()); // h_refcount
        put(&mut img, blk + 8, &1u32.to_le_bytes()); // h_blocks
        let e1 = entry(1, "mime_type", 1000, 0, 10);
        put(&mut img, blk + 32, &e1);
        put(&mut img, blk + 32 + e1.len(), &entry(7, "data", 1012, 0, 0)); // system.data: hidden
        put(&mut img, blk + 1000, b"text/plain");
        inode(&mut img, 13);
        // Inode 14: trusted.big lives in EA inode 15 (block map, one block).
        let at = inode(&mut img, 14);
        put(&mut img, at + 160, &XATTR_MAGIC.to_le_bytes());
        put(&mut img, at + 164, &entry(4, "big", 0, 15, 5));
        let at = inode(&mut img, 15);
        put(&mut img, at + 4, &5u32.to_le_bytes()); // i_size
        put(&mut img, at + 40, &10u32.to_le_bytes()); // i_block[0]
        put(&mut img, 10 * 1024, b"hello");
        Ext4::open(Arc::new(MemDev(img.into()))).unwrap()
    }

    #[test]
    fn xattrs_in_inode_block_and_ea_inode() {
        let fs = fixture();
        let attrs = fs.xattrs(12).unwrap();
        let names: Vec<&str> = attrs.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(names, ["security.selinux", "user.mime_type"]);
        assert_eq!(fs.getxattr(12, "security.selinux").unwrap(), b"u:object_r:adbd_exec:s0\0");
        assert_eq!(fs.getxattr(12, "user.mime_type").unwrap(), b"text/plain");
        assert_eq!(fs.getxattr(12, "system.data"), Err(ENODATA));
        assert_eq!(fs.listxattr(13).unwrap(), Vec::<String>::new());
        assert_eq!(fs.getxattr(14, "trusted.big").unwrap(), b"hello");
        assert_eq!(fs.setxattr(12, "user.x", b"", 0), Err(EROFS));
    }

    #[test]
    fn xattr_value_out_of_bounds_is_corrupt() {
        let fs = fixture();
        let mut img = fs.dev.read_vec(0, fs.dev.len() as usize).unwrap();
        put(&mut img, 4096 + 11 * 256 + 164, &entry(6, "selinux", 200, 0, 24)); // runs past the inode
        let fs = Ext4::open(Arc::new(MemDev(img.into()))).unwrap();
        assert!(fs.xattrs(12).is_err());
    }

    /// APEX payloads in the SDK image are ext4; their labels come from the build.
    #[test]
    fn sdk_image_apex_labels() {
        let Some(vfs) = crate::image::sdk_image() else { return eprintln!("skip: no Android SDK image") };
        for (path, label) in [
            ("/apex/com.android.adbd/bin/adbd", "u:object_r:adbd_exec:s0"),
            ("/apex/com.android.runtime/bin/linker64", "u:object_r:system_linker_exec:s0"),
            ("/apex/com.android.adbd", "u:object_r:system_file:s0"),
        ] {
            let node = vfs.resolve("/", path, false).unwrap();
            assert_eq!(vfs.fs_type(&node), "ext4");
            let v = vfs.getxattr(&node, "security.selinux").unwrap();
            assert_eq!(String::from_utf8_lossy(&v).trim_end_matches('\0'), label, "{path}");
            assert_eq!(vfs.setxattr(&node, "security.selinux", b"u:object_r:x:s0", 0), Err(EROFS));
        }
    }
}

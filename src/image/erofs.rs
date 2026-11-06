//! Read-only EROFS, the filesystem of modern Android partitions and APEX
//! payloads. Supports flat, inline-tail, and LZ4-compressed (full and compact
//! index) files; the compressed path follows Linux's fs/erofs/zmap.c.
//! Extended attributes (SELinux labels) follow fs/erofs/xattr.c.

use super::{Dev, invalid, le16, le32, le64, lz4};
use std::collections::HashMap;
use std::io;
use std::sync::{Arc, Mutex};

const MAGIC: u32 = 0xe0f5_e1e2;
const FEATURE_INCOMPAT_ZERO_PADDING: u32 = 0x1;
const FEATURE_INCOMPAT_FRAGMENTS: u32 = 0x20;
const FEATURE_INCOMPAT_XATTR_PREFIXES: u32 = 0x40;
const FEATURE_COMPAT_PLAIN_XATTR_PFX: u32 = 0x10;

/// e_name_index bit: the low bits index the long name prefix table.
const XATTR_LONG_PREFIX: u8 = 0x80;
/// Name prefixes by EROFS_XATTR_INDEX_* (5, lustre, is not exposed by Linux).
const XATTR_PREFIXES: [&str; 7] = ["", "user.", "system.posix_acl_access", "system.posix_acl_default", "trusted.", "", "security."];

const LAYOUT_FLAT_PLAIN: u8 = 0;
const LAYOUT_COMPRESSED_FULL: u8 = 1;
const LAYOUT_FLAT_INLINE: u8 = 2;
const LAYOUT_COMPRESSED_COMPACT: u8 = 3;

const LCLUSTER_PLAIN: u8 = 0;
const LCLUSTER_HEAD1: u8 = 1;
const LCLUSTER_NONHEAD: u8 = 2;
const LCLUSTER_HEAD2: u8 = 3;
/// On the first NONHEAD lcluster of a big pcluster: delta[0] holds the
/// compressed block count instead of a distance.
const LI_D0_CBLKCNT: u32 = 1 << 11;

const ADVISE_COMPACTED_2B: u16 = 0x0001;
const ADVISE_BIG_PCLUSTER_1: u16 = 0x0002;
const ADVISE_BIG_PCLUSTER_2: u16 = 0x0004;
const ADVISE_UNSUPPORTED: u16 = 0x0008 | 0x0010 | 0x0020; // inline / interlaced / fragment pclusters

const ALGORITHM_LZ4: u8 = 0;

pub struct Erofs {
    dev: Dev,
    blkbits: u32,
    meta_base: u64,
    root_nid: u64,
    build_time: u64,
    zero_padding: bool,
    /// Start of the shared xattr area.
    xattr_base: u64,
    /// Long xattr name prefixes: (short prefix index, infix).
    prefixes: Vec<(u8, Vec<u8>)>,
    /// Directories and symlinks, which every path lookup reads again. File
    /// contents are the page cache's business.
    meta: Mutex<HashMap<u64, Arc<[u8]>>>,
    /// Compressed files' extents, as those read recently need them.
    extents: Mutex<HashMap<u64, Arc<[Extent]>>>,
}

/// Holds this many extents' worth of indexes; they are quick to read back.
const EXTENTS_KEPT: usize = 1 << 20;

/// One compressed extent of a file. It runs up to the next one's `start`.
#[derive(Clone, Copy, Debug)]
struct Extent {
    start: u64,
    pblk: u32,
    /// Compressed blocks it takes.
    blocks: u16,
    /// LCLUSTER_*: how it is stored.
    kind: u8,
}

#[derive(Clone, Debug)]
pub struct Inode {
    pub nid: u64,
    pub mode: u32,
    pub size: u64,
    pub uid: u32,
    pub gid: u32,
    pub nlink: u32,
    pub mtime: u64,
    /// Raw block address / device number / compressed block count, by layout.
    pub raw: u32,
    layout: u8,
    /// End of the inode + xattr area (inline data / compression map follow).
    end: u64,
    /// Size of the xattr area, which ends at `end`.
    xattr_size: u64,
}

pub struct DirEntry {
    pub name: String,
    pub nid: u64,
    /// EROFS_FT_*: 1 file, 2 dir, 3 chr, 4 blk, 5 fifo, 6 sock, 7 symlink.
    pub file_type: u8,
}

/// One logical lcluster of a compressed file.
#[derive(Clone, Copy, Debug)]
struct Lcluster {
    kind: u8,
    /// HEAD/PLAIN: offset of the extent start within the lcluster.
    clusterofs: u32,
    /// HEAD/PLAIN: physical block of the pcluster.
    pblk: u64,
    /// NONHEAD: compressed block count of the preceding big pcluster, if recorded here.
    cblkcnt: Option<u32>,
}

impl Erofs {
    pub fn open(dev: Dev) -> io::Result<Arc<Erofs>> {
        let sb = dev.read_vec(1024, 128)?;
        if le32(&sb, 0) != MAGIC {
            return Err(invalid("not an EROFS filesystem"));
        }
        let blkbits = sb[12] as u32;
        if !(9..=16).contains(&blkbits) {
            return Err(invalid(format!(
                "erofs: unsupported block size 2^{blkbits}"
            )));
        }
        let (compat, incompat) = (le32(&sb, 8), le32(&sb, 80));
        let mut fs = Erofs {
            blkbits,
            meta_base: (le32(&sb, 40) as u64) << blkbits,
            root_nid: le16(&sb, 14) as u64,
            build_time: le64(&sb, 24),
            zero_padding: incompat & FEATURE_INCOMPAT_ZERO_PADDING != 0,
            xattr_base: (le32(&sb, 44) as u64) << blkbits,
            prefixes: Vec::new(),
            dev,
            meta: Mutex::default(),
            extents: Mutex::default(),
        };
        if sb[91] > 0 && incompat & FEATURE_INCOMPAT_XATTR_PREFIXES != 0 {
            let packed = (incompat & FEATURE_INCOMPAT_FRAGMENTS != 0 && compat & FEATURE_COMPAT_PLAIN_XATTR_PFX == 0)
                .then_some(le64(&sb, 96))
                .filter(|&nid| nid != 0);
            fs.prefixes = fs.long_prefixes(sb[91] as usize, le32(&sb, 92) as u64 * 4, packed)?;
        }
        Ok(Arc::new(fs))
    }

    /// The long xattr name prefix table: records of a le16 length, then the
    /// base prefix index and the infix, each 4-byte aligned. They live in the
    /// packed inode when there is one, else at an absolute offset.
    fn long_prefixes(&self, count: usize, start: u64, packed: Option<u64>) -> io::Result<Vec<(u8, Vec<u8>)>> {
        let packed = packed.map(|nid| self.inode(nid).and_then(|i| self.read(&i))).transpose()?;
        let read = |pos: u64, n: usize| match &packed {
            Some(d) => d.get(pos as usize..pos as usize + n).map(<[u8]>::to_vec).ok_or_else(|| invalid("erofs: xattr prefix past the packed inode")),
            None => self.dev.read_vec(pos, n),
        };
        let (mut pos, mut out) = (start, Vec::with_capacity(count));
        for _ in 0..count {
            pos = pos.next_multiple_of(4);
            let len = match le16(&read(pos, 2)?, 0) {
                0 => 1 << 16,
                n => n as usize,
            };
            let rec = read(pos + 2, len)?;
            pos += 2 + len as u64;
            out.push((rec[0], rec[1..].to_vec()));
        }
        Ok(out)
    }

    /// An inode's extended attributes as (full name, value): the shared ones
    /// (ids into the shared xattr area) first, then the inline entries.
    pub fn xattrs(&self, ino: &Inode) -> io::Result<Vec<(String, Vec<u8>)>> {
        let mut out = Vec::new();
        if ino.xattr_size == 0 {
            return Ok(out);
        }
        // struct erofs_xattr_ibody_header: name filter, shared count, reserved, shared ids.
        let body = self.dev.read_vec(ino.end - ino.xattr_size, ino.xattr_size as usize)?;
        let inline = 12 + body[4] as usize * 4;
        let ids = body.get(12..inline).ok_or_else(|| invalid(format!("erofs: bad shared xattr count (nid {})", ino.nid)))?;
        for id in ids.chunks_exact(4).map(|c| le32(c, 0) as u64) {
            let at = self.xattr_base + id * 4;
            let h = self.dev.read_vec(at, 4)?;
            let e = self.dev.read_vec(at + 4, h[0] as usize + le16(&h, 2) as usize)?;
            self.push_xattr(&mut out, &h, &e)?;
        }
        // struct erofs_xattr_entry: name length, name index, value size; name, value; 4-byte aligned.
        let mut p = inline;
        while p < body.len() {
            let h = body.get(p..p + 4).ok_or_else(|| invalid(format!("erofs: truncated xattr (nid {})", ino.nid)))?;
            let end = p + 4 + h[0] as usize + le16(h, 2) as usize;
            let e = body.get(p + 4..end).ok_or_else(|| invalid(format!("erofs: xattr overflows its inode (nid {})", ino.nid)))?;
            self.push_xattr(&mut out, h, e)?;
            p = end.next_multiple_of(4);
        }
        Ok(out)
    }

    fn push_xattr(&self, out: &mut Vec<(String, Vec<u8>)>, h: &[u8], e: &[u8]) -> io::Result<()> {
        let (name, value) = e.split_at(h[0] as usize);
        let (index, infix) = if h[1] & XATTR_LONG_PREFIX != 0 {
            let (base, infix) = self.prefixes.get((h[1] & !XATTR_LONG_PREFIX) as usize).ok_or_else(|| invalid("erofs: bad long xattr prefix"))?;
            (*base, infix.as_slice())
        } else {
            (h[1], &[][..])
        };
        // Namespaces Linux does not expose are skipped, not errors.
        if let Some(prefix) = XATTR_PREFIXES.get(index as usize).filter(|p| !p.is_empty()) {
            let full = [prefix.as_bytes(), infix, name].concat();
            out.push((String::from_utf8_lossy(&full).into_owned(), value.to_vec()));
        }
        Ok(())
    }

    fn bs(&self) -> u64 {
        1 << self.blkbits
    }

    pub fn root_nid(&self) -> u64 {
        self.root_nid
    }

    pub fn inode(&self, nid: u64) -> io::Result<Inode> {
        let pos = self.meta_base + nid * 32;
        let raw = self
            .dev
            .read_vec(pos, 64.min((self.dev.len() - pos) as usize))?;
        let format = le16(&raw, 0);
        let xattr_icount = le16(&raw, 2) as u64;
        let xattr_size = if xattr_icount == 0 {
            0
        } else {
            12 + (xattr_icount - 1) * 4
        };
        let layout = ((format >> 1) & 7) as u8;
        let mode = le16(&raw, 4) as u32;
        let ino = if format & 1 == 0 {
            Inode {
                nid,
                mode,
                nlink: le16(&raw, 6) as u32,
                size: le32(&raw, 8) as u64,
                raw: le32(&raw, 16),
                uid: le16(&raw, 24) as u32,
                gid: le16(&raw, 26) as u32,
                mtime: self.build_time,
                layout,
                end: pos + 32 + xattr_size,
                xattr_size,
            }
        } else {
            if raw.len() < 64 {
                return Err(invalid("erofs: truncated extended inode"));
            }
            Inode {
                nid,
                mode,
                size: le64(&raw, 8),
                raw: le32(&raw, 16),
                uid: le32(&raw, 24),
                gid: le32(&raw, 28),
                mtime: le64(&raw, 32),
                nlink: le32(&raw, 44),
                layout,
                end: pos + 64 + xattr_size,
                xattr_size,
            }
        };
        Ok(ino)
    }

    /// Whole file contents. Only directories and symlinks are kept.
    pub fn read(&self, ino: &Inode) -> io::Result<Arc<[u8]>> {
        let keep = matches!(ino.mode & 0o170000, 0o040000 | 0o120000);
        if keep && let Some(d) = self.meta.lock().unwrap().get(&ino.nid) {
            return Ok(d.clone());
        }
        let mut v = vec![0; ino.size as usize];
        let n = self.read_range(ino, 0, &mut v)?;
        v.truncate(n);
        let data: Arc<[u8]> = v.into();
        if keep {
            self.meta.lock().unwrap().insert(ino.nid, data.clone());
        }
        Ok(data)
    }

    /// Bytes of a file from `off`: as many as `buf` holds, unless it ends first.
    pub fn read_range(&self, ino: &Inode, off: u64, buf: &mut [u8]) -> io::Result<usize> {
        let n = ino.size.saturating_sub(off).min(buf.len() as u64) as usize;
        let buf = &mut buf[..n];
        if n == 0 {
            return Ok(0);
        }
        match ino.layout {
            LAYOUT_FLAT_PLAIN => self.dev.read_exact_at(((ino.raw as u64) << self.blkbits) + off, buf)?,
            LAYOUT_FLAT_INLINE => {
                // Whole blocks, then the tail stored just after the inode.
                let full = ino.size / self.bs() * self.bs();
                let in_blocks = full.saturating_sub(off).min(n as u64) as usize;
                let (head, tail) = buf.split_at_mut(in_blocks);
                if in_blocks > 0 {
                    self.dev.read_exact_at(((ino.raw as u64) << self.blkbits) + off, head)?;
                }
                if !tail.is_empty() {
                    self.dev.read_exact_at(ino.end + (off + in_blocks as u64 - full), tail)?;
                }
            }
            LAYOUT_COMPRESSED_FULL | LAYOUT_COMPRESSED_COMPACT => self.read_compressed(ino, off, buf)?,
            l => {
                return Err(invalid(format!(
                    "erofs: unsupported data layout {l} (nid {})",
                    ino.nid
                )));
            }
        }
        Ok(n)
    }

    pub fn readdir(&self, dir: &Inode) -> io::Result<Vec<DirEntry>> {
        let data = self.read(dir)?;
        let mut out = Vec::new();
        for blk in data.chunks(self.bs() as usize) {
            if blk.len() < 12 {
                continue;
            }
            let count = le16(blk, 8) as usize / 12;
            for i in 0..count {
                let nid = le64(blk, i * 12);
                let start = le16(blk, i * 12 + 8) as usize;
                let end = if i + 1 < count {
                    le16(blk, (i + 1) * 12 + 8) as usize
                } else {
                    blk.len()
                };
                let raw = blk
                    .get(start..end)
                    .ok_or_else(|| invalid("erofs: bad dirent"))?;
                let name = raw.split(|&b| b == 0).next().unwrap_or(raw);
                out.push(DirEntry {
                    name: String::from_utf8_lossy(name).into_owned(),
                    nid,
                    file_type: blk[i * 12 + 10],
                });
            }
        }
        Ok(out)
    }

    pub fn lookup(&self, dir: &Inode, name: &str) -> io::Result<Option<u64>> {
        Ok(self
            .readdir(dir)?
            .into_iter()
            .find(|e| e.name == name)
            .map(|e| e.nid))
    }

    /// A compressed file's extents, from its index.
    fn extents_of(&self, ino: &Inode) -> io::Result<(Arc<[Extent]>, u8)> {
        let map_header = ino.end.next_multiple_of(8);
        let h = self.dev.read_vec(map_header, 8)?;
        let advise = le16(&h, 4);
        let algorithms = h[6];
        let clusterbits = h[7];
        if advise & ADVISE_UNSUPPORTED != 0 || clusterbits & 0x80 != 0 {
            return Err(invalid(format!(
                "erofs: unsupported compression advise {advise:#x} (nid {})",
                ino.nid
            )));
        }
        if let Some(e) = self.extents.lock().unwrap().get(&ino.nid) {
            return Ok((e.clone(), algorithms));
        }
        let lclusterbits = self.blkbits + (clusterbits & 7) as u32;
        let lsize = 1u64 << lclusterbits;
        let total = ino.size.div_ceil(lsize) as usize;

        let lclusters = if ino.layout == LAYOUT_COMPRESSED_FULL {
            self.full_index(map_header, total)?
        } else {
            if lclusterbits != self.blkbits {
                return Err(invalid("erofs: compact index needs lcluster == block size"));
            }
            self.compact_index(map_header + 8, total, advise, lclusterbits)?
        };
        let heads = (0..total).filter(|&i| lclusters[i].kind != LCLUSTER_NONHEAD);
        let mut extents = Vec::new();
        for lcn in heads {
            let head = lclusters[lcn];
            let big = match head.kind {
                LCLUSTER_HEAD1 => advise & ADVISE_BIG_PCLUSTER_1 != 0,
                _ => advise & ADVISE_BIG_PCLUSTER_2 != 0,
            };
            let blocks = match lclusters.get(lcn + 1) {
                Some(next) if big && next.kind == LCLUSTER_NONHEAD => next.cblkcnt.unwrap_or(1),
                _ => 1,
            };
            extents.push(Extent {
                start: ((lcn as u64) << lclusterbits) + head.clusterofs as u64,
                pblk: u32::try_from(head.pblk).map_err(|_| invalid("erofs: block number out of range"))?,
                blocks: u16::try_from(blocks).map_err(|_| invalid("erofs: pcluster too big"))?,
                kind: head.kind,
            });
        }
        if extents.first().is_some_and(|e| e.start != 0) || (extents.is_empty() && ino.size > 0) {
            return Err(invalid(
                "erofs: compressed file does not start with a head lcluster",
            ));
        }
        if extents.windows(2).any(|w| w[0].start >= w[1].start) {
            return Err(invalid("erofs: non-contiguous extents"));
        }
        let extents: Arc<[Extent]> = extents.into();
        let mut kept = self.extents.lock().unwrap();
        if kept.values().map(|e| e.len()).sum::<usize>() + extents.len() > EXTENTS_KEPT {
            kept.clear();
        }
        kept.insert(ino.nid, extents.clone());
        Ok((extents, algorithms))
    }

    /// Reads from a compressed file: decompresses only the extents `buf` falls in.
    fn read_compressed(&self, ino: &Inode, off: u64, buf: &mut [u8]) -> io::Result<()> {
        let bs = self.bs();
        let (extents, algorithms) = self.extents_of(ino)?;
        let end_of = |i: usize| extents.get(i + 1).map_or(ino.size, |e| e.start);
        let mut i = extents.partition_point(|e| e.start <= off).saturating_sub(1);
        let mut done = 0;
        let mut out = Vec::new();
        while done < buf.len() {
            let e = *extents.get(i).ok_or_else(|| invalid("erofs: read past the last extent"))?;
            let (start, end) = (e.start, end_of(i));
            let want = (end - start) as usize;
            let pcluster = self.dev.read_vec(e.pblk as u64 * bs, e.blocks as usize * bs as usize)?;
            let at = off + done as u64;
            let n = ((end - at) as usize).min(buf.len() - done);
            if e.kind == LCLUSTER_PLAIN {
                let plain = pcluster.get(..want).ok_or_else(|| invalid("erofs: plain extent overflows pcluster"))?;
                buf[done..done + n].copy_from_slice(&plain[(at - start) as usize..][..n]);
            } else {
                let algorithm = match e.kind {
                    LCLUSTER_HEAD1 => algorithms & 0xf,
                    LCLUSTER_HEAD2 => algorithms >> 4,
                    k => return Err(invalid(format!("erofs: lcluster type {k} cannot head an extent"))),
                };
                if algorithm != ALGORITHM_LZ4 {
                    return Err(invalid(format!(
                        "erofs: unsupported compression algorithm {algorithm}"
                    )));
                }
                // With zero padding, compressed data is right-aligned in the pcluster.
                let skip = if self.zero_padding {
                    pcluster.iter().position(|&b| b != 0).unwrap_or(0)
                } else {
                    0
                };
                out.clear();
                out.reserve(want);
                lz4::decompress_into(&pcluster[skip..], &mut out, want)
                    .map_err(|err| invalid(format!("erofs nid {} extent @{start:#x}: {err}", ino.nid)))?;
                let got = out.get((at - start) as usize..(at - start) as usize + n).ok_or_else(|| invalid(format!("erofs nid {} extent @{start:#x}: short", ino.nid)))?;
                buf[done..done + n].copy_from_slice(got);
            }
            done += n;
            i += 1;
        }
        Ok(())
    }

    fn full_index(&self, map_header: u64, total: usize) -> io::Result<Vec<Lcluster>> {
        // Legacy layout: 8-byte map header, 8 reserved bytes, then 8 bytes per lcluster.
        let raw = self.dev.read_vec(map_header + 16, total * 8)?;
        Ok(raw
            .chunks_exact(8)
            .map(|e| {
                let kind = (le16(e, 0) & 3) as u8;
                let d0 = le16(e, 4) as u32;
                Lcluster {
                    kind,
                    clusterofs: le16(e, 2) as u32,
                    pblk: le32(e, 4) as u64,
                    cblkcnt: (kind == LCLUSTER_NONHEAD && d0 & LI_D0_CBLKCNT != 0)
                        .then_some(d0 & !LI_D0_CBLKCNT),
                }
            })
            .collect())
    }

    /// Decodes the compact index: packs of 2 (4-byte) or 16 (2-byte) entries,
    /// each pack ending in the 32-bit block address of its first pcluster.
    fn compact_index(
        &self,
        ebase: u64,
        total: usize,
        advise: u16,
        lclusterbits: u32,
    ) -> io::Result<Vec<Lcluster>> {
        let initial_4b = (((32 - ebase % 32) / 4) & 7) as usize;
        let compacted_2b = if advise & ADVISE_COMPACTED_2B != 0 && initial_4b < total {
            (total - initial_4b) / 16 * 16
        } else {
            0
        };
        // Packs are aligned on absolute positions, so buffer from a 32-byte boundary.
        let buf_start = ebase & !31;
        let buf_len = ((ebase - buf_start) as usize + total * 4 + 64)
            .min((self.dev.len() - buf_start) as usize);
        let buf = self.dev.read_vec(buf_start, buf_len)?;
        let lobits = lclusterbits.max(12);
        let big1 = advise & ADVISE_BIG_PCLUSTER_1 != 0;

        let decode = |pack: usize, bitpos: usize| -> (u32, u8) {
            let at = pack + bitpos / 8;
            let mut w = [0u8; 4];
            let avail = buf.len().saturating_sub(at).min(4);
            w[..avail].copy_from_slice(&buf[at..at + avail]);
            let v = u32::from_le_bytes(w) >> (bitpos & 7);
            (v & ((1 << lobits) - 1), ((v >> lobits) & 3) as u8)
        };

        let mut out = Vec::with_capacity(total);
        for lcn0 in 0..total {
            let mut lcn = lcn0;
            let mut pos = ebase;
            let mut shift = 2; // 4-byte entries
            if lcn >= initial_4b {
                pos += initial_4b as u64 * 4;
                lcn -= initial_4b;
                if lcn < compacted_2b {
                    shift = 1;
                } else {
                    pos += compacted_2b as u64 * 2;
                    lcn -= compacted_2b;
                }
            }
            pos += (lcn as u64) << shift;
            let vcnt: usize = if shift == 2 { 2 } else { 16 };
            if shift == 1 && lclusterbits > 12 {
                return Err(invalid("erofs: 2-byte compact index with large lclusters"));
            }
            let pack_bytes = vcnt << shift;
            let encodebits = (pack_bytes - 4) * 8 / vcnt;
            let in_pack = (pos & (pack_bytes as u64 - 1)) as usize;
            let pack = (pos - buf_start) as usize - in_pack;
            let i = in_pack >> shift;
            if pack + pack_bytes > buf.len() {
                return Err(invalid("erofs: compact index out of range"));
            }

            let (lo, kind) = decode(pack, encodebits * i);
            if kind == LCLUSTER_NONHEAD {
                let cblkcnt = (lo & LI_D0_CBLKCNT != 0).then_some(lo & !LI_D0_CBLKCNT);
                if cblkcnt.is_some() && !big1 {
                    return Err(invalid("erofs: CBLKCNT without big pclusters"));
                }
                out.push(Lcluster {
                    kind,
                    clusterofs: 1 << lclusterbits,
                    pblk: 0,
                    cblkcnt,
                });
                continue;
            }

            // HEAD/PLAIN: the pack's base address plus the pclusters before us in it.
            let mut nblk: i64 = 0;
            let mut j = i as i64;
            if !big1 {
                nblk = 1;
                while j > 0 {
                    j -= 1;
                    let (lo, t) = decode(pack, encodebits * j as usize);
                    if t == LCLUSTER_NONHEAD {
                        j -= lo as i64;
                    }
                    if j >= 0 {
                        nblk += 1;
                    }
                }
            } else {
                while j > 0 {
                    j -= 1;
                    let (lo, t) = decode(pack, encodebits * j as usize);
                    if t == LCLUSTER_NONHEAD {
                        if lo & LI_D0_CBLKCNT != 0 {
                            j -= 1;
                            nblk += (lo & !LI_D0_CBLKCNT) as i64;
                            continue;
                        }
                        if lo <= 1 {
                            return Err(invalid("erofs: corrupt big-pcluster delta"));
                        }
                        j -= lo as i64 - 2;
                        continue;
                    }
                    nblk += 1;
                }
            }
            let base = le32(&buf, pack + pack_bytes - 4) as i64;
            out.push(Lcluster {
                kind,
                clusterofs: lo,
                pblk: (base + nblk) as u64,
                cblkcnt: None,
            });
        }
        Ok(out)
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

    fn entry(index: u8, name: &str, value: &[u8]) -> Vec<u8> {
        let mut e = vec![name.len() as u8, index];
        e.extend((value.len() as u16).to_le_bytes());
        e.extend(name.as_bytes());
        e.extend(value);
        e.resize(e.len().next_multiple_of(4), 0);
        e
    }

    /// 4 KiB blocks: superblock, inodes (block 1), shared xattrs (block 2),
    /// the long prefix table (block 3). nid 0 has xattrs, nid 4 has none.
    fn fixture() -> Arc<Erofs> {
        let mut img = vec![0u8; 4 * 4096];
        put(&mut img, 1024, &MAGIC.to_le_bytes());
        img[1024 + 12] = 12;
        put(&mut img, 1024 + 40, &1u32.to_le_bytes()); // meta_blkaddr
        put(&mut img, 1024 + 44, &2u32.to_le_bytes()); // xattr_blkaddr
        put(&mut img, 1024 + 80, &FEATURE_INCOMPAT_XATTR_PREFIXES.to_le_bytes());
        img[1024 + 91] = 1; // xattr_prefix_count
        put(&mut img, 1024 + 92, &(3u32 * 4096 / 4).to_le_bytes()); // xattr_prefix_start
        // Long prefix 0: "trusted." + "overlay.".
        put(&mut img, 3 * 4096, &[9, 0, 4]);
        put(&mut img, 3 * 4096 + 3, b"overlay.");
        // Shared xattr id 2 (offset 8 in the shared area).
        put(&mut img, 2 * 4096 + 8, &entry(6, "selinux", b"u:object_r:test_exec:s0\0"));
        let mut body = vec![0u8; 12];
        body[4] = 1; // h_shared_count
        body.extend(2u32.to_le_bytes());
        body.extend(entry(1, "comment", b"hello"));
        body.extend(entry(XATTR_LONG_PREFIX, "opaque", b"y"));
        body.extend(entry(5, "x", b"z")); // lustre: not exposed
        let icount = (body.len() - 12) / 4 + 1;
        let inode = |icount: usize| {
            let mut i = vec![0u8; 32];
            i[2..4].copy_from_slice(&(icount as u16).to_le_bytes());
            i[4..6].copy_from_slice(&0o100644u16.to_le_bytes());
            i[6..8].copy_from_slice(&1u16.to_le_bytes());
            i
        };
        put(&mut img, 4096, &inode(icount));
        put(&mut img, 4096 + 32, &body);
        put(&mut img, 4096 + 4 * 32, &inode(0)); // nid 4
        Erofs::open(Arc::new(MemDev(img.into()))).unwrap()
    }

    #[test]
    fn xattrs_inline_shared_and_long_prefix() {
        let fs = fixture();
        let attrs = fs.xattrs(&fs.inode(0).unwrap()).unwrap();
        let names: Vec<&str> = attrs.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(names, ["security.selinux", "user.comment", "trusted.overlay.opaque"]);
        assert_eq!(fs.getxattr(0, "security.selinux").unwrap(), b"u:object_r:test_exec:s0\0");
        assert_eq!(fs.getxattr(0, "trusted.overlay.opaque").unwrap(), b"y");
        assert_eq!(fs.getxattr(0, "user.missing"), Err(ENODATA));
        assert_eq!(fs.getxattr(4, "security.selinux"), Err(ENODATA));
        assert_eq!(fs.listxattr(4).unwrap(), Vec::<String>::new());
        assert_eq!(fs.setxattr(0, "user.comment", b"x", 0), Err(EROFS));
        assert_eq!(fs.removexattr(0, "user.comment"), Err(EROFS));
    }

    #[test]
    fn xattr_overflowing_its_inode_is_corrupt() {
        let fs = fixture();
        let mut ino = fs.inode(0).unwrap();
        ino.xattr_size -= 4; // the last entry now runs past the area
        ino.end -= 4;
        assert!(fs.xattrs(&ino).is_err());
    }

    /// Labels as the build stored them in the SDK image's partitions.
    #[test]
    fn sdk_image_labels() {
        let Some(vfs) = crate::image::sdk_image() else { return eprintln!("skip: no Android SDK image") };
        for (path, label) in [
            ("/system/bin/init", "u:object_r:init_exec:s0"),
            ("/system/bin/logd", "u:object_r:logd_exec:s0"),
            ("/system/bin/sh", "u:object_r:shell_exec:s0"),
            ("/system/etc/selinux/plat_file_contexts", "u:object_r:file_contexts_file:s0"),
            ("/vendor/bin", "u:object_r:vendor_file:s0"),
        ] {
            let node = vfs.resolve("/", path, false).unwrap();
            assert_eq!(vfs.fs_type(&node), "erofs");
            let v = vfs.getxattr(&node, "security.selinux").unwrap();
            assert_eq!(String::from_utf8_lossy(&v).trim_end_matches('\0'), label, "{path}");
            assert!(vfs.listxattr(&node).unwrap().iter().any(|n| n == "security.selinux"));
            assert_eq!(vfs.setxattr(&node, "security.selinux", b"u:object_r:x:s0", 0), Err(EROFS));
        }
    }
}

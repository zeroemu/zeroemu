//! Read-only EROFS, the filesystem of modern Android partitions and APEX
//! payloads. Supports flat, inline-tail, and LZ4-compressed (full and compact
//! index) files; the compressed path follows Linux's fs/erofs/zmap.c.

use super::{Dev, invalid, le16, le32, le64, lz4};
use std::collections::HashMap;
use std::io;
use std::sync::{Arc, Mutex};

const MAGIC: u32 = 0xe0f5_e1e2;
const FEATURE_INCOMPAT_ZERO_PADDING: u32 = 0x1;

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
    cache: Mutex<HashMap<u64, Arc<[u8]>>>,
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
        Ok(Arc::new(Erofs {
            blkbits,
            meta_base: (le32(&sb, 40) as u64) << blkbits,
            root_nid: le16(&sb, 14) as u64,
            build_time: le64(&sb, 24),
            zero_padding: le32(&sb, 80) & FEATURE_INCOMPAT_ZERO_PADDING != 0,
            dev,
            cache: Mutex::new(HashMap::new()),
        }))
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
            }
        };
        Ok(ino)
    }

    /// Whole file contents, decompressed and cached.
    pub fn read(&self, ino: &Inode) -> io::Result<Arc<[u8]>> {
        if let Some(d) = self.cache.lock().unwrap().get(&ino.nid) {
            return Ok(d.clone());
        }
        let data: Arc<[u8]> = match ino.layout {
            LAYOUT_FLAT_PLAIN => self
                .dev
                .read_vec((ino.raw as u64) << self.blkbits, ino.size as usize)?,
            LAYOUT_FLAT_INLINE => {
                let full = ino.size / self.bs() * self.bs();
                let mut v = self
                    .dev
                    .read_vec((ino.raw as u64) << self.blkbits, full as usize)?;
                v.extend(self.dev.read_vec(ino.end, (ino.size - full) as usize)?);
                v
            }
            LAYOUT_COMPRESSED_FULL | LAYOUT_COMPRESSED_COMPACT => self.read_compressed(ino)?,
            l => {
                return Err(invalid(format!(
                    "erofs: unsupported data layout {l} (nid {})",
                    ino.nid
                )));
            }
        }
        .into();
        self.cache.lock().unwrap().insert(ino.nid, data.clone());
        Ok(data)
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

    fn read_compressed(&self, ino: &Inode) -> io::Result<Vec<u8>> {
        let bs = self.bs();
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

        let mut out = Vec::with_capacity(ino.size as usize);
        let heads: Vec<usize> = (0..total)
            .filter(|&i| lclusters[i].kind != LCLUSTER_NONHEAD)
            .collect();
        if heads.first() != Some(&0) {
            return Err(invalid(
                "erofs: compressed file does not start with a head lcluster",
            ));
        }
        for (k, &lcn) in heads.iter().enumerate() {
            let head = lclusters[lcn];
            let start = ((lcn as u64) << lclusterbits) + head.clusterofs as u64;
            let end = heads.get(k + 1).map_or(ino.size, |&n| {
                ((n as u64) << lclusterbits) + lclusters[n].clusterofs as u64
            });
            let want = (end - start) as usize;
            if start != out.len() as u64 {
                return Err(invalid("erofs: non-contiguous extents"));
            }

            let big = match head.kind {
                LCLUSTER_HEAD1 => advise & ADVISE_BIG_PCLUSTER_1 != 0,
                _ => advise & ADVISE_BIG_PCLUSTER_2 != 0,
            };
            let blocks = match lclusters.get(lcn + 1) {
                Some(next) if big && next.kind == LCLUSTER_NONHEAD => next.cblkcnt.unwrap_or(1),
                _ => 1,
            } as u64;
            let pcluster = self.dev.read_vec(head.pblk * bs, (blocks * bs) as usize)?;

            if head.kind == LCLUSTER_PLAIN {
                out.extend_from_slice(
                    pcluster
                        .get(..want)
                        .ok_or_else(|| invalid("erofs: plain extent overflows pcluster"))?,
                );
                continue;
            }
            let algorithm = match head.kind {
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
            lz4::decompress_into(&pcluster[skip..], &mut out, want)
                .map_err(|e| invalid(format!("erofs nid {} extent @{start:#x}: {e}", ino.nid)))?;
        }
        Ok(out)
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

//! Android dynamic partitions: the LP metadata inside the `super` partition
//! (see AOSP system/core/fs_mgr/liblp/include/liblp/metadata_format.h).

use super::{Dev, ExtentDev, invalid, le32, le64};
use std::io;

const RESERVED_BYTES: u64 = 4096;
const GEOMETRY_SIZE: u64 = 4096;
const GEOMETRY_MAGIC: u32 = 0x616c_4467;
const HEADER_MAGIC: u32 = 0x414c_5030;
const SECTOR: u64 = 512;
const TARGET_LINEAR: u32 = 0;
const TARGET_ZERO: u32 = 1;

pub struct LogicalPartition {
    pub name: String,
    pub dev: Dev,
}

pub fn partitions(sup: &Dev) -> io::Result<Vec<LogicalPartition>> {
    let geo = sup.read_vec(RESERVED_BYTES, 52)?;
    if le32(&geo, 0) != GEOMETRY_MAGIC {
        return Err(invalid("super: bad LP geometry magic"));
    }
    // Slot 0 primary metadata follows the primary and backup geometry.
    let hdr_off = RESERVED_BYTES + GEOMETRY_SIZE * 2;
    let hdr = sup.read_vec(hdr_off, 128)?;
    if le32(&hdr, 0) != HEADER_MAGIC {
        return Err(invalid("super: bad LP metadata magic"));
    }
    let header_size = le32(&hdr, 8) as u64;
    let tables_size = le32(&hdr, 44) as usize;
    // Table descriptors: partitions, extents, groups, block devices.
    let desc = |i: usize| {
        (
            le32(&hdr, 80 + i * 12) as usize,
            le32(&hdr, 84 + i * 12) as usize,
            le32(&hdr, 88 + i * 12) as usize,
        )
    };
    let (p_off, p_num, p_size) = desc(0);
    let (e_off, e_num, e_size) = desc(1);
    let tables = sup.read_vec(hdr_off + header_size, tables_size)?;

    let extents: Vec<(u64, u32, u64)> = (0..e_num)
        .map(|i| {
            let e = &tables[e_off + i * e_size..];
            (le64(e, 0), le32(e, 8), le64(e, 12))
        })
        .collect();

    let mut out = Vec::new();
    for i in 0..p_num {
        let p = &tables[p_off + i * p_size..p_off + (i + 1) * p_size];
        let name = String::from_utf8_lossy(&p[..36])
            .trim_end_matches('\0')
            .to_string();
        let first = le32(p, 40) as usize;
        let num = le32(p, 44) as usize;
        let mut map = Vec::new();
        let mut logical = 0;
        for &(sectors, target, data) in extents
            .get(first..first + num)
            .ok_or_else(|| invalid("super: bad extent index"))?
        {
            let len = sectors * SECTOR;
            let phys = match target {
                TARGET_LINEAR => Some(data * SECTOR),
                TARGET_ZERO => None,
                t => return Err(invalid(format!("super: unknown extent target {t}"))),
            };
            map.push((logical, len, phys));
            logical += len;
        }
        out.push(LogicalPartition {
            name,
            dev: ExtentDev::new(sup.clone(), map),
        });
    }
    Ok(out)
}

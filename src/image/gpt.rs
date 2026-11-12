//! GUID partition tables (the outer layer of emulator system.img / vendor.img).

use super::{Dev, ExtentDev, invalid, le32, le64};
use std::io;

pub const SECTOR: u64 = 512;
/// What a GPT header, at the second sector, starts with.
pub const SIGNATURE: &[u8; 8] = b"EFI PART";

pub struct Partition {
    pub name: String,
    pub dev: Dev,
}

pub fn partitions(disk: &Dev) -> io::Result<Vec<Partition>> {
    let header = disk.read_vec(SECTOR, 92)?;
    if header[..8] != SIGNATURE[..] {
        return Err(invalid("no GPT header"));
    }
    let entries_lba = le64(&header, 72);
    let count = le32(&header, 80) as usize;
    let entry_size = le32(&header, 84) as usize;
    let table = disk.read_vec(entries_lba * SECTOR, count * entry_size)?;

    let mut out = Vec::new();
    for e in table.chunks_exact(entry_size) {
        if e[..16].iter().all(|&b| b == 0) {
            continue; // unused entry
        }
        let first = le64(e, 32);
        let last = le64(e, 40);
        let name_utf16: Vec<u16> = e[56..128]
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .take_while(|&c| c != 0)
            .collect();
        out.push(Partition {
            name: String::from_utf16_lossy(&name_utf16),
            dev: ExtentDev::slice(disk.clone(), first * SECTOR, (last - first + 1) * SECTOR),
        });
    }
    Ok(out)
}

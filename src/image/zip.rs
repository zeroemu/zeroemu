//! Just enough zip to open APEX files: stored entries (APEX payloads, mounted
//! in place) and deflated ones (`original_apex` inside compressed APEXes),
//! always CRC-checked.

use super::{Dev, ExtentDev, MemDev, inflate, invalid, le16, le32};
use std::io;
use std::sync::Arc;

const METHOD_STORED: u16 = 0;
const METHOD_DEFLATED: u16 = 8;

pub struct Entry {
    pub name: String,
    pub method: u16,
    pub crc32: u32,
    pub size: u64,
    compressed_size: u64,
    data_offset: u64,
}

pub fn entries(zip: &Dev) -> io::Result<Vec<Entry>> {
    let len = zip.len();
    let tail_len = len.min(65536 + 22) as usize;
    let tail = zip.read_vec(len - tail_len as u64, tail_len)?;
    let eocd = (0..=tail.len() - 22)
        .rev()
        .find(|&i| tail[i..i + 4] == *b"PK\x05\x06")
        .ok_or_else(|| invalid("zip: no end of central directory"))?;
    let count = le16(&tail, eocd + 10) as usize;
    let cd_size = le32(&tail, eocd + 12) as usize;
    let cd_off = le32(&tail, eocd + 16) as u64;
    let cd = zip.read_vec(cd_off, cd_size)?;

    let mut out = Vec::with_capacity(count);
    let mut p = 0;
    for _ in 0..count {
        if cd.get(p..p + 4) != Some(b"PK\x01\x02") {
            return Err(invalid("zip: bad central directory entry"));
        }
        let method = le16(&cd, p + 10);
        let crc32 = le32(&cd, p + 16);
        let compressed_size = le32(&cd, p + 20) as u64;
        let size = le32(&cd, p + 24) as u64;
        let (nl, el, cl) = (
            le16(&cd, p + 28) as usize,
            le16(&cd, p + 30) as usize,
            le16(&cd, p + 32) as usize,
        );
        let local = le32(&cd, p + 42) as u64;
        let name = String::from_utf8_lossy(&cd[p + 46..p + 46 + nl]).into_owned();
        let lh = zip.read_vec(local, 30)?;
        let data_offset = local + 30 + le16(&lh, 26) as u64 + le16(&lh, 28) as u64;
        out.push(Entry {
            name,
            method,
            crc32,
            size,
            compressed_size,
            data_offset,
        });
        p += 46 + nl + el + cl;
    }
    Ok(out)
}

pub fn has_entry(zip: &Dev, name: &str) -> io::Result<bool> {
    Ok(entries(zip)?.iter().any(|e| e.name == name))
}

/// Opens an entry as a device after checking its CRC32. Stored entries are
/// read in place; deflated ones are decompressed into memory.
pub fn open(zip: &Dev, name: &str) -> io::Result<Dev> {
    let e = entries(zip)?
        .into_iter()
        .find(|e| e.name == name)
        .ok_or_else(|| invalid(format!("zip: no entry {name}")))?;
    let dev = match e.method {
        METHOD_STORED => ExtentDev::slice(zip.clone(), e.data_offset, e.size),
        METHOD_DEFLATED => {
            let raw = zip.read_vec(e.data_offset, e.compressed_size as usize)?;
            let data = inflate::inflate(&raw, e.size as usize).map_err(|err| invalid(format!("zip: {name}: {err}")))?;
            if data.len() as u64 != e.size {
                return Err(invalid(format!("zip: {name}: inflated to {} bytes, expected {}", data.len(), e.size)));
            }
            Arc::new(MemDev(data.into())) as Dev
        }
        m => return Err(invalid(format!("zip: {name}: unsupported compression method {m}"))),
    };
    let mut crc = Crc32::new();
    let mut buf = vec![0; 1 << 20];
    let mut off = 0;
    while off < e.size {
        let n = (e.size - off).min(buf.len() as u64) as usize;
        dev.read_exact_at(off, &mut buf[..n])?;
        crc.update(&buf[..n]);
        off += n as u64;
    }
    if crc.finish() != e.crc32 {
        return Err(invalid(format!("zip: CRC mismatch for {name}")));
    }
    Ok(dev)
}

pub struct Crc32 {
    table: [u32; 256],
    value: u32,
}

impl Crc32 {
    pub fn new() -> Self {
        let mut table = [0u32; 256];
        for (i, t) in table.iter_mut().enumerate() {
            let mut c = i as u32;
            for _ in 0..8 {
                c = if c & 1 != 0 {
                    0xedb8_8320 ^ (c >> 1)
                } else {
                    c >> 1
                };
            }
            *t = c;
        }
        Crc32 { table, value: !0 }
    }

    pub fn update(&mut self, data: &[u8]) {
        for &b in data {
            self.value = self.table[((self.value ^ b as u32) & 0xff) as usize] ^ (self.value >> 8);
        }
    }

    pub fn finish(&self) -> u32 {
        !self.value
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn crc32_known_value() {
        let mut c = super::Crc32::new();
        c.update(b"123456789");
        assert_eq!(c.finish(), 0xcbf4_3926);
    }
}

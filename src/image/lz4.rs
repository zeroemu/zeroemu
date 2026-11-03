//! LZ4 block-format decompressor (what EROFS uses for compressed pclusters).

use std::io;

/// Decompresses an LZ4 block into `out`, stopping once `out` is full
/// (EROFS pclusters may encode more than the extent being read).
pub fn decompress_into(src: &[u8], out: &mut Vec<u8>, want: usize) -> io::Result<()> {
    let bad = |what: &str| io::Error::new(io::ErrorKind::InvalidData, format!("lz4: {what}"));
    let base = out.len();
    let limit = base + want;
    let mut i = 0;
    while i < src.len() && out.len() < limit {
        let token = src[i];
        i += 1;

        let mut lit = (token >> 4) as usize;
        if lit == 15 {
            loop {
                let b = *src.get(i).ok_or_else(|| bad("truncated literal length"))?;
                i += 1;
                lit += b as usize;
                if b != 255 {
                    break;
                }
            }
        }
        let lits = src
            .get(i..i + lit)
            .ok_or_else(|| bad("truncated literals"))?;
        out.extend_from_slice(&lits[..lit.min(limit - out.len())]);
        i += lit;
        if i >= src.len() || out.len() >= limit {
            break; // the last sequence has literals only
        }

        let offset = u16::from_le_bytes([
            src[i],
            *src.get(i + 1).ok_or_else(|| bad("truncated offset"))?,
        ]) as usize;
        i += 2;
        if offset == 0 || offset > out.len() - base {
            return Err(bad("match offset out of range"));
        }
        let mut mlen = (token & 15) as usize + 4;
        if token & 15 == 15 {
            loop {
                let b = *src.get(i).ok_or_else(|| bad("truncated match length"))?;
                i += 1;
                mlen += b as usize;
                if b != 255 {
                    break;
                }
            }
        }
        let mlen = mlen.min(limit - out.len());
        let start = out.len() - offset;
        if offset >= mlen {
            out.extend_from_within(start..start + mlen);
        } else {
            // Overlapping copy (run-length style): byte by byte.
            for k in 0..mlen {
                let b = out[start + k];
                out.push(b);
            }
        }
    }
    if out.len() != limit {
        return Err(bad(&format!(
            "produced {} of {want} bytes",
            out.len() - base
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn literals_only() {
        let mut out = Vec::new();
        decompress_into(b"\x50hello", &mut out, 5).unwrap();
        assert_eq!(out, b"hello");
    }

    #[test]
    fn overlapping_match() {
        // "ab" literal, then a match of offset 2 length 8 -> "ababababab", then literal "!".
        let src = [0x24, b'a', b'b', 2, 0, 0x10, b'!'];
        let mut out = Vec::new();
        decompress_into(&src, &mut out, 11).unwrap();
        assert_eq!(out, b"ababababab!");
    }

    #[test]
    fn stops_at_requested_length() {
        let src = [0x24, b'a', b'b', 2, 0, 0x10, b'!'];
        let mut out = Vec::new();
        decompress_into(&src, &mut out, 5).unwrap();
        assert_eq!(out, b"ababa");
    }

    #[test]
    fn rejects_bad_offset() {
        let src = [0x14, b'a', 9, 0, 0x00];
        assert!(decompress_into(&src, &mut Vec::new(), 10).is_err());
    }
}

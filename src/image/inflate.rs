//! DEFLATE (RFC 1951) decoder, for compressed APEXes (`original_apex` entries).
//! Table-driven for codes up to FAST_BITS long, bit-by-bit beyond that.

use std::io;

const FAST_BITS: u32 = 10;
const MAX_BITS: usize = 15;

const LEN_BASE: [u16; 29] = [3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258];
const LEN_EXTRA: [u8; 29] = [0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0];
const DIST_BASE: [u16; 30] = [
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145,
    8193, 12289, 16385, 24577,
];
const DIST_EXTRA: [u8; 30] = [0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13];
const CLEN_ORDER: [usize; 19] = [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15];

fn bad(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, format!("inflate: {msg}"))
}

struct Bits<'a> {
    data: &'a [u8],
    pos: usize,
    buf: u64,
    cnt: u32,
    /// Zero bytes fed past the end of input; consuming any of them is an error.
    overrun: u32,
}

impl Bits<'_> {
    fn refill(&mut self) {
        while self.cnt <= 56 {
            let b = match self.data.get(self.pos) {
                Some(&b) => {
                    self.pos += 1;
                    b
                }
                None => {
                    self.overrun += 1;
                    0
                }
            };
            self.buf |= (b as u64) << self.cnt;
            self.cnt += 8;
        }
    }
    fn peek(&mut self, n: u32) -> u32 {
        if self.cnt < n {
            self.refill();
        }
        (self.buf & ((1u64 << n) - 1)) as u32
    }
    fn consume(&mut self, n: u32) -> io::Result<()> {
        self.buf >>= n;
        self.cnt -= n;
        // Bits still buffered that came from padding must not have been eaten.
        if self.overrun * 8 > self.cnt {
            return Err(bad("unexpected end of input"));
        }
        Ok(())
    }
    fn bits(&mut self, n: u32) -> io::Result<u32> {
        if n == 0 {
            return Ok(0);
        }
        let v = self.peek(n);
        self.consume(n)?;
        Ok(v)
    }
}

struct Huffman {
    /// Indexed by the next FAST_BITS input bits: (length << 16) | symbol, or 0.
    fast: Vec<u32>,
    counts: [u16; MAX_BITS + 1],
    /// Symbols ordered by (code length, symbol value), for the slow path.
    symbols: Vec<u16>,
}

impl Huffman {
    fn new(lengths: &[u8]) -> io::Result<Huffman> {
        let mut counts = [0u16; MAX_BITS + 1];
        for &l in lengths {
            counts[l as usize] += 1;
        }
        counts[0] = 0;
        let mut offs = [0u16; MAX_BITS + 2];
        for len in 1..=MAX_BITS {
            offs[len + 1] = offs[len] + counts[len];
        }
        let mut symbols = vec![0u16; offs[MAX_BITS + 1] as usize];
        let mut next = [0u32; MAX_BITS + 1];
        let mut code = 0u32;
        for len in 1..=MAX_BITS {
            code = (code + counts[len - 1] as u32) << 1;
            next[len] = code;
        }
        let mut fast = vec![0u32; 1 << FAST_BITS];
        for (sym, &len) in lengths.iter().enumerate() {
            if len == 0 {
                continue;
            }
            let len = len as usize;
            symbols[offs[len] as usize] = sym as u16;
            offs[len] += 1;
            let c = next[len];
            next[len] += 1;
            if c >> len != 0 {
                return Err(bad("over-subscribed code"));
            }
            if len as u32 <= FAST_BITS {
                let rev = (c.reverse_bits() >> (32 - len)) as usize;
                for i in (rev..1 << FAST_BITS).step_by(1 << len) {
                    fast[i] = (len as u32) << 16 | sym as u32;
                }
            }
        }
        Ok(Huffman { fast, counts, symbols })
    }

    fn decode(&self, bits: &mut Bits) -> io::Result<u16> {
        let e = self.fast[bits.peek(FAST_BITS) as usize];
        if e != 0 {
            bits.consume(e >> 16)?;
            return Ok(e as u16);
        }
        // Canonical decode, one bit at a time (codes are stored MSB first).
        let (mut code, mut first, mut index) = (0i32, 0i32, 0i32);
        for len in 1..=MAX_BITS {
            code |= bits.bits(1)? as i32;
            let count = self.counts[len] as i32;
            if code - count < first {
                return Ok(self.symbols[(index + code - first) as usize]);
            }
            index += count;
            first = (first + count) << 1;
            code <<= 1;
        }
        Err(bad("invalid Huffman code"))
    }
}

pub fn inflate(src: &[u8], size_hint: usize) -> io::Result<Vec<u8>> {
    let mut out = Vec::with_capacity(size_hint);
    let mut bits = Bits { data: src, pos: 0, buf: 0, cnt: 0, overrun: 0 };
    loop {
        let last = bits.bits(1)?;
        match bits.bits(2)? {
            0 => {
                let skip = bits.cnt % 8;
                bits.consume(skip)?;
                let len = bits.bits(16)?;
                if bits.bits(16)? != !len & 0xffff {
                    return Err(bad("stored block length mismatch"));
                }
                for _ in 0..len {
                    out.push(bits.bits(8)? as u8);
                }
            }
            1 => {
                let mut l = [0u8; 288];
                l[..144].fill(8);
                l[144..256].fill(9);
                l[256..280].fill(7);
                l[280..].fill(8);
                block(&mut bits, &mut out, &Huffman::new(&l)?, &Huffman::new(&[5u8; 30])?)?;
            }
            2 => {
                let hlit = bits.bits(5)? as usize + 257;
                let hdist = bits.bits(5)? as usize + 1;
                let hclen = bits.bits(4)? as usize + 4;
                let mut cl = [0u8; 19];
                for &i in &CLEN_ORDER[..hclen] {
                    cl[i] = bits.bits(3)? as u8;
                }
                let clh = Huffman::new(&cl)?;
                let mut lengths = vec![0u8; hlit + hdist];
                let mut i = 0;
                while i < lengths.len() {
                    let sym = clh.decode(&mut bits)?;
                    let (val, rep) = match sym {
                        0..=15 => (sym as u8, 1),
                        16 => (*lengths.get(i.wrapping_sub(1)).ok_or_else(|| bad("repeat with no previous length"))?, 3 + bits.bits(2)?),
                        17 => (0, 3 + bits.bits(3)?),
                        18 => (0, 11 + bits.bits(7)?),
                        _ => return Err(bad("bad code-length symbol")),
                    };
                    let end = i + rep as usize;
                    lengths.get_mut(i..end).ok_or_else(|| bad("code lengths overflow"))?.fill(val);
                    i = end;
                }
                let (lit, dist) = lengths.split_at(hlit);
                block(&mut bits, &mut out, &Huffman::new(lit)?, &Huffman::new(dist)?)?;
            }
            _ => return Err(bad("reserved block type")),
        }
        if last == 1 {
            return Ok(out);
        }
    }
}

fn block(bits: &mut Bits, out: &mut Vec<u8>, lit: &Huffman, dist: &Huffman) -> io::Result<()> {
    loop {
        let sym = lit.decode(bits)? as usize;
        match sym {
            0..=255 => out.push(sym as u8),
            256 => return Ok(()),
            257..=285 => {
                let i = sym - 257;
                let len = LEN_BASE[i] as usize + bits.bits(LEN_EXTRA[i] as u32)? as usize;
                let d = dist.decode(bits)? as usize;
                if d >= 30 {
                    return Err(bad("bad distance symbol"));
                }
                let distance = DIST_BASE[d] as usize + bits.bits(DIST_EXTRA[d] as u32)? as usize;
                if distance > out.len() {
                    return Err(bad("distance beyond output"));
                }
                let start = out.len() - distance;
                if distance >= len {
                    out.extend_from_within(start..start + len);
                } else {
                    for k in 0..len {
                        let b = out[start + k];
                        out.push(b);
                    }
                }
            }
            _ => return Err(bad("bad literal/length symbol")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::inflate;

    #[test]
    fn stored_block() {
        // BFINAL=1, BTYPE=00, LEN=5, NLEN=!5, "hello"
        let src = [0x01, 0x05, 0x00, 0xfa, 0xff, b'h', b'e', b'l', b'l', b'o'];
        assert_eq!(inflate(&src, 0).unwrap(), b"hello");
    }

    #[test]
    fn fixed_huffman_with_back_reference() {
        // Raw deflate of b"abcabcabcabc" from Python's zlib (wbits=-15, level 9).
        let src = [0x4b, 0x4c, 0x4a, 0x4e, 0x84, 0x21, 0x00];
        assert_eq!(inflate(&src, 0).unwrap(), b"abcabcabcabc");
    }

    #[test]
    fn dynamic_huffman() {
        // testdata/dynamic.deflate: raw deflate (BTYPE=2) of dynamic.txt, made with zlib.
        let src = include_bytes!("../../testdata/dynamic.deflate");
        let want = include_bytes!("../../testdata/dynamic.txt");
        assert_eq!(inflate(src, 0).unwrap(), want);
    }

    #[test]
    fn rejects_truncated_input() {
        assert!(inflate(&[0x4b, 0x4c], 0).is_err());
    }
}

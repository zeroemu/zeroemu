//! ELF64 loader for Linux executables (arm64 or x86_64, matching the host),
//! plus the initial process stack (argv / envp / auxv) laid out the way the
//! Linux kernel does it.

use crate::arch::Arch;
use crate::errno::*;
use crate::mm::{AddressSpace, Backing, Placement, STACK_SIZE, STACK_TOP, page_down, page_up};
use crate::pagecache::PageSource;
use crate::paging::{PROT_EXEC, PROT_READ, PROT_WRITE};
use crate::phys::{self, PAGE};
use std::collections::BTreeMap;
use std::sync::Arc;

const PT_LOAD: u32 = 1;
const PT_INTERP: u32 = 3;
const PT_PHDR: u32 = 6;
const ET_DYN: u16 = 3;
const PF_X: u32 = 1;
const PF_W: u32 = 2;
const PF_R: u32 = 4;

/// Where a position-independent main executable goes (Linux's ELF_ET_DYN_BASE
/// for a 39-bit address space); interpreters go wherever mmap puts them.
const MAIN_PIE_BASE: u64 = 0x55_5555_0000;

pub struct Image {
    /// First mapped address of the image.
    pub lo: u64,
    pub entry: u64,
    pub bias: u64,
    pub phdr: u64,
    pub phnum: u64,
    pub end: u64,
    pub interp: Option<String>,
}

fn u16_at(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes(b[o..o + 2].try_into().unwrap())
}
fn u32_at(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes(b[o..o + 4].try_into().unwrap())
}
fn u64_at(b: &[u8], o: usize) -> u64 {
    u64::from_le_bytes(b[o..o + 8].try_into().unwrap())
}

struct Segment {
    vaddr: u64,
    offset: u64,
    filesz: u64,
    memsz: u64,
    prot: u32,
}

/// Loads an ELF image of `size` bytes into `mm`, its pages to come from the file
/// as they are touched. `is_interp` places a PIE anywhere free; otherwise PIEs go
/// at MAIN_PIE_BASE.
pub fn load(mm: &mut AddressSpace, src: &Arc<dyn PageSource>, size: u64, name: &str, is_interp: bool) -> Result<Image, String> {
    let bad = |what: &str| format!("{name}: {what}");
    let read = |off: u64, len: usize| src.read_bytes(off, len).map_err(|e| format!("{name}: read: errno {e}"));
    let file = read(0, size.min(64) as usize)?;
    if file.len() < 64 || &file[0..4] != b"\x7fELF" || file[4] != 2 {
        return Err(bad("not an ELF64 file"));
    }
    if u16_at(&file, 18) != Arch::HOST.elf_machine() {
        return Err(bad(&format!("not a {:?} binary", Arch::HOST)));
    }
    let e_type = u16_at(&file, 16);
    let phoff = u64_at(&file, 32);
    let phentsize = u16_at(&file, 54) as usize;
    let phnum = u16_at(&file, 56) as usize;
    if phoff.saturating_add((phnum * phentsize) as u64) > size || phentsize < 56 {
        return Err(bad("program headers out of range"));
    }
    let headers = read(phoff, phnum * phentsize)?;

    let mut segs = Vec::new();
    let mut interp = None;
    let mut phdr_vaddr = None;
    let mut first_load = None;
    for i in 0..phnum {
        let ph = &headers[i * phentsize..];
        let (p_type, p_flags) = (u32_at(ph, 0), u32_at(ph, 4));
        let (offset, vaddr, filesz, memsz) = (u64_at(ph, 8), u64_at(ph, 16), u64_at(ph, 32), u64_at(ph, 40));
        match p_type {
            PT_LOAD => {
                if offset.saturating_add(filesz) > size || filesz > memsz || vaddr.checked_add(memsz).is_none() {
                    return Err(bad("segment out of range"));
                }
                first_load.get_or_insert(vaddr.wrapping_sub(offset));
                let prot = (if p_flags & PF_R != 0 { PROT_READ } else { 0 })
                    | (if p_flags & PF_W != 0 { PROT_WRITE } else { 0 })
                    | (if p_flags & PF_X != 0 { PROT_EXEC } else { 0 });
                segs.push(Segment { vaddr, offset, filesz, memsz, prot });
            }
            PT_INTERP => {
                if offset.saturating_add(filesz) > size || filesz > PAGE {
                    return Err(bad("bad PT_INTERP"));
                }
                let raw = read(offset, filesz as usize)?;
                let s = raw.split(|&b| b == 0).next().unwrap_or(&raw);
                interp = Some(String::from_utf8_lossy(s).into_owned());
            }
            PT_PHDR => phdr_vaddr = Some(vaddr),
            _ => {}
        }
    }
    let lo = page_down(segs.iter().map(|s| s.vaddr).min().ok_or_else(|| bad("no loadable segments"))?);
    let hi = page_up(segs.iter().map(|s| s.vaddr + s.memsz).max().unwrap());
    let span = hi - lo;

    let bias = match (e_type == ET_DYN, is_interp) {
        (false, _) => 0,
        (true, false) => MAIN_PIE_BASE - lo,
        (true, true) => mm.map(Placement::Hint(0), span, 0, Backing::Anon).map_err(|e| bad(&format!("no room (errno {e})")))? - lo,
    };
    // Gaps between segments are inaccessible, as with Linux's loader.
    mm.map(Placement::Fixed(lo + bias), span, 0, Backing::Anon)
        .map_err(|e| bad(&format!("cannot map at {:#x} (errno {e})", lo + bias)))?;
    let in_step = segs.iter().all(|s| (s.vaddr ^ s.offset).is_multiple_of(PAGE));
    let apart = segs.windows(2).all(|w| page_up(w[0].vaddr + w[0].memsz) <= page_down(w[1].vaddr));
    if in_step && apart {
        for s in &segs {
            let start = page_down(s.vaddr);
            let (file_end, end) = (page_up(s.vaddr + s.filesz), page_up(s.vaddr + s.memsz));
            let mut anon_from = start;
            if s.filesz > 0 {
                let backing = Backing::File { src: src.clone(), offset: page_down(s.offset) };
                mm.map(Placement::Fixed(start + bias), file_end - start, s.prot, backing).map_err(|e| bad(&format!("errno {e}")))?;
                anon_from = file_end;
                // What follows the segment in the file's last page is the start of its zeros.
                let zeros = (file_end - (s.vaddr + s.filesz)).min(s.memsz - s.filesz) as usize;
                if zeros > 0 {
                    mm.write_force(s.vaddr + s.filesz + bias, &vec![0; zeros]).map_err(|e| bad(&format!("errno {e}")))?;
                }
            }
            if end > anon_from {
                mm.map(Placement::Fixed(anon_from + bias), end - anon_from, s.prot, Backing::Anon).map_err(|e| bad(&format!("errno {e}")))?;
            }
        }
    } else {
        // Segments that share pages can't be mapped from the file: pages get both's
        // contents and both's protection.
        let mut prot_of: BTreeMap<u64, u32> = BTreeMap::new();
        for s in &segs {
            for page in (page_down(s.vaddr)..page_up(s.vaddr + s.memsz)).step_by(PAGE as usize) {
                *prot_of.entry(page).or_insert(0) |= s.prot;
            }
        }
        for &page in prot_of.keys() {
            mm.protect(page + bias, PAGE, PROT_READ | PROT_WRITE).map_err(|e| bad(&format!("mprotect errno {e}")))?;
        }
        for s in &segs {
            mm.write_force(s.vaddr + bias, &read(s.offset, s.filesz as usize)?).map_err(|e| bad(&format!("errno {e}")))?;
        }
        for (&page, &prot) in &prot_of {
            mm.protect(page + bias, PAGE, prot).map_err(|e| bad(&format!("mprotect errno {e}")))?;
        }
    }

    Ok(Image {
        lo: lo + bias,
        entry: u64_at(&file, 24) + bias,
        bias,
        // No PT_PHDR: the headers sit at file offset phoff inside the first segment.
        phdr: phdr_vaddr.unwrap_or(first_load.unwrap_or(0).wrapping_add(phoff)) + bias,
        phnum: phnum as u64,
        end: hi + bias,
        interp,
    })
}

// Auxiliary vector keys.
const AT_NULL: u64 = 0;
const AT_PHDR: u64 = 3;
const AT_PHENT: u64 = 4;
const AT_PHNUM: u64 = 5;
const AT_PAGESZ: u64 = 6;
const AT_BASE: u64 = 7;
const AT_ENTRY: u64 = 9;
const AT_UID: u64 = 11;
const AT_EUID: u64 = 12;
const AT_GID: u64 = 13;
const AT_EGID: u64 = 14;
const AT_PLATFORM: u64 = 15;
const AT_HWCAP: u64 = 16;
const AT_CLKTCK: u64 = 17;
const AT_SECURE: u64 = 23;
const AT_RANDOM: u64 = 25;
const AT_HWCAP2: u64 = 26;
const AT_EXECFN: u64 = 31;

/// Maps the main stack and lays out argc/argv/envp/auxv; returns the initial SP.
pub fn build_stack(mm: &mut AddressSpace, main: &Image, interp_base: u64, argv: &[String], envp: &[String]) -> Result<u64, i64> {
    mm.map(Placement::Fixed(STACK_TOP - STACK_SIZE), STACK_SIZE, PROT_READ | PROT_WRITE, Backing::Anon)?;
    let mut sp = STACK_TOP;
    let mut push_bytes = |mm: &mut AddressSpace, data: &[u8]| -> Result<u64, i64> {
        sp -= data.len() as u64;
        mm.write(sp, data)?;
        Ok(sp)
    };
    // As Linux lays them out: the argv strings, then the envp strings, in
    // order upwards from argv[0]. app_process renames itself by overwriting
    // argv[0] through the end of argv[argc - 1].
    let mut block = Vec::new();
    let mut offsets = Vec::with_capacity(argv.len() + envp.len());
    for s in argv.iter().chain(envp) {
        offsets.push(block.len() as u64);
        block.extend_from_slice(s.as_bytes());
        block.push(0);
    }
    let strings = push_bytes(mm, &block)?;
    mm.arg_start = strings;
    mm.arg_end = strings + offsets.get(argv.len()).copied().unwrap_or(block.len() as u64);
    let argv_ptrs: Vec<u64> = offsets[..argv.len()].iter().map(|o| strings + o).collect();
    let envp_ptrs: Vec<u64> = offsets[argv.len()..].iter().map(|o| strings + o).collect();
    let execfn = argv_ptrs.first().copied().unwrap_or(0);
    let platform = push_bytes(mm, if Arch::HOST == Arch::Aarch64 { b"aarch64\0" } else { b"x86_64\0" })?;
    let mut random = [0u8; 16];
    phys::random_bytes(&mut random);
    let random = push_bytes(mm, &random)?;

    let auxv: [(u64, u64); 18] = [
        (AT_PHDR, main.phdr),
        (AT_PHENT, 56),
        (AT_PHNUM, main.phnum),
        (AT_PAGESZ, 4096),
        (AT_BASE, interp_base),
        (AT_ENTRY, main.entry),
        (AT_UID, 0),
        (AT_EUID, 0),
        (AT_GID, 0),
        (AT_EGID, 0),
        (AT_PLATFORM, platform),
        (AT_HWCAP, Arch::HOST.hwcap()),
        (AT_HWCAP2, 0),
        (AT_CLKTCK, 100),
        (AT_SECURE, 0),
        (AT_RANDOM, random),
        (AT_EXECFN, execfn),
        (AT_NULL, 0),
    ];
    let words = 1 + argv_ptrs.len() + 1 + envp_ptrs.len() + 1 + auxv.len() * 2;
    if words as u64 * 8 + (STACK_TOP - sp) > STACK_SIZE / 4 {
        return Err(E2BIG);
    }
    let start = (sp - words as u64 * 8) & !15;
    let mut table = Vec::with_capacity(words * 8);
    let mut push = |v: u64| table.extend_from_slice(&v.to_le_bytes());
    push(argv_ptrs.len() as u64);
    argv_ptrs.iter().for_each(|&p| push(p));
    push(0);
    envp_ptrs.iter().for_each(|&p| push(p));
    push(0);
    for (k, v) in auxv {
        push(k);
        push(v);
    }
    mm.write(start, &table)?;
    mm.set_name(STACK_TOP - STACK_SIZE, STACK_SIZE, "[stack]");
    mm.start_stack = start;
    Ok(start)
}

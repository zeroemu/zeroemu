//! ELF64 loader for Linux executables (arm64 or x86_64, matching the host), plus the initial process stack
//! (argv / envp / auxv) laid out the way the Linux kernel does it.

use crate::arch::Arch;
use crate::mem::{self, BLOCK, GuestMem};

const PT_LOAD: u32 = 1;
const PT_INTERP: u32 = 3;
const PT_PHDR: u32 = 6;
const ET_DYN: u16 = 3;

/// Where position-independent images get placed.
const MAIN_PIE_BIAS: u64 = 0x1000_0000;
pub const INTERP_BIAS: u64 = 0x1800_0000;

pub struct Image {
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

pub fn load(mem: &GuestMem, file: &[u8], name: &str, is_interp: bool) -> Result<Image, String> {
    if file.len() < 64 || &file[0..4] != b"\x7fELF" || file[4] != 2 {
        return Err(format!("{name}: not an ELF64 file"));
    }
    if u16_at(file, 18) != Arch::HOST.elf_machine() {
        return Err(format!("{name}: not a {:?} binary", Arch::HOST));
    }
    let e_type = u16_at(file, 16);
    let bias = match (e_type, is_interp) {
        (ET_DYN, false) => MAIN_PIE_BIAS,
        (ET_DYN, true) => INTERP_BIAS,
        _ => 0,
    };
    let entry = u64_at(file, 24) + bias;
    let phoff = u64_at(file, 32) as usize;
    let phentsize = u16_at(file, 54) as usize;
    let phnum = u16_at(file, 56) as usize;

    let mut img = Image {
        entry,
        bias,
        phdr: 0,
        phnum: phnum as u64,
        end: 0,
        interp: None,
    };
    let mut first_load_vaddr = None;

    for i in 0..phnum {
        let ph = &file[phoff + i * phentsize..];
        let p_type = u32_at(ph, 0);
        let p_offset = u64_at(ph, 8) as usize;
        let p_vaddr = u64_at(ph, 16);
        let p_filesz = u64_at(ph, 32) as usize;
        let p_memsz = u64_at(ph, 40);
        match p_type {
            PT_LOAD => {
                let dst = p_vaddr + bias;
                first_load_vaddr.get_or_insert(p_vaddr - u64_at(ph, 8));
                if dst < BLOCK || !mem.contains(dst, p_memsz) {
                    return Err(format!(
                        "segment {dst:#x}+{p_memsz:#x} outside guest memory"
                    ));
                }
                mem.write(dst, &file[p_offset..p_offset + p_filesz]);
                mem.slice(dst + p_filesz as u64, p_memsz - p_filesz as u64)
                    .unwrap()
                    .fill(0);
                img.end = img.end.max(dst + p_memsz);
            }
            PT_INTERP => {
                let raw = &file[p_offset..p_offset + p_filesz];
                let s = raw.split(|&b| b == 0).next().unwrap_or(raw);
                img.interp = Some(String::from_utf8_lossy(s).into_owned());
            }
            PT_PHDR => img.phdr = p_vaddr + bias,
            _ => {}
        }
    }
    if img.phdr == 0 {
        // No PT_PHDR: the headers sit at file offset phoff inside the first segment.
        img.phdr = first_load_vaddr.unwrap_or(0) + phoff as u64 + bias;
    }
    Ok(img)
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
const AT_HWCAP: u64 = 16;
const AT_CLKTCK: u64 = 17;
const AT_SECURE: u64 = 23;
const AT_RANDOM: u64 = 25;
const AT_HWCAP2: u64 = 26;
const AT_EXECFN: u64 = 31;

/// Builds the initial stack and returns the stack pointer to start with.
pub fn build_stack(
    mem: &GuestMem,
    top: u64,
    main: &Image,
    interp_base: u64,
    argv: &[String],
    envp: &[String],
) -> u64 {
    let mut sp = top;
    let mut push_bytes = |data: &[u8]| -> u64 {
        sp -= data.len() as u64;
        mem.write(sp, data);
        sp
    };

    let random = push_bytes(&rand_bytes());
    let mut str_ptrs = |list: &[String]| -> Vec<u64> {
        list.iter()
            .map(|s| {
                let mut b = s.clone().into_bytes();
                b.push(0);
                push_bytes(&b)
            })
            .collect()
    };
    let argv_ptrs = str_ptrs(argv);
    let envp_ptrs = str_ptrs(envp);
    let execfn = argv_ptrs.first().copied().unwrap_or(0);

    let auxv: Vec<(u64, u64)> = vec![
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
        (AT_HWCAP, Arch::HOST.hwcap()),
        (AT_HWCAP2, 0),
        (AT_CLKTCK, 100),
        (AT_SECURE, 0),
        (AT_RANDOM, random),
        (AT_EXECFN, execfn),
        (AT_NULL, 0),
    ];

    let words = 1 + argv_ptrs.len() + 1 + envp_ptrs.len() + 1 + auxv.len() * 2;
    let mut sp = (sp - words as u64 * 8) & !15;
    let start = sp;
    let mut push = |v: u64| {
        mem.write_u64(sp, v);
        sp += 8;
    };
    push(argv_ptrs.len() as u64);
    argv_ptrs.iter().for_each(|&p| push(p));
    push(0);
    envp_ptrs.iter().for_each(|&p| push(p));
    push(0);
    for (k, v) in auxv {
        push(k);
        push(v);
    }
    start
}

fn rand_bytes() -> [u8; 16] {
    let mut b = [0u8; 16];
    mem::random_bytes(&mut b);
    b
}

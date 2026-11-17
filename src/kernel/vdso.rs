//! The vDSO, for arm64 processes: a small shared library Linux maps into every
//! process and names in the auxiliary vector (AT_SYSINFO_EHDR), whose
//! __kernel_clock_gettime, __kernel_gettimeofday and __kernel_clock_getres bionic
//! calls in place of the syscalls (bionic/libc/bionic/vdso.cpp). They read the
//! clocks from the virtual counter and a read-only page of the kernel's numbers,
//! [vvar], and never leave the VM, where each syscall is a VM exit. Android reads
//! the clocks thousands of times a second: every Looper message, frame and log line.
//! Signal handlers return to its __kernel_rt_sigreturn, as on Linux.
//!
//! The image is vdso/vdso.S, built into vdso/vdso.so by scripts/build-vdso.sh and
//! checked in. As on Linux (arch/arm64/kernel/vdso.c), every process maps the same
//! pages of it, and [vvar] is the page just below. x86_64 guests get none, and
//! ZEROEMU_NO_VDSO=1 leaves it out, so that strace and ZEROEMU_SYSCOUNT see clock
//! calls again.

use super::clock;
use crate::arch::Arch;
use crate::mm::{AddressSpace, Backing, Placement, SharedObject};
use crate::paging::{PROT_EXEC, PROT_READ, USER_TOP};
use crate::phys::{PAGE, PhysMem};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering, fence};
use std::sync::{Arc, LazyLock, Mutex};

static IMAGE: &[u8] = include_bytes!("vdso/vdso.so");

/// Where [vvar] is, with the image above it. The same in every process, as fork
/// keeps them where bionic found them; below where the signal page is in processes
/// without them.
pub const VVAR: u64 = USER_TOP - 8 * PAGE;
pub const BASE: u64 = VVAR + PAGE;

// The [vvar] page, as vdso.S reads it.
/// A sequence count, odd while the host changes what follows (include/vdso/helpers.h).
const SEQ: usize = 0;
/// The clock ids the vDSO answers itself, as a bit mask (clock::SERVED).
const SERVED: usize = 4;
/// The counter at CLOCK_MONOTONIC's zero: 0, as hvf.rs sets each vCPU's offset.
const COUNTER_BASE: usize = 8;
/// numer and denom: a tick is numer / denom nanoseconds.
const MULT: usize = 16;
/// The CLOCK_MONOTONIC time, in nanoseconds, the clocks' rates count from
/// (clock::Line's base).
const TURN: usize = 24;
/// For each clock id below 32, 16 bytes: what it adds to CLOCK_MONOTONIC at TURN, in
/// nanoseconds, and how fast it gains on it from there, in 2^-32 ns per ns (signed).
/// The wall clocks have CLOCK_REALTIME's line (clock::Line); the others, zeros.
const CLOCKS: usize = 64;

/// Whether arm64 processes get the vDSO.
pub fn enabled() -> bool {
    static ON: LazyLock<bool> = LazyLock::new(|| Arch::HOST == Arch::Aarch64 && crate::hv::clock::GUEST_COUNTER && std::env::var_os("ZEROEMU_NO_VDSO").is_none_or(|v| v == "0"));
    *ON
}

/// AT_SYSINFO_EHDR for a new program: where the image is, if processes have one.
pub fn base() -> Option<u64> {
    enabled().then_some(BASE)
}

/// Where signal handlers return to, if processes have a vDSO: its
/// __kernel_rt_sigreturn.
pub fn sigreturn() -> Option<u64> {
    static AT: LazyLock<Option<u64>> = LazyLock::new(|| symbol("__kernel_rt_sigreturn").map(|v| BASE + v));
    if enabled() { *AT } else { None }
}

/// The value of a symbol the image exports, found through its section headers.
fn symbol(name: &str) -> Option<u64> {
    let b = IMAGE;
    let u16_at = |o: usize| u16::from_le_bytes(b[o..o + 2].try_into().unwrap()) as usize;
    let u32_at = |o: usize| u32::from_le_bytes(b[o..o + 4].try_into().unwrap()) as usize;
    let u64_at = |o: usize| u64::from_le_bytes(b[o..o + 8].try_into().unwrap()) as usize;
    let (shoff, shnum) = (u64_at(40), u16_at(60));
    let dynsym = (0..shnum).map(|i| shoff + i * 64).find(|&s| u32_at(s + 4) == 11)?;
    let (symtab, size, strtab) = (u64_at(dynsym + 24), u64_at(dynsym + 32), u32_at(dynsym + 40));
    let strtab = u64_at(shoff + strtab * 64 + 24);
    (0..size / 24).map(|i| symtab + i * 24).find_map(|s| {
        let n = strtab + u32_at(s);
        let end = n + b[n..].iter().position(|&c| c == 0)?;
        (b[n..end] == *name.as_bytes()).then(|| u64_at(s + 8) as u64)
    })
}

pub struct Vdso {
    image: Arc<SharedObject>,
    vvar: Arc<SharedObject>,
    /// The [vvar] page, where the host writes it. Its frame stays for as long as
    /// `vvar` does: an object without a pager keeps its pages in memory.
    data: usize,
    /// One writer at a time, for the sequence count.
    writing: Mutex<()>,
}

impl Vdso {
    /// The vDSO and its [vvar] page, filled in; None when processes don't get one.
    pub fn new(phys: &Arc<PhysMem>) -> Result<Option<Vdso>, i64> {
        if !enabled() {
            return Ok(None);
        }
        let image = SharedObject::new(phys.clone());
        image.write(0, IMAGE)?;
        let vvar = SharedObject::new(phys.clone());
        let data = phys.host(vvar.frame(0)?) as usize;
        let v = Vdso { image, vvar, data, writing: Mutex::new(()) };
        let (numer, denom) = crate::hv::clock::timebase();
        v.write(|| {
            v.u64(COUNTER_BASE).store(0, Ordering::Relaxed);
            v.u32(MULT).store(numer, Ordering::Relaxed);
            v.u32(MULT + 4).store(denom, Ordering::Relaxed);
            v.put_line(clock::line());
            v.u32(SERVED).store(clock::SERVED, Ordering::Relaxed);
        });
        Ok(Some(v))
    }

    /// Maps [vvar] and [vdso] into a new address space.
    pub fn map(&self, mm: &mut AddressSpace) -> Result<(), i64> {
        // Private file mappings of the objects map their own frames until written,
        // so every process reads the one [vvar] the host writes, and a process that
        // makes it writable and writes it changes only its own copy.
        mm.map(Placement::Fixed(VVAR), PAGE, PROT_READ, Backing::File { src: self.vvar.clone(), offset: 0 })?;
        mm.set_name(VVAR, PAGE, "[vvar]");
        let len = (IMAGE.len() as u64).next_multiple_of(PAGE);
        mm.map(Placement::Fixed(BASE), len, PROT_READ | PROT_EXEC, Backing::File { src: self.image.clone(), offset: 0 })?;
        mm.set_name(BASE, len, "[vdso]");
        Ok(())
    }

    /// Hands the vDSO CLOCK_REALTIME's new line, which `line` works out once the
    /// vDSO's readers can see it changing (clock.rs says why).
    pub(super) fn update(&self, line: impl FnOnce() -> clock::Line) {
        self.write(|| self.put_line(line()));
    }

    fn put_line(&self, line: clock::Line) {
        self.u64(TURN).store(line.base, Ordering::Relaxed);
        for id in 0..32 {
            let (offset, rate) = if clock::WALL >> id & 1 != 0 { (line.offset, line.rate) } else { (0, 0) };
            self.u64(CLOCKS + id * 16).store(offset, Ordering::Relaxed);
            self.u64(CLOCKS + id * 16 + 8).store(rate as u64, Ordering::Relaxed);
        }
    }

    /// Changes the page as Linux's write_seqcount_begin and _end do: the count goes
    /// odd, then the changes, then the count goes even. The fences order each step
    /// for readers on other CPUs, which here are guests in the vDSO.
    fn write(&self, f: impl FnOnce()) {
        let _one = self.writing.lock().unwrap();
        let seq = self.u32(SEQ);
        let n = seq.load(Ordering::Relaxed);
        seq.store(n.wrapping_add(1), Ordering::Relaxed);
        fence(Ordering::Release);
        f();
        seq.store(n.wrapping_add(2), Ordering::Release);
    }

    fn u32(&self, off: usize) -> &AtomicU32 {
        unsafe { AtomicU32::from_ptr((self.data + off) as *mut u32) }
    }

    fn u64(&self, off: usize) -> &AtomicU64 {
        unsafe { AtomicU64::from_ptr((self.data + off) as *mut u64) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn u16_at(b: &[u8], o: usize) -> u16 {
        u16::from_le_bytes(b[o..o + 2].try_into().unwrap())
    }
    fn u32_at(b: &[u8], o: usize) -> u32 {
        u32::from_le_bytes(b[o..o + 4].try_into().unwrap())
    }
    fn u64_at(b: &[u8], o: usize) -> u64 {
        u64::from_le_bytes(b[o..o + 8].try_into().unwrap())
    }
    fn cstr(b: &[u8], o: usize) -> &str {
        let end = b[o..].iter().position(|&c| c == 0).unwrap();
        std::str::from_utf8(&b[o..o + end]).unwrap()
    }

    /// What bionic's linker (add_vdso, soinfo::prelink_image) and libc
    /// (__libc_init_vdso) need of the image: a malformed one kills every dynamic
    /// process at start.
    #[test]
    fn image_is_what_bionic_reads() {
        let b = IMAGE;
        assert_eq!(&b[..4], b"\x7fELF");
        assert_eq!((b[4], b[5]), (2, 1), "ELFCLASS64, little-endian");
        assert_eq!(u16_at(b, 16), 3, "ET_DYN");
        assert_eq!(u16_at(b, 18), 183, "EM_AARCH64");
        assert!(b.len() as u64 <= 2 * PAGE, "it takes at most two pages");
        let (phoff, shoff) = (u64_at(b, 32) as usize, u64_at(b, 40) as usize);
        let (phnum, shnum) = (u16_at(b, 56) as usize, u16_at(b, 60) as usize);
        assert_eq!(u16_at(b, 54), 56);
        assert_eq!(u16_at(b, 58), 64);
        // The section headers are mapped too: libc counts symbols from them.
        assert!(shoff + shnum * 64 <= b.len());

        let mut loads = 0;
        let mut dynamic = None;
        for i in 0..phnum {
            let p = phoff + i * 56;
            let (ty, flags, off, vaddr, filesz) = (u32_at(b, p), u32_at(b, p + 4), u64_at(b, p + 8), u64_at(b, p + 16), u64_at(b, p + 32));
            match ty {
                1 => {
                    loads += 1;
                    assert_eq!((off, vaddr), (0, 0), "one PT_LOAD at 0, mapped as it is in the file");
                    assert_eq!(flags, 5, "read and execute");
                    assert!(filesz as usize <= b.len());
                }
                2 => dynamic = Some(off as usize),
                _ => {}
            }
        }
        assert_eq!(loads, 1);
        let dynamic = dynamic.expect("PT_DYNAMIC");

        let mut tags = std::collections::HashMap::new();
        let mut d = dynamic;
        loop {
            let (tag, val) = (u64_at(b, d), u64_at(b, d + 8));
            if tag == 0 {
                break;
            }
            tags.insert(tag, val);
            d += 16;
        }
        const DT_HASH: u64 = 4;
        const DT_STRTAB: u64 = 5;
        const DT_SYMTAB: u64 = 6;
        const DT_RELA: u64 = 7;
        const DT_SONAME: u64 = 14;
        const DT_REL: u64 = 17;
        const DT_JMPREL: u64 = 23;
        const DT_TEXTREL: u64 = 22;
        const DT_GNU_HASH: u64 = 0x6fff_fef5;
        const DT_VERSYM: u64 = 0x6fff_fff0;
        const DT_VERDEF: u64 = 0x6fff_fffc;
        for t in [DT_HASH, DT_GNU_HASH, DT_STRTAB, DT_SYMTAB, DT_SONAME, DT_VERSYM, DT_VERDEF] {
            assert!(tags.contains_key(&t), "dynamic tag {t:#x}");
        }
        for t in [DT_RELA, DT_REL, DT_JMPREL, DT_TEXTREL] {
            assert!(!tags.contains_key(&t), "nothing to relocate (tag {t:#x})");
        }
        let strtab = tags[&DT_STRTAB] as usize;
        assert_eq!(cstr(b, strtab + tags[&DT_SONAME] as usize), "linux-vdso.so.1");

        // The symbols, found as __libc_init_vdso finds them: the SHT_DYNSYM section's
        // size, and DT_SYMTAB and DT_STRTAB.
        let dynsym = (0..shnum).map(|i| shoff + i * 64).find(|&s| u32_at(b, s + 4) == 11).expect("SHT_DYNSYM");
        let count = u64_at(b, dynsym + 32) as usize / 24;
        let symtab = tags[&DT_SYMTAB] as usize;
        let versym = tags[&DT_VERSYM] as usize;
        // Version 2 is LINUX_2.6.39, after the image's own name (VER_FLG_BASE).
        let verdef = tags[&DT_VERDEF] as usize;
        let second = verdef + u32_at(b, verdef + 16) as usize;
        assert_eq!(u16_at(b, second + 4), 2);
        assert_eq!(cstr(b, strtab + u32_at(b, second + u32_at(b, second + 12) as usize) as usize), "LINUX_2.6.39");
        let mut found = Vec::new();
        for i in 0..count {
            let s = symtab + i * 24;
            let name = cstr(b, strtab + u32_at(b, s) as usize);
            if name.starts_with("__kernel_") {
                let value = u64_at(b, s + 8);
                assert!(value > 0 && (value as usize) < b.len(), "{name} is in the image");
                assert_eq!(b[s + 4] & 0xf, 2, "{name} is a function");
                assert_eq!(u16_at(b, versym + i * 2), 2, "{name} is LINUX_2.6.39");
                found.push(name);
            }
        }
        found.sort();
        assert_eq!(found, ["__kernel_clock_getres", "__kernel_clock_gettime", "__kernel_gettimeofday", "__kernel_rt_sigreturn"]);
    }

    /// Unwinders recognise a signal frame's return address by these instructions,
    /// and some look one instruction back from it.
    #[test]
    fn sigreturn_is_what_unwinders_look_for() {
        let at = symbol("__kernel_rt_sigreturn").unwrap() as usize;
        assert_eq!(u32_at(IMAGE, at - 4), 0xd503201f, "a nop before it");
        assert_eq!(u32_at(IMAGE, at), 0xd2801168, "mov x8, #139");
        assert_eq!(u32_at(IMAGE, at + 4), 0xd4000001, "svc #0");
        assert!(symbol("__kernel_clock_gettime").is_some());
        assert_eq!(symbol("nothing"), None);
    }

    /// The clock functions have unwind information, so a profiler's sample in one
    /// unwinds to its caller; the signal return has none, so that LLVM's libunwind
    /// and libgcc unwind out of a handler from the signal frame (vdso.S says why).
    /// Read from .eh_frame_hdr's table, as both find it.
    #[test]
    fn unwind_information_covers_the_clocks_not_sigreturn() {
        let b = IMAGE;
        let (phoff, phnum) = (u64_at(b, 32) as usize, u16_at(b, 56) as usize);
        let hdr = (0..phnum).map(|i| phoff + i * 56).find(|&p| u32_at(b, p) == 0x6474_e550).map(|p| u64_at(b, p + 8) as usize).expect("PT_GNU_EH_FRAME");
        // version 1; eh_frame_ptr pc-relative, the count a u32, the table of pairs
        // relative to the header, all 4 bytes signed (DW_EH_PE_*).
        assert_eq!(&b[hdr..hdr + 4], [1, 0x1b, 0x03, 0x3b]);
        let count = u32_at(b, hdr + 8) as usize;
        let mut covered = Vec::new();
        for i in 0..count {
            let e = hdr + 12 + i * 8;
            let start = (hdr as i64 + u32_at(b, e) as i32 as i64) as usize;
            let fde = (hdr as i64 + u32_at(b, e + 4) as i32 as i64) as usize;
            // The FDE's own start, pc-relative, agrees with the table; its length follows.
            assert_eq!((fde as i64 + 8 + u32_at(b, fde + 8) as i32 as i64) as usize, start);
            covered.push(start..start + u32_at(b, fde + 12) as usize);
        }
        let covers = |at: u64| covered.iter().any(|r| r.contains(&(at as usize)));
        for f in ["__kernel_clock_gettime", "__kernel_gettimeofday", "__kernel_clock_getres"] {
            assert!(covers(symbol(f).unwrap()), "{f} has unwind information");
        }
        let at = symbol("__kernel_rt_sigreturn").unwrap();
        for a in [at - 4, at, at + 4] {
            assert!(!covers(a), "nothing covers the signal return at {a:#x}");
        }
    }
}

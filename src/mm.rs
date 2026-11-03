//! Address spaces: a VMA list plus page tables we own, filled lazily from page
//! faults. Big PROT_NONE reservations (bionic's allocator takes ~8 GiB) cost
//! only VMA bookkeeping; pages exist once touched.

use crate::errno::*;
use crate::hv::{KernelPage, PageTableRoot};
use crate::paging::{self, KERNEL_WINDOW, PROT_EXEC, PROT_READ, PROT_WRITE, USER_TOP};
use crate::phys::{PAGE, PhysMem};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

/// Lowest mappable address (Linux's mmap_min_addr on Android).
pub const MIN_ADDR: u64 = 0x8000;
pub const STACK_TOP: u64 = USER_TOP - (16 << 20);
pub const STACK_SIZE: u64 = 8 << 20;
/// mmap allocates top-down from here (leaving room for the stack to grow).
const MMAP_BASE: u64 = STACK_TOP - (1 << 30);

pub fn page_down(v: u64) -> u64 {
    v & !(PAGE - 1)
}
pub fn page_up(v: u64) -> u64 {
    v.saturating_add(PAGE - 1) & !(PAGE - 1)
}

#[derive(Clone)]
pub enum Backing {
    Anon,
    /// Private copy of a read-only file; `offset` is the file offset of the VMA start.
    File { data: Arc<[u8]>, offset: u64 },
    /// MAP_SHARED memory: the object owns the frames, every mapping (in any
    /// address space) points at the same ones.
    Shared { obj: Arc<SharedObject>, offset: u64 },
}

/// Memory shared between mappings: tmpfs/memfd file contents and
/// MAP_SHARED|MAP_ANONYMOUS regions. Frames are allocated on first use and
/// freed when the last mapping or file reference goes away.
pub struct SharedObject {
    phys: Arc<PhysMem>,
    pages: Mutex<Vec<u64>>,
}

impl SharedObject {
    pub fn new(phys: Arc<PhysMem>) -> Arc<SharedObject> {
        Arc::new(SharedObject { phys, pages: Mutex::new(Vec::new()) })
    }

    /// The frame holding page `idx`, allocated (zeroed) if needed.
    pub fn frame(&self, idx: usize) -> Result<u64, i64> {
        let mut pages = self.pages.lock().unwrap();
        if pages.len() <= idx {
            pages.resize(idx + 1, 0);
        }
        if pages[idx] == 0 {
            pages[idx] = self.phys.alloc()?;
        }
        Ok(pages[idx])
    }

    pub fn read(&self, off: u64, buf: &mut [u8]) {
        let pages = self.pages.lock().unwrap();
        let mut done = 0;
        while done < buf.len() {
            let at = off + done as u64;
            let (idx, po) = ((at / PAGE) as usize, (at % PAGE) as usize);
            let n = (PAGE as usize - po).min(buf.len() - done);
            match pages.get(idx).copied().filter(|&f| f != 0) {
                Some(f) => unsafe { std::ptr::copy_nonoverlapping(self.phys.host(f).add(po), buf.as_mut_ptr().add(done), n) },
                None => buf[done..done + n].fill(0), // a hole
            }
            done += n;
        }
    }

    pub fn write(&self, off: u64, data: &[u8]) -> Result<(), i64> {
        let mut done = 0;
        while done < data.len() {
            let at = off + done as u64;
            let (idx, po) = ((at / PAGE) as usize, (at % PAGE) as usize);
            let n = (PAGE as usize - po).min(data.len() - done);
            let f = self.frame(idx)?;
            unsafe { std::ptr::copy_nonoverlapping(data.as_ptr().add(done), self.phys.host(f).add(po), n) };
            done += n;
        }
        Ok(())
    }

    /// Zeroes everything from `off` on (truncation). Frames stay allocated,
    /// since other address spaces may still map them.
    pub fn zero_from(&self, off: u64) {
        let pages = self.pages.lock().unwrap();
        for (idx, &f) in pages.iter().enumerate() {
            let start = idx as u64 * PAGE;
            if f == 0 || start + PAGE <= off {
                continue;
            }
            let from = off.saturating_sub(start) as usize;
            unsafe { self.phys.host(f).add(from).write_bytes(0, PAGE as usize - from) };
        }
    }
}

impl Drop for SharedObject {
    fn drop(&mut self) {
        for &f in self.pages.get_mut().unwrap().iter().filter(|&&f| f != 0) {
            self.phys.free(f);
        }
    }
}

/// What an unmap left behind: frames and shared objects that must outlive the
/// next TLB flush.
#[derive(Default)]
pub struct Stale {
    frames: Vec<u64>,
    objs: Vec<Arc<SharedObject>>,
}

impl Stale {
    pub fn release(&mut self, phys: &PhysMem) {
        for f in self.frames.drain(..) {
            phys.free(f);
        }
        self.objs.clear();
    }
}

#[derive(Clone)]
pub struct Vma {
    pub end: u64,
    pub prot: u32,
    pub backing: Backing,
}

pub enum Placement {
    /// MAP_FIXED: replace whatever is there.
    Fixed(u64),
    /// MAP_FIXED_NOREPLACE: fail if anything is there.
    NoReplace(u64),
    /// A hint (or 0): used if free, otherwise the next top-down gap.
    Hint(u64),
}

/// The kernel window's page table, shared by every address space.
pub struct KernelWindow {
    table: u64,
}

impl KernelWindow {
    pub fn new(phys: &PhysMem, pages: &[KernelPage]) -> Result<KernelWindow, i64> {
        let table = phys.alloc()?;
        let mut owned = Vec::new();
        for p in pages {
            assert!((KERNEL_WINDOW..KERNEL_WINDOW + (1 << 30)).contains(&p.va), "kernel page outside the window");
            let slot = walk(phys, &mut owned, table, paging::gib_level() + 1, p.va, true)?.unwrap();
            phys.write_u64(slot, paging::kernel_page(p.gpa, p.exec));
        }
        Ok(KernelWindow { table }) // these tables live as long as the VM
    }
}

/// Finds (optionally creating) the leaf entry for `va`, starting from `table`
/// at `level`. Returns the guest-physical address of the entry.
fn walk(phys: &PhysMem, owned: &mut Vec<u64>, mut table: u64, level: usize, va: u64, create: bool) -> Result<Option<u64>, i64> {
    let leaf = paging::levels() - 1;
    for l in level..leaf {
        let slot = table + paging::index(va, l) as u64 * 8;
        let e = phys.read_u64(slot);
        if paging::is_valid(e) {
            table = paging::addr(e);
            continue;
        }
        if !create {
            return Ok(None);
        }
        let t = phys.alloc()?;
        owned.push(t);
        phys.write_u64(slot, paging::table(t));
        table = t;
    }
    Ok(Some(table + paging::index(va, leaf) as u64 * 8))
}

pub struct AddressSpace {
    phys: Arc<PhysMem>,
    pub root: PageTableRoot,
    vmas: BTreeMap<u64, Vma>,
    /// Page-table frames owned by this address space.
    tables: Vec<u64>,
    pub brk_start: u64,
    pub brk: u64,
    /// Set when entries were removed or downgraded: vCPUs must flush before
    /// re-entering the guest, and `stale` frames may be freed only after that.
    pub tlb_dirty: bool,
    stale: Stale,
}

impl AddressSpace {
    pub fn new(phys: Arc<PhysMem>, kernel: &KernelWindow, asid: u16) -> Result<AddressSpace, i64> {
        let root = phys.alloc()?;
        let mut tables = vec![root];
        // Path down to the 1-GiB-level table, then hook in the shared window.
        let mut table = root;
        for l in 0..paging::gib_level() {
            let t = phys.alloc()?;
            tables.push(t);
            phys.write_u64(table + paging::index(KERNEL_WINDOW, l) as u64 * 8, paging::table(t));
            table = t;
        }
        phys.write_u64(table + paging::index(KERNEL_WINDOW, paging::gib_level()) as u64 * 8, paging::table(kernel.table));
        Ok(AddressSpace {
            phys,
            root: PageTableRoot { root, asid },
            vmas: BTreeMap::new(),
            tables,
            brk_start: 0,
            brk: 0,
            tlb_dirty: false,
            stale: Stale::default(),
        })
    }

    pub fn set_brk_start(&mut self, at: u64) {
        self.brk_start = page_up(at);
        self.brk = self.brk_start;
    }

    // ---- VMAs ----

    fn find(&self, addr: u64) -> Option<(u64, &Vma)> {
        let (&start, vma) = self.vmas.range(..=addr).next_back()?;
        (addr < vma.end).then_some((start, vma))
    }

    fn is_free(&self, start: u64, end: u64) -> bool {
        if start < MIN_ADDR || end > USER_TOP || start >= end {
            return false;
        }
        match self.vmas.range(..end).next_back() {
            Some((_, v)) => v.end <= start,
            None => true,
        }
    }

    /// Splits the VMA containing `at` (if any) so that a VMA boundary falls there.
    fn split(&mut self, at: u64) {
        let Some((start, vma)) = self.find(at) else { return };
        if start == at {
            return;
        }
        let mut right = vma.clone();
        if let Backing::File { offset, .. } | Backing::Shared { offset, .. } = &mut right.backing {
            *offset += at - start;
        }
        self.vmas.get_mut(&start).unwrap().end = at;
        self.vmas.insert(at, right);
    }

    fn gap(&self, len: u64) -> Result<u64, i64> {
        let mut top = MMAP_BASE;
        for (&start, vma) in self.vmas.range(..MMAP_BASE).rev() {
            if vma.end <= top && top - vma.end >= len {
                return Ok(top - len);
            }
            top = top.min(start);
        }
        if top >= MIN_ADDR + len { Ok(top - len) } else { Err(ENOMEM) }
    }

    pub fn map(&mut self, place: Placement, len: u64, prot: u32, backing: Backing) -> Result<u64, i64> {
        let len = page_up(len);
        if len == 0 {
            return Err(EINVAL);
        }
        let start = match place {
            Placement::Fixed(a) => {
                if a % PAGE != 0 || a < MIN_ADDR || a.saturating_add(len) > USER_TOP {
                    return Err(EINVAL);
                }
                self.unmap(a, len)?;
                a
            }
            Placement::NoReplace(a) => {
                if a % PAGE != 0 {
                    return Err(EINVAL);
                }
                if !self.is_free(a, a.saturating_add(len)) {
                    return Err(EEXIST);
                }
                a
            }
            Placement::Hint(h) => {
                let h = page_down(h);
                if h != 0 && self.is_free(h, h.saturating_add(len)) { h } else { self.gap(len)? }
            }
        };
        self.vmas.insert(start, Vma { end: start + len, prot, backing });
        Ok(start)
    }

    pub fn unmap(&mut self, start: u64, len: u64) -> Result<(), i64> {
        let end = start.saturating_add(page_up(len)).min(USER_TOP);
        if !start.is_multiple_of(PAGE) {
            return Err(EINVAL);
        }
        if start >= end {
            return Ok(());
        }
        self.split(start);
        self.split(end);
        let freed = self.clear_pages(start, end);
        let doomed: Vec<u64> = self.vmas.range(start..end).map(|(&s, _)| s).collect();
        for s in doomed {
            if let Some(Vma { backing: Backing::Shared { obj, .. }, .. }) = self.vmas.remove(&s) {
                self.stale.objs.push(obj);
            }
        }
        if freed {
            self.tlb_dirty = true;
        }
        Ok(())
    }

    /// Drops the pages of [start, start+len) but keeps the mappings, so later
    /// accesses see fresh zeros (or the file) — MADV_DONTNEED semantics.
    pub fn discard(&mut self, start: u64, len: u64) -> Result<(), i64> {
        if !start.is_multiple_of(PAGE) {
            return Err(EINVAL);
        }
        if self.clear_pages(start, start.saturating_add(page_up(len))) {
            self.tlb_dirty = true;
        }
        Ok(())
    }

    fn is_shared(&self, va: u64) -> bool {
        matches!(self.find(va), Some((_, Vma { backing: Backing::Shared { .. }, .. })))
    }

    /// Clears the present pages of [start, end): private frames go to `stale`,
    /// shared ones stay with their object. Returns whether anything was present.
    fn clear_pages(&mut self, start: u64, end: u64) -> bool {
        let mut cleared = Vec::new();
        self.visit(start, end, &mut |phys, slot, va, e| {
            phys.write_u64(slot, 0);
            cleared.push((va, paging::addr(e)));
        });
        let any = !cleared.is_empty();
        for (va, frame) in cleared {
            if !self.is_shared(va) {
                self.stale.frames.push(frame);
            }
        }
        any
    }

    pub fn protect(&mut self, start: u64, len: u64, prot: u32) -> Result<(), i64> {
        let end = start.saturating_add(page_up(len));
        if !start.is_multiple_of(PAGE) || end > USER_TOP {
            return Err(EINVAL);
        }
        // Linux fails with ENOMEM if any part of the range is unmapped.
        let mut cur = start;
        for (&s, v) in self.vmas.range(..end) {
            if v.end <= cur {
                continue;
            }
            if s > cur {
                return Err(ENOMEM);
            }
            cur = v.end;
            if cur >= end {
                break;
            }
        }
        if cur < end {
            return Err(ENOMEM);
        }
        self.split(start);
        self.split(end);
        for (_, v) in self.vmas.range_mut(start..end) {
            v.prot = prot;
        }
        let mut changed = false;
        self.visit(start, end, &mut |phys, slot, _va, e| {
            phys.write_u64(slot, paging::user_page(paging::addr(e), prot));
            changed = true;
        });
        self.tlb_dirty |= changed;
        Ok(())
    }

    /// Moves (or resizes) a mapping, carrying its pages along.
    pub fn remap(&mut self, old: u64, old_len: u64, new_len: u64, may_move: bool, fixed: Option<u64>) -> Result<u64, i64> {
        let (old_len, new_len) = (page_up(old_len), page_up(new_len));
        if !old.is_multiple_of(PAGE) || new_len == 0 {
            return Err(EINVAL);
        }
        let (vstart, vma) = self.find(old).ok_or(EFAULT)?;
        if old + old_len > vma.end {
            return Err(EFAULT);
        }
        let (prot, mut backing) = (vma.prot, vma.backing.clone());
        if fixed.is_none() && new_len <= old_len {
            self.unmap(old + new_len, old_len - new_len)?;
            return Ok(old);
        }
        if fixed.is_none() && self.is_free(old + old_len, old + new_len) {
            self.split(old);
            self.split(old + old_len);
            self.vmas.get_mut(&old).unwrap().end = old + new_len; // grow in place
            return Ok(old);
        }
        if !may_move {
            return Err(ENOMEM);
        }
        let dst = match fixed {
            Some(a) => {
                self.unmap(a, new_len)?;
                a
            }
            None => self.gap(new_len)?,
        };
        if let Backing::File { offset, .. } | Backing::Shared { offset, .. } = &mut backing {
            *offset += old - vstart;
        }
        let keep = old_len.min(new_len);
        let mut moves = Vec::new();
        self.visit(old, old + keep, &mut |phys, slot, va, e| {
            phys.write_u64(slot, 0);
            moves.push((va - old, e));
        });
        // Drop the old range (its moved pages are no longer in the tables).
        self.split(old);
        self.split(old + old_len);
        self.vmas.remove(&old);
        self.unmap(old + keep, old_len - keep)?;
        self.vmas.insert(dst, Vma { end: dst + new_len, prot, backing });
        for (off, e) in moves {
            let slot = walk(&self.phys, &mut self.tables, self.root.root, 0, dst + off, true)?.unwrap();
            self.phys.write_u64(slot, e);
        }
        self.tlb_dirty = true;
        Ok(dst)
    }

    pub fn set_brk(&mut self, want: u64) -> u64 {
        if want < self.brk_start {
            return self.brk;
        }
        let (old_end, new_end) = (page_up(self.brk), page_up(want));
        if new_end > old_end {
            if !self.is_free(old_end, new_end) || self.map(Placement::Fixed(old_end), new_end - old_end, PROT_READ | PROT_WRITE, Backing::Anon).is_err() {
                return self.brk;
            }
        } else if new_end < old_end && self.unmap(new_end, old_end - new_end).is_err() {
            return self.brk;
        }
        self.brk = want;
        self.brk
    }

    // ---- pages ----

    /// Calls `f(phys, entry_slot, va, entry)` for every present user page in [start, end).
    fn visit(&self, start: u64, end: u64, f: &mut dyn FnMut(&PhysMem, u64, u64, u64)) {
        fn rec(phys: &PhysMem, table: u64, level: usize, base: u64, start: u64, end: u64, f: &mut dyn FnMut(&PhysMem, u64, u64, u64)) {
            let span = 1u64 << (12 + 9 * (paging::levels() - 1 - level));
            let first = (start.max(base) - base) / span;
            let last = ((end.min(base + 512 * span) - base).div_ceil(span)).min(512);
            for i in first..last {
                let va = base + i * span;
                if level == paging::gib_level() && va == KERNEL_WINDOW {
                    continue; // shared, not ours
                }
                let slot = table + i * 8;
                let e = phys.read_u64(slot);
                if !paging::is_valid(e) {
                    continue;
                }
                if level == paging::levels() - 1 {
                    f(phys, slot, va, e);
                } else {
                    rec(phys, paging::addr(e), level + 1, va, start, end, f);
                }
            }
        }
        if start < end {
            rec(&self.phys, self.root.root, 0, 0, start, end.min(USER_TOP), f);
        }
    }

    /// Handles a guest page fault. `Err` means the access is invalid (SIGSEGV).
    pub fn fault(&mut self, addr: u64, write: bool, exec: bool) -> Result<(), ()> {
        let page = page_down(addr);
        let Some((start, vma)) = self.find(page) else { return Err(()) };
        let ok = if exec {
            vma.prot & PROT_EXEC != 0
        } else if write {
            vma.prot & PROT_WRITE != 0
        } else {
            vma.prot & (PROT_READ | PROT_WRITE | PROT_EXEC) != 0
        };
        if !ok {
            return Err(());
        }
        let (prot, vma) = (vma.prot, vma.clone());
        let slot = walk(&self.phys, &mut self.tables, self.root.root, 0, page, true).map_err(|_| ())?.unwrap();
        let e = self.phys.read_u64(slot);
        if paging::is_valid(e) {
            if !paging::permits(e, write, exec) {
                self.phys.write_u64(slot, paging::user_page(paging::addr(e), prot));
            }
            // Either way the entry now allows it; a stale TLB entry caused the fault.
            self.tlb_dirty = true;
            return Ok(());
        }
        let frame = self.populate(start, &vma, page).map_err(|_| ())?;
        self.phys.write_u64(slot, paging::user_page(frame, prot));
        Ok(())
    }

    fn populate(&self, vma_start: u64, vma: &Vma, page: u64) -> Result<u64, i64> {
        if let Backing::Shared { obj, offset } = &vma.backing {
            return obj.frame(((offset + (page - vma_start)) / PAGE) as usize);
        }
        let frame = self.phys.alloc()?;
        if let Backing::File { data, offset } = &vma.backing {
            let off = (offset + (page - vma_start)) as usize;
            if off < data.len() {
                let n = (data.len() - off).min(PAGE as usize);
                unsafe { std::ptr::copy_nonoverlapping(data.as_ptr().add(off), self.phys.host(frame), n) };
            }
        }
        Ok(frame)
    }

    /// Host pointer to the byte at `va`, faulting the page in. `force` skips
    /// protection checks (the ELF loader writes read-only segments).
    fn host_ptr(&mut self, va: u64, write: bool, force: bool) -> Result<*mut u8, i64> {
        let va = crate::arch::untag(va);
        let page = page_down(va);
        let (start, vma) = self.find(page).ok_or(EFAULT)?;
        if !force {
            let ok = if write { vma.prot & PROT_WRITE != 0 } else { vma.prot & (PROT_READ | PROT_WRITE | PROT_EXEC) != 0 };
            if !ok {
                return Err(EFAULT);
            }
        }
        let vma = vma.clone();
        let slot = walk(&self.phys, &mut self.tables, self.root.root, 0, page, true)?.unwrap();
        let mut e = self.phys.read_u64(slot);
        if !paging::is_valid(e) {
            let frame = self.populate(start, &vma, page)?;
            e = paging::user_page(frame, vma.prot);
            self.phys.write_u64(slot, e);
        }
        Ok(unsafe { self.phys.host(paging::addr(e)).add((va - page) as usize) })
    }

    fn copy(&mut self, va: u64, len: usize, write: bool, force: bool, mut f: impl FnMut(*mut u8, usize, usize)) -> Result<(), i64> {
        let mut done = 0;
        while done < len {
            let at = va + done as u64;
            let n = ((PAGE - at % PAGE) as usize).min(len - done);
            let p = self.host_ptr(at, write, force)?;
            f(p, done, n);
            done += n;
        }
        Ok(())
    }

    pub fn read(&mut self, va: u64, buf: &mut [u8]) -> Result<(), i64> {
        let dst = buf.as_mut_ptr();
        self.copy(va, buf.len(), false, false, |p, off, n| unsafe { std::ptr::copy_nonoverlapping(p, dst.add(off), n) })
    }

    pub fn read_vec(&mut self, va: u64, len: usize) -> Result<Vec<u8>, i64> {
        let mut v = vec![0; len];
        self.read(va, &mut v)?;
        Ok(v)
    }

    pub fn write(&mut self, va: u64, data: &[u8]) -> Result<(), i64> {
        let src = data.as_ptr();
        self.copy(va, data.len(), true, false, |p, off, n| unsafe { std::ptr::copy_nonoverlapping(src.add(off), p, n) })
    }

    /// Writes regardless of page protection (loading read-only ELF segments).
    pub fn write_force(&mut self, va: u64, data: &[u8]) -> Result<(), i64> {
        let src = data.as_ptr();
        self.copy(va, data.len(), true, true, |p, off, n| unsafe { std::ptr::copy_nonoverlapping(src.add(off), p, n) })
    }

    pub fn read_u64(&mut self, va: u64) -> Result<u64, i64> {
        let mut b = [0u8; 8];
        self.read(va, &mut b)?;
        Ok(u64::from_le_bytes(b))
    }

    pub fn write_u64(&mut self, va: u64, v: u64) -> Result<(), i64> {
        self.write(va, &v.to_le_bytes())
    }

    pub fn read_u32(&mut self, va: u64) -> Result<u32, i64> {
        let mut b = [0u8; 4];
        self.read(va, &mut b)?;
        Ok(u32::from_le_bytes(b))
    }

    pub fn write_u32(&mut self, va: u64, v: u32) -> Result<(), i64> {
        self.write(va, &v.to_le_bytes())
    }

    /// A NUL-terminated string of at most 4 KiB (PATH_MAX).
    pub fn read_cstr(&mut self, va: u64) -> Result<String, i64> {
        let mut out = Vec::new();
        for i in 0..4096 {
            let mut b = [0u8; 1];
            self.read(va + i, &mut b)?;
            if b[0] == 0 {
                return Ok(String::from_utf8_lossy(&out).into_owned());
            }
            out.push(b[0]);
        }
        Err(ENAMETOOLONG)
    }

    // ---- lifecycle ----

    /// fork(): private pages are copied (eagerly; copy-on-write comes later),
    /// shared ones stay shared.
    pub fn fork(&self, kernel: &KernelWindow, asid: u16) -> Result<AddressSpace, i64> {
        let mut child = AddressSpace::new(self.phys.clone(), kernel, asid)?;
        child.vmas = self.vmas.clone();
        child.brk_start = self.brk_start;
        child.brk = self.brk;
        let mut pages = Vec::new();
        self.visit(0, USER_TOP, &mut |_, _, va, e| pages.push((va, e)));
        for (va, e) in pages {
            let frame = if self.is_shared(va) {
                paging::addr(e) // MAP_SHARED: both processes see the same frame
            } else {
                let f = self.phys.alloc()?;
                unsafe { std::ptr::copy_nonoverlapping(self.phys.host(paging::addr(e)), self.phys.host(f), PAGE as usize) };
                f
            };
            let slot = walk(&self.phys, &mut child.tables, child.root.root, 0, va, true)?.unwrap();
            self.phys.write_u64(slot, (e & !paging::addr(u64::MAX)) | frame);
        }
        Ok(child)
    }

    /// What was unmapped since the last flush; release it once that happened.
    pub fn take_stale(&mut self) -> Stale {
        std::mem::take(&mut self.stale)
    }

}

impl Drop for AddressSpace {
    fn drop(&mut self) {
        // Callers flush TLBs before dropping a space a vCPU may still cache
        // (exec switches roots first; exited processes have no vCPUs left).
        let mut pages = Vec::new();
        self.visit(0, USER_TOP, &mut |_, _, va, e| pages.push((va, paging::addr(e))));
        for (va, frame) in pages {
            if !self.is_shared(va) {
                self.phys.free(frame);
            }
        }
        let phys = self.phys.clone();
        self.stale.release(&phys);
        for f in self.tables.drain(..) {
            phys.free(f);
        }
    }
}

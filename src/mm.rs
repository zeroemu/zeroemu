//! Address spaces: a VMA list plus page tables we own, filled lazily from page
//! faults. Big PROT_NONE reservations (bionic's allocator takes ~8 GiB) cost
//! only VMA bookkeeping; pages exist once touched.

use crate::errno::*;
use crate::hv::{KernelPage, PageTableRoot};
use crate::pagecache::{PageCache, PageSource};
use crate::paging::{self, KERNEL_WINDOW, PROT_EXEC, PROT_READ, PROT_WRITE, USER_TOP};
use crate::phys::{PAGE, PhysMem};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, Weak};

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
    /// A private mapping of a file: its pages are shared until written, then
    /// copied; `offset` is the file offset of the VMA start.
    File { src: Arc<dyn PageSource>, offset: u64 },
    /// MAP_SHARED memory: the object owns the frames, every mapping (in any
    /// address space) points at the same ones.
    Shared { obj: Arc<SharedObject>, offset: u64 },
    /// Guest-physical pages that are not RAM (a GPU blob mapped above
    /// `PHYS_MAX`). The frames are not allocated or freed here; the last
    /// `DevMem` reference unmaps the GPA, and only after a TLB flush when
    /// the unmap path parked it in `Stale`.
    Dev { mem: Arc<DevMem>, offset: u64 },
}

/// One device-memory mapping. `on_drop` runs when the last reference goes,
/// which for an unmapped VMA is after the TLB flush (`Stale`).
pub struct DevMem {
    pub gpa: u64,
    pub len: u64,
    on_drop: Mutex<Option<Box<dyn FnOnce() + Send>>>,
}

impl DevMem {
    pub fn new(gpa: u64, len: u64, on_drop: impl FnOnce() + Send + 'static) -> Arc<DevMem> {
        Arc::new(DevMem { gpa, len, on_drop: Mutex::new(Some(Box::new(on_drop))) })
    }
}

impl Drop for DevMem {
    fn drop(&mut self) {
        if let Some(f) = self.on_drop.lock().unwrap().take() {
            f();
        }
    }
}

/// One page of a shared object.
#[derive(Clone, Copy, Default)]
struct Slot {
    /// The frame holding it, if it is in memory, or'd with REFERENCED and DIRTY.
    frame: u64,
    /// Where it can be read back from (see `pagecache::Store`), or 0.
    kept: u64,
    /// The clock has an entry for it: one is enough, whatever has happened since.
    on_clock: bool,
}

/// In a page's `frame`: looked at since the clock last came by.
const REFERENCED: u64 = 1;
/// In a page's `frame`: different from what is kept, so it must be written out to
/// leave memory. A page that has been mapped shared counts: nothing would say.
const DIRTY: u64 = 2;
const FLAGS: u64 = REFERENCED | DIRTY;

/// More pages than a file can have (`tmpfs`'s limit), which would otherwise mean a
/// huge index for a mapping at some huge offset.
const MAX_PAGES: usize = 1 << 28;

/// Memory shared between mappings: tmpfs/memfd file contents and
/// MAP_SHARED|MAP_ANONYMOUS regions. Frames are allocated on first use and
/// freed when the last mapping or file reference goes away.
///
/// With a pager (files on /data), pages nothing has mapped can leave memory for
/// the host's disk when the page cache makes room, and come back when wanted.
pub struct SharedObject {
    phys: Arc<PhysMem>,
    me: Weak<SharedObject>,
    pager: Option<Arc<PageCache>>,
    pages: Mutex<Vec<Slot>>,
}

impl SharedObject {
    pub fn new(phys: Arc<PhysMem>) -> Arc<SharedObject> {
        Self::with_pager(phys, None)
    }

    pub fn with_pager(phys: Arc<PhysMem>, pager: Option<Arc<PageCache>>) -> Arc<SharedObject> {
        Arc::new_cyclic(|me| SharedObject { phys, me: me.clone(), pager, pages: Mutex::new(Vec::new()) })
    }

    /// The frame holding page `idx`, which must exist in `pages`, brought into memory
    /// if it isn't there (read back if `fill`, because all of it won't be overwritten).
    fn in_memory(&self, pages: &mut [Slot], idx: usize, fill: bool) -> Result<u64, i64> {
        let slot = &mut pages[idx];
        if slot.frame != 0 {
            slot.frame |= REFERENCED;
            return Ok(slot.frame & !FLAGS);
        }
        let frame = self.phys.alloc()?;
        if let Some(pager) = &self.pager {
            if fill && slot.kept != 0 {
                let page = unsafe { std::slice::from_raw_parts_mut(self.phys.host(frame), PAGE as usize) };
                if let Err(e) = pager.store().read(slot.kept, page) {
                    self.phys.free(frame);
                    return Err(e);
                }
            }
            self.phys.mark_cached(frame);
            if !slot.on_clock {
                slot.on_clock = true;
                pager.watch_object(self.me.clone(), idx as u32);
            }
        }
        slot.frame = frame | REFERENCED;
        Ok(frame)
    }

    fn let_go(&self, frame: u64) {
        if self.pager.is_some() {
            self.phys.release_cached(frame);
        } else {
            self.phys.free(frame);
        }
    }

    fn make_room(&self) {
        if let Some(pager) = &self.pager {
            pager.balance();
        }
    }

    /// The frame holding page `idx`, allocated (zeroed) if needed. On an object with a
    /// pager it stays there only as long as something has it mapped.
    pub fn frame(&self, idx: usize) -> Result<u64, i64> {
        if idx >= MAX_PAGES {
            return Err(EFAULT);
        }
        let frame = {
            let mut pages = self.pages.lock().unwrap();
            if pages.len() <= idx {
                pages.resize(idx + 1, Slot::default());
            }
            self.in_memory(&mut pages, idx, true)?
        };
        self.make_room();
        Ok(frame)
    }

    /// The frame for a shared mapping of page `idx`, with a hold on it for that mapping.
    pub fn map_frame(&self, idx: usize) -> Result<u64, i64> {
        if idx >= MAX_PAGES {
            return Err(EFAULT);
        }
        let frame = {
            let mut pages = self.pages.lock().unwrap();
            if pages.len() <= idx {
                pages.resize(idx + 1, Slot::default());
            }
            let frame = self.in_memory(&mut pages, idx, true)?;
            pages[idx].frame |= DIRTY;
            self.phys.share(frame);
            frame
        };
        self.make_room();
        Ok(frame)
    }

    /// For an object that holds all its pages in memory (no pager), so can't fail.
    pub fn read(&self, off: u64, buf: &mut [u8]) {
        if self.try_read(off, buf).is_err() {
            buf.fill(0);
        }
    }

    /// Reads, or fails if a page that left memory can't be read back: its contents are
    /// still somewhere, and nobody should take zeros for them.
    pub fn try_read(&self, off: u64, buf: &mut [u8]) -> Result<(), i64> {
        let pages = self.pages.lock().unwrap();
        let mut done = 0;
        while done < buf.len() {
            let at = off + done as u64;
            let (idx, po) = ((at / PAGE) as usize, (at % PAGE) as usize);
            let n = (PAGE as usize - po).min(buf.len() - done);
            let dst = &mut buf[done..done + n];
            match pages.get(idx).copied().unwrap_or_default() {
                Slot { frame, .. } if frame != 0 => unsafe { std::ptr::copy_nonoverlapping(self.phys.host(frame & !FLAGS).add(po), dst.as_mut_ptr(), n) },
                // Straight from where it is kept: reading a file doesn't bring it in.
                Slot { kept, .. } if kept != 0 => self.pager.as_ref().ok_or(EIO)?.store().read(kept + po as u64, dst)?,
                _ => dst.fill(0), // a hole
            }
            done += n;
        }
        Ok(())
    }

    pub fn write(&self, off: u64, data: &[u8]) -> Result<(), i64> {
        {
            let mut pages = self.pages.lock().unwrap();
            let mut done = 0;
            while done < data.len() {
                let at = off + done as u64;
                let (idx, po) = ((at / PAGE) as usize, (at % PAGE) as usize);
                let n = (PAGE as usize - po).min(data.len() - done);
                if pages.len() <= idx {
                    pages.resize(idx + 1, Slot::default());
                }
                let f = self.in_memory(&mut pages, idx, n != PAGE as usize)?;
                unsafe { std::ptr::copy_nonoverlapping(data.as_ptr().add(done), self.phys.host(f).add(po), n) };
                pages[idx].frame |= DIRTY;
                done += n;
            }
        }
        self.make_room();
        Ok(())
    }

    /// Whether the page holding `off` has contents.
    #[cfg(test)]
    pub fn has_frame(&self, off: u64) -> bool {
        self.pages.lock().unwrap().get((off / PAGE) as usize).is_some_and(|s| s.frame != 0 || s.kept != 0)
    }

    /// Whether the page holding `off` is in memory.
    pub fn in_memory_now(&self, off: u64) -> bool {
        self.pages.lock().unwrap().get((off / PAGE) as usize).is_some_and(|s| s.frame != 0)
    }

    /// The offsets of the pages with contents, up to `end`.
    pub fn pages_with_contents(&self, end: u64) -> Vec<u64> {
        let pages = self.pages.lock().unwrap();
        pages.iter().enumerate().map(|(i, s)| (i as u64 * PAGE, s)).take_while(|(off, _)| *off < end).filter(|(_, s)| s.frame != 0 || s.kept != 0).map(|(off, _)| off).collect()
    }

    /// Zeroes everything from `off` on (truncation). Pages wholly past it go,
    /// unless something still maps them: those just read as zeros. Fails if the page it
    /// cuts in two can't be read back, which leaves that page as it was.
    pub fn zero_from(&self, off: u64) -> Result<(), i64> {
        let mut pages = self.pages.lock().unwrap();
        for idx in 0..pages.len() {
            let start = idx as u64 * PAGE;
            if start + PAGE <= off {
                continue;
            }
            let from = off.saturating_sub(start) as usize;
            let slot = pages[idx];
            if slot.frame == 0 && slot.kept == 0 {
                continue;
            }
            if from == 0 && (slot.frame == 0 || self.phys.is_sole_owner(slot.frame & !FLAGS)) {
                if slot.frame != 0 {
                    self.let_go(slot.frame & !FLAGS);
                }
                self.forget_kept(slot.kept);
                // The clock's entry, if any, stays until it comes up.
                pages[idx] = Slot { on_clock: slot.on_clock, ..Slot::default() };
                continue;
            }
            // Something of it stays: a page that isn't here comes back to be cut short.
            let f = self.in_memory(&mut pages, idx, true)?;
            unsafe { self.phys.host(f).add(from).write_bytes(0, PAGE as usize - from) };
            pages[idx].frame |= DIRTY;
        }
        Ok(())
    }

    fn forget_kept(&self, kept: u64) {
        if let Some(pager) = &self.pager {
            pager.store().forget(kept);
        }
    }

    /// Says where page `idx` can be read from, for a file coming back from disk.
    pub fn adopt(&self, idx: usize, kept: u64) {
        let mut pages = self.pages.lock().unwrap();
        if pages.len() <= idx {
            pages.resize(idx + 1, Slot::default());
        }
        pages[idx].kept = kept;
    }

    /// The clock has come to page `idx`: returns whether it should come back, which
    /// is if the page is still in memory afterwards.
    pub fn try_evict(&self, idx: u32) -> bool {
        let Some(pager) = &self.pager else { return false };
        let mut pages = self.pages.lock().unwrap();
        let Some(slot) = pages.get_mut(idx as usize) else { return false };
        if slot.frame == 0 {
            slot.on_clock = false;
            return false;
        }
        let frame = slot.frame & !FLAGS;
        if slot.frame & REFERENCED != 0 || !self.phys.is_sole_owner(frame) {
            slot.frame &= !REFERENCED;
            return true;
        }
        if slot.frame & DIRTY != 0 {
            let page = unsafe { std::slice::from_raw_parts(self.phys.host(frame), PAGE as usize) };
            match pager.store().write(slot.kept, page) {
                Ok(kept) => slot.kept = kept,
                Err(_) => return true, // no room on the host's disk: it stays here
            }
        }
        slot.frame = 0;
        slot.on_clock = false;
        self.phys.release_cached(frame);
        false
    }

    /// Whether the clock has any reason to come back to page `idx`.
    pub fn still_in_memory(&self, idx: u32) -> bool {
        let mut pages = self.pages.lock().unwrap();
        let Some(slot) = pages.get_mut(idx as usize) else { return false };
        if slot.frame == 0 {
            slot.on_clock = false;
            return false;
        }
        true
    }
}

/// A private mapping of the object: its pages until they are written. What is
/// written to the file before that shows through, as on Linux.
impl PageSource for SharedObject {
    fn page(&self, idx: u64) -> Result<Option<u64>, i64> {
        let frame = {
            let mut pages = self.pages.lock().unwrap();
            let idx = idx as usize;
            if !pages.get(idx).is_some_and(|s| s.frame != 0 || s.kept != 0) {
                return Ok(None);
            }
            let frame = self.in_memory(&mut pages, idx, true)?;
            self.phys.share(frame);
            frame
        };
        self.make_room();
        Ok(Some(frame))
    }

    fn read_bytes(&self, off: u64, len: usize) -> Result<Vec<u8>, i64> {
        let mut v = vec![0; len];
        self.try_read(off, &mut v)?;
        Ok(v)
    }
}

impl Drop for SharedObject {
    fn drop(&mut self) {
        for slot in std::mem::take(self.pages.get_mut().unwrap()) {
            if slot.frame != 0 {
                self.let_go(slot.frame & !FLAGS);
            }
            self.forget_kept(slot.kept);
        }
    }
}

/// What an unmap left behind: frames and shared objects that must outlive the
/// next TLB flush.
#[derive(Default)]
pub struct Stale {
    frames: Vec<u64>,
    objs: Vec<Arc<SharedObject>>,
    devs: Vec<Arc<DevMem>>,
}

/// `prot` without write access. A write-only mapping stays readable, as it is
/// on arm64: no entry grants EL0 write without read, and no access at all would
/// fault forever.
fn read_only(prot: u32) -> u32 {
    if prot & PROT_WRITE != 0 { (prot & !PROT_WRITE) | PROT_READ } else { prot }
}

impl Stale {
    pub fn absorb(&mut self, other: Stale) {
        self.frames.extend(other.frames);
        self.objs.extend(other.objs);
        self.devs.extend(other.devs);
    }

    pub fn release(&mut self, phys: &PhysMem) {
        for f in self.frames.drain(..) {
            phys.free(f);
        }
        self.objs.clear();
        // Device GPAs are unmapped here, after the TLB flush that made the
        // translations go away.
        self.devs.clear();
    }
}

/// A userfaultfd, as its registered mappings know it. When it closes, they go back
/// to being ordinary memory.
#[derive(Default)]
pub struct UffdCtx {
    pub open: AtomicBool,
}

/// `AddressSpace::fault`'s answer for a page a userfaultfd must supply: SIGBUS.
pub const FAULT_UFFD: i32 = -1;

/// What fork does with a mapping (madvise; binder's area is never inherited).
#[derive(Clone, Copy, PartialEq, Default)]
pub enum OnFork {
    #[default]
    Copy,
    /// MADV_DONTFORK: the child does not have it.
    Drop,
    /// MADV_WIPEONFORK: the child reads zeros.
    Wipe,
}

#[derive(Clone)]
pub struct Vma {
    pub end: u64,
    pub prot: u32,
    pub backing: Backing,
    pub on_fork: OnFork,
    /// Shown in /proc/<pid>/maps (a file path, "[stack]", …).
    pub name: Option<Arc<str>>,
    /// The userfaultfd that supplies this mapping's missing pages.
    pub uffd: Option<Arc<UffdCtx>>,
}

impl Vma {
    /// The userfaultfd in charge, if it is still open.
    fn uffd(&self) -> Option<&Arc<UffdCtx>> {
        self.uffd.as_ref().filter(|c| c.open.load(Ordering::Relaxed))
    }
}

/// (start, end, prot, shared, file offset, name) of one mapping.
pub type MapEntry = (u64, u64, u32, bool, u64, Option<Arc<str>>);

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
            let slot = walk(phys, 0, &mut owned, table, paging::gib_level() + 1, p.va, true)?.unwrap();
            phys.write_u64(slot, paging::kernel_page(p.gpa, p.exec));
        }
        Ok(KernelWindow { table }) // these tables live as long as the VM
    }
}

fn bump_offset(b: &mut Backing, add: u64) {
    match b {
        Backing::File { offset, .. } | Backing::Shared { offset, .. } | Backing::Dev { offset, .. } => *offset += add,
        Backing::Anon => {}
    }
}

/// Finds (optionally creating) the leaf entry for `va`, starting from `table`
/// at `level`. Returns the guest-physical address of the entry.
fn walk(phys: &PhysMem, owner: u32, owned: &mut Vec<u64>, mut table: u64, level: usize, va: u64, create: bool) -> Result<Option<u64>, i64> {
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
        let t = phys.alloc_for(owner)?;
        owned.push(t);
        phys.write_pte(slot, paging::table(t));
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
    /// The stack pointer exec started the program with (/proc/<pid>/stat
    /// startstack: bionic finds the main thread's stack mapping by it).
    pub start_stack: u64,
    /// Where argv's strings are: /proc/<pid>/cmdline reads them from here, so
    /// that a process that overwrites them (app_process) is seen renamed.
    pub arg_start: u64,
    pub arg_end: u64,
    pub brk: u64,
    /// Bumped when entries are removed or downgraded. `flushed_gen` catches up
    /// once a TLB flush has run in the guest. A thread behind on this flushes
    /// before re-entering, even if another thread has asked for a flush too:
    /// that one may be preempted, and this thread must not run on old entries.
    /// `stale` frames may be freed only after the flush.
    pub tlb_gen: u64,
    pub flushed_gen: u64,
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
            start_stack: 0,
            arg_start: 0,
            arg_end: 0,
            brk: 0,
            tlb_gen: 0,
            flushed_gen: 0,
            stale: Stale::default(),
        })
    }

    /// Who to allocate frames as, so that a process's sit together.
    fn owner(&self) -> u32 {
        self.root.asid as u32 + 1
    }

    pub fn set_brk_start(&mut self, at: u64) {
        self.brk_start = page_up(at);
        self.brk = self.brk_start;
    }

    // ---- VMAs ----

    /// The mapping at `addr`, as a crash report shows it.
    pub fn describe(&self, addr: u64) -> String {
        let addr = crate::arch::untag(addr);
        let Some((start, v)) = self.find(addr) else { return "no mapping".into() };
        let kind = match &v.backing {
            Backing::Anon => "anon",
            Backing::File { .. } => "file",
            Backing::Shared { .. } => "shared",
            Backing::Dev { .. } => "device",
        };
        let p = |bit: u32, c: char| if v.prot & bit != 0 { c } else { '-' };
        format!("{start:#x}-{:#x} {}{}{} {kind} {}", v.end, p(PROT_READ, 'r'), p(PROT_WRITE, 'w'), p(PROT_EXEC, 'x'), v.name.as_deref().unwrap_or(""))
    }

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
        bump_offset(&mut right.backing, at - start);
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
        self.vmas.insert(start, Vma { end: start + len, prot, backing, on_fork: OnFork::Copy, name: None, uffd: None });
        Ok(start)
    }

    /// Labels the mappings in [start, start+len) for /proc/<pid>/maps.
    pub fn set_name(&mut self, start: u64, len: u64, name: &str) {
        let end = start.saturating_add(page_up(len));
        self.split(start);
        self.split(end);
        let name: Arc<str> = name.into();
        for (_, v) in self.vmas.range_mut(start..end) {
            v.name = Some(name.clone());
        }
        self.merge(start, end);
    }

    /// Rejoins mappings around [lo, hi] that became identical, as Linux does
    /// after mprotect: mremap needs its source in one mapping, and bionic's
    /// atexit array is mprotected page by page, then grown with mremap.
    fn merge(&mut self, lo: u64, hi: u64) {
        fn joins(a_start: u64, a: &Vma, b_start: u64, b: &Vma) -> bool {
            let contiguous = |o1: &u64, o2: &u64| o1 + (a.end - a_start) == *o2;
            a.end == b_start
                && a.prot == b.prot
                && a.on_fork == b.on_fork
                && a.name == b.name
                && match (a.uffd(), b.uffd()) {
                    (None, None) => true,
                    (Some(x), Some(y)) => Arc::ptr_eq(x, y),
                    _ => false,
                }
                && match (&a.backing, &b.backing) {
                    (Backing::Anon, Backing::Anon) => true,
                    (Backing::File { src: s1, offset: o1 }, Backing::File { src: s2, offset: o2 }) => std::ptr::addr_eq(Arc::as_ptr(s1), Arc::as_ptr(s2)) && contiguous(o1, o2),
                    (Backing::Shared { obj: s1, offset: o1 }, Backing::Shared { obj: s2, offset: o2 }) => Arc::ptr_eq(s1, s2) && contiguous(o1, o2),
                    _ => false,
                }
        }
        let mut cur = self.vmas.range(..lo).next_back().or_else(|| self.vmas.range(lo..).next()).map(|(&s, _)| s);
        while let Some(s) = cur {
            let Some(n) = self.vmas.range(s + 1..).next().map(|(&n, _)| n) else { break };
            if n > hi {
                break;
            }
            if joins(s, &self.vmas[&s], n, &self.vmas[&n]) {
                let right = self.vmas.remove(&n).unwrap();
                self.vmas.get_mut(&s).unwrap().end = right.end;
            } else {
                cur = Some(n);
            }
        }
    }

    /// Every mapping, for /proc/<pid>/maps.
    pub fn maps(&self) -> Vec<MapEntry> {
        self.vmas
            .iter()
            .map(|(&s, v)| {
                let (shared, offset) = match &v.backing {
                    Backing::Anon => (false, 0),
                    Backing::File { offset, .. } => (false, *offset),
                    Backing::Shared { offset, .. } | Backing::Dev { offset, .. } => (true, *offset),
                };
                (s, v.end, v.prot, shared, offset, v.name.clone())
            })
            .collect()
    }

    /// "path+0xoffset" for a code address (for crash reports).
    pub fn symbolize(&self, va: u64) -> String {
        match self.find(crate::arch::untag(va)) {
            Some((start, v)) => {
                let name = v.name.as_deref().unwrap_or("[anon]");
                let va = crate::arch::untag(va);
                match &v.backing {
                    // The offset in the file, whatever gaps the linker left between segments.
                    Backing::File { offset, .. } | Backing::Shared { offset, .. } => format!("{name}+{:#x}", offset + (va - start)),
                    // Otherwise relative to the first mapping of that name.
                    _ => {
                        let base = self.vmas.range(..=start).rev().take_while(|(_, x)| x.name.as_deref() == Some(name)).last().map_or(start, |(&s, _)| s);
                        format!("{name}+{:#x}", va - base)
                    }
                }
            }
            None => "?".into(),
        }
    }

    /// Bytes of address space mapped, and bytes actually resident.
    pub fn usage(&self) -> (u64, u64) {
        let virt = self.vmas.iter().map(|(&s, v)| v.end - s).sum();
        let mut resident = 0;
        self.visit(0, USER_TOP, &mut |_, _, _, _| resident += PAGE);
        (virt, resident)
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
            match self.vmas.remove(&s).map(|v| v.backing) {
                Some(Backing::Shared { obj, .. }) => self.stale.objs.push(obj),
                Some(Backing::Dev { mem, .. }) => self.stale.devs.push(mem),
                _ => {}
            }
        }
        if freed {
            self.tlb_gen += 1;
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
            self.tlb_gen += 1;
        }
        Ok(())
    }

    /// Guest-physical address of `va` if it lies in shared memory (the key for
    /// futexes that other processes can wake). The page gets mapped here, if it wasn't:
    /// a page mapped somewhere stays in its frame, so that all see the same key.
    pub fn shared_frame(&mut self, va: u64) -> Option<u64> {
        let va = crate::arch::untag(va);
        let (_, vma) = self.find(va)?;
        if !matches!(vma.backing, Backing::Shared { .. }) {
            return None;
        }
        self.host_ptr(va, false, true).ok()?;
        let slot = walk(&self.phys, self.owner(), &mut self.tables, self.root.root, 0, page_down(va), false).ok()??;
        Some(paging::addr(self.phys.read_u64(slot)) + va % PAGE)
    }

    fn is_shared(&self, va: u64) -> bool {
        matches!(self.find(va), Some((_, Vma { backing: Backing::Shared { .. } | Backing::Dev { .. }, .. })))
    }

    /// Whether its pages aren't RAM, so that a mapping has no hold on them.
    fn is_device(&self, va: u64) -> bool {
        matches!(self.find(va), Some((_, Vma { backing: Backing::Dev { .. }, .. })))
    }

    /// Clears the present pages of [start, end): this mapping's holds on their
    /// frames go to `stale`. Returns whether anything was present.
    fn clear_pages(&mut self, start: u64, end: u64) -> bool {
        let mut cleared = Vec::new();
        self.visit(start, end, &mut |phys, slot, va, e| {
            phys.write_u64(slot, 0);
            cleared.push((va, paging::addr(e)));
        });
        let any = !cleared.is_empty();
        for (va, frame) in cleared {
            if !self.is_device(va) {
                self.stale.frames.push(frame);
            }
        }
        any
    }

    /// Whether every byte of [start, end) is mapped.
    pub fn covered(&self, start: u64, end: u64) -> bool {
        let mut cur = start;
        for (&s, v) in self.vmas.range(..end) {
            if v.end <= cur {
                continue;
            }
            if s > cur {
                return false;
            }
            cur = v.end;
            if cur >= end {
                return true;
            }
        }
        cur >= end
    }

    /// mincore: one byte per page of [start, end), 1 for one in memory.
    pub fn residency(&self, start: u64, end: u64) -> Vec<u8> {
        let mut out = vec![0u8; ((end - start) / PAGE) as usize];
        self.visit(start, end, &mut |_, _, va, _| out[((va - start) / PAGE) as usize] = 1);
        // Not mapped here yet, but in memory all the same: shared pages others touched.
        for (&s, v) in self.vmas.range(..end) {
            if let Backing::Shared { obj, offset } = &v.backing {
                for va in (s.max(start)..v.end.min(end)).step_by(PAGE as usize) {
                    if obj.in_memory_now(offset + (va - s)) {
                        out[((va - start) / PAGE) as usize] = 1;
                    }
                }
            }
        }
        out
    }

    /// The page-table entry for `frame` under `prot`: not writable while a
    /// private frame still has other owners, so the first write copies it.
    fn entry_for(&self, frame: u64, prot: u32, shared: bool) -> u64 {
        self.sync_for_exec(frame, prot);
        let prot = if !shared && !self.phys.is_sole_owner(frame) { read_only(prot) } else { prot };
        paging::user_page(frame, prot)
    }

    /// The host wrote what's in this frame, perhaps just now, and it may once have held
    /// other code: instruction caches don't see that by themselves on arm64.
    fn sync_for_exec(&self, frame: u64, prot: u32) {
        if prot & PROT_EXEC != 0 {
            self.phys.sync_icache(frame);
        }
    }

    /// Replaces a private frame still shared with other owners by a private copy.
    fn break_cow(&mut self, slot: u64, frame: u64, prot: u32) -> Result<u64, i64> {
        let copy = self.phys.alloc_for(self.owner())?;
        unsafe { std::ptr::copy_nonoverlapping(self.phys.host(frame), self.phys.host(copy), PAGE as usize) };
        self.sync_for_exec(copy, prot);
        let e = paging::user_page(copy, prot);
        self.phys.write_pte(slot, e);
        // Sibling threads may read it through old entries until the flush.
        self.stale.frames.push(frame);
        self.tlb_gen += 1;
        Ok(e)
    }

    /// madvise's fork policies. Only private anonymous memory can be wiped.
    pub fn set_on_fork(&mut self, start: u64, len: u64, on_fork: OnFork) -> Result<(), i64> {
        let end = start.saturating_add(page_up(len));
        if !start.is_multiple_of(PAGE) || end > USER_TOP {
            return Err(EINVAL);
        }
        if !self.covered(start, end) {
            return Err(ENOMEM);
        }
        self.split(start);
        self.split(end);
        if on_fork == OnFork::Wipe && self.vmas.range(start..end).any(|(_, v)| !matches!(v.backing, Backing::Anon)) {
            return Err(EINVAL);
        }
        for (_, v) in self.vmas.range_mut(start..end) {
            v.on_fork = on_fork;
        }
        self.merge(start, end);
        Ok(())
    }

    pub fn protect(&mut self, start: u64, len: u64, prot: u32) -> Result<(), i64> {
        let end = start.saturating_add(page_up(len));
        if !start.is_multiple_of(PAGE) || end > USER_TOP {
            return Err(EINVAL);
        }
        // Linux fails with ENOMEM if any part of the range is unmapped.
        if !self.covered(start, end) {
            return Err(ENOMEM);
        }
        self.split(start);
        self.split(end);
        for (_, v) in self.vmas.range_mut(start..end) {
            v.prot = prot;
        }
        self.merge(start, end);
        let mut changed = false;
        self.visit(start, end, &mut |phys, slot, va, e| {
            phys.write_u64(slot, self.entry_for(paging::addr(e), prot, self.is_shared(va)));
            changed = true;
        });
        if changed {
            self.tlb_gen += 1;
        }
        Ok(())
    }

    /// Moves (or resizes) a mapping, carrying its pages along. With `dont_unmap`
    /// (MREMAP_DONTUNMAP) the source stays mapped, without its pages.
    pub fn remap(&mut self, old: u64, old_len: u64, new_len: u64, may_move: bool, fixed: Option<u64>, dont_unmap: bool) -> Result<u64, i64> {
        let (old_len, new_len) = (page_up(old_len), page_up(new_len));
        if !old.is_multiple_of(PAGE) || new_len == 0 {
            return Err(EINVAL);
        }
        let (vstart, vma) = self.find(old).ok_or(EFAULT)?;
        if old + old_len > vma.end {
            return Err(EFAULT);
        }
        if old_len == 0 && !matches!(vma.backing, Backing::Shared { .. } | Backing::Dev { .. }) {
            return Err(EINVAL);
        }
        if dont_unmap && (old_len != new_len || !matches!(vma.backing, Backing::Anon)) {
            return Err(EINVAL);
        }
        let (prot, on_fork, mut backing, vma_name) = (vma.prot, vma.on_fork, vma.backing.clone(), vma.name.clone());
        if !dont_unmap && fixed.is_none() && new_len <= old_len {
            self.unmap(old + new_len, old_len - new_len)?;
            return Ok(old);
        }
        if !dont_unmap && fixed.is_none() && self.is_free(old + old_len, old + new_len) {
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
                if !a.is_multiple_of(PAGE) || a < MIN_ADDR || a.saturating_add(new_len) > USER_TOP {
                    return Err(EINVAL);
                }
                // mremap_to: source and destination may not overlap.
                if a < old.saturating_add(old_len) && old < a + new_len {
                    return Err(EINVAL);
                }
                self.unmap(a, new_len)?;
                a
            }
            None => self.gap(new_len)?,
        };
        bump_offset(&mut backing, old - vstart);
        let keep = old_len.min(new_len);
        // The tables at the destination first, since that can fail, and Linux's ENOMEM
        // means the old mapping is as it was.
        let mut present = Vec::new();
        self.visit(old, old + keep, &mut |_, _, va, _| present.push(va - old));
        let owner = self.owner();
        for off in &present {
            walk(&self.phys, owner, &mut self.tables, self.root.root, 0, dst + off, true)?;
        }
        let mut moves = Vec::new();
        self.visit(old, old + keep, &mut |phys, slot, va, e| {
            phys.write_u64(slot, 0);
            moves.push((va - old, e));
        });
        // Drop the old range while its VMA still says whether leftover pages are
        // shared; moved pages are no longer in the tables. old_len 0 keeps the
        // source, which is how Linux duplicates a shared mapping.
        if !dont_unmap {
            self.unmap(old, old_len)?;
        }
        self.vmas.insert(dst, Vma { end: dst + new_len, prot, backing, on_fork, name: vma_name, uffd: None });
        for (off, e) in moves {
            // These exist now, so this can't fail, and it can't use up anything.
            let slot = walk(&self.phys, owner, &mut self.tables, self.root.root, 0, dst + off, true)?.unwrap();
            self.phys.write_u64(slot, e);
        }
        self.tlb_gen += 1;
        Ok(dst)
    }

    /// UFFDIO_REGISTER: `ctx` supplies the missing pages of [start, start+len). Only
    /// private anonymous memory can be registered: all ART asks for.
    pub fn uffd_register(&mut self, ctx: &Arc<UffdCtx>, start: u64, len: u64) -> Result<(), i64> {
        let end = start.saturating_add(len);
        let mut any = false;
        for (&s, v) in self.vmas.range(..end).rev() {
            if v.end <= start {
                break;
            }
            let _ = s;
            any = true;
            if !matches!(v.backing, Backing::Anon) {
                return Err(EINVAL);
            }
            if v.uffd().is_some_and(|c| !Arc::ptr_eq(c, ctx)) {
                return Err(EBUSY);
            }
        }
        if !any {
            return Err(EINVAL);
        }
        self.split(start);
        self.split(end);
        for (_, v) in self.vmas.range_mut(start..end) {
            v.uffd = Some(ctx.clone());
        }
        self.merge(start, end);
        Ok(())
    }

    /// UFFDIO_UNREGISTER. Missing pages become ordinary zero pages again, and the
    /// mapping rejoins its neighbours: the next GC cycle's mremap needs it whole.
    pub fn uffd_unregister(&mut self, ctx: &Arc<UffdCtx>, start: u64, len: u64) -> Result<(), i64> {
        let end = start.saturating_add(len);
        self.split(start);
        self.split(end);
        for (_, v) in self.vmas.range_mut(start..end) {
            if v.uffd().is_some_and(|c| Arc::ptr_eq(c, ctx)) {
                v.uffd = None;
            }
        }
        self.merge(start, end);
        Ok(())
    }

    /// UFFDIO_COPY (with `src`) and UFFDIO_ZEROPAGE (without): maps the missing pages
    /// of [dst, dst+len). What was done, and if that is not everything, why not.
    pub fn uffd_fill(&mut self, ctx: &Arc<UffdCtx>, dst: u64, len: u64, src: Option<u64>) -> (u64, Option<i64>) {
        let mut done = 0;
        let mut page = [0u8; PAGE as usize];
        while done < len {
            let at = dst + done;
            let filled = (|| {
                let (_, vma) = self.find(at).ok_or(ENOENT)?;
                if !vma.uffd().is_some_and(|c| Arc::ptr_eq(c, ctx)) {
                    return Err(ENOENT);
                }
                let prot = vma.prot;
                let slot = walk(&self.phys, self.owner(), &mut self.tables, self.root.root, 0, at, true)?.unwrap();
                if paging::is_valid(self.phys.read_u64(slot)) {
                    return Err(EEXIST);
                }
                if let Some(src) = src {
                    self.read(src + done, &mut page)?;
                }
                let frame = self.phys.alloc_for(self.owner())?;
                if src.is_some() {
                    unsafe { std::ptr::copy_nonoverlapping(page.as_ptr(), self.phys.host(frame), page.len()) };
                }
                self.sync_for_exec(frame, prot);
                // It wasn't valid before, so no TLB holds it.
                self.phys.write_pte(slot, paging::user_page(frame, prot));
                Ok(())
            })();
            if let Err(e) = filled {
                return (done, Some(e));
            }
            done += PAGE;
        }
        (done, None)
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
            self.set_name(old_end, new_end - old_end, "[heap]");
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
    /// Handles a page fault. On failure, the si_code for SIGSEGV: nothing mapped
    /// there (SEGV_MAPERR), or the mapping forbids the access (SEGV_ACCERR).
    pub fn fault(&mut self, addr: u64, write: bool, exec: bool) -> Result<(), i32> {
        const SEGV_MAPERR: i32 = 1;
        const SEGV_ACCERR: i32 = 2;
        let page = page_down(addr);
        let Some((start, vma)) = self.find(page) else { return Err(SEGV_MAPERR) };
        let ok = if exec {
            vma.prot & PROT_EXEC != 0
        } else if write {
            vma.prot & PROT_WRITE != 0
        } else {
            vma.prot & (PROT_READ | PROT_WRITE | PROT_EXEC) != 0
        };
        if !ok {
            return Err(SEGV_ACCERR);
        }
        let (prot, vma) = (vma.prot, vma.clone());
        let slot = walk(&self.phys, self.owner(), &mut self.tables, self.root.root, 0, page, true).map_err(|_| SEGV_MAPERR)?.unwrap();
        let e = self.phys.read_u64(slot);
        if !paging::is_valid(e) && vma.uffd().is_some() {
            return Err(FAULT_UFFD);
        }
        if paging::is_valid(e) {
            let (frame, shared) = (paging::addr(e), matches!(vma.backing, Backing::Shared { .. } | Backing::Dev { .. }));
            if !paging::permits(e, write, exec) {
                if write && !shared && !self.phys.is_sole_owner(frame) {
                    // No thread can still write the old frame: fork flushed
                    // before it let go of the address space.
                    self.break_cow(slot, frame, prot).map_err(|_| SEGV_MAPERR)?;
                    return Ok(());
                }
                self.phys.write_u64(slot, self.entry_for(frame, prot, shared));
            }
            // Either way the entry now allows it; a stale TLB entry caused the fault.
            self.tlb_gen += 1;
            return Ok(());
        }
        let frame = self.populate(start, &vma, page, write).map_err(|_| SEGV_MAPERR)?;
        let shared = matches!(vma.backing, Backing::Shared { .. } | Backing::Dev { .. });
        self.phys.write_pte(slot, self.entry_for(frame, prot, shared));
        Ok(())
    }

    /// Each page present, as (where its mapping starts, its mapping, its address, its
    /// frame), and how many frames the tables themselves take. For a memory report.
    pub fn each_resident(&self, f: &mut dyn FnMut(u64, &Vma, u64, u64)) -> usize {
        fn go(mm: &AddressSpace, table: u64, level: usize, base: u64, f: &mut dyn FnMut(u64, &Vma, u64, u64)) {
            let shift = 12 + 9 * (paging::levels() - 1 - level);
            for i in 0..512u64 {
                let e = mm.phys.read_u64(table + i * 8);
                if !paging::is_valid(e) {
                    continue;
                }
                let va = base | i << shift;
                if level + 1 < paging::levels() {
                    go(mm, paging::addr(e), level + 1, va, f);
                } else if let Some((start, vma)) = mm.find(va) {
                    f(start, vma, va, paging::addr(e));
                }
            }
        }
        go(self, self.root.root, 0, 0, f);
        self.tables.len() + 1
    }

    /// The frame for a page not yet present, with a hold on it for this mapping.
    /// About to be written, a page of a file is copied at once.
    fn populate(&self, vma_start: u64, vma: &Vma, page: u64, write: bool) -> Result<u64, i64> {
        if let Backing::Shared { obj, offset } = &vma.backing {
            return obj.map_frame(((offset + (page - vma_start)) / PAGE) as usize);
        }
        if let Backing::Dev { mem, offset } = &vma.backing {
            let off = offset + (page - vma_start);
            if off >= mem.len {
                return Err(EFAULT);
            }
            return Ok(mem.gpa + off);
        }
        let Backing::File { src, offset } = &vma.backing else { return self.phys.alloc_for(self.owner()) };
        let Some(frame) = src.page((offset + (page - vma_start)) / PAGE)? else { return self.phys.alloc_for(self.owner()) };
        if !write || self.phys.is_sole_owner(frame) {
            return Ok(frame);
        }
        let copy = self.phys.alloc_for(self.owner());
        if let Ok(copy) = copy {
            unsafe { std::ptr::copy_nonoverlapping(self.phys.host(frame), self.phys.host(copy), PAGE as usize) };
        }
        self.phys.free(frame);
        copy
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
        let slot = walk(&self.phys, self.owner(), &mut self.tables, self.root.root, 0, page, true)?.unwrap();
        let mut e = self.phys.read_u64(slot);
        if !paging::is_valid(e) {
            // Only the userfaultfd may supply it, and all it knows of are the guest's
            // own faults (UFFD_USER_MODE_ONLY).
            if vma.uffd().is_some() {
                return Err(EFAULT);
            }
            let frame = self.populate(start, &vma, page, write)?;
            e = self.entry_for(frame, vma.prot, matches!(vma.backing, Backing::Shared { .. } | Backing::Dev { .. }));
            self.phys.write_pte(slot, e);
        } else if write && !matches!(vma.backing, Backing::Shared { .. } | Backing::Dev { .. }) && !self.phys.is_sole_owner(paging::addr(e)) {
            // The kernel writes past the page tables: it must not reach a frame
            // another process still shares.
            e = self.break_cow(slot, paging::addr(e), vma.prot)?;
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

    /// Atomically replaces the word at `va` with `f(current)` until that
    /// sticks or `f` declines (None). Guest threads on other vCPUs change the
    /// same word with their own atomics (the PI futex fast paths). Returns
    /// the value last seen and whether it was replaced.
    pub fn update_u32(&mut self, va: u64, mut f: impl FnMut(u32) -> Option<u32>) -> Result<(u32, bool), i64> {
        if !va.is_multiple_of(4) {
            return Err(EINVAL);
        }
        let word = unsafe { std::sync::atomic::AtomicU32::from_ptr(self.host_ptr(va, true, false)? as *mut u32) };
        let mut cur = word.load(std::sync::atomic::Ordering::SeqCst);
        loop {
            let Some(new) = f(cur) else { return Ok((cur, false)) };
            match word.compare_exchange_weak(cur, new, std::sync::atomic::Ordering::SeqCst, std::sync::atomic::Ordering::SeqCst) {
                Ok(_) => return Ok((cur, true)),
                Err(seen) => cur = seen,
            }
        }
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

    /// A copy of this address space. Shared mappings keep their frames;
    /// private frames are shared too, read-only in both spaces, until one
    /// writes (fault and host_ptr copy them then). A caller with other threads
    /// must flush TLBs before releasing the lock: they may hold writable entries
    /// for what is now read-only, and a copy made meanwhile would lose their writes.
    pub fn fork(&mut self, kernel: &KernelWindow, asid: u16) -> Result<AddressSpace, i64> {
        let mut child = AddressSpace::new(self.phys.clone(), kernel, asid).inspect_err(|_| self.phys.free_asid(asid))?;
        // A userfaultfd is the parent's: the child's pages are its own to fault in.
        child.vmas = self.vmas.iter().filter(|(_, v)| v.on_fork != OnFork::Drop).map(|(&s, v)| (s, Vma { uffd: None, ..v.clone() })).collect();
        child.brk_start = self.brk_start;
        child.start_stack = self.start_stack;
        (child.arg_start, child.arg_end) = (self.arg_start, self.arg_end);
        child.brk = self.brk;
        let mut pages = Vec::new();
        self.visit(0, USER_TOP, &mut |_, slot, va, e| pages.push((slot, va, e)));
        let mut downgraded = false;
        let mut failed = None;
        for (slot, va, e) in pages {
            if self.find(va).is_some_and(|(_, v)| v.on_fork != OnFork::Copy) {
                continue;
            }
            // Before anything else, since this can fail, and nothing later can.
            let owner = child.owner();
            let child_slot = match walk(&self.phys, owner, &mut child.tables, child.root.root, 0, va, true) {
                Ok(s) => s.unwrap(),
                Err(e) => {
                    failed = Some(e);
                    break;
                }
            };
            let mut entry = e;
            if !self.is_device(va) {
                self.phys.share(paging::addr(e));
            }
            if !self.is_shared(va) {
                let frame = paging::addr(e);
                if paging::permits(e, true, false) {
                    // Both copies read-only: the parent's entry changes under its threads.
                    let prot = self.find(va).map_or(0, |(_, v)| v.prot);
                    entry = paging::user_page(frame, read_only(prot));
                    self.phys.write_u64(slot, entry);
                    downgraded = true;
                }
            }
            self.phys.write_u64(child_slot, entry);
        }
        // Entries already changed are changed, whether or not the rest followed.
        if downgraded {
            self.tlb_gen += 1;
        }
        match failed {
            Some(e) => Err(e),
            None => Ok(child),
        }
    }

    /// What was unmapped since the last flush; release it once that happened.
    pub fn take_stale(&mut self) -> Stale {
        std::mem::take(&mut self.stale)
    }

    /// Takes back what a thread took and never flushed for.
    pub fn return_stale(&mut self, stale: Stale) {
        self.stale.absorb(stale);
    }

}

impl Drop for AddressSpace {
    fn drop(&mut self) {
        // Callers flush TLBs before dropping a space a vCPU may still cache
        // (exec switches roots first; exited processes have no vCPUs left).
        let mut pages = Vec::new();
        self.visit(0, USER_TOP, &mut |_, _, va, e| pages.push((va, paging::addr(e))));
        for (va, frame) in pages {
            if !self.is_device(va) {
                self.phys.free(frame);
            }
        }
        let phys = self.phys.clone();
        self.stale.release(&phys);
        for f in self.tables.drain(..) {
            phys.free(f);
        }
        phys.free_asid(self.root.asid);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Someone waiting on a shared word and someone waking it must use the same key,
    /// and a page that left memory and came back would be in another frame.
    #[test]
    fn a_shared_futex_keeps_its_key_while_memory_is_short() {
        let phys = PhysMem::new(Arc::new(crate::hv::NoHv));
        let cache = PageCache::new(phys.clone());
        cache.limit_idle(0);
        let kernel = KernelWindow::new(&phys, &[]).unwrap();
        let obj = SharedObject::with_pager(phys.clone(), Some(cache.clone()));
        obj.write(0, &[1; 4096]).unwrap();
        cache.reclaim(1 << 20);
        let mut a = AddressSpace::new(phys.clone(), &kernel, 1).unwrap();
        let at = a.map(Placement::Hint(0), PAGE, PROT_READ | PROT_WRITE, Backing::Shared { obj: obj.clone(), offset: 0 }).unwrap();
        let key = a.shared_frame(at + 8).unwrap();
        cache.reclaim(1 << 20);
        let mut b = AddressSpace::new(phys.clone(), &kernel, 2).unwrap();
        let there = b.map(Placement::Hint(0), PAGE, PROT_READ | PROT_WRITE, Backing::Shared { obj, offset: 0 }).unwrap();
        assert_eq!(b.shared_frame(there + 8).unwrap(), key);
    }

    /// mincore says what is in memory: not what could be read back.
    #[test]
    fn a_page_that_left_memory_isnt_called_resident() {
        let phys = PhysMem::new(Arc::new(crate::hv::NoHv));
        let cache = PageCache::new(phys.clone());
        cache.limit_idle(0);
        let kernel = KernelWindow::new(&phys, &[]).unwrap();
        let obj = SharedObject::with_pager(phys.clone(), Some(cache.clone()));
        obj.write(0, &[1; 8192]).unwrap();
        let mut a = AddressSpace::new(phys.clone(), &kernel, 1).unwrap();
        let at = a.map(Placement::Hint(0), PAGE * 2, PROT_READ, Backing::Shared { obj, offset: 0 }).unwrap();
        cache.reclaim(1 << 20);
        assert_eq!(a.residency(at, at + PAGE * 2), [0, 0]);
        assert_eq!(a.read_vec(at + PAGE, 1).unwrap(), [1], "it comes back");
        assert_eq!(a.residency(at, at + PAGE * 2), [0, 1]);
    }

    /// mremap's tables come first, so its failing can't lose what was mapped. (Nothing
    /// here can make it fail: this shows it still moves things when it doesn't.)
    #[test]
    fn a_moved_mapping_keeps_its_pages_and_holds() {
        let phys = PhysMem::new(Arc::new(crate::hv::NoHv));
        let kernel = KernelWindow::new(&phys, &[]).unwrap();
        let mut a = AddressSpace::new(phys.clone(), &kernel, 1).unwrap();
        let at = a.map(Placement::Hint(0), PAGE * 3, PROT_READ | PROT_WRITE, Backing::Anon).unwrap();
        a.write(at + PAGE, &[9]).unwrap();
        let moved = a.remap(at, PAGE * 3, PAGE * 3, true, Some(at + (1 << 30)), false).unwrap();
        assert_eq!(a.read_vec(moved + PAGE, 1).unwrap(), [9]);
        let mut b = a.fork(&kernel, 2).unwrap();
        b.write(moved + PAGE, &[8]).unwrap();
        assert_eq!(a.read_vec(moved + PAGE, 1).unwrap(), [9]);
        drop(a);
        drop(b);
        // Only the tables' fixed part of the kernel window's stays.
        assert!(phys.frames_in_use() < 16, "{} left", phys.frames_in_use());
    }
}

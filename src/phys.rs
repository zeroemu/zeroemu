//! Guest physical memory: one large host reservation, committed and handed to
//! the hypervisor in pieces as frames are needed, carved into 4 KiB frames.
//! Untouched memory costs nothing on either host.
//!
//! On macOS each block is a purgeable memory object, never marked volatile. That
//! is for two things. The system charges a page of ordinary memory once for each
//! of the host and the VM that has touched it, so Activity Monitor would show the
//! guest's memory twice; purgeable memory it charges by the object, once. And the
//! memory of an object can be given back whole, at once.

use crate::errno::ENOMEM;
use crate::hv::Hypervisor;
use std::ptr::NonNull;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

pub const PAGE: u64 = 4096;
/// Guest RAM ceiling: fits the default 36-bit IPA space of Apple Silicon.
pub const PHYS_MAX: u64 = 32 << 30;
/// IPA width this HVF configuration advertises (TCR_EL1.IPS). Device memory
/// (GPU blobs) is mapped above `PHYS_MAX` and must stay inside it.
pub const IPA_BITS: u32 = 36;
/// Hypervisor.framework maps only 16 KiB-aligned host, GPA and size.
pub const DEV_ALIGN: u64 = 16 << 10;
/// How much is committed and handed to the hypervisor at a time.
#[cfg(target_os = "macos")]
const MAP_UNIT: u64 = BLOCK;
#[cfg(not(target_os = "macos"))]
const MAP_UNIT: u64 = 64 << 20;
/// In a frame's count: the page cache holds it. Its own hold isn't counted, so
/// a count of 0 with this set is a cached page that nothing has mapped.
const CACHED: u32 = 1 << 31;

/// Memory goes back to the host by this much: a whole number of host pages, big
/// enough not to take too many memory objects, small enough to come free whole.
const BLOCK: u64 = 64 << 10;
const ALL_FREE: u32 = (1 << (BLOCK / PAGE)) - 1;
/// In a block's word: it is being filled for one owner, on no list.
const OPEN: u32 = 1 << 30;
/// In a block's word: its free frames have never been used, so they are zeros.
const FRESH: u32 = 1 << 29;
/// New blocks are filled for one process at a time, so that when it goes they all
/// empty and go back to the host. Processes share these, if there are more of them.
const OPEN_SLOTS: usize = 64;
/// Past this many blocks free, freed memory goes back to the host, down to `WARM_KEEP`
/// (memory handed out again soon is quicker to keep).
const WARM_MAX: usize = (64 << 20) / BLOCK as usize;
const WARM_KEEP: usize = (32 << 20) / BLOCK as usize;
/// Blocks with this many frames free or fewer get used before whole blocks: filling
/// them costs nothing. Those with more are left to empty, as long as there are whole
/// blocks to use instead.
const HOLES_FIRST: u32 = (BLOCK / PAGE / 2) as u32;
/// No block, in the lists of partly free ones.
const NO_BLOCK: u32 = u32::MAX;

/// What the guest is told it has, in bytes. An AVD says 4096 MB (hw.ramSize).
static RAM: AtomicU64 = AtomicU64::new(4096 << 20);

/// The memory the guest believes in: /proc/meminfo, sysinfo, how Android sizes
/// its caches and when it closes apps. Frames can go past this; see `PHYS_MAX`.
pub fn ram() -> u64 {
    RAM.load(Ordering::Relaxed)
}

pub fn set_ram(bytes: u64) {
    RAM.store(bytes, Ordering::Relaxed);
}

pub struct PhysMem {
    base: NonNull<u8>,
    hv: Arc<dyn Hypervisor>,
    alloc: Mutex<Alloc>,
    /// Host mappings installed above `PHYS_MAX` (not frames of `base`).
    ext: Mutex<Ext>,
    /// Per frame: how many owners beyond the first (copy-on-write sharing
    /// after fork). Zeroed lazily by the OS; a frame only ever pays for this
    /// when its page of counters is touched.
    extra_refs: Box<[AtomicU32]>,
    /// Frames in the page cache, and those of them nothing has mapped.
    cached: AtomicU64,
    cached_idle: AtomicU64,
    /// Address space ids in use, and where to look for the next: two live address
    /// spaces with one id would hit each other's translations.
    asids: Mutex<(Box<[u64]>, u32)>,
}

struct Alloc {
    /// Guest-physical end of the memory mapped into the VM so far.
    mapped: u64,
    /// Next never-used frame (fresh frames are already zero).
    bump: u64,
    /// Per block: which of its frames are free, and OPEN and FRESH.
    blocks: Box<[u32]>,
    /// Blocks with some frames free and some in use, by how many are free, as lists
    /// through `links`: (previous, next) per block. Using those with the fewest free
    /// first lets those with the most come free whole.
    partial: [u32; (BLOCK / PAGE) as usize],
    links: Box<[[u32; 2]]>,
    /// Which of `partial` have anything in them.
    partial_mask: u32,
    /// Blocks all free that the host still holds, oldest first.
    warm: Vec<u32>,
    /// Blocks all free that the host has been told it can have.
    returned: Vec<u32>,
    /// All free frames, wherever they are.
    free_frames: u64,
    /// Blocks on their way back to the host, or there already.
    away: u64,
    /// The block being filled for each owner slot, or 0.
    open: [u32; OPEN_SLOTS],
}

impl Alloc {
    /// The next free frame of block `b`, and whether it needs zeroing.
    fn take_from(&mut self, b: usize) -> (u64, bool) {
        let bits = self.blocks[b] & ALL_FREE;
        let bit = bits.trailing_zeros() as u64;
        self.blocks[b] = (self.blocks[b] & !ALL_FREE) | (bits & !(1 << bit));
        self.free_frames -= 1;
        (b as u64 * BLOCK + bit * PAGE, self.blocks[b] & FRESH == 0)
    }

    fn link(&mut self, b: usize, free: u32) {
        let head = self.partial[free as usize];
        self.links[b] = [NO_BLOCK, head];
        if head != NO_BLOCK {
            self.links[head as usize][0] = b as u32;
        }
        self.partial[free as usize] = b as u32;
        self.partial_mask |= 1 << free;
    }

    fn unlink(&mut self, b: usize, free: u32) {
        let [prev, next] = self.links[b];
        if next != NO_BLOCK {
            self.links[next as usize][0] = prev;
        }
        if prev != NO_BLOCK {
            self.links[prev as usize][1] = next;
        } else {
            self.partial[free as usize] = next;
            if next == NO_BLOCK {
                self.partial_mask &= !(1 << free);
            }
        }
    }

    /// A free frame of a block with others in use, one with at most `most` free: that
    /// takes no more of the host's memory, and it may let that block fill up.
    fn take_hole(&mut self, most: u32) -> Option<(u64, bool)> {
        let lists = self.partial_mask & ((2 << most) - 1);
        if lists == 0 {
            return None;
        }
        let free = lists.trailing_zeros();
        let b = self.partial[free as usize] as usize;
        self.unlink(b, free);
        let frame = self.take_from(b);
        if free > 1 {
            self.link(b, free - 1);
        }
        Some(frame)
    }

    /// A block all free to fill for one owner: `None` if there's none to reuse.
    fn take_whole(&mut self, base: *mut u8) -> Option<usize> {
        let b = match self.warm.pop() {
            Some(b) => b,
            None => {
                let b = self.returned.pop()?;
                os::reclaim(unsafe { base.add((b as u64 * BLOCK) as usize) }, BLOCK);
                self.away -= 1;
                b
            }
        };
        self.blocks[b as usize] |= OPEN;
        Some(b as usize)
    }
}

struct Ext {
    /// Next GPA to try, 16 KiB aligned, at or above `PHYS_MAX`.
    bump: u64,
    free: Vec<(u64, u64)>,
    live: Vec<ExtRange>,
}

struct ExtRange {
    gpa: u64,
    size: u64,
    host: usize,
}

// The reservation is plain memory shared by all guest threads; frame
// ownership is tracked by the address spaces.
unsafe impl Send for PhysMem {}
unsafe impl Sync for PhysMem {}

impl PhysMem {
    pub fn new(hv: Arc<dyn Hypervisor>) -> Arc<PhysMem> {
        let count = (PHYS_MAX / BLOCK) as usize;
        let mut blocks = vec![0u32; count].into_boxed_slice();
        // Frame 0 is never handed out, so 0 can mean "no frame", and 0 means no block
        // too: the other frames of block 0 are holes from the start.
        blocks[0] = (ALL_FREE & !1) | FRESH;
        let mut alloc = Alloc {
            mapped: 0,
            bump: BLOCK,
            blocks,
            partial: [NO_BLOCK; (BLOCK / PAGE) as usize],
            links: vec![[0, 0]; count].into_boxed_slice(),
            partial_mask: 0,
            warm: Vec::new(),
            returned: Vec::new(),
            free_frames: ALL_FREE.count_ones() as u64 - 1,
            away: 0,
            open: [0; OPEN_SLOTS],
        };
        alloc.link(0, ALL_FREE.count_ones() - 1);
        Arc::new(PhysMem {
            base: os::reserve(PHYS_MAX as usize),
            hv,
            // Frame 0 is never handed out, so 0 can mean "no frame".
            alloc: Mutex::new(alloc),
            ext: Mutex::new(Ext { bump: PHYS_MAX, free: Vec::new(), live: Vec::new() }),
            extra_refs: zeroed_counters((PHYS_MAX / PAGE) as usize),
            cached: AtomicU64::new(0),
            cached_idle: AtomicU64::new(0),
            asids: Mutex::new((vec![0u64; 1 << 10].into_boxed_slice(), 1)),
        })
    }

    /// Maps already-allocated host memory into the IPA space above RAM.
    /// `host` and `size` are rounded up to `DEV_ALIGN` (HVF's requirement);
    /// the returned GPA is aligned the same way. The range stays mapped until
    /// `unmap_external`.
    pub fn map_external(&self, host: *mut u8, size: u64) -> Result<u64, i64> {
        if host.is_null() || (host as u64) & (DEV_ALIGN - 1) != 0 || size == 0 {
            return Err(crate::errno::EINVAL);
        }
        let size = size.div_ceil(DEV_ALIGN) * DEV_ALIGN;
        let mut ext = self.ext.lock().unwrap();
        let gpa = if let Some(i) = ext.free.iter().position(|&(_, n)| n == size) {
            ext.free.swap_remove(i).0
        } else {
            let gpa = ext.bump;
            let end = gpa.checked_add(size).ok_or(crate::errno::ENOMEM)?;
            if end > 1u64 << IPA_BITS {
                return Err(crate::errno::ENOMEM);
            }
            ext.bump = end;
            gpa
        };
        if let Err(e) = self.hv.map_ram(host, gpa, size) {
            ext.free.push((gpa, size));
            eprintln!("[droidrt] device memory: {e}");
            return Err(crate::errno::ENOMEM);
        }
        ext.live.push(ExtRange { gpa, size, host: host as usize });
        Ok(gpa)
    }

    pub fn unmap_external(&self, gpa: u64) {
        let mut ext = self.ext.lock().unwrap();
        let Some(i) = ext.live.iter().position(|r| r.gpa == gpa) else { return };
        let range = ext.live.swap_remove(i);
        if let Err(e) = self.hv.unmap_ram(range.gpa, range.size) {
            eprintln!("[droidrt] device memory unmap: {e}");
        }
        ext.free.push((range.gpa, range.size));
    }

    /// An address space id nothing has, taken in turn: one that went is used again last.
    /// Whoever gets it starts on a vCPU that flushes first (a new one, or one switching
    /// roots at exec), so nothing is left of what it meant before.
    pub fn alloc_asid(&self) -> Result<u16, i64> {
        let mut g = self.asids.lock().unwrap();
        let (used, next) = &mut *g;
        for i in 0..=u16::MAX as u32 {
            // 0 is for no address space.
            let id = ((*next + i - 1) % u16::MAX as u32) + 1;
            let (word, bit) = ((id / 64) as usize, id % 64);
            if used[word] & 1 << bit == 0 {
                used[word] |= 1 << bit;
                *next = id % u16::MAX as u32 + 1;
                return Ok(id as u16);
            }
        }
        Err(ENOMEM)
    }

    pub fn free_asid(&self, id: u16) {
        self.asids.lock().unwrap().0[id as usize / 64] &= !(1 << (id % 64));
    }

    /// A zeroed frame, for something with no particular owner.
    pub fn alloc(&self) -> Result<u64, i64> {
        self.alloc_for(0)
    }

    /// A zeroed frame for `owner` (an address space), which gets neighbouring frames
    /// where it can, since those are the ones that go when it does.
    pub fn alloc_for(&self, owner: u32) -> Result<u64, i64> {
        let mut a = self.alloc.lock().unwrap();
        if a.mapped == 0 {
            self.map_more(&mut a)?;
        }
        let slot = owner as usize % OPEN_SLOTS;
        let b = a.open[slot] as usize;
        let (gpa, dirty) = if b != 0 {
            let frame = a.take_from(b);
            if a.blocks[b] & ALL_FREE == 0 {
                a.blocks[b] &= !(OPEN | FRESH);
                a.open[slot] = 0;
            }
            frame
        } else if let Some(frame) = a.take_hole(HOLES_FIRST) {
            frame
        } else if a.warm.is_empty()
            && let Some(frame) = a.take_hole(ALL_FREE.count_ones())
        {
            frame
        } else {
            let b = match a.take_whole(self.base.as_ptr()) {
                Some(b) => b,
                None => {
                    if a.bump + BLOCK > a.mapped {
                        self.map_more(&mut a)?;
                    }
                    let b = (a.bump / BLOCK) as usize;
                    a.bump += BLOCK;
                    a.blocks[b] = ALL_FREE | OPEN | FRESH;
                    a.free_frames += ALL_FREE.count_ones() as u64;
                    b
                }
            };
            let frame = a.take_from(b);
            a.open[slot] = b as u32;
            frame
        };
        drop(a);
        if dirty {
            unsafe { self.host(gpa).write_bytes(0, PAGE as usize) };
        }
        Ok(gpa)
    }

    fn map_more(&self, a: &mut Alloc) -> Result<(), i64> {
        if a.mapped + MAP_UNIT > PHYS_MAX {
            return Err(ENOMEM);
        }
        let host = unsafe { self.base.as_ptr().add(a.mapped as usize) };
        os::commit(host, MAP_UNIT);
        if let Err(e) = self.hv.map_ram(host, a.mapped, MAP_UNIT) {
            eprintln!("[droidrt] guest RAM: {e}");
            return Err(ENOMEM);
        }
        a.mapped += MAP_UNIT;
        Ok(())
    }

    /// Gives up one owner's hold on a frame; the last one frees it.
    pub fn free(&self, gpa: u64) {
        debug_assert!(gpa != 0 && gpa.is_multiple_of(PAGE));
        let others = &self.extra_refs[(gpa / PAGE) as usize];
        if let Ok(before) = others.fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| (n & !CACHED).checked_sub(1).map(|left| left | (n & CACHED))) {
            if before == CACHED | 1 {
                self.cached_idle.fetch_add(1, Ordering::Relaxed);
            }
            return;
        }
        debug_assert_eq!(others.load(Ordering::Relaxed), 0, "a frame freed with the page cache still holding it");
        let mut a = self.alloc.lock().unwrap();
        let b = (gpa / BLOCK) as usize;
        let was_free = (a.blocks[b] & ALL_FREE).count_ones();
        a.blocks[b] = (a.blocks[b] | 1 << (gpa % BLOCK / PAGE)) & !FRESH;
        a.free_frames += 1;
        if a.blocks[b] & OPEN != 0 {
            return; // its owner will get to it
        }
        if was_free > 0 {
            a.unlink(b, was_free);
        }
        if a.blocks[b] & ALL_FREE == ALL_FREE {
            a.warm.push(b as u32);
        } else {
            a.link(b, was_free + 1);
        }
        if a.warm.len() > WARM_MAX {
            let extra = a.warm.len() - WARM_KEEP;
            let mut going: Vec<u32> = a.warm.drain(..extra).collect();
            a.away += going.len() as u64;
            drop(a);
            // Nothing can allocate these until they are on `returned`.
            for &b in &going {
                os::release(unsafe { self.base.as_ptr().add((b as u64 * BLOCK) as usize) }, BLOCK);
            }
            self.alloc.lock().unwrap().returned.append(&mut going);
        }
    }

    /// One more owner of a frame (fork's copy-on-write, a cached page mapped).
    pub fn share(&self, gpa: u64) {
        if self.extra_refs[(gpa / PAGE) as usize].fetch_add(1, Ordering::AcqRel) == CACHED {
            self.cached_idle.fetch_sub(1, Ordering::Relaxed);
        }
    }

    /// Whether the caller is the frame's only owner.
    pub fn is_sole_owner(&self, gpa: u64) -> bool {
        self.extra_refs[(gpa / PAGE) as usize].load(Ordering::Acquire) & !CACHED == 0
    }

    /// A frame the caller alone owns now belongs to the page cache.
    pub fn mark_cached(&self, gpa: u64) {
        self.extra_refs[(gpa / PAGE) as usize].fetch_or(CACHED, Ordering::AcqRel);
        self.cached.fetch_add(1, Ordering::Relaxed);
        self.cached_idle.fetch_add(1, Ordering::Relaxed);
    }

    /// The page cache lets go of a frame, which lives on if something has it mapped.
    pub fn release_cached(&self, gpa: u64) {
        let before = self.extra_refs[(gpa / PAGE) as usize].fetch_and(!CACHED, Ordering::AcqRel);
        self.cached.fetch_sub(1, Ordering::Relaxed);
        if before == CACHED {
            self.cached_idle.fetch_sub(1, Ordering::Relaxed);
        }
        self.free(gpa);
    }

    pub fn is_cached(&self, gpa: u64) -> bool {
        self.extra_refs[(gpa / PAGE) as usize].load(Ordering::Acquire) & CACHED != 0
    }

    /// Frames in the page cache.
    pub fn cached_frames(&self) -> u64 {
        self.cached.load(Ordering::Relaxed)
    }

    /// Frames in the page cache that nothing has mapped: free for the taking.
    pub fn cached_idle_frames(&self) -> u64 {
        self.cached_idle.load(Ordering::Relaxed)
    }

    /// Makes instruction fetches see what the host wrote to a frame.
    pub fn sync_icache(&self, gpa: u64) {
        if gpa < PHYS_MAX {
            os::sync_icache(self.host(gpa), PAGE as usize);
        }
    }

    /// Host address of guest-physical `gpa` (a RAM frame, or a device mapping).
    pub fn host(&self, gpa: u64) -> *mut u8 {
        if gpa < PHYS_MAX {
            return unsafe { self.base.as_ptr().add(gpa as usize) };
        }
        let ext = self.ext.lock().unwrap();
        let range = ext.live.iter().find(|r| (r.gpa..r.gpa + r.size).contains(&gpa)).expect("device gpa");
        unsafe { (range.host as *mut u8).add((gpa - range.gpa) as usize) }
    }

    pub fn read_u64(&self, gpa: u64) -> u64 {
        unsafe { (self.host(gpa) as *const u64).read() }
    }

    /// Makes a page-table entry visible, after everything written so far: the frame it
    /// points at. Guest threads walk these tables without any lock, and on this
    /// architecture they could otherwise see the entry before the frame's contents.
    pub fn write_pte(&self, gpa: u64, value: u64) {
        std::sync::atomic::fence(std::sync::atomic::Ordering::Release);
        self.write_u64(gpa, value);
    }

    pub fn write_u64(&self, gpa: u64, v: u64) {
        unsafe { (self.host(gpa) as *mut u64).write(v) }
    }

    /// Frames the host is holding for us: those ever used, less those given back.
    pub fn frames_held(&self) -> u64 {
        let a = self.alloc.lock().unwrap();
        a.bump / PAGE - 1 - a.away * (BLOCK / PAGE)
    }

    /// Frames in use.
    pub fn frames_in_use(&self) -> u64 {
        let a = self.alloc.lock().unwrap();
        a.bump / PAGE - 1 - a.free_frames
    }
}

/// A big zeroed array: the allocator takes fresh pages from the OS, so the
/// parts never touched cost nothing.
fn zeroed_counters(n: usize) -> Box<[AtomicU32]> {
    let v: Box<[u32]> = vec![0u32; n].into_boxed_slice();
    // SAFETY: AtomicU32 has u32's size and alignment.
    unsafe { Box::from_raw(Box::into_raw(v) as *mut [AtomicU32]) }
}

pub fn random_bytes(buf: &mut [u8]) {
    os::random(buf)
}

#[cfg(unix)]
mod os {
    use std::ptr::{self, NonNull};

    pub fn reserve(size: usize) -> NonNull<u8> {
        let p = unsafe {
            libc::mmap(
                ptr::null_mut(),
                size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_ANON | libc::MAP_PRIVATE | libc::MAP_NORESERVE,
                -1,
                0,
            )
        };
        assert!(p != libc::MAP_FAILED, "failed to reserve guest memory");
        NonNull::new(p.cast()).unwrap()
    }

    #[cfg(target_os = "macos")]
    mod mach {
        unsafe extern "C" {
            pub static mach_task_self_: u32;
            pub fn mach_vm_allocate(task: u32, addr: *mut u64, size: u64, flags: i32) -> i32;
            pub fn vm_purgable_control(task: u32, addr: usize, control: i32, state: *mut i32) -> i32;
        }
        pub const VM_FLAGS_FIXED: i32 = 0;
        pub const VM_FLAGS_PURGABLE: i32 = 2;
        pub const VM_FLAGS_OVERWRITE: i32 = 0x4000;
        pub const VM_PURGABLE_SET_STATE: i32 = 0;
        pub const VM_PURGABLE_NONVOLATILE: i32 = 0;
        pub const VM_PURGABLE_EMPTY: i32 = 2;
    }

    /// Replaces a piece of the reservation with a memory object of its own. Pages
    /// still come by first touch.
    #[cfg(target_os = "macos")]
    pub fn commit(p: *mut u8, size: u64) {
        let mut addr = p as u64;
        let r = unsafe { mach::mach_vm_allocate(mach::mach_task_self_, &mut addr, size, mach::VM_FLAGS_FIXED | mach::VM_FLAGS_OVERWRITE | mach::VM_FLAGS_PURGABLE) };
        assert!(r == 0, "failed to commit guest memory: kern_return {r}");
    }

    /// Anonymous private memory is committed by first touch.
    #[cfg(not(target_os = "macos"))]
    pub fn commit(_p: *mut u8, _size: u64) {}

    /// The host takes this memory back, which is one memory object. It reads as zeros.
    #[cfg(target_os = "macos")]
    pub fn release(p: *mut u8, _size: u64) {
        let mut state = mach::VM_PURGABLE_EMPTY;
        let r = unsafe { mach::vm_purgable_control(mach::mach_task_self_, p as usize, mach::VM_PURGABLE_SET_STATE, &mut state) };
        debug_assert!(r == 0, "kern_return {r}");
    }

    #[cfg(not(target_os = "macos"))]
    pub fn release(p: *mut u8, size: u64) {
        unsafe { libc::madvise(p.cast(), size as usize, libc::MADV_DONTNEED) };
    }

    /// Memory given back is about to be used again.
    #[cfg(target_os = "macos")]
    pub fn reclaim(p: *mut u8, _size: u64) {
        let mut state = mach::VM_PURGABLE_NONVOLATILE;
        let r = unsafe { mach::vm_purgable_control(mach::mach_task_self_, p as usize, mach::VM_PURGABLE_SET_STATE, &mut state) };
        debug_assert!(r == 0, "kern_return {r}");
    }

    #[cfg(not(target_os = "macos"))]
    pub fn reclaim(_p: *mut u8, _size: u64) {}

    pub fn random(buf: &mut [u8]) {
        for chunk in buf.chunks_mut(256) {
            unsafe { libc::getentropy(chunk.as_mut_ptr().cast(), chunk.len()) };
        }
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    pub fn sync_icache(p: *mut u8, size: usize) {
        unsafe extern "C" {
            fn sys_icache_invalidate(start: *mut libc::c_void, len: usize);
        }
        unsafe { sys_icache_invalidate(p.cast(), size) };
    }

    /// x86 keeps its instruction caches coherent by itself.
    #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
    pub fn sync_icache(_p: *mut u8, _size: usize) {}
}

#[cfg(windows)]
mod os {
    use std::ptr::{self, NonNull};
    use windows_sys::Win32::Security::Cryptography::{BCRYPT_USE_SYSTEM_PREFERRED_RNG, BCryptGenRandom};
    use windows_sys::Win32::System::Memory::{MEM_COMMIT, MEM_RESERVE, MEM_RESET, PAGE_NOACCESS, PAGE_READWRITE, VirtualAlloc};

    pub fn reserve(size: usize) -> NonNull<u8> {
        let p = unsafe { VirtualAlloc(ptr::null(), size, MEM_RESERVE, PAGE_NOACCESS) };
        NonNull::new(p.cast()).expect("failed to reserve guest memory")
    }

    /// Commit charge is taken only for pieces actually in use.
    pub fn commit(p: *mut u8, size: u64) {
        let r = unsafe { VirtualAlloc(p.cast(), size as usize, MEM_COMMIT, PAGE_READWRITE) };
        assert!(!r.is_null(), "failed to commit guest memory");
    }

    /// The host may take this memory back. Its contents are gone, or may be.
    pub fn release(p: *mut u8, size: u64) {
        unsafe { VirtualAlloc(p.cast(), size as usize, MEM_RESET, PAGE_READWRITE) };
    }

    /// Memory given back is about to be used again: nothing to say to Windows.
    pub fn reclaim(_p: *mut u8, _size: u64) {}

    /// x86 keeps its instruction caches coherent by itself.
    pub fn sync_icache(_p: *mut u8, _size: usize) {}

    pub fn random(buf: &mut [u8]) {
        unsafe {
            BCryptGenRandom(ptr::null_mut(), buf.as_mut_ptr(), buf.len() as u32, BCRYPT_USE_SYSTEM_PREFERRED_RNG)
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn phys() -> Arc<PhysMem> {
        PhysMem::new(Arc::new(crate::hv::NoHv))
    }

    #[test]
    fn frames_come_back_zeroed_and_counted() {
        let phys = phys();
        let frames: Vec<u64> = (0..100).map(|_| phys.alloc().unwrap()).collect();
        assert_eq!(phys.frames_in_use(), 100);
        let unique: std::collections::HashSet<_> = frames.iter().collect();
        assert_eq!(unique.len(), 100);
        for &f in &frames {
            assert!(f != 0 && f.is_multiple_of(PAGE));
            unsafe { phys.host(f).write_bytes(0xaa, PAGE as usize) };
        }
        for &f in &frames {
            phys.free(f);
        }
        assert_eq!(phys.frames_in_use(), 0);
        let held = phys.frames_held();
        for _ in 0..100 {
            let f = phys.alloc().unwrap();
            let page = unsafe { std::slice::from_raw_parts(phys.host(f), PAGE as usize) };
            assert!(page.iter().all(|&b| b == 0));
        }
        assert_eq!(phys.frames_in_use(), 100);
        assert_eq!(phys.frames_held(), held, "uses what was freed before anything new");
    }

    /// Full blocks become free only if the frames left over go to blocks already in
    /// use: what's freed in bits doesn't keep every block half full.
    #[test]
    fn partly_free_blocks_fill_up_first() {
        let phys = phys();
        let per = (BLOCK / PAGE) as usize;
        let frames: Vec<u64> = (0..per * 8).map(|_| phys.alloc().unwrap()).collect();
        // One frame of each block.
        let singles: Vec<u64> = frames.iter().copied().filter(|f| f / PAGE % (BLOCK / PAGE) == 1).collect();
        singles.iter().for_each(|&f| phys.free(f));
        let held = phys.frames_held();
        for _ in 0..singles.len() {
            phys.alloc().unwrap();
        }
        assert_eq!(phys.frames_in_use(), frames.len() as u64);
        assert_eq!(phys.frames_held(), held, "no new block for what fits in the holes");
    }

    /// Of two blocks with room, the one with less: the other may yet come free.
    #[test]
    fn the_fullest_block_with_room_is_used_first() {
        let phys = phys();
        let per = (BLOCK / PAGE) as usize;
        let frames: Vec<u64> = (0..per * 5).map(|_| phys.alloc().unwrap()).collect();
        let block_of = |f: u64| f / BLOCK;
        let blocks: Vec<u64> = frames.iter().copied().map(block_of).collect::<std::collections::BTreeSet<_>>().into_iter().collect();
        // Keep block 0 and the open block out of this: use whole, closed ones.
        let (a, b, whole) = (blocks[1], blocks[2], blocks[3]);
        let of = |n: u64| frames.iter().copied().filter(move |&f| block_of(f) == n).collect::<Vec<_>>();
        of(a).into_iter().take(per - 1).for_each(|f| phys.free(f));
        phys.free(of(b)[0]);
        of(whole).into_iter().for_each(|f| phys.free(f));
        let f = phys.alloc_for(9).unwrap();
        assert_eq!(block_of(f), b);
        // What is left of `a` isn't used while there's a whole block to use instead.
        let g = phys.alloc_for(9).unwrap();
        assert_eq!(block_of(g), whole);
        // Nor after that: this owner has the rest of that block.
        let h = phys.alloc_for(9).unwrap();
        assert_eq!(block_of(h), whole);
        // With none, it does get used, before anything new.
        let i = phys.alloc_for(10).unwrap();
        assert_eq!(block_of(i), a);
    }

    #[test]
    fn no_two_live_address_spaces_share_an_id() {
        let phys = phys();
        let first = phys.alloc_asid().unwrap();
        assert_ne!(first, 0);
        // Round many more times than there are ids, while this one stays.
        let mut last = 0;
        for _ in 0..200_000 {
            let id = phys.alloc_asid().unwrap();
            assert_ne!(id, 0);
            assert_ne!(id, first);
            assert_ne!(id, last, "one that went comes back last");
            phys.free_asid(id);
            last = id;
        }
        let all: Vec<u16> = (0..u16::MAX - 1).map(|_| phys.alloc_asid().unwrap()).collect();
        assert_eq!(phys.alloc_asid(), Err(ENOMEM));
        assert_eq!(all.iter().collect::<std::collections::HashSet<_>>().len(), all.len());
    }

    /// A process's frames sit together, so that when it goes they all empty.
    #[test]
    fn what_one_owner_had_empties_together() {
        let phys = phys();
        let per = BLOCK / PAGE;
        // These are block 0's, with the frame that can't be handed out.
        for _ in 0..per - 1 {
            phys.alloc().unwrap();
        }
        let mut a = Vec::new();
        let mut b = Vec::new();
        for _ in 0..per * 20 {
            a.push(phys.alloc_for(1).unwrap());
            b.push(phys.alloc_for(2).unwrap());
        }
        let blocks = |v: &[u64]| v.iter().map(|f| f / BLOCK).collect::<std::collections::HashSet<_>>();
        assert!(blocks(&a).is_disjoint(&blocks(&b)));
        for &f in &a {
            phys.free(f);
        }
        // All whole again but the one still open.
        let whole = phys.alloc.lock().unwrap().warm.len() as u64;
        assert!(whole >= blocks(&a).len() as u64 - 1, "{whole} blocks whole");
    }

    #[test]
    fn a_frame_given_out_twice_would_show_here() {
        let phys = phys();
        let mut live: Vec<u64> = Vec::new();
        let mut seed = 0x9e37_79b9u32;
        for _ in 0..200_000 {
            seed ^= seed << 13;
            seed ^= seed >> 17;
            seed ^= seed << 5;
            if live.len() < 2000 && (seed & 3 != 0 || live.is_empty()) {
                let f = phys.alloc_for(seed >> 8 & 15).unwrap();
                let page = unsafe { std::slice::from_raw_parts(phys.host(f), PAGE as usize) };
                assert!(page.iter().all(|&b| b == 0), "{f:#x} isn't zero");
                unsafe { phys.host(f).write_bytes(0xcc, PAGE as usize) };
                live.push(f);
            } else {
                let i = (seed >> 4) as usize % live.len();
                phys.free(live.swap_remove(i));
            }
        }
        let unique: std::collections::HashSet<_> = live.iter().collect();
        assert_eq!(unique.len(), live.len());
        assert_eq!(phys.frames_in_use(), live.len() as u64);
    }

    #[test]
    fn plenty_freed_goes_back_to_the_host_and_can_be_used_again() {
        let phys = phys();
        let n = (WARM_MAX + 16) * (BLOCK / PAGE) as usize;
        let frames: Vec<u64> = (0..n).map(|_| phys.alloc().unwrap()).collect();
        let held = phys.frames_held();
        assert!(held <= n as u64 + BLOCK / PAGE, "only what was asked for: {held} for {n}");
        for &f in &frames {
            unsafe { phys.host(f).write_bytes(0x55, PAGE as usize) };
            phys.free(f);
        }
        assert_eq!(phys.frames_in_use(), 0);
        let after = phys.frames_held();
        assert!(after < held, "{after} of {held} still held");
        assert!(after >= (WARM_KEEP as u64 - 1) * BLOCK / PAGE, "some stay, for quick reuse: {after}");
        let again: Vec<u64> = (0..n).map(|_| phys.alloc().unwrap()).collect();
        for &f in again.iter().step_by(97) {
            let page = unsafe { std::slice::from_raw_parts(phys.host(f), PAGE as usize) };
            assert!(page.iter().all(|&b| b == 0));
        }
        assert_eq!(phys.frames_held(), held, "none new were needed");
        let unique: std::collections::HashSet<_> = again.iter().collect();
        assert_eq!(unique.len(), n);
    }
}

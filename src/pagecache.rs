//! The page cache: one copy of each page of each file on a read-only image, in
//! guest frames, read and decompressed when first wanted. Everything that maps a
//! page shares its frame until it writes, and a read(2) copies from it.
//!
//! Pages nothing has mapped are kept while there is room, then dropped oldest
//! first. Files on /data take their turn with these: their pages leave memory for
//! the host's disk (`Store`), as a file on a real device would be on flash.

use crate::errno::*;
use crate::image::ReadAt;
use crate::mm::SharedObject;
use crate::phys::{PAGE, PhysMem};
use crate::vfs::{FileSystem, io_errno};
use std::collections::{HashMap, HashSet, VecDeque};
use std::fs::File;
use std::io;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, OnceLock, Weak};

/// Where a private mapping's pages come from.
pub trait PageSource: Send + Sync {
    /// The frame holding page `idx`, with a hold on it for the caller. None where
    /// the file has no such page: the caller's own zeros will do.
    fn page(&self, idx: u64) -> Result<Option<u64>, i64>;
    /// `len` bytes from `off`, or as many as there are (some sources read zeros
    /// past their end: they don't know where that is, and the caller does).
    fn read_bytes(&self, off: u64, len: usize) -> Result<Vec<u8>, i64>;
}

/// Bytes outside guest memory (a generated file someone maps): each mapping gets
/// its own copy of what it touches.
pub struct Bytes {
    phys: Arc<PhysMem>,
    data: Arc<[u8]>,
}

impl Bytes {
    pub fn new(phys: Arc<PhysMem>, data: Arc<[u8]>) -> Bytes {
        Bytes { phys, data }
    }
}

impl PageSource for Bytes {
    fn page(&self, idx: u64) -> Result<Option<u64>, i64> {
        let off = idx.saturating_mul(PAGE);
        if off >= self.data.len() as u64 {
            return Ok(None);
        }
        let n = (self.data.len() as u64 - off).min(PAGE) as usize;
        let frame = self.phys.alloc()?;
        unsafe { std::ptr::copy_nonoverlapping(self.data.as_ptr().add(off as usize), self.phys.host(frame), n) };
        Ok(Some(frame))
    }

    fn read_bytes(&self, off: u64, len: usize) -> Result<Vec<u8>, i64> {
        let from = usize::try_from(off).unwrap_or(usize::MAX).min(self.data.len());
        Ok(self.data[from..from + len.min(self.data.len() - from)].to_vec())
    }
}

/// How much a miss reads: a file is mostly read in runs, and decompressing is by
/// the extent anyway.
const WINDOW_PAGES: u64 = 16;
/// How many pages nothing has mapped may stay. Reading them again is quick (the
/// host has the image file cached, and LZ4 is fast), so this needn't be much.
const IDLE_LIMIT: u64 = (256 << 20) / PAGE;
/// How far one trip looks for pages to drop. Pages mapped by something are passed
/// over, and a trip must not take long when most of them are.
const SCAN_BUDGET: usize = 512;
/// How far the clock can run ahead of the pages it has before it gets swept.
const SWEEP_SLACK: u64 = 1024;
#[cfg(test)]
pub const SWEEP_SLACK_FOR_TESTS: usize = SWEEP_SLACK as usize;
/// In a page's entry: looked up since the clock last came by.
const REFERENCED: u64 = 1;

/// What the clock comes round to.
enum Page {
    File(Arc<CachedFile>, u32),
    /// A page of a file on /data, which is free to be deleted meanwhile.
    Object(Weak<SharedObject>, u32),
}

impl Page {
    /// Tries to drop it: returns whether it should get another turn.
    fn try_evict(&self) -> bool {
        match self {
            Page::File(file, idx) => file.try_evict(*idx),
            Page::Object(obj, idx) => obj.upgrade().is_some_and(|o| o.try_evict(*idx)),
        }
    }

    /// Whether it is still there to come back to.
    fn alive(&self) -> bool {
        match self {
            Page::File(file, idx) => file.state.lock().unwrap().pages.contains_key(idx),
            Page::Object(obj, idx) => obj.upgrade().is_some_and(|o| o.still_in_memory(*idx)),
        }
    }
}

/// In a `kept` value: where a page of /data is when it isn't in memory. The rest of
/// the value is the byte's offset in that file.
const KEPT_IN_IMAGE: u64 = 1;
const KEPT_IN_SCRATCH: u64 = 2;
const KEPT_WHERE: u64 = KEPT_IN_IMAGE | KEPT_IN_SCRATCH;
/// A `kept` is a page's offset and tag, plus the offset in the page when reading part
/// of one, so tags sit in the top bits, clear of any offset.
const KEPT_SHIFT: u32 = 62;

/// Where the pages of /data go when they leave memory: the data image they were
/// last saved in, unchanged, or else a scratch file that goes when droidrt does.
#[derive(Default)]
pub struct Store {
    image: OnceLock<File>,
    scratch: OnceLock<io::Result<File>>,
    /// Offsets in the scratch file to use again.
    free: Mutex<Vec<u64>>,
    next: AtomicU64,
    /// Said once: pages have nowhere to go.
    complained: AtomicBool,
    /// When a write last failed, in seconds from `started`, and 0 for never: there is
    /// no use trying again for every page right away.
    last_failure: AtomicU64,
    started: OnceLock<std::time::Instant>,
}

/// How long to leave the host's disk alone after a write to it fails.
const WRITE_BACKOFF_SECS: u64 = 5;

impl Store {
    /// Pages to be read from `image` as `in_image` says.
    pub fn set_image(&self, image: File) {
        let _ = self.image.set(image);
    }

    /// A `kept` value for the page at `offset` in the image.
    pub fn in_image(offset: u64) -> u64 {
        offset | KEPT_IN_IMAGE << KEPT_SHIFT
    }

    fn scratch(&self) -> io::Result<&File> {
        self.scratch.get_or_init(open_scratch).as_ref().map_err(|e| io::Error::new(e.kind(), e.to_string()))
    }

    /// Reads from where `kept` says (with a place in the page added to it, if wanted).
    pub fn read(&self, kept: u64, buf: &mut [u8]) -> Result<(), i64> {
        let offset = kept & !(KEPT_WHERE << KEPT_SHIFT);
        let file = match kept >> KEPT_SHIFT {
            KEPT_IN_IMAGE => self.image.get().ok_or(EIO)?,
            KEPT_IN_SCRATCH => self.scratch().map_err(|_| EIO)?,
            _ => return Err(EIO),
        };
        read_exact_at(file, buf, offset).map_err(|e| {
            eprintln!("[droidrt] reading a page of /data back: {e}");
            EIO
        })
    }

    /// Writes a page out, over its old place if it has one in the scratch file.
    /// What to remember to read it back.
    pub fn write(&self, kept: u64, page: &[u8]) -> Result<u64, i64> {
        let now = self.started.get_or_init(std::time::Instant::now).elapsed().as_secs() + 1;
        let failed_at = self.last_failure.load(Ordering::Relaxed);
        if failed_at != 0 && now < failed_at + WRITE_BACKOFF_SECS {
            return Err(EIO);
        }
        let file = self.scratch();
        let has_place = kept >> KEPT_SHIFT == KEPT_IN_SCRATCH;
        let wrote = file.and_then(|file| {
            let offset = if has_place {
                kept & !(KEPT_WHERE << KEPT_SHIFT)
            } else if let Some(offset) = self.free.lock().unwrap().pop() {
                offset
            } else {
                self.next.fetch_add(PAGE, Ordering::Relaxed)
            };
            match write_all_at(file, page, offset) {
                Ok(()) => Ok(offset | KEPT_IN_SCRATCH << KEPT_SHIFT),
                Err(e) => {
                    // The place stays usable: it's the page's own, or goes back.
                    if !has_place {
                        self.free.lock().unwrap().push(offset);
                    }
                    Err(e)
                }
            }
        });
        wrote.map_err(|e| {
            self.last_failure.store(now, Ordering::Relaxed);
            if !self.complained.swap(true, Ordering::Relaxed) {
                eprintln!("[droidrt] pages of /data stay in memory: {e}");
            }
            EIO
        })
    }

    /// A page that won't be read back again.
    pub fn forget(&self, kept: u64) {
        if kept >> KEPT_SHIFT == KEPT_IN_SCRATCH {
            self.free.lock().unwrap().push(kept & !(KEPT_WHERE << KEPT_SHIFT));
        }
    }

    #[cfg(test)]
    pub fn scratch_free(&self) -> usize {
        self.free.lock().unwrap().len()
    }
}

/// A name for a scratch file not used yet.
fn scratch_path() -> std::path::PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    std::env::temp_dir().join(format!("droidrt-{}-{}.scratch", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)))
}

/// A file only this process has: it goes when the process does, however that happens.
#[cfg(unix)]
fn open_scratch() -> io::Result<File> {
    let path = scratch_path();
    let file = std::fs::OpenOptions::new().read(true).write(true).create_new(true).open(&path)?;
    std::fs::remove_file(&path)?;
    Ok(file)
}

#[cfg(windows)]
fn open_scratch() -> io::Result<File> {
    use std::os::windows::fs::OpenOptionsExt;
    const FILE_FLAG_DELETE_ON_CLOSE: u32 = 0x0400_0000;
    std::fs::OpenOptions::new().read(true).write(true).create_new(true).custom_flags(FILE_FLAG_DELETE_ON_CLOSE).open(scratch_path())
}

#[cfg(unix)]
fn read_exact_at(file: &File, buf: &mut [u8], offset: u64) -> io::Result<()> {
    std::os::unix::fs::FileExt::read_exact_at(file, buf, offset)
}

#[cfg(unix)]
fn write_all_at(file: &File, buf: &[u8], offset: u64) -> io::Result<()> {
    std::os::unix::fs::FileExt::write_all_at(file, buf, offset)
}

#[cfg(windows)]
fn read_exact_at(file: &File, buf: &mut [u8], offset: u64) -> io::Result<()> {
    let mut done = 0;
    while done < buf.len() {
        match std::os::windows::fs::FileExt::seek_read(file, &mut buf[done..], offset + done as u64)? {
            0 => return Err(io::ErrorKind::UnexpectedEof.into()),
            n => done += n,
        }
    }
    Ok(())
}

#[cfg(windows)]
fn write_all_at(file: &File, buf: &[u8], offset: u64) -> io::Result<()> {
    let mut done = 0;
    while done < buf.len() {
        match std::os::windows::fs::FileExt::seek_write(file, &buf[done..], offset + done as u64)? {
            0 => return Err(io::ErrorKind::WriteZero.into()),
            n => done += n,
        }
    }
    Ok(())
}

pub struct PageCache {
    pub phys: Arc<PhysMem>,
    /// By filesystem and inode. The clock keeps a file with pages alive, and mappings
    /// and open files do too; after that it goes, and lets go of its filesystem.
    files: Mutex<HashMap<(usize, u64), Weak<CachedFile>>>,
    /// Every page cached, in the order the clock will reach it.
    clock: Mutex<VecDeque<Page>>,
    /// How many pages nothing has mapped may stay.
    idle_limit: AtomicU64,
    store: Store,
}

pub struct CachedFile {
    me: Weak<CachedFile>,
    cache: Arc<PageCache>,
    fs: Arc<dyn FileSystem>,
    ino: u64,
    size: u64,
    /// As opened first. Only for reports.
    name: String,
    state: Mutex<FileState>,
    filled: Condvar,
}

#[derive(Default)]
struct FileState {
    /// By page: the frame, or'd with REFERENCED.
    pages: HashMap<u32, u64>,
    /// Windows being read, by someone who will wake the others.
    loading: HashSet<u32>,
}

impl PageCache {
    pub fn new(phys: Arc<PhysMem>) -> Arc<PageCache> {
        Arc::new(PageCache { phys, files: Mutex::default(), clock: Mutex::default(), idle_limit: AtomicU64::new(IDLE_LIMIT), store: Store::default() })
    }

    /// The one cached copy of a file.
    pub fn file(self: &Arc<Self>, fs: &Arc<dyn FileSystem>, ino: u64, size: u64, name: &str) -> Arc<CachedFile> {
        let key = (Arc::as_ptr(fs) as *const () as usize, ino);
        let mut files = self.files.lock().unwrap();
        if let Some(file) = files.get(&key).and_then(Weak::upgrade) {
            return file;
        }
        let file = Arc::new_cyclic(|me| CachedFile { me: me.clone(), cache: self.clone(), fs: fs.clone(), ino, size, name: name.to_string(), state: Mutex::default(), filled: Condvar::new() });
        files.insert(key, Arc::downgrade(&file));
        file
    }

    pub fn store(&self) -> &Store {
        &self.store
    }

    #[cfg(test)]
    pub fn limit_idle(&self, pages: u64) {
        self.idle_limit.store(pages, Ordering::Relaxed);
    }

    #[cfg(test)]
    pub fn clock_len(&self) -> usize {
        self.clock.lock().unwrap().len()
    }

    /// A page of a file on /data has come into memory.
    pub fn watch_object(&self, obj: Weak<SharedObject>, idx: u32) {
        self.clock.lock().unwrap().push_back(Page::Object(obj, idx));
    }

    /// One step of the clock: whether a page went, or None if it has nothing on it.
    fn tick(&self) -> Option<bool> {
        let page = self.clock.lock().unwrap().pop_front()?;
        // No lock held here: dropping pages takes their owners' locks, and may write.
        let again = page.try_evict();
        if again {
            self.clock.lock().unwrap().push_back(page);
        }
        Some(!again)
    }

    /// Clears the clock of pages long gone (a deleted file's, say), which go without
    /// telling it. It may not go round for a long time otherwise, while memory is plenty.
    fn sweep(&self) {
        let mut clock = self.clock.lock().unwrap();
        if clock.len() as u64 <= self.phys.cached_frames() * 2 + SWEEP_SLACK {
            return;
        }
        let batch: Vec<Page> = (0..SCAN_BUDGET.min(clock.len())).filter_map(|_| clock.pop_front()).collect();
        drop(clock);
        let alive: Vec<Page> = batch.into_iter().filter(Page::alive).collect();
        self.clock.lock().unwrap().extend(alive);
    }

    /// Drops pages nothing has mapped until few enough remain. A page looked up since
    /// the clock last came by, and one mapped now, get another turn.
    pub fn balance(&self) {
        self.sweep();
        for _ in 0..SCAN_BUDGET {
            if self.phys.cached_idle_frames() <= self.idle_limit.load(Ordering::Relaxed) {
                return;
            }
            if self.tick().is_none() {
                return;
            }
        }
    }

    /// Memory is short: lets `pages` pages go if it can, however recently they were
    /// used, and returns how many went.
    pub fn reclaim(&self, pages: u64) -> u64 {
        let mut gone = 0;
        // Twice round takes what a first time round only took the flag from.
        let mut steps = self.clock.lock().unwrap().len() * 2;
        while gone < pages && steps > 0 && self.phys.cached_idle_frames() > 0 {
            steps -= 1;
            let frames = self.phys.frames_in_use();
            match self.tick() {
                Some(true) if self.phys.frames_in_use() < frames => gone += 1,
                Some(_) => {}
                None => break,
            }
        }
        gone
    }

    /// The files holding the most pages, for a report.
    pub fn largest(&self, n: usize) -> Vec<(String, usize)> {
        let files: Vec<Arc<CachedFile>> = self.files.lock().unwrap().values().filter_map(Weak::upgrade).collect();
        let mut by: Vec<(String, usize)> = files.iter().map(|f| (f.name.clone(), f.state.lock().unwrap().pages.len())).collect();
        by.sort_by_key(|f| std::cmp::Reverse(f.1));
        by.truncate(n);
        by
    }
}

impl CachedFile {
    /// The clock has come to page `idx`: returns whether it should come back.
    fn try_evict(&self, idx: u32) -> bool {
        let mut st = self.state.lock().unwrap();
        let Some(&entry) = st.pages.get(&idx) else { return false };
        let frame = entry & !REFERENCED;
        // Under this lock nothing new can map it; what maps it now will let go in
        // its own time, and the clock will be back.
        if entry & REFERENCED != 0 || !self.cache.phys.is_sole_owner(frame) {
            st.pages.insert(idx, frame);
            return true;
        }
        st.pages.remove(&idx);
        self.cache.phys.release_cached(frame);
        false
    }

    fn fill(&self, window: u64) -> Result<(), i64> {
        let phys = &self.cache.phys;
        let first = window * WINDOW_PAGES;
        let start = first * PAGE;
        let mut buf = vec![0u8; (self.size - start).min(WINDOW_PAGES * PAGE) as usize];
        let mut done = 0;
        while done < buf.len() {
            match self.fs.read_at(self.ino, start + done as u64, &mut buf[done..]).map_err(io_errno)? {
                0 => break,
                n => done += n,
            }
        }
        let mut frames = Vec::with_capacity(WINDOW_PAGES as usize);
        let wanted: Vec<u64> = {
            let st = self.state.lock().unwrap();
            (first..first + (buf.len() as u64).div_ceil(PAGE)).filter(|i| !st.pages.contains_key(&(*i as u32))).collect()
        };
        for &idx in &wanted {
            let frame = match phys.alloc() {
                Ok(f) => f,
                Err(e) => {
                    frames.into_iter().for_each(|(_, f)| phys.release_cached(f));
                    return Err(e);
                }
            };
            let chunk = &buf[((idx - first) * PAGE) as usize..];
            unsafe { std::ptr::copy_nonoverlapping(chunk.as_ptr(), phys.host(frame), chunk.len().min(PAGE as usize)) };
            phys.mark_cached(frame);
            frames.push((idx as u32, frame));
        }
        self.state.lock().unwrap().pages.extend(frames.iter().copied());
        // Till it is on the clock, nothing can drop a page.
        if let Some(me) = self.me.upgrade() {
            let mut clock = self.cache.clock.lock().unwrap();
            clock.extend(frames.iter().map(|&(idx, _)| Page::File(me.clone(), idx)));
        }
        Ok(())
    }

    /// Bytes from `off`, up to `len` or the end of the file.
    pub fn read(&self, off: u64, len: usize) -> Result<Vec<u8>, i64> {
        let mut out = vec![0; self.size.saturating_sub(off).min(len as u64) as usize];
        self.read_into(off, &mut out)?;
        Ok(out)
    }

    fn read_into(&self, off: u64, buf: &mut [u8]) -> Result<(), i64> {
        let mut done = 0;
        while done < buf.len() {
            let at = off + done as u64;
            let (idx, within) = (at / PAGE, (at % PAGE) as usize);
            let n = (PAGE as usize - within).min(buf.len() - done);
            match self.page(idx)? {
                Some(frame) => {
                    unsafe { std::ptr::copy_nonoverlapping(self.cache.phys.host(frame).add(within), buf.as_mut_ptr().add(done), n) };
                    self.cache.phys.free(frame);
                }
                None => buf[done..done + n].fill(0),
            }
            done += n;
        }
        Ok(())
    }
}

impl PageSource for CachedFile {
    fn page(&self, idx: u64) -> Result<Option<u64>, i64> {
        if idx.saturating_mul(PAGE) >= self.size || idx > u32::MAX as u64 {
            return Ok(None);
        }
        let window = idx / WINDOW_PAGES;
        let mut st = self.state.lock().unwrap();
        loop {
            if let Some(entry) = st.pages.get_mut(&(idx as u32)) {
                *entry |= REFERENCED;
                let frame = *entry & !REFERENCED;
                self.cache.phys.share(frame);
                return Ok(Some(frame));
            }
            if st.loading.insert(window as u32) {
                drop(st);
                let filled = self.fill(window);
                st = self.state.lock().unwrap();
                st.loading.remove(&(window as u32));
                self.filled.notify_all();
                filled?;
                drop(st);
                self.cache.balance();
                st = self.state.lock().unwrap();
                continue;
            }
            st = self.filled.wait(st).unwrap();
        }
    }

    fn read_bytes(&self, off: u64, len: usize) -> Result<Vec<u8>, i64> {
        self.read(off, len)
    }
}

impl Drop for CachedFile {
    fn drop(&mut self) {
        // The clock holds on to a file with pages, so it has none now.
        debug_assert!(self.state.get_mut().unwrap().pages.is_empty());
        let key = (Arc::as_ptr(&self.fs) as *const () as usize, self.ino);
        let mut files = self.cache.files.lock().unwrap();
        // Unless the file is already back.
        if files.get(&key).is_some_and(|w| w.strong_count() == 0) {
            files.remove(&key);
        }
    }
}

/// A file on an image as a block device (an APEX on a loop device).
impl ReadAt for CachedFile {
    fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        if offset.saturating_add(buf.len() as u64) > self.size {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        self.read_into(offset, buf).map_err(|e| io::Error::other(Errno(e)))
    }
    fn len(&self) -> u64 {
        self.size
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mm::{AddressSpace, Backing, KernelWindow, Placement};
    use crate::paging::{PROT_READ, PROT_WRITE};
    use crate::vfs::{Dirent, Stat};
    use std::sync::atomic::AtomicUsize;

    /// Each byte is its offset's low byte, and each read is counted.
    struct Fake {
        size: u64,
        reads: AtomicUsize,
    }

    impl FileSystem for Fake {
        fn root(&self) -> io::Result<u64> {
            Ok(1)
        }
        fn stat(&self, ino: u64) -> io::Result<Stat> {
            Ok(Stat { ino, size: self.size, mode: crate::vfs::S_IFREG | 0o644, ..Default::default() })
        }
        fn lookup(&self, _: u64, _: &str) -> io::Result<Option<u64>> {
            Ok(None)
        }
        fn readdir(&self, _: u64) -> io::Result<Vec<Dirent>> {
            Ok(vec![])
        }
        fn read_all(&self, _: u64) -> io::Result<Arc<[u8]>> {
            unimplemented!("the cache reads ranges")
        }
        fn read_at(&self, _: u64, off: u64, buf: &mut [u8]) -> io::Result<usize> {
            self.reads.fetch_add(1, Ordering::Relaxed);
            let n = self.size.saturating_sub(off).min(buf.len() as u64) as usize;
            for (i, b) in buf[..n].iter_mut().enumerate() {
                *b = (off + i as u64) as u8;
            }
            Ok(n)
        }
    }

    fn fixture(size: u64) -> (Arc<PhysMem>, Arc<PageCache>, Arc<Fake>, Arc<CachedFile>) {
        let phys = PhysMem::new(Arc::new(crate::hv::NoHv));
        let cache = PageCache::new(phys.clone());
        let fake = Arc::new(Fake { size, reads: AtomicUsize::new(0) });
        let fs: Arc<dyn FileSystem> = fake.clone();
        let file = cache.file(&fs, 7, size, "/fake");
        (phys, cache, fake, file)
    }

    #[test]
    fn everyone_gets_the_same_frame_and_a_miss_reads_once() {
        let (phys, _cache, fake, file) = fixture(1 << 20);
        let a = file.page(3).unwrap().unwrap();
        let b = file.page(3).unwrap().unwrap();
        assert_eq!(a, b);
        assert_eq!(fake.reads.load(Ordering::Relaxed), 1);
        // The rest of the window came with it.
        let c = file.page(4).unwrap().unwrap();
        assert_eq!(fake.reads.load(Ordering::Relaxed), 1);
        assert_ne!(a, c);
        assert!(!phys.is_sole_owner(a));
        assert_eq!(phys.cached_frames(), WINDOW_PAGES);
        assert_eq!(phys.cached_idle_frames(), WINDOW_PAGES - 2);
        phys.free(a);
        assert_eq!(phys.cached_idle_frames(), WINDOW_PAGES - 2);
        phys.free(b);
        assert_eq!(phys.cached_idle_frames(), WINDOW_PAGES - 1);
        phys.free(c);
        assert_eq!(phys.cached_idle_frames(), WINDOW_PAGES);
    }

    #[test]
    fn reads_cross_pages_and_stop_at_the_end() {
        let (_phys, _cache, _fake, file) = fixture(PAGE * 2 + 100);
        let got = file.read(PAGE - 2, 4).unwrap();
        assert_eq!(got, [(PAGE - 2) as u8, (PAGE - 1) as u8, 0, 1]);
        assert_eq!(file.read(PAGE * 2 + 98, 100).unwrap(), [98, 99]);
        assert_eq!(file.read(PAGE * 2 + 100, 100).unwrap(), Vec::<u8>::new());
        // Past the last byte its last page is zeros, and past that there is no page.
        let f = file.page(2).unwrap().unwrap();
        let tail = unsafe { *file.cache.phys.host(f).add(100) };
        assert_eq!(tail, 0);
        file.cache.phys.free(f);
        assert_eq!(file.page(3).unwrap(), None);
    }

    #[test]
    fn idle_pages_go_and_mapped_ones_stay() {
        let (phys, cache, fake, file) = fixture(PAGE * WINDOW_PAGES * 8);
        cache.limit_idle(WINDOW_PAGES);
        let mapped = file.page(0).unwrap().unwrap();
        let before = phys.frames_in_use();
        for w in 1..8 {
            let f = file.page(w * WINDOW_PAGES).unwrap().unwrap();
            phys.free(f);
        }
        // Each page gets a second chance first, so this takes a few trips.
        for _ in 0..4 {
            cache.balance();
        }
        assert!(phys.cached_idle_frames() <= WINDOW_PAGES, "{} idle", phys.cached_idle_frames());
        assert!(phys.frames_in_use() < before + 7 * WINDOW_PAGES);
        let read = fake.reads.load(Ordering::Relaxed);
        // Still there, and the same frame: something has it.
        let again = file.page(0).unwrap().unwrap();
        assert_eq!(again, mapped);
        assert_eq!(fake.reads.load(Ordering::Relaxed), read);
        phys.free(again);
        phys.free(mapped);
    }

    #[test]
    fn nothing_is_left_when_a_file_goes() {
        let (phys, cache, _fake, file) = fixture(PAGE * WINDOW_PAGES * 2);
        let base = phys.frames_in_use();
        let f = file.page(0).unwrap().unwrap();
        phys.free(f);
        assert_eq!(phys.frames_in_use(), base + WINDOW_PAGES);
        cache.limit_idle(0);
        for _ in 0..4 {
            cache.balance();
        }
        assert_eq!(phys.frames_in_use(), base);
        assert_eq!(phys.cached_frames(), 0);
        // It is gone from the table too, so that it lets go of its filesystem.
        assert_eq!(Arc::strong_count(&file), 1);
    }

    #[test]
    fn writing_copies_and_leaves_the_file_alone() {
        let (phys, _cache, _fake, file) = fixture(PAGE * 4);
        let kernel = KernelWindow::new(&phys, &[]).unwrap();
        let (mut a, mut b) = (AddressSpace::new(phys.clone(), &kernel, 1).unwrap(), AddressSpace::new(phys.clone(), &kernel, 2).unwrap());
        let map = |mm: &mut AddressSpace| mm.map(Placement::Hint(0), PAGE * 4, PROT_READ | PROT_WRITE, Backing::File { src: file.clone(), offset: 0 }).unwrap();
        let (at_a, at_b) = (map(&mut a), map(&mut b));
        assert_eq!(a.read_vec(at_a + 5, 1).unwrap(), [5]);
        assert_eq!(b.read_vec(at_b + 5, 1).unwrap(), [5]);
        let shared = phys.frames_in_use();
        a.write(at_a + 5, &[99]).unwrap();
        assert_eq!(phys.frames_in_use(), shared + 1, "one page copied");
        assert_eq!(a.read_vec(at_a + 5, 1).unwrap(), [99]);
        assert_eq!(b.read_vec(at_b + 5, 1).unwrap(), [5]);
        assert_eq!(file.read(5, 1).unwrap(), [5]);
        // A page written before it was ever read is a copy too.
        b.write(at_b + PAGE, &[42]).unwrap();
        assert_eq!(b.read_vec(at_b + PAGE, 1).unwrap(), [42]);
        assert_eq!(a.read_vec(at_a + PAGE, 1).unwrap(), [0]);
        assert_eq!(file.read(PAGE, 1).unwrap(), [0]);
        // Going away gives back what they hold, and only that.
        drop(a);
        drop(b);
        assert_eq!(phys.cached_idle_frames(), phys.cached_frames());
    }

    #[test]
    fn a_fork_shares_what_the_cache_holds() {
        let (phys, _cache, _fake, file) = fixture(PAGE * 2);
        let kernel = KernelWindow::new(&phys, &[]).unwrap();
        let mut a = AddressSpace::new(phys.clone(), &kernel, 1).unwrap();
        let at = a.map(Placement::Hint(0), PAGE, PROT_READ | PROT_WRITE, Backing::File { src: file.clone(), offset: 0 }).unwrap();
        assert_eq!(a.read_vec(at, 1).unwrap(), [0]);
        let mut b = a.fork(&kernel, 2).unwrap();
        b.write(at, &[1]).unwrap();
        assert_eq!(a.read_vec(at, 1).unwrap(), [0]);
        a.write(at, &[2]).unwrap();
        assert_eq!(b.read_vec(at, 1).unwrap(), [1]);
        assert_eq!(file.read(0, 1).unwrap(), [0]);
    }

    /// Files as the image holds them, read through the cache, against what the
    /// archives say they hold. Touches compressed, flat and inline layouts.
    #[test]
    fn sdk_image_reads_true_through_the_cache() {
        let Some(vfs) = crate::image::sdk_image() else { return eprintln!("skip: no Android SDK image") };
        let phys = PhysMem::new(Arc::new(crate::hv::NoHv));
        vfs.set_page_cache(PageCache::new(phys));
        for path in ["/system/framework/framework-res.apk", "/system/framework/ext.jar", "/system/app/CaptivePortalLogin/CaptivePortalLogin.apk", "/apex/com.android.adbd/bin/adbd"] {
            let Ok(node) = vfs.resolve("/", path, true) else { continue };
            let file = vfs.cached(&node).unwrap().expect("cached");
            let whole = vfs.read_all(&node).unwrap();
            assert_eq!(file.read(0, usize::MAX).unwrap(), &*whole, "{path}");
            // Across any boundary, as a read of part of it would.
            let n = whole.len() as u64;
            for (off, len) in [(0, 1), (4095, 2), (n / 2, 70000), (n.saturating_sub(5), 100)] {
                let end = (off + len).min(n);
                assert_eq!(file.read(off, len as usize).unwrap(), &whole[off as usize..end as usize], "{path} at {off}");
            }
            if path.ends_with("k") || path.ends_with("r") {
                let dev: crate::image::Dev = file.clone();
                for e in crate::image::zip::entries(&dev).unwrap().iter().filter(|e| e.method == 0).take(3) {
                    crate::image::zip::open(&dev, &e.name).unwrap_or_else(|err| panic!("{path} {}: {err}", e.name));
                }
            }
        }
    }
}

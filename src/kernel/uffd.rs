//! userfaultfd, as far as ART's compacting collector needs it. With it ART runs the
//! CMC collector the image's boot image and apps were compiled for, rather than
//! recompiling everything for another one.
//!
//! The collector works in SIGBUS mode. It moves the heap's pages elsewhere with
//! mremap(MREMAP_DONTUNMAP) and registers the emptied range. A thread touching a page
//! not yet compacted gets SIGBUS, and ART's handler compacts the page and maps it with
//! UFFDIO_COPY. So there are never events to read from the descriptor, and nothing ever
//! waits in the kernel for a page. Only that mode is implemented.

use super::Thread;
use crate::errno::*;
use crate::mm::UffdCtx;
use crate::phys::PAGE;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

const UFFD_API: u64 = 0xaa;
const UFFD_USER_MODE_ONLY: u64 = 1;
const O_CLOEXEC: u64 = 0o2000000;
const O_NONBLOCK: u64 = 0o4000;
const UFFD_FEATURE_SIGBUS: u64 = 1 << 7;

const NR_REGISTER: u64 = 0x00;
const NR_UNREGISTER: u64 = 0x01;
const NR_WAKE: u64 = 0x02;
const NR_COPY: u64 = 0x03;
const NR_ZEROPAGE: u64 = 0x04;
const NR_API: u64 = 0x3f;
const UFFDIO_REGISTER_MODE_MISSING: u64 = 1;
const UFFDIO_COPY_MODE_DONTWAKE: u64 = 1;
const UFFDIO_COPY_MODE_WP: u64 = 2;
const UFFDIO_ZEROPAGE_MODE_DONTWAKE: u64 = 1;

/// "No features chosen yet": UFFDIO_API comes first, and once.
const NO_API: u64 = u64::MAX;

pub struct Uffd {
    ctx: Arc<UffdCtx>,
    features: AtomicU64,
}

impl Drop for Uffd {
    fn drop(&mut self) {
        self.ctx.open.store(false, Ordering::Relaxed);
    }
}

/// userfaultfd(2).
pub fn create(flags: u64) -> Result<Arc<Uffd>, i64> {
    if flags & !(O_CLOEXEC | O_NONBLOCK | UFFD_USER_MODE_ONLY) != 0 {
        return Err(EINVAL);
    }
    let ctx = Arc::new(UffdCtx::default());
    ctx.open.store(true, Ordering::Relaxed);
    Ok(Arc::new(Uffd { ctx, features: AtomicU64::new(NO_API) }))
}

/// A range the ioctls accept: whole pages, and something of them.
fn page_range(start: u64, len: u64) -> Result<(), i64> {
    if !start.is_multiple_of(PAGE) || !len.is_multiple_of(PAGE) || len == 0 || start.checked_add(len).is_none() {
        return Err(EINVAL);
    }
    Ok(())
}

impl Uffd {
    pub fn ioctl(&self, t: &Thread, cmd: u64, arg: u64) -> Result<i64, i64> {
        if (cmd >> 8) & 0xff != UFFD_API {
            return Err(ENOTTY);
        }
        let nr = cmd & 0xff;
        let mut mm = t.proc.mm();
        if nr == NR_API {
            let (api, features) = (mm.read_u64(arg)?, mm.read_u64(arg + 8)?);
            // Asking again is refused, or for what isn't here. Zero asks what there is.
            if api != UFFD_API || features & !UFFD_FEATURE_SIGBUS != 0 || self.features.load(Ordering::Relaxed) != NO_API {
                mm.write_u64(arg + 8, 0)?;
                mm.write_u64(arg + 16, 0)?;
                return Err(EINVAL);
            }
            self.features.store(features, Ordering::Relaxed);
            mm.write_u64(arg + 8, UFFD_FEATURE_SIGBUS)?;
            mm.write_u64(arg + 16, 1 << NR_REGISTER | 1 << NR_UNREGISTER | 1 << NR_API)?;
            return Ok(0);
        }
        let features = self.features.load(Ordering::Relaxed);
        if features == NO_API {
            return Err(EINVAL);
        }
        match nr {
            NR_REGISTER => {
                let (start, len, mode) = (mm.read_u64(arg)?, mm.read_u64(arg + 8)?, mm.read_u64(arg + 16)?);
                page_range(start, len)?;
                if mode != UFFDIO_REGISTER_MODE_MISSING || features & UFFD_FEATURE_SIGBUS == 0 {
                    return Err(EINVAL);
                }
                mm.uffd_register(&self.ctx, start, len)?;
                mm.write_u64(arg + 24, 1 << NR_WAKE | 1 << NR_COPY | 1 << NR_ZEROPAGE)?;
                Ok(0)
            }
            NR_UNREGISTER => {
                let (start, len) = (mm.read_u64(arg)?, mm.read_u64(arg + 8)?);
                page_range(start, len)?;
                mm.uffd_unregister(&self.ctx, start, len)?;
                Ok(0)
            }
            NR_WAKE => {
                page_range(mm.read_u64(arg)?, mm.read_u64(arg + 8)?)?; // nothing sleeps
                Ok(0)
            }
            NR_COPY => {
                let (dst, src, len, mode) = (mm.read_u64(arg)?, mm.read_u64(arg + 8)?, mm.read_u64(arg + 16)?, mm.read_u64(arg + 24)?);
                mm.write_u64(arg + 32, -EINVAL as u64)?;
                page_range(dst, len)?;
                page_range(src, len)?;
                if mode & !(UFFDIO_COPY_MODE_DONTWAKE | UFFDIO_COPY_MODE_WP) != 0 || (src < dst + len && dst < src + len) {
                    return Err(EINVAL);
                }
                let got = mm.uffd_fill(&self.ctx, dst, len, Some(src));
                Self::report(&mut mm, arg + 32, got)
            }
            NR_ZEROPAGE => {
                let (start, len, mode) = (mm.read_u64(arg)?, mm.read_u64(arg + 8)?, mm.read_u64(arg + 16)?);
                mm.write_u64(arg + 24, -EINVAL as u64)?;
                page_range(start, len)?;
                if mode & !UFFDIO_ZEROPAGE_MODE_DONTWAKE != 0 {
                    return Err(EINVAL);
                }
                let got = mm.uffd_fill(&self.ctx, start, len, None);
                Self::report(&mut mm, arg + 24, got)
            }
            _ => Err(EINVAL),
        }
    }

    /// As the kernel reports these: bytes mapped in the struct (or the error, if none
    /// were), and if not all of them, the error, or EAGAIN when some got through.
    fn report(mm: &mut crate::mm::AddressSpace, field: u64, (done, err): (u64, Option<i64>)) -> Result<i64, i64> {
        match err {
            None => {
                mm.write_u64(field, done)?;
                Ok(0)
            }
            Some(e) if done == 0 => {
                mm.write_u64(field, -e as u64)?;
                Err(e)
            }
            Some(_) => {
                mm.write_u64(field, done)?;
                Err(EAGAIN)
            }
        }
    }
}

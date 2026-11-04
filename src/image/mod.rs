//! Read-only access to Android images, layered as block devices:
//!
//!   system.img (GPT) → `super` partition → logical partition (LP metadata)
//!     → EROFS → file (e.g. an .apex zip) → stored zip entry → EROFS → file
//!
//! Every layer is a `ReadAt`, so filesystems never care what they sit on.
//! Pure Rust, no host filesystem APIs beyond opening the image file.

pub mod erofs;
pub mod ext4;
pub mod gpt;
pub mod inflate;
pub mod lp;
pub mod lz4;
pub mod zip;

use std::fs::File;
use std::io;
use std::path::Path;
use std::sync::Arc;

pub trait ReadAt: Send + Sync {
    /// Reads exactly `buf.len()` bytes at `offset`.
    fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<()>;
    fn len(&self) -> u64;

    fn read_vec(&self, offset: u64, len: usize) -> io::Result<Vec<u8>> {
        let mut v = vec![0; len];
        if len > 0 {
            self.read_exact_at(offset, &mut v)?;
        }
        Ok(v)
    }
}

pub type Dev = Arc<dyn ReadAt>;

fn out_of_range(offset: u64, len: usize, size: u64) -> io::Error {
    io::Error::new(
        io::ErrorKind::UnexpectedEof,
        format!("read {offset:#x}+{len:#x} past end of {size:#x}-byte device"),
    )
}

/// A host file.
pub struct FileDev {
    file: File,
    len: u64,
}

impl FileDev {
    pub fn open(path: &Path) -> io::Result<Dev> {
        let file = File::open(path)?;
        let len = file.metadata()?.len();
        Ok(Arc::new(FileDev { file, len }))
    }
}

impl ReadAt for FileDev {
    fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        if offset + buf.len() as u64 > self.len {
            return Err(out_of_range(offset, buf.len(), self.len));
        }
        #[cfg(unix)]
        {
            std::os::unix::fs::FileExt::read_exact_at(&self.file, buf, offset)
        }
        #[cfg(windows)]
        {
            let mut done = 0;
            while done < buf.len() {
                let n = std::os::windows::fs::FileExt::seek_read(
                    &self.file,
                    &mut buf[done..],
                    offset + done as u64,
                )?;
                if n == 0 {
                    return Err(io::ErrorKind::UnexpectedEof.into());
                }
                done += n;
            }
            Ok(())
        }
    }

    fn len(&self) -> u64 {
        self.len
    }
}

/// Bytes already in memory (e.g. a decompressed file).
pub struct MemDev(pub Arc<[u8]>);

impl ReadAt for MemDev {
    fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        let start = usize::try_from(offset).unwrap_or(usize::MAX);
        let src = start
            .checked_add(buf.len())
            .and_then(|end| self.0.get(start..end))
            .ok_or_else(|| out_of_range(offset, buf.len(), self.0.len() as u64))?;
        buf.copy_from_slice(src);
        Ok(())
    }

    fn len(&self) -> u64 {
        self.0.len() as u64
    }
}

/// A device assembled from extents of another device; unlisted ranges read as zeros.
pub struct ExtentDev {
    inner: Dev,
    /// (logical start, length, physical start on `inner`, or None for zero fill), sorted.
    extents: Vec<(u64, u64, Option<u64>)>,
    len: u64,
}

impl ExtentDev {
    #[allow(clippy::new_ret_no_self)] // devices are handed around as `Dev`
    pub fn new(inner: Dev, extents: Vec<(u64, u64, Option<u64>)>) -> Dev {
        let len = extents.last().map_or(0, |&(s, l, _)| s + l);
        Arc::new(ExtentDev {
            inner,
            extents,
            len,
        })
    }

    pub fn slice(inner: Dev, offset: u64, len: u64) -> Dev {
        ExtentDev::new(inner, vec![(0, len, Some(offset))])
    }
}

impl ReadAt for ExtentDev {
    fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        if offset + buf.len() as u64 > self.len {
            return Err(out_of_range(offset, buf.len(), self.len));
        }
        let mut done = 0usize;
        while done < buf.len() {
            let pos = offset + done as u64;
            let i = self.extents.partition_point(|&(s, l, _)| s + l <= pos);
            let (start, len, phys) = self.extents[i];
            let n = ((start + len - pos) as usize).min(buf.len() - done);
            let dst = &mut buf[done..done + n];
            match phys {
                Some(p) => self.inner.read_exact_at(p + (pos - start), dst)?,
                None => dst.fill(0),
            }
            done += n;
        }
        Ok(())
    }

    fn len(&self) -> u64 {
        self.len
    }
}

pub fn le16(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes(b[o..o + 2].try_into().unwrap())
}
pub fn le32(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes(b[o..o + 4].try_into().unwrap())
}
pub fn le64(b: &[u8], o: usize) -> u64 {
    u64::from_le_bytes(b[o..o + 8].try_into().unwrap())
}

pub fn invalid(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.into())
}

/// The Android SDK image tests read when it is installed: $DROIDRT_TEST_IMAGE,
/// else the newest arm64 image under ~/Library/Android/sdk (as test-android.sh).
#[cfg(test)]
pub fn sdk_image() -> Option<crate::vfs::Vfs> {
    let path = std::env::var_os("DROIDRT_TEST_IMAGE").map(std::path::PathBuf::from).or_else(|| {
        let root = Path::new(&std::env::var_os("HOME")?).join("Library/Android/sdk/system-images");
        let mut found: Vec<_> = std::fs::read_dir(&root).ok()?.flatten().filter_map(|v| {
            let n = v.file_name().into_string().ok()?;
            let ver: Vec<u32> = n.strip_prefix("android-")?.split('.').map(|p| p.parse().unwrap_or(0)).collect();
            std::fs::read_dir(v.path()).ok()?.flatten().map(|f| f.path().join("arm64-v8a/system.img")).find(|p| p.is_file()).map(|p| (ver, p))
        }).collect();
        found.sort();
        found.pop().map(|(_, p)| p)
    })?;
    match crate::android::open_system_image(&path, true) {
        Ok(v) => Some(v),
        Err(e) => panic!("{}: {e}", path.display()),
    }
}

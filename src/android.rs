//! Assembles an Android root filesystem from an SDK system image, the way
//! first-stage init and apexd would on a device: the logical partitions from
//! `super`, plus every APEX payload under /apex (unless Android's own init
//! and apexd are to mount them).

use crate::image::{Dev, FileDev, erofs::Erofs, gpt, lp, zip};
use crate::vfs::{FileSystem, LazyFs, Vfs, open_fs};
use std::io;
use std::path::Path;
use std::sync::Arc;

/// Logical partitions and where they are mounted ("system" is the root).
pub const PARTITIONS: [(&str, &str); 5] = [
    ("system", "/"),
    ("vendor", "/vendor"),
    ("system_ext", "/system_ext"),
    ("product", "/product"),
    ("system_dlkm", "/system_dlkm"),
];

/// `apexes`: pre-mount every APEX at /apex/<name>. Without, /apex is the
/// image's empty directory, for init to mount a tmpfs over and apexd to fill.
fn super_partitions(path: &Path) -> io::Result<Vec<lp::LogicalPartition>> {
    let disk = FileDev::open(path)?;
    let sup = gpt::partitions(&disk)?
        .into_iter()
        .find(|p| p.name == "super")
        .ok_or_else(|| io::Error::other("no `super` partition"))?;
    lp::partitions(&sup.dev)
}

/// The logical partitions in `super`, which first-stage init maps with
/// device-mapper (vold looks them up by name): name and contents.
pub fn logical_partitions(path: &Path) -> io::Result<Vec<(String, Dev)>> {
    Ok(super_partitions(path)?.into_iter().map(|p| (p.name, p.dev)).collect())
}

pub fn open_system_image(path: &Path, apexes: bool) -> io::Result<Vfs> {
    let logical = super_partitions(path)?;

    let mut vfs = Vfs::default();
    for (name, mountpoint) in PARTITIONS {
        if let Some(p) = logical.iter().find(|p| p.name == name) {
            vfs.mount(
                mountpoint,
                Erofs::open(p.dev.clone())? as Arc<dyn FileSystem>,
            );
        } else if name == "system" {
            return Err(io::Error::other("super has no `system` partition"));
        }
    }
    if apexes {
        mount_apexes(&mut vfs, "/system/apex")?;
    }
    Ok(vfs)
}

/// Mounts each `<dir>/*.apex` at /apex/<name>, opened lazily on first access.
fn mount_apexes(vfs: &mut Vfs, dir: &str) -> io::Result<()> {
    let Ok(node) = vfs.resolve("/", dir, true) else {
        return Ok(());
    };
    let entries = vfs
        .readdir(&node)
        .map_err(|e| io::Error::other(format!("readdir {dir}: errno {e}")))?;
    for e in entries {
        let Some(stem) = e.name.strip_suffix(".apex") else {
            continue;
        };
        // Google-signed builds ship com.google.android.X; it mounts as com.android.X.
        let name = stem.replacen("com.google.android.", "com.android.", 1);
        let file = vfs
            .resolve("/", &format!("{dir}/{}", e.name), true)
            .map_err(|errno| io::Error::other(format!("{dir}/{}: errno {errno}", e.name)))?;
        let (fs, ino) = (vfs.fs_arc(&file), file.ino);
        vfs.mount(&format!("/apex/{name}"), LazyFs::new(move || open_apex(fs, ino)));
    }
    Ok(())
}

/// The filesystem inside the APEX file `ino` of `fs`.
fn open_apex(fs: Arc<dyn FileSystem>, ino: u64) -> io::Result<Arc<dyn FileSystem>> {
    let size = fs.stat(ino)?.size;
    let mut apex: Dev = Arc::new(crate::vfs::FileAsDev { fs, ino, size });
    // A compressed APEX wraps the real one, deflated, as `original_apex` (apexd
    // decompresses it at boot on a device).
    if zip::has_entry(&apex, "original_apex")? {
        apex = zip::open(&apex, "original_apex")?;
    }
    open_fs(zip::open(&apex, "apex_payload.img")?)
}

/// The time zones the image's Android has: the names in its tzdata APEX's tzdata
/// (system/timezone, read by bionic's tzcode and libcore's ZoneInfoDb), whose header
/// is "tzdataYYYYx" and a NUL, then the big-endian offsets of the index, the data and
/// what follows, and whose index entries are a NUL-padded 40-byte name and three
/// 32-bit numbers. None if it can't be read.
pub fn time_zones(vfs: &Vfs) -> Option<Vec<String>> {
    let dir = vfs.resolve("/", "/system/apex", true).ok()?;
    let name = vfs.readdir(&dir).ok()?.into_iter().map(|e| e.name).find(|n| n.contains(".tzdata") && n.ends_with(".apex"))?;
    let file = vfs.resolve("/", &format!("/system/apex/{name}"), true).ok()?;
    let inside = Vfs::default();
    inside.mount("/", open_apex(vfs.fs_arc(&file), file.ino).ok()?);
    let data = inside.read_all(&inside.resolve("/", "/etc/tz/tzdata", true).ok()?).ok()?;
    tzdata_names(&data)
}

fn tzdata_names(data: &[u8]) -> Option<Vec<String>> {
    let be = |at: usize| data.get(at..at + 4).map(|b| u32::from_be_bytes(b.try_into().unwrap()) as usize);
    if !data.starts_with(b"tzdata") {
        return None;
    }
    let (index, end) = (be(12)?, be(16)?);
    let names: Vec<String> = data.get(index..end)?.chunks_exact(52).map(|e| String::from_utf8_lossy(&e[..40]).trim_end_matches('\0').to_string()).collect();
    (!names.is_empty()).then_some(names)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tzdata_names_come_from_its_index() {
        let mut d = b"tzdata2025b\0".to_vec();
        d.extend_from_slice(&24u32.to_be_bytes());
        d.extend_from_slice(&(24u32 + 104).to_be_bytes());
        d.extend_from_slice(&0u32.to_be_bytes());
        for name in ["Asia/Kolkata", "US/Eastern"] {
            let mut e = [0u8; 52];
            e[..name.len()].copy_from_slice(name.as_bytes());
            d.extend_from_slice(&e);
        }
        assert_eq!(tzdata_names(&d), Some(vec!["Asia/Kolkata".to_string(), "US/Eastern".to_string()]));
        assert_eq!(tzdata_names(b"nothing"), None);
    }

    /// The tested image's own list, when it is installed: what a boot checks against.
    #[test]
    fn the_tested_images_android_has_its_zones() {
        let Some(img) = crate::sdk::find().filter(|s| s.exists()).and_then(|s| s.images().into_iter().find(|i| i.is_tested())) else { return };
        let vfs = open_system_image(&img.system_img(), false).unwrap();
        let zones = time_zones(&vfs).expect("the tzdata APEX's zones");
        assert!(zones.iter().any(|z| z == "Asia/Kolkata") && zones.iter().any(|z| z == "US/Eastern"));
        assert!(!zones.iter().any(|z| z == "Factory"));
    }
}

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
        .ok_or_else(|| io::Error::other(format!("{}: no `super` partition", path.display())))?;
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
        vfs.mount(
            &format!("/apex/{name}"),
            LazyFs::new(move || {
                let size = fs.stat(ino)?.size;
                let mut apex: Dev = Arc::new(crate::vfs::FileAsDev { fs, ino, size });
                // A compressed APEX wraps the real one, deflated, as `original_apex`
                // (apexd decompresses it at boot on a device).
                if zip::has_entry(&apex, "original_apex")? {
                    apex = zip::open(&apex, "original_apex")?;
                }
                open_fs(zip::open(&apex, "apex_payload.img")?)
            }),
        );
    }
    Ok(())
}

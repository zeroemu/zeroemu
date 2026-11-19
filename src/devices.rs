//! Devices, as zeroemu.app lists them and `--device` boots them: a name, an installed
//! system image, and a /data of their own, as the Android Emulator's AVDs are. Each is
//! a folder in zeroemu's application data, devices/<id>/, holding device.ini and
//! data.img. The id is the folder's name, made from the name the device was created
//! with; it stays when the device is renamed.
//!
//! A boot without --device keeps /data in a file per image (`default_data_image`). Such
//! a file is listed here as a device too (`adopt`), so what a terminal boot saved shows
//! in the app, and `zeroemu` and the device share that /data.

use crate::sdk::{self, Image};
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, PartialEq)]
pub struct Device {
    /// Its folder's name.
    pub id: String,
    pub name: String,
    /// Its system image's SDK package path, system-images;<level>;<tag>;<abi>.
    pub package: String,
    /// Where its /data is kept: data.img in its folder, or the per-image file of
    /// terminal boots that it was made from.
    pub data: PathBuf,
    dir: PathBuf,
}

impl Device {
    /// Its device.ini, which is gone once it is deleted.
    pub fn ini(&self) -> PathBuf {
        self.dir.join("device.ini")
    }

    /// Its system image, if that is installed.
    pub fn image<'a>(&self, images: &'a [Image]) -> Option<&'a Image> {
        images.iter().find(|i| i.package() == self.package)
    }

    /// Whether a zeroemu is running it, and that zeroemu's process id if it says: the
    /// lock a boot holds on its /data (kernel::Persist), which has its id in it.
    pub fn running(&self) -> Option<Option<u32>> {
        let lock = lock_path(&self.data);
        let file = std::fs::File::open(&lock).ok()?;
        match file.try_lock() {
            // Free: let go at once. A boot that tries this very moment tries again.
            Ok(()) => None,
            Err(std::fs::TryLockError::WouldBlock) => Some(std::fs::read_to_string(&lock).ok().and_then(|s| s.trim().parse().ok())),
            Err(std::fs::TryLockError::Error(_)) => None,
        }
    }

    /// The image as people say it: "Android 16 · Google Play", or the package when
    /// it isn't installed.
    pub fn image_shown(&self, images: &[Image]) -> String {
        match self.image(images) {
            Some(i) => image_shown(i),
            None => format!("{} (not installed)", self.package.strip_prefix("system-images;").unwrap_or(&self.package).replace(';', "/")),
        }
    }
}

/// `<data>.lock`, as kernel::Persist names it.
fn lock_path(data: &Path) -> PathBuf {
    let mut s = data.as_os_str().to_owned();
    s.push(".lock");
    s.into()
}

/// An image's Android version and kind: "Android 16 · Google Play".
pub fn image_shown(img: &Image) -> String {
    let version = img.release().map(|r| format!("Android {r}")).unwrap_or_else(|| format!("API {}", img.api));
    format!("{version} · {}", tag_shown(&img.tag))
}

/// What the SDK Manager calls a system image's tag.
fn tag_shown(tag: &str) -> String {
    match tag {
        "google_apis_playstore" => "Google Play".into(),
        "google_apis" => "Google APIs".into(),
        "default" => "AOSP".into(),
        "android-automotive" | "android-automotive-playstore" => "Automotive".into(),
        "android-tv" | "google-tv" => "TV".into(),
        "android-wear" => "Wear OS".into(),
        "google_atd" | "aosp_atd" => "Automated Test Device".into(),
        other => other.replace(['_', '-'], " "),
    }
}

/// A new device's name: its image's Android version and kind, "Android 16 (Google
/// Play)", numbered after the first.
pub fn default_name(img: &Image, devices: &[Device]) -> String {
    let base = image_shown(img).replacen(" · ", " (", 1) + ")";
    let taken = |n: &str| devices.iter().any(|d| d.name.eq_ignore_ascii_case(n));
    if !taken(&base) {
        return base;
    }
    (2..).map(|i| format!("{base} {i}")).find(|n| !taken(n)).expect("some number is free")
}

/// The folder devices are kept in.
pub struct Store {
    dir: PathBuf,
}

// Making and changing devices is zeroemu.app's list's (src/gpu/window_macos/list.rs),
// which other systems don't have yet.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
impl Store {
    /// devices/ in zeroemu's application data.
    pub fn open() -> Option<Store> {
        Some(Store { dir: crate::data_dirs()?.0.join("devices") })
    }

    #[cfg(test)]
    fn at(dir: &Path) -> Store {
        Store { dir: dir.to_path_buf() }
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Every device, by name.
    pub fn list(&self) -> Vec<Device> {
        let mut out: Vec<Device> = std::fs::read_dir(&self.dir).into_iter().flatten().flatten().filter_map(|e| read(&e.path())).collect();
        out.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()).then_with(|| a.id.cmp(&b.id)));
        out
    }

    /// Makes a device of each per-image /data file of terminal boots that none has
    /// yet: `data_for` says where an image's is.
    pub fn adopt(&self, images: &[Image], data_for: impl Fn(&Image) -> Option<PathBuf>) {
        let mut devices = self.list();
        for img in images {
            let Some(data) = data_for(img).filter(|d| d.is_file()) else { continue };
            if devices.iter().any(|d| d.data == data) {
                continue;
            }
            let name = default_name(img, &devices);
            match self.make(&name, img, Some(&data)) {
                Ok(d) => devices.push(d),
                Err(e) => eprintln!("zeroemu: {}: {e}", data.display()),
            }
        }
    }

    /// A new device of `img`, with an empty /data.
    pub fn create(&self, name: &str, img: &Image) -> Result<Device, String> {
        self.make(name, img, None)
    }

    fn make(&self, name: &str, img: &Image, data: Option<&Path>) -> Result<Device, String> {
        let devices = self.list();
        let name = check_name(name, &devices, None)?;
        let taken = |id: &str| self.dir.join(id).exists();
        let base = id_for(&name);
        let id = std::iter::once(base.clone()).chain((2..).map(|i| format!("{base}-{i}"))).find(|id| !taken(id)).expect("some number is free");
        let dir = self.dir.join(&id);
        std::fs::create_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
        let d = Device { data: data.map_or_else(|| dir.join("data.img"), Path::to_path_buf), id, name, package: img.package(), dir };
        if let Err(e) = write(&d) {
            let _ = std::fs::remove_dir_all(&d.dir);
            return Err(e);
        }
        Ok(d)
    }

    /// The device with this name (any case), else this id; `id:<id>` is the id alone,
    /// as zeroemu.app's list passes it. Names first: a renamed device keeps the id its
    /// first name made, which may now be another device's name.
    pub fn find(&self, name: &str) -> Result<Device, String> {
        let devices = self.list();
        let found = match name.strip_prefix("id:") {
            Some(id) => devices.iter().find(|d| d.id == id),
            None => devices.iter().find(|d| d.name.eq_ignore_ascii_case(name)).or_else(|| devices.iter().find(|d| d.id == name)),
        };
        found
            .cloned()
            .ok_or_else(|| match devices.len() {
                0 => format!("there is no device {name:?}: none have been made yet (zeroemu.app makes them)"),
                _ => format!("there is no device {name:?}; zeroemu devices lists them"),
            })
    }

    pub fn rename(&self, d: &Device, name: &str) -> Result<Device, String> {
        let name = check_name(name, &self.list(), Some(&d.id))?;
        let renamed = Device { name, ..d.clone() };
        write(&renamed)?;
        Ok(renamed)
    }

    /// Starts its /data over, at its next boot.
    pub fn wipe(&self, d: &Device) -> Result<(), String> {
        let _held = hold(d)?;
        match std::fs::remove_file(&d.data) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(format!("{}: {e}", d.data.display())),
            _ => Ok(()),
        }
    }

    /// The device and its /data, which is gone for good: the per-image file of
    /// terminal boots too, if it was made from one, as `adopt` would bring it back.
    pub fn delete(&self, d: &Device) -> Result<(), String> {
        let _held = hold(d)?;
        if !d.data.starts_with(&d.dir) {
            for f in [d.data.clone(), lock_path(&d.data)] {
                match std::fs::remove_file(&f) {
                    Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(format!("{}: {e}", f.display())),
                    _ => {}
                }
            }
        }
        std::fs::remove_dir_all(&d.dir).map_err(|e| format!("{}: {e}", d.dir.display()))
    }
}

/// The lock a boot of `d` would take, taken here for as long as the result is kept:
/// a zeroemu starting it meanwhile can't, and one running it already means no.
fn hold(d: &Device) -> Result<std::fs::File, String> {
    let lock = lock_path(&d.data);
    let file = std::fs::OpenOptions::new().read(true).write(true).create(true).truncate(false).open(&lock).map_err(|e| format!("{}: {e}", lock.display()))?;
    match file.try_lock() {
        Ok(()) => Ok(file),
        Err(std::fs::TryLockError::WouldBlock) => Err(format!("{} is running; stop it first", d.name)),
        Err(std::fs::TryLockError::Error(e)) => Err(format!("{}: {e}", lock.display())),
    }
}

/// A device's folder, if it holds one.
fn read(dir: &Path) -> Option<Device> {
    let props = sdk::properties(&std::fs::read_to_string(dir.join("device.ini")).ok()?);
    let id = dir.file_name()?.to_str()?.to_string();
    let name = props.get("name").filter(|n| !n.is_empty()).cloned().unwrap_or_else(|| id.clone());
    let package = props.get("image").filter(|p| !p.is_empty())?.clone();
    let data = props.get("data").filter(|d| !d.is_empty()).map(PathBuf::from).unwrap_or_else(|| dir.join("data.img"));
    Some(Device { id, name, package, data, dir: dir.to_path_buf() })
}

/// Writes device.ini whole, then puts it in place, so a failure leaves the old one.
fn write(d: &Device) -> Result<(), String> {
    // device.ini is read as a .properties file (sdk::properties), which takes a
    // backslash as an escape: a Windows path keeps its own as doubled ones.
    let escape = |s: &str| s.replace('\\', "\\\\");
    let mut text = format!("name={}\nimage={}\n", escape(&d.name), escape(&d.package));
    if d.data != d.dir.join("data.img") {
        text += &format!("data={}\n", escape(&d.data.to_string_lossy()));
    }
    let path = d.dir.join("device.ini");
    let new = d.dir.join("device.ini.new");
    std::fs::write(&new, text).and_then(|()| std::fs::rename(&new, &path)).map_err(|e| format!("{}: {e}", path.display()))
}

/// A name for a device that isn't empty, fits on a line, and isn't another's.
fn check_name(name: &str, devices: &[Device], except: Option<&str>) -> Result<String, String> {
    let name = name.trim();
    if name.is_empty() {
        return Err("a device needs a name".into());
    }
    if name.chars().count() > 64 || name.chars().any(char::is_control) {
        return Err("a device's name is one line of at most 64 characters".into());
    }
    if devices.iter().any(|d| Some(d.id.as_str()) != except && d.name.eq_ignore_ascii_case(name)) {
        return Err(format!("there is a device named {name:?} already"));
    }
    Ok(name.to_string())
}

/// A folder name from a device's name: "Android 16 (Google Play)" is
/// android-16-google-play.
fn id_for(name: &str) -> String {
    let mut id = String::new();
    for c in name.chars().flat_map(char::to_lowercase) {
        if c.is_ascii_alphanumeric() {
            id.push(c);
        } else if !id.is_empty() && !id.ends_with('-') {
            id.push('-');
        }
    }
    let id: String = id.trim_end_matches('-').chars().take(40).collect();
    let id = id.trim_end_matches('-');
    if id.is_empty() { "device".into() } else { id.into() }
}

/// `zeroemu devices`: each device, its image, and whether it is running. The /data a
/// terminal boot keeps for an image becomes a device here too (`adopt`).
pub fn print_list() -> i32 {
    let Some(store) = Store::open() else {
        eprintln!("zeroemu: can't tell where devices are kept: HOME isn't set");
        return 1;
    };
    let images = sdk::find().filter(|s| s.exists()).map(|s| s.images()).unwrap_or_default();
    store.adopt(&images, |i| crate::default_data_image(&i.system_img()));
    let devices = store.list();
    println!("Devices: {}", store.dir().display());
    if devices.is_empty() {
        println!("\nNone yet. zeroemu.app makes them; a boot of an image without --device keeps one too.");
        return 0;
    }
    let rows: Vec<[String; 3]> = devices
        .iter()
        .map(|d| [d.name.clone(), d.image_shown(&images), if d.running().is_some() { "running".into() } else { String::new() }])
        .collect();
    let width = |c: usize| rows.iter().map(|r| r[c].chars().count()).max().unwrap_or(0);
    let (w0, w1) = (width(0), width(1));
    println!();
    for r in &rows {
        println!("{}", format!("{:w0$}  {:w1$}  {}", r[0], r[1], r[2]).trim_end());
    }
    println!("\nzeroemu --device <name> boots one.");
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn image(sdk: &Path, level: &str, tag: &str) -> Image {
        let dir = sdk.join("system-images").join(level).join(tag).join(sdk::host_abi());
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("build.prop"), "ro.build.version.release=16\n").unwrap();
        Image::from_dir(&dir)
    }

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("zeroemu-devices-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn ids_come_from_names() {
        assert_eq!(id_for("Android 16 (Google Play)"), "android-16-google-play");
        assert_eq!(id_for("  ***  "), "device");
        assert_eq!(id_for("Pixel—Test"), "pixel-test");
    }

    #[test]
    fn make_list_rename_and_delete() {
        let root = scratch("store");
        let img = image(&root.join("sdk"), "android-36.1", "google_apis_playstore");
        let store = Store::at(&root.join("devices"));
        assert_eq!(default_name(&img, &[]), "Android 16 (Google Play)");
        let a = store.create("Android 16 (Google Play)", &img).unwrap();
        assert_eq!(a.id, "android-16-google-play");
        assert_eq!(a.data, root.join("devices/android-16-google-play/data.img"));
        assert_eq!(default_name(&img, std::slice::from_ref(&a)), "Android 16 (Google Play) 2");
        assert!(store.create("android 16 (google play)", &img).is_err(), "names differ in more than case");
        assert!(store.create(" ", &img).is_err());
        let b = store.create("Work", &img).unwrap();
        assert_eq!(store.list(), vec![a.clone(), b.clone()]);
        let b = store.rename(&b, "A work phone").unwrap();
        assert_eq!(store.list().iter().map(|d| d.name.as_str()).collect::<Vec<_>>(), ["A work phone", "Android 16 (Google Play)"]);
        assert_eq!(store.find("work").unwrap(), b, "found by its id");
        assert_eq!(store.find("a WORK phone").unwrap(), b);
        // A new "Work" takes the name the renamed one's id came from: names win.
        let c = store.create("Work", &img).unwrap();
        assert_eq!(c.id, "work-2");
        assert_eq!(store.find("work").unwrap(), c);
        assert_eq!(store.find("id:work").unwrap(), b);
        store.delete(&c).unwrap();
        assert!(store.find("nothing").is_err());
        std::fs::write(&a.data, b"x").unwrap();
        store.wipe(&a).unwrap();
        assert!(!a.data.exists());
        store.delete(&a).unwrap();
        assert_eq!(store.list(), vec![b]);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn terminal_boots_data_is_adopted_once_and_deleted_with_the_device() {
        let root = scratch("adopt");
        let img = image(&root.join("sdk"), "android-36.1", "google_apis_playstore");
        let other = image(&root.join("sdk"), "android-35", "google_apis");
        let store = Store::at(&root.join("devices"));
        let file = root.join("data-0123.img");
        std::fs::write(&file, b"data").unwrap();
        let data_for = |i: &Image| (i.package() == img.package()).then(|| file.clone());
        store.adopt(&[img.clone(), other.clone()], data_for);
        store.adopt(&[img.clone(), other], data_for);
        let devices = store.list();
        assert_eq!(devices.len(), 1, "{devices:?}");
        assert_eq!((devices[0].name.as_str(), devices[0].data.as_path()), ("Android 16 (Google Play)", file.as_path()));
        assert_eq!(devices[0].image(std::slice::from_ref(&img)).map(Image::package), Some(img.package()));
        store.delete(&devices[0]).unwrap();
        assert!(!file.exists() && store.list().is_empty());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn backslashes_survive_device_ini() {
        let root = scratch("escape");
        let img = image(&root.join("sdk"), "android-36.1", "google_apis_playstore");
        let store = Store::at(&root.join("devices"));
        let file = PathBuf::from(r"C:\Users\tom\AppData\Local\zeroemu\data-1.img");
        let d = store.make(r"Tom\s phone", &img, Some(&file)).unwrap();
        assert_eq!(store.list(), vec![d.clone()]);
        assert_eq!((d.name.as_str(), d.data.as_path()), (r"Tom\s phone", file.as_path()));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_held_lock_is_running_with_its_process_id() {
        let root = scratch("lock");
        let img = image(&root.join("sdk"), "android-36.1", "google_apis_playstore");
        let store = Store::at(&root.join("devices"));
        let d = store.create("Phone", &img).unwrap();
        assert_eq!(d.running(), None);
        let lock = std::fs::OpenOptions::new().create(true).truncate(false).write(true).open(lock_path(&d.data)).unwrap();
        lock.try_lock().unwrap();
        std::fs::write(lock_path(&d.data), "4242\n").unwrap();
        assert_eq!(d.running(), Some(Some(4242)));
        assert!(store.delete(&d).is_err() && store.wipe(&d).is_err());
        drop(lock);
        assert_eq!(d.running(), None);
        let _ = std::fs::remove_dir_all(&root);
    }
}

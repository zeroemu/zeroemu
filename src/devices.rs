//! Devices, as zeroemu.app lists them and `--device` boots them: a name, an installed
//! system image, and a /data of their own, as the Android Emulator's AVDs are. Each is
//! a folder in zeroemu's application data, devices/<id>/, holding device.ini and
//! data.img. The id is the folder's name: the name the device was created with, then a
//! part no other device has had (`new_id`), so an id names one device for good. A
//! request made for a device that has since been deleted never reaches another made
//! after it under the same name. It stays when the device is renamed. Devices made
//! before ids had that part keep the ids they have.
//!
//! What changes devices, and a boot of one as it starts, takes devices/.lock first
//! (`Store::lock`), then checks that the device is still the one it was asked about
//! (`Store::current`): two zeroemu.apps, or one and `zeroemu --device`, take turns.
//!
//! A boot without --device keeps /data in a file per image (`default_data_image`). Such
//! a file is listed here as a device too (`adopt`), so what a terminal boot saved shows
//! in the app, and `zeroemu` and the device share that /data.

use crate::gpu::Display;
use crate::location::Source;
use crate::sdk::{self, Image};
use std::path::{Path, PathBuf};
use std::time::Duration;

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
    pub settings: Settings,
    dir: PathBuf,
}

/// What a device is like apart from its image, as an AVD's config.ini says
/// (hw.lcd.width, height and density, hw.ramSize, hw.cpu.ncore). None is zeroemu's
/// default, which `boot_settings` in main.rs fills in, so that a device made now
/// follows a better default later.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Settings {
    /// device.ini's screen= and density=.
    pub display: Option<Display>,
    /// ram=, in megabytes.
    pub ram_mb: Option<u64>,
    /// cpus=: how many cores Android sees and uses.
    pub cpus: Option<usize>,
    /// network=on|off.
    pub network: Option<bool>,
    /// timezone=, an IANA name; else the Mac's.
    pub time_zone: Option<String>,
    /// location=, as location::Source::parse reads it; else the time zone's city.
    pub location: Option<Source>,
    /// Keys this zeroemu doesn't know, from a newer one: kept, so a rename or an edit
    /// here doesn't lose them.
    pub(crate) others: Vec<(String, String)>,
}

/// The keys device.ini has.
const KEYS: [&str; 10] = ["name", "image", "data", "screen", "density", "ram", "cpus", "network", "timezone", "location"];

impl Settings {
    /// From device.ini's keys. A value that isn't valid reads as the default.
    fn read(props: &std::collections::HashMap<String, String>) -> Settings {
        let get = |k: &str| props.get(k).map(|v| v.trim()).filter(|v| !v.is_empty());
        let display = match (get("screen").and_then(|s| Display::parse_size(s).ok()), get("density").and_then(|d| d.parse().ok())) {
            (Some((w, h)), Some(dpi)) => Display::new(w, h, dpi).ok(),
            _ => None,
        };
        let mut others: Vec<(String, String)> = props.iter().filter(|(k, _)| !KEYS.contains(&k.as_str())).map(|(k, v)| (k.clone(), v.clone())).collect();
        others.sort();
        Settings {
            display,
            ram_mb: get("ram").and_then(|v| v.parse().ok()).filter(|mb| check_ram(*mb).is_ok()),
            cpus: get("cpus").and_then(|v| v.parse().ok()).filter(|n| (1..=64).contains(n)),
            network: match get("network") {
                Some("on") => Some(true),
                Some("off") => Some(false),
                _ => None,
            },
            time_zone: get("timezone").filter(|z| check_time_zone(z).is_ok()).map(str::to_string),
            location: get("location").and_then(|l| Source::parse(l).ok()),
            others,
        }
    }

    /// device.ini's lines for what is set.
    fn lines(&self) -> String {
        let mut out = String::new();
        if let Some(d) = self.display {
            out += &format!("screen={}x{}\ndensity={}\n", d.width, d.height, d.dpi);
        }
        if let Some(mb) = self.ram_mb {
            out += &format!("ram={mb}\n");
        }
        if let Some(n) = self.cpus {
            out += &format!("cpus={n}\n");
        }
        if let Some(on) = self.network {
            out += &format!("network={}\n", if on { "on" } else { "off" });
        }
        if let Some(z) = &self.time_zone {
            out += &format!("timezone={z}\n");
        }
        if let Some(l) = &self.location {
            out += &format!("location={}\n", l.to_ini());
        }
        for (k, v) in &self.others {
            out += &format!("{k}={v}\n");
        }
        out
    }
}

/// Memory Android may be told it has, in megabytes: from 1 GB to what zeroemu maps.
pub fn check_ram(mb: u64) -> Result<u64, String> {
    let max = crate::phys::PHYS_MAX >> 20;
    if (1024..=max).contains(&mb) { Ok(mb) } else { Err(format!("memory is from 1024 to {max} MB, not {mb}")) }
}

/// An IANA time zone name the tz database here has, such as Asia/Kolkata, exactly:
/// Android's own copy of the database (the tzdata APEX) has the same names, give or
/// take a zone added since the image was built, and looks them up with their case
/// (bionic's localtime.c, libcore's ZoneInfoDb), falling back to GMT for any other.
/// The Mac's disk ignores case, so each part of the name is matched against the
/// folder's own names, and the file must be a zone (TZif), not zone.tab or the like.
pub fn check_time_zone(zone: &str) -> Result<(), String> {
    let bad = || format!("{zone:?} isn't a time zone; they are named as Europe/Berlin and Asia/Kolkata are");
    if zone.is_empty() || zone.starts_with('/') || zone.split('/').any(|p| p.is_empty() || p == "." || p == "..") || zone.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(bad());
    }
    let Some(mut path) = zoneinfo_dir() else { return Ok(()) };
    // posix/ and right/ are copies of the zones with other leap-second rules.
    if zone.starts_with("posix/") || zone.starts_with("right/") {
        return Err(bad());
    }
    for part in zone.split('/') {
        let named = std::fs::read_dir(&path).into_iter().flatten().flatten().any(|e| e.file_name() == part);
        if !named {
            return Err(bad());
        }
        path.push(part);
    }
    let mut magic = [0u8; 4];
    let zone_file = std::fs::File::open(&path).and_then(|mut f| std::io::Read::read_exact(&mut f, &mut magic)).is_ok() && &magic == b"TZif";
    if zone_file { Ok(()) } else { Err(bad()) }
}

/// The host's copy of the tz database, where it has one.
fn zoneinfo_dir() -> Option<PathBuf> {
    let dir = PathBuf::from("/usr/share/zoneinfo");
    dir.is_dir().then_some(dir)
}

/// The Mac's own time zone, as /etc/localtime links to it (…/zoneinfo/Asia/Kolkata),
/// or as TZ names it.
pub fn host_time_zone() -> Option<String> {
    let named = |z: &str| check_time_zone(z).is_ok().then(|| z.to_string());
    if let Some(tz) = std::env::var("TZ").ok().map(|t| t.trim_start_matches(':').to_string())
        && let Some(z) = named(&tz)
    {
        return Some(z);
    }
    let link = std::fs::read_link("/etc/localtime").ok()?;
    let link = link.to_string_lossy();
    let zone = link.split_once("zoneinfo/")?.1;
    named(zone.strip_prefix("posix/").or_else(|| zone.strip_prefix("right/")).unwrap_or(zone))
}

/// The tz database's zones, for choosing one: zone1970.tab's (one per region where
/// clocks have agreed since 1970), by name. For zeroemu.app's form, which other
/// systems don't have yet.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub fn time_zones() -> Vec<String> {
    let Some(dir) = zoneinfo_dir() else { return Vec::new() };
    let text = std::fs::read_to_string(dir.join("zone1970.tab")).or_else(|_| std::fs::read_to_string(dir.join("zone.tab"))).unwrap_or_default();
    let mut zones: Vec<String> = text.lines().filter(|l| !l.starts_with('#')).filter_map(|l| l.split('\t').nth(2)).map(str::to_string).collect();
    zones.sort();
    zones.dedup();
    zones
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

    /// Takes devices/.lock for as long as the result is kept, if this is still the
    /// device it was when it was found: a boot of it, as it locks its /data, so that the
    /// device can't be deleted meanwhile (kernel::Persist).
    pub fn claim(&self) -> Result<Claim, String> {
        let store = Store { dir: self.dir.parent().ok_or("a device's folder has no parent")?.to_path_buf() };
        if !store.dir.is_dir() {
            return Err(gone(self));
        }
        let lock = store.lock()?;
        store.current(self)?;
        Ok(Claim(lock))
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

/// devices/.lock, held: see `Device::claim`.
pub struct Claim(#[allow(dead_code)] std::fs::File);

/// `<data>.lock`, as kernel::Persist names it.
fn lock_path(data: &Path) -> PathBuf {
    let mut s = data.as_os_str().to_owned();
    s.push(".lock");
    s.into()
}

/// The lock on a /data file, `<data>.lock`, taken: Ok(None) when someone else has it.
/// Tried twice, as zeroemu.app's list takes it for a moment to see whether a device is
/// running (`Device::running`). The file is never deleted while what it locks may be
/// used (only with a deleted device's folder, under devices/.lock), but should it be,
/// the lock taken on it is let go and taken again on the file there now, so that two
/// can never each hold one: what was locked must still be the file at that path.
pub(crate) fn lock_file(path: &Path) -> std::io::Result<Option<std::fs::File>> {
    for _ in 0..10 {
        let file = std::fs::OpenOptions::new().read(true).write(true).create(true).truncate(false).open(path)?;
        let mut tries = 0;
        loop {
            match file.try_lock() {
                Ok(()) => break,
                Err(std::fs::TryLockError::WouldBlock) if tries == 0 => std::thread::sleep(Duration::from_millis(100)),
                Err(std::fs::TryLockError::WouldBlock) => return Ok(None),
                Err(std::fs::TryLockError::Error(e)) => return Err(e),
            }
            tries += 1;
        }
        if same_file(&file, path)? {
            return Ok(Some(file));
        }
    }
    Err(std::io::Error::other(format!("{} keeps being replaced", path.display())))
}

/// Whether `path` is still the file `file` was opened as.
fn same_file(file: &std::fs::File, path: &Path) -> std::io::Result<bool> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let open = file.metadata()?;
        match std::fs::metadata(path) {
            Ok(now) => Ok(now.dev() == open.dev() && now.ino() == open.ino()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e),
        }
    }
    // Windows keeps an open file's name until the last handle is closed.
    #[cfg(not(unix))]
    {
        let _ = (file, path);
        Ok(true)
    }
}

/// What a request about a device that is no longer there, or no longer the same, says.
fn gone(d: &Device) -> String {
    format!("“{}” was changed or deleted meanwhile; look at the list again", d.name)
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

    /// devices/.lock, which whatever changes devices holds while it looks and changes,
    /// and a boot of one while it locks its /data (`Device::claim`). Waits for it: those
    /// who hold it are quick.
    fn lock(&self) -> Result<std::fs::File, String> {
        std::fs::create_dir_all(&self.dir).map_err(|e| format!("{}: {e}", self.dir.display()))?;
        let path = self.dir.join(".lock");
        let file = std::fs::OpenOptions::new().read(true).write(true).create(true).truncate(false).open(&path).map_err(|e| format!("{}: {e}", path.display()))?;
        file.lock().map_err(|e| format!("{}: {e}", path.display()))?;
        Ok(file)
    }

    /// `d` as its device.ini says now, if it is still that device: there, of the same
    /// image and with the same /data. Its name may have changed. Under `lock`.
    fn current(&self, d: &Device) -> Result<Device, String> {
        let dir = self.dir.join(&d.id);
        match read(&dir) {
            Some(now) if dir == d.dir && now.package == d.package && now.data == d.data => Ok(now),
            _ => Err(gone(d)),
        }
    }

    /// Every device, by name.
    pub fn list(&self) -> Vec<Device> {
        let mut out: Vec<Device> = std::fs::read_dir(&self.dir)
            .into_iter()
            .flatten()
            .flatten()
            .filter(|e| !e.file_name().to_string_lossy().starts_with('.'))
            .filter_map(|e| read(&e.path()))
            .collect();
        out.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()).then_with(|| a.id.cmp(&b.id)));
        out
    }

    /// Makes a device of each per-image /data file of terminal boots that none has
    /// yet: `data_for` says where an image's is.
    pub fn adopt(&self, images: &[Image], data_for: impl Fn(&Image) -> Option<PathBuf>) {
        let wanted: Vec<(&Image, PathBuf)> = images.iter().filter_map(|i| Some((i, data_for(i).filter(|d| d.is_file())?))).collect();
        // Most of the time there is nothing to do, and nothing to wait for.
        let devices = self.list();
        if wanted.iter().all(|(_, data)| devices.iter().any(|d| d.data == *data)) {
            return;
        }
        let _lock = match self.lock() {
            Ok(l) => l,
            Err(e) => return eprintln!("zeroemu: {e}"),
        };
        // Under the lock: another zeroemu may have adopted it or deleted it.
        let mut devices = self.list();
        for (img, data) in wanted {
            if !data.is_file() || devices.iter().any(|d| d.data == data) {
                continue;
            }
            let name = default_name(img, &devices);
            match self.make(&name, img, Some(&data), &Settings::default()) {
                Ok(d) => devices.push(d),
                Err(e) => eprintln!("zeroemu: {}: {e}", data.display()),
            }
        }
    }

    /// A new device of `img`, with an empty /data and the default settings.
    pub fn create(&self, name: &str, img: &Image) -> Result<Device, String> {
        self.create_with(name, img, &Settings::default())
    }

    /// A new device of `img`, with an empty /data.
    pub fn create_with(&self, name: &str, img: &Image, settings: &Settings) -> Result<Device, String> {
        let _lock = self.lock()?;
        self.make(name, img, None, settings)
    }

    /// Under `lock`.
    fn make(&self, name: &str, img: &Image, data: Option<&Path>, settings: &Settings) -> Result<Device, String> {
        let devices = self.list();
        let name = check_name(name, &devices, None)?;
        let base = id_for(&name);
        std::fs::create_dir_all(&self.dir).map_err(|e| format!("{}: {e}", self.dir.display()))?;
        // A folder of its own, made here: never one that is, or was, another's.
        let (id, dir) = loop {
            let id = new_id(&base);
            let dir = self.dir.join(&id);
            match std::fs::create_dir(&dir) {
                Ok(()) => break (id, dir),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(format!("{}: {e}", dir.display())),
            }
        };
        let d = Device { data: data.map_or_else(|| dir.join("data.img"), Path::to_path_buf), id, name, package: img.package(), settings: settings.clone(), dir };
        if let Err(e) = write(&d) {
            let _ = std::fs::remove_dir_all(&d.dir);
            return Err(e);
        }
        Ok(d)
    }

    /// The device with this name (any case), else this id; `id:<id>` is the id alone,
    /// as zeroemu.app's list passes it. Names first: a renamed device keeps the id its
    /// first name made, which may now be another device's name. No name starts with
    /// `id:` (`check_name`), so `id:` is never a name; a device named so before that
    /// was refused is found by its id, or renamed.
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

    /// Renames `d`, if it is still there.
    pub fn rename(&self, d: &Device, name: &str) -> Result<Device, String> {
        let _lock = self.lock()?;
        let now = self.current(d)?;
        let name = check_name(name, &self.list(), Some(&now.id))?;
        let renamed = Device { name, ..now };
        write(&renamed)?;
        Ok(renamed)
    }

    /// Changes `d`'s settings, if it is still there: for its next boot, so also while it
    /// runs.
    pub fn set_settings(&self, d: &Device, settings: &Settings) -> Result<Device, String> {
        let _lock = self.lock()?;
        let now = self.current(d)?;
        let changed = Device { settings: settings.clone(), ..now };
        write(&changed)?;
        Ok(changed)
    }

    /// Starts its /data over, at its next boot, if it is still there and not running.
    pub fn wipe(&self, d: &Device) -> Result<(), String> {
        let _lock = self.lock()?;
        let d = self.current(d)?;
        let _held = hold(&d)?;
        match std::fs::remove_file(&d.data) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(format!("{}: {e}", d.data.display())),
            _ => Ok(()),
        }
    }

    /// The device and its /data, which is gone for good: the per-image file of
    /// terminal boots too, if it was made from one, as `adopt` would bring it back. Only
    /// if it is still there and not running.
    ///
    /// That file's lock stays: a boot without --device may have it open, waiting its
    /// turn, and must then get the lock that any zeroemu after it takes, not one on a
    /// file no longer there that another can't see (it is what every boot of the image
    /// leaves beside its /data anyway). One in the device's folder goes with the folder:
    /// only a boot of the device uses it, and it opens it only under devices/.lock, once
    /// it has seen the device is there (`Device::claim`).
    pub fn delete(&self, d: &Device) -> Result<(), String> {
        let _lock = self.lock()?;
        let d = self.current(d)?;
        let _held = hold(&d)?;
        if !d.data.starts_with(&d.dir) {
            match std::fs::remove_file(&d.data) {
                Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(format!("{}: {e}", d.data.display())),
                _ => {}
            }
        }
        // device.ini first: if the rest fails, what is left is no device.
        std::fs::remove_file(d.ini()).map_err(|e| format!("{}: {e}", d.ini().display()))?;
        std::fs::remove_dir_all(&d.dir).map_err(|e| format!("{}: {e}", d.dir.display()))
    }
}

/// The lock a boot of `d` would take, taken here for as long as the result is kept:
/// a zeroemu starting it meanwhile can't, and one running it already means no.
fn hold(d: &Device) -> Result<std::fs::File, String> {
    let lock = lock_path(&d.data);
    match lock_file(&lock) {
        Ok(Some(file)) => Ok(file),
        Ok(None) => Err(format!("{} is running; stop it first", d.name)),
        Err(e) => Err(format!("{}: {e}", lock.display())),
    }
}

/// A device's folder, if it holds one.
fn read(dir: &Path) -> Option<Device> {
    let props = sdk::properties(&std::fs::read_to_string(dir.join("device.ini")).ok()?);
    let id = dir.file_name()?.to_str()?.to_string();
    let name = props.get("name").filter(|n| !n.is_empty()).cloned().unwrap_or_else(|| id.clone());
    let package = props.get("image").filter(|p| !p.is_empty())?.clone();
    let data = props.get("data").filter(|d| !d.is_empty()).map(PathBuf::from).unwrap_or_else(|| dir.join("data.img"));
    Some(Device { id, name, package, data, settings: Settings::read(&props), dir: dir.to_path_buf() })
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
    text += &escape(&d.settings.lines());
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
    // `--device id:<id>` is a device's id, as zeroemu.app's list starts one.
    if name.get(..3).is_some_and(|p| p.eq_ignore_ascii_case("id:")) {
        return Err("a device's name can't start with \"id:\"".into());
    }
    if devices.iter().any(|d| Some(d.id.as_str()) != except && d.name.eq_ignore_ascii_case(name)) {
        return Err(format!("there is a device named {name:?} already"));
    }
    Ok(name.to_string())
}

/// A new device's id: `base`, then a dot and 16 hex digits, from the time and the
/// randomness the standard library seeds its hash maps with. Ids made before had no
/// dot (`id_for` makes none), so none of theirs is ever made again either.
fn new_id(base: &str) -> String {
    use std::hash::{BuildHasher, Hasher};
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNT: AtomicU64 = AtomicU64::new(0);
    let mut h = std::collections::hash_map::RandomState::new().build_hasher();
    h.write_u128(std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0));
    h.write_u32(std::process::id());
    h.write_u64(COUNT.fetch_add(1, Ordering::Relaxed));
    format!("{base}.{:016x}", h.finish())
}

/// The start of a folder name, from a device's name: "Android 16 (Google Play)" is
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

    /// A device as a zeroemu before unique ids made it: its folder named for its name alone.
    fn legacy(store: &Store, id: &str, name: &str, img: &Image) -> Device {
        let dir = store.dir().join(id);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("device.ini"), format!("name={name}\nimage={}\n", img.package())).unwrap();
        read(&dir).unwrap()
    }

    #[test]
    fn ids_come_from_names() {
        assert_eq!(id_for("Android 16 (Google Play)"), "android-16-google-play");
        assert_eq!(id_for("  ***  "), "device");
        assert_eq!(id_for("Pixel—Test"), "pixel-test");
        let (a, b) = (new_id("work"), new_id("work"));
        assert_ne!(a, b);
        let hex = a.strip_prefix("work.").unwrap();
        assert!(hex.len() == 16 && hex.bytes().all(|c| c.is_ascii_hexdigit()), "{a}");
        // Never one an older zeroemu made: those have no dot.
        assert!(!id_for(&a).contains('.'));
    }

    #[test]
    fn make_list_rename_and_delete() {
        let root = scratch("store");
        let img = image(&root.join("sdk"), "android-36.1", "google_apis_playstore");
        let store = Store::at(&root.join("devices"));
        assert_eq!(default_name(&img, &[]), "Android 16 (Google Play)");
        let a = store.create("Android 16 (Google Play)", &img).unwrap();
        assert!(a.id.starts_with("android-16-google-play."), "{}", a.id);
        assert_eq!(a.data, root.join("devices").join(&a.id).join("data.img"));
        assert_eq!(default_name(&img, std::slice::from_ref(&a)), "Android 16 (Google Play) 2");
        assert!(store.create("android 16 (google play)", &img).is_err(), "names differ in more than case");
        assert!(store.create(" ", &img).is_err());
        let b = store.create("Work", &img).unwrap();
        assert_eq!(store.list(), vec![a.clone(), b.clone()]);
        let b = store.rename(&b, "A work phone").unwrap();
        assert_eq!(store.list().iter().map(|d| d.name.as_str()).collect::<Vec<_>>(), ["A work phone", "Android 16 (Google Play)"]);
        assert_eq!(store.find(&b.id).unwrap(), b, "found by its id");
        assert_eq!(store.find("a WORK phone").unwrap(), b);
        // A device named as another's id: names win, and id: is the id alone.
        let c = store.create(&b.id, &img).unwrap();
        assert_eq!(store.find(&b.id).unwrap(), c);
        assert_eq!(store.find(&format!("id:{}", b.id)).unwrap(), b);
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
    fn a_request_about_a_deleted_device_never_reaches_one_made_after_it() {
        let root = scratch("stale");
        let img = image(&root.join("sdk"), "android-36.1", "google_apis_playstore");
        let store = Store::at(&root.join("devices"));
        let old = store.create("Phone", &img).unwrap();
        // The list's row, as its confirmation was shown.
        let stale = old.clone();
        store.delete(&old).unwrap();
        let new = store.create("Phone", &img).unwrap();
        assert_ne!(new.id, old.id, "an id is never made twice");
        assert_ne!(new.dir, old.dir);
        std::fs::write(&new.data, b"kept").unwrap();
        assert!(store.wipe(&stale).is_err());
        assert!(store.delete(&stale).is_err());
        assert!(store.rename(&stale, "Other").is_err());
        assert!(stale.claim().is_err(), "a boot of it doesn't start");
        assert!(store.find(&format!("id:{}", stale.id)).is_err(), "nor does the list's Start");
        assert!(!stale.dir.exists(), "and nothing makes its folder again");
        assert_eq!(std::fs::read(&new.data).unwrap(), b"kept");
        assert_eq!(store.list(), vec![new.clone()]);
        // Renamed meanwhile, it is the same device: the request is for it.
        let renamed = store.rename(&new, "Phone 2").unwrap();
        let again = store.rename(&new, "Phone 3").unwrap();
        assert_eq!((again.id.as_str(), again.name.as_str()), (renamed.id.as_str(), "Phone 3"));
        // Made of something else in the same folder: no longer the same device.
        let other = image(&root.join("sdk"), "android-35", "google_apis");
        write(&Device { package: other.package(), ..again.clone() }).unwrap();
        assert!(store.wipe(&again).is_err() && store.delete(&again).is_err() && again.claim().is_err());
        assert_eq!(std::fs::read(&new.data).unwrap(), b"kept");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn devices_made_before_unique_ids_still_work() {
        let root = scratch("legacy");
        let img = image(&root.join("sdk"), "android-36.1", "google_apis_playstore");
        let store = Store::at(&root.join("devices"));
        let old = legacy(&store, "work", "Old phone", &img);
        assert_eq!(store.list(), vec![old.clone()]);
        assert_eq!(store.find("work").unwrap(), old);
        assert_eq!(store.find("id:work").unwrap(), old);
        assert!(old.claim().is_ok());
        let stale = old.clone();
        store.delete(&old).unwrap();
        // A new device named as the old one's id was made gets another id.
        let new = store.create("Work", &img).unwrap();
        assert_ne!(new.id, "work");
        assert!(store.delete(&stale).is_err() && store.find("id:work").is_err());
        assert_eq!(store.find("work").unwrap(), new, "by its name");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn no_name_reads_as_an_id() {
        let root = scratch("idprefix");
        let img = image(&root.join("sdk"), "android-36.1", "google_apis_playstore");
        let store = Store::at(&root.join("devices"));
        for name in ["id:work", "ID:work", " Id:x"] {
            assert!(store.create(name, &img).is_err(), "{name}");
        }
        let d = store.create("Phone", &img).unwrap();
        assert!(store.rename(&d, "id:phone").is_err());
        assert!(store.create("Kid: one", &img).is_ok() && store.create("id", &img).is_ok());
        // One named so before that was refused: id: is still the id alone.
        let target = legacy(&store, "foo", "Foo", &img);
        let _named = legacy(&store, "bar", "id:foo", &img);
        assert_eq!(store.find("id:foo").unwrap(), target);
        assert_eq!(store.find("bar").unwrap().name, "id:foo");
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
        let stale = devices[0].clone();
        store.delete(&devices[0]).unwrap();
        assert!(!file.exists() && store.list().is_empty());
        // A terminal boot saves the image's /data again, and it is adopted again: the
        // old device's request doesn't touch it.
        std::fs::write(&file, b"new").unwrap();
        store.adopt(std::slice::from_ref(&img), data_for);
        let again = store.list();
        assert_eq!(again.len(), 1);
        assert_ne!(again[0].id, stale.id);
        assert!(store.delete(&stale).is_err() && store.wipe(&stale).is_err());
        assert_eq!(std::fs::read(&file).unwrap(), b"new");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn many_at_once_adopt_one_device_and_make_one_of_a_name() {
        let root = scratch("race");
        let img = image(&root.join("sdk"), "android-36.1", "google_apis_playstore");
        let dir = root.join("devices");
        let file = root.join("data-0123.img");
        std::fs::write(&file, b"data").unwrap();
        for round in 0..5 {
            let barrier = std::sync::Barrier::new(8);
            let made = std::sync::atomic::AtomicUsize::new(0);
            std::thread::scope(|s| {
                for _ in 0..8 {
                    s.spawn(|| {
                        // Each a zeroemu of its own: a Store, and a lock file opened, of its own.
                        let store = Store::at(&dir);
                        barrier.wait();
                        store.adopt(std::slice::from_ref(&img), |_| Some(file.clone()));
                        if store.create(&format!("Same {round}"), &img).is_ok() {
                            made.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        }
                    });
                }
            });
            assert_eq!(made.into_inner(), 1);
            let list = Store::at(&dir).list();
            assert_eq!(list.iter().filter(|d| d.data == file).count(), 1, "{list:?}");
            assert_eq!(list.len(), round + 2);
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn backslashes_survive_device_ini() {
        let root = scratch("escape");
        let img = image(&root.join("sdk"), "android-36.1", "google_apis_playstore");
        let store = Store::at(&root.join("devices"));
        let file = PathBuf::from(r"C:\Users\tom\AppData\Local\zeroemu\data-1.img");
        let d = store.make(r"Tom\s phone", &img, Some(&file), &Settings::default()).unwrap();
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

    /// What a boot of a device does as it starts (kernel::Kernel::new): claims it, locks
    /// its /data, lets the claim go.
    fn boot(d: &Device) -> Result<Option<std::fs::File>, String> {
        let claim = d.claim()?;
        let locked = lock_file(&lock_path(&d.data)).map_err(|e| e.to_string());
        drop(claim);
        locked
    }

    #[test]
    fn a_boot_and_a_delete_take_turns() {
        let root = scratch("turns");
        let img = image(&root.join("sdk"), "android-36.1", "google_apis_playstore");
        let store = Store::at(&root.join("devices"));
        let d = store.create("Phone", &img).unwrap();
        // The boot first: the delete is refused.
        let running = boot(&d).unwrap().expect("free");
        assert!(store.delete(&d).unwrap_err().contains("running"));
        drop(running);
        // The delete first: the boot is refused, and makes nothing.
        store.delete(&d).unwrap();
        assert!(boot(&d).is_err());
        assert!(!d.dir.exists() && !lock_path(&d.data).exists());
        // A delete asked for while a boot holds its claim waits for it, and then
        // finds /data locked, whenever it was asked.
        let d = store.create("Phone", &img).unwrap();
        let (claimed_tx, claimed) = std::sync::mpsc::channel();
        let (stop_tx, stop) = std::sync::mpsc::channel::<()>();
        let booted = std::thread::spawn({
            let d = d.clone();
            move || {
                let claim = d.claim().unwrap();
                claimed_tx.send(()).unwrap();
                std::thread::sleep(Duration::from_millis(200));
                let data = lock_file(&lock_path(&d.data)).unwrap().expect("free");
                drop(claim);
                stop.recv().unwrap();
                drop(data);
            }
        });
        claimed.recv().unwrap();
        assert!(Store::at(&root.join("devices")).delete(&d).unwrap_err().contains("running"));
        stop_tx.send(()).unwrap();
        booted.join().unwrap();
        assert_eq!(store.list(), vec![d]);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[cfg(unix)]
    #[test]
    fn deleting_an_adopted_device_keeps_its_lock_file() {
        let root = scratch("lockfile");
        let img = image(&root.join("sdk"), "android-36.1", "google_apis_playstore");
        let store = Store::at(&root.join("devices"));
        let file = root.join("data-0123.img");
        std::fs::write(&file, b"data").unwrap();
        store.adopt(std::slice::from_ref(&img), |_| Some(file.clone()));
        let d = store.list().remove(0);
        // A terminal boot of the image has the lock file open, waiting its turn.
        let waiting = std::fs::OpenOptions::new().read(true).write(true).create(true).truncate(false).open(lock_path(&file)).unwrap();
        store.delete(&d).unwrap();
        assert!(!file.exists() && lock_path(&file).exists());
        // It gets the lock, and then no one else can: it is on the file they open too.
        waiting.try_lock().unwrap();
        assert!(same_file(&waiting, &lock_path(&file)).unwrap());
        assert!(lock_file(&lock_path(&file)).unwrap().is_none());
        drop(waiting);
        assert!(lock_file(&lock_path(&file)).unwrap().is_some());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[cfg(unix)]
    #[test]
    fn a_lock_on_a_file_no_longer_there_is_no_lock() {
        let root = scratch("replaced");
        std::fs::create_dir_all(&root).unwrap();
        let path = root.join("data.img.lock");
        let old = lock_file(&path).unwrap().unwrap();
        // Something deletes the file (an older zeroemu deleting a device did).
        std::fs::remove_file(&path).unwrap();
        assert!(!same_file(&old, &path).unwrap());
        // Then whoever locks the path gets the file there now; and a second can't.
        let now = lock_file(&path).unwrap().expect("the file there now is free");
        assert!(same_file(&now, &path).unwrap());
        assert!(lock_file(&path).unwrap().is_none());
        drop((old, now));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn settings_are_kept_and_old_devices_get_the_defaults() {
        let root = scratch("settings");
        let img = image(&root.join("sdk"), "android-36.1", "google_apis_playstore");
        let store = Store::at(&root.join("devices"));
        // Made before settings: name, image, nothing else.
        let old = store.create("Old", &img).unwrap();
        assert_eq!(store.find("Old").unwrap().settings, Settings::default());
        let settings = Settings {
            display: Some(Display::new(720, 1280, 320).unwrap()),
            ram_mb: Some(2048),
            cpus: Some(4),
            network: Some(false),
            time_zone: Some("Asia/Kolkata".into()),
            location: Some(Source::Point { lat: 12.97, lon: 77.59 }),
            others: Vec::new(),
        };
        let d = store.create_with("Small", &img, &settings).unwrap();
        assert_eq!(store.find("Small").unwrap().settings, settings);
        // A rename keeps them; set_settings changes them; a stale device can't.
        let d = store.rename(&d, "Small phone").unwrap();
        assert_eq!(store.find("Small phone").unwrap().settings, settings);
        let fewer = Settings { cpus: Some(2), ..settings.clone() };
        store.set_settings(&d, &fewer).unwrap();
        assert_eq!(store.find("Small phone").unwrap().settings.cpus, Some(2));
        store.delete(&old).unwrap();
        assert!(store.set_settings(&old, &fewer).is_err());
        // Nonsense reads as the default; keys from a newer zeroemu survive a rename.
        let ini = d.ini();
        let text = std::fs::read_to_string(&ini).unwrap() + "screen=7x9\nram=12\ncpus=0\nnetwork=maybe\nlocation=north\nfuture=yes\n";
        let text = text.replace("timezone=Asia/Kolkata", "timezone=Mars/Olympus");
        std::fs::write(&ini, text).unwrap();
        let now = store.find("Small phone").unwrap();
        assert_eq!((now.settings.ram_mb, now.settings.network, now.settings.time_zone.as_deref()), (None, None, None));
        let renamed = store.rename(&now, "Again").unwrap();
        assert!(std::fs::read_to_string(renamed.ini()).unwrap().contains("future=yes\n"));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn time_zones_are_checked_against_the_tz_database() {
        assert!(check_time_zone("../etc/passwd").is_err());
        assert!(check_time_zone("Asia Kolkata").is_err());
        if zoneinfo_dir().is_some() {
            assert!(check_time_zone("Asia/Kolkata").is_ok());
            assert!(check_time_zone("Mars/Olympus").is_err());
            // Android matches names with their case, and only zones are zones.
            assert!(check_time_zone("asia/kolkata").is_err());
            assert!(check_time_zone("zone.tab").is_err());
            assert!(check_time_zone("posix/Asia/Kolkata").is_err());
            assert!(time_zones().iter().any(|z| z == "Europe/Berlin"));
        }
    }
}

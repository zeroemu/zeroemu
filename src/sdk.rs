//! The Android SDK zeroemu reads from: where it is, the Android Emulator's GPU
//! renderer in it, and the system images installed, with whether each can boot.
//!
//! The SDK is found as Google's tools find it: `ANDROID_HOME`, then
//! `ANDROID_SDK_ROOT` (which Google has deprecated), then the default location.

use crate::image::{FileDev, gpt, le16, le32, lp};
use std::collections::HashMap;
use std::ffi::OsString;
use std::path::{Path, PathBuf};

/// The image zeroemu is tested with, on the host's ABI.
pub const TESTED_LEVEL: &str = "android-36.1";
pub const TESTED_TAG: &str = "google_apis_playstore";
/// The Android Emulator releases whose renderers zeroemu is tested with.
pub const TESTED_EMULATORS: &[&str] = &["37.1", "37.2"];

/// The Android ABI whose images run on this host's CPU.
pub fn host_abi() -> &'static str {
    if cfg!(target_arch = "aarch64") {
        "arm64-v8a"
    } else if cfg!(target_arch = "x86_64") {
        "x86_64"
    } else {
        "none"
    }
}

/// How messages name this computer.
pub fn host_name() -> &'static str {
    if cfg!(target_os = "macos") {
        "this Mac"
    } else if cfg!(windows) {
        "this PC"
    } else {
        "this computer"
    }
}

/// The SDK package of the tested image.
pub fn tested_package() -> String {
    format!("system-images;{TESTED_LEVEL};{TESTED_TAG};{}", host_abi())
}

pub struct Sdk {
    pub root: PathBuf,
    /// "ANDROID_HOME", "ANDROID_SDK_ROOT", or "the default location".
    pub found_by: &'static str,
}

/// The SDK's place when no variable names it, as Android Studio installs it.
fn default_root(env: &dyn Fn(&str) -> Option<OsString>) -> Option<PathBuf> {
    if cfg!(windows) {
        Some(PathBuf::from(env("LOCALAPPDATA")?).join("Android").join("Sdk"))
    } else if cfg!(target_os = "macos") {
        Some(PathBuf::from(env("HOME")?).join("Library/Android/sdk"))
    } else {
        Some(PathBuf::from(env("HOME")?).join("Android/Sdk"))
    }
}

/// How the help and messages write the default location.
pub fn default_root_shown() -> &'static str {
    if cfg!(windows) {
        r"%LOCALAPPDATA%\Android\Sdk"
    } else if cfg!(target_os = "macos") {
        "~/Library/Android/sdk"
    } else {
        "~/Android/Sdk"
    }
}

/// The first of ANDROID_HOME, ANDROID_SDK_ROOT and the default location that is
/// set, whether or not it exists (`Sdk::exists` says).
fn find_in(env: &dyn Fn(&str) -> Option<OsString>) -> Option<Sdk> {
    for var in ["ANDROID_HOME", "ANDROID_SDK_ROOT"] {
        if let Some(v) = env(var).filter(|v| !v.is_empty()) {
            return Some(Sdk { root: PathBuf::from(v), found_by: var });
        }
    }
    Some(Sdk { root: default_root(env)?, found_by: "the default location" })
}

pub fn find() -> Option<Sdk> {
    find_in(&|v| std::env::var_os(v))
}

/// What's wrong with the SDK that was found (or not), with the fix.
pub fn missing(sdk: Option<&Sdk>) -> crate::Problem {
    let install = format!("install Android Studio, which puts the SDK in {}, or set ANDROID_HOME to the SDK's folder", default_root_shown());
    match sdk {
        None => crate::Problem::new("no Android SDK found: ANDROID_HOME and ANDROID_SDK_ROOT aren't set", [install]),
        Some(s) if s.found_by.starts_with("ANDROID") => crate::Problem::new(
            format!("{} is {}, which isn't a folder", s.found_by, s.root.display()),
            [format!("set {} to the Android SDK's folder, or unset it to use {}", s.found_by, default_root_shown())],
        ),
        Some(s) => crate::Problem::new(format!("no Android SDK found: ANDROID_HOME and ANDROID_SDK_ROOT aren't set, and {} doesn't exist", s.root.display()), [install]),
    }
}

/// The Android SDK, or what to do to get one.
pub fn require() -> Result<Sdk, crate::Problem> {
    match find() {
        Some(s) if s.exists() => Ok(s),
        other => Err(missing(other.as_ref())),
    }
}

/// The renderer library's file names in the emulator's lib64, in the order tried.
/// The Windows emulator ships the first; older builds had the second.
const RENDERER_NAMES: &[&str] = if cfg!(windows) {
    &["libgfxstream_backend.dll", "gfxstream_backend.dll"]
} else if cfg!(target_os = "macos") {
    &["libgfxstream_backend.dylib"]
} else {
    &["libgfxstream_backend.so"]
};

pub struct Renderer {
    pub path: PathBuf,
    /// Named by ZEROEMU_GFXSTREAM rather than found in the SDK.
    pub from_env: bool,
}

/// Where the renderer is, or would be: ZEROEMU_GFXSTREAM, else the first of
/// RENDERER_NAMES present in the SDK's emulator (the first name if none is).
pub fn renderer(sdk: Option<&Sdk>) -> Option<Renderer> {
    if let Some(p) = std::env::var_os("ZEROEMU_GFXSTREAM").filter(|p| !p.is_empty()) {
        return Some(Renderer { path: p.into(), from_env: true });
    }
    let lib = sdk?.root.join("emulator").join("lib64");
    let path = RENDERER_NAMES.iter().map(|n| lib.join(n)).find(|p| p.is_file()).unwrap_or_else(|| lib.join(RENDERER_NAMES[0]));
    Some(Renderer { path, from_env: false })
}

/// The renderer library, which must exist, or what to do to get it.
pub fn require_renderer() -> Result<Renderer, crate::Problem> {
    let sdk = find();
    if let Some(r) = renderer(sdk.as_ref()) {
        if r.path.is_file() {
            return Ok(r);
        }
        if r.from_env {
            return Err(crate::Problem::new(
                format!("ZEROEMU_GFXSTREAM is {}, which doesn't exist", r.path.display()),
                ["unset ZEROEMU_GFXSTREAM to use the Android Emulator's renderer from the SDK"],
            ));
        }
    }
    match sdk {
        Some(s) if s.exists() => Err(no_emulator(&s)),
        other => Err(missing(other.as_ref())),
    }
}

/// The Android Emulator package isn't in `sdk`.
pub fn no_emulator(sdk: &Sdk) -> crate::Problem {
    let looked = renderer(Some(sdk)).map(|r| r.path).unwrap_or_default();
    crate::Problem::new(
        format!(
            "the Android Emulator package isn't installed: zeroemu draws with its GPU renderer, and there is none at {}",
            looked.display()
        ),
        [sdk.sdkmanager("emulator"), "or in Android Studio: SDK Manager, SDK Tools tab, Android Emulator".to_string()],
    )
}

/// Whether zeroemu is tested with this emulator release ("37.1.11").
pub fn emulator_tested(version: &str) -> bool {
    TESTED_EMULATORS.iter().any(|t| version == *t || version.strip_prefix(t).is_some_and(|r| r.starts_with('.')))
}

/// The tested releases as messages name them: "37.1.x and 37.2.x".
pub fn tested_emulators_shown() -> String {
    let all: Vec<String> = TESTED_EMULATORS.iter().map(|t| format!("{t}.x")).collect();
    match all.split_last() {
        Some((last, rest)) if !rest.is_empty() => format!("{} and {last}", rest.join(", ")),
        _ => all.concat(),
    }
}

impl Sdk {
    pub fn exists(&self) -> bool {
        self.root.is_dir()
    }

    /// The installed emulator's Pkg.Revision, e.g. "37.1.11".
    pub fn emulator_version(&self) -> Option<String> {
        let text = std::fs::read_to_string(self.root.join("emulator").join("source.properties")).ok()?;
        properties(&text).remove("Pkg.Revision")
    }

    pub fn adb(&self) -> PathBuf {
        self.root.join("platform-tools").join(if cfg!(windows) { "adb.exe" } else { "adb" })
    }

    /// The command that installs `package`: the SDK's own sdkmanager if it has one.
    pub fn sdkmanager(&self, package: &str) -> String {
        let tool = self.root.join("cmdline-tools").join("latest").join("bin").join(if cfg!(windows) { "sdkmanager.bat" } else { "sdkmanager" });
        let tool = if tool.is_file() { shell_quote(&tool.to_string_lossy()) } else { "sdkmanager".into() };
        format!("{tool} \"{package}\"")
    }

    pub fn images(&self) -> Vec<Image> {
        list_images(&self.root)
    }
}

/// `s` as a shell would read it back: quoted only if it needs to be.
pub fn shell_quote(s: &str) -> String {
    if !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphanumeric() || b"/._-+:@%,=".contains(&b)) {
        s.to_string()
    } else if cfg!(windows) {
        format!("\"{s}\"")
    } else {
        format!("'{}'", s.replace('\'', r"'\''"))
    }
}

/// A Java properties file, as the SDK's source.properties are: `key=value` (or
/// `key: value`) lines, `#` and `!` comments, backslash escapes.
pub fn properties(text: &str) -> HashMap<String, String> {
    let mut out = HashMap::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with('!') {
            continue;
        }
        let Some(at) = line.find(['=', ':']) else { continue };
        let unescape = |s: &str| {
            let mut out = String::new();
            let mut chars = s.chars();
            while let Some(c) = chars.next() {
                match c {
                    '\\' => match chars.next() {
                        Some('n') => out.push('\n'),
                        Some('t') => out.push('\t'),
                        Some(c) => out.push(c),
                        None => {}
                    },
                    c => out.push(c),
                }
            }
            out
        };
        out.insert(unescape(line[..at].trim()), unescape(line[at + 1..].trim()));
    }
    out
}

/// One installed system image: <sdk>/system-images/<level>/<tag>/<abi>/.
#[derive(Clone, Debug)]
pub struct Image {
    pub dir: PathBuf,
    /// As the SDK's package path names it, system-images;<level>;<tag>;<abi>: the
    /// folder names. For a folder outside an SDK, from its source.properties.
    pub level: String,
    pub tag: String,
    pub abi: String,
    /// SystemImage.TagId, which can list several: "google_apis_playstore,page_size_16kb".
    pub tags: Vec<String>,
    /// AndroidVersion.ApiLevel, e.g. "36.1".
    pub api: String,
    /// Pkg.Revision.
    pub revision: Option<String>,
    /// In an SDK's system-images folder, so its folder names are its package path.
    pub in_sdk: bool,
}

impl Image {
    /// The image in `dir`. In an SDK, its level, tag and ABI are the folder names,
    /// as sdkmanager names the package; source.properties gives the rest, where it
    /// exists (it doesn't for a download that never finished). Elsewhere, all of
    /// it comes from source.properties.
    pub fn from_dir(dir: &Path) -> Image {
        let props = std::fs::read_to_string(dir.join("source.properties")).map(|t| properties(&t)).unwrap_or_default();
        let name = |p: Option<&Path>| p.and_then(|p| p.file_name()).map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        let tag_dir = dir.parent();
        let level_dir = tag_dir.and_then(|t| t.parent());
        let in_sdk = level_dir.and_then(|l| l.parent()).and_then(|s| s.file_name()).is_some_and(|n| n == "system-images");
        let tags: Vec<String> = props.get("SystemImage.TagId").map(|t| t.split(',').map(|t| t.trim().to_string()).filter(|t| !t.is_empty()).collect()).unwrap_or_default();
        let prop = |key: &str| props.get(key).filter(|v| !v.is_empty()).cloned();
        let (level, tag, abi) = if in_sdk {
            (name(level_dir), name(tag_dir), name(Some(dir)))
        } else {
            let level = prop("AndroidVersion.ApiLevel").map(|api| format!("android-{api}")).unwrap_or_else(|| name(level_dir));
            (level, tags.first().cloned().unwrap_or_else(|| name(tag_dir)), prop("SystemImage.Abi").unwrap_or_else(|| name(Some(dir))))
        };
        let api = prop("AndroidVersion.ApiLevel").unwrap_or_else(|| level.strip_prefix("android-").unwrap_or(&level).to_string());
        Image { dir: dir.to_path_buf(), level, tag, abi, tags, api, revision: prop("Pkg.Revision"), in_sdk }
    }

    /// What `--image` takes, and `zeroemu images` shows: <level>/<tag>.
    pub fn name(&self) -> String {
        format!("{}/{}", self.level, self.tag)
    }

    pub fn package(&self) -> String {
        format!("system-images;{};{};{}", self.level, self.tag, self.abi)
    }

    pub fn system_img(&self) -> PathBuf {
        self.dir.join("system.img")
    }

    /// Android's version, e.g. "16", from the build.prop beside the image.
    pub fn release(&self) -> Option<String> {
        let text = std::fs::read_to_string(self.dir.join("build.prop")).ok()?;
        let props = properties(&text);
        props.get("ro.build.version.release").or_else(|| props.get("ro.system.build.version.release")).cloned()
    }

    /// The tested image: its package's level and tag. A copy outside an SDK counts
    /// when its source.properties say the same, with no other tag.
    pub fn is_tested(&self) -> bool {
        let tested = if self.in_sdk {
            self.level == TESTED_LEVEL && self.tag == TESTED_TAG
        } else {
            self.level == TESTED_LEVEL && self.tags == [TESTED_TAG]
        };
        tested && self.abi == host_abi()
    }

    /// Built for 16 KB pages: "ps16k" in the package's tag, or page_size_16kb among
    /// SystemImage.TagId's.
    pub fn page_size_16k(&self) -> bool {
        self.tag.contains("ps16k") || self.tags.iter().any(|t| t == "page_size_16kb")
    }
}

/// Every image under `root`/system-images, newest first.
pub fn list_images(root: &Path) -> Vec<Image> {
    let dirs = |p: &Path| -> Vec<PathBuf> {
        let mut v: Vec<PathBuf> = std::fs::read_dir(p)
            .into_iter()
            .flatten()
            .flatten()
            // is_dir follows links: an image may be linked in from elsewhere.
            .filter(|e| !e.file_name().to_string_lossy().starts_with('.') && e.path().is_dir())
            .map(|e| e.path())
            .collect();
        v.sort();
        v
    };
    let mut out = Vec::new();
    for level in dirs(&root.join("system-images")) {
        for tag in dirs(&level) {
            for abi in dirs(&tag) {
                out.push(Image::from_dir(&abi));
            }
        }
    }
    let version = |api: &str| -> Vec<u32> { api.split('.').map(|p| p.parse().unwrap_or(0)).collect() };
    out.sort_by(|a, b| version(&b.api).cmp(&version(&a.api)).then_with(|| a.level.cmp(&b.level)).then_with(|| a.tag.cmp(&b.tag)).then_with(|| a.abi.cmp(&b.abi)));
    out
}

#[derive(Clone, Debug, PartialEq)]
pub enum Support {
    Tested,
    Untested,
    Unsupported(String),
}

impl Support {
    pub fn boots(&self) -> bool {
        !matches!(self, Support::Unsupported(_))
    }
}

impl std::fmt::Display for Support {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Support::Tested => f.write_str("tested"),
            Support::Untested => f.write_str("untested"),
            Support::Unsupported(why) => write!(f, "unsupported: {why}"),
        }
    }
}

/// Why an image can't boot, from what's known without reading it.
fn unsupported_by_properties(img: &Image) -> Option<String> {
    if !img.system_img().is_file() {
        return Some("not fully installed".into());
    }
    if img.abi != host_abi() {
        return Some(format!("{} image; {} runs {} images", img.abi, host_name(), host_abi()));
    }
    if img.page_size_16k() {
        return Some("16 KB page size isn't supported yet".into());
    }
    None
}

/// Whether `img` can boot, and whether it is the one zeroemu is tested with.
pub fn classify(img: &Image) -> Support {
    if let Some(why) = unsupported_by_properties(img) {
        return Support::Unsupported(why);
    }
    match probe(&img.system_img()) {
        Err(why) => Support::Unsupported(why),
        Ok(()) if img.is_tested() => Support::Tested,
        Ok(()) => Support::Untested,
    }
}

/// A system.img given by path: its SDK image if it sits in one (source.properties
/// beside it), and whether it can boot.
pub fn classify_file(system_img: &Path) -> (Option<Image>, Support) {
    // Absolute, so a relative path still shows which folders hold it.
    let system_img = std::path::absolute(system_img).unwrap_or_else(|_| system_img.to_path_buf());
    let dir = system_img.parent().unwrap_or(Path::new("."));
    if system_img.file_name().is_some_and(|n| n == "system.img") && dir.join("source.properties").is_file() {
        let img = Image::from_dir(dir);
        let support = classify(&img);
        return (Some(img), support);
    }
    match probe(&system_img) {
        Ok(()) => (None, Support::Untested),
        Err(why) => (None, Support::Unsupported(why)),
    }
}

const NEEDS_10: &str = "needs Android 10 or newer";
const EROFS_MAGIC: u32 = 0xe0f5_e1e2;
const EXT4_MAGIC: u16 = 0xef53;

/// Reads only what says whether zeroemu can mount the image: the GPT, the super
/// partition's metadata, and each logical partition's superblock.
pub fn probe(system_img: &Path) -> Result<(), String> {
    // An image from before Android 10 is a bare filesystem, or a GPT with no super.
    // Anything else wrong is just that.
    let unreadable = |e: std::io::Error| match e.kind() {
        std::io::ErrorKind::UnexpectedEof => "its system.img is cut short".to_string(),
        _ => format!("its system.img can't be read ({e})"),
    };
    let disk = FileDev::open(system_img).map_err(unreadable)?;
    let header = disk.read_vec(gpt::SECTOR, 8).map_err(unreadable)?;
    if header[..] != gpt::SIGNATURE[..] {
        return Err(NEEDS_10.into());
    }
    let parts = gpt::partitions(&disk).map_err(unreadable)?;
    let sup = parts.into_iter().find(|p| p.name == "super").ok_or_else(|| NEEDS_10.to_string())?;
    let logical = lp::partitions(&sup.dev).map_err(|e| format!("its super partition can't be read ({e})"))?;
    if !logical.iter().any(|p| p.name == "system") {
        return Err("its super partition has no system partition".into());
    }
    for (name, _) in crate::android::PARTITIONS {
        let Some(p) = logical.iter().find(|p| p.name == name) else { continue };
        if p.dev.len() == 0 {
            continue;
        }
        let sb = p.dev.read_vec(1024, 64).map_err(|e| format!("its {name} partition can't be read ({e})"))?;
        if le32(&sb, 0) == EROFS_MAGIC {
            continue;
        }
        return Err(if le16(&sb, 56) == EXT4_MAGIC { "ext4 partitions aren't supported yet".into() } else { format!("its {name} partition isn't EROFS") });
    }
    Ok(())
}

/// What `--image` names: a level, optionally a tag, optionally an ABI.
#[derive(Debug, PartialEq)]
pub struct Spec {
    pub level: String,
    pub tag: Option<String>,
    pub abi: Option<String>,
}

/// "android-36.1", "36.1", "android-36.1/google_apis_playstore[/arm64-v8a]", or the
/// package path "system-images;android-36.1;google_apis_playstore;arm64-v8a".
pub fn parse_spec(s: &str) -> Result<Spec, String> {
    let bad = || format!("--image wants a name such as {TESTED_LEVEL}, {TESTED_LEVEL}/{TESTED_TAG}, or {}; got \"{s}\"", tested_package());
    let parts: Vec<&str> = match s.strip_prefix("system-images;") {
        Some(rest) => rest.split(';').collect(),
        None => s.trim_end_matches('/').split('/').collect(),
    };
    if parts.is_empty() || parts.len() > 3 || parts.iter().any(|p| p.is_empty()) {
        return Err(bad());
    }
    let level = if parts[0].starts_with(|c: char| c.is_ascii_digit()) { format!("android-{}", parts[0]) } else { parts[0].to_string() };
    Ok(Spec { level, tag: parts.get(1).map(|t| t.to_string()), abi: parts.get(2).map(|a| a.to_string()) })
}

impl Spec {
    fn matches(&self, img: &Image) -> bool {
        img.level == self.level && self.tag.as_ref().is_none_or(|t| *t == img.tag) && self.abi.as_ref().is_none_or(|a| *a == img.abi)
    }
}

/// The installed image `spec` names, on the host's ABI, with whether it boots. Of
/// several, the one that boots; the tested one if more than one does.
pub fn pick(spec: &str, images: &[Image], classify: impl Fn(&Image) -> Support) -> Result<(Image, Support), String> {
    let spec_ = parse_spec(spec)?;
    if let Some(abi) = spec_.abi.as_deref().filter(|&a| a != host_abi()) {
        return Err(format!("{abi} images can't run here: {} runs {} images", host_name(), host_abi()));
    }
    let all: Vec<&Image> = images.iter().filter(|i| spec_.matches(i)).collect();
    let here: Vec<&Image> = all.iter().copied().filter(|i| i.abi == host_abi()).collect();
    if here.is_empty() {
        if let Some(other) = all.first() {
            return Err(format!("{} ({}) is unsupported: {} image; {} runs {} images", other.name(), other.abi, other.abi, host_name(), host_abi()));
        }
        return Err(format!("no installed system image matches \"{spec}\"; zeroemu images lists them"));
    }
    let mut found: Vec<(&Image, Support)> = here.into_iter().map(|i| (i, classify(i))).collect();
    if found.len() > 1 {
        let boots: Vec<usize> = (0..found.len()).filter(|&i| found[i].1.boots()).collect();
        let chosen = boots.iter().copied().find(|&i| found[i].1 == Support::Tested).or_else(|| (boots.len() == 1).then(|| boots[0]));
        if let Some(i) = chosen {
            let (img, s) = found.swap_remove(i);
            return Ok((img.clone(), s));
        }
        let names: Vec<String> = found.iter().map(|(i, s)| format!("{} ({s})", i.name())).collect();
        return Err(if boots.is_empty() {
            format!("none of the images \"{spec}\" matches can boot: {}", names.join(", "))
        } else {
            format!("\"{spec}\" matches several images: {}; name one with its tag", names.join(", "))
        });
    }
    let (img, s) = found.remove(0);
    match s {
        Support::Unsupported(why) => Err(format!("{} is unsupported: {why}", img.name())),
        s => Ok((img.clone(), s)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fresh directory under the system's temp folder, removed when dropped.
    struct TempDir(PathBuf);
    impl TempDir {
        fn new(name: &str) -> TempDir {
            static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
            let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let p = std::env::temp_dir().join(format!("zeroemu-sdk-{name}-{}-{n}", std::process::id()));
            let _ = std::fs::remove_dir_all(&p);
            std::fs::create_dir_all(&p).unwrap();
            TempDir(p)
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn put(path: &Path, data: &[u8]) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, data).unwrap();
    }

    fn props(level: &str, tag: &str, abi: &str) -> String {
        format!(
            "Pkg.Desc=System Image {abi} with Google Play.\nPkg.Revision=4\nAndroidVersion.ApiLevel={}\nSystemImage.Abi={abi}\nSystemImage.TagId={tag}\nSystemImage.TagDisplay=Google Play\n",
            level.trim_start_matches("android-")
        )
    }

    /// A system.img as the emulator's are laid out: a GPT whose `super` partition holds
    /// LP metadata for `system` and `vendor`, each starting with the given superblock.
    fn fake_system_img(fs: &str) -> Vec<u8> {
        const SECTOR: usize = 512;
        let part_bytes = 4096;
        let super_start = 34 * SECTOR; // past the GPT header and entries
        let data_off = 64 * 1024; // logical partitions' data within super
        let super_len = data_off + 2 * part_bytes;
        let mut img = vec![0u8; super_start + super_len + 34 * SECTOR];
        let w32 = |b: &mut [u8], o: usize, v: u32| b[o..o + 4].copy_from_slice(&v.to_le_bytes());
        let w64 = |b: &mut [u8], o: usize, v: u64| b[o..o + 8].copy_from_slice(&v.to_le_bytes());
        // GPT header at LBA 1, one 128-byte entry at LBA 2.
        img[SECTOR..SECTOR + 8].copy_from_slice(b"EFI PART");
        w64(&mut img, SECTOR + 72, 2);
        w32(&mut img, SECTOR + 80, 1);
        w32(&mut img, SECTOR + 84, 128);
        let e = 2 * SECTOR;
        img[e] = 1; // a type GUID that isn't all zeros
        w64(&mut img, e + 32, (super_start / SECTOR) as u64);
        w64(&mut img, e + 40, ((super_start + super_len) / SECTOR - 1) as u64);
        for (i, c) in "super".encode_utf16().enumerate() {
            img[e + 56 + i * 2..e + 58 + i * 2].copy_from_slice(&c.to_le_bytes());
        }
        // LP geometry, then the metadata header, its tables: two partitions, two extents.
        let s = super_start;
        w32(&mut img, s + 4096, 0x616c_4467);
        let h = s + 4096 + 2 * 4096;
        let header_size = 128;
        w32(&mut img, h, 0x414c_5030);
        w32(&mut img, h + 8, header_size as u32);
        let (p_size, e_size) = (52, 24);
        w32(&mut img, h + 44, (2 * p_size + 2 * e_size) as u32);
        // Descriptors: partitions at 0, extents after them.
        w32(&mut img, h + 80, 0);
        w32(&mut img, h + 84, 2);
        w32(&mut img, h + 88, p_size as u32);
        w32(&mut img, h + 92, (2 * p_size) as u32);
        w32(&mut img, h + 96, 2);
        w32(&mut img, h + 100, e_size as u32);
        let t = h + header_size;
        for (i, name) in ["system", "vendor"].iter().enumerate() {
            let p = t + i * p_size;
            img[p..p + name.len()].copy_from_slice(name.as_bytes());
            w32(&mut img, p + 40, i as u32);
            w32(&mut img, p + 44, 1);
            let x = t + 2 * p_size + i * e_size;
            w64(&mut img, x, (part_bytes / SECTOR) as u64);
            w32(&mut img, x + 8, 0);
            w64(&mut img, x + 12, ((data_off + i * part_bytes) / SECTOR) as u64);
            let sb = s + data_off + i * part_bytes + 1024;
            match fs {
                "erofs" => w32(&mut img, sb, EROFS_MAGIC),
                "ext4" => img[sb + 56..sb + 58].copy_from_slice(&EXT4_MAGIC.to_le_bytes()),
                _ => {}
            }
        }
        img
    }

    /// An SDK tree with one image per entry: (level, tag, abi, system.img contents).
    fn fake_sdk(images: &[(&str, &str, &str, Option<Vec<u8>>)]) -> TempDir {
        let d = TempDir::new("tree");
        for (level, tag, abi, system) in images {
            let dir = d.0.join("system-images").join(level).join(tag).join(abi);
            put(&dir.join("source.properties"), props(level, tag, abi).as_bytes());
            if let Some(s) = system {
                put(&dir.join("system.img"), s);
            }
        }
        d
    }

    #[test]
    fn source_properties() {
        let p = properties("# comment\n! another\nPkg.Revision=37.1.11\n  Pkg.Path = emulator \nPkg.Desc=Android Emulator\nkey: value\nesc=a\\=b\\\\c\n\nnovalue\n");
        assert_eq!(p["Pkg.Revision"], "37.1.11");
        assert_eq!(p["Pkg.Path"], "emulator");
        assert_eq!(p["Pkg.Desc"], "Android Emulator");
        assert_eq!(p["key"], "value");
        assert_eq!(p["esc"], "a=b\\c");
        assert!(!p.contains_key("novalue"));
        assert_eq!(p.len(), 5);
    }

    #[test]
    fn emulator_versions() {
        assert!(emulator_tested("37.1.11"));
        assert!(emulator_tested("37.1"));
        assert!(emulator_tested("37.2.13"));
        assert!(!emulator_tested("37.10.1"));
        assert!(!emulator_tested("37.20.1"));
        assert!(!emulator_tested("36.1.9"));
        assert!(!emulator_tested("37.3.9"));
        assert_eq!(tested_emulators_shown(), "37.1.x and 37.2.x");
    }

    #[test]
    fn finds_the_sdk_in_order() {
        let env = |vars: &'static [(&'static str, &'static str)]| move |k: &str| vars.iter().find(|(n, _)| *n == k).map(|(_, v)| OsString::from(v));
        let s = find_in(&env(&[("ANDROID_HOME", "/a"), ("ANDROID_SDK_ROOT", "/b"), ("HOME", "/h"), ("LOCALAPPDATA", "/l")])).unwrap();
        assert_eq!((s.root, s.found_by), (PathBuf::from("/a"), "ANDROID_HOME"));
        let s = find_in(&env(&[("ANDROID_HOME", ""), ("ANDROID_SDK_ROOT", "/b"), ("HOME", "/h")])).unwrap();
        assert_eq!((s.root, s.found_by), (PathBuf::from("/b"), "ANDROID_SDK_ROOT"));
        let s = find_in(&env(&[("HOME", "/h"), ("LOCALAPPDATA", "/l")])).unwrap();
        assert_eq!(s.found_by, "the default location");
        if cfg!(target_os = "macos") {
            assert_eq!(s.root, PathBuf::from("/h/Library/Android/sdk"));
        }
        assert!(find_in(&env(&[])).is_none());
    }

    #[test]
    fn specs() {
        let spec = |level: &str, tag: Option<&str>, abi: Option<&str>| Spec { level: level.into(), tag: tag.map(Into::into), abi: abi.map(Into::into) };
        assert_eq!(parse_spec("android-36.1").unwrap(), spec("android-36.1", None, None));
        assert_eq!(parse_spec("36.1").unwrap(), spec("android-36.1", None, None));
        assert_eq!(parse_spec("android-36.1/google_apis_playstore").unwrap(), spec("android-36.1", Some("google_apis_playstore"), None));
        assert_eq!(parse_spec("android-36.1/google_apis/x86_64").unwrap(), spec("android-36.1", Some("google_apis"), Some("x86_64")));
        assert_eq!(
            parse_spec("system-images;android-36.1;google_apis_playstore;arm64-v8a").unwrap(),
            spec("android-36.1", Some("google_apis_playstore"), Some("arm64-v8a"))
        );
        assert!(parse_spec("").is_err());
        assert!(parse_spec("android-36.1//x").is_err());
        assert!(parse_spec("a/b/c/d").is_err());
        assert!(parse_spec("system-images;android-36.1;;arm64-v8a").is_err());
    }

    #[test]
    fn picks_an_image() {
        let host = host_abi();
        let other = if host == "x86_64" { "arm64-v8a" } else { "x86_64" };
        let d = fake_sdk(&[
            ("android-36.1", "google_apis_playstore", host, Some(vec![])),
            ("android-36.1", "google_apis", host, Some(vec![])),
            ("android-35", "google_apis", host, Some(vec![])),
            ("android-35", "google_apis", other, Some(vec![])),
            ("android-34", "aosp_atd", other, Some(vec![])),
        ]);
        let images = list_images(&d.0);
        let names: Vec<String> = images.iter().map(|i| format!("{} {}", i.name(), i.abi)).collect();
        assert_eq!(names[0], format!("android-36.1/google_apis {host}"), "newest first: {names:?}");
        assert_eq!(names.len(), 5);
        // Classified by name alone here: the tested one boots, google_apis doesn't.
        let by_name = |i: &Image| if i.is_tested() { Support::Tested } else if i.tag == "google_apis" && i.level == "android-36.1" { Support::Unsupported("ext4 partitions aren't supported yet".into()) } else { Support::Untested };
        let pick_ = |s: &str| pick(s, &images, by_name).map(|(i, s)| (i.package(), s));
        assert_eq!(pick_("android-36.1"), Ok((tested_package(), Support::Tested)));
        assert_eq!(pick_("36.1/google_apis_playstore"), Ok((tested_package(), Support::Tested)));
        assert_eq!(pick_(&tested_package()), Ok((tested_package(), Support::Tested)));
        assert_eq!(pick_("android-35"), Ok((format!("system-images;android-35;google_apis;{host}"), Support::Untested)));
        assert!(pick_("android-36.1/google_apis").unwrap_err().contains("ext4 partitions aren't supported yet"));
        assert!(pick_(&format!("android-35/google_apis/{other}")).unwrap_err().contains(&format!("{other} images can't run here: {} runs {host} images", host_name())));
        assert!(pick_("android-34").unwrap_err().contains("unsupported"));
        assert!(pick_("android-33").unwrap_err().contains("no installed system image matches"));
    }

    #[test]
    fn several_that_boot_are_ambiguous() {
        let host = host_abi();
        let d = fake_sdk(&[("android-35", "google_apis", host, Some(vec![])), ("android-35", "google_apis_playstore", host, Some(vec![]))]);
        let err = pick("android-35", &list_images(&d.0), |_| Support::Untested).unwrap_err();
        assert!(err.contains("matches several images: android-35/google_apis (untested), android-35/google_apis_playstore (untested)"), "{err}");
    }

    #[test]
    fn classifies_fake_trees() {
        let host = host_abi();
        let other = if host == "x86_64" { "arm64-v8a" } else { "x86_64" };
        let d = fake_sdk(&[
            (TESTED_LEVEL, TESTED_TAG, host, Some(fake_system_img("erofs"))),
            ("android-36", "google_apis", host, Some(fake_system_img("ext4"))),
            ("android-36", "google_apis_ps16k", host, Some(fake_system_img("erofs"))),
            ("android-35", "google_apis_playstore", host, Some(fake_system_img("erofs"))),
            ("android-35", "google_apis_playstore", other, Some(fake_system_img("erofs"))),
            ("android-34", "default", host, Some(fake_system_img("none"))),
            ("android-28", "google_apis", host, Some(vec![0; 8192])),
            ("android-29", "google_apis", host, Some(vec![])),
            ("android-30", "google_apis", host, None),
        ]);
        // A download that never finished: no source.properties either.
        std::fs::create_dir_all(d.0.join("system-images/android-37/google_apis/arm64-v8a/.installer")).unwrap();
        let got: HashMap<String, String> = list_images(&d.0).iter().map(|i| (format!("{} {}", i.name(), i.abi), classify(i).to_string())).collect();
        let want = |name: &str, abi: &str, s: &str| assert_eq!(got.get(&format!("{name} {abi}")).map(String::as_str), Some(s), "{name} {abi}: {got:?}");
        want("android-36.1/google_apis_playstore", host, "tested");
        want("android-36/google_apis", host, "unsupported: ext4 partitions aren't supported yet");
        want("android-36/google_apis_ps16k", host, "unsupported: 16 KB page size isn't supported yet");
        want("android-35/google_apis_playstore", host, "untested");
        want("android-35/google_apis_playstore", other, &format!("unsupported: {other} image; {} runs {host} images", host_name()));
        want("android-34/default", host, "unsupported: its system partition isn't EROFS");
        want("android-28/google_apis", host, "unsupported: needs Android 10 or newer");
        want("android-29/google_apis", host, "unsupported: its system.img is cut short");
        want("android-30/google_apis", host, "unsupported: not fully installed");
        want("android-37/google_apis", "arm64-v8a", "unsupported: not fully installed");
        assert_eq!(got.len(), 10);
        // By path, as --system gives it: the properties beside it count.
        let tested = d.0.join("system-images").join(TESTED_LEVEL).join(TESTED_TAG).join(host).join("system.img");
        let (img, s) = classify_file(&tested);
        assert_eq!((img.map(|i| i.package()), s), (Some(tested_package()), Support::Tested));
        let bare = d.0.join("bare.img");
        put(&bare, &fake_system_img("erofs"));
        assert_eq!(classify_file(&bare).1, Support::Untested);
    }

    /// Google's 16 KB images list two tags in SystemImage.TagId, and their folder
    /// another: the folder names are the package, and either says 16 KB.
    #[test]
    fn several_tags() {
        let host = host_abi();
        let d = fake_sdk(&[(TESTED_LEVEL, TESTED_TAG, host, Some(fake_system_img("erofs")))]);
        // As in Google's arm64-v8a-playstore-ps16k-36.1_r04.zip.
        let ps16k = format!(
            "Pkg.Desc=System Image {host} with Google Play.\nPkg.Revision=4\nAndroidVersion.ApiLevel=36.1\nAndroidVersion.ExtensionLevel=20\n\
             AndroidVersion.IsBaseSdk=true\nSystemImage.Abi={host}\nSystemImage.TagId=google_apis_playstore,page_size_16kb\n\
             SystemImage.TagDisplay=Google Play 16 KB\nSystemImage.GpuSupport=true\n"
        );
        let dir = d.0.join("system-images").join(TESTED_LEVEL).join("google_apis_playstore_ps16k").join(host);
        put(&dir.join("source.properties"), ps16k.as_bytes());
        put(&dir.join("system.img"), &fake_system_img("erofs"));
        // Only TagId says 16 KB here.
        let other = d.0.join("system-images/android-35/google_apis_playstore").join(host);
        put(&other.join("source.properties"), ps16k.replace("36.1", "35").as_bytes());
        put(&other.join("system.img"), &fake_system_img("erofs"));
        // A later extension's folder isn't the tested image, whatever its properties say.
        let ext = d.0.join("system-images").join(format!("{TESTED_LEVEL}-ext21")).join(TESTED_TAG).join(host);
        put(&ext.join("source.properties"), props(TESTED_LEVEL, TESTED_TAG, host).as_bytes());
        put(&ext.join("system.img"), &fake_system_img("erofs"));
        // An empty TagId: the folder still names it.
        let empty = d.0.join("system-images/android-34/default").join(host);
        put(&empty.join("source.properties"), b"AndroidVersion.ApiLevel=34\nSystemImage.TagId=\n");
        put(&empty.join("system.img"), &fake_system_img("erofs"));

        let images = list_images(&d.0);
        let img = images.iter().find(|i| i.dir == dir).unwrap();
        assert_eq!(img.name(), format!("{TESTED_LEVEL}/google_apis_playstore_ps16k"));
        assert_eq!(img.package(), format!("system-images;{TESTED_LEVEL};google_apis_playstore_ps16k;{host}"));
        assert_eq!(img.tags, ["google_apis_playstore", "page_size_16kb"]);
        assert!(!img.is_tested());
        let sixteen = Support::Unsupported("16 KB page size isn't supported yet".into());
        assert_eq!(classify(img), sixteen);
        let other = images.iter().find(|i| i.dir == other).unwrap();
        assert_eq!(other.name(), "android-35/google_apis_playstore");
        assert_eq!(classify(other), sixteen);
        let ext = images.iter().find(|i| i.dir == ext).unwrap();
        assert!(!ext.is_tested());
        assert_eq!(classify(ext), Support::Untested);
        let empty = images.iter().find(|i| i.dir == empty).unwrap();
        assert_eq!((empty.name(), empty.tags.len()), ("android-34/default".into(), 0));

        let pick_ = |s: &str| pick(s, &images, classify).map(|(i, s)| (i.package(), s));
        assert_eq!(pick_(TESTED_LEVEL), Ok((tested_package(), Support::Tested)));
        assert!(pick_(&format!("{TESTED_LEVEL}/google_apis_playstore_ps16k")).unwrap_err().contains("16 KB page size"));
        assert!(pick_(&format!("system-images;{TESTED_LEVEL};google_apis_playstore_ps16k;{host}")).unwrap_err().contains("16 KB page size"));
        assert!(pick_("android-35").unwrap_err().contains("16 KB page size"));

        // A copy outside an SDK: its properties are all there is.
        let copy = d.0.join("copies/ps16k");
        put(&copy.join("source.properties"), ps16k.as_bytes());
        put(&copy.join("system.img"), &fake_system_img("erofs"));
        let (img, s) = classify_file(&copy.join("system.img"));
        let img = img.unwrap();
        assert_eq!((img.name(), img.in_sdk, s), (format!("{TESTED_LEVEL}/google_apis_playstore"), false, sixteen));
        let tested = d.0.join("copies/tested");
        put(&tested.join("source.properties"), props(TESTED_LEVEL, TESTED_TAG, host).as_bytes());
        put(&tested.join("system.img"), &fake_system_img("erofs"));
        assert_eq!(classify_file(&tested.join("system.img")).1, Support::Tested);
    }

    /// The real tested image, when installed: the probe reads it as bootable.
    #[test]
    fn classifies_the_installed_tested_image() {
        let Some(sdk) = find().filter(|s| s.exists()) else { return eprintln!("skip: no Android SDK") };
        let Some(img) = sdk.images().into_iter().find(|i| i.is_tested() && i.system_img().is_file()) else {
            return eprintln!("skip: the tested image isn't installed");
        };
        let started = std::time::Instant::now();
        assert_eq!(classify(&img), Support::Tested);
        assert!(started.elapsed() < std::time::Duration::from_secs(1), "probe took {:?}", started.elapsed());
        assert_eq!(img.package(), tested_package());
        assert_eq!(img.release().as_deref(), Some("16"));
    }

    #[test]
    fn quoting() {
        assert_eq!(shell_quote("/usr/local/bin/zeroemu"), "/usr/local/bin/zeroemu");
        if !cfg!(windows) {
            assert_eq!(shell_quote("/Users/a b/zeroemu"), "'/Users/a b/zeroemu'");
            assert_eq!(shell_quote("it's"), r"'it'\''s'");
        }
    }
}

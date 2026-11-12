//! `zeroemu images` and `zeroemu doctor`: what's installed, and what a boot needs.
//! Neither changes anything on disk.

use crate::Problem;
use crate::sdk::{self, Image, Support};

/// Each image with whether it can boot.
pub fn classify_all(images: &[Image]) -> Vec<(&Image, Support)> {
    images.iter().map(|i| (i, sdk::classify(i))).collect()
}

/// The images with what `--image` calls them, their ABI and Android version, and
/// whether each can boot, a line each.
pub fn image_table(images: &[(&Image, Support)], indent: &str) -> String {
    let rows: Vec<[String; 4]> = images.iter().map(|(i, s)| [i.name(), i.abi.clone(), i.release().map(|r| format!("Android {r}")).unwrap_or_default(), s.to_string()]).collect();
    let width = |c: usize| rows.iter().map(|r| r[c].len()).max().unwrap_or(0);
    let (w0, w1, w2) = (width(0), width(1), width(2));
    let mut out = String::new();
    for r in &rows {
        out += &format!("{indent}{:w0$}  {:w1$}  {:w2$}  {}\n", r[0], r[1], r[2], r[3]);
    }
    out
}

pub fn images() -> i32 {
    let sdk = match sdk::require() {
        Ok(s) => s,
        Err(p) => {
            eprintln!("zeroemu: {p}");
            return 1;
        }
    };
    println!("Android SDK: {} ({})", sdk.root.display(), how_found(&sdk));
    let images = sdk.images();
    if images.is_empty() {
        println!("No system images are installed. Install the one zeroemu is tested with:\n  {}", sdk.sdkmanager(&sdk::tested_package()));
        return 0;
    }
    let images = classify_all(&images);
    println!();
    print!("{}", image_table(&images, ""));
    println!();
    match images.iter().find(|(i, _)| i.is_tested()) {
        Some((_, Support::Tested)) => println!("zeroemu boots the tested image. zeroemu --image <name> boots another."),
        Some((i, _)) => println!("The tested image can't boot, as above. Reinstall it with:\n  {}", sdk.sdkmanager(&i.package())),
        None => println!("The tested image isn't installed. Install it with:\n  {}", sdk.sdkmanager(&sdk::tested_package())),
    }
    if !images.iter().any(|(_, s)| *s == Support::Tested) && images.iter().any(|(_, s)| s.boots()) {
        println!("zeroemu --image <name> boots an untested one.");
    }
    0
}

fn how_found(sdk: &sdk::Sdk) -> String {
    match sdk.found_by {
        "ANDROID_SDK_ROOT" => "from ANDROID_SDK_ROOT, which Google has deprecated for ANDROID_HOME".into(),
        v if v.starts_with("ANDROID") => format!("from {v}"),
        other => other.into(),
    }
}

#[derive(Default)]
struct Report {
    failed: usize,
}

impl Report {
    fn line(&mut self, status: &str, text: &str, fix: &[String]) {
        if status == "FAIL" {
            self.failed += 1;
        }
        println!("{status:<5} {text}");
        for (i, f) in fix.iter().enumerate() {
            println!("      {} {f}", if i == 0 { "fix:" } else { "    " });
        }
    }
    fn ok(&mut self, text: &str) {
        self.line("ok", text, &[]);
    }
    fn warn(&mut self, text: &str, fix: &[String]) {
        self.line("warn", text, fix);
    }
    fn fail(&mut self, what: &str, p: Problem) {
        self.line("FAIL", &format!("{what}: {}", p.what), &p.fix);
    }
}

/// Checks each thing a boot needs, a line each. Exits 0 when a boot should work.
pub fn doctor() -> i32 {
    let mut r = Report::default();
    platform(&mut r);
    match crate::hv::probe() {
        Ok(()) => r.ok("hypervisor: zeroemu can create a VM"),
        Err(p) => r.fail("hypervisor", p),
    }
    match sdk::find() {
        Some(s) if s.exists() => {
            r.ok(&format!("Android SDK: {} ({})", s.root.display(), how_found(&s)));
            emulator(&mut r, &s);
            tested_image(&mut r, &s);
            let adb = s.adb();
            if adb.is_file() {
                r.ok(&format!("adb: {}", adb.display()));
            } else {
                r.warn(
                    &format!("adb: not installed (looked for {}); zeroemu boots without it, but it's how to reach the device", adb.display()),
                    &[s.sdkmanager("platform-tools")],
                );
            }
        }
        other => {
            r.fail("Android SDK", sdk::missing(other.as_ref()));
            if let Some(rend) = sdk::renderer(None) {
                r.line(if rend.path.is_file() { "ok" } else { "FAIL" }, &format!("renderer: {} (from ZEROEMU_GFXSTREAM)", rend.path.display()), &[]);
            }
        }
    }
    saved_devices(&mut r);
    println!();
    match r.failed {
        0 => println!("A boot should work: run zeroemu."),
        1 => println!("1 problem to fix before zeroemu can boot."),
        n => println!("{n} problems to fix before zeroemu can boot."),
    }
    (r.failed > 0) as i32
}

fn platform(r: &mut Report) {
    if cfg!(all(target_os = "macos", target_arch = "aarch64")) {
        let version = macos_version().map(|v| format!(" {v}")).unwrap_or_default();
        r.ok(&format!("platform: macOS{version} on Apple Silicon"));
    } else if cfg!(all(windows, target_arch = "x86_64")) {
        r.warn("platform: Windows x86_64. Windows support is untested: it has no window, and has never booted", &[]);
    } else {
        r.fail(
            "platform",
            Problem::new(
                format!("{} on {} isn't supported", std::env::consts::OS, std::env::consts::ARCH),
                ["run zeroemu on a Mac with Apple Silicon"],
            ),
        );
    }
}

#[cfg(target_os = "macos")]
fn macos_version() -> Option<String> {
    let mut buf = [0u8; 64];
    let mut len = buf.len();
    let r = unsafe { libc::sysctlbyname(c"kern.osproductversion".as_ptr(), buf.as_mut_ptr().cast(), &mut len, std::ptr::null_mut(), 0) };
    (r == 0).then(|| String::from_utf8_lossy(&buf[..len.min(buf.len())]).trim_end_matches('\0').to_string())
}

#[cfg(not(target_os = "macos"))]
fn macos_version() -> Option<String> {
    None
}

/// The renderer, and whether the Android Emulator it comes from is the tested one.
fn emulator(r: &mut Report, s: &sdk::Sdk) {
    let Some(rend) = sdk::renderer(Some(s)) else { return };
    if rend.from_env {
        if rend.path.is_file() {
            r.ok(&format!("renderer: {} (from ZEROEMU_GFXSTREAM)", rend.path.display()));
        } else {
            r.fail(
                "renderer",
                Problem::new(
                    format!("ZEROEMU_GFXSTREAM is {}, which doesn't exist", rend.path.display()),
                    ["unset ZEROEMU_GFXSTREAM to use the Android Emulator's renderer from the SDK"],
                ),
            );
        }
        return;
    }
    if !rend.path.is_file() {
        return r.fail("renderer", sdk::no_emulator(s));
    }
    r.ok(&format!("renderer: {}", rend.path.display()));
    match s.emulator_version() {
        Some(v) if sdk::emulator_tested(&v) => r.ok(&format!("Android Emulator {v}, tested")),
        Some(v) => r.warn(&format!("Android Emulator {v}: zeroemu is tested with {}, and other releases' renderers may not work", sdk::tested_emulators_shown()), &[]),
        None => r.warn(&format!("Android Emulator: can't tell which release (no Pkg.Revision in {})", s.root.join("emulator").join("source.properties").display()), &[]),
    }
}

fn tested_image(r: &mut Report, s: &sdk::Sdk) {
    let images = s.images();
    let others = match images.len() {
        0 => "no images are installed".to_string(),
        1 => "1 image installed".to_string(),
        n => format!("{n} images installed (zeroemu images lists them)"),
    };
    let Some(img) = images.iter().find(|i| i.is_tested()) else {
        return r.fail(
            "system image",
            Problem::new(
                format!("the tested one, {}/{} ({}), isn't installed; {others}", sdk::TESTED_LEVEL, sdk::TESTED_TAG, sdk::host_abi()),
                [s.sdkmanager(&sdk::tested_package()), "or boot an untested image with zeroemu --image <name>".into()],
            ),
        );
    };
    match sdk::classify(img) {
        Support::Unsupported(why) => r.fail(
            "system image",
            Problem::new(format!("{} ({}) can't boot: {why}", img.name(), img.abi), [format!("{} reinstalls it", s.sdkmanager(&img.package()))]),
        ),
        _ => {
            let revision = img.revision.as_ref().map(|v| format!(", revision {v}")).unwrap_or_default();
            r.ok(&format!("system image: {} ({}{revision}), tested; {others}", img.name(), img.abi))
        }
    }
}

/// Where devices are saved. Only looks: the old folder moves at the next boot.
fn saved_devices(r: &mut Report) {
    let Some((dir, legacy)) = crate::data_dirs() else {
        return r.warn("saved devices: can't tell where they go (HOME isn't set)", &["give a boot --data <file>, or --ephemeral".into()]);
    };
    let count = |d: &std::path::Path| {
        std::fs::read_dir(d).into_iter().flatten().flatten().filter(|e| e.file_name().to_string_lossy().starts_with("data-") && e.file_name().to_string_lossy().ends_with(".img")).count()
    };
    let saved = match count(&dir) {
        0 => "none yet".to_string(),
        1 => "1 device".to_string(),
        n => format!("{n} devices"),
    };
    let moving = if !dir.exists() && legacy.is_dir() { format!("; the next boot moves those in {} there", legacy.display()) } else { String::new() };
    r.ok(&format!("saved devices: {} ({saved}){moving}", dir.display()));
}

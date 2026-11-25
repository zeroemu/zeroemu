//! zeroemu.app (scripts/build-app.sh): started from Finder, the Dock, Launchpad or
//! Spotlight, zeroemu has no terminal. What it would print goes to a log file, and what
//! keeps a device from starting is said in an alert. Run from a terminal, even from
//! inside the bundle, it behaves as it always does.

use std::path::{Path, PathBuf};

/// Whether LaunchServices started this process from zeroemu.app: the binary is the
/// bundle's, its parent is launchd, which a shell or a script running the bundle's
/// binary never is, and nothing reads what it prints.
pub fn opened_as_app() -> bool {
    #[cfg(target_os = "macos")]
    {
        static APP: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
        *APP.get_or_init(|| {
            let in_bundle = std::env::current_exe().is_ok_and(|p| p.to_string_lossy().contains(".app/Contents/MacOS/"));
            in_bundle && unsafe { libc::getppid() == 1 && libc::isatty(2) == 0 }
        })
    }
    #[cfg(not(target_os = "macos"))]
    false
}

/// zeroemu's arguments, without the one LaunchServices may put first for an app it
/// opens (`-psn_0_12345`, the old Carbon process serial number), which means nothing
/// to zeroemu.
pub fn args() -> impl Iterator<Item = String> {
    let mut args = std::env::args().skip(1).peekable();
    if opened_as_app() {
        args.next_if(|a| launch_services_arg(a));
    }
    args
}

fn launch_services_arg(arg: &str) -> bool {
    arg.starts_with("-psn_")
}

/// Where the app's output goes, where Console looks for apps' logs:
/// ~/Library/Logs/zeroemu/zeroemu.log, with the run before's beside it.
#[cfg(unix)]
fn log_path() -> Option<PathBuf> {
    let home = std::env::var_os("HOME")?;
    Some(PathBuf::from(home).join("Library/Logs/zeroemu/zeroemu.log"))
}

/// Sends stdout and stderr to the log, keeping the last run's as
/// zeroemu.previous.log. Returns the log's path, or None if it can't be written, when
/// what zeroemu prints goes nowhere, as it did.
pub fn start_log() -> Option<PathBuf> {
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd;
        let path = log_path()?;
        std::fs::create_dir_all(path.parent()?).ok()?;
        let _ = std::fs::rename(&path, path.with_file_name("zeroemu.previous.log"));
        let file = std::fs::OpenOptions::new().create(true).append(true).open(&path).ok()?;
        unsafe {
            libc::dup2(file.as_raw_fd(), 1);
            libc::dup2(file.as_raw_fd(), 2);
        }
        eprintln!("zeroemu {}, opened as an app", env!("CARGO_PKG_VERSION"));
        Some(path)
    }
    #[cfg(not(unix))]
    None
}

/// The bundle this zeroemu runs from: <x>.app, three folders up from the binary.
pub fn bundle() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let bundle = exe.parent()?.parent()?.parent()?;
    (bundle.extension()? == "app").then(|| bundle.to_path_buf())
}

// ---- Which zeroemu shows the list of devices ----
//
// One zeroemu at a time shows the list, and holds zeroemu-list.lock beside its
// application data while it does, with its process id in it. The lock says whether
// the list File > Show Device List opened is still there or has started a device.

fn list_lock_path() -> Option<PathBuf> {
    Some(crate::data_dirs()?.0.with_file_name("zeroemu-list.lock"))
}

fn open_lock(path: &Path) -> std::io::Result<std::fs::File> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    std::fs::OpenOptions::new().read(true).write(true).create(true).truncate(false).open(path)
}

/// The process id the zeroemu holding the lock wrote, if it has yet.
fn holder(path: &Path) -> Option<u32> {
    std::fs::read_to_string(path).ok()?.trim().parse().ok()
}

/// The list's lock, which the zeroemu showing the list holds until it drops it.
pub struct ListLock(std::fs::File);

impl Drop for ListLock {
    fn drop(&mut self) {
        let _ = self.0.set_len(0);
    }
}

/// Takes the list's lock for this zeroemu, which is to show the list: Ok(None) when
/// there's no telling (no HOME, a lock file that can't be made), when it shows the
/// list all the same. Err with the process id of the zeroemu that shows it already,
/// if it said. Tries for half a second: one looking whether a list shows
/// (`list_shown_by`) holds the lock for a moment.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub fn hold_list() -> Result<Option<ListLock>, Option<u32>> {
    match list_lock_path() {
        Some(path) => hold_at(&path, 10),
        None => Ok(None),
    }
}

fn hold_at(path: &Path, tries: u32) -> Result<Option<ListLock>, Option<u32>> {
    use std::io::Write;
    let Ok(mut file) = open_lock(path) else { return Ok(None) };
    for i in 1..=tries {
        match file.try_lock() {
            Ok(()) => {
                let _ = file.set_len(0).and_then(|()| write!(file, "{}", std::process::id()));
                return Ok(Some(ListLock(file)));
            }
            Err(std::fs::TryLockError::WouldBlock) if i < tries => std::thread::sleep(std::time::Duration::from_millis(50)),
            Err(std::fs::TryLockError::WouldBlock) => {}
            Err(std::fs::TryLockError::Error(_)) => return Ok(None),
        }
    }
    Err(holder(path))
}

/// Whether another zeroemu shows the list: Some, with its process id if it said.
/// Shared, so that two zeroemus looking at once (two devices closed together) don't
/// each take the other for a list.
pub fn list_shown_by() -> Option<Option<u32>> {
    shown_at(&list_lock_path()?)
}

fn shown_at(path: &Path) -> Option<Option<u32>> {
    let file = open_lock(path).ok()?;
    match file.try_lock_shared() {
        Err(std::fs::TryLockError::WouldBlock) => Some(holder(path)),
        Ok(()) | Err(std::fs::TryLockError::Error(_)) => None,
    }
}

/// The device of a zeroemu the list started stopped, not by Quit: the list again,
/// unless a zeroemu shows it already (one File > Show Device List opened, still
/// open), as this one's VM can't be made again. Two lists opened at once (two devices
/// closed together) end as one: the second to start finds the first's lock.
pub fn back_to_list() {
    match list_shown_by() {
        Some(Some(pid)) => crate::gpu::activate_device_list(pid),
        Some(None) => {}
        None => {
            if let Err(e) = open_list() {
                eprintln!("zeroemu: the list of devices didn't open: {e}");
            }
        }
    }
}

/// Opens the app's list of devices in a zeroemu of its own, as `open -n` does: one
/// process runs one device, and this one may be running one, or be about to exit.
/// What this one was given of HOME, the SDK's variables and ZEROEMU_*'s goes with it,
/// as LaunchServices would give it launchd's: a test's scratch HOME and its FIFOs.
pub fn open_list() -> Result<(), String> {
    let bundle = bundle().ok_or("zeroemu isn't running from zeroemu.app")?;
    let mut open = std::process::Command::new("/usr/bin/open");
    open.arg("-n");
    for (k, v) in std::env::vars_os() {
        let name = k.to_string_lossy();
        if name.starts_with("ZEROEMU_") || ["HOME", "ANDROID_HOME", "ANDROID_SDK_ROOT"].contains(&&*name) {
            let mut pair = k.clone();
            pair.push("=");
            pair.push(&v);
            open.arg("--env").arg(pair);
        }
    }
    match open.arg(&bundle).status() {
        Ok(s) if s.success() => Ok(()),
        Ok(s) => Err(format!("open -n {} exited with {s}", bundle.display())),
        Err(e) => Err(format!("/usr/bin/open: {e}")),
    }
}

/// Why a boot of zeroemu.app ended that nobody asked to end, for an alert: None for a
/// quit, a power off, or a restart asked for in Android (its power menu's Restart is
/// "userrequested") or with `adb reboot` (no target), which zeroemu takes as a power
/// off. `code` is the boot's exit code, `reboot` what Android asked to restart into.
pub fn stopped_by_itself(code: i32, reboot: Option<&str>) -> Option<String> {
    match reboot {
        _ if code == 0 => None,
        Some("" | "userrequested") => None,
        Some(target) => Some(format!(
            "Android asked to restart into \"{target}\", as it does when a core part of it keeps crashing, \
             and zeroemu stops then. The log has init's account of it."
        )),
        None if code > 128 => Some(format!("Android's init was killed by signal {}.", code - 128)),
        None => Some(format!("Android's init exited with status {code}.")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_launch_services_arguments_are_dropped() {
        assert!(launch_services_arg("-psn_0_1234567"));
        assert!(!launch_services_arg("--ephemeral"));
        assert!(!launch_services_arg("-psn"));
    }

    #[test]
    fn only_a_stop_nobody_asked_for_is_explained() {
        assert_eq!(stopped_by_itself(0, None), None);
        assert_eq!(stopped_by_itself(1, Some("userrequested")), None);
        assert_eq!(stopped_by_itself(1, Some("")), None);
        assert!(stopped_by_itself(1, Some("bootloader")).is_some_and(|w| w.contains("\"bootloader\"")));
        assert!(stopped_by_itself(137, None).is_some_and(|w| w.contains("signal 9")));
        assert!(stopped_by_itself(3, None).is_some_and(|w| w.contains("status 3")));
    }

    fn lock_path(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("zeroemu-list-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir.join("list.lock")
    }

    #[test]
    fn the_list_shows_while_its_lock_is_held_and_not_after() {
        let path = lock_path("held");
        assert_eq!(shown_at(&path), None);
        let held = hold_at(&path, 1).unwrap().expect("a lock");
        // A second list finds the first, and which zeroemu shows it.
        assert_eq!(shown_at(&path), Some(Some(std::process::id())));
        assert!(matches!(hold_at(&path, 2), Err(Some(pid)) if pid == std::process::id()));
        // Closed, or started a device: no list shows, and the next may.
        drop(held);
        assert_eq!(holder(&path), None);
        assert_eq!(shown_at(&path), None);
        assert!(hold_at(&path, 1).unwrap().is_some());
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn zeroemus_looking_at_once_dont_take_each_other_for_a_list() {
        let path = lock_path("look");
        let looking = open_lock(&path).unwrap();
        looking.try_lock_shared().unwrap();
        assert_eq!(shown_at(&path), None);
        // A list starting while one looks waits the look out.
        let release = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(80));
            drop(looking);
        });
        assert!(hold_at(&path, 10).unwrap().is_some());
        release.join().unwrap();
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }
}

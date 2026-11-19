//! zeroemu.app (scripts/build-app.sh): started from Finder, the Dock, Launchpad or
//! Spotlight, zeroemu has no terminal. What it would print goes to a log file, and what
//! keeps a device from starting is said in an alert. Run from a terminal, even from
//! inside the bundle, it behaves as it always does.

use std::path::PathBuf;

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
}

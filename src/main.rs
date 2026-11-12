//! zeroemu: runs Android's (Linux) userspace binaries directly on the host CPU
//! inside a kernel-less hardware VM, implementing the Linux syscall ABI in Rust.

mod android;
mod arch;
mod doctor;
mod elf;
mod errno;
#[allow(dead_code)] // implemented by the gfxstream host backend, called by the DRM driver
mod gpu;
mod hv;
mod image;
mod kernel;
mod mm;
mod pagecache;
mod paging;
mod phys;
mod sdk;
mod tmpfs;
mod vfs;

use kernel::Kernel;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

/// What an error with the command line prints, on stderr.
const USAGE: &str = "usage: zeroemu [options]                  boot Android in a window
       zeroemu images | doctor
       zeroemu [--system <img>] <program> [args...]
zeroemu --help lists the options.";

/// `--help`, on stdout.
fn help() -> String {
    let data = if cfg!(windows) {
        r"%LOCALAPPDATA%\zeroemu"
    } else if cfg!(target_os = "macos") {
        "~/Library/Application Support/zeroemu"
    } else {
        "~/.local/share/zeroemu"
    };
    let stop = if cfg!(windows) {
        "Stop it with Ctrl-C; on Windows, /data isn't saved then."
    } else {
        "Stop it by closing the window or pressing Ctrl-C;\n/data is saved then."
    };
    format!(
        "zeroemu {version}: runs Android's userspace from an Android SDK system image on the
host CPU, with no guest kernel.

usage:
  zeroemu [options]       boot Android in a window
  zeroemu images          list the system images installed in the Android SDK,
                          and whether each can boot: tested, untested, or
                          unsupported (and why)
  zeroemu doctor          check what a boot needs, and say how to fix what's
                          missing
  zeroemu --help | -h     show this help
  zeroemu --version | -V  show the version

Boot options:
  --image <name>          an installed image, by level, level/tag or package:
                            {level}
                            {level}/{tag}
                            {package}
                          The ABI is always this computer's.
  --system <path>         a system.img file, or the folder holding it
  --data <file>           keep /data in this file (by default, a file per image
                          in {data})
  --ephemeral             keep nothing: /data starts empty and is thrown away
  --wipe-data             start /data over
  --ram <MB>              how much memory Android is told it has (default 4096)
  --no-net                no network
  --adb-port <port>       the port host adb connects to (by default the first
                          free pair from 5554/5555, so adb lists emulator-5554)
  --no-adb                no adb
  --headless              no window
  --boot                  boot; the same as giving no program

Without --image or --system, zeroemu boots {level}/{tag},
the image it is tested with. {stop}

Development:
  --push <host>:<guest>   copy a host file into the booted device
  --run <cmd>             run a shell command once SurfaceFlinger is up
  zeroemu --system <img> --ls <path> | --cat <path>
                          list a folder or print a file of the image
  zeroemu [--system <img>] [--strace] [--display] [--] <program> [args...]
                          run one program: from the image, or a static Linux
                          binary. -- ends the options, for a program whose
                          name starts with -
  zeroemu --gpu-selftest  check the renderer and the window

Environment:
  ANDROID_HOME            the Android SDK; else ANDROID_SDK_ROOT, else
                          {sdk}
  ZEROEMU_LOG=<V|D|I|W|E|F|S>
                          the lowest priority of Android's log that prints:
                          W for a boot, I for a program
  ZEROEMU_GFXSTREAM=<path>
                          the renderer library, in place of the Android
                          Emulator's
  ZEROEMU_GPU_LOG=<S|E|W|I|D>
                          the lowest priority of the renderer's log that
                          prints: E (its errors) by default
  ZEROEMU_BACKGROUND=1    open the window behind others, without taking focus
",
        version = env!("CARGO_PKG_VERSION"),
        level = sdk::TESTED_LEVEL,
        tag = sdk::TESTED_TAG,
        package = sdk::tested_package(),
        sdk = sdk::default_root_shown(),
    )
}

/// Something in the way of a boot, and what fixes it.
#[derive(Debug)]
pub struct Problem {
    pub what: String,
    /// A line each: the first is what to do, the rest say more.
    pub fix: Vec<String>,
}

impl Problem {
    pub fn new(what: impl Into<String>, fix: impl IntoIterator<Item = impl Into<String>>) -> Problem {
        Problem { what: what.into(), fix: fix.into_iter().map(Into::into).collect() }
    }
}

impl std::fmt::Display for Problem {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str(&self.what)?;
        for (i, line) in self.fix.iter().enumerate() {
            write!(f, "\n  {} {line}", if i == 0 { "fix:" } else { "    " })?;
        }
        Ok(())
    }
}

impl From<Problem> for String {
    fn from(p: Problem) -> String {
        p.to_string()
    }
}

/// Running one program rather than a boot: when zeroemu itself fails, it exits 127,
/// as a shell does for a program it can't run.
static PROGRAM: AtomicBool = AtomicBool::new(false);

fn main() -> ExitCode {
    // A panic is a zeroemu bug. Unhandled, it kills only the host thread that
    // was running one guest thread, which then freezes without a trace; stop
    // everything loudly instead.
    kernel::reserve_dump_signal();
    #[cfg(unix)]
    raise_fd_limit();
    let default = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        default(info);
        kernel::trace::flush_if_free();
        eprintln!("[zeroemu] internal error in {}; stopping", std::thread::current().name().unwrap_or("?"));
        std::process::exit(101);
    }));
    let result = run();
    kernel::trace::flush();
    match result {
        Ok(code) => ExitCode::from(code as u8),
        Err(e) => {
            eprintln!("zeroemu: {e}");
            ExitCode::from(if PROGRAM.load(Ordering::Relaxed) { 127 } else { 1 })
        }
    }
}

/// The system image a boot or program uses.
struct Chosen {
    path: PathBuf,
    /// Its SDK package, when it is one.
    image: Option<sdk::Image>,
    support: sdk::Support,
}

fn run() -> Result<i32, String> {
    let mut args = std::env::args().skip(1).peekable();
    if let Some(cmd) = args.next_if(|a| a == "images" || a == "doctor") {
        if let Some(extra) = args.next() {
            return Err(format!("{cmd} takes no arguments, got {extra}\n{USAGE}"));
        }
        return Ok(if cmd == "images" { doctor::images() } else { doctor::doctor() });
    }
    let mut root = PathBuf::from("/");
    let mut system: Option<PathBuf> = None;
    let mut image: Option<String> = None;
    let mut inspect: Option<(String, String)> = None;
    let mut strace = std::env::var_os("ZEROEMU_STRACE").is_some();
    let mut boot = false;
    let mut push: Vec<(String, Vec<u8>)> = Vec::new();
    let mut run: Option<String> = None;
    let mut display = false;
    let mut headless = false;
    let mut gpu_selftest = false;
    let mut data: Option<PathBuf> = None;
    let mut ephemeral = false;
    let mut wipe_data = false;
    let mut adb_port: Option<u16> = None;
    let mut no_adb = false;
    let mut no_net = false;
    let wants = |flag: &str| format!("{flag} wants a value\n{USAGE}");
    while let Some(flag) = args.peek().filter(|a| a.starts_with('-')).cloned() {
        args.next();
        let mut value = || args.next().ok_or_else(|| wants(&flag));
        match flag.as_str() {
            // The end of the options: what follows is the program and its arguments,
            // or init's, even if they start with -.
            "--" => break,
            "--help" | "-h" => {
                print!("{}", help());
                return Ok(0);
            }
            "--version" | "-V" => {
                println!("zeroemu {}", env!("CARGO_PKG_VERSION"));
                return Ok(0);
            }
            "--root" => root = value()?.into(),
            "--system" => system = Some(value()?.into()),
            "--image" => image = Some(value()?),
            "--ls" | "--cat" => inspect = Some((flag.clone(), value()?)),
            "--strace" => strace = true,
            // Android's init as pid 1. First-stage init's work (mounting
            // partitions, loading SELinux policy) is done by zeroemu itself,
            // so init starts at its second stage. A window comes with it
            // unless --headless is also given. The same as giving no program,
            // but what follows goes to init.
            "--boot" => boot = true,
            // Development: copy a host file into the booted device (a
            // writable path such as /data/local/tmp/x), and run a shell command
            // once SurfaceFlinger is up, its output on the terminal.
            "--push" => {
                let spec = value()?;
                let (host, guest) = spec.split_once(':').ok_or(format!("--push wants <host file>:<guest path>, got {spec}"))?;
                push.push((guest.to_string(), std::fs::read(host).map_err(|e| format!("{host}: {e}"))?));
            }
            "--run" => run = Some(value()?),
            // Where a booted device keeps /data between boots (by default, a file for
            // this image in the user's application data); not at all; or starting over.
            "--data" => data = Some(value()?.into()),
            "--ephemeral" => ephemeral = true,
            "--wipe-data" => wipe_data = true,
            // Host adb: normally found on the first port pair free for an emulator.
            "--adb-port" => {
                let v = value()?;
                adb_port = Some(v.parse().map_err(|_| format!("--adb-port wants a port number, got {v}"))?);
            }
            "--no-adb" => no_adb = true,
            "--no-net" => no_net = true,
            // As hw.ramSize says in an AVD: what the guest believes it has.
            "--ram" => {
                let v = value()?;
                let max = phys::PHYS_MAX >> 20;
                let mb = v.parse::<u64>().ok().filter(|mb| (1024..=max).contains(mb)).ok_or(format!("--ram wants megabytes from 1024 to {max}, got {v}"))?;
                phys::set_ram(mb << 20);
            }
            "--display" => display = true,
            "--headless" => headless = true,
            "--gpu-selftest" => gpu_selftest = true,
            _ => return Err(format!("unknown flag {flag}\n{USAGE}")),
        }
    }
    if gpu_selftest {
        return gpu::selftest();
    }
    let mut argv: Vec<String> = args.collect();
    // No program: a boot.
    let boot = boot || (argv.is_empty() && inspect.is_none());
    // Mistakes in the command line exit 1, a program or not.
    if !boot && (!push.is_empty() || run.is_some()) {
        return Err("--push and --run are for a boot, not a program".into());
    }
    if image.is_some() && system.is_some() {
        return Err("--image and --system both name an image; give one".into());
    }
    PROGRAM.store(!boot && inspect.is_none(), Ordering::Relaxed);
    if boot {
        kernel::quiet_logs();
    }
    // The VM first: without one nothing else matters. The guest's threads use this one.
    let hv = match inspect {
        Some(_) => None,
        None => Some(hv::create()?),
    };
    let chosen = choose_image(image.as_deref(), system.as_deref(), boot)?;
    let vfs = match &chosen {
        Some(c) => Some(android::open_system_image(&c.path, !boot).map_err(|e| format!("{}: {e}", c.path.display()))?),
        None => None,
    };
    if let Some((cmd, path)) = inspect {
        return inspect_image(vfs.as_ref().ok_or("--ls and --cat need --system or --image")?, &cmd, &path);
    }
    let hv = hv.expect("made above for all but --ls and --cat");
    if boot {
        if argv.is_empty() {
            argv = vec!["second_stage".into()];
        }
        argv.insert(0, "/system/bin/init".into());
    }
    let argv_copy = argv.clone();
    // --headless wins over both --display and the window a boot has.
    // ZEROEMU_GPU=fake is the in-memory virtio-gpu (guest tests, no window).
    let show = !headless && (display || boot);
    let fake = std::env::var("ZEROEMU_GPU").as_deref() == Ok("fake");
    if show && !fake {
        check_renderer()?;
    }
    let system = chosen.as_ref().map(|c| c.path.clone());
    let data = match &system {
        Some(img) if boot && !ephemeral => data.or_else(|| default_data_image(img)).map(|path| kernel::DataImage { path, wipe: wipe_data }),
        _ => None,
    };
    // Before any thread starts: they all inherit the mask.
    if data.is_some() {
        kernel::reserve_exit_signals();
    }
    let data_path = data.as_ref().map(|d| d.path.clone());
    let extras = boot.then_some(kernel::BootExtras { push, run, data, network: !no_net });
    let adb = if (boot && !no_adb) || adb_port.is_some() { kernel::adb::start(adb_port) } else { None };
    if boot && let Some(c) = &chosen {
        print_status(c, data_path.as_deref(), adb, show);
    }
    let gpu: Option<Arc<dyn gpu::GpuBackend>> = if fake {
        Some(gpu::fake())
    } else if show {
        Some(gpu::open(1080, 2400)?)
    } else {
        None
    };
    if show && !fake {
        let gpu_guest = gpu.clone();
        let done = Arc::new(AtomicBool::new(false));
        let done_thr = done.clone();
        let slot: Arc<Mutex<Option<Result<i32, String>>>> = Arc::new(Mutex::new(None));
        let slot_thr = slot.clone();
        let root = root.clone();
        std::thread::spawn(move || {
            let _stop = Stop(done_thr);
            let code = boot_guest(hv, root, system, vfs, strace, extras, argv, argv_copy, gpu_guest);
            *slot_thr.lock().unwrap_or_else(|p| p.into_inner()) = Some(code);
        });
        gpu::pump_until(&done);
        // Last owner: tear the renderer down on the main thread.
        drop(gpu);
        return slot.lock().unwrap_or_else(|p| p.into_inner()).take().unwrap_or_else(|| Err("guest thread panicked".into()));
    }
    boot_guest(hv, root, system, vfs, strace, extras, argv, argv_copy, gpu)
}

/// The image `--image` or `--system` names, or for a boot without either, the
/// tested one. An image that can't boot is an error that says why.
fn choose_image(image: Option<&str>, system: Option<&Path>, boot: bool) -> Result<Option<Chosen>, String> {
    if let Some(spec) = image {
        let sdk = sdk::require()?;
        let (img, support) = sdk::pick(spec, &sdk.images(), sdk::classify)?;
        return Ok(Some(Chosen { path: img.system_img(), image: Some(img), support }));
    }
    if let Some(p) = system {
        let path = if p.is_dir() { p.join("system.img") } else { p.to_path_buf() };
        if !path.is_file() {
            return Err(format!("{}: no such file", path.display()));
        }
        let (image, support) = sdk::classify_file(&path);
        if let sdk::Support::Unsupported(why) = &support {
            return Err(format!("{}: unsupported: {why}", path.display()));
        }
        return Ok(Some(Chosen { path, image, support }));
    }
    if !boot {
        return Ok(None);
    }
    let sdk = sdk::require()?;
    let images = sdk.images();
    let Some(img) = images.iter().find(|i| i.is_tested()) else {
        return Err(not_installed(&sdk, &images));
    };
    match sdk::classify(img) {
        sdk::Support::Unsupported(why) => Err(Problem::new(
            format!("the tested system image, {} ({}), can't boot: {why}", img.name(), img.abi),
            [format!("{} reinstalls it", sdk.sdkmanager(&img.package()))],
        )
        .into()),
        support => Ok(Some(Chosen { path: img.system_img(), image: Some(img.clone()), support })),
    }
}

/// The tested image isn't installed: how to install it, and what else could boot.
fn not_installed(sdk: &sdk::Sdk, images: &[sdk::Image]) -> String {
    let mut out = format!(
        "the system image zeroemu is tested with isn't installed: {}/{} ({})\nInstall it with:\n  {}\n",
        sdk::TESTED_LEVEL,
        sdk::TESTED_TAG,
        sdk::host_abi(),
        sdk.sdkmanager(&sdk::tested_package())
    );
    if images.is_empty() {
        out += &format!("No system images are installed in {}.", sdk.root.display());
        return out;
    }
    let images = doctor::classify_all(images);
    out += &format!("Installed in {}:\n", sdk.root.display());
    out += &doctor::image_table(&images, "  ");
    out += if images.iter().any(|(_, s)| s.boots()) { "--image <name> boots one of those, untested." } else { "None of those can boot." };
    out
}

/// What a boot says before it starts: the image, where /data is kept, the adb
/// serial, and how to stop.
fn print_status(c: &Chosen, data: Option<&Path>, adb: Option<u16>, window: bool) {
    let what = match &c.image {
        Some(i) => format!("{} ({}{})", i.name(), i.release().map(|r| format!("Android {r}, ")).unwrap_or_default(), i.abi),
        None => c.path.display().to_string(),
    };
    eprintln!("zeroemu: image {what}, {}", c.support);
    match data {
        Some(p) => eprintln!("zeroemu: /data is kept in {}", p.display()),
        None => eprintln!("zeroemu: /data is not kept"),
    }
    if let Some(port) = adb {
        eprintln!("zeroemu: adb serial emulator-{}", port - 1);
    }
    let how = if window { "close the window or press Ctrl-C" } else { "press Ctrl-C" };
    let save = match data {
        Some(_) if cfg!(windows) => "; on Windows, /data isn't saved then",
        Some(_) => "; /data is saved then",
        None => "",
    };
    eprintln!("zeroemu: to stop, {how}{save}");
}

/// The renderer must be there before a window opens; a release other than the
/// tested one only gets a warning.
fn check_renderer() -> Result<(), Problem> {
    let r = sdk::require_renderer()?;
    if r.from_env {
        return Ok(());
    }
    let Some(sdk) = sdk::find() else { return Ok(()) };
    match sdk.emulator_version() {
        Some(v) if sdk::emulator_tested(&v) => {}
        Some(v) => eprintln!("zeroemu: warning: Android Emulator {v} is installed; zeroemu is tested with {}, and other releases' renderers may not work", sdk::tested_emulators_shown()),
        None => eprintln!("zeroemu: warning: can't tell which Android Emulator is installed (no Pkg.Revision in {})", sdk.root.join("emulator/source.properties").display()),
    }
    Ok(())
}

struct Stop(Arc<AtomicBool>);
impl Drop for Stop {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}

#[allow(clippy::too_many_arguments)]
fn boot_guest(
    hv: Arc<dyn hv::Hypervisor>,
    root: PathBuf,
    system: Option<PathBuf>,
    vfs: Option<vfs::Vfs>,
    strace: bool,
    extras: Option<kernel::BootExtras>,
    argv: Vec<String>,
    argv_copy: Vec<String>,
    gpu: Option<Arc<dyn gpu::GpuBackend>>,
) -> Result<i32, String> {
    let gpu = gpu;
    let program = argv.first().ok_or(USAGE)?.clone();
    let envp = vec![
        "PATH=/product/bin:/apex/com.android.runtime/bin:/system/bin:/system_ext/bin:/vendor/bin".to_string(),
        "ANDROID_ROOT=/system".to_string(),
        "ANDROID_DATA=/data".to_string(),
        "HOME=/".to_string(),
    ];

    let partitions = match &system {
        Some(img) => android::logical_partitions(img).map_err(|e| format!("{}: {e}", img.display()))?,
        None => Vec::new(),
    };
    let kernel = Kernel::new(hv, vfs, partitions, strace, extras, gpu)?;
    let mut mm = kernel.new_address_space().map_err(|e| format!("address space: errno {e}"))?;
    let (state, exe) = if system.is_some() {
        kernel
            .load_program(None, &mut mm, "/", &program, argv, &envp)
            .map_err(|e| format!("{program}: cannot execute (errno {e})"))?
    } else {
        // No image: a freestanding host binary (the test guests).
        let read = |p: &str| std::fs::read(root.join(p.trim_start_matches('/'))).or_else(|_| std::fs::read(p)).map_err(|e| format!("{p}: {e}"));
        let source = |data: Vec<u8>| (data.len() as u64, kernel.bytes_source(data.into()));
        let (size, src) = source(read(&program)?);
        let main = elf::load(&mut mm, &src, size, &program, false)?;
        let (entry, base) = match &main.interp {
            Some(i) => {
                let (size, src) = source(read(i)?);
                let li = elf::load(&mut mm, &src, size, i, true)?;
                (li.entry, li.bias)
            }
            None => (main.entry, 0),
        };
        mm.set_brk_start(main.end);
        let sp = elf::build_stack(&mut mm, &main, base, &argv, &envp).map_err(|e| format!("stack: errno {e}"))?;
        mm.set_name(main.lo, main.end - main.lo, &program);
        (hv::CpuState::new_user(entry, sp), program.clone())
    };
    kernel.start(mm, exe, &argv_copy, state)?;
    let status = kernel.wait_root();
    kernel.save_data();
    // Like a shell: the exit code, or 128 + the signal that killed it.
    Ok(if status & 0x7f == 0 { (status >> 8) & 0xff } else { 128 + (status & 0x7f) })
}

/// Each host connection is a descriptor, and launchd's default allows 256.
#[cfg(unix)]
fn raise_fd_limit() {
    unsafe {
        let mut r: libc::rlimit = std::mem::zeroed();
        if libc::getrlimit(libc::RLIMIT_NOFILE, &mut r) != 0 {
            return;
        }
        // macOS refuses its own "infinity" as a limit, so try something less.
        for want in [r.rlim_max, 65536, 10240] {
            let want = want.min(r.rlim_max);
            if want <= r.rlim_cur {
                return;
            }
            if libc::setrlimit(libc::RLIMIT_NOFILE, &libc::rlimit { rlim_cur: want, rlim_max: r.rlim_max }) == 0 {
                return;
            }
        }
    }
}

/// The user's application data: where zeroemu's folder of saved devices goes.
fn app_data() -> Option<PathBuf> {
    if cfg!(windows) {
        Some(PathBuf::from(std::env::var_os("LOCALAPPDATA")?))
    } else if cfg!(target_os = "macos") {
        Some(PathBuf::from(std::env::var_os("HOME")?).join("Library/Application Support"))
    } else {
        Some(PathBuf::from(std::env::var_os("HOME")?).join(".local/share"))
    }
}

/// Where devices are saved, a file per system image, and where they were saved
/// under the project's old name.
pub fn data_dirs() -> Option<(PathBuf, PathBuf)> {
    let base = app_data()?;
    Some((base.join("zeroemu"), base.join("droidrt")))
}

/// A file for this image's device in the user's application data. Moves devices
/// saved under the project's old name first.
fn default_data_image(system: &Path) -> Option<PathBuf> {
    // FNV-1a of the image's path: a device per image.
    let path = std::fs::canonicalize(system).ok()?;
    let id = path.to_string_lossy().bytes().fold(0xcbf2_9ce4_8422_2325u64, |h, b| (h ^ b as u64).wrapping_mul(0x0100_0000_01b3));
    let (dir, legacy) = data_dirs()?;
    if !dir.exists() && legacy.is_dir() && std::fs::rename(&legacy, &dir).is_ok() {
        eprintln!("zeroemu: moved saved devices from {} to {}", legacy.display(), dir.display());
    }
    Some(dir.join(format!("data-{id:016x}.img")))
}

fn inspect_image(vfs: &vfs::Vfs, cmd: &str, path: &str) -> Result<i32, String> {
    let node = vfs
        .resolve("/", path, cmd == "--cat")
        .map_err(|e| format!("{path}: errno {e}"))?;
    if cmd == "--cat" {
        let data = vfs
            .read_all(&node)
            .map_err(|e| format!("{path}: errno {e}"))?;
        std::io::Write::write_all(&mut std::io::stdout(), &data).map_err(|e| e.to_string())?;
        return Ok(0);
    }
    let st = vfs.stat(&node).map_err(|e| format!("{path}: errno {e}"))?;
    if st.mode & vfs::S_IFMT != vfs::S_IFDIR {
        println!(
            "{:o} {:>6}:{:<6} {:>10} {}",
            st.mode, st.uid, st.gid, st.size, node.path
        );
        return Ok(0);
    }
    let mut entries = vfs
        .readdir(&node)
        .map_err(|e| format!("{path}: errno {e}"))?;
    entries.sort_by(|a, b| a.name.cmp(&b.name));
    for e in entries.iter().filter(|e| e.name != "." && e.name != "..") {
        let child = format!("{}/{}", node.path.trim_end_matches('/'), e.name);
        match vfs.resolve("/", &child, false).and_then(|n| vfs.stat(&n)) {
            Ok(st) if st.mode & vfs::S_IFMT == vfs::S_IFLNK => {
                let n = vfs.resolve("/", &child, false).unwrap();
                let target = vfs
                    .read_all(&n)
                    .map(|t| String::from_utf8_lossy(&t).into_owned())
                    .unwrap_or_default();
                println!("{:o} {:>10} {} -> {}", st.mode, st.size, e.name, target);
            }
            Ok(st) => println!("{:o} {:>10} {}", st.mode, st.size, e.name),
            Err(errno) => println!("? {} (errno {errno})", e.name),
        }
    }
    Ok(0)
}

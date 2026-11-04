//! droidrt: runs Android's (Linux) userspace binaries directly on the host CPU
//! inside a kernel-less hardware VM, implementing the Linux syscall ABI in Rust.

mod android;
mod arch;
mod elf;
mod errno;
mod hv;
mod image;
mod kernel;
mod mm;
mod paging;
mod phys;
mod tmpfs;
mod vfs;

use kernel::Kernel;
use std::path::PathBuf;
use std::process::ExitCode;

const USAGE: &str = "usage: droidrt [--system <system.img>] [--strace] <program> [args...]
       droidrt --system <system.img> --ls <path> | --cat <path>";

fn main() -> ExitCode {
    match run() {
        Ok(code) => ExitCode::from(code as u8),
        Err(e) => {
            eprintln!("droidrt: {e}");
            ExitCode::from(127)
        }
    }
}

fn run() -> Result<i32, String> {
    let mut args = std::env::args().skip(1).peekable();
    let mut root = PathBuf::from("/");
    let mut system: Option<PathBuf> = None;
    let mut inspect: Option<(String, String)> = None;
    let mut strace = std::env::var_os("DROIDRT_STRACE").is_some();
    while let Some(flag) = args.peek().filter(|a| a.starts_with("--")).cloned() {
        args.next();
        match flag.as_str() {
            "--root" => root = args.next().ok_or(USAGE)?.into(),
            "--system" => system = Some(args.next().ok_or(USAGE)?.into()),
            "--ls" | "--cat" => inspect = Some((flag.clone(), args.next().ok_or(USAGE)?)),
            "--strace" => strace = true,
            _ => return Err(format!("unknown flag {flag}\n{USAGE}")),
        }
    }
    let vfs = match &system {
        Some(img) => Some(android::open_system_image(img).map_err(|e| format!("{}: {e}", img.display()))?),
        None => None,
    };
    if let Some((cmd, path)) = inspect {
        return inspect_image(vfs.as_ref().ok_or("--ls/--cat need --system")?, &cmd, &path);
    }
    let argv: Vec<String> = args.collect();
    let argv_copy = argv.clone();
    let program = argv.first().ok_or(USAGE)?.clone();
    let envp = vec![
        "PATH=/product/bin:/apex/com.android.runtime/bin:/system/bin:/system_ext/bin:/vendor/bin".to_string(),
        "ANDROID_ROOT=/system".to_string(),
        "ANDROID_DATA=/data".to_string(),
        "HOME=/".to_string(),
    ];

    let kernel = Kernel::new(hv::create()?, vfs, strace)?;
    let mut mm = kernel.new_address_space().map_err(|e| format!("address space: errno {e}"))?;
    let (state, exe) = if system.is_some() {
        kernel
            .load_program(&mut mm, "/", &program, argv, &envp)
            .map_err(|e| format!("{program}: cannot execute (errno {e})"))?
    } else {
        // No image: a freestanding host binary (the test guests).
        let read = |p: &str| std::fs::read(root.join(p.trim_start_matches('/'))).or_else(|_| std::fs::read(p)).map_err(|e| format!("{p}: {e}"));
        let main = elf::load(&mut mm, &read(&program)?, &program, false)?;
        let (entry, base) = match &main.interp {
            Some(i) => {
                let li = elf::load(&mut mm, &read(i)?, i, true)?;
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
    // Like a shell: the exit code, or 128 + the signal that killed it.
    Ok(if status & 0x7f == 0 { (status >> 8) & 0xff } else { 128 + (status & 0x7f) })
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

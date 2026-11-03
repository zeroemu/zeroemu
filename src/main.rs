//! droidrt: runs Android's (Linux) userspace binaries directly on the host CPU
//! inside a kernel-less hardware VM, implementing the Linux syscall ABI in Rust.

mod android;
mod arch;
mod elf;
mod errno;
mod hv;
mod image;
mod kernel;
mod mem;
mod vfs;

use arch::Arch;
use hv::Exit;
use kernel::{Flow, Process};
use mem::{GuestMem, STACK_TOP};
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

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
        Some(img) => {
            Some(android::open_system_image(img).map_err(|e| format!("{}: {e}", img.display()))?)
        }
        None => None,
    };
    if let Some((cmd, path)) = inspect {
        return inspect_image(vfs.as_ref().ok_or("--ls/--cat need --system")?, &cmd, &path);
    }
    let guest_argv: Vec<String> = args.collect();
    let program = guest_argv.first().ok_or(USAGE)?.clone();
    let vfs = vfs.map(Arc::new);

    // Programs and their interpreter come from the image when one is given,
    // otherwise from the host filesystem (for the freestanding test guests).
    let read_file = |path: &str| -> Result<Vec<u8>, String> {
        match &vfs {
            Some(v) => {
                let node = v
                    .resolve("/", path, true)
                    .map_err(|e| format!("{path}: errno {e}"))?;
                Ok(v.read_all(&node)
                    .map_err(|e| format!("{path}: errno {e}"))?
                    .to_vec())
            }
            None => std::fs::read(root.join(path.trim_start_matches('/')).as_path())
                .or_else(|_| std::fs::read(path))
                .map_err(|e| format!("{path}: {e}")),
        }
    };

    let mem = GuestMem::new();
    let hv = hv::create(&mem)?;

    let main_image = elf::load(&mem, &read_file(&program)?, &program, false)?;
    let (entry, interp_base, brk_limit) = match &main_image.interp {
        Some(interp) => {
            let li = elf::load(&mem, &read_file(interp)?, interp, true)?;
            (li.entry, li.bias, elf::INTERP_BIAS)
        }
        None => (main_image.entry, 0, mem::MMAP_BASE),
    };

    let envp = vec![
        "PATH=/product/bin:/apex/com.android.runtime/bin:/system/bin:/system_ext/bin:/vendor/bin"
            .to_string(),
        "ANDROID_ROOT=/system".to_string(),
        "ANDROID_DATA=/data".to_string(),
        "HOME=/".to_string(),
    ];
    let sp = elf::build_stack(
        &mem,
        STACK_TOP,
        &main_image,
        interp_base,
        &guest_argv,
        &envp,
    );

    let mut vcpu = hv.create_vcpu(entry, sp)?;
    let mut proc = Process::new(
        Arch::HOST,
        vfs.clone(),
        program.clone(),
        main_image.end,
        brk_limit,
    );
    proc.strace = strace;

    loop {
        match vcpu.run() {
            Exit::Syscall => {
                if let Flow::Exit(code) = proc.syscall(&mem, vcpu.as_mut()) {
                    return Ok(code);
                }
            }
            Exit::Fault { pc, addr, detail } => {
                return Err(format!(
                    "guest fault at pc={pc:#x} addr={addr:#x}: {detail}"
                ));
            }
        }
    }
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

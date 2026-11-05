//! Host adb reaches the device as it reaches an emulator: the adb server talks to
//! a loopback port, and droidrt connects that to a guest vsock listener on port 5555,
//! which adbd opens. Guest networking is not involved, so adb stays available for
//! debugging it. adbd's own RSA check stays on: loopback is open to anyone on the host.
//! The host's public key is offered as /adb_keys, as the emulator does for this image
//! by another route, so the user's own adb is already authorized.

use super::hostio::Io;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

pub const GUEST_PORT: u32 = 5555;
/// Console and adb ports come in pairs, emulator-<console>, as the adb server expects.
const FIRST_CONSOLE: u16 = 5554;
const LAST_CONSOLE: u16 = 5584;

/// Ports the guest's alias for the host's loopback won't reach: the adb server takes
/// commands for any device from anyone who can connect, with the host's key, and
/// these are devices' own ports.
pub fn reserved_host_port(port: u16) -> bool {
    // A server on the usual port counts whatever this process was told about another.
    let socket_port = std::env::var("ADB_SERVER_SOCKET").ok().and_then(|s| s.rsplit(':').next()?.parse().ok());
    port == 5037 || port == server_port() || Some(port) == socket_port || (FIRST_CONSOLE..=LAST_CONSOLE + 1).contains(&port) || port == HOST_PORT.load(Ordering::Relaxed)
}

fn server_port() -> u16 {
    std::env::var("ANDROID_ADB_SERVER_PORT").ok().and_then(|p| p.parse().ok()).unwrap_or(5037)
}

/// The host port, once listening.
static HOST_PORT: AtomicU16 = AtomicU16::new(0);

/// Keeps /adb_keys up to date with the host's key, which adb only makes when first run.
static KEYS: OnceLock<Arc<crate::tmpfs::MemFile>> = OnceLock::new();
static LAST_KEY: Mutex<Vec<u8>> = Mutex::new(Vec::new());

fn listen(port: u16) -> Option<TcpListener> {
    TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], port))).ok()
}

/// Starts listening on `port`, or on the first free pair an emulator could have.
pub fn start(port: Option<u16>) {
    let listener = match port {
        Some(p) => listen(p).map(|l| (l, None)),
        None => (FIRST_CONSOLE..=LAST_CONSOLE).step_by(2).find_map(|console| {
            let c = listen(console)?;
            Some((listen(console + 1)?, Some(c)))
        }),
    };
    let Some((listener, console)) = listener else {
        eprintln!("droidrt: no free port for adb");
        return;
    };
    let Ok(addr) = listener.local_addr() else { return };
    HOST_PORT.store(addr.port(), Ordering::Relaxed);
    // There is no console. Accept and close, or `adb emu` would wait forever for one.
    if let Some(c) = console {
        let _ = std::thread::Builder::new().name("adb-console".into()).spawn(move || {
            for conn in c.incoming() {
                drop(conn);
            }
        });
    }
    let _ = std::thread::Builder::new().name("adb-listener".into()).spawn(move || {
        for conn in listener.incoming().flatten() {
            let _ = std::thread::Builder::new().name("adb-connection".into()).spawn(move || connection(conn));
        }
    });
    notify_server();
}

/// One host connection: held open until a guest listener takes it.
fn connection(conn: TcpStream) {
    let _ = conn.set_nodelay(true);
    refresh_key();
    let io = Io::new();
    if io.attach(conn).is_err() {
        return;
    }
    let mut io = Some(io);
    while let Some(i) = io.take() {
        if let Err(i) = super::vsock::offer(GUEST_PORT, i) {
            io = Some(i);
            std::thread::sleep(Duration::from_millis(100));
        }
    }
}

/// A guest listener on the adb port has appeared.
pub fn guest_listening() {
    let _ = std::thread::Builder::new().name("adb-notify".into()).spawn(notify_server);
}

/// Tells a running adb server about this device, as an emulator does: it only scans for
/// devices when it starts. No reply comes. With no server, its scan will find this.
fn notify_server() {
    use std::io::Write;
    let port = HOST_PORT.load(Ordering::Relaxed);
    if port == 0 {
        return;
    }
    if let Ok(mut s) = TcpStream::connect_timeout(&SocketAddr::from(([127, 0, 0, 1], server_port())), Duration::from_secs(1)) {
        let request = format!("host:emulator:{port}");
        let _ = write!(s, "{:04x}{request}", request.len());
    }
}

/// The host's public key, as adb's key file has it.
fn host_key() -> Vec<u8> {
    let home = std::env::var_os(if cfg!(windows) { "USERPROFILE" } else { "HOME" });
    let Some(home) = home else { return Vec::new() };
    let path = std::path::PathBuf::from(home).join(".android").join("adbkey.pub");
    let mut key = std::fs::read(path).unwrap_or_default();
    if !key.is_empty() && key.last() != Some(&b'\n') {
        key.push(b'\n');
    }
    key
}

/// Installs the file that stands in for /adb_keys.
pub fn set_key_file(file: Arc<crate::tmpfs::MemFile>) {
    let _ = KEYS.set(file);
    refresh_key();
}

/// Only when it changed: adbd may be reading it.
fn refresh_key() {
    let Some(file) = KEYS.get() else { return };
    let key = host_key();
    let mut last = LAST_KEY.lock().unwrap();
    if *last != key {
        file.truncate(0);
        let _ = file.write_at(0, &key);
        *last = key;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_adb_server_and_device_ports_are_kept_from_guests() {
        assert!(reserved_host_port(5037), "the usual server, whatever the environment says");
        assert!(reserved_host_port(5554) && reserved_host_port(5585));
        assert!(!reserved_host_port(5586) && !reserved_host_port(80) && !reserved_host_port(8080));
    }
}

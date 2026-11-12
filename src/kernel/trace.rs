//! ZEROEMU_TRACE=<file>: Android's trace markers go to a host file. atrace,
//! SurfaceFlinger, HWUI, the composer and the framework write them to tracefs's
//! `trace_marker` when their tags are on (`ZEROEMU_PROPS=debug.atrace.tags.enableflags=<hex>`).
//! Each becomes a line: the guest's CLOCK_MONOTONIC in microseconds, the writer's pid
//! and tid, and the marker as written ("B|pid|name", "E|pid", "C|pid|name|value", ...).
//! zeroemu adds its own as pid 0, from host threads, on the same clock.

use std::io::Write;
use std::sync::{Mutex, OnceLock};

/// trace_marker's device number: a character device of zeroemu's own (Linux's is a
/// regular file; nothing that writes to it looks).
pub const MARKER_RDEV: u64 = (1 << 8) | 12;

static OUT: OnceLock<Option<Mutex<std::io::BufWriter<std::fs::File>>>> = OnceLock::new();

fn out() -> Option<&'static Mutex<std::io::BufWriter<std::fs::File>>> {
    OUT.get_or_init(|| {
        let path = std::env::var_os("ZEROEMU_TRACE")?;
        match std::fs::File::create(&path) {
            Ok(f) => {
                // What a kill or crash would lose is at most a quarter second of it.
                let _ = std::thread::Builder::new().name("trace-flush".into()).spawn(|| {
                    loop {
                        std::thread::sleep(std::time::Duration::from_millis(250));
                        flush();
                    }
                });
                Some(Mutex::new(std::io::BufWriter::with_capacity(1 << 20, f)))
            }
            Err(e) => {
                eprintln!("zeroemu: ZEROEMU_TRACE {}: {e}", std::path::Path::new(&path).display());
                None
            }
        }
    })
    .as_ref()
}

/// Whether markers are kept.
pub fn enabled() -> bool {
    out().is_some()
}

/// A guest's write to trace_marker.
pub fn marker(pid: i32, tid: i32, data: &[u8]) {
    let Some(out) = out() else { return };
    let text = String::from_utf8_lossy(data);
    let line = format!("{} {pid} {tid} {}\n", super::monotonic_ns() / 1000, text.trim_end_matches(['\n', '\0']));
    let _ = out.lock().unwrap_or_else(|p| p.into_inner()).write_all(line.as_bytes());
}

/// A slice of zeroemu's work for a guest thread, shown on that thread: ends when
/// dropped.
pub struct GuestSpan(i32, i32);

pub fn guest_span(pid: i32, tid: i32, name: &str) -> GuestSpan {
    marker(pid, tid, format!("B|{pid}|{name}").as_bytes());
    GuestSpan(pid, tid)
}

impl Drop for GuestSpan {
    fn drop(&mut self) {
        marker(self.0, self.1, format!("E|{}", self.0).as_bytes());
    }
}

/// A slice of zeroemu's own work, as pid 0 on a host thread: ends when dropped.
pub struct Span(Option<&'static str>);

pub fn span(name: &'static str) -> Span {
    if !enabled() {
        return Span(None);
    }
    host(&format!("B|0|{name}"));
    Span(Some(name))
}

impl Drop for Span {
    fn drop(&mut self) {
        if self.0.is_some() {
            host("E|0");
        }
    }
}

fn host(text: &str) {
    marker(0, host_tid(), text.as_bytes());
}

/// A small number per host thread, apart from guest tids.
fn host_tid() -> i32 {
    use std::sync::atomic::{AtomicI32, Ordering};
    static NEXT: AtomicI32 = AtomicI32::new(1_000_000);
    thread_local!(static TID: i32 = NEXT.fetch_add(1, Ordering::Relaxed));
    TID.with(|t| *t)
}

/// Writes out what is buffered: at exit, when asked (SIGUSR1's dump), and four
/// times a second.
pub fn flush() {
    if let Some(out) = OUT.get().and_then(|o| o.as_ref()) {
        let _ = out.lock().unwrap_or_else(|p| p.into_inner()).flush();
    }
}

/// flush() for a panic: the panicking thread may hold the lock.
pub fn flush_if_free() {
    if let Some(out) = OUT.get().and_then(|o| o.as_ref())
        && let Ok(mut w) = out.try_lock()
    {
        let _ = w.flush();
    }
}

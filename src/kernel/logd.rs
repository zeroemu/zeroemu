//! logd, answered inside the kernel: the three sockets liblog talks to, so
//! every Android process's log output appears on stderr and Android's own
//! `logcat` can read it back.
//!
//! - `/dev/socket/logdw` (datagram): each write is an `android_log_header_t`
//!   (log id u8, tid u16, realtime sec u32 + nsec u32) and a payload; text
//!   buffers carry priority u8, tag\0, message\0.
//! - `/dev/socket/logdr` (seqpacket): a reader sends one command
//!   (`dumpAndClose` or `stream`, then `lids=0,3 tail=N start=S.N pid=P`) and
//!   receives one `logger_entry` packet per record.
//! - `/dev/socket/logd` (stream): control commands such as `clear 0` and
//!   `getLogSize 0`, each answered with a NUL-terminated string.
//!
//! `DROIDRT_LOG=<V|D|I|W|E|F|S>` sets the lowest priority printed (default I).
//! Once init starts the real logd on sockets of its own, the kernel still
//! prints what that logd receives (`tap`), so logs stay on the terminal.

use super::unix::{self, Service, Socket};
use crate::vfs::Vfs;
use std::collections::VecDeque;
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::time::Instant;

const LOG_ID_MAX: u8 = 8;
/// Buffers with binary payloads (events, stats, security): kept, not printed.
const BINARY: u32 = 1 << 2 | 1 << 5 | 1 << 6;
/// sizeof(android_log_header_t).
const HEADER: usize = 11;
/// sizeof(logger_entry), the v4 header readers receive.
const ENTRY_HEADER: usize = 28;
/// LOGGER_ENTRY_MAX_PAYLOAD.
const PAYLOAD_MAX: usize = 4068;
/// What each buffer reports as its size; all buffers share one ring of this
/// times the buffer count.
const BUFFER_SIZE: usize = 256 << 10;

struct Entry {
    lid: u8,
    pid: i32,
    tid: u32,
    sec: u32,
    nsec: u32,
    payload: Vec<u8>,
}

impl Entry {
    /// A datagram written to logdw by process `pid`.
    fn parse(data: &[u8], pid: i32) -> Option<Entry> {
        if data.len() <= HEADER || data[0] >= LOG_ID_MAX {
            return None;
        }
        Some(Entry {
            lid: data[0],
            pid,
            tid: u16::from_le_bytes([data[1], data[2]]) as u32,
            sec: le32(&data[3..]),
            nsec: le32(&data[7..]),
            payload: data[HEADER..data.len().min(HEADER + PAYLOAD_MAX)].to_vec(),
        })
    }

    /// Prints a text record the way `logcat -v threadtime` does, with time
    /// since boot in place of the date.
    fn print(&self) {
        let (level, boot) = printer();
        if BINARY & 1 << self.lid != 0 {
            return;
        }
        let Some((&prio, rest)) = self.payload.split_first() else { return };
        if prio < level {
            return;
        }
        let (tag, rest) = cstr(rest);
        let (msg, _) = cstr(rest);
        let p = b"??VDIWEFS".get(prio as usize).copied().unwrap_or(b'?') as char;
        let tag = String::from_utf8_lossy(tag);
        let msg = String::from_utf8_lossy(msg);
        let t = boot.elapsed();
        let mut out = String::new();
        for line in msg.trim_end_matches('\n').split('\n') {
            out += &format!("{:5}.{:03} {:5} {:5} {p} {tag}: {line}\n", t.as_secs(), t.subsec_millis(), self.pid, self.tid);
        }
        eprint!("{out}");
    }

    fn packet(&self) -> Vec<u8> {
        let mut p = Vec::with_capacity(ENTRY_HEADER + self.payload.len());
        p.extend_from_slice(&(self.payload.len() as u16).to_le_bytes());
        p.extend_from_slice(&(ENTRY_HEADER as u16).to_le_bytes());
        p.extend_from_slice(&self.pid.to_le_bytes());
        p.extend_from_slice(&self.tid.to_le_bytes());
        p.extend_from_slice(&self.sec.to_le_bytes());
        p.extend_from_slice(&self.nsec.to_le_bytes());
        p.extend_from_slice(&(self.lid as u32).to_le_bytes());
        p.extend_from_slice(&0u32.to_le_bytes()); // uid: everything runs as root
        p.extend_from_slice(&self.payload);
        p
    }
}

/// What a reader asked for.
#[derive(Clone, Copy)]
struct Filter {
    lids: u32,
    pid: i32,
    start: (u32, u32),
}

impl Filter {
    fn wants(&self, e: &Entry) -> bool {
        self.lids & 1 << e.lid != 0 && (self.pid == 0 || self.pid == e.pid) && (e.sec, e.nsec) >= self.start
    }
}

#[derive(Default)]
struct Logs {
    entries: VecDeque<Entry>,
    bytes: usize,
    /// `stream` readers, sent each new entry as it arrives.
    readers: Vec<(Weak<Socket>, Filter)>,
}

struct Logd {
    logs: Mutex<Logs>,
}

/// (lowest priority printed to stderr, time zero), fixed at first use.
fn printer() -> (u8, Instant) {
    static PRINTER: OnceLock<(u8, Instant)> = OnceLock::new();
    *PRINTER.get_or_init(|| {
        let level = match std::env::var("DROIDRT_LOG").ok().and_then(|v| v.bytes().next()) {
            Some(b'V' | b'v') => 2,
            Some(b'D' | b'd') => 3,
            Some(b'W' | b'w') => 5,
            Some(b'E' | b'e') => 6,
            Some(b'F' | b'f') => 7,
            Some(b'S' | b's') => u8::MAX,
            _ => 4,
        };
        (level, Instant::now())
    })
}

/// AID_LOGD and AID_STATSD, which own these sockets on a device.
const LOGD: (u32, u32) = (1036, 1036);
const STATSD: (u32, u32) = (1066, 1066);

/// Creates logd's sockets in /dev/socket (and a sink for statsd's), with
/// logd.rc's modes; the returned sockets must be kept alive.
pub fn start(vfs: &Vfs) -> Vec<Arc<Socket>> {
    printer();
    let logd: Arc<dyn Service> = Arc::new(Logd { logs: Mutex::default() });
    vec![
        unix::bind_service(vfs, "/dev/socket/logdw", 0o222, LOGD, logd.clone()),
        unix::listen_service(vfs, "/dev/socket/logdr", unix::SOCK_SEQPACKET, 0o666, LOGD, logd.clone()),
        unix::listen_service(vfs, "/dev/socket/logd", unix::SOCK_STREAM, 0o666, LOGD, logd),
        unix::bind_service(vfs, "/dev/socket/statsdw", 0o222, STATSD, Arc::new(Discard)),
    ]
}

/// A datagram delivered to a process's /dev/socket/logdw (the real logd):
/// printed exactly as the kernel's logd prints its own records.
pub fn tap(data: &[u8], pid: i32) {
    if let Some(e) = Entry::parse(data, pid) {
        e.print();
    }
}

/// Accepts datagrams and drops them.
struct Discard;
impl Service for Discard {}

fn cstr(b: &[u8]) -> (&[u8], &[u8]) {
    match b.iter().position(|&c| c == 0) {
        Some(n) => (&b[..n], &b[n + 1..]),
        None => (b, &[]),
    }
}

fn le32(b: &[u8]) -> u32 {
    u32::from_le_bytes(b[..4].try_into().unwrap())
}

impl Logd {
    fn clear(&self, lids: u32) {
        let mut logs = self.logs.lock().unwrap();
        logs.entries.retain(|e| lids & 1 << e.lid == 0);
        logs.bytes = logs.entries.iter().map(|e| e.payload.len()).sum();
    }

    fn used(&self, lids: u32) -> usize {
        let logs = self.logs.lock().unwrap();
        logs.entries.iter().filter(|e| lids & 1 << e.lid != 0).map(|e| ENTRY_HEADER + e.payload.len()).sum()
    }

    /// Answers one control command.
    fn control(&self, cmd: &str) -> String {
        let mut words = cmd.split_whitespace();
        let verb = words.next().unwrap_or("");
        // Buffer ids are sent as signed numbers; -1 means all of them.
        let lids = match words.next().and_then(|w| w.parse::<i64>().ok()) {
            Some(id) if (0..LOG_ID_MAX as i64).contains(&id) => 1 << id,
            _ => u32::MAX,
        };
        match verb {
            "clear" => {
                self.clear(lids);
                "success".into()
            }
            "getLogSize" => BUFFER_SIZE.to_string(),
            "getLogSizeUsed" | "getLogSizeReadable" => self.used(lids).to_string(),
            "setLogSize" | "setPruneList" | "reinit" => "success".into(),
            "getPruneList" => String::new(),
            "getStatistics" => format!("droidrt logd: {} bytes in {} entries\n", self.used(u32::MAX), self.logs.lock().unwrap().entries.len()),
            _ => "Invalid".into(),
        }
    }
}

impl Service for Logd {
    /// logdw: one record from process `pid`.
    fn datagram(&self, data: &[u8], pid: i32) {
        let Some(e) = Entry::parse(data, pid) else { return };
        e.print();
        let mut logs = self.logs.lock().unwrap();
        if !logs.readers.is_empty() {
            let packet = e.packet();
            logs.readers.retain(|(conn, f)| !f.wants(&e) || conn.upgrade().is_some_and(|c| c.push(packet.clone())));
        }
        logs.bytes += e.payload.len();
        logs.entries.push_back(e);
        while logs.bytes > BUFFER_SIZE * LOG_ID_MAX as usize {
            let old = logs.entries.pop_front().unwrap();
            logs.bytes -= old.payload.len();
        }
    }

    /// logdr: a reader's command.
    fn packet(&self, conn: &Arc<Socket>, data: &[u8]) {
        let cmd = String::from_utf8_lossy(cstr(data).0).into_owned();
        let mut f = Filter { lids: u32::MAX, pid: 0, start: (0, 0) };
        let mut tail = 0;
        for word in cmd.split_whitespace() {
            if let Some(v) = word.strip_prefix("lids=") {
                f.lids = v.split(',').filter_map(|id| id.parse::<u8>().ok()).filter(|&id| id < LOG_ID_MAX).fold(0, |m, id| m | 1 << id);
            } else if let Some(v) = word.strip_prefix("tail=") {
                tail = v.parse().unwrap_or(0);
            } else if let Some(v) = word.strip_prefix("pid=") {
                f.pid = v.parse().unwrap_or(0);
            } else if let Some(v) = word.strip_prefix("start=") {
                let (s, ns) = v.split_once('.').unwrap_or((v, "0"));
                f.start = (s.parse().unwrap_or(0), ns.parse().unwrap_or(0));
            }
        }
        let mut logs = self.logs.lock().unwrap();
        let matching: Vec<&Entry> = logs.entries.iter().filter(|e| f.wants(e)).collect();
        let skip = if tail > 0 { matching.len().saturating_sub(tail) } else { 0 };
        for e in &matching[skip..] {
            conn.push(e.packet());
        }
        if cmd.starts_with("dumpAndClose") {
            conn.finish();
        } else {
            logs.readers.push((Arc::downgrade(conn), f));
        }
    }

    /// logd: NUL-terminated control commands.
    fn handle(&self, buf: &mut Vec<u8>) -> Option<Vec<u8>> {
        let n = buf.iter().position(|&c| c == 0)?;
        let cmd = String::from_utf8_lossy(&buf[..n]).into_owned();
        buf.drain(..=n);
        let mut reply = self.control(&cmd).into_bytes();
        reply.push(0);
        Some(reply)
    }
}

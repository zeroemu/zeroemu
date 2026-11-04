//! AF_INET and AF_INET6 sockets, with no network behind them yet: connecting
//! and sending fail as on a device with no route. They exist for what
//! Android does with them besides talking, chiefly netd's iptables: legacy
//! ip_tables / ip6_tables get and replace whole tables through socket
//! options on a raw socket. droidrt keeps those tables (nothing filters).

use super::files::{File, Kind};
use super::{Kernel, Thread};
use crate::arch::Sysno;
use crate::errno::*;
use std::collections::HashMap;
use std::sync::{Arc, LazyLock, Mutex};

pub const AF_INET: u64 = 2;
pub const AF_INET6: u64 = 10;
pub const AF_KEY: u64 = 15;
const SOCK_RAW: u32 = 3;
const SOCK_NONBLOCK: u64 = 0o4000;
const SOCK_CLOEXEC: u64 = 0o2000000;

const SOL_SOCKET: u64 = 1;
const SOL_IP: u64 = 0;
const SOL_IPV6: u64 = 41;
const SO_TYPE: u64 = 3;
const SO_ERROR: u64 = 4;
const SO_PROTOCOL: u64 = 38;
const SO_DOMAIN: u64 = 39;

// ip_tables / ip6_tables socket options (same numbers at SOL_IP and SOL_IPV6).
const SO_SET_REPLACE: u64 = 64;
const SO_SET_ADD_COUNTERS: u64 = 65;
const SO_GET_INFO: u64 = 64;
const SO_GET_ENTRIES: u64 = 65;

pub struct Inet {
    pub family: u64,
    pub ty: u32,
    pub proto: u32,
    opts: Mutex<super::unix::SockOpts>,
}

impl Inet {
    fn v6(&self) -> bool {
        self.family == AF_INET6
    }
}

/// One table as GET_INFO describes it, its rules as GET_ENTRIES returns them.
#[derive(Clone)]
struct Table {
    valid_hooks: u32,
    hook_entry: [u32; 5],
    underflow: [u32; 5],
    num_entries: u32,
    entries: Vec<u8>,
}

/// (IPv6?, table name) -> table.
static TABLES: LazyLock<Mutex<HashMap<(bool, String), Table>>> = LazyLock::new(Mutex::default);

/// A fresh table: the kernel's built-in chains, each an ACCEPT policy, then
/// the ERROR entry that ends every table.
fn initial(v6: bool, name: &str) -> Option<Table> {
    // NF_INET_PRE_ROUTING, LOCAL_IN, FORWARD, LOCAL_OUT, POST_ROUTING.
    let valid_hooks: u32 = match name {
        "filter" | "security" => 0b01110,
        "mangle" => 0b11111,
        "nat" => 0b11011,
        "raw" => 0b01001,
        _ => return None,
    };
    // sizeof(ipt_entry) / sizeof(ip6t_entry), and where their fields sit.
    let (entry, target_off, next_off) = if v6 { (168, 140, 142) } else { (112, 88, 90) };
    let rule = |target: &[u8]| {
        let mut e = vec![0u8; entry];
        e[target_off..target_off + 2].copy_from_slice(&(entry as u16).to_le_bytes());
        e[next_off..next_off + 2].copy_from_slice(&((entry + target.len()) as u16).to_le_bytes());
        e.extend_from_slice(target);
        e
    };
    // xt_standard_target: xt_entry_target (size, name "", revision) + verdict, 8-aligned.
    let mut accept = vec![0u8; 40];
    accept[0..2].copy_from_slice(&40u16.to_le_bytes());
    accept[32..36].copy_from_slice(&(-2i32).to_le_bytes()); // -NF_ACCEPT - 1
    // xt_error_target: xt_entry_target named "ERROR" + errorname "ERROR", 8-aligned.
    let mut error = vec![0u8; 64];
    error[0..2].copy_from_slice(&64u16.to_le_bytes());
    error[2..7].copy_from_slice(b"ERROR");
    error[32..37].copy_from_slice(b"ERROR");
    let mut t = Table { valid_hooks, hook_entry: [u32::MAX; 5], underflow: [u32::MAX; 5], num_entries: 0, entries: Vec::new() };
    for hook in 0..5 {
        if valid_hooks & 1 << hook != 0 {
            let at = t.entries.len() as u32;
            t.hook_entry[hook] = at;
            t.underflow[hook] = at;
            t.entries.extend(rule(&accept));
            t.num_entries += 1;
        }
    }
    t.entries.extend(rule(&error));
    t.num_entries += 1;
    Some(t)
}

fn table_name(raw: &[u8]) -> String {
    let end = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
    String::from_utf8_lossy(&raw[..end]).into_owned()
}

fn with_table<R>(v6: bool, name: &str, f: impl FnOnce(&mut Table) -> R) -> Result<R, i64> {
    let mut tables = TABLES.lock().unwrap();
    let key = (v6, name.to_string());
    if !tables.contains_key(&key) {
        tables.insert(key.clone(), initial(v6, name).ok_or(ENOENT)?);
    }
    Ok(f(tables.get_mut(&key).unwrap()))
}

impl Kernel {
    pub(super) fn inet_socket(&self, t: &Arc<Thread>, a: [u64; 6]) -> Result<i64, i64> {
        let ty = (a[1] & 0xf) as u32;
        if !(1..=3).contains(&ty) && ty != 5 {
            return Err(EINVAL);
        }
        let sock = Inet { family: a[0], ty, proto: a[2] as u32, opts: Mutex::default() };
        let file = File::new(Kind::Inet(Arc::new(sock)), (a[1] & SOCK_NONBLOCK) as u32);
        t.files().alloc(file, a[1] & SOCK_CLOEXEC != 0, 0)
    }

    pub(super) fn inet_syscall(&self, no: Sysno, t: &Arc<Thread>, s: &Inet, a: [u64; 6]) -> Result<i64, i64> {
        use Sysno::*;
        match no {
            getsockopt => self.inet_getsockopt(t, s, a),
            setsockopt => self.inet_setsockopt(t, s, a),
            // Options, binds and listens succeed; nothing can reach the socket.
            bind | listen | shutdown => Ok(0),
            connect | sendto | sendmsg => Err(ENETUNREACH),
            getsockname => {
                let len = if s.v6() { 28 } else { 16 };
                let mut addr = vec![0u8; len];
                addr[0..2].copy_from_slice(&(s.family as u16).to_le_bytes());
                let mut mm = t.proc.mm();
                let room = mm.read_u32(a[2])? as usize;
                mm.write(a[1], &addr[..room.min(len)])?;
                mm.write_u32(a[2], len as u32)?;
                Ok(0)
            }
            getpeername => Err(ENOTCONN),
            recvfrom | recvmsg | accept | accept4 => Err(EAGAIN),
            _ => Err(EOPNOTSUPP),
        }
    }

    pub(super) fn inet_ioctl(&self, t: &Arc<Thread>, cmd: u64, arg: u64) -> Result<i64, i64> {
        const SIOCGIFCONF: u64 = 0x8912;
        if cmd == SIOCGIFCONF {
            // struct ifconf: a length, then a buffer of ifreqs (none: the size wanted).
            let mut mm = t.proc.mm();
            let room = mm.read_u32(arg)? as usize;
            let buf = mm.read_u64(arg + 8)?;
            if buf != 0 && room >= 40 {
                let mut req = [0u8; 40];
                req[..2].copy_from_slice(b"lo");
                req[16..18].copy_from_slice(&2u16.to_le_bytes()); // AF_INET
                req[20..24].copy_from_slice(&[127, 0, 0, 1]);
                mm.write(buf, &req)?;
            }
            mm.write_u32(arg, 40)?;
            return Ok(0);
        }
        let mut req = [0u8; 40];
        t.proc.mm().read(arg, &mut req)?;
        super::net::ifreq_ioctl(cmd, &mut req)?;
        t.proc.mm().write(arg, &req)?;
        Ok(0)
    }

    fn inet_getsockopt(&self, t: &Arc<Thread>, s: &Inet, a: [u64; 6]) -> Result<i64, i64> {
        let (level, name, val, lenp) = (a[1], a[2], a[3], a[4]);
        let len = t.proc.mm().read_u32(lenp)? as usize;
        if level == SOL_SOCKET {
            let v: u32 = match name {
                SO_TYPE => s.ty,
                SO_DOMAIN => s.family as u32,
                SO_PROTOCOL => s.proto,
                SO_ERROR => 0,
                _ => {
                    let v = s.opts.lock().unwrap().get(name).ok_or(ENOPROTOOPT)?;
                    let mut mm = t.proc.mm();
                    mm.write(val, &v[..len.min(v.len())])?;
                    mm.write_u32(lenp, len.min(v.len()) as u32)?;
                    return Ok(0);
                }
            };
            let mut mm = t.proc.mm();
            mm.write(val, &v.to_le_bytes()[..len.min(4)])?;
            mm.write_u32(lenp, 4)?;
            return Ok(0);
        }
        if s.ty != SOCK_RAW || level != if s.v6() { SOL_IPV6 } else { SOL_IP } {
            return Err(ENOPROTOOPT);
        }
        // ip6_tables numbers its revision queries 68/69, ip_tables 66/67.
        let revision = if s.v6() { [68, 69] } else { [66, 67] };
        match name {
            SO_GET_INFO => {
                if len != 84 {
                    return Err(EINVAL);
                }
                let mut info = t.proc.mm().read_vec(val, 84)?;
                let tbl = with_table(s.v6(), &table_name(&info[..32]), |t| t.clone())?;
                info[32..36].copy_from_slice(&tbl.valid_hooks.to_le_bytes());
                for h in 0..5 {
                    info[36 + h * 4..40 + h * 4].copy_from_slice(&tbl.hook_entry[h].to_le_bytes());
                    info[56 + h * 4..60 + h * 4].copy_from_slice(&tbl.underflow[h].to_le_bytes());
                }
                info[76..80].copy_from_slice(&tbl.num_entries.to_le_bytes());
                info[80..84].copy_from_slice(&(tbl.entries.len() as u32).to_le_bytes());
                t.proc.mm().write(val, &info)?;
                Ok(0)
            }
            SO_GET_ENTRIES => {
                // struct ipt_get_entries: name, size, then the rules (8-aligned).
                if len < 40 {
                    return Err(EINVAL);
                }
                let head = t.proc.mm().read_vec(val, 40)?;
                let size = u32::from_le_bytes(head[32..36].try_into().unwrap()) as usize;
                if len != 40 + size {
                    return Err(EINVAL);
                }
                let entries = with_table(s.v6(), &table_name(&head[..32]), |t| t.entries.clone())?;
                if entries.len() != size {
                    return Err(EAGAIN); // the table changed since GET_INFO
                }
                t.proc.mm().write(val + 40, &entries)?;
                Ok(0)
            }
            // Every match and target is there, at any revision.
            n if revision.contains(&n) => Ok(1),
            _ => Err(ENOPROTOOPT),
        }
    }

    fn inet_setsockopt(&self, t: &Arc<Thread>, s: &Inet, a: [u64; 6]) -> Result<i64, i64> {
        let (level, name, val, len) = (a[1], a[2], a[3], a[4] as usize);
        if level == SOL_SOCKET {
            let v = super::unix::sockopt_bytes(t, val, a[4])?;
            s.opts.lock().unwrap().set(name, &v)?;
            return Ok(0);
        }
        if s.ty != SOCK_RAW || level != if s.v6() { SOL_IPV6 } else { SOL_IP } {
            return Ok(0); // TOS, TTL, buffer sizes...: accepted
        }
        match name {
            SO_SET_REPLACE => {
                // struct ipt_replace: name, valid_hooks, num_entries, size,
                // hook_entry[5], underflow[5], num_counters, counters, rules
                // (unlike ipt_getinfo, the counts come first).
                if len < 96 {
                    return Err(EINVAL);
                }
                let head = t.proc.mm().read_vec(val, 96)?;
                let u = |o: usize| u32::from_le_bytes(head[o..o + 4].try_into().unwrap());
                let size = u(40) as usize;
                if len < 96 + size || size > 64 << 20 {
                    return Err(EINVAL);
                }
                let mut tbl = Table { valid_hooks: u(32), hook_entry: [0; 5], underflow: [0; 5], num_entries: u(36), entries: t.proc.mm().read_vec(val + 96, size)? };
                for h in 0..5 {
                    tbl.hook_entry[h] = u(44 + h * 4);
                    tbl.underflow[h] = u(64 + h * 4);
                }
                let name = table_name(&head[..32]);
                with_table(s.v6(), &name, |t| *t = tbl)?;
                // The old rules' counters go back to the caller: none counted.
                let (num_counters, counters) = (u(84) as usize, u64::from_le_bytes(head[88..96].try_into().unwrap()));
                if counters != 0 && num_counters > 0 {
                    t.proc.mm().write(counters, &vec![0u8; num_counters.min(1 << 20) * 16])?;
                }
                Ok(0)
            }
            SO_SET_ADD_COUNTERS => Ok(0),
            _ => Err(ENOPROTOOPT),
        }
    }
}


//! The name server guests are told of, at 10.0.2.3:53: answered here, from the host's
//! own resolver. That honours the host's hosts file, split DNS and VPNs, works the same
//! on every host, and needs no raw packets to a server the host may not let us reach.
//!
//! What this gives up: only A records come back. AAAA and everything else are answered
//! with nothing (there's no IPv6 route to use one by), there are no CNAME chains, TTLs
//! are made up, and any failure at all is SERVFAIL since std doesn't say which it was.
//! Answers fit in 512 bytes, so nobody has a reason to ask again over TCP.

use super::inet::Inet;
use std::collections::VecDeque;
use std::net::{Ipv4Addr, SocketAddr, ToSocketAddrs};
use std::sync::{Mutex, Weak};

pub const SERVER: [u8; 4] = [10, 0, 2, 3];
pub const PORT: u16 = 53;

const TYPE_A: u16 = 1;
const CLASS_IN: u16 = 1;
const TTL: u32 = 60;
const NOERROR: u8 = 0;
const FORMERR: u8 = 1;
const SERVFAIL: u8 = 2;
const NOTIMP: u8 = 4;

/// A slow lookup holds a thread, and they can't be cancelled.
const MAX_WORKERS: usize = 8;
/// Past this a query is lost, as a datagram can be. The resolver asks again.
const MAX_WAITING: usize = 256;

struct Question {
    id: [u8; 2],
    recursion_desired: bool,
    /// The question section, returned as it came: a resolver compares it, case included.
    raw: Vec<u8>,
    name: String,
    qtype: u16,
    qclass: u16,
}

enum Parsed {
    /// Not a query at all: nothing to answer.
    Ignore,
    Refuse([u8; 2], u8),
    Query(Question),
}

fn parse(q: &[u8]) -> Parsed {
    if q.len() < 12 {
        return Parsed::Ignore;
    }
    let id = [q[0], q[1]];
    if q[2] & 0x80 != 0 {
        return Parsed::Ignore; // a response
    }
    if q[2] & 0x78 != 0 {
        return Parsed::Refuse(id, NOTIMP); // not a standard query
    }
    if u16::from_be_bytes([q[4], q[5]]) != 1 {
        return Parsed::Refuse(id, FORMERR);
    }
    let mut name = String::new();
    let mut at = 12;
    loop {
        let Some(&len) = q.get(at) else { return Parsed::Refuse(id, FORMERR) };
        at += 1;
        if len == 0 {
            break;
        }
        // A pointer has no business in the only name there is.
        if len > 63 || at + len as usize > q.len() || name.len() + len as usize >= 255 {
            return Parsed::Refuse(id, FORMERR);
        }
        if !name.is_empty() {
            name.push('.');
        }
        for &b in &q[at..at + len as usize] {
            name.push(if b.is_ascii_graphic() { b as char } else { '\u{fffd}' });
        }
        at += len as usize;
    }
    let Some(tail) = q.get(at..at + 4) else { return Parsed::Refuse(id, FORMERR) };
    Parsed::Query(Question {
        id,
        recursion_desired: q[2] & 1 != 0,
        raw: q[12..at + 4].to_vec(),
        name,
        qtype: u16::from_be_bytes([tail[0], tail[1]]),
        qclass: u16::from_be_bytes([tail[2], tail[3]]),
    })
}

fn answer(q: &Question, rcode: u8, ips: &[Ipv4Addr]) -> Vec<u8> {
    let mut out = Vec::with_capacity(512);
    out.extend_from_slice(&q.id);
    out.push(0x80 | u8::from(q.recursion_desired)); // QR, RD as asked
    out.push(0x80 | rcode); // RA
    let fits = 512usize.saturating_sub(12 + q.raw.len()) / 16;
    let count = ips.len().min(fits);
    for n in [1, count as u16, 0, 0] {
        out.extend_from_slice(&n.to_be_bytes());
    }
    out.extend_from_slice(&q.raw);
    for ip in &ips[..count] {
        out.extend_from_slice(&[0xc0, 12]); // the name in the question
        out.extend_from_slice(&TYPE_A.to_be_bytes());
        out.extend_from_slice(&CLASS_IN.to_be_bytes());
        out.extend_from_slice(&TTL.to_be_bytes());
        out.extend_from_slice(&4u16.to_be_bytes());
        out.extend_from_slice(&ip.octets());
    }
    out
}

/// The host's own loopback is 10.0.2.2 from in here, and a guest's 127.0.0.1 is the guest.
fn guest_view(ip: Ipv4Addr) -> Ipv4Addr {
    if ip.is_loopback() { Ipv4Addr::new(10, 0, 2, 2) } else { ip }
}

fn lookup(name: &str) -> Result<Vec<Ipv4Addr>, ()> {
    if name.contains('\u{fffd}') {
        return Err(());
    }
    let mut ips = Vec::new();
    for addr in (name, 0u16).to_socket_addrs().map_err(|_| ())? {
        if let SocketAddr::V4(a) = addr {
            let ip = guest_view(*a.ip());
            if !ips.contains(&ip) {
                ips.push(ip);
            }
        }
    }
    Ok(ips)
}

struct Job {
    question: Question,
    reply_to: Weak<Inet>,
}

struct Pool {
    waiting: VecDeque<Job>,
    workers: usize,
}

static POOL: Mutex<Pool> = Mutex::new(Pool { waiting: VecDeque::new(), workers: 0 });

fn reply(to: &Weak<Inet>, message: Vec<u8>) {
    if let Some(s) = to.upgrade() {
        s.deliver(SocketAddr::from((SERVER, PORT)), message);
    }
}

/// A datagram sent to the server. Its answer arrives as one from the server.
pub fn query(data: &[u8], reply_to: Weak<Inet>) {
    let question = match parse(data) {
        Parsed::Ignore => return,
        Parsed::Refuse(id, rcode) => {
            return reply(&reply_to, [&id[..], &[0x80, 0x80 | rcode], &[0; 8]].concat());
        }
        Parsed::Query(q) => q,
    };
    if question.qtype != TYPE_A || question.qclass != CLASS_IN || question.name.is_empty() {
        return reply(&reply_to, answer(&question, NOERROR, &[]));
    }
    if question.name.eq_ignore_ascii_case("localhost") {
        return reply(&reply_to, answer(&question, NOERROR, &[Ipv4Addr::LOCALHOST]));
    }
    let mut pool = POOL.lock().unwrap();
    if pool.waiting.len() >= MAX_WAITING {
        return;
    }
    pool.waiting.push_back(Job { question, reply_to });
    if pool.workers < MAX_WORKERS {
        // The default stack: this goes through the host's resolver, which is no small thing.
        if std::thread::Builder::new().name("dns".into()).spawn(worker).is_ok() {
            pool.workers += 1;
        }
    }
}

fn worker() {
    loop {
        let job = {
            let mut pool = POOL.lock().unwrap();
            match pool.waiting.pop_front() {
                Some(job) => job,
                None => {
                    pool.workers -= 1;
                    return;
                }
            }
        };
        if job.reply_to.strong_count() == 0 {
            continue;
        }
        let q = &job.question;
        let message = match lookup(&q.name) {
            Ok(ips) => answer(q, NOERROR, &ips),
            Err(()) => answer(q, SERVFAIL, &[]),
        };
        reply(&job.reply_to, message);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn query_bytes(name: &str, qtype: u16) -> Vec<u8> {
        let mut q = vec![0xab, 0xcd, 1, 0, 0, 1, 0, 0, 0, 0, 0, 1];
        for label in name.split('.') {
            q.push(label.len() as u8);
            q.extend_from_slice(label.as_bytes());
        }
        q.push(0);
        q.extend_from_slice(&qtype.to_be_bytes());
        q.extend_from_slice(&1u16.to_be_bytes());
        q
    }

    #[test]
    fn parses_a_question_and_ignores_what_follows() {
        let mut q = query_bytes("WwW.Example.com", 1);
        let question_end = q.len();
        q.extend_from_slice(&[0, 0, 41, 2, 0, 0, 0, 0, 0, 0, 0]); // OPT
        let Parsed::Query(parsed) = parse(&q) else { panic!() };
        assert_eq!(parsed.name, "WwW.Example.com");
        assert_eq!(parsed.qtype, 1);
        assert_eq!(parsed.raw, q[12..question_end]);
    }

    #[test]
    fn answers_keep_the_id_and_question() {
        let q = query_bytes("a.example", 1);
        let Parsed::Query(parsed) = parse(&q) else { panic!() };
        let out = answer(&parsed, NOERROR, &[Ipv4Addr::new(1, 2, 3, 4)]);
        assert_eq!(out[..2], [0xab, 0xcd]);
        assert_eq!(out[2] & 0x81, 0x81);
        assert_eq!(out[3] & 0xf, 0);
        assert_eq!(u16::from_be_bytes([out[6], out[7]]), 1);
        assert_eq!(out[12..12 + parsed.raw.len()], parsed.raw);
        assert_eq!(out[out.len() - 4..], [1, 2, 3, 4]);
        assert_eq!(out[12 + parsed.raw.len()..12 + parsed.raw.len() + 2], [0xc0, 12]);
    }

    #[test]
    fn answers_fit_in_a_datagram_without_edns() {
        let q = query_bytes("a.example", 1);
        let Parsed::Query(parsed) = parse(&q) else { panic!() };
        let many = vec![Ipv4Addr::new(1, 2, 3, 4); 100];
        let out = answer(&parsed, NOERROR, &many);
        assert!(out.len() <= 512);
        assert_eq!(out[2] & 2, 0, "never truncated");
        let count = u16::from_be_bytes([out[6], out[7]]) as usize;
        assert_eq!(out.len(), 12 + parsed.raw.len() + count * 16);
    }

    #[test]
    fn refuses_what_it_cannot_read() {
        assert!(matches!(parse(&[0; 4]), Parsed::Ignore));
        let mut response = query_bytes("a", 1);
        response[2] |= 0x80;
        assert!(matches!(parse(&response), Parsed::Ignore));
        let mut pointer = query_bytes("a", 1);
        pointer[12] = 0xc0;
        assert!(matches!(parse(&pointer), Parsed::Refuse(_, FORMERR)));
        let mut cut = query_bytes("a.example", 1);
        cut.truncate(cut.len() - 2);
        assert!(matches!(parse(&cut), Parsed::Refuse(_, FORMERR)));
    }

    #[test]
    fn a_name_for_the_hosts_loopback_is_its_alias() {
        assert_eq!(guest_view(Ipv4Addr::new(127, 0, 0, 1)), Ipv4Addr::new(10, 0, 2, 2));
        assert_eq!(guest_view(Ipv4Addr::new(8, 8, 8, 8)), Ipv4Addr::new(8, 8, 8, 8));
    }
}

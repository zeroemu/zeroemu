//! Credentials and capabilities: real/effective/saved/fs ids, supplementary
//! groups, the five capability sets and securebits, with Linux's rules for
//! how id changes and execve transform them (kernel/sys.c, kernel/groups.c,
//! kernel/capability.c, security/commoncap.c). Identity bookkeeping only:
//! file access stays permissive. Kept per process rather than per thread
//! (bionic, unlike glibc, never relies on per-thread credentials).

use super::{Kernel, Thread};
use crate::arch::Sysno;
use crate::errno::*;
use crate::vfs::{S_IFDIR, S_IFMT, Stat};
use std::sync::Arc;

pub const CAP_LAST_CAP: u32 = 40;
pub const CAP_ALL: u64 = (1 << (CAP_LAST_CAP + 1)) - 1;
pub const CAP_KILL: u32 = 5;
pub const CAP_SETGID: u32 = 6;
pub const CAP_SETUID: u32 = 7;
pub const CAP_SETPCAP: u32 = 8;
pub const CAP_NET_BIND_SERVICE: u32 = 10;
pub const CAP_NET_ADMIN: u32 = 12;
pub const CAP_NET_RAW: u32 = 13;
pub const CAP_SYS_PTRACE: u32 = 19;
pub const CAP_SYS_ADMIN: u32 = 21;
pub const CAP_SYS_BOOT: u32 = 22;
pub const CAP_SYS_NICE: u32 = 23;
pub const CAP_SYS_RESOURCE: u32 = 24;
/// What follows fsuid changes: CHOWN, DAC_OVERRIDE, DAC_READ_SEARCH, FOWNER,
/// FSETID, LINUX_IMMUTABLE, MKNOD, MAC_OVERRIDE.
const CAP_FS_SET: u64 = 0x1f | 1 << 9 | 1 << 27 | 1 << 32;

const SECURE_NOROOT: u32 = 1 << 0;
const SECURE_NO_SETUID_FIXUP: u32 = 1 << 2;
const SECURE_KEEP_CAPS: u32 = 1 << 4;
const SECURE_KEEP_CAPS_LOCKED: u32 = 1 << 5;
const SECURE_NO_CAP_AMBIENT_RAISE: u32 = 1 << 6;
const SECURE_ALL_BITS: u64 = 0x55;
const SECURE_ALL_LOCKS: u64 = 0xaa;

const CAP_V1: u32 = 0x1998_0330;
const CAP_V2: u32 = 0x2007_1026;
const CAP_V3: u32 = 0x2008_0522;
const NGROUPS_MAX: u64 = 65536;
/// (uid_t)-1: "unchanged" for set*id, never a valid id.
const NO_ID: u32 = u32::MAX;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Creds {
    pub uid: u32,
    pub euid: u32,
    pub suid: u32,
    pub fsuid: u32,
    pub gid: u32,
    pub egid: u32,
    pub sgid: u32,
    pub fsgid: u32,
    /// Sorted, as Linux keeps them.
    pub groups: Vec<u32>,
    pub inh: u64,
    pub prm: u64,
    pub eff: u64,
    pub bnd: u64,
    pub amb: u64,
    pub securebits: u32,
}

impl Creds {
    /// The first process: root with every capability.
    pub fn root() -> Creds {
        Creds { uid: 0, euid: 0, suid: 0, fsuid: 0, gid: 0, egid: 0, sgid: 0, fsgid: 0, groups: Vec::new(), inh: 0, prm: CAP_ALL, eff: CAP_ALL, bnd: CAP_ALL, amb: 0, securebits: 0 }
    }

    pub fn capable(&self, cap: u32) -> bool {
        self.eff & 1 << cap != 0
    }

    /// access(2) for a file with attributes `st`; `want` is R_OK|W_OK|X_OK. Unlike
    /// open, it asks about the real ids, whose only capabilities are root's,
    /// unless `effective` (AT_EACCESS).
    pub fn may_access(&self, st: &Stat, want: u32, effective: bool) -> bool {
        const NO_SETUID_FIXUP: u32 = 1 << 2;
        const DAC_OVERRIDE: u64 = 1 << 1;
        const DAC_READ_SEARCH: u64 = 1 << 2;
        let (uid, gid, caps) = if effective {
            (self.fsuid, self.fsgid, self.eff)
        } else if self.secure(NO_SETUID_FIXUP) {
            (self.uid, self.gid, self.eff)
        } else {
            (self.uid, self.gid, if self.uid == 0 { self.prm } else { 0 })
        };
        let class = if st.uid == uid {
            st.mode >> 6
        } else if st.gid == gid || self.groups.contains(&st.gid) {
            st.mode >> 3
        } else {
            st.mode
        };
        if want & !class & 7 == 0 {
            return true;
        }
        let dir = st.mode & S_IFMT == S_IFDIR;
        // Even DAC_OVERRIDE only runs what something could run.
        if caps & DAC_OVERRIDE != 0 && (want & 1 == 0 || dir || st.mode & 0o111 != 0) {
            return true;
        }
        caps & DAC_READ_SEARCH != 0 && want & !(4 | if dir { 1 } else { 0 }) == 0
    }

    fn secure(&self, bit: u32) -> bool {
        self.securebits & bit != 0
    }

    /// execve of a file without capabilities or set-id bits: root gets its
    /// bounding set back (unless SECBIT_NOROOT), everyone else keeps only
    /// the ambient set (cap_bprm_creds_from_file).
    pub fn exec(&mut self) {
        let root = !self.secure(SECURE_NOROOT);
        let prm = if root && (self.euid == 0 || self.uid == 0) { self.bnd | self.inh } else { 0 };
        self.suid = self.euid;
        self.fsuid = self.euid;
        self.sgid = self.egid;
        self.fsgid = self.egid;
        self.prm = prm | self.amb;
        self.eff = if root && self.euid == 0 { self.prm } else { self.amb };
        self.securebits &= !SECURE_KEEP_CAPS;
    }

    /// What a [res]uid change does to the capability sets (cap_emulate_setxuid).
    fn fix_setuid(&mut self, old: &Creds) {
        if self.secure(SECURE_NO_SETUID_FIXUP) {
            return;
        }
        let had_root = old.uid == 0 || old.euid == 0 || old.suid == 0;
        if had_root && self.uid != 0 && self.euid != 0 && self.suid != 0 {
            if !self.secure(SECURE_KEEP_CAPS) {
                self.prm = 0;
                self.eff = 0;
            }
            self.amb = 0;
        }
        if old.euid == 0 && self.euid != 0 {
            self.eff = 0;
        }
        if old.euid != 0 && self.euid == 0 {
            self.eff = self.prm;
        }
    }

    fn fix_setfsuid(&mut self, old: &Creds) {
        if self.secure(SECURE_NO_SETUID_FIXUP) {
            return;
        }
        if old.fsuid == 0 && self.fsuid != 0 {
            self.eff &= !CAP_FS_SET;
        }
        if old.fsuid != 0 && self.fsuid == 0 {
            self.eff |= self.prm & CAP_FS_SET;
        }
    }

    /// Whether these credentials may signal a process holding `target`.
    pub fn may_kill(&self, target: &Creds) -> bool {
        [self.euid, self.uid].iter().any(|&u| u == target.suid || u == target.uid) || self.capable(CAP_KILL)
    }

    /// __ptrace_may_access with PTRACE_MODE_REALCREDS: our real uid and gid
    /// equal all three of the target's user ids and all three of its group ids.
    pub fn same_real_ids(&self, target: &Creds) -> bool {
        [target.uid, target.euid, target.suid].iter().all(|&u| u == self.uid) && [target.gid, target.egid, target.sgid].iter().all(|&g| g == self.gid)
    }

    /// cap_safe_nice: the target's permitted set must fit inside ours unless
    /// we hold CAP_SYS_NICE. setpriority, ioprio_set and the schedulers share it.
    pub fn safe_nice(&self, target: &Creds) -> bool {
        target.prm & !self.prm == 0 || self.capable(CAP_SYS_NICE)
    }
}

fn cap_valid(cap: u64) -> bool {
    cap <= CAP_LAST_CAP as u64
}

/// Syscalls served by creds.rs, control.rs and sched.rs.
pub fn handles(no: Sysno) -> bool {
    use Sysno::*;
    matches!(
        no,
        getuid | geteuid | getgid | getegid | setuid | setgid | setreuid | setregid | setresuid | setresgid | getresuid | getresgid
            | setfsuid | setfsgid | getgroups | setgroups | capget | capset | prctl | seccomp | getrlimit | setrlimit | prlimit64
            | personality | sethostname | setdomainname | reboot | process_vm_readv | process_vm_writev | setpriority | getpriority
            | sched_setscheduler | sched_getscheduler | sched_setparam | sched_getparam | sched_setattr | sched_getattr
            | sched_get_priority_max | sched_get_priority_min | sched_rr_get_interval | ioprio_set | ioprio_get | setpgid | getpgid
            | getpgrp | getsid | setsid
    )
}

impl Kernel {
    pub(super) fn creds_syscall(self: &Arc<Self>, no: Sysno, t: &Arc<Thread>, a: [u64; 6]) -> Result<i64, i64> {
        use Sysno::*;
        let id = |i: usize| a[i] as u32;
        match no {
            getuid => Ok(self.creds(t).uid as i64),
            geteuid => Ok(self.creds(t).euid as i64),
            getgid => Ok(self.creds(t).gid as i64),
            getegid => Ok(self.creds(t).egid as i64),
            getresuid | getresgid => {
                let c = self.creds(t);
                let ids = if no == getresuid { [c.uid, c.euid, c.suid] } else { [c.gid, c.egid, c.sgid] };
                let mut mm = t.proc.mm();
                for (i, v) in ids.into_iter().enumerate() {
                    mm.write_u32(a[i], v)?;
                }
                Ok(0)
            }
            setuid | setgid => self.set_id(t, no == setuid, id(0)),
            setreuid | setregid => self.set_re_id(t, no == setreuid, id(0), id(1)),
            setresuid | setresgid => self.set_res_id(t, no == setresuid, [id(0), id(1), id(2)]),
            setfsuid | setfsgid => Ok(self.set_fs_id(t, no == setfsuid, id(0)) as i64),
            getgroups => {
                let size = super::int(a[0]);
                let groups = self.creds(t).groups;
                if size < 0 {
                    return Err(EINVAL);
                }
                if size == 0 {
                    return Ok(groups.len() as i64);
                }
                if (size as usize) < groups.len() {
                    return Err(EINVAL);
                }
                let bytes: Vec<u8> = groups.iter().flat_map(|g| g.to_le_bytes()).collect();
                t.proc.mm().write(a[1], &bytes)?;
                Ok(groups.len() as i64)
            }
            setgroups => {
                let size = super::int(a[0]);
                if !self.creds(t).capable(CAP_SETGID) {
                    return Err(EPERM);
                }
                if size < 0 || size as u64 > NGROUPS_MAX {
                    return Err(EINVAL);
                }
                let raw = if size > 0 { t.proc.mm().read_vec(a[1], size as usize * 4)? } else { Vec::new() };
                let mut groups: Vec<u32> = raw.chunks(4).map(|c| u32::from_le_bytes(c.try_into().unwrap())).collect();
                groups.sort_unstable();
                t.proc.creds.lock().unwrap().groups = groups;
                Ok(0)
            }
            capget => self.capget(t, a[0], a[1]),
            capset => self.capset(t, a[0], a[1]),
            setpgid | getpgid | getpgrp | getsid | setsid => self.pgrp_syscall(no, t, a),
            n if super::sched::handles(n) => self.sched_syscall(n, t, a),
            n => self.control_syscall(n, t, a),
        }
    }

    pub(super) fn creds(&self, t: &Thread) -> Creds {
        t.proc.creds.lock().unwrap().clone()
    }

    /// commit_creds: gaining caps or changing identity makes the process
    /// non-dumpable and clears the caller's parent-death signal. The
    /// dumpable bit is stored before the new ids are published, so a
    /// process_vm reader that observes the new ids also observes it
    /// (a reader samples creds, then dumpable).
    fn commit(&self, t: &Thread, new: Creds) {
        let mut c = t.proc.creds.lock().unwrap();
        let changed = c.euid != new.euid || c.egid != new.egid || c.fsuid != new.fsuid || c.fsgid != new.fsgid || new.prm & !c.prm != 0;
        if changed {
            t.proc.attrs.lock().unwrap().dumpable = 0;
            t.attrs.lock().unwrap().pdeathsig = 0;
        }
        *c = new;
    }

    fn set_id(&self, t: &Thread, user: bool, v: u32) -> Result<i64, i64> {
        if v == NO_ID {
            return Err(EINVAL);
        }
        let old = self.creds(t);
        let mut new = old.clone();
        let (r, e, s, f) = if user { (&mut new.uid, &mut new.euid, &mut new.suid, &mut new.fsuid) } else { (&mut new.gid, &mut new.egid, &mut new.sgid, &mut new.fsgid) };
        if old.capable(if user { CAP_SETUID } else { CAP_SETGID }) {
            *r = v;
            *s = v;
        } else if v != *r && v != *s {
            return Err(EPERM);
        }
        *e = v;
        *f = v;
        if user {
            new.fix_setuid(&old);
        }
        self.commit(t, new);
        Ok(0)
    }

    fn set_re_id(&self, t: &Thread, user: bool, rv: u32, ev: u32) -> Result<i64, i64> {
        let old = self.creds(t);
        let cap = old.capable(if user { CAP_SETUID } else { CAP_SETGID });
        let mut new = old.clone();
        let (r, e, s, f) = if user { (&mut new.uid, &mut new.euid, &mut new.suid, &mut new.fsuid) } else { (&mut new.gid, &mut new.egid, &mut new.sgid, &mut new.fsgid) };
        let (or, oe, os) = (*r, *e, *s);
        if rv != NO_ID {
            if rv != or && rv != oe && !cap {
                return Err(EPERM);
            }
            *r = rv;
        }
        if ev != NO_ID {
            if ev != or && ev != oe && ev != os && !cap {
                return Err(EPERM);
            }
            *e = ev;
        }
        if rv != NO_ID || (ev != NO_ID && ev != or) {
            *s = *e;
        }
        *f = *e;
        if user {
            new.fix_setuid(&old);
        }
        self.commit(t, new);
        Ok(0)
    }

    fn set_res_id(&self, t: &Thread, user: bool, v: [u32; 3]) -> Result<i64, i64> {
        let old = self.creds(t);
        let cur = if user { [old.uid, old.euid, old.suid, old.fsuid] } else { [old.gid, old.egid, old.sgid, old.fsgid] };
        let noop = (v[0] == NO_ID || v[0] == cur[0]) && (v[1] == NO_ID || v[1] == cur[1] && v[1] == cur[3]) && (v[2] == NO_ID || v[2] == cur[2]);
        if noop {
            return Ok(0); // succeeds without privilege
        }
        let foreign = v.iter().any(|&n| n != NO_ID && !cur[..3].contains(&n));
        if foreign && !old.capable(if user { CAP_SETUID } else { CAP_SETGID }) {
            return Err(EPERM);
        }
        let mut new = old.clone();
        let ids = if user { [&mut new.uid, &mut new.euid, &mut new.suid] } else { [&mut new.gid, &mut new.egid, &mut new.sgid] };
        for (slot, &n) in ids.into_iter().zip(&v) {
            if n != NO_ID {
                *slot = n;
            }
        }
        if user {
            new.fsuid = new.euid;
            new.fix_setuid(&old);
        } else {
            new.fsgid = new.egid;
        }
        self.commit(t, new);
        Ok(0)
    }

    /// setfsuid/setfsgid return the previous value whether or not they succeed.
    fn set_fs_id(&self, t: &Thread, user: bool, v: u32) -> u32 {
        let old = self.creds(t);
        let ids = if user { [old.uid, old.euid, old.suid, old.fsuid] } else { [old.gid, old.egid, old.sgid, old.fsgid] };
        let prev = ids[3];
        if v == NO_ID || v == prev || !(ids.contains(&v) || old.capable(if user { CAP_SETUID } else { CAP_SETGID })) {
            return prev;
        }
        let mut new = old.clone();
        if user {
            new.fsuid = v;
            new.fix_setfsuid(&old);
        } else {
            new.fsgid = v;
        }
        self.commit(t, new);
        prev
    }

    /// Validates a capability header; a bad version is answered with the
    /// preferred one. Returns the number of 32-bit words per set.
    fn cap_version(&self, t: &Thread, hdr: u64) -> Result<usize, i64> {
        let mut mm = t.proc.mm();
        match mm.read_u32(hdr)? {
            CAP_V1 => Ok(1),
            CAP_V2 | CAP_V3 => Ok(2),
            _ => {
                mm.write_u32(hdr, CAP_V3)?;
                Err(EINVAL)
            }
        }
    }

    fn capget(&self, t: &Thread, hdr: u64, data: u64) -> Result<i64, i64> {
        let words = match self.cap_version(t, hdr) {
            Err(EINVAL) if data == 0 => return Ok(0), // libcap's version probe
            r => r?,
        };
        if data == 0 {
            return Ok(0);
        }
        let pid = t.proc.mm().read_u32(hdr + 4)? as i32;
        if pid < 0 {
            return Err(EINVAL);
        }
        let c = if pid == 0 || pid == t.proc.pid { self.creds(t) } else { self.live_process(pid).ok_or(ESRCH)?.creds.lock().unwrap().clone() };
        let mut out = Vec::new();
        for w in 0..words {
            for set in [c.eff, c.prm, c.inh] {
                out.extend_from_slice(&((set >> (32 * w)) as u32).to_le_bytes());
            }
        }
        t.proc.mm().write(data, &out)?;
        Ok(0)
    }

    fn capset(&self, t: &Thread, hdr: u64, data: u64) -> Result<i64, i64> {
        let words = self.cap_version(t, hdr)?;
        let pid = t.proc.mm().read_u32(hdr + 4)? as i32;
        if pid != 0 && pid != t.proc.pid {
            return Err(EPERM);
        }
        let raw = t.proc.mm().read_vec(data, words * 12)?;
        let word = |w: usize, i: usize| u32::from_le_bytes(raw[w * 12 + i * 4..w * 12 + i * 4 + 4].try_into().unwrap()) as u64;
        let set = |i: usize| (0..words).fold(0u64, |acc, w| acc | word(w, i) << (32 * w)) & CAP_ALL;
        let (eff, prm, inh) = (set(0), set(1), set(2));
        let old = self.creds(t);
        let subset = |a: u64, b: u64| a & !b == 0;
        if (!old.capable(CAP_SETPCAP) && !subset(inh, old.inh | old.prm)) || !subset(inh, old.inh | old.bnd) || !subset(prm, old.prm) || !subset(eff, prm) {
            return Err(EPERM);
        }
        let mut new = old.clone();
        new.eff = eff;
        new.prm = prm;
        new.inh = inh;
        new.amb &= prm & inh;
        self.commit(t, new);
        Ok(0)
    }

    /// The capability prctls: bounding set, ambient set, securebits, keepcaps.
    pub(super) fn cap_prctl(&self, t: &Thread, op: u64, a: [u64; 6]) -> Result<i64, i64> {
        const PR_GET_KEEPCAPS: u64 = 7;
        const PR_SET_KEEPCAPS: u64 = 8;
        const PR_CAPBSET_READ: u64 = 23;
        const PR_CAPBSET_DROP: u64 = 24;
        const PR_GET_SECUREBITS: u64 = 27;
        const PR_SET_SECUREBITS: u64 = 28;
        const PR_CAP_AMBIENT: u64 = 47;
        let old = self.creds(t);
        let mut new = old.clone();
        match op {
            PR_GET_KEEPCAPS => return Ok(old.secure(SECURE_KEEP_CAPS) as i64),
            PR_SET_KEEPCAPS => {
                if a[1] > 1 {
                    return Err(EINVAL);
                }
                if old.secure(SECURE_KEEP_CAPS_LOCKED) {
                    return Err(EPERM);
                }
                new.securebits = if a[1] == 1 { old.securebits | SECURE_KEEP_CAPS } else { old.securebits & !SECURE_KEEP_CAPS };
            }
            PR_CAPBSET_READ => return if cap_valid(a[1]) { Ok((old.bnd >> a[1] & 1) as i64) } else { Err(EINVAL) },
            PR_CAPBSET_DROP => {
                if !old.capable(CAP_SETPCAP) {
                    return Err(EPERM);
                }
                if !cap_valid(a[1]) {
                    return Err(EINVAL);
                }
                new.bnd &= !(1 << a[1]);
            }
            PR_GET_SECUREBITS => return Ok(old.securebits as i64),
            PR_SET_SECUREBITS => {
                let (cur, want) = (old.securebits as u64, a[1]);
                let locked = cur & SECURE_ALL_LOCKS;
                if (locked >> 1) & (cur ^ want) != 0 || locked & !want != 0 || want & !(SECURE_ALL_LOCKS | SECURE_ALL_BITS) != 0 || !old.capable(CAP_SETPCAP) {
                    return Err(EPERM);
                }
                new.securebits = want as u32;
            }
            PR_CAP_AMBIENT => {
                const IS_SET: u64 = 1;
                const RAISE: u64 = 2;
                const LOWER: u64 = 3;
                const CLEAR_ALL: u64 = 4;
                if a[1] == CLEAR_ALL {
                    if a[2] | a[3] | a[4] != 0 {
                        return Err(EINVAL);
                    }
                    new.amb = 0;
                } else {
                    if !cap_valid(a[2]) || a[3] | a[4] != 0 {
                        return Err(EINVAL);
                    }
                    let bit = 1u64 << a[2];
                    match a[1] {
                        IS_SET => return Ok((old.amb & bit != 0) as i64),
                        RAISE if old.prm & bit == 0 || old.inh & bit == 0 || old.secure(SECURE_NO_CAP_AMBIENT_RAISE) => return Err(EPERM),
                        RAISE => new.amb |= bit,
                        LOWER => new.amb &= !bit,
                        _ => return Err(EINVAL),
                    }
                }
            }
            _ => return Err(EINVAL),
        }
        self.commit(t, new);
        Ok(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn user(uid: u32) -> Creds {
        Creds { uid, euid: uid, suid: uid, fsuid: uid, prm: 0, eff: 0, ..Creds::root() }
    }

    #[test]
    fn leaving_root_drops_capabilities_unless_kept() {
        let root = Creds::root();
        let mut c = Creds { uid: 1000, euid: 1000, suid: 1000, ..root.clone() };
        c.fix_setuid(&root);
        assert_eq!((c.prm, c.eff, c.amb), (0, 0, 0));
        let kept = Creds { securebits: SECURE_KEEP_CAPS, amb: 1, ..root.clone() };
        let mut c = Creds { uid: 1000, euid: 1000, suid: 1000, ..kept.clone() };
        c.fix_setuid(&kept);
        assert_eq!((c.prm, c.eff, c.amb), (CAP_ALL, 0, 0));
        // only the effective uid leaves root: effective set cleared, then restored
        let mut c = Creds { euid: 1000, ..root.clone() };
        c.fix_setuid(&root);
        assert_eq!((c.prm, c.eff), (CAP_ALL, 0));
        let back = c.clone();
        c.euid = 0;
        c.fix_setuid(&back);
        assert_eq!(c.eff, CAP_ALL);
    }

    #[test]
    fn exec_recomputes_capabilities() {
        let mut root = Creds { bnd: CAP_ALL & !(1 << CAP_SYS_BOOT), ..Creds::root() };
        root.exec();
        assert_eq!((root.prm, root.eff), (CAP_ALL & !(1 << CAP_SYS_BOOT), CAP_ALL & !(1 << CAP_SYS_BOOT)));
        let mut u = Creds { inh: 1 << 10, amb: 1 << 10, prm: 1 << 10 | 1 << 12, ..user(1000) };
        u.exec();
        assert_eq!((u.prm, u.eff, u.amb), (1 << 10, 1 << 10, 1 << 10));
        let mut noroot = Creds { securebits: SECURE_NOROOT, ..Creds::root() };
        noroot.exec();
        assert_eq!((noroot.prm, noroot.eff), (0, 0));
    }

    #[test]
    fn kill_permission_follows_uids() {
        let (a, b) = (user(1000), user(1001));
        assert!(a.may_kill(&a) && !a.may_kill(&b) && Creds::root().may_kill(&b));
        assert!(Creds { euid: 1001, ..a.clone() }.may_kill(&b));
        assert!(!a.may_kill(&Creds { euid: 1000, ..b.clone() }));
    }

    #[test]
    fn ptrace_and_nice_follow_the_whole_set() {
        let attacker = user(1000);
        let mixed = Creds { euid: 1000, suid: 0, ..user(0) };
        assert!(!attacker.same_real_ids(&mixed) && attacker.same_real_ids(&attacker));
        let strong = Creds { prm: CAP_ALL, ..user(1000) };
        assert!(!attacker.safe_nice(&strong) && strong.safe_nice(&attacker) && Creds::root().safe_nice(&strong));
    }
}

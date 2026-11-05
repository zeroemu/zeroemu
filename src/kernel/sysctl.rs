//! /proc/sys: the kernel tunables Android reads and writes, with Linux's
//! defaults. Writes are validated like the kernel's proc_dointvec_minmax /
//! proc_dostring handlers and read back; nothing else consumes most of them.

use crate::errno::*;
use std::sync::{Mutex, OnceLock};

#[derive(Clone, Copy)]
enum Kind {
    /// A string of at most this many bytes.
    Str(usize),
    /// An integer in [min, max].
    Int(i64, i64),
    /// Whitespace-separated integers (printed tab-separated).
    Ints,
    /// Read-only.
    Ro,
}

use Kind::*;

const MAX: i64 = i64::MAX;
const MIN: i64 = i64::MIN;

#[cfg(target_arch = "aarch64")]
const RND_BITS: (&str, i64, i64, &str, i64, i64) = ("18", 18, 24, "11", 11, 16); // 39-bit VA, 4 KiB pages
#[cfg(not(target_arch = "aarch64"))]
const RND_BITS: (&str, i64, i64, &str, i64, i64) = ("28", 28, 32, "8", 8, 16);

/// (path under /proc/sys, default, kind). Sorted, so directories group.
const BASE: &[(&str, &str, Kind)] = &[
    ("abi/swp", "0", Int(0, 2)),
    ("fs/aio-max-nr", "65536", Int(0, MAX)),
    ("fs/aio-nr", "0", Ro),
    ("fs/epoll/max_user_watches", "1048576", Int(0, MAX)),
    ("fs/file-max", "524288", Int(0, MAX)),
    ("fs/file-nr", "1024\t0\t524288", Ro),
    ("fs/inotify/max_queued_events", "16384", Int(0, MAX)),
    ("fs/inotify/max_user_instances", "128", Int(0, MAX)),
    ("fs/inotify/max_user_watches", "65536", Int(0, MAX)),
    ("fs/lease-break-time", "45", Int(MIN, MAX)),
    ("fs/leases-enable", "1", Int(MIN, MAX)),
    ("fs/mount-max", "100000", Int(1, MAX)),
    ("fs/nr_open", "1048576", Int(64, 1 << 30)),
    ("fs/overflowgid", "65534", Int(0, 65535)),
    ("fs/overflowuid", "65534", Int(0, 65535)),
    ("fs/pipe-max-size", "1048576", Int(4096, 1 << 31)),
    ("fs/pipe-user-pages-hard", "0", Int(0, MAX)),
    ("fs/pipe-user-pages-soft", "16384", Int(0, MAX)),
    ("fs/protected_fifos", "0", Int(0, 2)),
    ("fs/protected_hardlinks", "1", Int(0, 1)),
    ("fs/protected_regular", "0", Int(0, 2)),
    ("fs/protected_symlinks", "1", Int(0, 1)),
    ("fs/suid_dumpable", "0", Int(0, 2)),
    ("kernel/bpf_stats_enabled", "0", Int(0, 1)),
    ("kernel/cap_last_cap", "40", Ro),
    ("kernel/core_pattern", "core", Str(127)),
    ("kernel/core_pipe_limit", "0", Int(MIN, MAX)),
    ("kernel/core_uses_pid", "0", Int(MIN, MAX)),
    ("kernel/ctrl-alt-del", "0", Int(MIN, MAX)),
    ("kernel/dmesg_restrict", "0", Int(0, 1)),
    ("kernel/domainname", "(none)", Str(64)),
    ("kernel/hostname", "localhost", Str(64)),
    ("kernel/hung_task_check_count", "4194304", Int(0, 4194304)),
    ("kernel/hung_task_panic", "0", Int(0, 1)),
    ("kernel/hung_task_timeout_secs", "120", Int(0, MAX)),
    ("kernel/hung_task_warnings", "10", Int(-1, MAX)),
    ("kernel/io_uring_disabled", "0", Int(0, 2)),
    ("kernel/kexec_load_disabled", "0", Int(0, 1)),
    ("kernel/kptr_restrict", "0", Int(0, 2)),
    ("kernel/modprobe", "/sbin/modprobe", Str(255)),
    ("kernel/modules_disabled", "0", Int(0, 1)),
    ("kernel/ngroups_max", "65536", Ro),
    ("kernel/osrelease", "6.6.0-droidrt", Ro),
    ("kernel/ostype", "Linux", Ro),
    ("kernel/overflowgid", "65534", Int(0, 65535)),
    ("kernel/overflowuid", "65534", Int(0, 65535)),
    ("kernel/panic", "0", Int(MIN, MAX)),
    ("kernel/panic_on_oops", "0", Int(MIN, MAX)),
    ("kernel/perf_cpu_time_max_percent", "25", Int(0, 100)),
    ("kernel/perf_event_max_sample_rate", "100000", Int(1, MAX)),
    ("kernel/perf_event_mlock_kb", "516", Int(MIN, MAX)),
    ("kernel/perf_event_paranoid", "2", Int(MIN, MAX)),
    ("kernel/pid_max", "32768", Int(301, 4194304)),
    ("kernel/printk", "4\t4\t1\t7", Ints),
    ("kernel/printk_devkmsg", "on", Str(9)),
    ("kernel/random/boot_id", "", Ro),
    ("kernel/random/entropy_avail", "256", Ro),
    ("kernel/random/poolsize", "256", Ro),
    ("kernel/random/urandom_min_reseed_secs", "60", Int(MIN, MAX)),
    ("kernel/random/uuid", "", Ro),
    ("kernel/random/write_wakeup_threshold", "256", Int(MIN, MAX)),
    ("kernel/randomize_va_space", "2", Int(0, 2)),
    ("kernel/sched_child_runs_first", "0", Int(MIN, MAX)),
    ("kernel/sched_energy_aware", "1", Int(0, 1)),
    ("kernel/sched_latency_ns", "6000000", Int(100000, 1_000_000_000)),
    ("kernel/sched_rr_timeslice_ms", "100", Int(MIN, MAX)),
    ("kernel/sched_rt_period_us", "1000000", Int(1, MAX)),
    ("kernel/sched_rt_runtime_us", "950000", Int(-1, MAX)),
    ("kernel/sched_schedstats", "0", Int(0, 1)),
    ("kernel/sched_tunable_scaling", "1", Int(0, 2)),
    ("kernel/sched_util_clamp_max", "1024", Int(0, 1024)),
    ("kernel/sched_util_clamp_min", "1024", Int(0, 1024)),
    ("kernel/sched_util_clamp_min_rt_default", "1024", Int(0, 1024)),
    ("kernel/sched_wakeup_granularity_ns", "1000000", Int(0, 1_000_000_000)),
    ("kernel/seccomp/actions_avail", "kill_process kill_thread trap errno user_notif trace log allow", Ro),
    ("kernel/shmall", "18446744073692774399", Ro),
    ("kernel/shmmax", "18446744073692774399", Ro),
    ("kernel/shmmni", "4096", Int(1, 1 << 15)),
    ("kernel/softlockup_panic", "0", Int(0, 1)),
    ("kernel/sysrq", "1", Int(MIN, MAX)),
    ("kernel/tainted", "0", Int(0, MAX)),
    ("kernel/threads-max", "62482", Int(20, 0x3fff_ffff)),
    ("kernel/unprivileged_bpf_disabled", "2", Int(0, 2)),
    ("kernel/version", "#1 SMP PREEMPT droidrt", Ro),
    ("net/core/bpf_jit_enable", "1", Int(0, 2)),
    ("net/core/bpf_jit_harden", "0", Int(0, 2)),
    ("net/core/bpf_jit_kallsyms", "0", Int(0, 1)),
    ("net/core/netdev_max_backlog", "1000", Int(MIN, MAX)),
    ("net/core/optmem_max", "20480", Int(MIN, MAX)),
    ("net/core/rmem_default", "212992", Int(0, MAX)),
    ("net/core/rmem_max", "212992", Int(0, MAX)),
    ("net/core/somaxconn", "4096", Int(0, MAX)),
    ("net/core/wmem_default", "212992", Int(0, MAX)),
    ("net/core/wmem_max", "212992", Int(0, MAX)),
    ("net/core/xfrm_acq_expires", "30", Int(MIN, MAX)),
    ("net/ipv4/conf/all/accept_redirects", "1", Int(MIN, MAX)),
    ("net/ipv4/conf/default/accept_redirects", "1", Int(MIN, MAX)),
    ("net/ipv4/fwmark_reflect", "0", Int(MIN, MAX)),
    ("net/ipv4/ip_forward", "0", Int(0, 1)),
    ("net/ipv4/ip_local_port_range", "32768\t60999", Ints),
    ("net/ipv4/ping_group_range", "1\t0", Ints),
    ("net/ipv4/tcp_default_init_rwnd", "0", Int(MIN, MAX)),
    ("net/ipv4/tcp_fwmark_accept", "0", Int(MIN, MAX)),
    ("net/ipv4/tcp_syncookies", "1", Int(MIN, MAX)),
    ("net/ipv6/conf/all/accept_redirects", "1", Int(MIN, MAX)),
    ("net/ipv6/conf/all/disable_ipv6", "0", Int(MIN, MAX)),
    ("net/ipv6/conf/default/accept_redirects", "1", Int(MIN, MAX)),
    ("net/ipv6/fwmark_reflect", "0", Int(MIN, MAX)),
    ("net/unix/max_dgram_qlen", "10", Int(MIN, MAX)),
    ("vm/compaction_proactiveness", "20", Int(0, 100)),
    ("vm/dirty_background_bytes", "0", Int(0, MAX)),
    ("vm/dirty_background_ratio", "10", Int(0, 100)),
    ("vm/dirty_bytes", "0", Int(0, MAX)),
    ("vm/dirty_expire_centisecs", "3000", Int(0, MAX)),
    ("vm/dirty_ratio", "20", Int(0, 100)),
    ("vm/dirty_writeback_centisecs", "500", Int(0, MAX)),
    ("vm/drop_caches", "0", Int(1, 4)),
    ("vm/extfrag_threshold", "500", Int(-1000, 1000)),
    ("vm/extra_free_kbytes", "0", Int(0, MAX)),
    ("vm/laptop_mode", "0", Int(MIN, MAX)),
    ("vm/max_map_count", "65530", Int(0, MAX)),
    ("vm/min_free_kbytes", "8192", Int(0, MAX)),
    ("vm/min_free_order_shift", "1", Int(MIN, MAX)),
    ("vm/mmap_min_addr", "4096", Int(0, MAX)),
    ("vm/mmap_rnd_bits", RND_BITS.0, Int(RND_BITS.1, RND_BITS.2)),
    ("vm/mmap_rnd_compat_bits", RND_BITS.3, Int(RND_BITS.4, RND_BITS.5)),
    ("vm/oom_dump_tasks", "1", Int(MIN, MAX)),
    ("vm/oom_kill_allocating_task", "0", Int(MIN, MAX)),
    ("vm/overcommit_kbytes", "0", Int(0, MAX)),
    ("vm/overcommit_memory", "1", Int(0, 2)),
    ("vm/overcommit_ratio", "50", Int(MIN, MAX)),
    ("vm/page-cluster", "3", Int(0, 31)),
    ("vm/panic_on_oom", "0", Int(0, 2)),
    ("vm/stat_interval", "1", Int(MIN, MAX)),
    ("vm/swappiness", "60", Int(0, 200)),
    ("vm/unprivileged_userfaultfd", "0", Int(0, 1)),
    ("vm/vfs_cache_pressure", "100", Int(0, MAX)),
    ("vm/watermark_boost_factor", "15000", Int(0, MAX)),
    ("vm/watermark_scale_factor", "10", Int(1, 3000)),
];

/// Per-interface IPv4 knobs (net/ipv4/conf/<iface>/), with Linux's defaults.
const IPV4_CONF: &[(&str, &str)] = &[
    ("accept_local", "0"), ("accept_redirects", "1"), ("accept_source_route", "0"), ("arp_accept", "0"),
    ("arp_announce", "0"), ("arp_filter", "0"), ("arp_ignore", "0"), ("arp_notify", "0"), ("bc_forwarding", "0"),
    ("bootp_relay", "0"), ("disable_policy", "0"), ("disable_xfrm", "0"), ("drop_gratuitous_arp", "0"),
    ("drop_unicast_in_l2_multicast", "0"), ("force_igmp_version", "0"), ("forwarding", "0"),
    ("igmpv2_unsolicited_report_interval", "10000"), ("igmpv3_unsolicited_report_interval", "1000"),
    ("ignore_routes_with_linkdown", "0"), ("log_martians", "0"), ("medium_id", "0"), ("promote_secondaries", "0"),
    ("proxy_arp", "0"), ("proxy_arp_pvlan", "0"), ("route_localnet", "0"), ("rp_filter", "0"),
    ("secure_redirects", "1"), ("send_redirects", "1"), ("shared_media", "1"), ("src_valid_mark", "0"), ("tag", "0"),
];

/// Per-interface IPv6 knobs (net/ipv6/conf/<iface>/), with Linux's defaults
/// and Android's accept_ra_rt_table.
const IPV6_CONF: &[(&str, &str)] = &[
    ("accept_dad", "1"), ("accept_ra", "1"), ("accept_ra_defrtr", "1"), ("accept_ra_from_local", "0"),
    ("accept_ra_min_hop_limit", "1"), ("accept_ra_min_lft", "0"), ("accept_ra_mtu", "1"), ("accept_ra_pinfo", "1"),
    ("accept_ra_rt_info_max_plen", "0"), ("accept_ra_rt_info_min_plen", "0"), ("accept_ra_rt_table", "0"),
    ("accept_ra_rtr_pref", "1"), ("accept_redirects", "1"), ("accept_source_route", "0"), ("accept_untracked_na", "0"),
    ("addr_gen_mode", "0"), ("autoconf", "1"), ("dad_transmits", "1"), ("disable_ipv6", "0"), ("disable_policy", "0"),
    ("drop_unicast_in_l2_multicast", "0"), ("drop_unsolicited_na", "0"), ("enhanced_dad", "1"),
    ("force_mld_version", "0"), ("force_tllao", "0"), ("forwarding", "0"), ("hop_limit", "64"),
    ("ignore_routes_with_linkdown", "0"), ("keep_addr_on_down", "0"), ("max_addresses", "16"),
    ("max_desync_factor", "600"), ("mldv1_unsolicited_report_interval", "10000"),
    ("mldv2_unsolicited_report_interval", "1000"), ("mtu", "1280"), ("ndisc_notify", "0"), ("ndisc_tclass", "0"),
    ("optimistic_dad", "0"), ("proxy_ndp", "0"), ("ra_defrtr_metric", "1024"), ("regen_max_retry", "3"),
    ("router_probe_interval", "60"), ("router_solicitation_delay", "1"), ("router_solicitation_interval", "4"),
    ("router_solicitation_max_interval", "3600"), ("router_solicitations", "-1"), ("rpl_seg_enabled", "0"),
    ("seg6_enabled", "0"), ("suppress_frag_ndisc", "1"), ("temp_prefered_lft", "86400"), ("temp_valid_lft", "604800"),
    ("use_oif_addrs_only", "0"), ("use_optimistic", "0"), ("use_tempaddr", "0"),
];

/// Neighbour-table knobs (net/ipv{4,6}/neigh/<iface>/).
const NEIGH: &[(&str, &str)] = &[
    ("anycast_delay", "100"), ("app_solicit", "0"), ("base_reachable_time", "30"), ("base_reachable_time_ms", "30000"),
    ("delay_first_probe_time", "5"), ("gc_stale_time", "60"), ("interval_probe_time_ms", "5000"), ("locktime", "100"),
    ("mcast_resolicit", "0"), ("mcast_solicit", "3"), ("proxy_delay", "80"), ("proxy_qlen", "64"),
    ("retrans_time", "100"), ("retrans_time_ms", "1000"), ("ucast_solicit", "3"), ("unres_qlen", "101"),
    ("unres_qlen_bytes", "212992"),
];

/// BASE and, for each interface (net.rs: lo) plus "all" and "default", its
/// conf and neigh knobs.
fn table() -> &'static [(&'static str, &'static str, Kind)] {
    static T: OnceLock<Vec<(&'static str, &'static str, Kind)>> = OnceLock::new();
    T.get_or_init(|| {
        let mut v = BASE.to_vec();
        let mut add = |path: String, def: &'static str, kind: Kind| {
            if !v.iter().any(|(p, _, _)| *p == path) {
                v.push((Box::leak(path.into_boxed_str()), def, kind));
            }
        };
        for iface in ["all", "default", "lo", super::net::ETH] {
            for (key, def) in IPV4_CONF {
                add(format!("net/ipv4/conf/{iface}/{key}"), def, Int(MIN, MAX));
            }
            add(format!("net/ipv4/conf/{iface}/mc_forwarding"), "0", Ro);
            for (key, def) in IPV6_CONF {
                let def = match (iface, *key) {
                    ("lo", "mtu") => "65536",
                    ("lo", "use_tempaddr") => "-1",
                    _ => def,
                };
                add(format!("net/ipv6/conf/{iface}/{key}"), def, Int(MIN, MAX));
            }
            add(format!("net/ipv6/conf/{iface}/mc_forwarding"), "0", Ro);
            add(format!("net/ipv6/conf/{iface}/stable_secret"), "", Str(64));
        }
        for proto in ["ipv4", "ipv6"] {
            for iface in ["default", "lo", super::net::ETH] {
                for (key, def) in NEIGH {
                    add(format!("net/{proto}/neigh/{iface}/{key}"), def, Int(MIN, MAX));
                }
            }
            for (key, def) in [("gc_interval", "30"), ("gc_thresh1", "128"), ("gc_thresh2", "512"), ("gc_thresh3", "1024")] {
                add(format!("net/{proto}/neigh/default/{key}"), def, Int(MIN, MAX));
            }
        }
        v
    })
}

/// A node of the /proc/sys tree: an entry of table(), or a directory (an
/// index past table() into `dirs()`; the first is /proc/sys itself).
pub enum Entry {
    Dir(Vec<(String, u16)>),
    File(String),
}

/// Every directory, as a path under /proc/sys ("" first).
fn dirs() -> &'static [String] {
    static DIRS: OnceLock<Vec<String>> = OnceLock::new();
    DIRS.get_or_init(|| {
        let mut v = vec![String::new()];
        for (path, _, _) in table() {
            let mut p = *path;
            while let Some((d, _)) = p.rsplit_once('/') {
                if !v.iter().any(|x| x == d) {
                    v.push(d.to_string());
                }
                p = d;
            }
        }
        v
    })
}

fn uuid() -> String {
    let mut r = [0u8; 16];
    crate::phys::random_bytes(&mut r);
    r[6] = (r[6] & 0x0f) | 0x40; // version 4
    r[8] = (r[8] & 0x3f) | 0x80;
    let h: String = r.iter().map(|b| format!("{b:02x}")).collect();
    format!("{}-{}-{}-{}-{}", &h[0..8], &h[8..12], &h[12..16], &h[16..20], &h[20..32])
}

pub struct Sysctl {
    values: Mutex<Vec<String>>,
}

impl Sysctl {
    pub fn new() -> Sysctl {
        let boot_id = uuid();
        let values = table().iter().map(|(p, d, _)| if *p == "kernel/random/boot_id" { boot_id.clone() } else { d.to_string() }).collect();
        Sysctl { values: Mutex::new(values) }
    }

    /// The root directory's index (/proc/sys).
    pub fn root() -> u16 {
        table().len() as u16
    }

    pub fn entry(&self, idx: u16) -> Option<Entry> {
        let i = idx as usize;
        if let Some((path, _, _)) = table().get(i) {
            return Some(Entry::File(match *path {
                "kernel/random/uuid" => uuid(),
                _ => self.values.lock().unwrap()[i].clone(),
            }));
        }
        let dir = dirs().get(i - table().len())?;
        let prefix = if dir.is_empty() { String::new() } else { format!("{dir}/") };
        let mut out: Vec<(String, u16)> = Vec::new();
        let names = table().iter().map(|(p, _, _)| p.to_string()).enumerate().chain(dirs().iter().cloned().enumerate().map(|(j, d)| (j + table().len(), d)));
        for (j, p) in names {
            if let Some(name) = p.strip_prefix(&prefix).filter(|n| !n.is_empty() && !n.contains('/')) {
                out.push((name.to_string(), j as u16));
            }
        }
        out.sort();
        Some(Entry::Dir(out))
    }

    pub fn parent(idx: u16) -> u16 {
        let path = match table().get(idx as usize) {
            Some((p, _, _)) => p.to_string(),
            None => dirs().get(idx as usize - table().len()).cloned().unwrap_or_default(),
        };
        let parent = path.rsplit_once('/').map_or("", |(d, _)| d);
        (dirs().iter().position(|d| d == parent).unwrap_or(0) + table().len()) as u16
    }

    pub fn writable(idx: u16) -> bool {
        table().get(idx as usize).is_some_and(|(_, _, k)| !matches!(k, Ro))
    }

    /// One write(2): the new value, validated like the kernel's handlers.
    pub fn write(&self, idx: u16, data: &[u8]) -> Result<usize, i64> {
        let (_, _, kind) = table().get(idx as usize).ok_or(EINVAL)?;
        let text = String::from_utf8_lossy(data);
        let value = match kind {
            Ro => return Err(EINVAL),
            // proc_dostring: up to the first newline, truncated to the maximum.
            Str(max) => {
                let s = text.split('\n').next().unwrap_or("");
                s.chars().scan(0, |n, c| {
                    *n += c.len_utf8();
                    (*n <= *max).then_some(c)
                }).collect()
            }
            Int(min, max) => {
                let v: i64 = text.trim().parse().map_err(|_| EINVAL)?;
                if v < *min || v > *max {
                    return Err(EINVAL);
                }
                v.to_string()
            }
            Ints => {
                let v: Vec<i64> = text.split_whitespace().map(|w| w.parse().map_err(|_| EINVAL)).collect::<Result<_, _>>()?;
                if v.is_empty() {
                    return Err(EINVAL);
                }
                v.iter().map(|n| n.to_string()).collect::<Vec<_>>().join("\t")
            }
        };
        let value = match table()[idx as usize].0 {
            // Rounded up to a power-of-two number of pages, as pipes are sized.
            "fs/pipe-max-size" => (value.parse::<u64>().unwrap_or(4096).max(4096).next_power_of_two()).to_string(),
            _ => value,
        };
        self.values.lock().unwrap()[idx as usize] = value;
        Ok(data.len())
    }

    pub fn get(&self, path: &str) -> String {
        table().iter().position(|(p, _, _)| *p == path).map(|i| self.values.lock().unwrap()[i].clone()).unwrap_or_default()
    }

    /// Stores a value the kernel itself sets (sethostname, setdomainname), unvalidated.
    pub fn set(&self, path: &str, value: String) {
        if let Some(i) = table().iter().position(|(p, _, _)| *p == path) {
            self.values.lock().unwrap()[i] = value;
        }
    }

    /// /proc/sys/fs/pipe-max-size: what an unprivileged F_SETPIPE_SZ may ask for.
    pub fn pipe_max_size(&self) -> usize {
        self.get("fs/pipe-max-size").parse().unwrap_or(1 << 20)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sysctl_tree_and_writes() {
        let s = Sysctl::new();
        let Some(Entry::Dir(top)) = s.entry(Sysctl::root()) else { panic!() };
        let names: Vec<&str> = top.iter().map(|(n, _)| n.as_str()).collect();
        assert!(names.contains(&"kernel") && names.contains(&"vm") && names.contains(&"fs") && names.contains(&"net"));
        let kernel = top.iter().find(|(n, _)| n == "kernel").unwrap().1;
        assert_eq!(Sysctl::parent(kernel), Sysctl::root());
        let Some(Entry::Dir(k)) = s.entry(kernel) else { panic!() };
        let kptr = k.iter().find(|(n, _)| n == "kptr_restrict").unwrap().1;
        assert_eq!(Sysctl::parent(kptr), kernel);
        // init's SetKptrRestrictAction: 4 and 3 are refused, 2 sticks.
        assert_eq!(s.write(kptr, b"4\n"), Err(EINVAL));
        assert_eq!(s.write(kptr, b"2\n"), Ok(2));
        assert!(matches!(s.entry(kptr), Some(Entry::File(v)) if v == "2"));
        let host = k.iter().find(|(n, _)| n == "hostname").unwrap().1;
        s.write(host, b"droid\n").unwrap();
        assert_eq!(s.get("kernel/hostname"), "droid");
        let osrel = k.iter().find(|(n, _)| n == "osrelease").unwrap().1;
        assert!(!Sysctl::writable(osrel));
        let fs = top.iter().find(|(n, _)| n == "fs").unwrap().1;
        let Some(Entry::Dir(f)) = s.entry(fs) else { panic!() };
        let pms = f.iter().find(|(n, _)| n == "pipe-max-size").unwrap().1;
        s.write(pms, b"100000").unwrap();
        assert_eq!(s.pipe_max_size(), 131072);
    }
}

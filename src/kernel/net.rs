//! The network interfaces droidrt shows: loopback, the TUN devices programs
//! create (system_server's Thread network makes "thread-wpan"), and for a device on
//! the network, eth1. No packets pass through any of them: guest sockets are
//! connected to host sockets directly, and these exist so that Android believes
//! it has a network. One list feeds /sys/class/net, rtnetlink (RTM_GETLINK,
//! RTM_GETADDR) and the SIOCGIF*/SIOCSIF* ioctls.
//!
//! Not eth0: the image's overlays configure that as a restricted interface, which can
//! never become the default network.

use crate::errno::*;
use crate::vfs::FileSystem;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

const ARPHRD_LOOPBACK: u16 = 772;
/// A TUN device: no link-layer header.
const ARPHRD_NONE: u16 = 0xfffe;
const ARPHRD_ETHER: u16 = 1;
const IFF_UP: u32 = 0x1;
const IFF_BROADCAST: u32 = 0x2;
const IFF_LOOPBACK: u32 = 0x8;
const IFF_POINTOPOINT: u32 = 0x10;
const IFF_RUNNING: u32 = 0x40;
const IFF_NOARP: u32 = 0x80;
const IFF_MULTICAST: u32 = 0x1000;
const IFF_LOWER_UP: u32 = 0x10000;

#[derive(Clone)]
struct Iface {
    name: String,
    index: i32,
    ty: u16,
    mtu: u32,
    flags: u32,
    mac: [u8; 6],
    /// Its IPv4 addresses and prefix lengths, the primary one first.
    ipv4: Vec<([u8; 4], u8)>,
}

/// The network interface's name, and what a device's static configuration gives it.
pub const ETH: &str = "eth1";
pub const ETH_ADDRESS: [u8; 4] = [10, 0, 2, 15];
const ETH_MAC: [u8; 6] = [0x52, 0x54, 0, 0x12, 0x34, 0x56];

static IFACES: Mutex<Vec<Iface>> = Mutex::new(Vec::new());
static NEXT_INDEX: Mutex<i32> = Mutex::new(2);
/// eth1's address, while it's up and has one, or else 0: whether the device has a network.
static ETH_PRIMARY: AtomicU32 = AtomicU32::new(0);

/// What this device shows as the source of what it sends beyond itself, if it can.
pub fn eth_address() -> Option<[u8; 4]> {
    Some(ETH_PRIMARY.load(Ordering::Relaxed)).filter(|&ip| ip != 0).map(u32::to_be_bytes)
}

/// Whether the device has a route to anywhere but itself.
pub fn ipv4_up() -> bool {
    eth_address().is_some()
}
static SYS: OnceLock<Arc<dyn FileSystem>> = OnceLock::new();

fn lo() -> Iface {
    Iface { name: "lo".into(), index: 1, ty: ARPHRD_LOOPBACK, mtu: 65536, flags: IFF_UP | IFF_LOOPBACK | IFF_RUNNING, mac: [0; 6], ipv4: vec![([127, 0, 0, 1], 8)] }
}

/// The interfaces, `lo` first.
fn all() -> Vec<Iface> {
    let mut v = vec![lo()];
    v.extend(IFACES.lock().unwrap().iter().cloned());
    v
}

pub fn exists(name: &str) -> bool {
    by_name(name).is_some()
}

fn by_name(name: &str) -> Option<Iface> {
    all().into_iter().find(|i| i.name == name)
}

/// /sys/class/net/<name>.
fn publish_iface(sys: &dyn FileSystem, i: &Iface) {
    let put = |file: &str, value: String| super::block::put_file(sys, &format!("class/net/{}/{file}", i.name), &(value + "\n"));
    put("ifindex", i.index.to_string());
    put("iflink", i.index.to_string());
    put("type", i.ty.to_string());
    put("mtu", i.mtu.to_string());
    put("flags", format!("{:#x}", i.flags));
    let hex = |b: [u8; 6]| b.map(|x| format!("{x:02x}")).join(":");
    put("address", hex(i.mac));
    put("broadcast", hex(if i.ty == ARPHRD_ETHER { [0xff; 6] } else { [0; 6] }));
    put("addr_len", if i.ty == ARPHRD_NONE { "0" } else { "6" }.into());
    put("operstate", if i.ty == ARPHRD_LOOPBACK { "unknown" } else if i.flags & IFF_UP != 0 { "up" } else { "down" }.into());
    put("carrier", "1".into());
    put("dev_id", "0x0".into());
    put("tx_queue_len", if i.ty == ARPHRD_NONE { "500" } else { "1000" }.into());
    put("uevent", format!("INTERFACE={}\nIFINDEX={}", i.name, i.index));
}

/// `network`: the device has eth1, up and waiting for an address, before anything
/// looks: nothing needs telling that it appeared.
pub fn publish(sys: Arc<dyn FileSystem>, network: bool) {
    publish_iface(sys.as_ref(), &lo());
    if network {
        let mut next = NEXT_INDEX.lock().unwrap();
        let eth = Iface { name: ETH.into(), index: *next, ty: ARPHRD_ETHER, mtu: 1500, flags: IFF_UP | IFF_BROADCAST | IFF_RUNNING | IFF_MULTICAST, mac: ETH_MAC, ipv4: Vec::new() };
        *next += 1;
        publish_iface(sys.as_ref(), &eth);
        IFACES.lock().unwrap().push(eth);
    }
    let _ = SYS.set(sys);
}

/// TUNSETIFF: a new TUN (or TAP) interface. `name` may hold a %d to number.
pub fn add_tun(name: &str, tap: bool) -> Result<String, i64> {
    // The name becomes a directory under /sys/class/net.
    if name == "." || name == ".." || name.contains('/') {
        return Err(EINVAL);
    }
    let mut list = IFACES.lock().unwrap();
    let name = if name.is_empty() || name.contains("%d") {
        let pattern = if name.is_empty() { if tap { "tap%d" } else { "tun%d" } } else { name };
        (0..).map(|n| pattern.replace("%d", &n.to_string())).find(|n| n != "lo" && !list.iter().any(|i| &i.name == n)).unwrap()
    } else {
        if name == "lo" || list.iter().any(|i| i.name == name) {
            return Err(EBUSY);
        }
        name.to_string()
    };
    if name.len() > 15 {
        return Err(EINVAL);
    }
    let mut next = NEXT_INDEX.lock().unwrap();
    let iface = Iface {
        name: name.clone(),
        index: *next,
        ty: if tap { ARPHRD_ETHER } else { ARPHRD_NONE },
        mtu: 1500,
        flags: if tap { IFF_MULTICAST } else { IFF_POINTOPOINT | IFF_NOARP | IFF_MULTICAST },
        mac: [0; 6],
        ipv4: Vec::new(),
    };
    *next += 1;
    if let Some(sys) = SYS.get() {
        publish_iface(sys.as_ref(), &iface);
    }
    list.push(iface);
    Ok(name)
}

/// The TUN device closed: its interface goes.
pub fn remove(name: &str) {
    IFACES.lock().unwrap().retain(|i| i.name != name);
    if let Some(sys) = SYS.get() {
        super::block::remove_tree(sys.as_ref(), &format!("class/net/{name}"));
    }
}

fn attr(out: &mut Vec<u8>, ty: u16, data: &[u8]) {
    out.extend_from_slice(&(4 + data.len() as u16).to_le_bytes());
    out.extend_from_slice(&ty.to_le_bytes());
    out.extend_from_slice(data);
    out.resize(out.len().next_multiple_of(4), 0);
}

/// RTM_NEWLINK for one interface: ifinfomsg and its attributes.
fn link_payload(i: &Iface) -> Vec<u8> {
    const IFLA_ADDRESS: u16 = 1;
    const IFLA_BROADCAST: u16 = 2;
    const IFLA_IFNAME: u16 = 3;
    const IFLA_MTU: u16 = 4;
    const IFLA_TXQLEN: u16 = 13;
    const IFLA_OPERSTATE: u16 = 16;
    const IFLA_CARRIER: u16 = 33;
    let up = i.flags & IFF_UP != 0;
    let mut p = vec![0u8, 0];
    p.extend_from_slice(&i.ty.to_le_bytes());
    p.extend_from_slice(&i.index.to_le_bytes());
    p.extend_from_slice(&(i.flags | if up { IFF_LOWER_UP } else { 0 }).to_le_bytes());
    p.extend_from_slice(&0u32.to_le_bytes());
    let mut name = i.name.as_bytes().to_vec();
    name.push(0);
    attr(&mut p, IFLA_IFNAME, &name);
    attr(&mut p, IFLA_MTU, &i.mtu.to_le_bytes());
    attr(&mut p, IFLA_TXQLEN, &1000u32.to_le_bytes());
    // IF_OPER_UNKNOWN for lo (as Linux), UP / DOWN otherwise.
    attr(&mut p, IFLA_OPERSTATE, &[if i.ty == ARPHRD_LOOPBACK { 0 } else if up { 6 } else { 2 }]);
    attr(&mut p, IFLA_CARRIER, &[1]);
    if i.ty != ARPHRD_NONE {
        attr(&mut p, IFLA_ADDRESS, &i.mac);
        attr(&mut p, IFLA_BROADCAST, if i.ty == ARPHRD_ETHER { &[0xff; 6] } else { &[0; 6] });
    }
    p
}

/// RTM_GETLINK dump: every interface.
pub fn link_payloads() -> Vec<Vec<u8>> {
    all().iter().map(link_payload).collect()
}

/// RTM_NEWADDR payloads for `lo` (127.0.0.1/8, ::1/128), of `family` (0: both).
pub fn addr_payloads(family: u8) -> Vec<Vec<u8>> {
    const IFA_ADDRESS: u16 = 1;
    const IFA_LOCAL: u16 = 2;
    const IFA_LABEL: u16 = 3;
    const IFA_FLAGS: u16 = 8;
    const IFA_F_PERMANENT: u32 = 0x80;
    const RT_SCOPE_HOST: u8 = 254;
    let mut out = Vec::new();
    if family == 0 || family == 2 {
        let mut p = vec![2u8, 8, IFA_F_PERMANENT as u8, RT_SCOPE_HOST];
        p.extend_from_slice(&1u32.to_le_bytes());
        attr(&mut p, IFA_ADDRESS, &[127, 0, 0, 1]);
        attr(&mut p, IFA_LOCAL, &[127, 0, 0, 1]);
        attr(&mut p, IFA_LABEL, b"lo\0");
        attr(&mut p, IFA_FLAGS, &IFA_F_PERMANENT.to_le_bytes());
        out.push(p);
    }
    if family == 0 || family == 10 {
        let mut p = vec![10u8, 128, IFA_F_PERMANENT as u8, RT_SCOPE_HOST];
        p.extend_from_slice(&1u32.to_le_bytes());
        let mut one = [0u8; 16];
        one[15] = 1;
        attr(&mut p, IFA_ADDRESS, &one);
        attr(&mut p, IFA_FLAGS, &IFA_F_PERMANENT.to_le_bytes());
        out.push(p);
    }
    if family == 0 || family == 2 {
        out.extend(IFACES.lock().unwrap().iter().flat_map(|i| i.ipv4.iter().map(|&(ip, prefix)| address_message(i, ip, prefix))));
    }
    out
}

/// RTM_NEWADDR or RTM_DELADDR for an interface's IPv4 address. IpClient won't read one
/// without IFA_ADDRESS and IFA_FLAGS, and this is its only source for the address.
fn address_message(i: &Iface, ip: [u8; 4], prefix: u8) -> Vec<u8> {
    const IFA_ADDRESS: u16 = 1;
    const IFA_LOCAL: u16 = 2;
    const IFA_LABEL: u16 = 3;
    const IFA_BROADCAST: u16 = 4;
    const IFA_FLAGS: u16 = 8;
    const IFA_F_PERMANENT: u32 = 0x80;
    let mut p = vec![2u8, prefix, IFA_F_PERMANENT as u8, 0];
    p.extend_from_slice(&i.index.to_le_bytes());
    attr(&mut p, IFA_ADDRESS, &ip);
    attr(&mut p, IFA_LOCAL, &ip);
    let mask = u32::MAX.checked_shr(prefix as u32).unwrap_or(0);
    attr(&mut p, IFA_BROADCAST, &(u32::from_be_bytes(ip) | mask).to_be_bytes());
    let mut label = i.name.as_bytes().to_vec();
    label.push(0);
    attr(&mut p, IFA_LABEL, &label);
    attr(&mut p, IFA_FLAGS, &IFA_F_PERMANENT.to_le_bytes());
    p
}

/// What the rest of the kernel goes by: eth1's first address, if it's up.
fn refresh_eth(i: &Iface) {
    if i.name == ETH {
        let usable = if i.flags & IFF_UP != 0 { i.ipv4.first().map_or(0, |&(ip, _)| u32::from_be_bytes(ip)) } else { 0 };
        ETH_PRIMARY.store(usable, Ordering::Relaxed);
    }
}

/// Gives interface `index` another address. The message to announce, if that's news.
pub fn add_address(index: i32, ip: [u8; 4], prefix: u8) -> Result<Option<Vec<u8>>, i64> {
    let mut list = IFACES.lock().unwrap();
    let Some(i) = list.iter_mut().find(|i| i.index == index) else {
        return if index == 1 { Ok(None) } else { Err(ENODEV) };
    };
    match i.ipv4.iter_mut().find(|a| a.0 == ip) {
        Some(a) if a.1 == prefix => return Ok(None),
        Some(a) => a.1 = prefix,
        None => i.ipv4.push((ip, prefix)),
    }
    refresh_eth(i);
    Ok(Some(address_message(i, ip, prefix)))
}

/// Takes from interface `index` the first address that fits what's named, as
/// inet_rtm_deladdr does. The message to announce.
pub fn del_address(index: i32, local: Option<[u8; 4]>, network: Option<([u8; 4], u8)>) -> Result<Vec<u8>, i64> {
    let mut list = IFACES.lock().unwrap();
    let i = list.iter_mut().find(|i| i.index == index).ok_or(if index == 1 { EADDRNOTAVAIL } else { ENODEV })?;
    let fits = |&(ip, prefix): &([u8; 4], u8)| {
        local.is_none_or(|l| l == ip)
            && network.is_none_or(|(n, p)| {
                let mask = (!u32::MAX.checked_shr(p as u32).unwrap_or(0)) as u32;
                p == prefix && u32::from_be_bytes(n) & mask == u32::from_be_bytes(ip) & mask
            })
    };
    let at = i.ipv4.iter().position(fits).ok_or(EADDRNOTAVAIL)?;
    let (ip, prefix) = i.ipv4.remove(at);
    refresh_eth(i);
    Ok(address_message(i, ip, prefix))
}

/// RTM_NEWLINK or SIOCSIFFLAGS: changes the flags `change` selects, all of them if it's
/// 0, among those anyone may change. The new link message, if they moved.
pub fn set_flags(index: i32, flags: u32, change: u32) -> Option<Vec<u8>> {
    // IFF_DEBUG, NOTRAILERS, NOARP, PROMISC, ALLMULTI, MULTICAST, PORTSEL, AUTOMEDIA, DYNAMIC
    const SETTABLE: u32 = IFF_UP | 0x4 | 0x20 | 0x80 | 0x100 | 0x200 | IFF_MULTICAST | 0x2000 | 0x4000 | 0x8000;
    if flags == 0 && change == 0 {
        return None;
    }
    let change = if change == 0 { SETTABLE } else { change & SETTABLE };
    let mut list = IFACES.lock().unwrap();
    let i = list.iter_mut().find(|i| i.index == index)?;
    let mut new = (i.flags & !change) | (flags & change);
    // There's no cable to look at: running is just being up.
    new = if new & IFF_UP != 0 { new | IFF_RUNNING } else { new & !IFF_RUNNING };
    if new == i.flags {
        return None;
    }
    i.flags = new;
    refresh_eth(i);
    if let Some(sys) = SYS.get() {
        publish_iface(sys.as_ref(), i);
    }
    Some(link_payload(i))
}

/// Whether `ip` is one of this device's own addresses on an interface other than lo.
pub fn is_local_v4(ip: [u8; 4]) -> bool {
    IFACES.lock().unwrap().iter().any(|i| i.flags & IFF_UP != 0 && i.ipv4.iter().any(|a| a.0 == ip))
}

/// Addresses for SIOCGIFCONF: each interface's IPv4 address, `lo`'s first.
pub fn ipv4_addresses() -> Vec<(String, [u8; 4])> {
    all().into_iter().flat_map(|i| i.ipv4.iter().map(|&(ip, _)| (i.name.clone(), ip)).collect::<Vec<_>>()).collect()
}

/// The interface an RTM_GETLINK request names (by index, or IFLA_IFNAME).
pub fn link_requested(body: &[u8]) -> Option<Vec<u8>> {
    if body.len() < 16 {
        return None;
    }
    let index = i32::from_le_bytes(body[4..8].try_into().unwrap());
    if index != 0 {
        return all().iter().find(|i| i.index == index).map(link_payload);
    }
    let mut off = 16;
    while off + 4 <= body.len() {
        let len = u16::from_le_bytes([body[off], body[off + 1]]) as usize;
        let ty = u16::from_le_bytes([body[off + 2], body[off + 3]]);
        if len < 4 || off + len > body.len() {
            break;
        }
        if ty == 3 {
            let name = &body[off + 4..off + len];
            let end = name.iter().position(|&b| b == 0).unwrap_or(name.len());
            return by_name(&String::from_utf8_lossy(&name[..end])).as_ref().map(link_payload);
        }
        off += len.next_multiple_of(4);
    }
    None
}

/// The SIOCGIF* / SIOCSIF* ioctls on an inet socket. `req` is the caller's
/// struct ifreq (40 bytes: a name, then a union); the reply goes back in it.
pub fn ifreq_ioctl(cmd: u64, req: &mut [u8; 40]) -> Result<(), i64> {
    const SIOCGIFNAME: u64 = 0x8910;
    const SIOCGIFFLAGS: u64 = 0x8913;
    const SIOCSIFFLAGS: u64 = 0x8914;
    const SIOCGIFADDR: u64 = 0x8915;
    const SIOCSIFADDR: u64 = 0x8916;
    const SIOCGIFNETMASK: u64 = 0x891b;
    const SIOCETHTOOL: u64 = 0x8946;
    const SIOCGIFMTU: u64 = 0x8921;
    const SIOCSIFMTU: u64 = 0x8922;
    const SIOCGIFHWADDR: u64 = 0x8927;
    const SIOCGIFINDEX: u64 = 0x8933;
    if cmd == SIOCGIFNAME {
        let index = i32::from_le_bytes(req[16..20].try_into().unwrap());
        let i = all().into_iter().find(|i| i.index == index).ok_or(ENODEV)?;
        req[..16].fill(0);
        req[..i.name.len()].copy_from_slice(i.name.as_bytes());
        return Ok(());
    }
    let end = req[..16].iter().position(|&b| b == 0).unwrap_or(16);
    let name = String::from_utf8_lossy(&req[..end]).into_owned();
    let i = by_name(&name).ok_or(ENODEV)?;
    let set = |f: &dyn Fn(&mut Iface)| {
        if let Some(x) = IFACES.lock().unwrap().iter_mut().find(|x| x.name == name) {
            f(x);
            if let Some(sys) = SYS.get() {
                publish_iface(sys.as_ref(), x);
            }
        }
    };
    let u = &mut req[16..];
    match cmd {
        SIOCGIFINDEX => u[..4].copy_from_slice(&i.index.to_le_bytes()),
        SIOCGIFFLAGS => u[..2].copy_from_slice(&((i.flags & 0xffff) as u16).to_le_bytes()),
        SIOCGIFMTU => u[..4].copy_from_slice(&i.mtu.to_le_bytes()),
        SIOCGIFHWADDR => {
            u.fill(0);
            u[..2].copy_from_slice(&i.ty.to_le_bytes());
            u[2..8].copy_from_slice(&i.mac);
        }
        SIOCGIFADDR | SIOCGIFNETMASK => {
            let &(ip, prefix) = i.ipv4.first().ok_or(EADDRNOTAVAIL)?;
            u.fill(0);
            u[..2].copy_from_slice(&2u16.to_le_bytes()); // AF_INET
            let value = if cmd == SIOCGIFADDR { ip } else { (!u32::MAX.checked_shr(prefix as u32).unwrap_or(0)).to_be_bytes() };
            u[4..8].copy_from_slice(&value);
        }
        // netd clears an interface with this before configuring it.
        SIOCSIFADDR => {
            let ip: [u8; 4] = u[4..8].try_into().unwrap();
            if i.index == 1 || i.ipv4.first().is_some_and(|a| a.0 == ip) {
                return Ok(());
            }
            // 0 takes every address, and anything else replaces the primary one.
            let prefix = i.ipv4.first().map_or(24, |a| a.1);
            let gone = if ip == [0; 4] { i.ipv4.len() } else { i.ipv4.len().min(1) };
            for _ in 0..gone {
                super::netlink::announce_address(false, &del_address(i.index, None, None)?);
            }
            if ip != [0; 4]
                && let Some(message) = add_address(i.index, ip, prefix)?
            {
                super::netlink::announce_address(true, &message);
            }
        }
        // Drivers answer for themselves, and there isn't one.
        SIOCETHTOOL => return Err(EOPNOTSUPP),
        // lo stays up at its MTU; others take what they are given.
        SIOCSIFFLAGS => {
            let flags = u16::from_le_bytes([u[0], u[1]]) as u32;
            if let Some(payload) = set_flags(i.index, flags, 0xffff) {
                super::netlink::announce_link(&payload);
            }
        }
        SIOCSIFMTU => {
            let mtu = u32::from_le_bytes(u[..4].try_into().unwrap());
            if !(68..=65535).contains(&mtu) {
                return Err(EINVAL);
            }
            set(&|x| x.mtu = mtu);
        }
        _ => return Err(ENOTTY),
    }
    Ok(())
}

pub const TUN_MINOR: u32 = 200;

pub fn tun_rdev() -> u64 {
    super::block::makedev(super::block::MISC_MAJOR, TUN_MINOR)
}

/// An open /dev/tun: once TUNSETIFF names it, an interface. No packet ever
/// arrives; what is written is dropped.
pub struct Tun {
    st: Mutex<TunState>,
}

#[derive(Default)]
struct TunState {
    iface: Option<String>,
    flags: u16,
    persist: bool,
}

impl Tun {
    pub fn new() -> Tun {
        Tun { st: Mutex::new(TunState::default()) }
    }

    pub fn ioctl(&self, cmd: u64, arg: u64, io: &mut dyn super::ashmem::Io) -> Result<i64, i64> {
        const TUNSETIFF: u64 = 0x4004_54ca;
        const TUNSETPERSIST: u64 = 0x4004_54cb;
        const TUNGETFEATURES: u64 = 0x8004_54cf;
        const TUNGETIFF: u64 = 0x8004_54d2;
        const IFF_TUN: u16 = 0x1;
        const IFF_TAP: u16 = 0x2;
        /// IFF_TUN | IFF_TAP | IFF_NAPI | IFF_NAPI_FRAGS | IFF_NO_CARRIER |
        /// IFF_MULTI_QUEUE | IFF_NO_PI | IFF_ONE_QUEUE | IFF_VNET_HDR | IFF_TUN_EXCL.
        const FEATURES: u32 = 0x1 | 0x2 | 0x10 | 0x20 | 0x40 | 0x100 | 0x1000 | 0x2000 | 0x4000 | 0x8000;
        let mut st = self.st.lock().unwrap();
        match cmd {
            TUNSETIFF => {
                if st.iface.is_some() {
                    return Err(EINVAL);
                }
                let mut req = [0u8; 40];
                io.read(arg, &mut req)?;
                let flags = u16::from_le_bytes([req[16], req[17]]);
                let tap = match flags & (IFF_TUN | IFF_TAP) {
                    IFF_TUN => false,
                    IFF_TAP => true,
                    _ => return Err(EINVAL),
                };
                let end = req[..16].iter().position(|&b| b == 0).unwrap_or(16);
                let name = add_tun(&String::from_utf8_lossy(&req[..end]), tap)?;
                req[..16].fill(0);
                req[..name.len()].copy_from_slice(name.as_bytes());
                io.write(arg, &req)?;
                st.iface = Some(name);
                st.flags = flags;
                Ok(0)
            }
            TUNGETIFF => {
                let name = st.iface.clone().ok_or(EBADFD)?;
                let mut req = [0u8; 40];
                req[..name.len()].copy_from_slice(name.as_bytes());
                req[16..18].copy_from_slice(&st.flags.to_le_bytes());
                io.write(arg, &req)?;
                Ok(0)
            }
            TUNGETFEATURES => {
                io.write(arg, &FEATURES.to_le_bytes())?;
                Ok(0)
            }
            TUNSETPERSIST => {
                st.persist = arg != 0;
                Ok(0)
            }
            // Owner, group, link type, offloads, filters, buffer and header sizes.
            0x4004_54cc..=0x4004_54d8 => Ok(0),
            _ => Err(EINVAL),
        }
    }
}

impl Drop for Tun {
    fn drop(&mut self) {
        let st = self.st.get_mut().unwrap();
        if let (Some(name), false) = (&st.iface, st.persist) {
            remove(name);
        }
    }
}

//! The network interfaces droidrt shows: loopback only, as a Linux with no
//! network devices. One description of `lo` feeds /sys/class/net, rtnetlink
//! (RTM_GETLINK, RTM_GETADDR) and the SIOCGIF* ioctls on inet sockets.

use crate::errno::*;
use crate::vfs::FileSystem;

pub const LO_INDEX: i32 = 1;
const LO_NAME: &str = "lo";
const LO_MTU: u32 = 65536;
const ARPHRD_LOOPBACK: u16 = 772;
/// IFF_UP | IFF_LOOPBACK | IFF_RUNNING, and IFF_LOWER_UP (rtnetlink only).
const LO_FLAGS: u32 = 0x1 | 0x8 | 0x40;
const IFF_LOWER_UP: u32 = 0x10000;

/// /sys/class/net/lo.
pub fn publish(sys: &dyn FileSystem) {
    let put = |name: &str, value: String| super::block::put_file(sys, &format!("class/net/{LO_NAME}/{name}"), &(value + "\n"));
    put("ifindex", LO_INDEX.to_string());
    put("iflink", LO_INDEX.to_string());
    put("type", ARPHRD_LOOPBACK.to_string());
    put("mtu", LO_MTU.to_string());
    put("flags", format!("{LO_FLAGS:#x}"));
    put("address", "00:00:00:00:00:00".into());
    put("broadcast", "00:00:00:00:00:00".into());
    put("addr_len", "6".into());
    put("operstate", "unknown".into());
    put("carrier", "1".into());
    put("dev_id", "0x0".into());
    put("tx_queue_len", "1000".into());
    put("uevent", format!("INTERFACE={LO_NAME}\nIFINDEX={LO_INDEX}"));
}

fn attr(out: &mut Vec<u8>, ty: u16, data: &[u8]) {
    out.extend_from_slice(&(4 + data.len() as u16).to_le_bytes());
    out.extend_from_slice(&ty.to_le_bytes());
    out.extend_from_slice(data);
    out.resize(out.len().next_multiple_of(4), 0);
}

/// RTM_NEWLINK for `lo`: ifinfomsg and its attributes.
pub fn link_payload() -> Vec<u8> {
    const IFLA_ADDRESS: u16 = 1;
    const IFLA_BROADCAST: u16 = 2;
    const IFLA_IFNAME: u16 = 3;
    const IFLA_MTU: u16 = 4;
    const IFLA_TXQLEN: u16 = 13;
    const IFLA_OPERSTATE: u16 = 16;
    const IFLA_CARRIER: u16 = 33;
    let mut p = vec![0u8, 0];
    p.extend_from_slice(&ARPHRD_LOOPBACK.to_le_bytes());
    p.extend_from_slice(&LO_INDEX.to_le_bytes());
    p.extend_from_slice(&(LO_FLAGS | IFF_LOWER_UP).to_le_bytes());
    p.extend_from_slice(&0u32.to_le_bytes());
    attr(&mut p, IFLA_IFNAME, b"lo\0");
    attr(&mut p, IFLA_MTU, &LO_MTU.to_le_bytes());
    attr(&mut p, IFLA_TXQLEN, &1000u32.to_le_bytes());
    attr(&mut p, IFLA_OPERSTATE, &[0]); // IF_OPER_UNKNOWN, as Linux's lo
    attr(&mut p, IFLA_CARRIER, &[1]);
    attr(&mut p, IFLA_ADDRESS, &[0; 6]);
    attr(&mut p, IFLA_BROADCAST, &[0; 6]);
    p
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
        p.extend_from_slice(&(LO_INDEX as u32).to_le_bytes());
        attr(&mut p, IFA_ADDRESS, &[127, 0, 0, 1]);
        attr(&mut p, IFA_LOCAL, &[127, 0, 0, 1]);
        attr(&mut p, IFA_LABEL, b"lo\0");
        attr(&mut p, IFA_FLAGS, &IFA_F_PERMANENT.to_le_bytes());
        out.push(p);
    }
    if family == 0 || family == 10 {
        let mut p = vec![10u8, 128, IFA_F_PERMANENT as u8, RT_SCOPE_HOST];
        p.extend_from_slice(&(LO_INDEX as u32).to_le_bytes());
        let mut one = [0u8; 16];
        one[15] = 1;
        attr(&mut p, IFA_ADDRESS, &one);
        attr(&mut p, IFA_FLAGS, &IFA_F_PERMANENT.to_le_bytes());
        out.push(p);
    }
    out
}

/// Which interface an RTM_GETLINK request names: by index, or IFLA_IFNAME.
pub fn link_requested(body: &[u8]) -> bool {
    if body.len() < 16 {
        return false;
    }
    let index = i32::from_le_bytes(body[4..8].try_into().unwrap());
    if index != 0 {
        return index == LO_INDEX;
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
            return &name[..end] == LO_NAME.as_bytes();
        }
        off += len.next_multiple_of(4);
    }
    false
}

/// The SIOCGIF* / SIOCSIF* ioctls on an inet socket. `req` is the caller's
/// struct ifreq (40 bytes: a name, then a union); the reply goes back in it.
pub fn ifreq_ioctl(cmd: u64, req: &mut [u8; 40]) -> Result<(), i64> {
    const SIOCGIFNAME: u64 = 0x8910;
    const SIOCGIFFLAGS: u64 = 0x8913;
    const SIOCSIFFLAGS: u64 = 0x8914;
    const SIOCGIFADDR: u64 = 0x8915;
    const SIOCGIFMTU: u64 = 0x8921;
    const SIOCSIFMTU: u64 = 0x8922;
    const SIOCGIFHWADDR: u64 = 0x8927;
    const SIOCGIFINDEX: u64 = 0x8933;
    if cmd == SIOCGIFNAME {
        let index = i32::from_le_bytes(req[16..20].try_into().unwrap());
        if index != LO_INDEX {
            return Err(ENODEV);
        }
        req[..16].fill(0);
        req[..2].copy_from_slice(LO_NAME.as_bytes());
        return Ok(());
    }
    let end = req[..16].iter().position(|&b| b == 0).unwrap_or(16);
    if &req[..end] != LO_NAME.as_bytes() {
        return Err(ENODEV);
    }
    let u = &mut req[16..];
    match cmd {
        SIOCGIFINDEX => u[..4].copy_from_slice(&LO_INDEX.to_le_bytes()),
        SIOCGIFFLAGS => u[..2].copy_from_slice(&(LO_FLAGS as u16).to_le_bytes()),
        SIOCGIFMTU => u[..4].copy_from_slice(&LO_MTU.to_le_bytes()),
        SIOCGIFHWADDR => {
            u.fill(0);
            u[..2].copy_from_slice(&ARPHRD_LOOPBACK.to_le_bytes());
        }
        SIOCGIFADDR => {
            u.fill(0);
            u[..2].copy_from_slice(&2u16.to_le_bytes()); // AF_INET
            u[4..8].copy_from_slice(&[127, 0, 0, 1]);
        }
        SIOCSIFFLAGS | SIOCSIFMTU => {} // lo stays up, at its MTU
        _ => return Err(ENOTTY),
    }
    Ok(())
}

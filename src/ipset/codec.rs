//! Netfilter protocol encoding and decoding.
//!
//! `NetfilterRequest` is the typed request model.  Each variant encodes to
//! a `Vec<u8>` via `encode(seq)`.  Decode helpers interpret the raw bytes
//! returned by `socket::NetlinkSocket::recv_for_seq`.
//!
//! `NlBuilder` is a private wire-format builder; no caller outside this
//! module needs to construct raw netlink bytes directly.

use super::config::NftFamily;
use std::net::IpAddr;

// -- Subsystem / command constants -------------------------------------------

const NFNL_SUBSYS_IPSET: u16 = 6;
const IPSET_CMD_ADD: u16 = 9;
const IPSET_CMD_TEST: u16 = 11;
const IPSET_PROTOCOL: u8 = 6;

const NFNL_SUBSYS_NFTABLES: u16 = 10;
const NFT_MSG_NEWSETELEM: u16 = 12;
const NFT_MSG_GETSETELEM: u16 = 13;
const NFNL_MSG_BATCH_BEGIN: u16 = 16;
const NFNL_MSG_BATCH_END: u16 = 17;

const NFPROTO_INET: u8 = 1;
const NFPROTO_IPV4: u8 = 2;
const NFPROTO_ARP: u8 = 3;
const NFPROTO_NETDEV: u8 = 5;
const NFPROTO_BRIDGE: u8 = 7;
const NFPROTO_IPV6: u8 = 10;
const NFNETLINK_V0: u8 = 0;

const NLM_F_REQUEST: u16 = 0x01;
const NLM_F_ACK: u16 = 0x04;
const NLM_F_CREATE: u16 = 0x400;
const NLM_F_EXCL: u16 = 0x200;

pub(super) const NLMSG_ERROR: u16 = 0x2;

const NLA_F_NESTED: u16 = 1 << 15;
const NLA_F_NET_BYTEORDER: u16 = 1 << 14;

const IPSET_ATTR_PROTOCOL: u16 = 1;
const IPSET_ATTR_SETNAME: u16 = 2;
const IPSET_ATTR_LINENO: u16 = 9;
const IPSET_ATTR_ADT: u16 = 8;
const IPSET_ATTR_DATA: u16 = 7;
const IPSET_ATTR_IP: u16 = 1;
const IPSET_ATTR_IPADDR_IPV4: u16 = 1;
const IPSET_ATTR_IPADDR_IPV6: u16 = 2;
const IPSET_ERR_EXIST: i32 = 4103;

const NFTA_SET_ELEM_LIST_TABLE: u16 = 1;
const NFTA_SET_ELEM_LIST_SET: u16 = 2;
const NFTA_SET_ELEM_LIST_ELEMENTS: u16 = 3;
const NFTA_LIST_ELEM: u16 = 1;
const NFTA_SET_ELEM_KEY: u16 = 1;
const NFTA_SET_ELEM_FLAGS: u16 = 3;
const NFTA_DATA_VALUE: u16 = 1;
const NFT_SET_ELEM_INTERVAL_END: u32 = 1;

// -- Typed request model -----------------------------------------------------

/// A typed netfilter request that knows how to encode itself into wire bytes.
pub(super) enum NetfilterRequest<'a> {
    IpsetTest {
        name: &'a str,
        ip: IpAddr,
    },
    /// All IPs in `ips` must belong to the same address family.
    IpsetAddBatch {
        name: &'a str,
        ips: &'a [IpAddr],
    },
    NftSetTest {
        family: NftFamily,
        table: &'a str,
        set: &'a str,
        ip: IpAddr,
    },
    NftSetAdd {
        family: NftFamily,
        table: &'a str,
        set: &'a str,
        ips: &'a [IpAddr],
    },
}

impl<'a> NetfilterRequest<'a> {
    /// Encode this request into wire-format bytes with `seq` stamped into the
    /// nlmsg header.  For nftset add, the returned buffer contains the
    /// BATCH_BEGIN + data + BATCH_END messages concatenated.
    pub(super) fn encode(&self, seq: u32) -> Vec<u8> {
        match *self {
            Self::IpsetTest { name, ip } => encode_ipset_test(name, ip, seq),
            Self::IpsetAddBatch { name, ips } => encode_ipset_add_batch(name, ips, seq),
            Self::NftSetTest {
                family,
                table,
                set,
                ip,
            } => encode_nftset_test(family, table, set, ip, seq),
            Self::NftSetAdd {
                family,
                table,
                set,
                ips,
            } => encode_nftset_add(family, table, set, ips, seq),
        }
    }
}

// -- Encode helpers ----------------------------------------------------------

fn encode_ipset_test(name: &str, ip: IpAddr, seq: u32) -> Vec<u8> {
    let mut msg = NlBuilder::new(
        ipset_msg_type(IPSET_CMD_TEST),
        NLM_F_REQUEST,
        ip_family(ip),
        0,
    );
    msg.set_seq(seq);
    msg.attr(IPSET_ATTR_PROTOCOL, &[IPSET_PROTOCOL]);
    msg.attr_nul(IPSET_ATTR_SETNAME, name);
    ipset_elem(&mut msg, ip);
    msg.buf
}

fn encode_ipset_add_batch(name: &str, ips: &[IpAddr], seq: u32) -> Vec<u8> {
    assert!(!ips.is_empty());
    let family = ip_family(ips[0]);
    let mut msg = NlBuilder::new(
        ipset_msg_type(IPSET_CMD_ADD),
        NLM_F_REQUEST | NLM_F_ACK,
        family,
        0,
    );
    msg.set_seq(seq);
    msg.attr(IPSET_ATTR_PROTOCOL, &[IPSET_PROTOCOL]);
    msg.attr_nul(IPSET_ATTR_SETNAME, name);
    msg.attr(IPSET_ATTR_LINENO, &0u32.to_ne_bytes());
    msg.nest(IPSET_ATTR_ADT, |msg| {
        for &ip in ips {
            ipset_elem(msg, ip);
        }
    });
    msg.buf
}

fn encode_nftset_test(family: NftFamily, table: &str, set: &str, ip: IpAddr, seq: u32) -> Vec<u8> {
    let mut msg = NlBuilder::new(
        nft_msg_type(NFT_MSG_GETSETELEM),
        NLM_F_REQUEST,
        nft_family_code(family),
        0,
    );
    msg.set_seq(seq);
    msg.attr_nul(NFTA_SET_ELEM_LIST_TABLE, table);
    msg.attr_nul(NFTA_SET_ELEM_LIST_SET, set);
    msg.nest(NFTA_SET_ELEM_LIST_ELEMENTS, |msg| {
        msg.nest(NFTA_LIST_ELEM, |msg| {
            msg.nest(NFTA_SET_ELEM_KEY, |msg| {
                msg.attr_ip(NFTA_DATA_VALUE | NLA_F_NET_BYTEORDER, ip);
            });
        });
    });
    msg.buf
}

fn encode_nftset_add(
    family: NftFamily,
    table: &str,
    set: &str,
    ips: &[IpAddr],
    seq: u32,
) -> Vec<u8> {
    let mut buf = Vec::new();

    let mut begin = NlBuilder::batch(NFNL_MSG_BATCH_BEGIN);
    begin.set_seq(seq);
    buf.extend_from_slice(&begin.buf);

    let mut msg = NlBuilder::new(
        nft_msg_type(NFT_MSG_NEWSETELEM),
        NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL,
        nft_family_code(family),
        0,
    );
    msg.set_seq(seq);
    msg.attr_nul(NFTA_SET_ELEM_LIST_TABLE, table);
    msg.attr_nul(NFTA_SET_ELEM_LIST_SET, set);
    msg.nest(NFTA_SET_ELEM_LIST_ELEMENTS, |msg| {
        for &ip in ips {
            nft_interval_elem(msg, ip, false);
            nft_interval_elem(msg, ip_next(ip), true);
        }
    });
    buf.extend_from_slice(&msg.buf);

    let mut end = NlBuilder::batch(NFNL_MSG_BATCH_END);
    end.set_seq(seq);
    buf.extend_from_slice(&end.buf);

    buf
}

// -- Decode helpers ----------------------------------------------------------

/// Interpret a response to an ipset TEST command.
/// Returns `true` when the IP is present in the set.
pub(super) fn decode_ipset_test(msg_type: u16, data: &[u8]) -> bool {
    match nlmsg_errno(msg_type, data) {
        Some(0) | None => true,
        Some(code) if code.abs() == IPSET_ERR_EXIST => false,
        Some(_) => false,
    }
}

/// Interpret a response to an nftset GET-ELEM command.
/// Returns `true` when the element was found.
pub(super) fn decode_nft_test(msg_type: u16) -> bool {
    msg_type == nft_msg_type(NFT_MSG_NEWSETELEM)
}

/// Check an ACK response, treating EEXIST / IPSET_ERR_EXIST as success.
/// Used for add operations where the IP may already be present.
pub(super) fn decode_ack_ok_or_exists(msg_type: u16, data: &[u8]) -> anyhow::Result<()> {
    match nlmsg_errno(msg_type, data) {
        Some(0) | None => Ok(()),
        Some(code) if code.abs() == IPSET_ERR_EXIST || code.abs() == libc::EEXIST => Ok(()),
        Some(code) => Err(anyhow::anyhow!("netlink error: {code}")),
    }
}

// -- Wire-format helpers (private) -------------------------------------------

fn nlmsg_errno(msg_type: u16, data: &[u8]) -> Option<i32> {
    if msg_type != NLMSG_ERROR || data.len() < 20 {
        return None;
    }
    // NLMSG_ERROR payload: i32 error code at byte 16 (after 16-byte nlmsghdr).
    Some(i32::from_ne_bytes(data[16..20].try_into().ok()?))
}

fn ipset_elem(msg: &mut NlBuilder, ip: IpAddr) {
    msg.nest(IPSET_ATTR_DATA, |msg| {
        msg.nest(IPSET_ATTR_IP, |msg| {
            let attr = match ip {
                IpAddr::V4(_) => IPSET_ATTR_IPADDR_IPV4,
                IpAddr::V6(_) => IPSET_ATTR_IPADDR_IPV6,
            };
            msg.attr_ip(attr | NLA_F_NET_BYTEORDER, ip);
        });
    });
}

fn nft_interval_elem(msg: &mut NlBuilder, ip: IpAddr, end: bool) {
    msg.nest(NFTA_LIST_ELEM, |msg| {
        if end {
            msg.attr(
                NFTA_SET_ELEM_FLAGS,
                &NFT_SET_ELEM_INTERVAL_END.to_be_bytes(),
            );
        }
        msg.nest(NFTA_SET_ELEM_KEY, |msg| {
            msg.attr_ip(NFTA_DATA_VALUE | NLA_F_NET_BYTEORDER, ip);
        });
    });
}

pub(super) fn ip_family(ip: IpAddr) -> u8 {
    match ip {
        IpAddr::V4(_) => libc::AF_INET as u8,
        IpAddr::V6(_) => libc::AF_INET6 as u8,
    }
}

pub(super) fn nft_family_code(family: NftFamily) -> u8 {
    match family {
        NftFamily::Inet => NFPROTO_INET,
        NftFamily::Ip => NFPROTO_IPV4,
        NftFamily::Ip6 => NFPROTO_IPV6,
        NftFamily::Arp => NFPROTO_ARP,
        NftFamily::Bridge => NFPROTO_BRIDGE,
        NftFamily::Netdev => NFPROTO_NETDEV,
    }
}

pub(super) fn ip_next(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(ip) => IpAddr::V4(u32::from(ip).wrapping_add(1).into()),
        IpAddr::V6(ip) => IpAddr::V6(u128::from(ip).wrapping_add(1).into()),
    }
}

fn ipset_msg_type(cmd: u16) -> u16 {
    (NFNL_SUBSYS_IPSET << 8) | cmd
}

fn nft_msg_type(cmd: u16) -> u16 {
    (NFNL_SUBSYS_NFTABLES << 8) | cmd
}

// -- NlBuilder (private wire-format builder) ---------------------------------

struct NlBuilder {
    buf: Vec<u8>,
}

impl NlBuilder {
    fn new(msg_type: u16, flags: u16, family: u8, res_id: u16) -> Self {
        // 16-byte nlmsghdr + 4-byte nfgenmsg = 20 bytes total fixed header.
        let mut buf = vec![0u8; 20];
        buf[4..6].copy_from_slice(&msg_type.to_ne_bytes()); // nlmsg_type
        buf[6..8].copy_from_slice(&flags.to_ne_bytes()); // nlmsg_flags
                                                         // buf[8..12] = nlmsg_seq  (set via set_seq)
                                                         // buf[12..16] = nlmsg_pid (left 0 — kernel echoes it in responses)
        buf[16] = family; // nfgenmsg.nfgen_family
        buf[17] = NFNETLINK_V0; // nfgenmsg.version
        buf[18..20].copy_from_slice(&res_id.to_be_bytes()); // nfgenmsg.res_id
        let mut out = Self { buf };
        out.finish_len();
        out
    }

    fn batch(msg_type: u16) -> Self {
        Self::new(
            msg_type,
            NLM_F_REQUEST,
            libc::AF_UNSPEC as u8,
            NFNL_SUBSYS_NFTABLES,
        )
    }

    fn set_seq(&mut self, seq: u32) {
        self.buf[8..12].copy_from_slice(&seq.to_ne_bytes());
    }

    fn attr(&mut self, kind: u16, data: &[u8]) {
        let len = 4 + data.len();
        self.buf.extend_from_slice(&(len as u16).to_ne_bytes());
        self.buf.extend_from_slice(&kind.to_ne_bytes());
        self.buf.extend_from_slice(data);
        self.pad_to_4();
        self.finish_len();
    }

    fn attr_ip(&mut self, kind: u16, ip: IpAddr) {
        match ip {
            IpAddr::V4(ip) => self.attr(kind, &ip.octets()),
            IpAddr::V6(ip) => self.attr(kind, &ip.octets()),
        }
    }

    fn attr_nul(&mut self, kind: u16, value: &str) {
        let bytes = value.as_bytes();
        let len = (4 + bytes.len() + 1) as u16;
        self.buf.extend_from_slice(&len.to_ne_bytes());
        self.buf.extend_from_slice(&kind.to_ne_bytes());
        self.buf.extend_from_slice(bytes);
        self.buf.push(0);
        self.pad_to_4();
        self.finish_len();
    }

    fn nest(&mut self, kind: u16, f: impl FnOnce(&mut Self)) {
        let start = self.buf.len();
        self.buf.extend_from_slice(&0u16.to_ne_bytes());
        self.buf
            .extend_from_slice(&(kind | NLA_F_NESTED).to_ne_bytes());
        f(self);
        let len = (self.buf.len() - start) as u16;
        self.buf[start..start + 2].copy_from_slice(&len.to_ne_bytes());
        self.pad_to_4();
        self.finish_len();
    }

    fn finish_len(&mut self) {
        let len = self.buf.len() as u32;
        self.buf[0..4].copy_from_slice(&len.to_ne_bytes());
    }

    fn pad_to_4(&mut self) {
        while !self.buf.len().is_multiple_of(4) {
            self.buf.push(0);
        }
    }
}

//! Netfilter protocol encoding and decoding.
//!
//! `NetfilterRequest` is the typed request model.  Each variant encodes to
//! a `Vec<u8>` via `encode(seq)`.  Decode helpers interpret the raw bytes
//! returned by `socket::NetlinkSocket::recv_for_seq`.
//!
//! `NlBuilder` is a private wire-format builder; no caller outside this
//! module needs to construct raw netlink bytes directly.
//!
//! Decoders here run on a worker thread over untrusted kernel netlink bytes;
//! with `panic = "abort"` a panic would abort the process, so new `unwrap()`
//! calls are denied outside of tests.
#![cfg_attr(not(test), warn(clippy::unwrap_used))]

use super::config::NftFamily;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

// -- Subsystem / command constants -------------------------------------------

const NFNL_SUBSYS_IPSET: u16 = 6;
const IPSET_CMD_ADD: u16 = 9;
const IPSET_CMD_TEST: u16 = 11;
const IPSET_PROTOCOL: u8 = 6;

const NFNL_SUBSYS_NFTABLES: u16 = 10;
const NFT_MSG_NEWSET: u16 = 9;
const NFT_MSG_GETSET: u16 = 10;
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
const NLM_F_CREATE: u16 = 0x400;
const NLM_F_EXCL: u16 = 0x200;

pub(super) const NLMSG_ERROR: u16 = 0x2;

const NLA_F_NESTED: u16 = 1 << 15;
const NLA_F_NET_BYTEORDER: u16 = 1 << 14;
/// Mask to strip flag bits and get the bare NLA type.
const NLA_TYPE_MASK: u16 = !(NLA_F_NESTED | NLA_F_NET_BYTEORDER);

const IPSET_ATTR_PROTOCOL: u16 = 1;
const IPSET_ATTR_SETNAME: u16 = 2;
const IPSET_ATTR_LINENO: u16 = 9;
const IPSET_ATTR_ADT: u16 = 8;
const IPSET_ATTR_DATA: u16 = 7;
const IPSET_ATTR_IP: u16 = 1;
const IPSET_ATTR_IPADDR_IPV4: u16 = 1;
const IPSET_ATTR_IPADDR_IPV6: u16 = 2;
const IPSET_ATTR_CIDR: u16 = 3;
const IPSET_ERR_EXIST: i32 = 4103;

const NFTA_SET_ELEM_LIST_TABLE: u16 = 1;
const NFTA_SET_ELEM_LIST_SET: u16 = 2;
const NFTA_SET_ELEM_LIST_ELEMENTS: u16 = 3;
const NFTA_LIST_ELEM: u16 = 1;
const NFTA_SET_ELEM_KEY: u16 = 1;
const NFTA_SET_ELEM_FLAGS: u16 = 3;
const NFTA_DATA_VALUE: u16 = 1;
const NFT_SET_ELEM_INTERVAL_END: u32 = 1;

// nftset metadata attributes (for NFT_MSG_GETSET / NFT_MSG_NEWSET).
const NFTA_SET_TABLE: u16 = 1;
const NFTA_SET_NAME: u16 = 2;
const NFTA_SET_FLAGS: u16 = 3;

/// `NFT_SET_INTERVAL` kernel flag: set stores interval ranges.
pub(super) const NFT_SET_INTERVAL: u32 = 0x4;

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
        /// When `Some(prefix)` each IP is written as a CIDR entry (hash:net sets).
        mask: Option<u8>,
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
        /// When `Some(prefix)`, mask IPs to their network address before writing.
        mask: Option<u8>,
        /// When `true` (only meaningful with `mask`), write each prefix as an
        /// interval range `[network, next_network)` instead of a single element.
        /// Requires the target set to carry the `NFT_SET_INTERVAL` flag.
        /// Without a mask the existing host-interval format is always used.
        interval: bool,
    },
    /// Query set metadata to check for the `NFT_SET_INTERVAL` flag.
    NftSetGetMeta {
        family: NftFamily,
        table: &'a str,
        set: &'a str,
    },
}

impl<'a> NetfilterRequest<'a> {
    /// Encode this request into wire-format bytes with `seq` stamped into the
    /// nlmsg header.  For nftset add, the returned buffer contains the
    /// BATCH_BEGIN + data + BATCH_END messages concatenated.
    pub(super) fn encode(&self, seq: u32) -> Vec<u8> {
        match *self {
            Self::IpsetTest { name, ip } => encode_ipset_test(name, ip, seq),
            Self::IpsetAddBatch { name, ips, mask } => {
                encode_ipset_add_batch(name, ips, mask, seq)
            }
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
                mask,
                interval,
            } => encode_nftset_add(family, table, set, ips, mask, interval, seq),
            Self::NftSetGetMeta { family, table, set } => {
                encode_nftset_getmeta(family, table, set, seq)
            }
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
    ipset_elem(&mut msg, ip, None);
    msg.buf
}

fn encode_ipset_add_batch(name: &str, ips: &[IpAddr], mask: Option<u8>, seq: u32) -> Vec<u8> {
    let Some(first) = ips.first().copied() else {
        return Vec::new();
    };
    let family = ip_family(first);
    // Fire-and-forget: no NLM_F_ACK, so the kernel processes the add silently.
    // EEXIST is accepted by the kernel without a response regardless.
    let mut msg = NlBuilder::new(ipset_msg_type(IPSET_CMD_ADD), NLM_F_REQUEST, family, 0);
    msg.set_seq(seq);
    msg.attr(IPSET_ATTR_PROTOCOL, &[IPSET_PROTOCOL]);
    msg.attr_nul(IPSET_ATTR_SETNAME, name);
    msg.attr(IPSET_ATTR_LINENO, &0u32.to_ne_bytes());
    msg.nest(IPSET_ATTR_ADT, |msg| {
        for &ip in ips {
            let write_ip = mask.map(|m| apply_mask(ip, m)).unwrap_or(ip);
            ipset_elem(msg, write_ip, mask);
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
    mask: Option<u8>,
    interval: bool,
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
            match mask {
                Some(prefix) => {
                    let net = apply_mask(ip, prefix);
                    if interval {
                        // Write a prefix range: [net, next_net) as two interval endpoints.
                        let end = prefix_end(net, prefix);
                        nft_interval_elem(msg, net, false);
                        nft_interval_elem(msg, end, true);
                    } else {
                        // Set has no interval flag; write just the network address.
                        nft_interval_elem(msg, net, false);
                    }
                }
                None => {
                    if interval {
                        // Interval set: a host is the half-open range [ip, ip+1).
                        nft_interval_elem(msg, ip, false);
                        nft_interval_elem(msg, ip_next(ip), true);
                    } else {
                        // Plain set: a single host element.  Writing interval
                        // endpoints to a non-interval set is rejected with EINVAL.
                        nft_interval_elem(msg, ip, false);
                    }
                }
            }
        }
    });
    buf.extend_from_slice(&msg.buf);

    let mut end = NlBuilder::batch(NFNL_MSG_BATCH_END);
    end.set_seq(seq);
    buf.extend_from_slice(&end.buf);

    buf
}

fn encode_nftset_getmeta(family: NftFamily, table: &str, set: &str, seq: u32) -> Vec<u8> {
    let mut msg = NlBuilder::new(
        nft_msg_type(NFT_MSG_GETSET),
        NLM_F_REQUEST,
        nft_family_code(family),
        0,
    );
    msg.set_seq(seq);
    msg.attr_nul(NFTA_SET_TABLE, table);
    msg.attr_nul(NFTA_SET_NAME, set);
    msg.buf
}

// -- Decode helpers ----------------------------------------------------------

/// Interpret a response to an ipset TEST command.
/// Returns `true` when the IP is present in the set.
pub(super) fn decode_ipset_test(msg_type: u16, data: &[u8]) -> anyhow::Result<bool> {
    match nlmsg_errno(msg_type, data) {
        Some(0) => Ok(true),
        Some(code) if code.abs() == IPSET_ERR_EXIST => Ok(false),
        Some(code) => Err(anyhow::anyhow!("netlink ipset test error: {code}")),
        None if msg_type != NLMSG_ERROR => Ok(true),
        None => Err(anyhow::anyhow!("truncated netlink ipset test response")),
    }
}

/// Interpret a response to an nftset GET-ELEM command.
/// Returns `true` when the element was found.
pub(super) fn decode_nft_test(msg_type: u16, data: &[u8]) -> anyhow::Result<bool> {
    if msg_type == nft_msg_type(NFT_MSG_NEWSETELEM) {
        return Ok(true);
    }
    match nlmsg_errno(msg_type, data) {
        Some(code) if code.abs() == libc::ENOENT => Ok(false),
        Some(0) => Ok(true),
        Some(code) => Err(anyhow::anyhow!("netlink nftset test error: {code}")),
        None if msg_type == NLMSG_ERROR => {
            Err(anyhow::anyhow!("truncated netlink nftset test response"))
        }
        None => Err(anyhow::anyhow!(
            "unexpected netlink nftset response type: {msg_type}"
        )),
    }
}

/// Parse the `NFTA_SET_FLAGS` from a `NFT_MSG_NEWSET` response.
/// Returns 0 if no flags attribute is present (set has no special flags).
pub(super) fn decode_nft_set_flags(msg_type: u16, data: &[u8]) -> anyhow::Result<u32> {
    if msg_type != nft_msg_type(NFT_MSG_NEWSET) {
        if let Some(code) = nlmsg_errno(msg_type, data) {
            return Err(anyhow::anyhow!(
                "netlink GETSET error: errno={}",
                code.abs()
            ));
        }
        return Err(anyhow::anyhow!(
            "unexpected msg type {msg_type} in GETSET response"
        ));
    }
    // data = full nlmsg: 16-byte nlmsghdr + 4-byte nfgenmsg + NLA attributes.
    if data.len() < 20 {
        return Err(anyhow::anyhow!("truncated NEWSET response"));
    }
    for (attr_type, value) in nla_iter(&data[20..]) {
        if attr_type == NFTA_SET_FLAGS && value.len() >= 4 {
            // `value.len() >= 4` makes the four indexed reads infallible; build the
            // array directly to avoid a `try_into().unwrap()` panic path.
            return Ok(u32::from_be_bytes([value[0], value[1], value[2], value[3]]));
        }
    }
    Ok(0)
}

// -- IP address helpers ------------------------------------------------------

/// Mask `ip` to its network address for the given prefix length.
pub(super) fn apply_mask(ip: IpAddr, prefix: u8) -> IpAddr {
    match ip {
        IpAddr::V4(v4) => {
            let bits = u32::from(v4);
            let mask = if prefix == 0 {
                0u32
            } else if prefix >= 32 {
                u32::MAX
            } else {
                u32::MAX << (32 - prefix)
            };
            IpAddr::V4(Ipv4Addr::from(bits & mask))
        }
        IpAddr::V6(v6) => {
            let bits = u128::from(v6);
            let mask = if prefix == 0 {
                0u128
            } else if prefix >= 128 {
                u128::MAX
            } else {
                u128::MAX << (128 - prefix)
            };
            IpAddr::V6(Ipv6Addr::from(bits & mask))
        }
    }
}

/// Return the first address immediately after the prefix (the interval end point).
pub(super) fn prefix_end(network: IpAddr, prefix: u8) -> IpAddr {
    match network {
        IpAddr::V4(v4) => {
            let bits = u32::from(v4);
            let size = if prefix >= 32 {
                1u32
            } else {
                1u32 << (32 - prefix)
            };
            IpAddr::V4(Ipv4Addr::from(bits.wrapping_add(size)))
        }
        IpAddr::V6(v6) => {
            let bits = u128::from(v6);
            let size = if prefix >= 128 {
                1u128
            } else {
                1u128 << (128 - prefix)
            };
            IpAddr::V6(Ipv6Addr::from(bits.wrapping_add(size)))
        }
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

fn ipset_elem(msg: &mut NlBuilder, ip: IpAddr, mask: Option<u8>) {
    msg.nest(IPSET_ATTR_DATA, |msg| {
        msg.nest(IPSET_ATTR_IP, |msg| {
            let attr = match ip {
                IpAddr::V4(_) => IPSET_ATTR_IPADDR_IPV4,
                IpAddr::V6(_) => IPSET_ATTR_IPADDR_IPV6,
            };
            msg.attr_ip(attr | NLA_F_NET_BYTEORDER, ip);
        });
        if let Some(cidr) = mask {
            msg.attr(IPSET_ATTR_CIDR, &[cidr]);
        }
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

/// Iterate over top-level NLA (netlink attribute) entries in `data`.
/// Each item is `(type_without_flags, value_bytes)`.
fn nla_iter(data: &[u8]) -> impl Iterator<Item = (u16, &[u8])> {
    NlaIter { data, pos: 0 }
}

struct NlaIter<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Iterator for NlaIter<'a> {
    type Item = (u16, &'a [u8]);

    fn next(&mut self) -> Option<Self::Item> {
        if self.pos + 4 > self.data.len() {
            return None;
        }
        let nla_len =
            u16::from_ne_bytes(self.data[self.pos..self.pos + 2].try_into().ok()?) as usize;
        if nla_len < 4 {
            return None;
        }
        let end = self.pos.checked_add(nla_len)?;
        if end > self.data.len() {
            return None;
        }
        let nla_type = u16::from_ne_bytes(self.data[self.pos + 2..self.pos + 4].try_into().ok()?)
            & NLA_TYPE_MASK;
        let value = &self.data[self.pos + 4..end];
        self.pos = (end + 3) & !3; // advance to next 4-byte boundary
        Some((nla_type, value))
    }
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

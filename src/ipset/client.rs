//! High-level netfilter client: IP adds and nftset metadata queries.
//!
//! `NetfilterClient` owns a `NetlinkSocket` and translates typed requests
//! (via `codec::NetfilterRequest`) into netlink messages.
//!
//! Adds are fire-and-forget: the kernel commits the ipset/nftset entry inside
//! the `send()` syscall, so no ACK recv is needed (duplicates return `EEXIST`,
//! which the kernel reports without us having to read it). Only the startup
//! `NFT_SET_INTERVAL` metadata query reads a reply.

use anyhow::Result;
use std::io;
use std::net::IpAddr;

use super::codec::{self, NetfilterRequest};
use super::config::{NftFamily, SetName};
use super::socket::NetlinkSocket;

#[derive(Debug)]
pub(super) struct NetfilterClient {
    sock: NetlinkSocket,
}

impl NetfilterClient {
    pub(super) fn new() -> Result<Self> {
        Ok(Self {
            sock: NetlinkSocket::open()?,
        })
    }

    /// Query whether the nftset carries the `NFT_SET_INTERVAL` flag.
    /// Returns `false` on timeout or if the flag is absent.
    pub(super) fn query_nft_interval_flag(
        &mut self,
        family: NftFamily,
        table: &str,
        set: &str,
    ) -> Result<bool> {
        let seq = self.sock.alloc_seq();
        self.sock
            .send_raw(&NetfilterRequest::NftSetGetMeta { family, table, set }.encode(seq))?;
        let msg = match self.sock.recv_for_seq(seq) {
            Ok(msg) => msg,
            Err(e) if is_timeout(&e) => return Ok(false),
            Err(e) => return Err(e.into()),
        };
        let flags = codec::decode_nft_set_flags(msg.msg_type, &msg.data)?;
        Ok(flags & codec::NFT_SET_INTERVAL != 0)
    }

    /// Add `ips` to `set`.  Relies on `EEXIST` for duplicates (blind add).
    ///
    /// `interval` selects the nftset element representation: when `true` (the
    /// target set carries `NFT_SET_INTERVAL`) each element is written as a
    /// half-open range via two interval endpoints — `[net, next_net)` for a
    /// masked prefix or `[ip, ip+1)` for a single host. When `false`, elements
    /// are written as plain single keys.
    ///
    /// Fire-and-forget: the kernel processes the add within the `send()` syscall, so no
    /// recv round-trip is needed (errors on these background adds are non-fatal).
    /// For ipset, IPs are grouped by address family and sent in separate messages (the
    /// kernel rejects mixed-family batches); for nftset, all IPs go in one batch.
    pub(super) fn add_many(&mut self, set: &SetName, ips: &[IpAddr], interval: bool) -> Result<()> {
        if ips.is_empty() {
            return Ok(());
        }
        match set {
            SetName::IpSet { name, mask } => self.add_ipset(name, ips, *mask),
            SetName::NftSet {
                family,
                table,
                set: set_name,
                mask,
            } => self.send_chunked(ips, |chunk, seq| {
                NetfilterRequest::NftSetAdd {
                    family: *family,
                    table,
                    set: set_name,
                    ips: chunk,
                    mask: *mask,
                    interval,
                }
                .encode(seq)
            }),
        }
    }

    // -- Private helpers --------------------------------------------------------

    /// Send `ips` in `MAX_IPS_PER_MESSAGE`-sized chunks, encoding each chunk via
    /// `encode(chunk, seq)`. Fire-and-forget: keeps sending after a send error so
    /// one bad chunk doesn't abort the rest, but reports the first error seen (if any).
    fn send_chunked(
        &mut self,
        ips: &[IpAddr],
        mut encode: impl FnMut(&[IpAddr], u32) -> Vec<u8>,
    ) -> Result<()> {
        let mut first_err: Option<anyhow::Error> = None;
        for chunk in ips.chunks(MAX_IPS_PER_MESSAGE) {
            let seq = self.sock.alloc_seq();
            if let Err(e) = self.sock.send_raw(&encode(chunk, seq)) {
                first_err.get_or_insert(e);
            }
        }
        first_err.map_or(Ok(()), Err)
    }

    fn add_ipset(&mut self, name: &str, ips: &[IpAddr], mask: Option<u8>) -> Result<()> {
        // ipset ADD requires that all IPs in one message share the same family.
        let (v4, v6): (Vec<IpAddr>, Vec<IpAddr>) = ips.iter().copied().partition(IpAddr::is_ipv4);
        let mut first_err: Option<anyhow::Error> = None;
        for family_ips in [v4.as_slice(), v6.as_slice()] {
            if !family_ips.is_empty() {
                if let Err(e) = self.add_ipset_family(name, family_ips, mask) {
                    first_err.get_or_insert(e);
                }
            }
        }
        first_err.map_or(Ok(()), Err)
    }

    fn add_ipset_family(&mut self, name: &str, ips: &[IpAddr], mask: Option<u8>) -> Result<()> {
        self.send_chunked(ips, |chunk, seq| {
            NetfilterRequest::IpsetAddBatch {
                name,
                ips: chunk,
                mask,
            }
            .encode(seq)
        })
    }
}

/// Cap on IPs encoded into a single netlink message. The nested `IPSET_ATTR_ADT` /
/// `NFTA_SET_ELEM_LIST_ELEMENTS` attribute carries a `u16` length prefix
/// (`NlBuilder::nest`); an interval nftset write emits *two* elements per IP
/// (range start + end), so at up to ~40 bytes per element this could reach
/// ~80,000 bytes for a few thousand IPs in one message — silently overflowing
/// that `u16` length and corrupting the message. The kernel would then see a
/// truncated attribute (or reject it) with pathdns never finding out, since
/// these adds are fire-and-forget. 500 keeps every message comfortably under
/// `u16::MAX` even at double-counted worst-case element sizes.
const MAX_IPS_PER_MESSAGE: usize = 500;

fn is_timeout(e: &io::Error) -> bool {
    e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut
}

//! High-level netfilter client: test, add, and add_many operations.
//!
//! `NetfilterClient` owns a `NetlinkSocket` and translates typed requests
//! (via `codec::NetfilterRequest`) into socket send/receive pairs.
//!
//! `AddPolicy` controls whether add operations pre-test each IP before
//! sending an add request.  `BlindAdd` is the recommended default: it
//! relies on the kernel returning `EEXIST` for duplicate entries (which
//! `codec::decode_ack_ok_or_exists` already treats as success), avoiding
//! an extra round-trip per IP.

use anyhow::{anyhow, Result};
use std::io;
use std::net::IpAddr;

use super::codec::{self, NetfilterRequest};
use super::config::{NftFamily, SetName};
use super::socket::{self, NetlinkSocket};

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

    /// Test whether `ip` is present in `set`.  Socket timeout → `Err`.
    pub(super) fn test(&mut self, set: &SetName, ip: IpAddr) -> Result<bool> {
        let seq = self.sock.alloc_seq();
        let req = match set {
            SetName::IpSet { name, .. } => NetfilterRequest::IpsetTest { name, ip },
            SetName::NftSet {
                family, table, set, ..
            } => NetfilterRequest::NftSetTest {
                family: *family,
                table,
                set,
                ip,
            },
        };
        self.sock.send_raw(&req.encode(seq))?;

        let msg = self.recv_for_test(seq)?;
        match set {
            SetName::IpSet { .. } => codec::decode_ipset_test(msg.msg_type, &msg.data),
            SetName::NftSet { .. } => codec::decode_nft_test(msg.msg_type, &msg.data),
        }
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
    /// `interval` is only used for nftset entries that have a mask: when
    /// `true` each masked IP is written as a prefix range `[net, net_end)`.
    ///
    /// For ipset, IPs are grouped by address family and sent in separate
    /// messages (the kernel rejects mixed-family batches).
    /// For nftset, all IPs are sent in one batch.
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
            } => self.add_nftset(*family, table, set_name, ips, *mask, interval),
        }
    }

    // -- Private helpers --------------------------------------------------------

    fn add_ipset(&mut self, name: &str, ips: &[IpAddr], mask: Option<u8>) -> Result<()> {
        // ipset ADD requires that all IPs in one message share the same family.
        let v4: Vec<IpAddr> = ips.iter().copied().filter(IpAddr::is_ipv4).collect();
        let v6: Vec<IpAddr> = ips.iter().copied().filter(IpAddr::is_ipv6).collect();
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
        let seq = self.sock.alloc_seq();
        self.sock
            .send_raw(&NetfilterRequest::IpsetAddBatch { name, ips, mask }.encode(seq))?;
        // No recv: the message is sent without NLM_F_ACK so the kernel never
        // sends a response.  This eliminates one blocking recv() per ipset batch,
        // making ipset adds fully fire-and-forget.
        Ok(())
    }

    fn add_nftset(
        &mut self,
        family: NftFamily,
        table: &str,
        set: &str,
        ips: &[IpAddr],
        mask: Option<u8>,
        interval: bool,
    ) -> Result<()> {
        let seq = self.sock.alloc_seq();
        self.sock.send_raw(
            &NetfilterRequest::NftSetAdd {
                family,
                table,
                set,
                ips,
                mask,
                interval,
            }
            .encode(seq),
        )?;
        self.recv_ack_add(seq)
    }

    /// Pipeline nftset adds: send all messages first, then receive all acks in order.
    ///
    /// This collapses N serial round-trips (one per set) into a single kernel RTT
    /// by exploiting the FIFO ordering guarantee of a single netlink socket.
    /// The nftables batch protocol requires an ack per `NFNL_MSG_BATCH_END`, so
    /// we cannot drop them the way we do for ipset — we just overlap the sends.
    pub(super) fn add_nftset_pipelined(
        &mut self,
        chunks: &[(super::config::SetName, Vec<IpAddr>, bool)],
    ) -> Result<()> {
        if chunks.is_empty() {
            return Ok(());
        }
        // Phase 1: send all messages, collecting the seq numbers we'll need to ack.
        let mut seqs: Vec<u32> = Vec::with_capacity(chunks.len());
        for (set, ips, interval) in chunks {
            let super::config::SetName::NftSet {
                family,
                table,
                set: set_name,
                mask,
            } = set
            else {
                continue;
            };
            let seq = self.sock.alloc_seq();
            self.sock.send_raw(
                &NetfilterRequest::NftSetAdd {
                    family: *family,
                    table,
                    set: set_name,
                    ips,
                    mask: *mask,
                    interval: *interval,
                }
                .encode(seq),
            )?;
            seqs.push(seq);
        }
        // Phase 2: drain acks in the same order we sent them.
        // recv_for_seq discards messages with non-matching seqs, so receiving
        // in send order is required to avoid losing acks for later seqs.
        let mut first_err: Option<anyhow::Error> = None;
        for seq in seqs {
            match self.sock.recv_for_seq(seq) {
                Ok(msg) => {
                    if let Err(e) = codec::decode_ack_ok_or_exists(msg.msg_type, &msg.data) {
                        first_err.get_or_insert(e);
                    }
                }
                Err(e) if is_timeout(&e) => {}
                Err(e) => {
                    first_err.get_or_insert(anyhow::anyhow!(e));
                }
            }
        }
        first_err.map_or(Ok(()), Err)
    }

    /// Receive for add operations.  Timeout is treated as `Ok` — the kernel
    /// likely processed the request; absence of an ACK is non-fatal.
    fn recv_ack_add(&mut self, seq: u32) -> Result<()> {
        match self.sock.recv_for_seq(seq) {
            Ok(msg) => codec::decode_ack_ok_or_exists(msg.msg_type, &msg.data),
            Err(e) if is_timeout(&e) => Ok(()),
            Err(e) => Err(e.into()),
        }
    }

    /// Receive for test operations.  Timeout is an error — the result is
    /// unknown and the caller must not treat this as "not found".
    fn recv_for_test(&mut self, seq: u32) -> Result<socket::RecvMsg> {
        match self.sock.recv_for_seq(seq) {
            Ok(msg) => Ok(msg),
            Err(e) if is_timeout(&e) => Err(anyhow!("netlink test timed out: {e}")),
            Err(e) => Err(e.into()),
        }
    }
}

fn is_timeout(e: &io::Error) -> bool {
    e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut
}

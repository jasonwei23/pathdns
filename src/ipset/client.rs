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
use super::config::SetName;
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
            SetName::IpSet(name) => NetfilterRequest::IpsetTest { name, ip },
            SetName::NftSet { family, table, set } => NetfilterRequest::NftSetTest {
                family: *family,
                table,
                set,
                ip,
            },
        };
        self.sock.send_raw(&req.encode(seq))?;

        let msg = self.recv_for_test(seq)?;
        Ok(match set {
            SetName::IpSet(_) => codec::decode_ipset_test(msg.msg_type, &msg.data),
            SetName::NftSet { .. } => codec::decode_nft_test(msg.msg_type),
        })
    }

    /// Add `ips` to `set`.  Relies on `EEXIST` for duplicates (blind add).
    ///
    /// For ipset, IPs are grouped by address family and sent in separate
    /// messages (the kernel rejects mixed-family batches).
    /// For nftset, all IPs are sent in one batch.
    pub(super) fn add_many(&mut self, set: &SetName, ips: &[IpAddr]) -> Result<()> {
        if ips.is_empty() {
            return Ok(());
        }
        match set {
            SetName::IpSet(name) => self.add_ipset(name, ips),
            SetName::NftSet {
                family,
                table,
                set: set_name,
            } => self.add_nftset(*family, table, set_name, ips),
        }
    }

    // -- Private helpers --------------------------------------------------------

    fn add_ipset(&mut self, name: &str, ips: &[IpAddr]) -> Result<()> {
        // ipset ADD requires that all IPs in one message share the same family.
        let v4: Vec<IpAddr> = ips.iter().copied().filter(IpAddr::is_ipv4).collect();
        let v6: Vec<IpAddr> = ips.iter().copied().filter(IpAddr::is_ipv6).collect();
        let mut first_err: Option<anyhow::Error> = None;
        for family_ips in [v4.as_slice(), v6.as_slice()] {
            if !family_ips.is_empty() {
                if let Err(e) = self.add_ipset_family(name, family_ips) {
                    first_err.get_or_insert(e);
                }
            }
        }
        first_err.map_or(Ok(()), Err)
    }

    fn add_ipset_family(&mut self, name: &str, ips: &[IpAddr]) -> Result<()> {
        let seq = self.sock.alloc_seq();
        self.sock
            .send_raw(&NetfilterRequest::IpsetAddBatch { name, ips }.encode(seq))?;
        self.recv_ack_add(seq)
    }

    fn add_nftset(
        &mut self,
        family: super::config::NftFamily,
        table: &str,
        set: &str,
        ips: &[IpAddr],
    ) -> Result<()> {
        let seq = self.sock.alloc_seq();
        self.sock.send_raw(
            &NetfilterRequest::NftSetAdd {
                family,
                table,
                set,
                ips,
            }
            .encode(seq),
        )?;
        self.recv_ack_add(seq)
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

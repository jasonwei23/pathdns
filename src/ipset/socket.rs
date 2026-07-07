//! Raw netlink socket: open, send, and a seq-filtering receive loop.
//!
//! The receive loop reads datagrams in a loop, iterates over all nlmsg entries
//! in each datagram, and returns the first message whose seq field matches the
//! requested seq.  Stale responses from prior timed-out operations (with a
//! different seq) are silently discarded.
//!
//! This module parses untrusted kernel netlink bytes on a worker thread; with
//! `panic = "abort"` any panic here would take down the whole process, so new
//! `unwrap()` calls are denied outside of tests.
#![cfg_attr(not(test), warn(clippy::unwrap_used))]

use crate::sys;
use anyhow::{anyhow, Context, Result};
use std::io;
use std::os::fd::{AsRawFd, OwnedFd};

const NETLINK_NETFILTER: i32 = 12;

#[derive(Debug)]
pub(super) struct NetlinkSocket {
    fd: OwnedFd,
    seq: u32,
    recv_buf: Vec<u8>,
}

/// A single nlmsg entry extracted from a received datagram.
pub(super) struct RecvMsg {
    pub(super) msg_type: u16,
    /// Full message bytes including the 16-byte nlmsghdr.
    pub(super) data: Vec<u8>,
}

impl NetlinkSocket {
    /// Open a netfilter netlink socket with a 50 ms receive timeout.
    /// The timeout bounds the blocking `recv` in `recv_for_seq` — used only by
    /// the startup `NFT_SET_INTERVAL` metadata query — so a missing reply can
    /// never hang a thread. IP adds are fire-and-forget and never call it.
    pub(super) fn open() -> Result<Self> {
        let fd = sys::socket(libc::AF_NETLINK, libc::SOCK_RAW, NETLINK_NETFILTER)
            .context("failed to open netfilter netlink socket")?;

        sys::set_receive_timeout(fd.as_raw_fd(), std::time::Duration::from_millis(50))
            .context("failed to set netlink receive timeout")?;

        // Bind so the kernel assigns a port ID (nl_pid).
        sys::bind_netlink(fd.as_raw_fd()).context("failed to bind netlink socket")?;

        Ok(Self {
            fd,
            seq: 1,
            recv_buf: vec![0u8; 8192],
        })
    }

    /// Allocate the next sequence number. Never returns 0.
    pub(super) fn alloc_seq(&mut self) -> u32 {
        let s = self.seq;
        self.seq = self.seq.wrapping_add(1).max(1);
        s
    }

    pub(super) fn send_raw(&self, buf: &[u8]) -> Result<()> {
        let sent =
            sys::send(self.fd.as_raw_fd(), buf, 0).context("failed to send netlink request")?;
        if sent != buf.len() {
            return Err(anyhow!("short netlink send: {sent} != {}", buf.len()));
        }
        Ok(())
    }

    /// Receive messages until one whose `nlmsg_seq` matches `seq` is found.
    ///
    /// A single datagram may contain multiple nlmsg entries; all entries are
    /// examined before issuing the next `recv()` syscall.  Messages with a
    /// non-matching seq are silently discarded (they are stale responses from
    /// a previous timed-out operation).
    ///
    /// Returns `io::Error` on socket timeout (`EAGAIN`/`ETIMEDOUT`) or any
    /// other I/O error.
    pub(super) fn recv_for_seq(&mut self, seq: u32) -> io::Result<RecvMsg> {
        loop {
            let n = sys::recv(self.fd.as_raw_fd(), &mut self.recv_buf, 0)?;
            let buf = &self.recv_buf[..n];

            // Walk all nlmsg entries packed into this datagram.
            let mut pos = 0usize;
            while pos + 16 <= buf.len() {
                // The loop guard guarantees `buf[pos..pos + 16]` is in bounds, so every
                // fixed-offset read below is infallible — build the arrays by indexing
                // directly rather than via a fallible `try_into`.
                let msg_len =
                    u32::from_ne_bytes([buf[pos], buf[pos + 1], buf[pos + 2], buf[pos + 3]])
                        as usize;
                if msg_len < 16 {
                    break; // malformed entry
                }
                let msg_type = u16::from_ne_bytes([buf[pos + 4], buf[pos + 5]]);
                let msg_seq =
                    u32::from_ne_bytes([buf[pos + 8], buf[pos + 9], buf[pos + 10], buf[pos + 11]]);

                let Some(data_end) = pos.checked_add(msg_len) else {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "netlink message length overflow",
                    ));
                };
                if data_end > buf.len() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "truncated netlink message",
                    ));
                }

                if msg_seq == seq {
                    return Ok(RecvMsg {
                        msg_type,
                        data: buf[pos..data_end].to_vec(),
                    });
                }

                // Not our message — skip to the next entry (4-byte aligned).
                let aligned = (msg_len + 3) & !3;
                pos = pos.saturating_add(aligned);
            }
            // No matching entry in this datagram; issue another recv().
            // The socket timeout will fire if no further datagrams arrive.
        }
    }
}

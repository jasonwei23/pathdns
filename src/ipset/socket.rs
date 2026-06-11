//! Raw netlink socket: open, send, and a seq-filtering receive loop.
//!
//! The receive loop reads datagrams in a loop, iterates over all nlmsg entries
//! in each datagram, and returns the first message whose seq field matches the
//! requested seq.  Stale responses from prior timed-out operations (with a
//! different seq) are silently discarded.

use anyhow::{anyhow, Context, Result};
use std::io;
use std::mem;
use std::os::fd::RawFd;

const NETLINK_NETFILTER: i32 = 12;

#[derive(Debug)]
pub(super) struct NetlinkSocket {
    fd: RawFd,
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
    pub(super) fn open() -> Result<Self> {
        let fd = unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_RAW, NETLINK_NETFILTER) };
        if fd < 0 {
            return Err(io::Error::last_os_error())
                .context("failed to open netfilter netlink socket");
        }

        // 50 ms receive timeout — matches the previous behaviour.
        let timeout = libc::timeval {
            tv_sec: 0,
            tv_usec: 50_000,
        };
        if unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                &timeout as *const _ as *const libc::c_void,
                mem::size_of_val(&timeout) as libc::socklen_t,
            )
        } < 0
        {
            let err = io::Error::last_os_error();
            unsafe { libc::close(fd) };
            return Err(err).context("failed to set netlink receive timeout");
        }

        // Bind so the kernel assigns a port ID (nl_pid).
        let mut sa: libc::sockaddr_nl = unsafe { mem::zeroed() };
        sa.nl_family = libc::AF_NETLINK as u16;
        let sa_len = mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t;
        if unsafe { libc::bind(fd, &sa as *const _ as *const libc::sockaddr, sa_len) } < 0 {
            let err = io::Error::last_os_error();
            unsafe { libc::close(fd) };
            return Err(err).context("failed to bind netlink socket");
        }

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
            unsafe { libc::send(self.fd, buf.as_ptr() as *const libc::c_void, buf.len(), 0) };
        if sent < 0 {
            return Err(io::Error::last_os_error()).context("failed to send netlink request");
        }
        if sent as usize != buf.len() {
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
            let n = unsafe {
                libc::recv(
                    self.fd,
                    self.recv_buf.as_mut_ptr() as *mut libc::c_void,
                    self.recv_buf.len(),
                    0,
                )
            };
            if n < 0 {
                return Err(io::Error::last_os_error());
            }
            let buf = &self.recv_buf[..n as usize];

            // Walk all nlmsg entries packed into this datagram.
            let mut pos = 0usize;
            while pos + 16 <= buf.len() {
                let msg_len = u32::from_ne_bytes(buf[pos..pos + 4].try_into().unwrap()) as usize;
                if msg_len < 16 {
                    break; // malformed entry
                }
                let msg_type = u16::from_ne_bytes(buf[pos + 4..pos + 6].try_into().unwrap());
                let msg_seq = u32::from_ne_bytes(buf[pos + 8..pos + 12].try_into().unwrap());

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

impl Drop for NetlinkSocket {
    fn drop(&mut self) {
        unsafe { libc::close(self.fd) };
    }
}

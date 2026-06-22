//! Small, safe wrappers around the Linux C ABI used by pathdns.
//!
//! Keeping pointer construction, file-descriptor ownership transfer and libc calls
//! here makes the rest of the program ordinary safe Rust.  Every public function in
//! this module owns or borrows all memory touched by the kernel for the full syscall.

use std::collections::HashSet;
use std::ffi::{CStr, CString};
use std::io;
use std::mem;
use std::net::SocketAddr;
use std::os::fd::{FromRawFd, OwnedFd, RawFd};
use std::time::Duration;

/// Create a close-on-exec socket and immediately take ownership of its descriptor.
pub(crate) fn socket(
    domain: libc::c_int,
    ty: libc::c_int,
    protocol: libc::c_int,
) -> io::Result<OwnedFd> {
    // SAFETY: `socket` has no memory arguments.  A non-negative result is a new,
    // uniquely-owned descriptor, transferred to OwnedFd exactly once below.
    let fd = unsafe { libc::socket(domain, ty | libc::SOCK_CLOEXEC, protocol) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the successful socket call returned a fresh owned descriptor.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Bind an INET/INET6 socket to a Rust `SocketAddr`.
pub(crate) fn bind_inet(fd: RawFd, addr: SocketAddr) -> io::Result<()> {
    let rc = match addr {
        SocketAddr::V4(addr) => {
            let raw = libc::sockaddr_in {
                sin_family: libc::AF_INET as libc::sa_family_t,
                sin_port: addr.port().to_be(),
                sin_addr: libc::in_addr {
                    s_addr: u32::from_ne_bytes(addr.ip().octets()),
                },
                sin_zero: [0; 8],
            };
            // SAFETY: `raw` is a fully initialized sockaddr_in and remains alive
            // for the duration of this synchronous syscall.
            unsafe {
                libc::bind(
                    fd,
                    &raw as *const _ as *const libc::sockaddr,
                    mem::size_of_val(&raw) as libc::socklen_t,
                )
            }
        }
        SocketAddr::V6(addr) => {
            let raw = libc::sockaddr_in6 {
                sin6_family: libc::AF_INET6 as libc::sa_family_t,
                sin6_port: addr.port().to_be(),
                sin6_flowinfo: addr.flowinfo(),
                sin6_addr: libc::in6_addr {
                    s6_addr: addr.ip().octets(),
                },
                sin6_scope_id: addr.scope_id(),
            };
            // SAFETY: `raw` is a fully initialized sockaddr_in6 and remains alive
            // for the duration of this synchronous syscall.
            unsafe {
                libc::bind(
                    fd,
                    &raw as *const _ as *const libc::sockaddr,
                    mem::size_of_val(&raw) as libc::socklen_t,
                )
            }
        }
    };
    cvt_zero(rc)
}

pub(crate) fn listen(fd: RawFd, backlog: libc::c_int) -> io::Result<()> {
    // SAFETY: no pointers are passed; the kernel validates the descriptor.
    cvt_zero(unsafe { libc::listen(fd, backlog) })
}

fn set_socket_option_value<T>(
    fd: RawFd,
    level: libc::c_int,
    option: libc::c_int,
    value: &T,
) -> io::Result<()> {
    // SAFETY: `value` points to `size_of::<T>()` readable bytes and lives through
    // the synchronous call.  setsockopt never retains the pointer.
    let rc = unsafe {
        libc::setsockopt(
            fd,
            level,
            option,
            value as *const T as *const libc::c_void,
            mem::size_of::<T>() as libc::socklen_t,
        )
    };
    cvt_zero(rc)
}

pub(crate) fn set_socket_i32(
    fd: RawFd,
    level: libc::c_int,
    option: libc::c_int,
    value: libc::c_int,
) -> io::Result<()> {
    set_socket_option_value(fd, level, option, &value)
}

pub(crate) fn set_socket_u32(
    fd: RawFd,
    level: libc::c_int,
    option: libc::c_int,
    value: u32,
) -> io::Result<()> {
    set_socket_option_value(fd, level, option, &value)
}

pub(crate) fn set_receive_timeout(fd: RawFd, timeout: Duration) -> io::Result<()> {
    let timeval = libc::timeval {
        tv_sec: timeout.as_secs().min(i64::MAX as u64) as _,
        tv_usec: timeout.subsec_micros() as _,
    };
    set_socket_option_value(fd, libc::SOL_SOCKET, libc::SO_RCVTIMEO, &timeval)
}

/// Set a socket option represented by an arbitrary byte string (SO_BINDTODEVICE).
pub(crate) fn set_socket_option_bytes(
    fd: RawFd,
    level: libc::c_int,
    option: libc::c_int,
    value: &[u8],
) -> io::Result<()> {
    // SAFETY: the slice is readable for exactly `value.len()` bytes and is retained
    // by this stack frame until setsockopt returns.
    let rc = unsafe {
        libc::setsockopt(
            fd,
            level,
            option,
            value.as_ptr() as *const libc::c_void,
            value.len() as libc::socklen_t,
        )
    };
    cvt_zero(rc)
}

/// Read a u32-array socket option, returning the number of complete values written.
pub(crate) fn get_socket_u32s(
    fd: RawFd,
    level: libc::c_int,
    option: libc::c_int,
    values: &mut [u32],
) -> io::Result<usize> {
    let mut len = mem::size_of_val(values) as libc::socklen_t;
    // SAFETY: `values` is writable for the advertised length and `len` is a valid
    // in/out socklen_t.  getsockopt does not retain either pointer.
    let rc = unsafe {
        libc::getsockopt(
            fd,
            level,
            option,
            values.as_mut_ptr() as *mut libc::c_void,
            &mut len,
        )
    };
    cvt_zero(rc)?;
    Ok((len as usize / mem::size_of::<u32>()).min(values.len()))
}

#[cfg(test)]
pub(crate) fn get_socket_u32(
    fd: RawFd,
    level: libc::c_int,
    option: libc::c_int,
) -> io::Result<u32> {
    let mut value = [0u32; 1];
    let count = get_socket_u32s(fd, level, option, &mut value)?;
    if count == 1 {
        Ok(value[0])
    } else {
        Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "socket option returned no u32 value",
        ))
    }
}

pub(crate) fn bind_netlink(fd: RawFd) -> io::Result<()> {
    // sockaddr_nl contains libc-private padding on some targets, so initialize the
    // complete C POD value before setting its public family field.
    // SAFETY: all-zero is a valid base representation for sockaddr_nl.
    let mut addr: libc::sockaddr_nl = unsafe { mem::zeroed() };
    addr.nl_family = libc::AF_NETLINK as libc::sa_family_t;
    // SAFETY: `addr` is fully initialized and remains alive through bind.
    let rc = unsafe {
        libc::bind(
            fd,
            &addr as *const _ as *const libc::sockaddr,
            mem::size_of_val(&addr) as libc::socklen_t,
        )
    };
    cvt_zero(rc)
}

pub(crate) fn send(fd: RawFd, buf: &[u8], flags: libc::c_int) -> io::Result<usize> {
    loop {
        // SAFETY: `buf` is readable for `buf.len()` bytes and lives through send.
        let n = unsafe {
            libc::send(
                fd,
                buf.as_ptr() as *const libc::c_void,
                buf.len(),
                flags,
            )
        };
        if n >= 0 {
            return Ok(n as usize);
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

pub(crate) fn recv(fd: RawFd, buf: &mut [u8], flags: libc::c_int) -> io::Result<usize> {
    loop {
        // SAFETY: `buf` is writable for `buf.len()` bytes and lives through recv.
        let n = unsafe {
            libc::recv(
                fd,
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len(),
                flags,
            )
        };
        if n >= 0 {
            return Ok(n as usize);
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

/// Pop one entry from a socket's Linux error queue.
pub(crate) fn recv_error_queue(
    fd: RawFd,
    data: &mut [u8],
    control: &mut [u8],
) -> io::Result<usize> {
    let mut iov = libc::iovec {
        iov_base: data.as_mut_ptr() as *mut libc::c_void,
        iov_len: data.len(),
    };
    // SAFETY: a zeroed msghdr is valid before its explicitly initialized pointer
    // and length fields are filled below.
    let mut msg: libc::msghdr = unsafe { mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.as_mut_ptr() as *mut libc::c_void;
    msg.msg_controllen = control.len() as _;
    loop {
        // SAFETY: the iovec/control pointers refer to live mutable slices for the
        // full synchronous recvmsg call.
        let n = unsafe { libc::recvmsg(fd, &mut msg, libc::MSG_ERRQUEUE | libc::MSG_DONTWAIT) };
        if n >= 0 {
            return Ok(n as usize);
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

pub(crate) fn page_size() -> usize {
    // SAFETY: sysconf has no pointer arguments or caller-side invariants.
    let value = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    usize::try_from(value).ok().filter(|v| *v > 0).unwrap_or(4096)
}

pub(crate) fn clock_realtime() -> io::Result<libc::timespec> {
    // SAFETY: all-zero is a valid timespec representation and the pointer is a
    // writable out-parameter for clock_gettime.
    let mut now: libc::timespec = unsafe { mem::zeroed() };
    // SAFETY: `now` remains live and writable throughout the call.
    let rc = unsafe { libc::clock_gettime(libc::CLOCK_REALTIME, &mut now) };
    cvt_zero(rc)?;
    Ok(now)
}

pub(crate) fn zeroed_msghdr() -> libc::msghdr {
    // SAFETY: Linux defines an all-zero msghdr as an empty message descriptor.
    unsafe { mem::zeroed() }
}

pub(crate) fn read_timespec(bytes: &[u8]) -> Option<libc::timespec> {
    if bytes.len() < mem::size_of::<libc::timespec>() {
        return None;
    }
    // SAFETY: all-zero is valid for timespec; the bounded copy initializes every
    // byte from a live source without assuming payload alignment.
    let mut value: libc::timespec = unsafe { mem::zeroed() };
    // SAFETY: the length check above proves both regions are valid for a complete
    // timespec, and the byte slice need not satisfy timespec alignment.
    unsafe {
        std::ptr::copy_nonoverlapping(
            bytes.as_ptr(),
            &mut value as *mut _ as *mut u8,
            mem::size_of::<libc::timespec>(),
        );
    }
    Some(value)
}

/// Parse the prefix of a kernel-produced sockaddr buffer.
pub(crate) fn read_sockaddr_bytes(bytes: &[u8]) -> Option<SocketAddr> {
    // SAFETY: all-zero is a valid sockaddr_storage representation.
    let mut storage: libc::sockaddr_storage = unsafe { mem::zeroed() };
    let len = bytes.len().min(mem::size_of_val(&storage));
    // SAFETY: both pointers are valid for `len`, the regions cannot overlap, and
    // `len` is capped to the destination size.
    unsafe {
        std::ptr::copy_nonoverlapping(
            bytes.as_ptr(),
            &mut storage as *mut _ as *mut u8,
            len,
        );
    }
    read_sockaddr(&storage, len as libc::socklen_t)
}

fn read_sockaddr(
    storage: &libc::sockaddr_storage,
    len: libc::socklen_t,
) -> Option<SocketAddr> {
    match storage.ss_family as libc::c_int {
        libc::AF_INET if len as usize >= mem::size_of::<libc::sockaddr_in>() => {
            // SAFETY: sockaddr_storage provides the required size/alignment and the
            // length check proves all sockaddr_in bytes were initialized.
            let addr = unsafe { &*(storage as *const _ as *const libc::sockaddr_in) };
            Some(SocketAddr::from((
                std::net::Ipv4Addr::from(addr.sin_addr.s_addr.to_ne_bytes()),
                u16::from_be(addr.sin_port),
            )))
        }
        libc::AF_INET6 if len as usize >= mem::size_of::<libc::sockaddr_in6>() => {
            // SAFETY: as above, for sockaddr_in6.
            let addr = unsafe { &*(storage as *const _ as *const libc::sockaddr_in6) };
            Some(SocketAddr::V6(std::net::SocketAddrV6::new(
                std::net::Ipv6Addr::from(addr.sin6_addr.s6_addr),
                u16::from_be(addr.sin6_port),
                addr.sin6_flowinfo,
                addr.sin6_scope_id,
            )))
        }
        _ => None,
    }
}

/// Reusable storage for one `sendmmsg(2)` batch.
///
/// Payload pointers are installed and consumed inside `send`; they never escape a
/// safe method call.  The self-referential address/iovec pointers target fixed Vec
/// allocations whose lengths never change.
pub(crate) struct SendMmsgBatch {
    names: Vec<libc::sockaddr_storage>,
    iovecs: Vec<libc::iovec>,
    messages: Vec<libc::mmsghdr>,
}

// SAFETY: every raw pointer stored permanently in this type points into one of its
// fixed, owned Vec allocations. Moving the Vec handles between threads does not move
// those allocations. Temporary payload pointers are replaced before every syscall
// and are never dereferenced after `send` returns.
unsafe impl Send for SendMmsgBatch {}

impl SendMmsgBatch {
    pub(crate) fn new(capacity: usize) -> Self {
        // SAFETY: these Linux C message/address structures permit all-zero values.
        let mut names = (0..capacity)
            .map(|_| unsafe { mem::zeroed::<libc::sockaddr_storage>() })
            .collect::<Vec<_>>();
        // SAFETY: an all-zero iovec denotes an empty buffer.
        let mut iovecs = vec![unsafe { mem::zeroed::<libc::iovec>() }; capacity];
        // SAFETY: an all-zero mmsghdr is valid before its fields are wired below.
        let mut messages = vec![unsafe { mem::zeroed::<libc::mmsghdr>() }; capacity];

        for index in 0..capacity {
            messages[index].msg_hdr.msg_name =
                &mut names[index] as *mut _ as *mut libc::c_void;
            messages[index].msg_hdr.msg_iov = &mut iovecs[index];
            messages[index].msg_hdr.msg_iovlen = 1 as _;
        }
        Self {
            names,
            iovecs,
            messages,
        }
    }

    pub(crate) fn capacity(&self) -> usize {
        self.messages.len()
    }

    /// Send every item yielded by `items` in one non-blocking syscall.
    pub(crate) fn send<'a, I>(&mut self, fd: RawFd, items: I) -> io::Result<usize>
    where
        I: IntoIterator<Item = (&'a [u8], SocketAddr)>,
    {
        let mut count = 0usize;
        for (payload, peer) in items {
            if count == self.capacity() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "sendmmsg batch exceeds allocated capacity",
                ));
            }
            let addr_len = write_sockaddr(peer, &mut self.names[count]);
            self.messages[count].msg_hdr.msg_namelen = addr_len;
            self.iovecs[count].iov_base = payload.as_ptr() as *mut libc::c_void;
            self.iovecs[count].iov_len = payload.len();
            self.messages[count].msg_len = 0;
            count += 1;
        }
        if count == 0 {
            return Ok(0);
        }

        loop {
            // SAFETY: all `count` headers point to initialized, live address/iovec
            // storage; each iovec points to a payload borrowed for this method call.
            let sent = unsafe {
                libc::sendmmsg(
                    fd,
                    self.messages.as_mut_ptr(),
                    count as libc::c_uint,
                    libc::MSG_DONTWAIT as _,
                )
            };
            if sent >= 0 {
                return Ok(sent as usize);
            }
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::Interrupted {
                return Err(error);
            }
        }
    }
}

fn write_sockaddr(
    peer: SocketAddr,
    storage: &mut libc::sockaddr_storage,
) -> libc::socklen_t {
    // Zero unused bytes as required by strict libc/kernel implementations.
    // SAFETY: `storage` is a valid initialized object and is exclusively borrowed.
    unsafe { std::ptr::write_bytes(storage, 0, 1) };
    match peer {
        SocketAddr::V4(addr) => {
            let raw = libc::sockaddr_in {
                sin_family: libc::AF_INET as libc::sa_family_t,
                sin_port: addr.port().to_be(),
                sin_addr: libc::in_addr {
                    s_addr: u32::from_ne_bytes(addr.ip().octets()),
                },
                sin_zero: [0; 8],
            };
            // SAFETY: sockaddr_storage is large/aligned enough for sockaddr_in and
            // is exclusively borrowed for this write.
            unsafe { (storage as *mut _ as *mut libc::sockaddr_in).write(raw) };
            mem::size_of::<libc::sockaddr_in>() as libc::socklen_t
        }
        SocketAddr::V6(addr) => {
            let raw = libc::sockaddr_in6 {
                sin6_family: libc::AF_INET6 as libc::sa_family_t,
                sin6_port: addr.port().to_be(),
                sin6_flowinfo: addr.flowinfo(),
                sin6_addr: libc::in6_addr {
                    s6_addr: addr.ip().octets(),
                },
                sin6_scope_id: addr.scope_id(),
            };
            // SAFETY: sockaddr_storage is large/aligned enough for sockaddr_in6 and
            // is exclusively borrowed for this write.
            unsafe { (storage as *mut _ as *mut libc::sockaddr_in6).write(raw) };
            mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t
        }
    }
}

/// Enumerate host interface names while guaranteeing `freeifaddrs` on every exit.
pub(crate) fn interface_names() -> io::Result<Vec<String>> {
    struct IfAddrs(*mut libc::ifaddrs);
    impl Drop for IfAddrs {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // SAFETY: the pointer came from a successful getifaddrs call and is
                // released exactly once by this owner.
                unsafe { libc::freeifaddrs(self.0) };
            }
        }
    }

    let mut head = std::ptr::null_mut();
    // SAFETY: `head` is a valid writable out-pointer.
    if unsafe { libc::getifaddrs(&mut head) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let list = IfAddrs(head);
    let mut seen = HashSet::new();
    let mut names = Vec::new();
    let mut cursor = list.0;
    while !cursor.is_null() {
        // SAFETY: getifaddrs returns a valid linked list through the owning head;
        // the list remains alive until `list` drops after this loop.
        let item = unsafe { &*cursor };
        if !item.ifa_name.is_null() {
            // SAFETY: libc guarantees that ifa_name is a NUL-terminated string for
            // every live entry in the getifaddrs list.
            let name = unsafe { CStr::from_ptr(item.ifa_name) }
                .to_string_lossy()
                .into_owned();
            if seen.insert(name.clone()) {
                names.push(name);
            }
        }
        cursor = item.ifa_next;
    }
    Ok(names)
}

pub(crate) fn interface_cstring(name: &str) -> io::Result<CString> {
    CString::new(name).map_err(|_| io::Error::other("interface name contains null byte"))
}

fn cvt_zero(rc: libc::c_int) -> io::Result<()> {
    if rc < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(test)]
#[path = "tests/sys.rs"]
mod tests;

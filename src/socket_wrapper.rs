use std::{net::SocketAddr, os::unix::io::{AsRawFd, RawFd}};

const MAX_DATAGRAMS : usize = 128;
// Custom wrapper for the raw socket file descriptor
pub struct CustomUdpSocket {
    fd: RawFd,
    //msghdrs: Box<[libc::mmsghdr; MAX_DATAGRAMS]>
}

// struct MmsgHdrWrapper(libc::mmsghdr);

// unsafe impl Sync for CustomUdpSocket {}
// unsafe impl Send for CustomUdpSocket {}

impl CustomUdpSocket {
    pub fn new(port: u16) -> std::io::Result<Self> {
        // Create UDP socket using libc
        let rcvbuf_size = 104857600; // 100MB
        let sndbuf_size = 104857600; // 100MB
        let fd = unsafe {
            libc::socket(
                libc::AF_INET,
                libc::SOCK_DGRAM | libc::SOCK_NONBLOCK,
                libc::IPPROTO_UDP,
            )
        };

        if fd == -1 {
            return Err(std::io::Error::last_os_error());
        }

        if let -1 = unsafe { libc::setsockopt(
            fd, 
            libc::SOL_SOCKET, 
            libc::SO_RCVBUF, 
            &rcvbuf_size as *const _ as *const libc::c_void, 
            std::mem::size_of_val(&rcvbuf_size) as u32) } 
        {
            return Err(std::io::Error::last_os_error());
        }

        if let -1 = unsafe { libc::setsockopt(
            fd, 
            libc::SOL_SOCKET, 
            libc::SO_SNDBUF, 
            &sndbuf_size as *const _ as *const libc::c_void, 
            std::mem::size_of_val(&sndbuf_size) as u32) } 
        {
            return Err(std::io::Error::last_os_error());
        }

        if let -1 = unsafe { libc::setsockopt(
            fd, 
            libc::IPPROTO_IP, 
            libc::IP_PKTINFO, 
            &true as *const _ as *const libc::c_void, 
            std::mem::size_of::<libc::c_int>() as libc::socklen_t) } 
        {
            return Err(std::io::Error::last_os_error());
        }

        // Prepare socket address
        let addr = libc::sockaddr_in {
            sin_family: libc::AF_INET as libc::sa_family_t,
            sin_port: port.to_be(),
            sin_addr: libc::in_addr {
                s_addr: libc::INADDR_ANY,
            },
            sin_zero: [0; 8],
        };

        // Set SO_PORT_REUSE
        if let -1 = unsafe {
            libc::setsockopt(
                fd, 
                libc::SOL_SOCKET, 
                libc::SO_REUSEPORT, 
                &1 as *const _ as *const libc::c_void, 
                std::mem::size_of_val(&1) as libc::socklen_t)
        } {
            return Err(std::io::Error::last_os_error());
        };

        // Bind socket
        let bind_result = unsafe {
            libc::bind(
                fd,
                &addr as *const libc::sockaddr_in as *const libc::sockaddr,
                std::mem::size_of_val(&addr) as libc::socklen_t,
            )
        };

        if bind_result == -1 {
            unsafe { libc::close(fd) };
            return Err(std::io::Error::last_os_error());
        }

        Ok(Self { fd })
    }

    
    // Read a single message using libc::recvfrom
    pub fn recv_from(&self, buf: &mut [u8]) -> std::io::Result<(usize, std::net::SocketAddr)> {
        let mut src_addr: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
        let mut addr_len = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;

        let bytes_read = unsafe {
            libc::recvfrom(
                self.fd,
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len(),
                0,
                &mut src_addr as *mut _ as *mut libc::sockaddr,
                &mut addr_len,
            )
        };

        if bytes_read == -1 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EAGAIN) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::WouldBlock,
                    "Operation would block",
                ));
            }
            return Err(err);
        }

        // Convert the source address to a Rust SocketAddr
        let src_addr = unsafe {
            std::net::SocketAddrV4::new(
                std::net::Ipv4Addr::from((*(&src_addr as *const _ as *const libc::sockaddr_in)).sin_addr.s_addr.to_ne_bytes()),
                u16::from_be((*(&src_addr as *const _ as *const libc::sockaddr_in)).sin_port),
            )
        };
        Ok((bytes_read as usize, std::net::SocketAddr::V4(src_addr)))
    }



    pub fn send_to(&self, buf: &[u8], addr: SocketAddr) -> std::io::Result<usize> {
        let (sin_family, sin_port, sin_addr) = match addr {
            SocketAddr::V4(addr) => (
                libc::AF_INET as libc::sa_family_t,
                addr.port().to_be(),
                libc::in_addr {
                    s_addr: u32::from_ne_bytes(addr.ip().octets()),
                },
            ),
            SocketAddr::V6(_) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Unsupported,
                    "IPv6 not supported in this example",
                ));
            }
        };

        let dest_addr = libc::sockaddr_in {
            sin_family,
            sin_port,
            sin_addr,
            sin_zero: [0; 8],
        };

        let bytes_sent = unsafe {
            libc::sendto(
                self.fd,
                buf.as_ptr() as *const libc::c_void,
                buf.len(),
                0,
                &dest_addr as *const libc::sockaddr_in as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            )
        };

        if bytes_sent == -1 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EAGAIN) || err.raw_os_error() == Some(libc::EWOULDBLOCK) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::WouldBlock,
                    "Operation would block",
                ));
            }
            return Err(err);
        }

        Ok(bytes_sent as usize)
    }


}


impl AsRawFd for CustomUdpSocket {
    fn as_raw_fd(&self) -> RawFd {
        self.fd
    }
}

impl Drop for CustomUdpSocket {
    fn drop(&mut self) {
        unsafe { libc::close(self.fd) };
    }
}
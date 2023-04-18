use bstr::ByteSlice;
use std::fmt::Display;
use std::{
    error::Error,
    fmt,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, ToSocketAddrs},
};
use tokio::io;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

// Const bytes
pub const VERSION5: u8 = 0x05;
pub const RESERVED: u8 = 0x00;

// Request command
pub enum Command {
    Connect = 0x01,
    Bind = 0x02,
    UdpAssosiate = 0x3,
}

impl Command {
    pub fn from(byte: usize) -> Option<Command> {
        match byte {
            1 => Some(Command::Connect),
            2 => Some(Command::Bind),
            3 => Some(Command::UdpAssosiate),
            _ => None,
        }
    }
}

#[derive(PartialEq)]
pub enum AuthMethod {
    NoAuth = 0x00,
    UserPass = 0x02,
    NoMethods = 0xFF,
}

pub enum SocksAddr<'a> {
    Ipv4(&'a [u8]),
    Domain(&'a [u8]),
    Ipv6(&'a [u8]),
}

impl<'a> fmt::Display for SocksAddr<'a> {
    fn fmt(&self, w: &mut fmt::Formatter) -> fmt::Result {
        match self {
            SocksAddr::Ipv4(b) => write!(w, "{}.{}.{}.{}", b[0], b[1], b[2], b[3]),
            SocksAddr::Domain(b) => write!(w, "{:?}", b.as_bstr()),
            SocksAddr::Ipv6(b) => write!(w, "[{:02X?}{:02X?}:{:02X?}{:02X?}:{:02X?}{:02X?}:{:02X?}{:02X?}:{:02X?}{:02X?}:{:02X?}{:02X?}:{:02X?}{:02X?}:{:02X?}{:02X?}]",
                                         b[0], b[1], b[2], b[3],
                                         b[4], b[5], b[6], b[7],
                                         b[8], b[9], b[10], b[11],
                                         b[12], b[13], b[14], b[15],
            ),
        }
    }
}

#[derive(Debug, Clone)]
pub enum TargetAddr {
    V4(SocketAddrV4),
    V6(SocketAddrV6),
    Domain((String, u16)),
}

#[derive(PartialEq)]
pub enum AddrType {
    V4 = 0x01,
    Domain = 0x03,
    V6 = 0x04,
}

impl TargetAddr {
    fn len(&self) -> usize {
        match self {
            TargetAddr::V4(_) => 4,
            TargetAddr::V6(_) => 16,
            TargetAddr::Domain((domain, _)) => domain.len() + 1,
        }
    }
    fn addr_type(&self) -> AddrType {
        match self {
            TargetAddr::V4(_) => AddrType::V4,
            TargetAddr::V6(_) => AddrType::V4,
            TargetAddr::Domain(_) => AddrType::Domain,
        }
    }
    fn write_to(&self, buf: &mut [u8]) {
        match self {
            TargetAddr::V4(addr) => {
                let mut ip = addr.ip().octets().to_vec();
                ip.extend(&addr.port().to_be_bytes());
                buf[..].copy_from_slice(&ip[..]);
            }
            TargetAddr::V6(addr) => {
                let mut ip = addr.ip().octets().to_vec();
                ip.extend(&addr.port().to_be_bytes());
                buf[..].copy_from_slice(&ip[..]);
            }
            TargetAddr::Domain((domain, port)) => {
                let mut ip = domain.as_bytes().to_vec();
                ip.extend(&port.to_be_bytes());
                buf[0] = domain.len() as u8;
                buf[1..].copy_from_slice(&ip[..]);
            }
        }
    }
}

impl AddrType {
    pub fn from(byte: usize) -> Option<AddrType> {
        match byte {
            1 => Some(AddrType::V4),
            3 => Some(AddrType::Domain),
            4 => Some(AddrType::V6),
            _ => None,
        }
    }

    pub async fn get_socket_addrs<S: AsyncRead + AsyncWrite + Unpin>(
        socket: &mut S,
    ) -> Result<Vec<SocketAddr>, Box<dyn Error>> {
        // Read address type
        let mut addr_type = [0u8; 1];
        socket.read_exact(&mut addr_type).await?;
        let addr_type = AddrType::from(addr_type[0] as usize);
        if addr_type.is_none() {
            Err(Response::AddrTypeNotSupported)?;
        }
        let addr_type = addr_type.unwrap();

        // Read address
        let addr;
        if let AddrType::Domain = addr_type {
            let mut dlen = [0u8; 1];
            socket.read_exact(&mut dlen).await?;
            let mut domain = vec![0u8; dlen[0] as usize];
            socket.read_exact(&mut domain).await?;
            addr = domain;
        } else if let AddrType::V4 = addr_type {
            let mut v4 = [0u8; 4];
            socket.read_exact(&mut v4).await?;
            addr = Vec::from(v4);
        } else {
            let mut v6 = [0u8; 16];
            socket.read_exact(&mut v6).await?;
            addr = Vec::from(v6);
        }

        // Read port
        let mut port = [0u8; 2];
        socket.read_exact(&mut port).await?;
        let port = (u16::from(port[0]) << 8) | u16::from(port[1]);

        // Return socket address vector
        match addr_type {
            AddrType::V6 => {
                let new_addr = (0..8)
                    .map(|x| (u16::from(addr[(x * 2)]) << 8) | u16::from(addr[(x * 2) + 1]))
                    .collect::<Vec<u16>>();
                Ok(vec![SocketAddr::from(SocketAddrV6::new(
                    Ipv6Addr::new(
                        new_addr[0],
                        new_addr[1],
                        new_addr[2],
                        new_addr[3],
                        new_addr[4],
                        new_addr[5],
                        new_addr[6],
                        new_addr[7],
                    ),
                    port,
                    0,
                    0,
                ))])
            }
            AddrType::V4 => Ok(vec![SocketAddr::from(SocketAddrV4::new(
                Ipv4Addr::new(addr[0], addr[1], addr[2], addr[3]),
                port,
            ))]),
            AddrType::Domain => {
                let mut domain = String::from_utf8_lossy(&addr[..]).to_string();
                domain.push_str(&":");
                domain.push_str(&port.to_string());
                Ok(domain.to_socket_addrs()?.collect())
            }
        }
    }
}

#[allow(dead_code)]
#[derive(Debug)]
pub enum Response {
    Success = 0x00,
    Failure = 0x01,
    RuleFailure = 0x02,
    NetworkUnreachable = 0x03,
    HostUnreachable = 0x04,
    ConnectionRefused = 0x05,
    TtlExpired = 0x06,
    CommandNotSupported = 0x07,
    AddrTypeNotSupported = 0x08,
}

impl Display for Response {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Error: {:?}", self)
    }
}

impl Error for Response {}

pub async fn socks_handshake<'a>(
    stream: &mut TcpStream,
    addr_buf: &'a mut [u8],
    user_pass: Option<(String, String)>,
) -> Result<(SocksAddr<'a>, u16), Box<dyn Error>> {
    let with_userpass = user_pass.is_some();
    let methods_len = if with_userpass { 2 } else { 1 };

    // Start SOCKS5 communication
    let mut data = vec![0; methods_len + 2];
    data[0] = VERSION5; // Set SOCKS version
    data[1] = methods_len as u8; // Set authentiaction methods count
    if with_userpass {
        data[2] = AuthMethod::UserPass as u8;
    }
    data[1 + methods_len] = AuthMethod::NoAuth as u8;
    stream.write_all(&mut data).await?;

    // Read method selection response
    let mut response = [0u8; 2];
    stream.read_exact(&mut response).await?;

    // Check SOCKS version
    if response[0] != VERSION5 {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Invalid SOCKS version",
        ))?;
    }

    if response[1] == AuthMethod::UserPass as u8 {
        if let Some((username, password)) = user_pass {
            // Send username & password
            let mut data = vec![0; username.len() + password.len() + 3];
            data[0] = VERSION5;
            data[1] = username.len() as u8;
            data[2..2 + username.len()].copy_from_slice(username.as_bytes());
            data[2 + username.len()] = password.len() as u8;
            data[3 + username.len()..].copy_from_slice(password.as_bytes());
            stream.write_all(&data).await?;

            // Read & check server response
            let mut response = [0; 2];
            stream.read_exact(&mut response).await?;
            if response[1] != Response::Success as u8 {
                Err(io::Error::new(
                    io::ErrorKind::Other,
                    "Wrong username/password",
                ))?;
            }
        } else {
            Err(io::Error::new(
                io::ErrorKind::Other,
                "Username & password requried",
            ))?;
        }
    } else if response[1] != AuthMethod::NoAuth as u8 {
        Err(io::Error::new(
            io::ErrorKind::Other,
            "Invalid authentication method",
        ))?;
    }
    let mut buf = [0u8; 2];
    stream.read_exact(&mut buf).await?;

    let n = buf[1] as usize;

    let mut buf = [0u8; 4];
    stream.read_exact(&mut buf[..n]).await?;
    let addr = match buf[3] {
        1 => {
            let buf = &mut addr_buf[..4];
            stream.read_exact(buf).await?;
            SocksAddr::Ipv4(buf)
        }
        3 => {
            let n = stream.read_u8().await? as usize;
            let buf = &mut addr_buf[..n];
            stream.read_exact(buf).await?;
            SocksAddr::Domain(buf)
        }
        4 => {
            let buf = &mut addr_buf[..16];
            stream.read_exact(buf).await?;
            SocksAddr::Ipv6(buf)
        }
        x => Err(io::Error::new(
            io::ErrorKind::Other,
            "Unsupported address type",
        ))?,
    };

    let port = stream.read_u16().await?;

    Ok((addr, port))
}

async fn connect(
    proxy_addr: &SocketAddr,
    addr: &SocksAddr<'_>,
    port: u16,
) -> Result<TcpStream, Box<dyn Error>> {
    log::debug!("Connecting to proxy server at {}", proxy_addr);
    let mut proxy = TcpStream::connect(proxy_addr).await?;
    log::debug!("Connected to {:?}", proxy_addr);

    proxy.write_all(&[5, 1, 0]).await?;

    let mut buf = [0u8; 2];
    proxy.read_exact(&mut buf).await?;

    if buf != [5, 0] {
        Err(io::Error::new(
            io::ErrorKind::Other,
            "Proxy didn't accept anonymous auth",
        ))?
    }

    let mut buf = vec![5, 1, 0];

    match addr {
        SocksAddr::Ipv4(b) => {
            buf.push(1);
            buf.extend(*b);
        }
        SocksAddr::Domain(b) => {
            buf.push(3);
            buf.push(b.len() as u8);
            buf.extend(*b);
        }
        SocksAddr::Ipv6(b) => {
            buf.push(4);
            buf.extend(*b);
        }
    }

    buf.extend(&port.to_be_bytes());

    proxy.write_all(&buf).await?;

    Ok(proxy)
}

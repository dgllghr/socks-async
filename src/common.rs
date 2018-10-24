use std::convert::TryFrom;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use tokio::io;
use tokio::net::TcpStream;
use tokio::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum CommandCode {
    Connect,
    Bind,
    Associate,
}

impl TryFrom<&u8> for CommandCode {
    type Error = io::Error;

    fn try_from(b: &u8) -> Result<Self, Self::Error> {
        match b {
            0x01 => Ok(CommandCode::Connect),
            0x02 => Ok(CommandCode::Bind),
            0x03 => Ok(CommandCode::Associate),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "command code not recognized",
            )),
        }
    }
}

impl Into<u8> for &CommandCode {
    fn into(self) -> u8 {
        match self {
            CommandCode::Connect => 0x01,
            CommandCode::Bind => 0x02,
            CommandCode::Associate => 0x03,
        }
    }
}

impl Into<u8> for CommandCode {
    fn into(self) -> u8 {
        (&self).into()
    }
}

#[derive(Clone, PartialEq, Eq, Hash)]
pub enum AddressType {
    IpV4,
    IpV6,
    DomainName,
}

impl TryFrom<&u8> for AddressType {
    type Error = io::Error;

    fn try_from(b: &u8) -> Result<Self, Self::Error> {
        match b {
            0x01 => Ok(AddressType::IpV4),
            0x04 => Ok(AddressType::IpV6),
            0x03 => Ok(AddressType::DomainName),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "address type not recognized",
            )),
        }
    }
}

impl Into<u8> for &AddressType {
    fn into(self) -> u8 {
        match self {
            AddressType::IpV4 => 0x01,
            AddressType::IpV6 => 0x04,
            AddressType::DomainName => 0x03,
        }
    }
}

impl Into<u8> for AddressType {
    fn into(self) -> u8 {
        (&self).into()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Address {
    Ip(SocketAddr),
    Domain(String, u16),
}

impl Address {
    pub fn address_type(&self) -> AddressType {
        match self {
            Address::Ip(SocketAddr::V4(_)) => AddressType::IpV4,
            Address::Ip(SocketAddr::V6(_)) => AddressType::IpV6,
            Address::Domain(_, _) => AddressType::DomainName,
        }
    }

    pub fn encode(&self, buf: &mut [u8]) -> usize {
        match self {
            Address::Ip(SocketAddr::V4(ip_v4)) => {
                buf[..4].clone_from_slice(&ip_v4.ip().octets()[..]);
                let port = ip_v4.port();
                buf[4] = ((port >> 8) & 0xFF) as u8;
                buf[5] = (port & 0xFF) as u8;
                6
            }
            Address::Ip(SocketAddr::V6(ip_v6)) => {
                buf[..16].clone_from_slice(&ip_v6.ip().octets()[..]);
                let port = ip_v6.port();
                buf[17] = ((port >> 8) & 0xFF) as u8;
                buf[18] = (port & 0xFF) as u8;
                18
            }
            Address::Domain(domain_name, port) => {
                let len = std::cmp::min(domain_name.len(), 255) as usize;
                buf[0] = len as u8;
                buf[1..(len + 1)].copy_from_slice(&domain_name[..len].as_bytes()[..]);
                buf[len + 1] = ((port >> 8) & (0xFF as u16)) as u8;
                buf[len + 2] = (port & 0xFF) as u8;
                len + 3
            }
        }
    }

    pub async fn decode<'a, R>(
        from: R,
        buf: &'a mut [u8],
        addr_type: &'a AddressType,
    ) -> io::Result<(R, Address)>
    where
        R: 'a + AsyncRead,
    {
        match addr_type {
            AddressType::IpV4 => {
                let (from, _) = await!(io::read_exact(from, &mut buf[..6]))?;
                let addr = parse_ip_v4(buf);
                Ok((from, addr))
            }
            AddressType::IpV6 => {
                let (from, _) = await!(io::read_exact(from, &mut buf[..18]))?;
                let addr = parse_ip_v6(buf);
                Ok((from, addr))
            }
            AddressType::DomainName => {
                let (from, _) = await!(io::read_exact(from, &mut buf[..1]))?;
                let buf_size = buf[0] as usize + 2;
                let (from, _) = await!(io::read_exact(from, &mut buf[1..(buf_size + 1)]))?;
                let addr = parse_domain_addr(buf);
                Ok((from, addr))
            }
        }
    }
}

fn parse_ip_v4(buf: &[u8]) -> Address {
    let addr = Ipv4Addr::new(buf[0], buf[1], buf[2], buf[3]);
    let port = ((buf[4] as u16) << 8) | (buf[5] as u16);
    Address::Ip(SocketAddr::V4(SocketAddrV4::new(addr, port)))
}

fn parse_ip_v6(buf: &[u8]) -> Address {
    let a = ((buf[0] as u16) << 8) | (buf[1] as u16);
    let b = ((buf[2] as u16) << 8) | (buf[3] as u16);
    let c = ((buf[4] as u16) << 8) | (buf[5] as u16);
    let d = ((buf[6] as u16) << 8) | (buf[7] as u16);
    let e = ((buf[8] as u16) << 8) | (buf[9] as u16);
    let f = ((buf[10] as u16) << 8) | (buf[11] as u16);
    let g = ((buf[12] as u16) << 8) | (buf[13] as u16);
    let h = ((buf[14] as u16) << 8) | (buf[15] as u16);
    let addr = Ipv6Addr::new(a, b, c, d, e, f, g, h);
    let port = ((buf[16] as u16) << 8) | (buf[17] as u16);
    Address::Ip(SocketAddr::V6(SocketAddrV6::new(addr, port, 0, 0)))
}

fn parse_domain_addr(buf: &[u8]) -> Address {
    let domain_length = buf[0] as usize;
    let split_point = domain_length + 1;
    let domain_name = String::from_utf8_lossy(&buf[1..split_point]);
    let port = ((buf[split_point] as u16) << 8) | (buf[split_point + 1] as u16);
    let addr = Address::Domain(domain_name.to_string(), port);
    addr
}

pub enum Reply {
    Success(TcpStream, Address),
    ServerFailure,
    ConnNotAllowed,
    NetworkUnreachable,
    HostUnreachable,
    ConnectionRefused,
    TtlExpired,
    CommandNotSupported,
    AddressTypeNotSupported,
    Other(u8, Option<TcpStream>),
}

impl Reply {
    pub fn code(&self) -> u8 {
        match self {
            Reply::Success(_, _) => 0x00,
            Reply::ServerFailure => 0x01,
            Reply::ConnNotAllowed => 0x02,
            Reply::NetworkUnreachable => 0x03,
            Reply::HostUnreachable => 0x04,
            Reply::ConnectionRefused => 0x05,
            Reply::TtlExpired => 0x06,
            Reply::CommandNotSupported => 0x07,
            Reply::AddressTypeNotSupported => 0x08,
            Reply::Other(code, _) => code.clone(),
        }
    }

    pub fn from_err_code(code: u8) -> Reply {
        match code {
            0x01 => Reply::ServerFailure,
            0x02 => Reply::ConnNotAllowed,
            0x03 => Reply::NetworkUnreachable,
            0x04 => Reply::HostUnreachable,
            0x05 => Reply::ConnectionRefused,
            0x06 => Reply::TtlExpired,
            0x07 => Reply::CommandNotSupported,
            0x08 => Reply::AddressTypeNotSupported,
            _ => Reply::Other(code, None),
        }
    }
}

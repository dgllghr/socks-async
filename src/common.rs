use bytes::BufMut;
use std::convert::TryFrom;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use tokio::io;
use tokio::net::TcpStream;

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

#[derive(Clone, PartialEq, Eq, Hash)]
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

    pub fn encode<B>(&self, buf: &mut B)
    where
        B: BufMut,
    {
        match self {
            Address::Ip(SocketAddr::V4(ip_v4)) => {
                buf.put_slice(&ip_v4.ip().octets());
                buf.put_u16_be(ip_v4.port());
            }
            Address::Ip(SocketAddr::V6(ip_v6)) => {
                buf.put_slice(&ip_v6.ip().octets());
                buf.put_u16_be(ip_v6.port());
            }
            Address::Domain(domain_name, port) => {
                buf.put_u8(domain_name.len() as u8);
                let len = std::cmp::min(domain_name.len(), 255);
                buf.put_slice(&domain_name[..len].as_bytes());
                buf.put_u16_be(*port);
            }
        }
    }

    pub fn decode<B>(address_type: &AddressType, buf: B) -> (Address, B)
    where
        B: AsRef<[u8]>,
    {
        match address_type {
            AddressType::IpV4 => parse_ip_v4(buf),
            AddressType::IpV6 => parse_ip_v6(buf),
            AddressType::DomainName => parse_domain_addr(buf),
        }
    }
}

fn parse_ip_v4<B>(buf: B) -> (Address, B)
where
    B: AsRef<[u8]>,
{
    let ba = buf.as_ref();
    let addr = Ipv4Addr::new(ba[0], ba[1], ba[2], ba[3]);
    let port = ((ba[4] as u16) << 8) | (ba[5] as u16);
    (
        Address::Ip(SocketAddr::V4(SocketAddrV4::new(addr, port))),
        buf,
    )
}

fn parse_ip_v6<B>(buf: B) -> (Address, B)
where
    B: AsRef<[u8]>,
{
    let ba = buf.as_ref();
    let a = ((ba[0] as u16) << 8) | (ba[1] as u16);
    let b = ((ba[2] as u16) << 8) | (ba[3] as u16);
    let c = ((ba[4] as u16) << 8) | (ba[5] as u16);
    let d = ((ba[6] as u16) << 8) | (ba[7] as u16);
    let e = ((ba[8] as u16) << 8) | (ba[9] as u16);
    let f = ((ba[10] as u16) << 8) | (ba[11] as u16);
    let g = ((ba[12] as u16) << 8) | (ba[13] as u16);
    let h = ((ba[14] as u16) << 8) | (ba[15] as u16);
    let addr = Ipv6Addr::new(a, b, c, d, e, f, g, h);
    let port = ((ba[16] as u16) << 8) | (ba[17] as u16);
    (
        Address::Ip(SocketAddr::V6(SocketAddrV6::new(addr, port, 0, 0))),
        buf,
    )
}

fn parse_domain_addr<B>(buf: B) -> (Address, B)
where
    B: AsRef<[u8]>,
{
    let ba = buf.as_ref();
    let domain_length = ba[0] as usize;
    let split_point = domain_length + 1;
    let domain_name = String::from_utf8_lossy(&ba[1..split_point]);
    let port = ((ba[split_point] as u16) << 8) | (ba[split_point + 1] as u16);
    let addr = Address::Domain(domain_name.to_string(), port);
    (addr, buf)
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

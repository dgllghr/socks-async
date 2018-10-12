use bytes::BufMut;
use std::convert::TryFrom;
use std::net::SocketAddr;
use tokio::io;

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
}

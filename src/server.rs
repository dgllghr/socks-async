use super::auth::*;
use super::common::*;
use bytes::{BufMut, BytesMut};
use std;
use std::collections::HashSet;
use std::convert::TryFrom;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::time::Duration;
use tokio::io;
use tokio::net::{TcpListener, TcpStream};
use tokio::prelude::*;

#[derive(Clone)]
pub struct Server<A: Clone, C: Clone> {
    auth: A,
    connector: C,
    handshake_timeout: Duration,
}

struct Greeting {
    client: TcpStream,
    buf: BytesMut,
    auth_methods: HashSet<AuthMethod>,
}

struct Request {
    client: TcpStream,
    buf: BytesMut,
    cmd_code: CommandCode,
    address: Address,
}

pub trait Connector {
    type R: ReplyMessage;
    type ConnectFuture: Future<Item=Self::R, Error=io::Error> + Send;
    
    fn connect(&self, address: &Address) -> Self::ConnectFuture;
}

/// Simple connector that can connect to IP addresses. Does not support DNS
/// lookups and cannot connect to domains. A request with a domain address
/// will result in reply code 0x08: address type not supported
#[derive(Clone)]
pub struct DefaultConnector;

pub trait ReplyMessage {
    type Future: Future<Item=(TcpStream, BytesMut), Error=io::Error> + Send;
    
    fn send(&self, address: &Address, client: TcpStream, buf: BytesMut) -> Self::Future;
    fn connection(self) -> Option<TcpStream>;
}

pub enum Reply {
    Success(TcpStream),
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

pub struct RawReply {
    connection: Option<TcpStream>,
    message: BytesMut,
}

impl<A, R, C> Server<A, C>
where
    A: 'static + AuthProtocol + Clone + Send,
    R: 'static + ReplyMessage + Send,
    C: 'static + Connector<R=R> + Clone + Send,
{
    pub fn new(auth: A, connector: C, handshake_timeout: Duration) -> Server<A, C> {
        Server {
            auth,
            connector,
            handshake_timeout,
        }
    }

    pub async fn listen(self, addr: SocketAddr) -> std::io::Result<()> {
        let listener = TcpListener::bind(&addr)?;
        let mut incoming = listener.incoming();
        while let Some(stream) = await!(incoming.next()) {
            let server = self.clone();
            let client = stream?;
            tokio::spawn_async(async move {
                match await!(server.client_handler(client)) {
                    Ok(_) => (),
                    Err(err) => println!("error in socks connection. {:?}", err),
                }
            });
        }
        Ok(())
    }

    async fn client_handler(self, client: TcpStream) -> io::Result<()> {
        // TODO handshake timeout
        let buf = BytesMut::with_capacity(257);
        let greeting = await!(recv_greeting(client, buf))?;
        if greeting.auth_methods.is_empty() {
            await!(reject_greeting(greeting.client))?;
            return Err(io::Error::new(io::ErrorKind::Other, "no auth methods"));
        }

        let server_auth_methods = self.auth.methods();
        let auth_method = select_auth_method(&server_auth_methods, &greeting.auth_methods);
        if let None = auth_method {
            await!(reject_greeting(greeting.client))?;
            return Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "no acceptable auth methods"
            ));
        }
        let client = await!(accept_greeting(greeting.client, auth_method.as_ref().unwrap()))?;

        let auth_result = await!(self.auth.authenticate(client, auth_method.unwrap(), greeting.buf))?;
        if !auth_result.authenticated {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "authentication failed. access denied."
            ));
        }

        let request = await!(recv_conn_request(auth_result.client, auth_result.buf))?;
        if request.cmd_code != CommandCode::Connect {
            await!(Reply::CommandNotSupported.send(&request.address, request.client, request.buf))?;
            return Err(io::Error::new(io::ErrorKind::ConnectionRefused, "command not supported."));
        }
        let reply = await!(self.connector.connect(&request.address))?;
        let (client, _) = await!(reply.send(&request.address, request.client, request.buf))?;
        match reply.connection() {
            Some(c) => await!(copy(client, c)),
            None => Ok(()),
        }
    }
}

impl Default for Server<NoAuth, DefaultConnector> {
    fn default() -> Self {
        Server {
            auth: NoAuth,
            connector: DefaultConnector,
            handshake_timeout: Duration::from_secs(3),
        }
    }
}

impl Default for DefaultConnector {
    fn default() -> Self {
        DefaultConnector {}
    }
}

impl Connector for DefaultConnector {
    type R = Reply;
    type ConnectFuture = Box<Future<Item=Self::R, Error=io::Error> + Send>;

    fn connect(&self, address: &Address) -> Box<Future<Item=Self::R, Error=io::Error> + Send> {
        match address {
            Address::Ip(addr) => {
                let f = TcpStream::connect(addr)
                    .map(|c| Reply::Success(c))
                    .or_else(|err| {
                        let reply = match err.kind() {
                            io::ErrorKind::ConnectionRefused => Reply::ConnectionRefused,
                            io::ErrorKind::AddrNotAvailable => Reply::HostUnreachable,
                            io::ErrorKind::PermissionDenied => Reply::ConnNotAllowed,
                            _ => Reply::ServerFailure,
                        };
                        future::ok(reply)
                    });
                Box::new(f)
            }
            Address::Domain(_, _) => {
                Box::new(future::ok(Reply::AddressTypeNotSupported))
            }
        } 
    }
}

impl Reply {
    fn code(&self) -> u8 {
        match self {
            Reply::Success(_) => 0x00,
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
}

impl ReplyMessage for Reply {
    type Future = io::WriteAll<TcpStream, BytesMut>;

    fn connection(self) -> Option<TcpStream> {
        match self {
            Reply::Success(conn) => Some(conn),
            Reply::Other(_, conn) => conn,
            _ => None,
        }
    }

    fn send(&self, address: &Address, client: TcpStream, mut buf: BytesMut) -> Self::Future {
        buf.clear();
        let addr_type = (&address.address_type()).into();
        buf.put_slice(&[0x05, self.code(), 0x00, addr_type]);
        address.encode(&mut buf);
        io::write_all(client, buf.take())
    }
}

impl ReplyMessage for RawReply {
    type Future = io::WriteAll<TcpStream, BytesMut>;

    fn connection(self) -> Option<TcpStream> {
        self.connection
    }

    fn send(&self, _address: &Address, client: TcpStream, _buf: BytesMut) -> Self::Future {
        io::write_all(client, self.message.clone())
    }
}

async fn recv_greeting(client: TcpStream, mut buf: BytesMut) -> std::io::Result<Greeting> {
    buf.resize(2, 0);
    let (client, mut buf) = await!(io::read_exact(client, buf))?;
    if buf[0] != 0x05 {
        return Err(io::Error::new(io::ErrorKind::Other, "invalid version. only socks5 supported."));
    }
    let num_auth_methods = buf[1];
    buf.resize(num_auth_methods as usize, 0);
    let (client, buf) = await!(io::read_exact(client, buf))?;
    let auth_methods = buf.iter().map(|b| b.into()).collect();
    Ok(Greeting { client, buf, auth_methods })
}

async fn accept_greeting(client: TcpStream, auth_method: &AuthMethod) -> std::io::Result<TcpStream> {
    let (client, _) = await!(io::write_all(client, [0x05, auth_method.into()]))?;
    Ok(client)
}

async fn reject_greeting(client: TcpStream) -> std::io::Result<()> {
    let _ = await!(io::write_all(client, [0x05, 0xff]))?;
    Ok(())
}

fn select_auth_method<'a, 'b>(
    server_auth_methods: &'a [AuthMethod],
    client_auth_methods: &'b HashSet<AuthMethod>,
) -> Option<&'a AuthMethod> {
    for am in server_auth_methods {
        if client_auth_methods.contains(&am) {
            return Some(am)
        }
    }
    None
}

async fn recv_conn_request(client: TcpStream, mut buf: BytesMut) -> std::io::Result<Request> {
    buf.resize(4, 0);
    let (client, buf) = await!(io::read_exact(client, buf))?;
    if buf[0] != 0x05 {
        return Err(io::Error::new(io::ErrorKind::Other, "invalid version. only socks5 supported."));
    }
    let cmd_code = CommandCode::try_from(&buf[1])?;
    if buf[2] != 0 {
        return Err(io::Error::new(io::ErrorKind::Other, "invalid reserved byte."));
    }
    let addr_type = AddressType::try_from(&buf[3])?;
    let (client, buf, address) = await!(parse_address(client, buf, addr_type))?;
    Ok(Request { client, buf, cmd_code, address })
}

async fn parse_address(
    client: TcpStream,
    mut buf: BytesMut,
    addr_type: AddressType,
) -> io::Result<(TcpStream, BytesMut, Address)> {
    match addr_type {
        AddressType::IpV4 => {
            buf.resize(6, 0);
            let (client, buf) = await!(io::read_exact(client, buf))?;
            let (ip_v4, buf) = parse_ip_v4(buf);
            let addr = Address::Ip(SocketAddr::V4(ip_v4));
            Ok((client, buf, addr))
        }
        AddressType::IpV6 => {
            buf.resize(18, 0);
            let (client, buf) = await!(io::read_exact(client, buf))?;
            let (ip_v6, buf) = parse_ip_v6(buf);
            let addr = Address::Ip(SocketAddr::V6(ip_v6));
            Ok((client, buf, addr))
        }
        AddressType::DomainName => {
            let (client, ds_buf) = await!(io::read_exact(client, [0]))?;
            let domain_length = ds_buf[0] as usize;
            buf.resize(domain_length + 2, 0);
            let (client, buf) = await!(io::read_exact(client, buf))?;
            let (domain_name, port, buf) = parse_domain_addr(buf, domain_length)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            let addr = Address::Domain(domain_name.to_string(), port);
            Ok((client, buf, addr))
        }
    }
}

fn parse_ip_v4(buf: BytesMut) -> (SocketAddrV4, BytesMut) {
    let addr = Ipv4Addr::new(buf[0], buf[1], buf[2], buf[3]);
    let port = ((buf[4] as u16) << 8) | (buf[5] as u16);
    (SocketAddrV4::new(addr, port), buf)
}

fn parse_ip_v6(buf: BytesMut) -> (SocketAddrV6, BytesMut) {
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
    (SocketAddrV6::new(addr, port, 0, 0), buf)
}

fn parse_domain_addr(
    buf: BytesMut,
    domain_length: usize,
) -> Result<(String, u16, BytesMut), std::str::Utf8Error> {
    let (d, p) = buf.split_at(domain_length);
    let domain_name = std::str::from_utf8(d)?;
    let port = ((p[0] as u16) << 8) | (p[1] as u16);
    Ok((domain_name.to_string(), port, buf))
}

async fn copy(left: TcpStream, right: TcpStream) -> io::Result<()> {
    let (left_reader, left_writer) = left.split();
    let (right_reader, right_writer) = right.split();
    let result = await!(io::copy(left_reader, right_writer)
        .select2(io::copy(right_reader, left_writer)));
    match result {
        Ok(_) => Ok(()),
        // TODO investigate this error system
        Err(_) => Err(io::Error::new(io::ErrorKind::Other, "error transferring data"))
    }
}

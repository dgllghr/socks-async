pub use super::auth::*;
pub use super::common::*;
use std;
use std::collections::HashSet;
use std::convert::TryFrom;
use std::net::SocketAddr;
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
    auth_methods: HashSet<AuthMethod>,
}

#[derive(Debug)]
struct Request {
    client: TcpStream,
    cmd_code: CommandCode,
    address: Address,
}

pub trait Connector {
    type R: ReplyMessage;
    type ConnectFuture: Future<Item = Self::R, Error = io::Error> + Send;

    fn connect(&self, address: &Address) -> Self::ConnectFuture;
}

/// Simple connector that can connect to IP addresses. Does not support DNS
/// lookups and cannot connect to domains. A request with a domain address
/// will result in reply code 0x08: address type not supported
#[derive(Clone)]
pub struct DefaultConnector;

pub trait ReplyMessage {
    fn connection(self) -> Option<TcpStream>;
    fn encode<'a>(&'a self, address: &'a Address, buf: &'a mut [u8]) -> &'a [u8];
}

pub struct RawReply {
    connection: Option<TcpStream>,
    message: Vec<u8>,
}

impl<A, R, C> Server<A, C>
where
    A: 'static + AuthServerProtocol + Clone + Send,
    R: 'static + ReplyMessage + Send,
    C: 'static + Connector<R = R> + Clone + Send,
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
            tokio::spawn_async(
                async move {
                    match await!(server.client_handler(client)) {
                        Ok(_) => (),
                        Err(err) => println!("error in socks connection. {:?}", err),
                    }
                },
            );
        }
        Ok(())
    }

    async fn client_handler(self, client: TcpStream) -> io::Result<()> {
        // TODO handshake timeout
        let mut buf = Vec::with_capacity(257);
        buf.resize(257, 0);
        let greeting = await!(recv_greeting(client, &mut buf[..]))?;
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
                "no acceptable auth methods",
            ));
        }
        let client = await!(accept_greeting(
            greeting.client,
            auth_method.as_ref().unwrap()
        ))?;

        let auth_result = await!(self.auth.check_auth(client, auth_method.unwrap(), buf))?;
        if !auth_result.authorized {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "authentication failed. access denied.",
            ));
        }

        let client = auth_result.conn;
        let mut buf = auth_result.buf;
        buf.resize(257, 0);
        let request = await!(recv_conn_request(client, &mut buf[..]))?;
        let client = request.client;
        if request.cmd_code != CommandCode::Connect {
            let reply_buf = Reply::CommandNotSupported.encode(&request.address, &mut buf[..]);
            await!(io::write_all(client, reply_buf))?;
            return Err(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                "command not supported.",
            ));
        }
        let reply = await!(self.connector.connect(&request.address))?;
        let reply_buf = reply.encode(&request.address, &mut buf[..]);
        let (client, _) = await!(io::write_all(client, reply_buf))?;
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
    type ConnectFuture = Box<Future<Item = Self::R, Error = io::Error> + Send>;

    fn connect(&self, address: &Address) -> Box<Future<Item = Self::R, Error = io::Error> + Send> {
        let address = address.clone();
        match address {
            Address::Ip(addr) => {
                let f = TcpStream::connect(&addr)
                    // TODO use actual instead of provided address?
                    .map(|c| Reply::Success(c, address))
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
            Address::Domain(_, _) => Box::new(future::ok(Reply::AddressTypeNotSupported)),
        }
    }
}

impl ReplyMessage for Reply {
    fn connection(self) -> Option<TcpStream> {
        match self {
            Reply::Success(conn, _) => Some(conn),
            Reply::Other(_, conn) => conn,
            _ => None,
        }
    }

    fn encode<'a>(&'a self, address: &'a Address, buf: &'a mut [u8]) -> &'a [u8] {
        let addr_type = (&address.address_type()).into();
        buf[..4].clone_from_slice(&[0x05, self.code(), 0x00, addr_type][..]);
        let size = address.encode(&mut buf[4..]);
        &buf[..(size + 4)]
    }
}

impl ReplyMessage for RawReply {
    fn connection(self) -> Option<TcpStream> {
        self.connection
    }

    fn encode(&self, _address: &Address, _buf: &mut [u8]) -> &[u8] {
        &self.message[..]
    }
}

async fn recv_greeting(client: TcpStream, buf: &mut [u8]) -> std::io::Result<Greeting> {
    let (client, _) = await!(io::read_exact(client, &mut buf[..2]))?;
    if buf[0] != 0x05 {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            "invalid version. only socks5 supported.",
        ));
    }
    let num_auth_methods = buf[1] as usize;
    let (client, buf) = await!(io::read_exact(client, &mut buf[..num_auth_methods]))?;
    let auth_methods = buf.iter().map(|b| b.into()).collect();
    Ok(Greeting {
        client,
        auth_methods,
    })
}

async fn accept_greeting(
    client: TcpStream,
    auth_method: &AuthMethod,
) -> std::io::Result<TcpStream> {
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
            return Some(am);
        }
    }
    None
}

async fn recv_conn_request(client: TcpStream, buf: &mut [u8]) -> std::io::Result<Request> {
    let (client, _) = await!(io::read_exact(client, &mut buf[..4]))?;
    if buf[0] != 0x05 {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            "invalid version. only socks5 supported.",
        ));
    }
    let cmd_code = CommandCode::try_from(&buf[1])?;
    if buf[2] != 0 {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            "invalid reserved byte.",
        ));
    }
    let addr_type = AddressType::try_from(&buf[3])?;
    let (client, address) = await!(Address::decode(client, buf, &addr_type))?;
    Ok(Request {
        client,
        cmd_code,
        address,
    })
}

async fn copy(left: TcpStream, right: TcpStream) -> io::Result<()> {
    let (left_reader, left_writer) = left.split();
    let (right_reader, right_writer) = right.split();
    let result =
        await!(io::copy(left_reader, right_writer).select2(io::copy(right_reader, left_writer)));
    match result {
        Ok(_) => Ok(()),
        // TODO investigate this error system
        Err(_) => Err(io::Error::new(
            io::ErrorKind::Other,
            "error transferring data",
        )),
    }
}

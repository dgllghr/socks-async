pub use super::auth::*;
pub use super::common::*;
use bytes::{BufMut, BytesMut};
use std::convert::TryFrom;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io;
use tokio::net::TcpStream;

#[derive(Clone)]
pub struct Client<A: Clone> {
    auth: A,
    handshake_timeout: Duration,
}

impl<A> Client<A>
where
    A: 'static + AuthClientProtocol + Clone + Send,
{
    pub fn new(auth: A, handshake_timeout: Duration) -> Client<A> {
        Client {
            auth,
            handshake_timeout,
        }
    }

    pub async fn connect(
        &self,
        socks_server_addr: SocketAddr,
        target_addr: Address
    ) -> io::Result<Reply> {
        let buf = BytesMut::with_capacity(262);
        let server = await!(TcpStream::connect(&socks_server_addr))?;
        let (server, _) = await!(self.establish(server, buf, target_addr))?;
        Ok(server)
    }

    async fn establish(
        &self,
        server: TcpStream,
        buf: BytesMut,
        address: Address,
    ) -> io::Result<(Reply, BytesMut)> {
        let auth_methods = &self.auth.methods();
        let (server, buf) = await!(send_greeting(server, buf, auth_methods))?;
        let (server, buf, auth_method) = await!(recv_greeting_response(server, buf))?;
        if !auth_methods.contains(&auth_method) {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "server returned unexpected auth method",
            ));
        }

        // auth
        let auth_result = await!(self.auth.send_auth(server, &auth_method, buf))?;
        if !auth_result.authorized {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "authorization failed",
            ));
        }

        // request/reply
        let (server, buf) = await!(send_request(auth_result.conn, auth_result.buf, &address))?;
        await!(recv_reply(server, buf))
    }
}

async fn send_greeting(
    server: TcpStream,
    mut buf: BytesMut,
    auth_methods: &[AuthMethod],
) -> io::Result<(TcpStream, BytesMut)> {
    buf.clear();
    let num_auth_methods = auth_methods.len();
    buf.put_slice(&[0x05, num_auth_methods as u8]);
    for m in auth_methods {
        buf.put_u8(m.into());
    }
    await!(io::write_all(server, buf))
}

async fn recv_greeting_response(
    server: TcpStream,
    mut buf: BytesMut,
) -> io::Result<(TcpStream, BytesMut, AuthMethod)> {
    buf.resize(2, 0);
    let (server, buf) = await!(io::read_exact(server, buf))?;
    if buf[0] != 0x05 {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            "invalid version. only socks5 supported.",
        ));
    }
    if buf[1] == 0xFF {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            "no acceptable auth methods",
        ));
    }
    let auth_method = buf[1].into();
    Ok((server, buf, auth_method))
}

async fn send_request(
    server: TcpStream,
    mut buf: BytesMut,
    addr: &Address,
) -> io::Result<(TcpStream, BytesMut)> {
    buf.clear();
    let cmd = CommandCode::Connect.into();
    let addr_type = addr.address_type().into();
    buf.put_slice(&[0x05, cmd, 0x00, addr_type]);
    addr.encode(&mut buf);
    await!(io::write_all(server, buf))
}

async fn recv_reply(server: TcpStream, mut buf: BytesMut) -> io::Result<(Reply, BytesMut)> {
    buf.resize(4, 0);
    let (server, buf) = await!(io::read_exact(server, buf))?;
    if buf[0] != 0x05 {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            "invalid version. only socks5 supported.",
        ));
    }
    if buf[2] != 0x00 {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            "invalid reserved byte.",
        ));
    }
    // TODO convert to appropriate response
    if buf[1] != 0x00 {
        let reply = Reply::from_err_code(buf[1]);
        return Ok((reply, buf));
    }

    let addr_type = AddressType::try_from(&buf[3])?;
    let (server, mut buf, start) = await!(prepare_address_buf(server, buf, &addr_type))?;
    let (server, _) = await!(io::read_exact(server, &mut buf[start..]))?;
    let (addr, buf) = Address::decode(&addr_type, buf);

    Ok((Reply::Success(server, addr), buf))
}

async fn prepare_address_buf(
    server: TcpStream,
    mut buf: BytesMut,
    addr_type: &AddressType,
) -> io::Result<(TcpStream, BytesMut, usize)> {
    match addr_type {
        AddressType::IpV4 => {
            buf.resize(6, 0);
            Ok((server, buf, 0))
        }
        AddressType::IpV6 => {
            buf.resize(18, 0);
            Ok((server, buf, 0))
        }
        AddressType::DomainName => {
            buf.resize(1, 0);
            let (server, mut buf) = await!(io::read_exact(server, buf))?;
            buf.resize(buf[0] as usize + 3, 0);
            Ok((server, buf, 1))
        }
    }
}

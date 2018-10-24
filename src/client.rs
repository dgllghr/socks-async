pub use super::auth::*;
pub use super::common::*;
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
        target_addr: Address,
    ) -> io::Result<Reply> {
        let mut buf = Vec::with_capacity(520);
        buf.resize(520, 0);
        let server = await!(TcpStream::connect(&socks_server_addr))?;
        let reply = await!(self.establish(server, buf, target_addr))?;
        Ok(reply)
    }

    async fn establish<'a>(
        &'a self,
        server: TcpStream,
        mut buf: Vec<u8>,
        address: Address,
    ) -> io::Result<Reply> {
        let auth_methods = &self.auth.methods();
        let server = await!(send_greeting(server, &mut buf[..], auth_methods))?;
        let (server, auth_method) = await!(recv_greeting_response(server, &mut buf[..]))?;
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
        let mut buf = auth_result.buf;
        buf.resize(520, 0);

        // request/reply
        let server = await!(send_request(auth_result.conn, &mut buf[..], &address))?;
        await!(recv_reply(server, &mut buf[..]))
    }
}

async fn send_greeting<'a>(
    server: TcpStream,
    buf: &'a mut [u8],
    auth_methods: &'a [AuthMethod],
) -> io::Result<TcpStream> {
    let num_auth_methods = auth_methods.len();
    buf[..2].copy_from_slice(&[0x05, num_auth_methods as u8][..]);
    for (i, m) in auth_methods.iter().enumerate() {
        buf[i + 2] = m.into();
    }
    let buf_size = auth_methods.len() + 2;
    let (server, _) = await!(io::write_all(server, &buf[..buf_size]))?;
    Ok(server)
}

async fn recv_greeting_response(
    server: TcpStream,
    buf: &mut [u8],
) -> io::Result<(TcpStream, AuthMethod)> {
    let (server, _) = await!(io::read_exact(server, &mut buf[..2]))?;
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
    Ok((server, auth_method))
}

async fn send_request<'a>(
    server: TcpStream,
    buf: &'a mut [u8],
    addr: &'a Address,
) -> io::Result<TcpStream> {
    let cmd = CommandCode::Connect.into();
    let addr_type = addr.address_type().into();
    buf[..4].copy_from_slice(&[0x05, cmd, 0x00, addr_type][..]);
    let addr_length = addr.encode(&mut buf[4..]);
    let buf_size = addr_length + 4;
    let (server, _) = await!(io::write_all(server, &buf[..buf_size]))?;
    Ok(server)
}

async fn recv_reply(server: TcpStream, buf: &mut [u8]) -> io::Result<Reply> {
    let (server, _) = await!(io::read_exact(server, &mut buf[..4]))?;
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
        return Ok(reply);
    }

    let addr_type = AddressType::try_from(&buf[3])?;
    let (server, addr) = await!(Address::decode(server, &mut buf[..], &addr_type))?;
    Ok(Reply::Success(server, addr))
}

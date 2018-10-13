use bytes::BytesMut;
use tokio::io;
use tokio::net::TcpStream;
use tokio::prelude::*;

#[derive(Clone, PartialEq, Eq, Hash)]
pub enum AuthMethod {
    NoAuth,
    UserPass,
    Other(u8),
}

impl From<&u8> for AuthMethod {
    fn from(b: &u8) -> Self {
        match b {
            0x00 => AuthMethod::NoAuth,
            0x02 => AuthMethod::UserPass,
            _ => AuthMethod::Other(b.clone()),
        }
    }
}

impl Into<u8> for &AuthMethod {
    fn into(self) -> u8 {
        match self {
            AuthMethod::NoAuth => 0x00,
            AuthMethod::UserPass => 0x02,
            AuthMethod::Other(b) => b.clone(),
        }
    }
}

impl Into<u8> for AuthMethod {
    fn into(self) -> u8 {
        (&self).into()
    }
}

pub struct AuthResult {
    pub authorized: bool,
    pub client: TcpStream,
    pub buf: BytesMut,
}

pub trait AuthProtocol {
    type Future: Future<Item = AuthResult, Error = std::io::Error> + Send;

    fn methods(&self) -> Vec<AuthMethod>;
    fn authenticate(
        &self,
        client: TcpStream,
        auth_method: &AuthMethod,
        buf: BytesMut,
    ) -> Self::Future;
}

#[derive(Clone)]
pub struct NoAuth;

impl AuthProtocol for NoAuth {
    type Future = future::FutureResult<AuthResult, io::Error>;

    fn methods(&self) -> Vec<AuthMethod> {
        vec![AuthMethod::NoAuth]
    }

    fn authenticate(
        &self,
        client: TcpStream,
        _auth_method: &AuthMethod,
        buf: BytesMut,
    ) -> Self::Future {
        future::ok(AuthResult {
            authorized: true,
            client,
            buf,
        })
    }
}

#[derive(Clone)]
pub struct UserPassAuth {
    pub username: String,
    pub password: String,
}

impl UserPassAuth {
    pub fn new(username: &str, password: &str) -> UserPassAuth {
        UserPassAuth { username: username.to_string(), password: password.to_string() }
    }
}

impl AuthProtocol for UserPassAuth {
    type Future = Box<Future<Item = AuthResult, Error = std::io::Error> + Send>;

    fn methods(&self) -> Vec<AuthMethod> {
        vec![AuthMethod::UserPass]
    }

    fn authenticate(
        &self,
        client: TcpStream,
        _auth_method: &AuthMethod,
        buf: BytesMut,
    ) -> Self::Future {
        let server_username = self.username.clone();
        let server_password = self.password.clone();
        let f = recv_username_password(client, buf)
            .and_then(move |(client, buf, username, password)| {
                let unauthorized = username != server_username || password != server_password;
                let response_code = if unauthorized { 0xff } else { 0x00 };
                io::write_all(client, [0x01, response_code])
                    .map(move |(client, _)| AuthResult{ client, buf, authorized: !unauthorized })
            });
        Box::new(f)
    }
}

fn recv_username_password(
    conn: TcpStream,
    mut buf: BytesMut,
) -> Box<Future<Item=(TcpStream, BytesMut, String, String), Error=io::Error> + Send> {
    buf.resize(2, 0);
    let f = io::read_exact(conn, buf)
        .and_then(|(conn, mut buf)| -> Box<Future<Item=(TcpStream, BytesMut), Error=io::Error> + Send> {
            if buf[0] != 0x01 {
                Box::new(Err(io::Error::new(
                    io::ErrorKind::Other,
                    "invalid version. only socks5 supported.",
                )).into_future())
            } else {
                let username_len = buf[1] as usize;
                buf.resize(username_len + 1, 0);
                Box::new(io::read_exact(conn, buf))
            }
        })
        .and_then(|(conn, mut buf)| {
            let username_len = buf.len() - 1;
            let username = String::from_utf8_lossy(&buf[..username_len]).into_owned();
            let password_len = buf[username_len] as usize;
            buf.resize(password_len, 0);
            io::read_exact(conn, buf)
                .map(move |(conn, buf)| {
                    let password = String::from_utf8_lossy(&buf[..]).into_owned();
                    (conn, buf, username, password)
                })
        });
    Box::new(f)
}

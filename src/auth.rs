use std::fmt;
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

impl From<u8> for AuthMethod {
    fn from(b: u8) -> Self {
        AuthMethod::from(&b)
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
    pub conn: TcpStream,
    pub buf: Vec<u8>,
}

pub trait AuthServerProtocol {
    type Future: Future<Item = AuthResult, Error = std::io::Error> + Send;

    fn methods(&self) -> Vec<AuthMethod>;
    fn check_auth(&self, client: TcpStream, auth_method: &AuthMethod, buf: Vec<u8>)
        -> Self::Future;
}

pub trait AuthClientProtocol {
    type Future: Future<Item = AuthResult, Error = std::io::Error> + Send;

    fn methods(&self) -> Vec<AuthMethod>;
    fn send_auth(&self, server: TcpStream, auth_method: &AuthMethod, buf: Vec<u8>) -> Self::Future;
}

#[derive(Clone)]
pub struct NoAuth;

impl AuthServerProtocol for NoAuth {
    type Future = future::FutureResult<AuthResult, io::Error>;

    fn methods(&self) -> Vec<AuthMethod> {
        vec![AuthMethod::NoAuth]
    }

    fn check_auth(
        &self,
        client: TcpStream,
        _auth_method: &AuthMethod,
        buf: Vec<u8>,
    ) -> Self::Future {
        future::ok(AuthResult {
            authorized: true,
            conn: client,
            buf,
        })
    }
}

impl AuthClientProtocol for NoAuth {
    type Future = future::FutureResult<AuthResult, io::Error>;

    fn methods(&self) -> Vec<AuthMethod> {
        vec![AuthMethod::NoAuth]
    }

    fn send_auth(
        &self,
        server: TcpStream,
        _auth_method: &AuthMethod,
        buf: Vec<u8>,
    ) -> Self::Future {
        future::ok(AuthResult {
            authorized: true,
            conn: server,
            buf,
        })
    }
}

#[derive(Debug, Copy, Clone)]
pub struct InvalidCredentialsError;

impl fmt::Display for InvalidCredentialsError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt("invalid credentials. must be <= 255 bytes", f)
    }
}

#[derive(Clone)]
pub struct UserPassAuth {
    pub username: Vec<u8>,
    pub password: Vec<u8>,
}

impl UserPassAuth {
    pub fn new(username: &str, password: &str) -> Result<UserPassAuth, InvalidCredentialsError> {
        let u_bytes = username.as_bytes();
        let p_bytes = password.as_bytes();
        if p_bytes.len() > 255 || p_bytes.len() > 255 {
            return Err(InvalidCredentialsError);
        }
        Ok(UserPassAuth {
            username: u_bytes.to_vec(),
            password: p_bytes.to_vec(),
        })
    }
}

impl AuthServerProtocol for UserPassAuth {
    type Future = Box<Future<Item = AuthResult, Error = std::io::Error> + Send>;

    fn methods(&self) -> Vec<AuthMethod> {
        vec![AuthMethod::UserPass]
    }

    fn check_auth(
        &self,
        client: TcpStream,
        _auth_method: &AuthMethod,
        buf: Vec<u8>,
    ) -> Self::Future {
        let server_username = self.username.clone();
        let server_password = self.password.clone();
        let f = recv_username_password(client, buf).and_then(
            move |(client, buf, username, password)| {
                let unauthorized = username != server_username || password != server_password;
                let response_code = if unauthorized { 0xff } else { 0x00 };
                io::write_all(client, [0x01, response_code]).map(move |(client, _)| AuthResult {
                    conn: client,
                    buf,
                    authorized: !unauthorized,
                })
            },
        );
        Box::new(f)
    }
}

impl AuthClientProtocol for UserPassAuth {
    type Future = Box<Future<Item = AuthResult, Error = std::io::Error> + Send>;

    fn methods(&self) -> Vec<AuthMethod> {
        vec![AuthMethod::UserPass]
    }

    fn send_auth(
        &self,
        server: TcpStream,
        _auth_method: &AuthMethod,
        mut buf: Vec<u8>,
    ) -> Self::Future {
        let username_size = self.username.len();
        let buf_size = username_size + self.password.len() + 3;
        buf.resize(buf_size, 0);
        buf[0] = 0x01;
        buf[1] = self.username.len() as u8;
        buf[2..(username_size + 2)].copy_from_slice(&self.username[..]);
        buf[username_size + 2] = self.password.len() as u8;
        buf[(username_size + 3)..].copy_from_slice(&self.password[..]);
        let f = io::write_all(server, buf).and_then(move |(server, buf)| {
            io::read_exact(server, [0x0; 2]).and_then(move |(server, resp)| {
                if resp[0] != 0x01 {
                    Box::new(
                        Err(io::Error::new(
                            io::ErrorKind::Other,
                            "invalid version. only socks5 supported.",
                        ))
                        .into_future(),
                    )
                } else {
                    let authorized = resp[1] == 0x00;
                    Box::new(
                        Ok(AuthResult {
                            conn: server,
                            buf,
                            authorized,
                        })
                        .into_future(),
                    )
                }
            })
        });
        Box::new(f)
    }
}

fn recv_username_password(
    conn: TcpStream,
    mut buf: Vec<u8>,
) -> Box<Future<Item = (TcpStream, Vec<u8>, Vec<u8>, Vec<u8>), Error = io::Error> + Send> {
    buf.resize(2, 0);
    let f = io::read_exact(conn, buf)
        .and_then(move |(conn, mut buf)| -> Box<Future<Item=(TcpStream, Vec<u8>), Error=io::Error> + Send> {
            if buf[0] != 0x01 {
                Box::new(Err(io::Error::new(
                    io::ErrorKind::Other,
                    "invalid version. only socks5 supported.",
                )).into_future())
            } else {
                let buf_size = buf[1] as usize + 1;
                buf.resize(buf_size, 0);
                Box::new(io::read_exact(conn, buf))
            }
        })
        .and_then(|(conn, mut buf)| {
            let username_len = buf.len() - 1;
            let username = (&buf[..username_len]).to_vec();
            let password_len = buf[username_len] as usize;
            buf.resize(password_len, 0);
            io::read_exact(conn, buf)
                .map(move |(conn, buf)| {
                    let password = (&buf[..]).to_vec();
                    (conn, buf, username, password)
                })
        });
    Box::new(f)
}

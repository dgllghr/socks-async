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

pub struct AuthResult {
    pub authenticated: bool,
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
            authenticated: true,
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

impl AuthProtocol for UserPassAuth {
    type Future = Box<Future<Item = AuthResult, Error = std::io::Error> + Send>;

    fn methods(&self) -> Vec<AuthMethod> {
        vec![AuthMethod::UserPass]
    }

    fn authenticate(
        &self,
        _client: TcpStream,
        _auth_method: &AuthMethod,
        _buf: BytesMut,
    ) -> Self::Future {
        unimplemented!()
    }
}

use super::common::Address;
use super::server::{Connector, DefaultConnector, Reply};
use std::net::SocketAddr;
use tokio::io;
use tokio::prelude::*;
use trust_dns_resolver::AsyncResolver;

/// server::Connector that performs DNS lookups on domain names
#[derive(Clone)]
pub struct DnsConnector {
    resolver: AsyncResolver,
}

impl DnsConnector {
    pub fn new(resolver: AsyncResolver) -> DnsConnector {
        DnsConnector { resolver }
    }
}

impl Connector for DnsConnector {
    type R = Reply;
    type ConnectFuture = Box<Future<Item = Self::R, Error = io::Error> + Send>;

    fn connect(&self, address: &Address) -> Self::ConnectFuture {
        match address {
            Address::Ip(ip) => DefaultConnector::default().connect(&Address::Ip(ip.clone())),
            Address::Domain(domain_name, port) => {
                let port = port.clone();
                let f = self
                    .resolver
                    .lookup_ip(domain_name.as_str())
                    .map_err(|err| {
                        let message = format!("error in dns resolution. {}", err);
                        io::Error::new(io::ErrorKind::Other, message)
                    })
                    .and_then(move |ips| {
                        let socket_addr = ips.iter().next().map(|ip| SocketAddr::from((ip, port)));
                        match socket_addr {
                            Some(ip) => DefaultConnector::default().connect(&Address::Ip(ip)),
                            None => Box::new(future::err(io::Error::new(
                                io::ErrorKind::NotFound,
                                "ip not found for host name",
                            ))),
                        }
                    });
                Box::new(f)
            }
        }
    }
}

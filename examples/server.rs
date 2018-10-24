#![feature(await_macro, async_await, futures_api, try_from)]

#[macro_use]
extern crate tokio;

use socks_async::dns;
use socks_async::server;

use std::net::SocketAddr;
use std::time::Duration;
use trust_dns_resolver::config::*;
use trust_dns_resolver::AsyncResolver;

fn main() {
    let addr = "0.0.0.0:8080".parse::<SocketAddr>().unwrap();
    let (username, password) = ("username", "password");

    let (resolver, dns_background) =
        AsyncResolver::new(ResolverConfig::default(), ResolverOpts::default());
    tokio::run_async(
        async move {
            tokio::spawn(dns_background);

            let auth = server::UserPassAuth::new(username, password).unwrap();
            let connector = dns::DnsConnector::new(resolver);
            let s = server::Server::new(auth, connector, Duration::from_secs(5));
            let result = await!(s.listen(addr));
            match result {
                Ok(()) => (),
                Err(err) => println!("server stopped. {}", err),
            }
        },
    );
}

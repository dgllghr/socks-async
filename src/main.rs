#![feature(await_macro, async_await, futures_api, try_from)]

#[macro_use]
extern crate tokio;

mod auth;
mod common;
mod dns;
mod server;

use std::net::SocketAddr;
use std::time::Duration;
use trust_dns_resolver::AsyncResolver;
use trust_dns_resolver::config::*;

fn main() {
    let addr = "0.0.0.0:8920".parse::<SocketAddr>().unwrap();

    let (resolver, dns_background) = AsyncResolver::new(
        ResolverConfig::default(),
        ResolverOpts::default()
    );
    tokio::run_async(async move {
        tokio::spawn(dns_background);

        let connector = dns::DnsConnector::new(resolver);
        let s = server::Server::new(auth::NoAuth, connector, Duration::from_secs(5));
        let result = await!(s.listen(addr));
        match result {
            Ok(()) => (),
            Err(err) => println!("error starting server. {}", err),
        }
    });
}

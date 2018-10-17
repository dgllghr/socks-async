#![feature(await_macro, async_await, futures_api, try_from)]

#[macro_use]
extern crate tokio;

use socks_async::client;

use std::net::SocketAddr;
use std::time::Duration;

fn main() {
    let server_addr = "0.0.0.0:8080".parse::<SocketAddr>().unwrap();
    let (username, password) = ("username", "password");

    tokio::run_async(
        async move {
            // let auth = client::UserPassAuth::new(username, password);
            let s = client::Client::new(client::NoAuth, Duration::from_secs(5));
            let reply = await!(s.connect(server_addr));
            match reply {
                Ok(client::Reply::Success(_, _)) => {
                    println!("connected to server");
                }
                _ => {
                    println!("failed to connect");
                }
            }
        },
    );
}

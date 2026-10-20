//! A server on 127.0.0.1:2121 (or the port in the environment variable `PORT`) that keeps everything in memory. User `alice`, password `secret`.
//!
//! ```sh
//! cargo run --example memory
//! curl --user alice:secret ftp://127.0.0.1:2121/
//! ```
//!
//! With the argument `tls` it offers explicit FTPS, with a certificate made for the run (so a client has to be told to trust it):
//!
//! ```sh
//! cargo run --example memory -- tls
//! curl --ssl-reqd --insecure --user alice:secret ftp://127.0.0.1:2121/
//! ```

#[path = "../tests/common/mod.rs"]
mod common;

use std::sync::Arc;
use thirtyftp::{Config, NoEvents, serve};
use tokio::net::TcpListener;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let port = std::env::var("PORT").unwrap_or_else(|_| "2121".to_string());
    let listener = TcpListener::bind(format!("127.0.0.1:{port}")).await?;
    println!("Listening on {}", listener.local_addr()?);
    let backend = common::Memory::new();
    let mut config = Config::default();
    if std::env::args().any(|argument| argument == "tls") {
        config.tls = Some(common::tls().server);
        println!("Explicit FTPS is on");
    }
    let config = Arc::new(config);
    loop {
        let (stream, peer) = listener.accept().await?;
        let (config, backend) = (config.clone(), backend.clone());
        tokio::spawn(async move {
            let end = serve(stream, peer, config, backend, Arc::new(NoEvents)).await;
            println!("{peer}: {end:?}");
        });
    }
}

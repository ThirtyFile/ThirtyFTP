//! A server on 127.0.0.1:2121 that keeps everything in memory. User `alice`, password `secret`.
//!
//! ```sh
//! cargo run --example memory
//! curl --user alice:secret ftp://127.0.0.1:2121/
//! ```

#[path = "../tests/common/mod.rs"]
mod common;

use std::sync::Arc;
use thirtyftp::{Config, NoEvents, serve};
use tokio::net::TcpListener;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let listener = TcpListener::bind("127.0.0.1:2121").await?;
    println!("Listening on {}", listener.local_addr()?);
    let backend = common::Memory::new();
    let config = Arc::new(Config::default());
    loop {
        let (stream, peer) = listener.accept().await?;
        let (config, backend) = (config.clone(), backend.clone());
        tokio::spawn(async move {
            let end = serve(stream, peer, config, backend, Arc::new(NoEvents)).await;
            println!("{peer}: {end:?}");
        });
    }
}

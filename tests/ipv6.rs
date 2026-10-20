//! A server on an IPv6 address: `EPSV` is the passive command, `PASV` is for IPv4, and the protocol arguments name the family

mod common;

use common::*;
use std::net::SocketAddr;
use thirtyftp::Config;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// A server on ::1, or `None` where the system has no IPv6 loopback
async fn server_v6(config: Config) -> Option<Server> {
    TcpListener::bind("[::1]:0").await.ok()?;
    Some(start_on("[::1]:0", config).await)
}

#[tokio::test]
async fn epsv_is_the_passive_command_of_ipv6() {
    let Some(server) = server_v6(Config::default()).await else { return };
    let mut client = Client::connect(&server).await;
    client.login().await;
    assert_eq!(client.code("PASV").await, 501, "PASV is for IPv4");
    let (code, lines) = client.command("EPSV 1").await;
    assert_eq!((code, lines[0].as_str()), (522, "Network protocol not supported, use (2)"));
    assert_eq!(client.code("EPSV 2").await, 229);
    let data = client.epsv().await;
    assert!(data.is_ipv6());
    let mut stream = TcpStream::connect(data).await.unwrap();
    assert_eq!(client.code("STOR f.txt").await, 150);
    stream.write_all(b"over ipv6").await.unwrap();
    stream.shutdown().await.unwrap();
    assert_eq!(client.reply().await.0, 226);
    assert_eq!(download_v6(&mut client, "f.txt").await, b"over ipv6");
}

async fn download_v6(client: &mut Client, name: &str) -> Vec<u8> {
    let address = client.epsv().await;
    let mut stream = TcpStream::connect(address).await.unwrap();
    assert_eq!(client.code(&format!("RETR {name}")).await, 150);
    let mut data = Vec::new();
    stream.read_to_end(&mut data).await.unwrap();
    assert_eq!(client.reply().await.0, 226);
    data
}

#[tokio::test]
async fn active_mode_over_ipv6() {
    let Some(server) = server_v6({
        let mut config = Config::default();
        config.active_mode = true;
        config
    })
    .await
    else {
        return;
    };
    let mut client = Client::connect(&server).await;
    client.login().await;
    let listener = TcpListener::bind("[::1]:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    // PORT is IPv4 only; EPRT with the protocol 2 is the way
    assert_eq!(client.code("PORT 127,0,0,1,200,1").await, 504);
    let (code, lines) = client.command("EPRT |1|127.0.0.1|5000|").await;
    assert_eq!(code, 504, "{lines:?}");
    assert_eq!(client.code(&format!("EPRT |2|::1|{port}|")).await, 200);
    client.send("NLST").await;
    let (mut stream, _) = tokio::time::timeout(std::time::Duration::from_secs(10), listener.accept()).await.expect("no connection").unwrap();
    assert_eq!(client.reply().await.0, 150);
    let mut data = Vec::new();
    stream.read_to_end(&mut data).await.unwrap();
    assert_eq!(client.reply().await.0, 226);
    let _: SocketAddr = stream.peer_addr().unwrap();
}

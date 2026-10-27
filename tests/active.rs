//! Active mode (PORT and EPRT): off by default, and restricted to the client's own address and to ports from 1024 up when on

mod common;

use common::*;
use std::time::Duration;
use thirtyftp::Config;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

async fn active_server() -> Server {
    start_with({
        let mut config = Config::default();
        config.active_mode = true;
        config
    })
    .await
}

/// A listener for the data connection, announced with PORT
async fn announce_port(client: &mut Client) -> TcpListener {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    assert_eq!(client.code(&format!("PORT 127,0,0,1,{},{}", port >> 8, port & 0xff)).await, 200);
    listener
}

async fn accept(listener: &TcpListener) -> TcpStream {
    tokio::time::timeout(Duration::from_secs(10), listener.accept()).await.expect("the server did not connect").unwrap().0
}

#[tokio::test]
async fn it_is_off_by_default() {
    let server = start().await;
    let mut client = Client::connect(&server).await;
    client.login().await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    assert_eq!(client.code(&format!("PORT 127,0,0,1,{},{}", port >> 8, port & 0xff)).await, 502);
    assert_eq!(client.code(&format!("EPRT |1|127.0.0.1|{port}|")).await, 502);
    assert_eq!(client.code("NLST").await, 425);
    assert!(tokio::time::timeout(Duration::from_millis(300), listener.accept()).await.is_err(), "the server must not connect");
}

#[tokio::test]
async fn upload_download_and_listing() {
    let server = active_server().await;
    let mut client = Client::connect(&server).await;
    client.login().await;
    assert_eq!(client.code("NLST").await, 425);
    let listener = announce_port(&mut client).await;
    client.send("STOR a.txt").await;
    let mut stream = accept(&listener).await;
    assert_eq!(stream.peer_addr().unwrap().ip().to_string(), "127.0.0.1");
    assert_eq!(client.reply().await.0, 150);
    stream.write_all(b"sent by the client").await.unwrap();
    stream.shutdown().await.unwrap();
    assert_eq!(client.reply().await.0, 226);
    assert_eq!(server.backend.files.lock().unwrap().get("/a.txt"), Some(&b"sent by the client".to_vec()));
    // One data connection for one transfer: the next needs a new PORT
    assert_eq!(client.code("NLST").await, 425);
    let listener = announce_port(&mut client).await;
    client.send("RETR a.txt").await;
    let mut stream = accept(&listener).await;
    assert_eq!(client.reply().await.0, 150);
    let mut data = Vec::new();
    stream.read_to_end(&mut data).await.unwrap();
    assert_eq!(data, b"sent by the client");
    assert_eq!(client.reply().await.0, 226);
    let listener = announce_port(&mut client).await;
    client.send("NLST").await;
    let mut stream = accept(&listener).await;
    assert_eq!(client.reply().await.0, 150);
    let mut data = Vec::new();
    stream.read_to_end(&mut data).await.unwrap();
    assert_eq!(data, b"a.txt\r\n");
    assert_eq!(client.reply().await.0, 226);
}

#[tokio::test]
async fn eprt_does_the_same() {
    let server = active_server().await;
    let mut client = Client::connect(&server).await;
    client.login().await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    assert_eq!(client.code(&format!("EPRT |1|127.0.0.1|{port}|")).await, 200);
    client.send("LIST").await;
    let mut stream = accept(&listener).await;
    assert_eq!(client.reply().await.0, 150);
    let mut data = Vec::new();
    stream.read_to_end(&mut data).await.unwrap();
    assert_eq!(client.reply().await.0, 226);
    assert!(data.is_empty(), "nothing in the root yet");
}

#[tokio::test]
async fn the_server_connects_to_the_address_of_the_client_only() {
    let server = active_server().await;
    let mut client = Client::connect(&server).await;
    client.login().await;
    // 127.0.0.2 is not the address the control connection comes from (127.0.0.1)
    assert_eq!(client.code("PORT 127,0,0,2,200,1").await, 504);
    assert_eq!(client.code("PORT 10,1,2,3,200,1").await, 504);
    assert_eq!(client.code("EPRT |1|8.8.8.8|5000|").await, 504);
    assert_eq!(client.code("EPRT |2|::1|5000|").await, 504);
    assert_eq!(client.code("EPRT |2|2001:db8::1|5000|").await, 504);
    // And nothing is announced after a refusal, not even the one before it
    let listener = announce_port(&mut client).await;
    assert_eq!(client.code("PORT 10,1,2,3,200,1").await, 504);
    assert_eq!(client.code("NLST").await, 425);
    assert!(tokio::time::timeout(Duration::from_millis(300), listener.accept()).await.is_err());
}

#[tokio::test]
async fn the_server_connects_to_ports_from_1024_up_only() {
    let server = active_server().await;
    let mut client = Client::connect(&server).await;
    client.login().await;
    for line in [
        "PORT 127,0,0,1,0,21",
        "PORT 127,0,0,1,0,80",
        "PORT 127,0,0,1,3,255",
        "PORT 127,0,0,1,0,0",
        "EPRT |1|127.0.0.1|22|",
        "EPRT |1|127.0.0.1|1023|",
        "EPRT |1|127.0.0.1|0|",
    ] {
        assert_eq!(client.code(line).await, 504, "{line}");
    }
    assert_eq!(client.code("NLST").await, 425);
}

#[tokio::test]
async fn malformed_arguments() {
    let server = active_server().await;
    let mut client = Client::connect(&server).await;
    client.login().await;
    for line in ["PORT 1,2,3,4,5", "PORT 1,2,3,4,5,6,7", "PORT x", "PORT 127,0,0,1,4,256", "EPRT |1|127.0.0.1|", "EPRT |1|127.0.0.1|x|", "EPRT hello"] {
        assert_eq!(client.code(line).await, 501, "{line}");
    }
    let (code, lines) = client.command("EPRT |3|something|5000|").await;
    assert_eq!((code, lines[0].as_str()), (522, "Network protocol not supported, use (1)"));
}

#[tokio::test]
async fn a_later_command_replaces_the_earlier_one() {
    let server = active_server().await;
    let mut client = Client::connect(&server).await;
    client.login().await;
    let listener = announce_port(&mut client).await;
    // PASV replaces the PORT: the transfer uses the passive port, and the server does not connect to the listener
    let address = client.pasv().await;
    client.send("NLST").await;
    let stream = TcpStream::connect(address).await.unwrap();
    assert_eq!(client.reply().await.0, 150);
    let mut stream = stream;
    let mut data = Vec::new();
    stream.read_to_end(&mut data).await.unwrap();
    assert_eq!(client.reply().await.0, 226);
    assert!(tokio::time::timeout(Duration::from_millis(300), listener.accept()).await.is_err());
    // PORT replaces the PASV, and closes its port
    let address = client.pasv().await;
    let listener = announce_port(&mut client).await;
    assert!(TcpStream::connect(address).await.is_err(), "the passive port is closed");
    client.send("NLST").await;
    let _stream = accept(&listener).await;
    assert_eq!(client.reply().await.0, 150);
    assert_eq!(client.reply().await.0, 226);
}

#[tokio::test]
async fn nobody_listening_is_425() {
    let server = active_server().await;
    let mut client = Client::connect(&server).await;
    client.login().await;
    // A port that is ours and not listening: nobody else can be given it while the socket is held, and a connection to it is refused
    let socket = tokio::net::TcpSocket::new_v4().unwrap();
    socket.bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let port = socket.local_addr().unwrap().port();
    assert_eq!(client.code(&format!("PORT 127,0,0,1,{},{}", port >> 8, port & 0xff)).await, 200);
    assert_eq!(client.code("STOR a.txt").await, 425, "no 150: the data connection was never open");
    drop(socket);
    assert!(server.backend.files.lock().unwrap().is_empty());
    assert_eq!(client.code("NOOP").await, 200);
}

#[tokio::test]
async fn the_message_says_what_to_use() {
    let server = active_server().await;
    let mut client = Client::connect(&server).await;
    client.login().await;
    assert_eq!(client.command("RETR f").await, (425, vec!["Use PORT, PASV or EPSV first.".to_string()]));
    assert_eq!(client.code("EPSV ALL").await, 200);
    assert_eq!(client.code("PORT 127,0,0,1,200,1").await, 501, "RFC 2428: after EPSV ALL");
}

#[tokio::test]
async fn abor_during_an_active_upload() {
    let server = active_server().await;
    let mut client = Client::connect(&server).await;
    client.login().await;
    let listener = announce_port(&mut client).await;
    client.send("STOR a.txt").await;
    let mut stream = accept(&listener).await;
    assert_eq!(client.reply().await.0, 150);
    stream.write_all(b"partial").await.unwrap();
    eventually(|| server.backend.started_writes.load(std::sync::atomic::Ordering::SeqCst) == 1).await;
    client.send("ABOR").await;
    assert_eq!(client.reply().await.0, 426);
    assert_eq!(client.reply().await.0, 226);
    assert!(server.backend.files.lock().unwrap().is_empty());
}

// The TLS policy is the one of passive mode

#[tokio::test]
async fn with_tls_required_the_data_connection_must_be_protected() {
    let tls = tls();
    let server = start_with({
        let mut config = Config::default();
        config.active_mode = true;
        config.require_tls = true;
        config.tls = Some(tls.server.clone());
        config
    })
    .await;
    let mut client = Client::connect(&server).await;
    client.upgrade(&tls).await;
    client.login().await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let port_line = format!("PORT 127,0,0,1,{},{}", port >> 8, port & 0xff);
    // Not protected yet
    assert_eq!(client.code(&port_line).await, 534);
    assert_eq!(client.code(&format!("EPRT |1|127.0.0.1|{port}|")).await, 534);
    assert_eq!(client.code("PBSZ 0").await, 200);
    assert_eq!(client.code("PROT P").await, 200);
    assert_eq!(client.code(&port_line).await, 200);
    // The level changes after the announcement: no transfer in plain text
    assert_eq!(client.code("PROT C").await, 200);
    assert_eq!(client.code("STOR a.txt").await, 534);
    assert!(tokio::time::timeout(Duration::from_millis(300), listener.accept()).await.is_err(), "the server must not connect in plain text");
    // And with PROT P the server is the TLS server on the connection it opens
    assert_eq!(client.code("PROT P").await, 200);
    client.send("STOR a.txt").await;
    let stream = accept(&listener).await;
    assert_eq!(client.reply().await.0, 150);
    let mut stream = tls.connect(stream).await;
    stream.write_all(b"private").await.unwrap();
    stream.shutdown().await.unwrap();
    let mut rest = Vec::new();
    stream.read_to_end(&mut rest).await.unwrap();
    assert_eq!(client.reply().await.0, 226);
    assert_eq!(server.backend.files.lock().unwrap().get("/a.txt"), Some(&b"private".to_vec()));
}

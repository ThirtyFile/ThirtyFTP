//! Explicit FTPS (RFC 4217): AUTH TLS, PBSZ and PROT, the TLS policy, TLS on data connections, and how an upload ends

mod common;

use common::*;
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};
use thirtyftp::{Config, SessionEnd};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

async fn server_with(tls: &Tls, change: impl FnOnce(&mut Config)) -> Server {
    let mut config = Config::default();
    config.tls = Some(tls.server.clone());
    change(&mut config);
    start_with(config).await
}

async fn secure_server(tls: &Tls) -> Server {
    server_with(tls, |_| {}).await
}

/// A client that has signed in over TLS, with `PROT P`
async fn secure(server: &Server, tls: &Tls) -> Client {
    let mut client = Client::connect(server).await;
    client.secure_login(tls).await;
    client
}

/// The data connection of a transfer, with TLS. The client connects, sends the command, and starts the handshake when the server says 150
async fn tls_transfer(client: &mut Client, tls: &Tls, address: SocketAddr, command: &str) -> tokio_rustls::client::TlsStream<TcpStream> {
    let tcp = TcpStream::connect(address).await.unwrap();
    assert_eq!(client.code(command).await, 150, "{command}");
    tls.connect(tcp).await
}

async fn secure_upload(client: &mut Client, tls: &Tls, name: &str, data: &[u8]) {
    let address = client.pasv().await;
    let mut stream = tls_transfer(client, tls, address, &format!("STOR {name}")).await;
    stream.write_all(data).await.unwrap();
    stream.shutdown().await.unwrap();
    // The server's close_notify: the end of the data connection
    let mut rest = Vec::new();
    stream.read_to_end(&mut rest).await.unwrap();
    assert_eq!(client.reply().await.0, 226);
}

async fn secure_download(client: &mut Client, tls: &Tls, command: &str) -> Vec<u8> {
    let address = client.pasv().await;
    let mut stream = tls_transfer(client, tls, address, command).await;
    let mut data = Vec::new();
    stream.read_to_end(&mut data).await.expect("the data must end with a close_notify");
    // Answer the server's close_notify with ours, as a client does
    stream.shutdown().await.unwrap();
    assert_eq!(client.reply().await.0, 226, "{command}");
    data
}

#[tokio::test]
async fn auth_tls_upgrades_the_control_connection() {
    let tls = tls();
    let server = secure_server(&tls).await;
    let mut client = Client::connect(&server).await;
    let feat = client.command("FEAT").await.1;
    for line in ["AUTH TLS", "PBSZ", "PROT"] {
        assert!(feat.iter().any(|l| l.trim() == line), "{line} in {feat:?}");
    }
    assert!(client.command("STAT").await.1.join("\n").contains("Control connection is not encrypted"));
    client.upgrade(&tls).await;
    assert!(client.command("STAT").await.1.join("\n").contains("Control connection is encrypted"));
    client.login().await;
    assert_eq!(client.command("PWD").await.0, 257);
    let (context, _) = server.backend.logins.lock().unwrap()[0].clone();
    assert!(context.encrypted, "the backend is told that the control connection is encrypted");
    // A plain sign-in says it was not
    let mut plain = Client::connect(&server).await;
    plain.login().await;
    assert!(!server.backend.logins.lock().unwrap()[1].0.encrypted);
}

#[tokio::test]
async fn auth_without_tls_settings_is_502() {
    let server = start().await;
    let mut client = Client::connect(&server).await;
    assert_eq!(client.code("AUTH TLS").await, 502);
    assert_eq!(client.code("PBSZ 0").await, 503);
    let feat = client.command("FEAT").await.1;
    assert!(!feat.iter().any(|l| l.contains("AUTH")), "{feat:?}");
}

#[tokio::test]
async fn the_mechanisms_and_when_auth_is_allowed() {
    let tls = tls();
    let server = secure_server(&tls).await;
    let mut client = Client::connect(&server).await;
    assert_eq!(client.code("AUTH SSL").await, 504);
    assert_eq!(client.code("AUTH TLS-P").await, 504);
    assert_eq!(client.code("AUTH X").await, 504);
    assert_eq!(client.code("CCC").await, 534, "going back to plain text is refused");
    let mut client = Client::connect(&server).await;
    assert_eq!(client.code("auth tls-c").await, 234);
    client.start_tls(&tls).await;
    assert_eq!(client.code("AUTH TLS").await, 503, "TLS is on already");
    assert_eq!(client.code("CCC").await, 534);
    // After signing in
    let mut client = Client::connect(&server).await;
    client.login().await;
    assert_eq!(client.code("AUTH TLS").await, 503);
    assert_eq!(client.code("PWD").await, 257, "and the connection is still plain and usable");
}

#[tokio::test]
async fn a_failed_handshake_ends_the_session() {
    let tls = tls();
    let server = secure_server(&tls).await;
    let mut client = Client::connect(&server).await;
    assert_eq!(client.code("AUTH TLS").await, 234);
    // Not a ClientHello
    client.send_bytes(b"USER alice\r\n").await;
    // The server may send an alert; then it closes the connection
    let mut rest = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(5), client.reader.read_to_end(&mut rest)).await.expect("the connection stayed open");
    assert!(!String::from_utf8_lossy(&rest).contains("331"), "nothing is answered in plain text");
    eventually(|| matches!(server.ends.lock().unwrap().first(), Some(SessionEnd::TlsHandshakeFailed))).await;
    assert!(server.backend.logins.lock().unwrap().is_empty());
}

#[tokio::test]
async fn a_handshake_that_never_comes_is_given_up() {
    let tls = tls();
    let server = server_with(&tls, |config| config.limits.tls_handshake_timeout = Duration::from_millis(300)).await;
    let mut client = Client::connect(&server).await;
    assert_eq!(client.code("AUTH TLS").await, 234);
    assert!(client.closed().await);
    eventually(|| matches!(server.ends.lock().unwrap().first(), Some(SessionEnd::TlsHandshakeFailed))).await;
}

#[tokio::test]
async fn require_tls_refuses_the_sign_in_until_auth_tls() {
    let tls = tls();
    let server = server_with(&tls, |config| config.require_tls = true).await;
    let mut client = Client::connect(&server).await;
    assert_eq!(client.code("USER alice").await, 530);
    assert_eq!(client.code("PASS secret").await, 503);
    assert!(server.backend.logins.lock().unwrap().is_empty());
    client.upgrade(&tls).await;
    client.login().await;
}

#[tokio::test]
async fn the_sign_in_before_auth_does_not_carry_over() {
    let tls = tls();
    let server = secure_server(&tls).await;
    let mut client = Client::connect(&server).await;
    assert_eq!(client.code("USER alice").await, 331);
    client.upgrade(&tls).await;
    // The state is new after AUTH (RFC 4217 section 4): the name given before is forgotten
    assert_eq!(client.code("PASS secret").await, 503);
}

// The switch to TLS right after the 234

#[tokio::test]
async fn what_the_client_sent_after_auth_tls_in_plain_text_is_never_answered() {
    let tls = tls();
    let server = secure_server(&tls).await;
    let mut client = Client::connect(&server).await;
    // The commands after AUTH TLS are sent before the client has seen the 234
    client.send_bytes(b"AUTH TLS\r\nUSER alice\r\nPASS secret\r\nPWD\r\n").await;
    assert_eq!(client.reply().await.0, 234);
    // Nothing in plain text follows the 234: no 331, no 230
    let mut byte = [0u8; 1];
    let plain = tokio::time::timeout(Duration::from_millis(500), client.reader.read(&mut byte)).await;
    assert!(plain.is_err(), "the server answered in plain text after the 234: {byte:?}");
    client.start_tls(&tls).await;
    // And none of them was carried out
    assert_eq!(client.code("PWD").await, 530);
    assert!(server.backend.logins.lock().unwrap().is_empty());
}

#[tokio::test]
async fn pbsz_and_prot_need_their_order() {
    let tls = tls();
    let server = secure_server(&tls).await;
    let mut client = Client::connect(&server).await;
    assert_eq!(client.code("PBSZ 0").await, 503, "before AUTH TLS");
    assert_eq!(client.code("PROT P").await, 503);
    client.upgrade(&tls).await;
    assert_eq!(client.code("PROT P").await, 503, "before PBSZ");
    assert_eq!(client.command("PBSZ 0").await, (200, vec!["PBSZ=0".to_string()]));
    assert_eq!(client.command("PBSZ 4096").await, (200, vec!["PBSZ=0".to_string()]), "TLS has no buffer: the size is 0");
    assert_eq!(client.code("PROT P").await, 200);
    assert_eq!(client.code("prot c").await, 200);
    assert_eq!(client.code("PROT S").await, 536);
    assert_eq!(client.code("PROT E").await, 536);
    assert_eq!(client.code("PROT X").await, 504);
    assert_eq!(client.code("PROT").await, 501);
}

#[tokio::test]
async fn upload_download_and_listings_over_tls() {
    let tls = tls();
    let server = secure_server(&tls).await;
    let mut client = secure(&server, &tls).await;
    let data = pattern(3_000_000);
    secure_upload(&mut client, &tls, "scan.pdf", &data).await;
    assert_eq!(server.backend.files.lock().unwrap().get("/scan.pdf"), Some(&data));
    assert_eq!(secure_download(&mut client, &tls, "RETR scan.pdf").await, data);
    assert_eq!(secure_download(&mut client, &tls, "NLST").await, b"scan.pdf\r\n");
    let list = String::from_utf8(secure_download(&mut client, &tls, "LIST").await).unwrap();
    assert!(list.ends_with(" scan.pdf\r\n"), "{list:?}");
    assert!(String::from_utf8(secure_download(&mut client, &tls, "MLSD").await).unwrap().starts_with("type=file;size=3000000;"));
    secure_upload(&mut client, &tls, "empty", b"").await;
    assert_eq!(server.backend.files.lock().unwrap().get("/empty"), Some(&Vec::new()));
}

#[tokio::test]
async fn the_control_connection_ends_with_a_close_notify() {
    let tls = tls();
    let server = secure_server(&tls).await;
    let mut client = secure(&server, &tls).await;
    assert_eq!(client.code("QUIT").await, 221);
    assert!(client.closed_cleanly().await, "QUIT must end the TLS connection with a close_notify");
}

#[tokio::test]
async fn plain_data_connections_are_allowed_when_tls_is_not_required() {
    let tls = tls();
    let server = secure_server(&tls).await;
    let mut client = Client::connect(&server).await;
    client.upgrade(&tls).await;
    client.login().await;
    assert_eq!(client.code("PBSZ 0").await, 200);
    assert_eq!(client.code("PROT C").await, 200);
    let address = client.pasv().await;
    let mut stream = TcpStream::connect(address).await.unwrap();
    assert_eq!(client.code("STOR plain.txt").await, 150);
    stream.write_all(b"in the clear").await.unwrap();
    stream.shutdown().await.unwrap();
    assert_eq!(client.reply().await.0, 226);
    assert_eq!(server.backend.files.lock().unwrap().get("/plain.txt"), Some(&b"in the clear".to_vec()));
}

// The policy on the data channel

#[tokio::test]
async fn with_tls_required_pasv_and_epsv_are_refused_until_prot_p() {
    let tls = tls();
    let server = server_with(&tls, |config| config.require_tls = true).await;
    let mut client = Client::connect(&server).await;
    client.upgrade(&tls).await;
    client.login().await;
    // No PBSZ and PROT yet
    assert_eq!(client.code("PASV").await, 534);
    assert_eq!(client.code("EPSV").await, 534, "EPSV is checked like PASV");
    assert_eq!(client.code("PBSZ 0").await, 200);
    assert_eq!(client.code("PROT C").await, 200);
    assert_eq!(client.code("PASV").await, 534);
    assert_eq!(client.code("EPSV").await, 534);
    assert_eq!(client.code("PROT P").await, 200);
    assert_eq!(client.code("PASV").await, 227);
    assert_eq!(client.code("EPSV").await, 229);
}

#[tokio::test]
async fn prot_c_after_pasv_cannot_give_a_transfer_in_plain_text() {
    let tls = tls();
    let server = server_with(&tls, |config| config.require_tls = true).await;
    let mut client = secure(&server, &tls).await;
    secure_upload(&mut client, &tls, "secret.txt", b"private content").await;
    // PASV was fine with PROT P; the level changes before the transfer
    let address = client.pasv().await;
    assert_eq!(client.code("PROT C").await, 200);
    for command in ["RETR secret.txt", "LIST", "NLST", "MLSD", "STOR other.txt"] {
        assert_eq!(client.code(command).await, 534, "{command}");
    }
    // Nothing was sent on the plain data connection, and nothing is stored
    let mut stream = TcpStream::connect(address).await.unwrap();
    let mut buffer = [0u8; 16];
    assert!(tokio::time::timeout(Duration::from_millis(300), stream.read(&mut buffer)).await.is_err(), "nothing may be sent in plain text");
    assert!(!server.backend.files.lock().unwrap().contains_key("/other.txt"));
    assert_eq!(server.backend.started_writes.load(Ordering::SeqCst), 1);
    // Back to PROT P: the same port and the same connection serve a transfer, now over TLS
    assert_eq!(client.code("PROT P").await, 200);
    assert_eq!(client.code("RETR secret.txt").await, 150);
    let mut stream = tls.connect(stream).await;
    let mut data = Vec::new();
    stream.read_to_end(&mut data).await.unwrap();
    assert_eq!(data, b"private content");
    assert_eq!(client.reply().await.0, 226);
}

// A failed handshake on the data connection

#[tokio::test]
async fn a_data_connection_that_is_not_tls_is_refused_and_nothing_is_stored() {
    let tls = tls();
    let server = secure_server(&tls).await;
    let mut client = secure(&server, &tls).await;
    secure_upload(&mut client, &tls, "keep.txt", b"SECRET-CONTENT").await;
    // An upload: the client talks plain text to a port that needs TLS
    let address = client.pasv().await;
    let mut stream = TcpStream::connect(address).await.unwrap();
    stream.write_all(b"this is not a ClientHello\r\n").await.unwrap();
    assert_eq!(client.code("STOR keep.txt").await, 150);
    let reply = client.reply().await;
    assert_eq!(reply.0, 425, "{reply:?}");
    assert_eq!(server.backend.started_writes.load(Ordering::SeqCst), 1, "the backend must not be asked to store anything");
    assert_eq!(server.backend.files.lock().unwrap().get("/keep.txt"), Some(&b"SECRET-CONTENT".to_vec()), "and the old file stays");
    // A download: the file must not reach the plain connection
    let address = client.pasv().await;
    let mut stream = TcpStream::connect(address).await.unwrap();
    stream.write_all(b"plain text\r\n").await.unwrap();
    assert_eq!(client.code("RETR keep.txt").await, 150);
    assert_eq!(client.reply().await.0, 425);
    let mut received = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut received)).await;
    assert!(!String::from_utf8_lossy(&received).contains("SECRET-CONTENT"));
    // A listing too
    let address = client.pasv().await;
    let mut stream = TcpStream::connect(address).await.unwrap();
    stream.write_all(b"plain text\r\n").await.unwrap();
    assert_eq!(client.code("NLST").await, 150);
    assert_eq!(client.reply().await.0, 425);
    let mut received = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut received)).await;
    assert!(!String::from_utf8_lossy(&received).contains("keep.txt"));
    // The session goes on
    assert_eq!(client.code("NOOP").await, 200);
}

#[tokio::test]
async fn a_data_connection_that_never_starts_the_handshake_is_given_up() {
    let tls = tls();
    let server = server_with(&tls, |config| config.limits.tls_handshake_timeout = Duration::from_millis(300)).await;
    let mut client = secure(&server, &tls).await;
    let address = client.pasv().await;
    let _silent = TcpStream::connect(address).await.unwrap();
    assert_eq!(client.code("STOR f.txt").await, 150);
    let start = Instant::now();
    assert_eq!(client.reply().await.0, 425);
    assert!(start.elapsed() < Duration::from_secs(5));
    assert_eq!(server.backend.started_writes.load(Ordering::SeqCst), 0);
}

// How an upload ends

#[tokio::test]
async fn the_server_answers_the_end_of_an_upload_before_the_storage_is_done() {
    let tls = tls();
    let server = secure_server(&tls).await;
    let mut client = secure(&server, &tls).await;
    let address = client.pasv().await;
    // The storage takes 2 s after the last byte
    let mut stream = tls_transfer(&mut client, &tls, address, "STOR slowend.bin").await;
    stream.write_all(b"the whole file").await.unwrap();
    let start = Instant::now();
    stream.shutdown().await.unwrap();
    // The client waits for the server's close_notify before it takes the transfer for done
    let mut rest = Vec::new();
    stream.read_to_end(&mut rest).await.expect("the server's close_notify");
    assert!(start.elapsed() < Duration::from_millis(1500), "the server's close_notify came after the storage was done: {:?}", start.elapsed());
    assert!(server.backend.files.lock().unwrap().is_empty(), "the storage is still busy");
    assert_eq!(client.reply().await.0, 226);
    assert_eq!(server.backend.files.lock().unwrap().get("/slowend.bin"), Some(&b"the whole file".to_vec()));
}

#[tokio::test]
async fn an_upload_that_ends_without_a_close_notify_is_a_truncation_not_a_226() {
    let tls = tls();
    let server = secure_server(&tls).await;
    let mut client = secure(&server, &tls).await;
    let address = client.pasv().await;
    let mut stream = tls_transfer(&mut client, &tls, address, "STOR cut.bin").await;
    stream.write_all(b"half of the file").await.unwrap();
    stream.flush().await.unwrap();
    // The TCP connection ends, and the TLS connection was not closed
    drop(stream);
    let reply = client.reply().await;
    assert_eq!(reply.0, 426, "{reply:?}");
    assert!(server.backend.files.lock().unwrap().is_empty(), "a truncated upload is not stored");
    eventually(|| server.backend.aborted_writes.load(Ordering::SeqCst) == 1).await;
    assert_eq!(client.code("NOOP").await, 200);
}

#[tokio::test]
async fn a_plain_upload_ends_with_the_end_of_the_connection() {
    // Without TLS the end of the connection is the end of the data: it has no close_notify
    let server = start().await;
    let mut client = Client::connect(&server).await;
    client.login().await;
    let address = client.pasv().await;
    let mut stream = TcpStream::connect(address).await.unwrap();
    assert_eq!(client.code("STOR plain.bin").await, 150);
    stream.write_all(b"data").await.unwrap();
    drop(stream);
    assert_eq!(client.reply().await.0, 226);
}

#[tokio::test]
async fn data_connections_get_no_session_tickets() {
    let tls = tls();
    let server = secure_server(&tls).await;
    let mut client = secure(&server, &tls).await;
    // The control connection is given tickets (the count is of the ones the client has read)
    assert!(tls.tickets.count() > 0, "the test must see tickets on the control connection");
    let before = tls.tickets.count();
    secure_upload(&mut client, &tls, "f.bin", b"abc").await;
    assert_eq!(secure_download(&mut client, &tls, "RETR f.bin").await, b"abc");
    assert_eq!(secure_download(&mut client, &tls, "NLST").await, b"f.bin\r\n");
    assert_eq!(tls.tickets.count(), before, "the data connections must not send tickets");
}

#[tokio::test]
async fn abor_during_a_tls_upload() {
    let tls = tls();
    let server = secure_server(&tls).await;
    let mut client = secure(&server, &tls).await;
    let address = client.pasv().await;
    let mut stream = tls_transfer(&mut client, &tls, address, "STOR f.bin").await;
    stream.write_all(b"partial").await.unwrap();
    stream.flush().await.unwrap();
    eventually(|| server.backend.started_writes.load(Ordering::SeqCst) == 1).await;
    client.send("ABOR").await;
    assert_eq!(client.reply().await.0, 426);
    assert_eq!(client.reply().await.0, 226);
    assert!(server.backend.files.lock().unwrap().is_empty());
    assert_eq!(server.backend.aborted_writes.load(Ordering::SeqCst), 1);
    assert_eq!(client.code("NOOP").await, 200);
}

#[tokio::test]
async fn a_client_library_over_tls() {
    use suppaftp::tokio::{AsyncRustlsConnector, AsyncRustlsFtpStream};
    for mode in [suppaftp::Mode::Passive, suppaftp::Mode::ExtendedPassive] {
        let tls = tls();
        let server = secure_server(&tls).await;
        let mut ftp = AsyncRustlsFtpStream::connect(server.address).await.unwrap();
        ftp = ftp.into_secure(AsyncRustlsConnector::from(tokio_rustls::TlsConnector::from(tls.client.clone())), "localhost").await.unwrap();
        ftp.set_mode(mode);
        ftp.login("alice", "secret").await.unwrap();
        ftp.transfer_type(suppaftp::types::FileType::Binary).await.unwrap();
        let data = pattern(700_000);
        ftp.put_file("a.bin", &mut std::io::Cursor::new(data.clone())).await.unwrap();
        assert_eq!(server.backend.files.lock().unwrap().get("/a.bin"), Some(&data));
        let mut stream = ftp.retr_as_stream("a.bin").await.unwrap();
        let mut received = Vec::new();
        stream.read_to_end(&mut received).await.unwrap();
        stream.finish().await.unwrap();
        assert_eq!(received, data);
        assert_eq!(ftp.nlst(None).await.unwrap(), ["a.bin"]);
        ftp.quit().await.unwrap();
    }
}

#[tokio::test]
async fn a_download_over_tls_ends_even_when_the_client_keeps_its_end_open() {
    // The server waits for the client's close_notify before it closes, so the end of the data is not lost; a client that never sends it does not
    // keep the 226 waiting for longer than that
    let tls = tls();
    let server = server_with(&tls, |config| config.limits.tls_close_wait = Duration::from_millis(400)).await;
    let mut client = secure(&server, &tls).await;
    secure_upload(&mut client, &tls, "f.bin", &pattern(100_000)).await;
    let address = client.pasv().await;
    let mut stream = tls_transfer(&mut client, &tls, address, "RETR f.bin").await;
    let mut data = Vec::new();
    stream.read_to_end(&mut data).await.unwrap();
    assert_eq!(data, pattern(100_000));
    let start = Instant::now();
    assert_eq!(client.reply().await.0, 226);
    assert!(start.elapsed() < Duration::from_secs(3), "{:?}", start.elapsed());
    drop(stream);
}

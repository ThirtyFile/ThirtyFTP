//! Passive mode and the transfers: PASV and EPSV, uploads, downloads and listings, and ABOR while they run

mod common;

use common::*;
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};
use thirtyftp::{Config, Direction, TransferEnd};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpSocket, TcpStream};

async fn connect(address: SocketAddr) -> TcpStream {
    TcpStream::connect(address).await.unwrap()
}

async fn read_all(mut stream: TcpStream) -> Vec<u8> {
    let mut bytes = Vec::new();
    tokio::time::timeout(Duration::from_secs(10), stream.read_to_end(&mut bytes)).await.expect("the data did not end").unwrap();
    bytes
}

/// Signs in, sends a file through a new passive connection, and returns when `226` came
async fn upload(client: &mut Client, name: &str, data: &[u8]) {
    let address = client.pasv().await;
    let mut stream = connect(address).await;
    assert_eq!(client.code(&format!("STOR {name}")).await, 150);
    stream.write_all(data).await.unwrap();
    stream.shutdown().await.unwrap();
    assert_eq!(client.reply().await.0, 226);
}

async fn download(client: &mut Client, name: &str) -> Vec<u8> {
    let address = client.pasv().await;
    let stream = connect(address).await;
    assert_eq!(client.code(&format!("RETR {name}")).await, 150);
    let data = read_all(stream).await;
    assert_eq!(client.reply().await.0, 226);
    data
}

async fn listing(client: &mut Client, command: &str) -> String {
    let address = client.pasv().await;
    let stream = connect(address).await;
    assert_eq!(client.code(command).await, 150, "{command}");
    let data = read_all(stream).await;
    assert_eq!(client.reply().await.0, 226, "{command}");
    String::from_utf8(data).unwrap()
}

fn pattern(length: usize) -> Vec<u8> {
    (0..length).map(|i| (i * 7 + i / 251) as u8).collect()
}

#[tokio::test]
async fn pasv_tells_the_address_of_the_connection_and_a_port_that_listens() {
    let server = start().await;
    let mut client = Client::connect(&server).await;
    client.login().await;
    let (code, lines) = client.command("PASV").await;
    assert_eq!(code, 227);
    assert!(lines[0].starts_with("Entering Passive Mode (127,0,0,1,"), "{lines:?}");
    let address = client.pasv().await;
    assert_eq!(address.ip().to_string(), "127.0.0.1");
    assert!(address.port() >= 49152);
    connect(address).await;
}

#[tokio::test]
async fn epsv_tells_only_the_port() {
    let server = start().await;
    let mut client = Client::connect(&server).await;
    client.login().await;
    let (code, lines) = client.command("EPSV").await;
    assert_eq!(code, 229);
    assert!(lines[0].starts_with("Entering Extended Passive Mode (|||") && lines[0].ends_with("|)."), "{lines:?}");
    connect(client.epsv().await).await;
}

#[tokio::test]
async fn upload_and_download() {
    let server = start().await;
    let mut client = Client::connect(&server).await;
    client.login().await;
    // More than the buffers, so that it needs many reads
    let data = pattern(5_000_000);
    upload(&mut client, "scan.pdf", &data).await;
    assert_eq!(server.backend.files.lock().unwrap().get("/scan.pdf"), Some(&data));
    assert_eq!(download(&mut client, "scan.pdf").await, data);
    // An empty file
    upload(&mut client, "empty", b"").await;
    assert_eq!(download(&mut client, "empty").await, b"");
    assert_eq!(client.command("SIZE scan.pdf").await, (213, vec!["5000000".to_string()]));
}

#[tokio::test]
async fn the_working_directory_is_where_a_file_goes() {
    let server = start().await;
    let mut client = Client::connect(&server).await;
    client.login().await;
    assert_eq!(client.code("MKD in").await, 257);
    assert_eq!(client.code("CWD in").await, 250);
    upload(&mut client, "a b.txt", b"hello").await;
    upload(&mut client, "/top.txt", b"top").await;
    assert!(server.backend.files.lock().unwrap().contains_key("/in/a b.txt"));
    assert!(server.backend.files.lock().unwrap().contains_key("/top.txt"));
    assert_eq!(download(&mut client, "../top.txt").await, b"top");
}

#[tokio::test]
async fn listings() {
    let server = start().await;
    let mut client = Client::connect(&server).await;
    client.login().await;
    assert_eq!(client.code("MKD sub").await, 257);
    upload(&mut client, "a.txt", b"12345").await;
    let list = listing(&mut client, "LIST").await;
    assert!(list.contains("-rw-r--r--") && list.contains(" 5 Sep  9  2001 a.txt\r\n"), "{list:?}");
    assert!(list.contains("drwxr-xr-x") && list.ends_with(" sub\r\n") || list.contains(" sub\r\n"), "{list:?}");
    assert_eq!(listing(&mut client, "LIST -la").await, list, "options are ignored");
    let names = listing(&mut client, "NLST").await;
    assert!(names == "a.txt\r\nsub\r\n" || names == "sub\r\na.txt\r\n", "{names:?}");
    let facts = listing(&mut client, "MLSD").await;
    assert!(facts.contains("type=file;size=5;modify=20010909014640; a.txt\r\n"), "{facts:?}");
    assert!(facts.contains("type=dir;modify=20010909014640;") || facts.contains("type=dir;"), "{facts:?}");
    // The listing of a file is that file
    assert_eq!(listing(&mut client, "NLST a.txt").await, "a.txt\r\n");
    assert!(listing(&mut client, "LIST a.txt").await.ends_with(" a.txt\r\n"));
    // Of a directory by its path
    assert_eq!(listing(&mut client, "NLST sub").await, "");
}

#[tokio::test]
async fn a_listing_that_cannot_be_made_is_550_and_the_port_stays() {
    let server = start().await;
    let mut client = Client::connect(&server).await;
    client.login().await;
    let address = client.pasv().await;
    assert_eq!(client.code("LIST nowhere").await, 550);
    assert_eq!(client.code("MLSD nowhere").await, 550);
    assert_eq!(client.code("RETR nowhere").await, 550);
    assert_eq!(client.code("RETR /").await, 550, "a directory");
    // The same passive connection is still there for a transfer that can be made
    let stream = connect(address).await;
    assert_eq!(client.code("NLST").await, 150);
    read_all(stream).await;
    assert_eq!(client.reply().await.0, 226);
}

#[tokio::test]
async fn a_transfer_without_pasv_is_425() {
    let server = start().await;
    let mut client = Client::connect(&server).await;
    client.login().await;
    for line in ["STOR f", "RETR f", "LIST", "NLST", "MLSD"] {
        assert_eq!(client.command(line).await, (425, vec!["Use PASV or EPSV first.".to_string()]), "{line}");
    }
}

#[tokio::test]
async fn a_data_connection_is_for_one_transfer() {
    let server = start().await;
    let mut client = Client::connect(&server).await;
    client.login().await;
    let address = client.pasv().await;
    let stream = connect(address).await;
    assert_eq!(client.code("NLST").await, 150);
    read_all(stream).await;
    assert_eq!(client.reply().await.0, 226);
    // The port is closed, and the next transfer needs a new PASV
    assert!(TcpStream::connect(address).await.is_err());
    assert_eq!(client.code("NLST").await, 425);
}

// The behaviours that libunftp got wrong (plan, section 3)

#[tokio::test]
async fn a_new_pasv_closes_the_previous_port_at_once() {
    let server = start().await;
    let mut client = Client::connect(&server).await;
    client.login().await;
    let first = client.pasv().await;
    let second = client.pasv().await;
    assert_ne!(first.port(), second.port());
    // The first port doesn't listen any more: only one passive port per session
    assert!(TcpStream::connect(first).await.is_err(), "the first port must be closed");
    let third = client.epsv().await;
    assert!(TcpStream::connect(second).await.is_err(), "EPSV closes the port of PASV too");
    let stream = connect(third).await;
    assert_eq!(client.code("NLST").await, 150);
    read_all(stream).await;
    assert_eq!(client.reply().await.0, 226);
}

#[tokio::test]
async fn a_data_connection_from_another_address_is_closed_and_the_port_keeps_waiting() {
    let server = start().await;
    let mut client = Client::connect(&server).await;
    client.login().await;
    upload(&mut client, "f.txt", b"content").await;
    let address = client.pasv().await;
    // 127.0.0.2 is not the address of the client (127.0.0.1)
    let socket = TcpSocket::new_v4().unwrap();
    socket.bind("127.0.0.2:0".parse().unwrap()).unwrap();
    let mut stranger = socket.connect(address).await.unwrap();
    // No 150 yet: the data connection is not there
    client.send("RETR f.txt").await;
    let mut byte = [0u8; 1];
    let read = tokio::time::timeout(Duration::from_secs(5), stranger.read(&mut byte)).await.expect("the stranger was not closed");
    assert!(matches!(read, Ok(0) | Err(_)), "the stranger must get nothing");
    // The stranger did not use up the port: the client connects, and gets its file
    let stream = connect(address).await;
    assert_eq!(client.reply().await.0, 150);
    assert_eq!(read_all(stream).await, b"content");
    assert_eq!(client.reply().await.0, 226);
}

#[tokio::test]
async fn nothing_is_stored_from_a_stranger() {
    let server = start().await;
    let mut client = Client::connect(&server).await;
    client.login().await;
    let address = client.pasv().await;
    let socket = TcpSocket::new_v4().unwrap();
    socket.bind("127.0.0.2:0".parse().unwrap()).unwrap();
    let mut stranger = socket.connect(address).await.unwrap();
    let _ = stranger.write_all(b"evil").await;
    let _ = stranger.shutdown().await;
    client.send("STOR f.txt").await;
    let mut stream = connect(address).await;
    assert_eq!(client.reply().await.0, 150);
    stream.write_all(b"good").await.unwrap();
    stream.shutdown().await.unwrap();
    assert_eq!(client.reply().await.0, 226);
    assert_eq!(server.backend.files.lock().unwrap().get("/f.txt"), Some(&b"good".to_vec()));
}

#[tokio::test]
async fn abor_during_an_upload_is_answered_at_once_and_the_upload_is_dropped() {
    let server = start().await;
    let mut client = Client::connect(&server).await;
    client.login().await;
    upload(&mut client, "keep.txt", b"the old file").await;
    let address = client.pasv().await;
    let mut stream = connect(address).await;
    assert_eq!(client.code("STOR keep.txt").await, 150);
    stream.write_all(b"partial data, and no end").await.unwrap();
    eventually(|| server.backend.started_writes.load(Ordering::SeqCst) == 2).await;
    let start = Instant::now();
    // The Telnet sequence a client sends before ABOR, as RFC 959 describes
    client.send_bytes(b"\xff\xf4\xff\xf2ABOR\r\n").await;
    assert_eq!(client.reply().await.0, 426);
    assert_eq!(client.reply().await.0, 226);
    assert!(start.elapsed() < Duration::from_secs(3), "ABOR must be answered while the transfer runs: {:?}", start.elapsed());
    // The write was dropped, and the old file is kept
    assert_eq!(server.backend.aborted_writes.load(Ordering::SeqCst), 1);
    assert_eq!(server.backend.files.lock().unwrap().get("/keep.txt"), Some(&b"the old file".to_vec()));
    // The data connection is closed by the server
    let mut buffer = [0u8; 1];
    assert!(matches!(tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buffer)).await, Ok(Ok(0)) | Ok(Err(_))));
    // And the session goes on
    assert_eq!(client.code("NOOP").await, 200);
    let ended = server.events.ended.lock().unwrap().clone();
    assert_eq!(ended.last().map(|(_, end)| end.clone()), Some(TransferEnd::Aborted));
}

#[tokio::test]
async fn abor_before_the_client_connects_is_answered() {
    let server = start().await;
    let mut client = Client::connect(&server).await;
    client.login().await;
    let address = client.pasv().await;
    client.send("STOR f.txt").await;
    client.send("ABOR").await;
    // The client never connected: nothing was opened, so there is no 150
    assert_eq!(client.reply().await.0, 426);
    assert_eq!(client.reply().await.0, 226);
    assert!(TcpStream::connect(address).await.is_err(), "the port is given back");
    assert_eq!(client.code("NOOP").await, 200);
    assert_eq!(server.backend.started_writes.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn abor_during_a_download() {
    let server = start().await;
    let mut client = Client::connect(&server).await;
    client.login().await;
    // Much more than the sockets hold, so that the server is waiting for the client to read
    upload(&mut client, "big.bin", &pattern(40_000_000)).await;
    let address = client.pasv().await;
    let mut stream = connect(address).await;
    assert_eq!(client.code("RETR big.bin").await, 150);
    let mut some = vec![0u8; 1000];
    stream.read_exact(&mut some).await.unwrap();
    client.send("ABOR").await;
    assert_eq!(client.reply().await.0, 426);
    assert_eq!(client.reply().await.0, 226);
    assert_eq!(client.code("NOOP").await, 200);
}

#[tokio::test]
async fn stat_during_a_transfer_shows_the_progress() {
    let server = start().await;
    let mut client = Client::connect(&server).await;
    client.login().await;
    let address = client.pasv().await;
    let mut stream = connect(address).await;
    assert_eq!(client.code("STOR f.bin").await, 150);
    stream.write_all(&[7u8; 12_345]).await.unwrap();
    // The server reads it: wait for the number to show
    let mut text = String::new();
    for _ in 0..100 {
        let (code, lines) = client.command("STAT").await;
        assert_eq!(code, 211);
        text = lines.join("\n");
        if text.contains("12345 bytes") {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(text.contains("Receiving /f.bin: 12345 bytes so far"), "{text}");
    // Other commands wait for the end of the transfer; NOOP is answered
    assert_eq!(client.code("NOOP").await, 200);
    assert_eq!(client.code("CWD /").await, 450);
    assert_eq!(client.code("PASV").await, 450);
    stream.shutdown().await.unwrap();
    assert_eq!(client.reply().await.0, 226);
    assert_eq!(client.code("CWD /").await, 250);
}

#[tokio::test]
async fn quit_during_a_transfer_aborts_it_and_closes() {
    let server = start().await;
    let mut client = Client::connect(&server).await;
    client.login().await;
    let address = client.pasv().await;
    let mut stream = connect(address).await;
    assert_eq!(client.code("STOR f.bin").await, 150);
    stream.write_all(b"some").await.unwrap();
    eventually(|| server.backend.started_writes.load(Ordering::SeqCst) == 1).await;
    assert_eq!(client.code("QUIT").await, 221);
    assert!(client.closed().await);
    eventually(|| server.backend.aborted_writes.load(Ordering::SeqCst) == 1).await;
    assert!(server.backend.files.lock().unwrap().is_empty());
}

#[tokio::test]
async fn a_control_connection_that_closes_during_an_upload_drops_the_upload() {
    let server = start().await;
    let mut client = Client::connect(&server).await;
    client.login().await;
    let address = client.pasv().await;
    let mut stream = connect(address).await;
    assert_eq!(client.code("STOR f.bin").await, 150);
    stream.write_all(b"some").await.unwrap();
    eventually(|| server.backend.started_writes.load(Ordering::SeqCst) == 1).await;
    drop(client);
    eventually(|| server.backend.aborted_writes.load(Ordering::SeqCst) == 1).await;
    assert!(server.backend.files.lock().unwrap().is_empty());
    eventually(|| server.events.ended.lock().unwrap().iter().any(|(_, end)| *end == TransferEnd::Aborted)).await;
}

#[tokio::test]
async fn no_data_connection_in_time_is_425_and_the_session_goes_on() {
    let server = start_with({
        let mut config = Config::default();
        config.limits.data_accept_timeout = Duration::from_millis(300);
        config
    })
    .await;
    let mut client = Client::connect(&server).await;
    client.login().await;
    let address = client.pasv().await;
    assert_eq!(client.code("NLST").await, 425);
    assert!(TcpStream::connect(address).await.is_err(), "the port is given back");
    assert_eq!(client.code("NOOP").await, 200);
}

#[tokio::test]
async fn a_transfer_that_stands_still_is_aborted_with_426() {
    let server = start_with({
        let mut config = Config::default();
        config.limits.transfer_idle_timeout = Duration::from_millis(400);
        config
    })
    .await;
    let mut client = Client::connect(&server).await;
    client.login().await;
    let address = client.pasv().await;
    let mut stream = connect(address).await;
    assert_eq!(client.code("STOR f.bin").await, 150);
    stream.write_all(b"and then nothing").await.unwrap();
    let start = Instant::now();
    assert_eq!(client.reply().await.0, 426);
    assert!(start.elapsed() < Duration::from_secs(5));
    assert!(server.backend.files.lock().unwrap().is_empty(), "an upload that stood still is not stored");
    assert_eq!(server.backend.aborted_writes.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn a_slow_upload_that_keeps_moving_is_not_aborted() {
    let server = start_with({
        let mut config = Config::default();
        config.limits.transfer_idle_timeout = Duration::from_millis(500);
        config
    })
    .await;
    let mut client = Client::connect(&server).await;
    client.login().await;
    let address = client.pasv().await;
    let mut stream = connect(address).await;
    assert_eq!(client.code("STOR slow.bin").await, 150);
    // Longer than the idle time in all, never the idle time without a byte
    for _ in 0..8 {
        stream.write_all(b"0123456789").await.unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    stream.shutdown().await.unwrap();
    assert_eq!(client.reply().await.0, 226);
    assert_eq!(server.backend.files.lock().unwrap().get("/slow.bin").map(Vec::len), Some(80));
}

#[tokio::test]
async fn the_control_connection_is_not_idle_while_a_transfer_runs() {
    let server = start_with({
        let mut config = Config::default();
        config.idle_timeout = Duration::from_millis(400);
        config
    })
    .await;
    let mut client = Client::connect(&server).await;
    client.login().await;
    let address = client.pasv().await;
    let mut stream = connect(address).await;
    assert_eq!(client.code("STOR f.bin").await, 150);
    // The client waits for 226 longer than the idle time of the control connection
    for _ in 0..4 {
        stream.write_all(b"0123456789").await.unwrap();
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
    stream.shutdown().await.unwrap();
    assert_eq!(client.reply().await.0, 226);
    assert_eq!(client.code("NOOP").await, 200);
}

#[tokio::test]
async fn a_storage_error_after_150_is_the_final_reply() {
    let server = start().await;
    let mut client = Client::connect(&server).await;
    client.login().await;
    let address = client.pasv().await;
    let mut stream = connect(address).await;
    assert_eq!(client.code("STOR full.bin").await, 150);
    let _ = stream.write_all(b"data").await;
    assert_eq!(client.reply().await.0, 552);
    assert_eq!(client.code("NOOP").await, 200);
}

#[tokio::test]
async fn a_backend_that_panics_does_not_stop_the_session() {
    let server = start().await;
    let mut client = Client::connect(&server).await;
    client.login().await;
    let address = client.pasv().await;
    let mut stream = connect(address).await;
    assert_eq!(client.code("STOR panic.bin").await, 150);
    let _ = stream.write_all(b"data").await;
    assert_eq!(client.reply().await.0, 451);
    assert_eq!(client.code("NOOP").await, 200);
}

#[tokio::test]
async fn rest_is_for_retr_and_for_the_next_command_only() {
    let server = start().await;
    let mut client = Client::connect(&server).await;
    client.login().await;
    upload(&mut client, "f.txt", b"0123456789").await;
    assert_eq!(client.command("REST 4").await.0, 350);
    assert_eq!(download(&mut client, "f.txt").await, b"456789");
    // It is used up
    assert_eq!(download(&mut client, "f.txt").await, b"0123456789");
    // Another command between cancels it
    assert_eq!(client.code("REST 4").await, 350);
    assert_eq!(client.code("NOOP").await, 200);
    assert_eq!(download(&mut client, "f.txt").await, b"0123456789");
    // An offset at the end is an empty rest, one beyond it is invalid (RFC 1123 section 4.1.3.4)
    assert_eq!(client.code("REST 10").await, 350);
    assert_eq!(download(&mut client, "f.txt").await, b"");
    assert_eq!(client.code("REST 11").await, 350);
    client.pasv().await;
    assert_eq!(client.code("RETR f.txt").await, 554);
    // The backend stores whole files only
    assert_eq!(client.code("REST 4").await, 350);
    assert_eq!(client.code("STOR g.txt").await, 554);
    assert_eq!(client.code("REST 0").await, 350);
    upload(&mut client, "g.txt", b"x").await;
    assert_eq!(client.code("REST x").await, 501);
}

#[tokio::test]
async fn size_mdtm_and_mlst() {
    let server = start().await;
    let mut client = Client::connect(&server).await;
    client.login().await;
    upload(&mut client, "f.txt", b"12345").await;
    assert_eq!(client.command("SIZE f.txt").await, (213, vec!["5".to_string()]));
    assert_eq!(client.code("SIZE nowhere").await, 550);
    assert_eq!(client.code("SIZE /").await, 550);
    assert_eq!(client.command("MDTM f.txt").await, (213, vec!["20010909014640".to_string()]));
    assert_eq!(client.code("MDTM nowhere").await, 550);
    let (code, lines) = client.command("MLST f.txt").await;
    assert_eq!(code, 250);
    assert_eq!(lines, ["Listing /f.txt", " type=file;size=5;modify=20010909014640; /f.txt", "End"]);
    let (code, lines) = client.command("MLST /").await;
    assert_eq!(code, 250);
    assert!(lines[1].trim_start().starts_with("type=dir;"), "{lines:?}");
    assert_eq!(client.code("MLST nowhere").await, 550);
}

#[tokio::test]
async fn opts_mlst_chooses_the_facts() {
    let server = start().await;
    let mut client = Client::connect(&server).await;
    client.login().await;
    upload(&mut client, "f.txt", b"12345").await;
    let feat = client.command("FEAT").await.1;
    assert!(feat.iter().any(|line| line.trim() == "MLST type*;size*;modify*;"), "{feat:?}");
    assert_eq!(client.command("OPTS MLST size;perm;").await, (200, vec!["MLST OPTS size;".to_string()]));
    assert_eq!(listing(&mut client, "MLSD").await, "size=5; f.txt\r\n");
    let feat = client.command("FEAT").await.1;
    assert!(feat.iter().any(|line| line.trim() == "MLST size*;"), "{feat:?}");
}

#[tokio::test]
async fn stat_with_a_path_lists_on_the_control_connection() {
    let server = start().await;
    let mut client = Client::connect(&server).await;
    client.login().await;
    upload(&mut client, "f.txt", b"12345").await;
    let (code, lines) = client.command("STAT /").await;
    assert_eq!(code, 213);
    assert!(lines.iter().any(|line| line.ends_with(" f.txt")), "{lines:?}");
    assert_eq!(client.code("STAT nowhere").await, 550);
}

#[tokio::test]
async fn epsv_all_and_the_protocol_argument() {
    let server = start().await;
    let mut client = Client::connect(&server).await;
    client.login().await;
    assert_eq!(client.code("EPSV 1").await, 229);
    let (code, lines) = client.command("EPSV 2").await;
    assert_eq!((code, lines[0].as_str()), (522, "Network protocol not supported, use (1)"));
    assert_eq!(client.code("EPSV 9").await, 522);
    assert_eq!(client.code("EPSV x").await, 501);
    assert_eq!(client.code("EPSV ALL").await, 200);
    assert_eq!(client.code("PASV").await, 501, "RFC 2428: PASV is refused after EPSV ALL");
    assert_eq!(client.code("EPSV").await, 229);
}

#[tokio::test]
async fn the_passive_host_can_be_set() {
    let server = start_with({
        let mut config = Config::default();
        config.passive_host = thirtyftp::PassiveHost::Ip("203.0.113.9".parse().unwrap());
        config
    })
    .await;
    let mut client = Client::connect(&server).await;
    client.login().await;
    let (code, lines) = client.command("PASV").await;
    assert_eq!(code, 227);
    assert!(lines[0].starts_with("Entering Passive Mode (203,0,113,9,"), "{lines:?}");
    // EPSV tells no address: the client uses the control connection's
    assert_eq!(client.code("EPSV").await, 229);
    let server = start_with({
        let mut config = Config::default();
        config.passive_host = thirtyftp::PassiveHost::Dns("localhost".to_string());
        config
    })
    .await;
    let mut client = Client::connect(&server).await;
    client.login().await;
    let (code, lines) = client.command("PASV").await;
    assert_eq!(code, 227);
    assert!(lines[0].starts_with("Entering Passive Mode (127,0,0,1,"), "{lines:?}");
}

#[tokio::test]
async fn the_passive_ports_come_from_the_range_and_are_given_back() {
    // A free port: bind to 0 and let go
    let port = {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        listener.local_addr().unwrap().port()
    };
    let server = start_with({
        let mut config = Config::default();
        config.passive_ports = port..=port;
        config
    })
    .await;
    let mut first = Client::connect(&server).await;
    first.login().await;
    assert_eq!(first.pasv().await.port(), port);
    let mut second = Client::connect(&server).await;
    second.login().await;
    assert_eq!(second.code("PASV").await, 425, "the only port is used by the first session");
    // The first session lets go of it when it ends
    assert_eq!(first.code("QUIT").await, 221);
    drop(first);
    let mut address = None;
    for _ in 0..100 {
        let (code, lines) = second.command("PASV").await;
        if code == 227 {
            address = Some(lines);
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(address.is_some_and(|lines| lines[0].ends_with(&format!(",{},{}).", port >> 8, port & 0xff))));
}

#[tokio::test]
async fn events_tell_the_transfers() {
    let server = start().await;
    let mut client = Client::connect(&server).await;
    client.login().await;
    upload(&mut client, "f.txt", b"12345").await;
    download(&mut client, "f.txt").await;
    listing(&mut client, "NLST").await;
    let started = server.events.started.lock().unwrap().clone();
    assert_eq!(started.iter().map(|t| t.direction).collect::<Vec<_>>(), [Direction::Upload, Direction::Download, Direction::Listing]);
    assert_eq!(started[0].path.to_string(), "/f.txt");
    let ended = server.events.ended.lock().unwrap().clone();
    assert_eq!(ended.iter().map(|(_, end)| end.clone()).collect::<Vec<_>>(), [TransferEnd::Completed(5), TransferEnd::Completed(5), TransferEnd::Completed(7)]);
}

#[tokio::test]
async fn many_uploads_at_once() {
    let server = start().await;
    let mut tasks = Vec::new();
    for index in 0..20 {
        let server_address = server.address;
        tasks.push(tokio::spawn(async move {
            let mut client = Client { reader: tokio::io::BufReader::new(TcpStream::connect(server_address).await.unwrap()) };
            assert_eq!(client.reply().await.0, 220);
            client.login().await;
            let data = pattern(200_000 + index);
            upload(&mut client, &format!("file{index}.bin"), &data).await;
            assert_eq!(download(&mut client, &format!("file{index}.bin")).await, data);
        }));
    }
    for task in tasks {
        task.await.unwrap();
    }
    assert_eq!(server.backend.files.lock().unwrap().len(), 20);
}

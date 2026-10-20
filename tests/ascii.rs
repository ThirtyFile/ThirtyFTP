//! TYPE A: the bytes are not changed unless the host turns the conversion of line ends on

mod common;

use common::*;
use thirtyftp::Config;

const TEXT: &[u8] = b"line one\r\nline two\r\n\r\nlone\rcr\nbare lf\n";

#[tokio::test]
async fn by_default_ascii_transfers_do_not_change_the_bytes() {
    let server = start().await;
    let mut client = Client::connect(&server).await;
    client.login().await;
    assert_eq!(client.code("TYPE A").await, 200);
    upload(&mut client, "a.txt", TEXT).await;
    assert_eq!(server.backend.files.lock().unwrap().get("/a.txt"), Some(&TEXT.to_vec()));
    assert_eq!(download(&mut client, "a.txt").await, TEXT);
}

#[tokio::test]
async fn with_the_conversion_on_ascii_files_are_stored_with_lf_and_sent_with_crlf() {
    let server = start_with({
        let mut config = Config::default();
        config.ascii_conversion = true;
        config
    })
    .await;
    let mut client = Client::connect(&server).await;
    client.login().await;
    assert_eq!(client.code("TYPE A").await, 200);
    upload(&mut client, "a.txt", TEXT).await;
    assert_eq!(server.backend.files.lock().unwrap().get("/a.txt"), Some(&b"line one\nline two\n\nlone\rcr\nbare lf\n".to_vec()));
    assert_eq!(download(&mut client, "a.txt").await, b"line one\r\nline two\r\n\r\nlone\rcr\r\nbare lf\r\n");
    assert_eq!(client.command("SIZE a.txt").await.1, ["35"], "SIZE is of the stored file");
    // A binary transfer is not touched
    assert_eq!(client.code("TYPE I").await, 200);
    upload(&mut client, "b.bin", TEXT).await;
    assert_eq!(server.backend.files.lock().unwrap().get("/b.bin"), Some(&TEXT.to_vec()));
    assert_eq!(download(&mut client, "b.bin").await, TEXT);
    // And back
    assert_eq!(client.code("TYPE A").await, 200);
    assert_eq!(download(&mut client, "b.bin").await, b"line one\r\nline two\r\n\r\nlone\rcr\r\nbare lf\r\n".to_vec());
}

#[tokio::test]
async fn a_big_ascii_file_with_the_conversion_on() {
    let server = start_with({
        let mut config = Config::default();
        config.ascii_conversion = true;
        config
    })
    .await;
    let mut client = Client::connect(&server).await;
    client.login().await;
    assert_eq!(client.code("TYPE A").await, 200);
    let lines: String = (0..200_000).map(|i| format!("line {i}\r\n")).collect();
    upload(&mut client, "big.txt", lines.as_bytes()).await;
    let stored = server.backend.files.lock().unwrap().get("/big.txt").cloned().unwrap();
    assert_eq!(stored, lines.replace("\r\n", "\n").into_bytes());
    assert_eq!(download(&mut client, "big.txt").await, lines.as_bytes());
}

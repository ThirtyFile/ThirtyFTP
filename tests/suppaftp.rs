//! A real client library (suppaftp, which ThirtyFile's tests use) against the control connection

mod common;

use common::*;
use suppaftp::tokio::AsyncFtpStream;

#[tokio::test]
async fn sign_in_navigate_and_quit() {
    let server = start().await;
    let mut ftp = AsyncFtpStream::connect(server.address).await.unwrap();
    ftp.login("alice", "secret").await.unwrap();
    assert_eq!(ftp.pwd().await.unwrap(), "/");
    ftp.mkdir("scans").await.unwrap();
    ftp.cwd("scans").await.unwrap();
    assert_eq!(ftp.pwd().await.unwrap(), "/scans");
    ftp.cdup().await.unwrap();
    assert_eq!(ftp.pwd().await.unwrap(), "/");
    ftp.noop().await.unwrap();
    ftp.transfer_type(suppaftp::types::FileType::Binary).await.unwrap();
    assert!(ftp.cwd("missing").await.is_err());
    ftp.quit().await.unwrap();
}

#[tokio::test]
async fn a_wrong_password_is_an_error() {
    let server = start().await;
    let mut ftp = AsyncFtpStream::connect(server.address).await.unwrap();
    assert!(ftp.login("alice", "wrong").await.is_err());
}

async fn download(ftp: &mut AsyncFtpStream, name: &str) -> Result<Vec<u8>, suppaftp::FtpError> {
    let mut stream = ftp.retr_as_stream(name).await?;
    let mut bytes = vec![];
    tokio::io::AsyncReadExt::read_to_end(&mut stream, &mut bytes).await.map_err(suppaftp::FtpError::ConnectionError)?;
    stream.finish().await?;
    Ok(bytes)
}

async fn round_trip(mode: suppaftp::Mode) {
    let server = start().await;
    let mut ftp = AsyncFtpStream::connect(server.address).await.unwrap();
    ftp.set_mode(mode);
    ftp.login("alice", "secret").await.unwrap();
    ftp.transfer_type(suppaftp::types::FileType::Binary).await.unwrap();
    ftp.mkdir("in").await.unwrap();
    ftp.cwd("in").await.unwrap();
    let data: Vec<u8> = (0..300_000u32).map(|i| (i % 251) as u8).collect();
    let stored = ftp.put_file("scan 1.pdf", &mut std::io::Cursor::new(data.clone())).await.unwrap();
    assert_eq!(stored, data.len() as u64);
    assert_eq!(server.backend.files.lock().unwrap().get("/in/scan 1.pdf"), Some(&data));
    assert_eq!(ftp.size("scan 1.pdf").await.unwrap(), data.len());
    assert!(ftp.mdtm("scan 1.pdf").await.is_ok());
    assert_eq!(download(&mut ftp, "scan 1.pdf").await.unwrap(), data);
    assert_eq!(ftp.nlst(None).await.unwrap(), ["scan 1.pdf"]);
    let list = ftp.list(None).await.unwrap();
    assert_eq!(list.len(), 1);
    assert!(list[0].ends_with("scan 1.pdf") && list[0].starts_with("-rw"), "{list:?}");
    assert!(ftp.rm("scan 1.pdf").await.is_err(), "deleting is refused");
    assert!(ftp.rmdir("/in").await.is_err());
    assert!(ftp.rename("scan 1.pdf", "x").await.is_err());
    assert!(download(&mut ftp, "missing").await.is_err());
    ftp.noop().await.unwrap();
    ftp.quit().await.unwrap();
}

#[tokio::test]
async fn upload_download_and_listings_with_pasv() {
    round_trip(suppaftp::Mode::Passive).await;
}

#[tokio::test]
async fn upload_download_and_listings_with_epsv() {
    round_trip(suppaftp::Mode::ExtendedPassive).await;
}

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

#![no_main]

use libfuzzer_sys::fuzz_target;
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use thirtyftp::{Backend, Config, Entry, FsError, FtpPath, LoginContext, LoginError, NoEvents, serve};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// A backend with one file and one directory, which accepts everything it is sent
struct Tiny;

impl Backend for Tiny {
    type User = ();

    async fn login(&self, _: &LoginContext, _: &str, _: &str) -> Result<(), LoginError> {
        Ok(())
    }

    async fn metadata(&self, _: &(), path: &FtpPath) -> Result<Entry, FsError> {
        match path.to_string().as_str() {
            "/" | "/dir" => Ok(Entry::directory("dir", None)),
            "/file" => Ok(Entry::file("file", 3, None)),
            _ => Err(FsError::NotFound),
        }
    }

    async fn list(&self, _: &(), path: &FtpPath) -> Result<Vec<Entry>, FsError> {
        match path.to_string().as_str() {
            "/" | "/dir" => Ok(vec![Entry::file("file", 3, None), Entry::directory("dir", None)]),
            "/file" => Err(FsError::WrongType),
            _ => Err(FsError::NotFound),
        }
    }

    async fn read(&self, _: &(), path: &FtpPath, _: u64) -> Result<Box<dyn AsyncRead + Send + Unpin>, FsError> {
        if path.to_string() == "/file" { Ok(Box::new(std::io::Cursor::new(b"abc".to_vec()))) } else { Err(FsError::NotFound) }
    }

    async fn write(&self, _: &(), _: &FtpPath, data: &mut (dyn AsyncRead + Send + Unpin)) -> Result<u64, FsError> {
        let mut sink = Vec::new();
        data.take(1 << 20).read_to_end(&mut sink).await.map_err(|e| FsError::Local(e.to_string()))?;
        Ok(sink.len() as u64)
    }

    async fn make_dir(&self, _: &(), _: &FtpPath) -> Result<(), FsError> {
        Ok(())
    }

    async fn change_dir(&self, _: &(), path: &FtpPath) -> Result<(), FsError> {
        if path.to_string() == "/" || path.to_string() == "/dir" { Ok(()) } else { Err(FsError::NotFound) }
    }
}

fn runtime() -> &'static tokio::runtime::Runtime {
    static RUNTIME: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    RUNTIME.get_or_init(|| tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap())
}

fuzz_target!(|data: &[u8]| {
    runtime().block_on(async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let mut config = Config::default();
        config.passive_ports = 0..=0;
        config.limits.data_accept_timeout = Duration::from_millis(100);
        config.limits.transfer_idle_timeout = Duration::from_millis(100);
        config.idle_timeout = Duration::from_secs(5);
        config.active_mode = data.first().is_some_and(|byte| byte & 1 == 1);
        let server = tokio::spawn(async move {
            let (stream, peer) = listener.accept().await.unwrap();
            serve(stream, peer, Arc::new(config), Arc::new(Tiny), Arc::new(NoEvents)).await
        });
        let mut client = TcpStream::connect(address).await.unwrap();
        // Half of the runs sign in first, so that the commands that need a user are reached
        let login: &[u8] = if data.first().is_some_and(|byte| byte & 2 == 2) { b"USER a\r\nPASS b\r\n" } else { b"" };
        let _ = client.write_all(login).await;
        let _ = client.write_all(data).await;
        let _ = client.shutdown().await;
        let mut sink = Vec::new();
        let _ = tokio::time::timeout(Duration::from_secs(3), client.read_to_end(&mut sink)).await;
        drop(client);
        match tokio::time::timeout(Duration::from_secs(8), server).await {
            Ok(Ok(_end)) => {}
            Ok(Err(error)) => panic!("the session task failed: {error}"),
            Err(_) => panic!("the session did not end after the client closed"),
        }
    });
});

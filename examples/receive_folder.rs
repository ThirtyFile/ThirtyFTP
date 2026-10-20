//! A receive folder: devices such as scanners and cameras upload files into one folder, and can't list, read or delete anything.
//!
//! ```sh
//! cargo run --example receive_folder -- --dir ./incoming --user scanner --password change-me
//! ```
//!
//! Options: `--dir <folder>` (default `./incoming`), `--user <name>` and `--password <text>` (required), `--port <number>` (default 2121), and
//! `--cert <file.pem> --key <file.pem>` to offer explicit FTPS and require it.
//!
//! The point to see is [`Backend::write`]: an upload goes to a temporary file next to the final one, and replaces the final file only when the
//! whole upload has arrived. When the transfer is aborted or cut off, the future is dropped, the temporary file is removed, and the file that was
//! there before stays.

use async_trait::async_trait;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use thirtyftp::{Backend, Config, Entry, Events, FsError, FtpPath, LoginContext, LoginError, SessionEnd, TransferEnd, TransferInfo, serve};
use tokio::io::{AsyncRead, AsyncWriteExt};
use tokio::net::TcpListener;

struct ReceiveFolder {
    root: PathBuf,
    user: String,
    password: String,
}

/// The temporary file of an upload. It is removed unless the upload was completed
struct PartFile {
    path: PathBuf,
    complete: bool,
}

impl Drop for PartFile {
    fn drop(&mut self) {
        if !self.complete {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

impl ReceiveFolder {
    /// The place on disk of a path of the session. The library has resolved `.` and `..` already; what is left to refuse are the names that the file
    /// system treats in its own way
    fn locate(&self, path: &FtpPath) -> Result<PathBuf, FsError> {
        let mut location = self.root.clone();
        for name in path.components() {
            let special = name.contains(['\\', ':', '<', '>', '"', '|', '?', '*']) || name.ends_with(['.', ' ']) || name.starts_with(".part-");
            if special {
                return Err(FsError::NameNotAllowed);
            }
            location.push(name);
        }
        Ok(location)
    }
}

fn io_error(error: std::io::Error) -> FsError {
    match error.kind() {
        std::io::ErrorKind::NotFound => FsError::NotFound,
        std::io::ErrorKind::PermissionDenied => FsError::PermissionDenied,
        std::io::ErrorKind::AlreadyExists => FsError::AlreadyExists,
        _ => FsError::Local(error.to_string()),
    }
}

#[async_trait]
impl Backend for ReceiveFolder {
    type User = ();

    async fn login(&self, _context: &LoginContext, user: &str, password: &str) -> Result<(), LoginError> {
        // A real host compares in constant time, counts the failures of an address, and looks the user up
        if user == self.user && password == self.password { Ok(()) } else { Err(LoginError::Incorrect) }
    }

    async fn metadata(&self, _: &(), path: &FtpPath) -> Result<Entry, FsError> {
        let metadata = tokio::fs::metadata(self.locate(path)?).await.map_err(io_error)?;
        let name = path.file_name().unwrap_or("/");
        // Devices send files; they don't get to see what is there
        if metadata.is_dir() { Ok(Entry::directory(name, None)) } else { Err(FsError::PermissionDenied) }
    }

    async fn list(&self, _: &(), _: &FtpPath) -> Result<Vec<Entry>, FsError> {
        Err(FsError::PermissionDenied)
    }

    async fn read(&self, _: &(), _: &FtpPath, _: u64) -> Result<Box<dyn AsyncRead + Send + Unpin>, FsError> {
        Err(FsError::PermissionDenied)
    }

    async fn write(&self, _: &(), path: &FtpPath, data: &mut (dyn AsyncRead + Send + Unpin)) -> Result<u64, FsError> {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let target = self.locate(path)?;
        let parent = target.parent().ok_or(FsError::NameNotAllowed)?;
        let part = PartFile { path: parent.join(format!(".part-{}-{}", std::process::id(), COUNTER.fetch_add(1, Ordering::Relaxed))), complete: false };
        let mut part = part;
        let mut file = tokio::fs::File::create(&part.path).await.map_err(io_error)?;
        // If this future is dropped here, the upload did not complete: `part` removes its file
        let length = tokio::io::copy(data, &mut file).await.map_err(io_error)?;
        file.flush().await.map_err(io_error)?;
        file.sync_all().await.map_err(io_error)?;
        drop(file);
        tokio::fs::rename(&part.path, &target).await.map_err(io_error)?;
        part.complete = true;
        Ok(length)
    }

    async fn make_dir(&self, _: &(), path: &FtpPath) -> Result<(), FsError> {
        tokio::fs::create_dir(self.locate(path)?).await.map_err(io_error)
    }

    async fn change_dir(&self, _: &(), path: &FtpPath) -> Result<(), FsError> {
        let metadata = tokio::fs::metadata(self.locate(path)?).await.map_err(io_error)?;
        if metadata.is_dir() { Ok(()) } else { Err(FsError::WrongType) }
    }
}

/// What the host learns from the library: here it only prints it
struct Log;

impl Events for Log {
    fn signed_in(&self, peer: std::net::SocketAddr, user: &str) {
        println!("{peer}: {user} signed in");
    }

    fn login_failed(&self, peer: std::net::SocketAddr, user: &str) {
        println!("{peer}: sign-in as {user} failed");
    }

    fn transfer_ended(&self, peer: std::net::SocketAddr, _: &str, transfer: &TransferInfo, end: &TransferEnd) {
        println!("{peer}: {:?} {}: {end:?}", transfer.direction, transfer.path);
    }
}

fn tls_config(certificate: &Path, key: &Path) -> Result<Arc<rustls::ServerConfig>, Box<dyn std::error::Error>> {
    let certificates = CertificateDer::pem_file_iter(certificate)?.collect::<Result<Vec<_>, _>>()?;
    let key = PrivateKeyDer::from_pem_file(key)?;
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let config =
        rustls::ServerConfig::builder_with_provider(provider).with_safe_default_protocol_versions()?.with_no_client_auth().with_single_cert(certificates, key)?;
    Ok(Arc::new(config))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut options = std::collections::HashMap::new();
    let mut arguments = std::env::args().skip(1);
    while let Some(name) = arguments.next() {
        let value = arguments.next().ok_or_else(|| format!("{name} needs a value"))?;
        options.insert(name, value);
    }
    let root = PathBuf::from(options.get("--dir").map(String::as_str).unwrap_or("./incoming"));
    tokio::fs::create_dir_all(&root).await?;
    let user = options.get("--user").ok_or("--user is required")?.clone();
    let password = options.get("--password").ok_or("--password is required")?.clone();
    let port: u16 = options.get("--port").map(|port| port.parse()).transpose()?.unwrap_or(2121);

    let mut config = Config::default();
    if let (Some(certificate), Some(key)) = (options.get("--cert"), options.get("--key")) {
        config.tls = Some(tls_config(Path::new(certificate), Path::new(key))?);
        config.require_tls = true;
    }
    let config = Arc::new(config);
    let backend = Arc::new(ReceiveFolder { root, user, password });

    let listener = TcpListener::bind(("0.0.0.0", port)).await?;
    println!("Receiving into {} on port {port}{}", backend.root.display(), if config.require_tls { " (FTPS required)" } else { "" });
    // The host accepts the connections, and decides who may connect and how many at once: this example lets everyone in
    loop {
        let (stream, peer) = listener.accept().await?;
        let (config, backend) = (config.clone(), backend.clone());
        tokio::spawn(async move {
            let end = serve(stream, peer, config, backend, Arc::new(Log)).await;
            if let SessionEnd::Io(error) = &end {
                println!("{peer}: connection failed: {error}");
            }
        });
    }
}

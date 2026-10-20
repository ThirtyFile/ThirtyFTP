//! A receive folder: devices such as scanners and cameras upload files into one folder, and can't list, read or delete anything.
//!
//! ```sh
//! cargo run --example receive_folder -- --dir ./incoming --user scanner --password change-me
//! ```
//!
//! Options: `--dir <folder>` (default `./incoming`), `--user <name>` and `--password <text>` (required), `--port <number>` (default 2121),
//! `--max-size <bytes>` (the biggest file; default 1 GiB), `--max-connections <number>` (default 100), and `--cert <file.pem> --key <file.pem>` to offer
//! explicit FTPS and require it.
//!
//! Things to see:
//! - [`Backend::write`]: an upload goes to a temporary file next to the final one, and replaces the final file only when the whole upload has arrived.
//!   When the transfer is aborted or cut off, the future is dropped, the temporary file is removed, and the file that was there before stays.
//! - The size of a file is limited here, by the backend: the library moves what the client sends for as long as the client sends it.
//! - `FtpPath::to_native` places a path under the folder, and refuses the names that Windows treats in its own way.
//! - The host limits the connections: the library serves the ones it is given.

use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use thirtyftp::{Backend, Config, Entry, Events, FsError, FtpPath, LoginContext, LoginError, SessionEnd, TransferEnd, TransferInfo, serve};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt, BufWriter};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;

struct ReceiveFolder {
    root: PathBuf,
    user: String,
    password: String,
    max_size: u64,
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

/// The start of the name of a temporary file
const PART: &str = ".part-";

impl ReceiveFolder {
    /// The place on disk of a path of the session. The library has resolved `.` and `..`; `to_native` refuses the names that the file system treats in its
    /// own way; and the names of the temporary files are the library user's to keep for itself
    fn locate(&self, path: &FtpPath) -> Result<PathBuf, FsError> {
        if path.components().iter().any(|name| name.to_ascii_lowercase().starts_with(PART)) {
            return Err(FsError::NameNotAllowed);
        }
        path.to_native(&self.root).map_err(|_| FsError::NameNotAllowed)
    }
}

impl Backend for ReceiveFolder {
    type User = ();

    async fn login(&self, _context: &LoginContext, user: &str, password: &str) -> Result<(), LoginError> {
        // A real host compares in constant time, counts the failures of an address, and looks the user up
        if user == self.user && password == self.password { Ok(()) } else { Err(LoginError::Incorrect) }
    }

    async fn metadata(&self, _: &(), path: &FtpPath) -> Result<Entry, FsError> {
        let metadata = tokio::fs::metadata(self.locate(path)?).await?;
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
        let mut part = PartFile { path: parent.join(format!("{PART}{}-{}", std::process::id(), COUNTER.fetch_add(1, Ordering::Relaxed))), complete: false };
        let file = tokio::fs::File::create(&part.path).await?;
        // Small reads and writes to a file are slow: each goes to the pool of blocking threads. A megabyte at a time is 15 times faster
        let mut file = BufWriter::with_capacity(1 << 20, file);
        // One byte more than the limit is read, to tell a file of exactly the limit from one that is too big. The upload is read to its end
        let length = tokio::io::copy(&mut data.take(self.max_size + 1), &mut file).await?;
        if length > self.max_size {
            return Err(FsError::QuotaExceeded);
        }
        // If this future is dropped before the end, the upload did not complete: `part` removes its file
        file.flush().await?;
        file.get_ref().sync_all().await?;
        drop(file);
        tokio::fs::rename(&part.path, &target).await?;
        part.complete = true;
        Ok(length)
    }

    async fn make_dir(&self, _: &(), path: &FtpPath) -> Result<(), FsError> {
        Ok(tokio::fs::create_dir(self.locate(path)?).await?)
    }

    async fn change_dir(&self, _: &(), path: &FtpPath) -> Result<(), FsError> {
        let metadata = tokio::fs::metadata(self.locate(path)?).await?;
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
    let max_size: u64 = options.get("--max-size").map(|size| size.parse()).transpose()?.unwrap_or(1 << 30);
    let max_connections: usize = options.get("--max-connections").map(|number| number.parse()).transpose()?.unwrap_or(100);

    let mut config = Config::default();
    if let (Some(certificate), Some(key)) = (options.get("--cert"), options.get("--key")) {
        config.tls = Some(tls_config(Path::new(certificate), Path::new(key))?);
        config.require_tls = true;
    }
    let config = Arc::new(config);
    let backend = Arc::new(ReceiveFolder { root, user, password, max_size });

    let listener = TcpListener::bind(("0.0.0.0", port)).await?;
    println!("Receiving into {} on port {port}{}", backend.root.display(), if config.require_tls { " (FTPS required)" } else { "" });
    // The host accepts the connections, and decides who may connect and how many at once: this one keeps the number of connections, and closes the
    // ones that come when there are too many. Counting them per address is the next step
    let permits = Arc::new(Semaphore::new(max_connections));
    loop {
        let (stream, peer) = listener.accept().await?;
        let Ok(permit) = permits.clone().try_acquire_owned() else {
            println!("{peer}: refused, there are {max_connections} connections");
            continue;
        };
        let (config, backend) = (config.clone(), backend.clone());
        tokio::spawn(async move {
            let end = serve(stream, peer, config, backend, Arc::new(Log)).await;
            if let SessionEnd::Io(error) = &end {
                println!("{peer}: connection failed: {error}");
            }
            drop(permit);
        });
    }
}

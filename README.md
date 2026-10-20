# ThirtyFTP

A small FTP and FTPS server library for Rust, on Tokio and rustls. You accept the connections; ThirtyFTP speaks the protocol; a backend that you write
decides who may sign in and where the files go. It suits **receive folders**, where scanners, cameras and other devices upload files, and any program
that needs an FTP endpoint.

- Passive mode and explicit FTPS (`AUTH TLS`); active mode as an option
- Uploads, and listing and downloads when your backend allows them; making folders
- Deleting, renaming and `SITE` are refused, as a receive folder keeps what it is sent
- No `unsafe`, and no panic on anything a client sends

## Add it

```toml
[dependencies]
thirtyftp = { git = "https://github.com/ThirtyFile/ThirtyFTP" }
tokio = { version = "1", features = ["full"] }
```

(It will be on crates.io; then `thirtyftp = "0.1"`.)

## A server in one file

A backend answers six questions: who may sign in, what a path is, what a folder holds, how to read a file, how to store one, and how to make a folder.
This one accepts one user and counts the bytes of what is uploaded:

```rust,no_run
use std::sync::Arc;
use thirtyftp::{Backend, Config, Entry, FsError, FtpPath, LoginContext, LoginError, NoEvents, serve};
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::net::TcpListener;

struct Uploads;

impl Backend for Uploads {
    type User = ();

    async fn login(&self, _: &LoginContext, user: &str, password: &str) -> Result<(), LoginError> {
        if user == "scanner" && password == "change-me" { Ok(()) } else { Err(LoginError::Incorrect) }
    }

    async fn metadata(&self, _: &(), _: &FtpPath) -> Result<Entry, FsError> {
        Err(FsError::PermissionDenied)
    }

    async fn list(&self, _: &(), _: &FtpPath) -> Result<Vec<Entry>, FsError> {
        Err(FsError::PermissionDenied)
    }

    async fn read(&self, _: &(), _: &FtpPath, _: u64) -> Result<Box<dyn AsyncRead + Send + Unpin>, FsError> {
        Err(FsError::PermissionDenied)
    }

    async fn write(&self, _: &(), path: &FtpPath, data: &mut (dyn AsyncRead + Send + Unpin)) -> Result<u64, FsError> {
        let mut bytes = Vec::new();
        data.read_to_end(&mut bytes).await?;
        println!("{path}: {} bytes", bytes.len());
        Ok(bytes.len() as u64)
    }

    async fn make_dir(&self, _: &(), _: &FtpPath) -> Result<(), FsError> {
        Err(FsError::PermissionDenied)
    }

    async fn change_dir(&self, _: &(), _: &FtpPath) -> Result<(), FsError> {
        Ok(())
    }
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let listener = TcpListener::bind("0.0.0.0:2121").await?;
    let config = Arc::new(Config::default());
    let backend = Arc::new(Uploads);
    loop {
        let (stream, peer) = listener.accept().await?;
        tokio::spawn(serve(stream, peer, config.clone(), backend.clone(), Arc::new(NoEvents)));
    }
}
```

Try it with any client:

```sh
curl --user scanner:change-me -T photo.jpg ftp://127.0.0.1:2121/photo.jpg
lftp -u scanner,change-me -e "put photo.jpg; bye" ftp://127.0.0.1:2121
python3 -c "import ftplib; f = ftplib.FTP(); f.connect('127.0.0.1', 2121); f.login('scanner', 'change-me'); f.storbinary('STOR photo.jpg', open('photo.jpg', 'rb'))"
```

## Store the files in a folder

[`examples/receive_folder.rs`](examples/receive_folder.rs) is a complete receive folder: one user, a folder on disk, a size limit, a limit on the
connections, and optional FTPS.

```sh
cargo run --example receive_folder -- --dir ./incoming --user scanner --password change-me
cargo run --example receive_folder -- --dir ./incoming --user scanner --password change-me --cert cert.pem --key key.pem
```

The part of a backend that touches the disk is two calls. `to_native` puts a path under your folder, and refuses the names that Windows treats in its own
way (`C:`, `..\x`, `CON`, `aux.txt`, a name that ends with a dot):

```rust,ignore
let place = path.to_native(&self.root).map_err(|_| FsError::NameNotAllowed)?;
let file = tokio::fs::File::create(&place).await?;
```

An upload that does not complete must leave nothing behind: `write` is dropped when the client aborts or the connection is cut, so write to a temporary
file and rename it when `write` has read all the data (the example does).

## Offer FTPS

Build a `rustls::ServerConfig` with your certificate and give it to the library. With `require_tls` a client must use `AUTH TLS` before it signs in, and
`PROT P` before it moves data:

```rust,no_run
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::sync::Arc;
use thirtyftp::Config;

fn config() -> Result<Config, Box<dyn std::error::Error>> {
    let certificates = CertificateDer::pem_file_iter("cert.pem")?.collect::<Result<Vec<_>, _>>()?;
    let key = PrivateKeyDer::from_pem_file("key.pem")?;
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let tls = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_single_cert(certificates, key)?;

    let mut config = Config::default();
    config.tls = Some(Arc::new(tls));
    config.require_tls = true;
    Ok(config)
}
```

The library asks rustls for no crypto provider: use `aws-lc-rs` or `ring`, whichever your program has. Many old scanners and cameras speak TLS 1.2 only; enable
the `tls12` feature of rustls for them.

## Behind NAT, a firewall or Docker

A client connects its data connection to a port of the server. Choose the ports, publish them, and tell clients which address to use:

```rust,no_run
use thirtyftp::{Config, PassiveHost};

fn main() {
    let mut config = Config::default();
    config.passive_ports = 50000..=50100;
    config.passive_host = PassiveHost::Dns("ftp.example.com".to_string());
}
```

```sh
docker run -p 2121:2121 -p 50000-50100:50000-50100 my-ftp-server
```

`PassiveHost::Ip(..)` gives an address, and `PassiveHost::FromConnection` (the default) the address the client connected to.

## Limit the connections and see what happens

The library serves the connections it is given. Counting them, and refusing the ones that are too many, is yours; `Events` tells you about sign-ins and
transfers:

```rust,no_run
use std::net::SocketAddr;
use std::sync::Arc;
use thirtyftp::{Events, TransferEnd, TransferInfo};
use tokio::sync::Semaphore;

struct Log;

impl Events for Log {
    fn signed_in(&self, peer: SocketAddr, user: &str) {
        println!("{peer}: {user} signed in");
    }

    fn login_failed(&self, peer: SocketAddr, user: &str) {
        println!("{peer}: sign-in as {user} failed");
    }

    fn transfer_ended(&self, peer: SocketAddr, _user: &str, transfer: &TransferInfo, end: &TransferEnd) {
        println!("{peer}: {:?} {}: {end:?}", transfer.direction, transfer.path);
    }
}

fn main() {
    // In the loop that accepts: `let Ok(permit) = permits.clone().try_acquire_owned() else { continue };`, and drop the permit when the session ends
    let permits = Arc::new(Semaphore::new(100));
    let events: Arc<dyn Events> = Arc::new(Log);
    let _ = (permits, events);
}
```

## Settings

`Config::default()` is a sensible start: a 5-minute idle time, 3 sign-in attempts, 60 seconds to sign in, passive ports 49152 to 65535. Change what you need:

```rust,no_run
use std::time::Duration;
use thirtyftp::Config;

fn main() {
    let mut config = Config::default();
    config.greeting = "Scan here".to_string();
    config.idle_timeout = Duration::from_secs(120);
    config.limits.max_login_attempts = 5;
    config.limits.login_timeout = Duration::from_secs(20);
    config.limits.max_transfer_time = Some(Duration::from_secs(3600));
    config.ascii_conversion = true; // CRLF <-> LF for TYPE A; off keeps the bytes as they are
    config.active_mode = false; // PORT and EPRT, only to the client's own address and ports from 1024 up
}
```

Every setting is documented on `Config` and `Limits` in the crate documentation.

## Good to know

- A backend's `write` reads to the end of the data, and keeps nothing if it is dropped or fails. The size of a file is the backend's to limit.
- `QUIT` or a closed control connection lets a transfer that has its data finish, so a camera that doesn't wait for the `226` doesn't lose its file.
- A connection from another address than the client's is never used as its data connection. Two clients behind one NAT address could race for a passive
  port; give them separate port ranges, or use FTPS on a network where the address is the client.
- The host counts connections and failed sign-ins per address; the library closes a connection after 3 failed sign-ins.
- The specifications followed, row by row with the tests that show them, are on the `conformance` page of the crate documentation.

## Contributing

See [CONTRIBUTING](.github/CONTRIBUTING.md). Security problems are reported privately: [SECURITY](.github/SECURITY.md).

## Licence

[Apache-2.0](LICENSE)

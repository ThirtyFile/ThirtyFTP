//! A small backend in memory, and a client that speaks raw FTP, for the tests

#![allow(dead_code)] // Each test file uses part of this

use async_trait::async_trait;
use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use thirtyftp::{Backend, Config, Entry, Events, FsError, FtpPath, LoginContext, LoginError, SessionEnd, TransferEnd, TransferInfo, serve};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

/// Users and password `alice`/`secret`, `bob`/`hunter2`; the directories and files in memory
#[derive(Default)]
pub struct Memory {
    pub directories: Mutex<BTreeSet<String>>,
    pub files: Mutex<BTreeMap<String, Vec<u8>>>,
    pub logins: Mutex<Vec<(LoginContext, String)>>,
    /// Make `login` say the user store is down
    pub down: Mutex<bool>,
    /// How many uploads began, and how many of them did not complete (the future was dropped, or the data failed)
    pub started_writes: AtomicUsize,
    pub aborted_writes: AtomicUsize,
}

/// The time every file of the memory was last changed: 2001-09-09 01:46:40 UTC
pub fn modified() -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(1_000_000_000)
}

/// Counts an upload as aborted when it is dropped before it is done
struct WriteGuard<'a> {
    done: bool,
    aborted: &'a AtomicUsize,
}

impl Drop for WriteGuard<'_> {
    fn drop(&mut self) {
        if !self.done {
            self.aborted.fetch_add(1, Ordering::SeqCst);
        }
    }
}

impl Memory {
    pub fn new() -> Arc<Memory> {
        let memory = Memory::default();
        memory.directories.lock().unwrap().insert("/".to_string());
        Arc::new(memory)
    }
}

#[async_trait]
impl Backend for Memory {
    type User = String;

    async fn login(&self, context: &LoginContext, user: &str, password: &str) -> Result<String, LoginError> {
        if *self.down.lock().unwrap() {
            return Err(LoginError::Unavailable);
        }
        self.logins.lock().unwrap().push((context.clone(), user.to_string()));
        match (user, password) {
            ("alice", "secret") | ("bob", "hunter2") | ("space", " pass word ") | ("empty", "") => Ok(user.to_string()),
            ("blocked", _) => Err(LoginError::Refused("This user is blocked.".to_string())),
            _ => Err(LoginError::Incorrect),
        }
    }

    async fn metadata(&self, _: &String, path: &FtpPath) -> Result<Entry, FsError> {
        let key = path.to_string();
        let name = path.file_name().unwrap_or("/").to_string();
        if self.directories.lock().unwrap().contains(&key) {
            return Ok(Entry::directory(name, None));
        }
        match self.files.lock().unwrap().get(&key) {
            Some(data) => Ok(Entry::file(name, data.len() as u64, Some(modified()))),
            None => Err(FsError::NotFound),
        }
    }

    async fn list(&self, _: &String, path: &FtpPath) -> Result<Vec<Entry>, FsError> {
        let key = path.to_string();
        if self.files.lock().unwrap().contains_key(&key) {
            return Err(FsError::WrongType);
        }
        if !self.directories.lock().unwrap().contains(&key) {
            return Err(FsError::NotFound);
        }
        let mut entries = Vec::new();
        for directory in self.directories.lock().unwrap().iter() {
            if directory != "/" && FtpPath::resolve(&FtpPath::root(), directory).unwrap().parent() == *path {
                entries.push(Entry::directory(directory.rsplit('/').next().unwrap(), None));
            }
        }
        for (file, data) in self.files.lock().unwrap().iter() {
            if FtpPath::resolve(&FtpPath::root(), file).unwrap().parent() == *path {
                entries.push(Entry::file(file.rsplit('/').next().unwrap(), data.len() as u64, Some(modified())));
            }
        }
        Ok(entries)
    }

    async fn read(&self, _: &String, path: &FtpPath, offset: u64) -> Result<Box<dyn AsyncRead + Send + Unpin>, FsError> {
        match self.files.lock().unwrap().get(&path.to_string()) {
            Some(data) => Ok(Box::new(std::io::Cursor::new(data[(offset as usize).min(data.len())..].to_vec()))),
            None => Err(FsError::NotFound),
        }
    }

    async fn write(&self, _: &String, path: &FtpPath, data: &mut (dyn AsyncRead + Send + Unpin)) -> Result<u64, FsError> {
        match path.file_name() {
            Some("full.bin") => return Err(FsError::QuotaExceeded),
            Some("busy.bin") => return Err(FsError::Unavailable),
            Some("panic.bin") => panic!("the backend panics"),
            _ => {}
        }
        self.started_writes.fetch_add(1, Ordering::SeqCst);
        let mut guard = WriteGuard { done: false, aborted: &self.aborted_writes };
        let mut bytes = Vec::new();
        data.read_to_end(&mut bytes).await.map_err(|e| FsError::Local(e.to_string()))?;
        let length = bytes.len() as u64;
        if path.file_name() == Some("slowend.bin") {
            // The storage takes its time after the last byte, as a big file being moved into place does
            tokio::time::sleep(Duration::from_millis(1500)).await;
        }
        // Stored only when the data came to its end
        self.files.lock().unwrap().insert(path.to_string(), bytes);
        guard.done = true;
        Ok(length)
    }

    async fn make_dir(&self, _: &String, path: &FtpPath) -> Result<(), FsError> {
        let mut directories = self.directories.lock().unwrap();
        if !directories.contains(&path.parent().to_string()) {
            return Err(FsError::NotFound);
        }
        if !directories.insert(path.to_string()) {
            return Err(FsError::AlreadyExists);
        }
        Ok(())
    }

    async fn change_dir(&self, _: &String, path: &FtpPath) -> Result<(), FsError> {
        if self.directories.lock().unwrap().contains(&path.to_string()) { Ok(()) } else { Err(FsError::NotFound) }
    }
}

/// Counts what the host is told
#[derive(Default)]
pub struct Recorder {
    pub signed_in: Mutex<Vec<String>>,
    pub failed: Mutex<Vec<String>>,
    pub started: Mutex<Vec<TransferInfo>>,
    pub ended: Mutex<Vec<(TransferInfo, TransferEnd)>>,
}

impl Events for Recorder {
    fn signed_in(&self, _: SocketAddr, user: &str) {
        self.signed_in.lock().unwrap().push(user.to_string());
    }

    fn login_failed(&self, _: SocketAddr, user: &str) {
        self.failed.lock().unwrap().push(user.to_string());
    }

    fn transfer_started(&self, _: SocketAddr, _: &str, transfer: &TransferInfo) {
        self.started.lock().unwrap().push(transfer.clone());
    }

    fn transfer_ended(&self, _: SocketAddr, _: &str, transfer: &TransferInfo, end: &TransferEnd) {
        self.ended.lock().unwrap().push((transfer.clone(), end.clone()));
    }
}

/// A server on a free port of 127.0.0.1, serving each connection with `serve`
pub struct Server {
    pub address: SocketAddr,
    pub backend: Arc<Memory>,
    pub events: Arc<Recorder>,
    /// How the sessions ended, in order
    pub ends: Arc<Mutex<Vec<SessionEnd>>>,
    /// How many connections the server accepted. A session that panics never reports how it ended, so this is more than the ends
    pub accepted: Arc<AtomicUsize>,
    accept: JoinHandle<()>,
}

impl Drop for Server {
    fn drop(&mut self) {
        self.accept.abort();
    }
}

pub async fn start() -> Server {
    start_with(Config::default()).await
}

pub async fn start_with(config: Config) -> Server {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let backend = Memory::new();
    let events = Arc::new(Recorder::default());
    let ends = Arc::new(Mutex::new(Vec::new()));
    let accepted = Arc::new(AtomicUsize::new(0));
    let config = Arc::new(config);
    let accept = tokio::spawn({
        let (backend, events, ends, accepted) = (backend.clone(), events.clone(), ends.clone(), accepted.clone());
        async move {
            loop {
                let Ok((stream, peer)) = listener.accept().await else { return };
                accepted.fetch_add(1, Ordering::SeqCst);
                let (config, backend, events, ends) = (config.clone(), backend.clone(), events.clone(), ends.clone());
                tokio::spawn(async move {
                    let end = serve(stream, peer, config, backend, events).await;
                    ends.lock().unwrap().push(end);
                });
            }
        }
    });
    Server { address, backend, events, ends, accepted, accept }
}

/// A client that sends what it is told to, and reads replies
pub struct Client {
    pub reader: BufReader<Conn>,
    pub peer: SocketAddr,
}

/// A connection of the test client: plain, or TLS after `AUTH TLS`
pub enum Conn {
    Plain(TcpStream),
    Tls(Box<tokio_rustls::client::TlsStream<TcpStream>>),
    Gone,
}

impl AsyncRead for Conn {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Conn::Plain(stream) => Pin::new(stream).poll_read(cx, buf),
            Conn::Tls(stream) => Pin::new(&mut **stream).poll_read(cx, buf),
            Conn::Gone => Poll::Ready(Err(io::ErrorKind::NotConnected.into())),
        }
    }
}

impl AsyncWrite for Conn {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Conn::Plain(stream) => Pin::new(stream).poll_write(cx, buf),
            Conn::Tls(stream) => Pin::new(&mut **stream).poll_write(cx, buf),
            Conn::Gone => Poll::Ready(Err(io::ErrorKind::NotConnected.into())),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Conn::Plain(stream) => Pin::new(stream).poll_flush(cx),
            Conn::Tls(stream) => Pin::new(&mut **stream).poll_flush(cx),
            Conn::Gone => Poll::Ready(Err(io::ErrorKind::NotConnected.into())),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Conn::Plain(stream) => Pin::new(stream).poll_shutdown(cx),
            Conn::Tls(stream) => Pin::new(&mut **stream).poll_shutdown(cx),
            Conn::Gone => Poll::Ready(Err(io::ErrorKind::NotConnected.into())),
        }
    }
}

/// A certificate for `localhost` made for the test, the settings of a server and of a client that trusts it, and a count of the TLS 1.3 session
/// tickets the client has been given
pub struct Tls {
    pub server: Arc<rustls::ServerConfig>,
    pub client: Arc<rustls::ClientConfig>,
    pub tickets: Arc<Tickets>,
}

/// A session store of a client that counts the tickets it is given
#[derive(Debug)]
pub struct Tickets {
    memory: rustls::client::ClientSessionMemoryCache,
    count: AtomicUsize,
}

impl Tickets {
    pub fn count(&self) -> usize {
        self.count.load(Ordering::SeqCst)
    }
}

impl rustls::client::ClientSessionStore for Tickets {
    fn set_kx_hint(&self, server_name: rustls::pki_types::ServerName<'static>, group: rustls::NamedGroup) {
        self.memory.set_kx_hint(server_name, group)
    }

    fn kx_hint(&self, server_name: &rustls::pki_types::ServerName<'_>) -> Option<rustls::NamedGroup> {
        self.memory.kx_hint(server_name)
    }

    fn set_tls12_session(&self, server_name: rustls::pki_types::ServerName<'static>, value: rustls::client::Tls12ClientSessionValue) {
        self.memory.set_tls12_session(server_name, value)
    }

    fn tls12_session(&self, server_name: &rustls::pki_types::ServerName<'_>) -> Option<rustls::client::Tls12ClientSessionValue> {
        self.memory.tls12_session(server_name)
    }

    fn remove_tls12_session(&self, server_name: &rustls::pki_types::ServerName<'static>) {
        self.memory.remove_tls12_session(server_name)
    }

    fn insert_tls13_ticket(&self, server_name: rustls::pki_types::ServerName<'static>, value: rustls::client::Tls13ClientSessionValue) {
        self.count.fetch_add(1, Ordering::SeqCst);
        self.memory.insert_tls13_ticket(server_name, value)
    }

    fn take_tls13_ticket(&self, server_name: &rustls::pki_types::ServerName<'static>) -> Option<rustls::client::Tls13ClientSessionValue> {
        self.memory.take_tls13_ticket(server_name)
    }
}

pub fn tls() -> Tls {
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let generated = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let certificate: CertificateDer<'static> = generated.cert.der().clone();
    let key = PrivateKeyDer::try_from(generated.signing_key.serialize_der()).unwrap();
    let server = rustls::ServerConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![certificate.clone()], key)
        .unwrap();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(certificate).unwrap();
    let tickets = Arc::new(Tickets { memory: rustls::client::ClientSessionMemoryCache::new(32), count: AtomicUsize::new(0) });
    let mut client =
        rustls::ClientConfig::builder_with_provider(provider).with_safe_default_protocol_versions().unwrap().with_root_certificates(roots).with_no_client_auth();
    client.resumption = rustls::client::Resumption::store(tickets.clone());
    Tls { server: Arc::new(server), client: Arc::new(client), tickets }
}

impl Tls {
    /// Does the client side of a TLS handshake on a connection, as to `localhost`
    pub async fn connect(&self, stream: TcpStream) -> tokio_rustls::client::TlsStream<TcpStream> {
        let name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
        tokio_rustls::TlsConnector::from(self.client.clone()).connect(name, stream).await.unwrap()
    }
}

impl Client {
    /// Connects and reads the greeting
    pub async fn connect(server: &Server) -> Client {
        let mut client = Client::connect_silent(server).await;
        let greeting = client.reply().await;
        assert_eq!(greeting.0, 220, "{greeting:?}");
        client
    }

    pub async fn connect_silent(server: &Server) -> Client {
        Client::connect_raw(server.address).await
    }

    /// Connects, and reads nothing
    pub async fn connect_raw(address: SocketAddr) -> Client {
        Client { reader: BufReader::new(Conn::Plain(TcpStream::connect(address).await.unwrap())), peer: address }
    }

    /// `AUTH TLS` and the handshake
    pub async fn upgrade(&mut self, tls: &Tls) {
        assert_eq!(self.code("AUTH TLS").await, 234);
        self.start_tls(tls).await;
    }

    /// The handshake, after the server has said 234
    pub async fn start_tls(&mut self, tls: &Tls) {
        assert!(self.reader.buffer().is_empty(), "the server sent something after the 234");
        let Conn::Plain(stream) = std::mem::replace(self.reader.get_mut(), Conn::Gone) else { panic!("not plain") };
        self.reader = BufReader::new(Conn::Tls(Box::new(tls.connect(stream).await)));
    }

    /// `AUTH TLS`, the sign-in, `PBSZ 0` and `PROT P`
    pub async fn secure_login(&mut self, tls: &Tls) {
        self.upgrade(tls).await;
        self.login().await;
        assert_eq!(self.code("PBSZ 0").await, 200);
        assert_eq!(self.code("PROT P").await, 200);
    }

    /// Whether the server ended the TLS connection with a close_notify (and not by cutting it)
    pub async fn closed_cleanly(&mut self) -> bool {
        let mut byte = [0u8; 1];
        matches!(tokio::time::timeout(Duration::from_secs(5), self.reader.read(&mut byte)).await, Ok(Ok(0)))
    }

    pub async fn send(&mut self, line: &str) {
        self.send_bytes(format!("{line}\r\n").as_bytes()).await;
    }

    pub async fn send_bytes(&mut self, bytes: &[u8]) {
        self.reader.get_mut().write_all(bytes).await.unwrap();
    }

    /// Reads one reply (all its lines): the code and the text of the lines, each without its line end
    pub async fn reply(&mut self) -> (u16, Vec<String>) {
        let mut lines = Vec::new();
        let mut code: Option<String> = None;
        loop {
            let mut line = String::new();
            let read = tokio::time::timeout(Duration::from_secs(10), self.reader.read_line(&mut line)).await.expect("no reply within 10 s").unwrap();
            assert!(read > 0, "the connection closed, replies so far: {lines:?}");
            assert!(line.ends_with("\r\n"), "a reply line must end with CRLF: {line:?}");
            let line = line.trim_end_matches("\r\n").to_string();
            match &code {
                None => {
                    assert!(line.len() >= 4 && line.as_bytes()[..3].iter().all(u8::is_ascii_digit), "not a reply: {line:?}");
                    let digits = line[..3].to_string();
                    let separator = line.as_bytes()[3];
                    assert!(separator == b' ' || separator == b'-', "not a reply: {line:?}");
                    lines.push(line[4..].to_string());
                    if separator == b' ' {
                        return (digits.parse().unwrap(), lines);
                    }
                    code = Some(digits);
                }
                Some(digits) => {
                    if line.len() >= 4 && line.starts_with(digits.as_str()) && line.as_bytes()[3] == b' ' {
                        lines.push(line[4..].to_string());
                        return (digits.parse().unwrap(), lines);
                    }
                    lines.push(line);
                }
            }
        }
    }

    /// Sends a command and reads its reply
    pub async fn command(&mut self, line: &str) -> (u16, Vec<String>) {
        self.send(line).await;
        self.reply().await
    }

    /// The code of the reply to a command
    pub async fn code(&mut self, line: &str) -> u16 {
        self.command(line).await.0
    }

    /// Signs in as alice
    pub async fn login(&mut self) {
        assert_eq!(self.code("USER alice").await, 331);
        assert_eq!(self.code("PASS secret").await, 230);
    }

    /// PASV: the address to connect the data connection to
    pub async fn pasv(&mut self) -> SocketAddr {
        let (code, lines) = self.command("PASV").await;
        assert_eq!(code, 227, "{lines:?}");
        let start = lines[0].find('(').unwrap() + 1;
        let end = lines[0].find(')').unwrap();
        let numbers: Vec<u16> = lines[0][start..end].split(',').map(|n| n.parse().unwrap()).collect();
        assert_eq!(numbers.len(), 6, "{lines:?}");
        SocketAddr::from(([numbers[0] as u8, numbers[1] as u8, numbers[2] as u8, numbers[3] as u8], numbers[4] * 256 + numbers[5]))
    }

    /// EPSV: the address to connect the data connection to (the address of the control connection, and the port of the reply)
    pub async fn epsv(&mut self) -> SocketAddr {
        let (code, lines) = self.command("EPSV").await;
        assert_eq!(code, 229, "{lines:?}");
        let start = lines[0].find("(|||").unwrap() + 4;
        let end = lines[0].find("|)").unwrap();
        SocketAddr::new(self.peer.ip(), lines[0][start..end].parse().unwrap())
    }

    /// Whether the server has closed the connection (nothing more to read)
    pub async fn closed(&mut self) -> bool {
        let mut byte = [0u8; 1];
        match tokio::time::timeout(Duration::from_secs(5), self.reader.read(&mut byte)).await {
            Ok(Ok(0)) | Ok(Err(_)) => true,
            Ok(Ok(_)) => false,
            Err(_) => panic!("the connection stayed open"),
        }
    }
}

/// Waits until `check` is true, up to 5 s
pub async fn eventually(mut check: impl FnMut() -> bool) {
    for _ in 0..100 {
        if check() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("the condition did not come true");
}

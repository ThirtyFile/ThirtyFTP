//! A small backend in memory, and a client that speaks raw FTP, for the tests

#![allow(dead_code)] // Each test file uses part of this

use async_trait::async_trait;
use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use thirtyftp::{Backend, Config, Entry, Events, FsError, FtpPath, LoginContext, LoginError, SessionEnd, serve};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWriteExt, BufReader};
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
            Some(data) => Ok(Entry::file(name, data.len() as u64, None)),
            None => Err(FsError::NotFound),
        }
    }

    async fn list(&self, _: &String, path: &FtpPath) -> Result<Vec<Entry>, FsError> {
        let key = path.to_string();
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
                entries.push(Entry::file(file.rsplit('/').next().unwrap(), data.len() as u64, None));
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
        let mut bytes = Vec::new();
        data.read_to_end(&mut bytes).await.map_err(|e| FsError::Local(e.to_string()))?;
        let length = bytes.len() as u64;
        self.files.lock().unwrap().insert(path.to_string(), bytes);
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
}

impl Events for Recorder {
    fn signed_in(&self, _: SocketAddr, user: &str) {
        self.signed_in.lock().unwrap().push(user.to_string());
    }

    fn login_failed(&self, _: SocketAddr, user: &str) {
        self.failed.lock().unwrap().push(user.to_string());
    }
}

/// A server on a free port of 127.0.0.1, serving each connection with `serve`
pub struct Server {
    pub address: SocketAddr,
    pub backend: Arc<Memory>,
    pub events: Arc<Recorder>,
    /// How the sessions ended, in order
    pub ends: Arc<Mutex<Vec<SessionEnd>>>,
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
    let config = Arc::new(config);
    let accept = tokio::spawn({
        let (backend, events, ends) = (backend.clone(), events.clone(), ends.clone());
        async move {
            loop {
                let Ok((stream, peer)) = listener.accept().await else { return };
                let (config, backend, events, ends) = (config.clone(), backend.clone(), events.clone(), ends.clone());
                tokio::spawn(async move {
                    let end = serve(stream, peer, config, backend, events).await;
                    ends.lock().unwrap().push(end);
                });
            }
        }
    });
    Server { address, backend, events, ends, accept }
}

/// A client that sends what it is told to, and reads replies
pub struct Client {
    pub reader: BufReader<TcpStream>,
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
        Client { reader: BufReader::new(TcpStream::connect(server.address).await.unwrap()) }
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

//! One control connection: the state of the session and what each command does (RFC 959 section 5, RFC 1123 section 4.1).

use crate::backend::{Backend, Entry, EntryKind, FsError, LoginContext, LoginError};
use crate::codec::{Line, LineReader};
use crate::command::{self, Command, ParseError, TypeArg};
use crate::config::{Config, PassiveHost};
use crate::events::{Direction, Events, TransferEnd, TransferInfo};
use crate::listing::{self, Facts};
use crate::passive;
use crate::path::FtpPath;
use crate::reply::{Reply, text};
use crate::time;
use crate::transfer::{self, Event, Failure, Job, Work};
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime};
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time::{Instant, sleep_until, timeout};
use tracing::{Instrument, debug, info, trace, warn};

/// Why a session ended
#[derive(Debug)]
#[non_exhaustive]
pub enum SessionEnd {
    /// The client sent `QUIT`
    Quit,
    /// The client closed the connection
    ClientClosed,
    /// No command came within [`Config::idle_timeout`]. The connection was closed without a reply
    IdleTimeout,
    /// The client failed to sign in [`Limits::max_login_attempts`](crate::Limits::max_login_attempts) times
    TooManyLoginFailures,
    /// The backend couldn't decide on a sign-in ([`LoginError::Unavailable`])
    LoginUnavailable,
    /// Reading or writing the connection failed
    Io(io::Error),
}

/// Serves one control connection until it ends.
///
/// The host accepts the connection, and decides who may connect and how many may at once; this does the protocol. A session never panics on what a
/// client sends. It ends when the client quits or closes the connection, when it is idle for too long, when the connection fails, or when the
/// future is dropped (the host's way to stop a session). A transfer that runs then is aborted: [`Backend::write`] is dropped, which is how it learns
/// that the upload did not complete.
pub async fn serve<B: Backend>(stream: TcpStream, peer: SocketAddr, config: Arc<Config>, backend: Arc<B>, events: Arc<dyn Events>) -> SessionEnd {
    let local = match stream.local_addr() {
        Ok(local) => local,
        Err(error) => return SessionEnd::Io(error),
    };
    let session = Session {
        stream,
        lines: LineReader::new(config.limits.max_line),
        config,
        backend,
        events,
        peer,
        local,
        login: Login::New,
        failed_logins: 0,
        cwd: FtpPath::root(),
        ascii: false,
        facts: Facts::default(),
        passive: None,
        epsv_all: false,
        rest: None,
        transfer: None,
    };
    let span = tracing::info_span!("ftp_session", %peer);
    async move {
        let end = session.run().await;
        debug!(?end, "session ended");
        end
    }
    .instrument(span)
    .await
}

enum Login<U> {
    /// Nothing yet, or the last attempt failed
    New,
    /// The name is given, the password is next
    UserGiven(String),
    SignedIn {
        name: String,
        user: Arc<U>,
    },
}

/// A transfer that runs
struct Running {
    handle: JoinHandle<()>,
    events: mpsc::Receiver<Event>,
    /// The bytes moved so far
    progress: Arc<AtomicU64>,
    info: TransferInfo,
}

struct Session<B: Backend> {
    stream: TcpStream,
    lines: LineReader,
    config: Arc<Config>,
    backend: Arc<B>,
    events: Arc<dyn Events>,
    peer: SocketAddr,
    local: SocketAddr,
    login: Login<B::User>,
    failed_logins: u32,
    cwd: FtpPath,
    /// TYPE A: kept for STAT; the transfers treat the bytes the same either way
    ascii: bool,
    /// The facts MLSD and MLST give (`OPTS MLST`)
    facts: Facts,
    /// The listener of the passive data connection. A session has one: a new PASV or EPSV replaces it, and closes the old at once
    passive: Option<TcpListener>,
    /// `EPSV ALL` was sent: PASV is refused from then on (RFC 2428 section 4)
    epsv_all: bool,
    /// The offset of `REST`, for the next command
    rest: Option<u64>,
    transfer: Option<Running>,
}

impl<B: Backend> Drop for Session<B> {
    /// The host drops the session to stop it: a transfer that runs is aborted, and the host is told
    fn drop(&mut self) {
        if let Some(running) = self.transfer.take() {
            running.handle.abort();
            self.events.transfer_ended(self.peer, self.user_name(), &running.info, &TransferEnd::Aborted);
        }
    }
}

/// What a command leaves to do
type Outcome = io::Result<Option<SessionEnd>>;

/// What wakes the session
enum Wake {
    Transfer(Option<Event>),
    Line(io::Result<Option<Line>>),
    Idle,
}

/// What the transfer says next, or nothing ever when there is none
async fn next_event(transfer: &mut Option<Running>) -> Option<Event> {
    match transfer {
        Some(running) => running.events.recv().await,
        None => std::future::pending().await,
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ListKind {
    List,
    Nlst,
    Mlsd,
}

impl<B: Backend> Session<B> {
    async fn run(mut self) -> SessionEnd {
        info!("connected");
        let greeting = Reply::new(220, &self.config.greeting);
        if let Err(error) = self.send(greeting).await {
            return SessionEnd::Io(error);
        }
        let mut last_activity = Instant::now();
        loop {
            // The time to wait is for the whole line: a client that sends a byte now and then doesn't keep the connection open. It doesn't run while a
            // transfer does: the client waits for its end
            let idle_deadline = last_activity + self.config.idle_timeout;
            let waiting = self.transfer.is_none();
            let wake = tokio::select! {
                // What a transfer has to say goes before the next command
                biased;
                event = next_event(&mut self.transfer) => Wake::Transfer(event),
                line = self.lines.next_line(&mut self.stream) => Wake::Line(line),
                () = sleep_until(idle_deadline), if waiting => Wake::Idle,
            };
            let outcome = match wake {
                Wake::Idle => return SessionEnd::IdleTimeout,
                Wake::Transfer(event) => self.transfer_event(event).await,
                Wake::Line(Err(error)) => return SessionEnd::Io(error),
                Wake::Line(Ok(None)) => return SessionEnd::ClientClosed,
                Wake::Line(Ok(Some(Line::TooLong))) => self.reply(500, "Command line too long.").await,
                Wake::Line(Ok(Some(Line::Text(line)))) => match command::parse(&line) {
                    Ok(command) => {
                        debug!(verb = command.verb(), "command");
                        trace!(?command, "command arguments");
                        self.handle(command).await
                    }
                    Err(ParseError::Unknown) => self.reply(500, text::SYNTAX_COMMAND).await,
                    Err(ParseError::Syntax) => self.reply(501, text::SYNTAX_PARAMETERS).await,
                },
            };
            last_activity = Instant::now();
            match outcome {
                Ok(None) => {}
                Ok(Some(end)) => return end,
                Err(error) => return SessionEnd::Io(error),
            }
        }
    }

    /// Sends a reply. A client that doesn't read it can't keep the session waiting longer than the idle time
    async fn send(&mut self, reply: Reply) -> io::Result<()> {
        let bytes = reply.encode();
        timeout(self.config.idle_timeout, async {
            self.stream.write_all(&bytes).await?;
            self.stream.flush().await
        })
        .await
        .unwrap_or_else(|_| Err(io::ErrorKind::TimedOut.into()))
    }

    async fn reply(&mut self, code: u16, text: &str) -> Outcome {
        self.send(Reply::new(code, text)).await.map(|()| None)
    }

    async fn send_reply(&mut self, reply: Reply) -> Outcome {
        self.send(reply).await.map(|()| None)
    }

    fn signed_in(&self) -> bool {
        matches!(self.login, Login::SignedIn { .. })
    }

    fn user(&self) -> Option<Arc<B::User>> {
        match &self.login {
            Login::SignedIn { user, .. } => Some(user.clone()),
            _ => None,
        }
    }

    fn user_name(&self) -> &str {
        match &self.login {
            Login::SignedIn { name, .. } => name,
            _ => "",
        }
    }

    async fn handle(&mut self, command: Command) -> Outcome {
        if !self.signed_in() && needs_login(&command) {
            return self.reply(530, text::NOT_LOGGED_IN).await;
        }
        if self.transfer.is_some() {
            return self.during_transfer(command).await;
        }
        // REST is for the transfer command that follows it. Clients send PASV or EPSV between the two, and any other command cancels it
        let rest = if matches!(command, Command::Rest(_) | Command::Pasv | Command::Epsv(_)) { None } else { self.rest.take() };
        match command {
            Command::User(name) => self.user_command(name).await,
            Command::Pass(password) => self.pass(password.0).await,
            Command::Acct => self.reply(202, text::SUPERFLUOUS).await,
            Command::Quit => {
                self.reply(221, text::CLOSING).await?;
                Ok(Some(SessionEnd::Quit))
            }
            Command::Noop => self.reply(200, text::COMMAND_OK).await,
            Command::Syst => self.reply(215, "UNIX Type: L8").await,
            Command::Feat => {
                let mut lines = vec!["Extensions supported:".to_string()];
                lines.extend(self.features());
                lines.push("End".to_string());
                self.send_reply(Reply::multi(211, lines)).await
            }
            Command::Opts { name, value } => self.opts(&name, value.as_deref()).await,
            Command::Help(topic) => self.help(topic).await,
            Command::Stat(None) => self.status().await,
            Command::Stat(Some(argument)) => self.stat_path(&argument).await,
            Command::Pwd => {
                let reply = format!("{} is the current directory.", quoted(&self.cwd));
                self.reply(257, &reply).await
            }
            Command::Cwd(argument) => self.change_dir(&argument).await,
            Command::Cdup => self.change_dir("..").await,
            Command::Mkd(argument) => self.make_dir(&argument).await,
            // Receive folders keep what they are sent: deleting and renaming are refused on purpose
            Command::Rmd(_) | Command::Dele(_) | Command::Rnfr(_) | Command::Rnto(_) | Command::Appe(_) => self.reply(550, "Permission denied.").await,
            Command::Type(argument) => self.data_type(argument).await,
            Command::Mode(letter) => match letter {
                'S' => self.reply(200, "Mode set to S.").await,
                'B' | 'C' => self.reply(504, text::NOT_IMPLEMENTED_PARAMETER).await,
                _ => self.reply(501, text::SYNTAX_PARAMETERS).await,
            },
            Command::Stru(letter) => match letter {
                'F' => self.reply(200, "Structure set to F.").await,
                'R' | 'P' => self.reply(504, text::NOT_IMPLEMENTED_PARAMETER).await,
                _ => self.reply(501, text::SYNTAX_PARAMETERS).await,
            },
            Command::Allo => self.reply(202, text::SUPERFLUOUS).await,
            Command::Ccc => self.reply(534, "Request denied for policy reasons.").await,
            Command::Port(_) | Command::Eprt(_) => self.reply(502, "Active mode is not supported.").await,
            Command::Site(_) => self.reply(502, "SITE commands are not supported.").await,
            Command::Abor => self.reply(226, "No transfer in progress.").await,
            Command::Pasv => self.passive_mode(false).await,
            Command::Epsv(argument) => self.epsv(argument.as_deref()).await,
            Command::List(argument) => self.listing(ListKind::List, argument).await,
            Command::Nlst(argument) => self.listing(ListKind::Nlst, argument).await,
            Command::Mlsd(argument) => self.listing(ListKind::Mlsd, argument).await,
            Command::Retr(argument) => self.retrieve(&argument, rest.unwrap_or(0)).await,
            Command::Stor(argument) => self.store(&argument, rest.unwrap_or(0)).await,
            Command::Rest(offset) => {
                self.rest = Some(offset);
                self.reply(350, &format!("Restarting at {offset}. Send STORE or RETRIEVE to initiate transfer.")).await
            }
            Command::Size(argument) => self.size(&argument).await,
            Command::Mdtm(argument) => self.modification_time(&argument).await,
            Command::Mlst(argument) => self.mlst(argument.as_deref()).await,
            // Later milestones
            Command::Auth(_) => self.reply(502, text::NOT_IMPLEMENTED).await,
            Command::Pbsz(_) | Command::Prot(_) => self.reply(503, text::BAD_SEQUENCE).await,
            Command::Unsupported(_) => self.reply(502, text::NOT_IMPLEMENTED).await,
        }
    }

    /// While a transfer runs, the control connection answers ABOR and STAT at any time (RFC 959 section 4.1.3, RFC 1123 section 4.1.3.3), and QUIT.
    /// The other commands wait for the transfer to end: they are refused, and may be sent again
    async fn during_transfer(&mut self, command: Command) -> Outcome {
        match command {
            Command::Abor => {
                self.abort_transfer().await;
                self.send(Reply::new(426, "Connection closed; transfer aborted.")).await?;
                self.reply(226, text::DATA_CLOSED).await
            }
            Command::Stat(None) => {
                let Some(running) = &self.transfer else { return Ok(None) };
                let what = match running.info.direction {
                    Direction::Upload => "Receiving",
                    Direction::Download => "Sending",
                    Direction::Listing => "Sending a listing of",
                };
                let lines = [
                    "FTP server status:".to_string(),
                    format!("{what} {}: {} bytes so far", running.info.path, running.progress.load(Ordering::Relaxed)),
                    "End of status".to_string(),
                ];
                self.send_reply(Reply::multi(211, lines)).await
            }
            Command::Quit => {
                self.abort_transfer().await;
                self.reply(221, text::CLOSING).await?;
                Ok(Some(SessionEnd::Quit))
            }
            Command::Noop => self.reply(200, text::COMMAND_OK).await,
            _ => self.reply(450, "A transfer is in progress.").await,
        }
    }

    /// Stops the transfer and waits until it has let go of everything: the upload the backend was storing is dropped, not finished
    async fn abort_transfer(&mut self) {
        if let Some(running) = self.transfer.take() {
            running.handle.abort();
            let _ = running.handle.await;
            self.events.transfer_ended(self.peer, self.user_name(), &running.info, &TransferEnd::Aborted);
        }
    }

    /// The transfer says something: its data connection is open (`150`), or it is over (the final reply)
    async fn transfer_event(&mut self, event: Option<Event>) -> Outcome {
        match event {
            Some(Event::Started) => {
                if let Some(running) = &self.transfer {
                    self.events.transfer_started(self.peer, self.user_name(), &running.info);
                }
                self.reply(150, "File status okay; about to open data connection.").await
            }
            done => {
                // A task that ended without saying how (it panicked) is a failure of the storage
                let result = match done {
                    Some(Event::Done(result)) => result,
                    _ => Err(Failure::Storage(FsError::Local("the transfer task failed".to_string()))),
                };
                let Some(running) = self.transfer.take() else { return Ok(None) };
                let end = match &result {
                    Ok(bytes) => TransferEnd::Completed(*bytes),
                    Err(_) => TransferEnd::Failed,
                };
                self.events.transfer_ended(self.peer, self.user_name(), &running.info, &end);
                let reply = match result {
                    Ok(_) => Reply::new(226, text::DATA_CLOSED),
                    Err(Failure::NoConnection) => Reply::new(425, "Can't open data connection."),
                    Err(Failure::Aborted) => Reply::new(426, "Connection closed; transfer aborted."),
                    Err(Failure::Storage(error)) => {
                        if let FsError::Local(message) = &error {
                            warn!(%message, "storage error in a transfer");
                        }
                        file_error_reply(&error)
                    }
                };
                self.send_reply(reply).await
            }
        }
    }

    async fn user_command(&mut self, name: String) -> Outcome {
        if self.signed_in() {
            return self.reply(503, "Already logged in.").await;
        }
        if self.config.require_tls {
            return self.reply(530, "Login needs an encrypted connection.").await;
        }
        self.login = Login::UserGiven(name);
        self.reply(331, text::NEED_PASSWORD).await
    }

    async fn pass(&mut self, password: String) -> Outcome {
        let name = match std::mem::replace(&mut self.login, Login::New) {
            Login::UserGiven(name) => name,
            signed_in @ Login::SignedIn { .. } => {
                self.login = signed_in;
                return self.reply(503, "Already logged in.").await;
            }
            Login::New => return self.reply(503, "Login with USER first.").await,
        };
        let context = LoginContext { peer: self.peer, local: self.local, encrypted: false };
        match self.backend.login(&context, &name, &password).await {
            Ok(user) => {
                info!(user = %name, "signed in");
                self.events.signed_in(self.peer, &name);
                self.login = Login::SignedIn { name, user: Arc::new(user) };
                self.reply(230, text::LOGGED_IN).await
            }
            Err(LoginError::Unavailable) => {
                self.reply(421, text::UNAVAILABLE).await?;
                Ok(Some(SessionEnd::LoginUnavailable))
            }
            Err(error) => {
                info!(user = %name, %error, "sign-in failed");
                self.events.login_failed(self.peer, &name);
                self.failed_logins += 1;
                if self.failed_logins >= self.config.limits.max_login_attempts {
                    self.reply(421, "Too many failed login attempts.").await?;
                    return Ok(Some(SessionEnd::TooManyLoginFailures));
                }
                match error {
                    LoginError::Refused(reason) => self.reply(530, &reason).await,
                    _ => self.reply(530, "Login incorrect.").await,
                }
            }
        }
    }

    /// The lines of FEAT (RFC 2389), for what is done
    fn features(&self) -> Vec<String> {
        vec![
            "EPSV".to_string(),
            "MDTM".to_string(),
            format!("MLST {}", self.facts.names(true)),
            "PASV".to_string(),
            "REST STREAM".to_string(),
            "SIZE".to_string(),
            "UTF8".to_string(),
        ]
    }

    async fn opts(&mut self, name: &str, value: Option<&str>) -> Outcome {
        match (name, value.map(str::to_ascii_uppercase).as_deref()) {
            ("UTF8", Some("ON")) => self.reply(200, "UTF8 is always on.").await,
            ("UTF8", Some("OFF")) => self.reply(504, "UTF8 can't be turned off.").await,
            ("MLST", _) => {
                // Without a list, all the facts (RFC 3659 section 7.9.1)
                self.facts = match value {
                    Some(list) => Facts::select(list),
                    None => Facts::default(),
                };
                let reply = format!("MLST OPTS {}", self.facts.names(false));
                self.reply(200, &reply).await
            }
            _ => self.reply(501, "Option not understood.").await,
        }
    }

    async fn help(&mut self, topic: Option<String>) -> Outcome {
        match topic {
            None => {
                let verbs: Vec<&str> = command::SYNTAX.iter().map(|(verb, _)| *verb).collect();
                let mut lines = vec!["The following commands are recognized:".to_string()];
                lines.extend(verbs.chunks(8).map(|row| row.join(" ")));
                lines.push(text::HELP.to_string());
                self.send_reply(Reply::multi(214, lines)).await
            }
            Some(topic) => {
                let topic = topic.to_ascii_uppercase();
                match command::SYNTAX.iter().find(|(verb, _)| *verb == topic) {
                    Some((_, syntax)) => self.reply(214, &format!("Syntax: {syntax}")).await,
                    None => self.reply(501, "Unknown command.").await,
                }
            }
        }
    }

    /// STAT without an argument (RFC 959 section 4.1.3): the state of the connection
    async fn status(&mut self) -> Outcome {
        let user = match &self.login {
            Login::SignedIn { name, .. } => format!("Logged in as {name}"),
            _ => "Not logged in".to_string(),
        };
        let lines = [
            "FTP server status:".to_string(),
            format!("Connected from {}", self.peer.ip()),
            "Control connection is not encrypted".to_string(),
            user,
            format!("TYPE: {}, STRU: File, MODE: Stream", if self.ascii { "ASCII" } else { "BINARY" }),
            "End of status".to_string(),
        ];
        self.send_reply(Reply::multi(211, lines)).await
    }

    /// STAT with a path (RFC 959 section 4.1.3): the listing of LIST, on the control connection
    async fn stat_path(&mut self, argument: &str) -> Outcome {
        let Some(path) = self.resolve(argument).await? else { return Ok(None) };
        let Some(user) = self.user() else { return self.reply(530, text::NOT_LOGGED_IN).await };
        match self.entries(&user, &path, ListKind::List).await {
            Ok(entries) => {
                let listing = listing::list(&entries, SystemTime::now());
                let mut lines = vec![format!("Status of {path}:")];
                lines.extend(listing.lines().map(str::to_string));
                lines.push("End of status".to_string());
                self.send_reply(Reply::multi(213, lines)).await
            }
            Err(error) => self.file_error(error).await,
        }
    }

    async fn data_type(&mut self, argument: TypeArg) -> Outcome {
        match argument {
            TypeArg::Ascii => {
                self.ascii = true;
                self.reply(200, "Type set to A.").await
            }
            TypeArg::Image => {
                self.ascii = false;
                self.reply(200, "Type set to I.").await
            }
            TypeArg::Unsupported => self.reply(504, text::NOT_IMPLEMENTED_PARAMETER).await,
        }
    }

    /// Resolves a path of the client. A path that can't be used is answered (553), and `None` returned
    async fn resolve(&mut self, argument: &str) -> io::Result<Option<FtpPath>> {
        match FtpPath::resolve(&self.cwd, argument) {
            Ok(path) => Ok(Some(path)),
            Err(_) => {
                self.reply(553, text::NAME_NOT_ALLOWED).await?;
                Ok(None)
            }
        }
    }

    async fn change_dir(&mut self, argument: &str) -> Outcome {
        let Some(path) = self.resolve(argument).await? else { return Ok(None) };
        let Some(user) = self.user() else { return self.reply(530, text::NOT_LOGGED_IN).await };
        match self.backend.change_dir(&user, &path).await {
            Ok(()) => {
                self.cwd = path;
                self.reply(250, text::FILE_ACTION_OK).await
            }
            Err(error) => self.file_error(error).await,
        }
    }

    async fn make_dir(&mut self, argument: &str) -> Outcome {
        let Some(path) = self.resolve(argument).await? else { return Ok(None) };
        let Some(user) = self.user() else { return self.reply(530, text::NOT_LOGGED_IN).await };
        match self.backend.make_dir(&user, &path).await {
            Ok(()) => {
                let reply = format!("{} created.", quoted(&path));
                self.reply(257, &reply).await
            }
            Err(error) => self.file_error(error).await,
        }
    }

    async fn size(&mut self, argument: &str) -> Outcome {
        let Some(path) = self.resolve(argument).await? else { return Ok(None) };
        let Some(user) = self.user() else { return self.reply(530, text::NOT_LOGGED_IN).await };
        match self.backend.metadata(&user, &path).await {
            Ok(entry) if entry.kind == EntryKind::File => self.reply(213, &entry.size.to_string()).await,
            Ok(_) => self.reply(550, "Not a plain file.").await,
            Err(error) => self.file_error(error).await,
        }
    }

    async fn modification_time(&mut self, argument: &str) -> Outcome {
        let Some(path) = self.resolve(argument).await? else { return Ok(None) };
        let Some(user) = self.user() else { return self.reply(530, text::NOT_LOGGED_IN).await };
        match self.backend.metadata(&user, &path).await {
            Ok(Entry { modified: Some(modified), .. }) => self.reply(213, &time::mlsx(modified)).await,
            Ok(_) => self.reply(550, "Modification time is not available.").await,
            Err(error) => self.file_error(error).await,
        }
    }

    /// MLST (RFC 3659 section 7.2): the facts of one path, on the control connection
    async fn mlst(&mut self, argument: Option<&str>) -> Outcome {
        let path = match argument {
            Some(argument) => match self.resolve(argument).await? {
                Some(path) => path,
                None => return Ok(None),
            },
            None => self.cwd.clone(),
        };
        let Some(user) = self.user() else { return self.reply(530, text::NOT_LOGGED_IN).await };
        match self.backend.metadata(&user, &path).await {
            Ok(entry) => {
                let lines = [format!("Listing {path}"), listing::mlst(&entry, &path.to_string(), self.facts), "End".to_string()];
                self.send_reply(Reply::multi(250, lines)).await
            }
            Err(error) => self.file_error(error).await,
        }
    }

    async fn file_error(&mut self, error: FsError) -> Outcome {
        let reply = file_error_reply(&error);
        if let FsError::Local(message) = &error {
            warn!(%message, "storage error");
        }
        self.send_reply(reply).await
    }

    // Passive mode

    /// PASV and EPSV: a new listener, and the old one is closed first, so a session never holds two ports (RFC 959 section 4.1.2, RFC 2428)
    async fn passive_mode(&mut self, extended: bool) -> Outcome {
        if !extended && self.epsv_all {
            return self.reply(501, "PASV is not allowed after EPSV ALL.").await;
        }
        self.passive = None;
        let address = if extended {
            None
        } else {
            match self.passive_address().await {
                Ok(address) => Some(address),
                Err(reply) => return self.send_reply(reply).await,
            }
        };
        let listener = match passive::bind(self.local.ip(), &self.config.passive_ports).await {
            Ok(listener) => listener,
            Err(error) => {
                warn!(%error, "no port for a passive data connection");
                return self.reply(425, "Can't open data connection.").await;
            }
        };
        let port = match listener.local_addr() {
            Ok(address) => address.port(),
            Err(_) => return self.reply(425, "Can't open data connection.").await,
        };
        self.passive = Some(listener);
        match address {
            Some(ip) => self.reply(227, &passive::pasv_text(ip, port)).await,
            None => self.reply(229, &passive::epsv_text(port)).await,
        }
    }

    /// The address a PASV reply tells (RFC 959 has IPv4 only)
    async fn passive_address(&self) -> Result<Ipv4Addr, Reply> {
        match &self.config.passive_host {
            PassiveHost::Ip(ip) => Ok(*ip),
            PassiveHost::Dns(name) => match timeout(Duration::from_secs(5), tokio::net::lookup_host((name.as_str(), 0))).await {
                Ok(Ok(addresses)) => addresses
                    .filter_map(|address| match address.ip() {
                        IpAddr::V4(ip) => Some(ip),
                        IpAddr::V6(_) => None,
                    })
                    .next()
                    .ok_or_else(|| Reply::new(425, "Can't open data connection.")),
                _ => Err(Reply::new(425, "Can't open data connection.")),
            },
            _ => match passive::canonical(self.local.ip()) {
                IpAddr::V4(ip) => Ok(ip),
                IpAddr::V6(_) => Err(Reply::new(501, "PASV is for IPv4. Use EPSV.")),
            },
        }
    }

    async fn epsv(&mut self, argument: Option<&str>) -> Outcome {
        let version = match passive::canonical(self.local.ip()) {
            IpAddr::V4(_) => "1",
            IpAddr::V6(_) => "2",
        };
        match argument {
            None => self.passive_mode(true).await,
            Some(argument) if argument.eq_ignore_ascii_case("ALL") => {
                self.epsv_all = true;
                self.reply(200, "EPSV ALL command successful.").await
            }
            Some(argument) if argument == version => self.passive_mode(true).await,
            Some(argument) if argument.bytes().all(|b| b.is_ascii_digit()) => self.reply(522, &format!("Network protocol not supported, use ({version})")).await,
            Some(_) => self.reply(501, text::SYNTAX_PARAMETERS).await,
        }
    }

    // Transfers

    /// The entries of a directory. LIST and NLST of a file give that file (the backend says so with `WrongType`)
    async fn entries(&self, user: &B::User, path: &FtpPath, kind: ListKind) -> Result<Vec<Entry>, FsError> {
        match self.backend.list(user, path).await {
            Err(FsError::WrongType) if kind != ListKind::Mlsd => match self.backend.metadata(user, path).await {
                Ok(entry) if entry.kind == EntryKind::File => Ok(vec![entry]),
                Ok(_) => Err(FsError::WrongType),
                Err(error) => Err(error),
            },
            other => other,
        }
    }

    async fn listing(&mut self, kind: ListKind, argument: Option<String>) -> Outcome {
        if self.passive.is_none() {
            return self.reply(425, "Use PASV or EPSV first.").await;
        }
        let path = match argument {
            Some(argument) => match self.resolve(&argument).await? {
                Some(path) => path,
                None => return Ok(None),
            },
            None => self.cwd.clone(),
        };
        let Some(user) = self.user() else { return self.reply(530, text::NOT_LOGGED_IN).await };
        let entries = match self.entries(&user, &path, kind).await {
            Ok(entries) => entries,
            Err(error) => return self.file_error(error).await,
        };
        let listing = match kind {
            ListKind::List => listing::list(&entries, SystemTime::now()),
            ListKind::Nlst => listing::names(&entries),
            ListKind::Mlsd => listing::mlsd(&entries, self.facts),
        };
        self.start_transfer(Work::Listing(listing.into_bytes()), TransferInfo { direction: Direction::Listing, path }).await
    }

    async fn retrieve(&mut self, argument: &str, offset: u64) -> Outcome {
        if self.passive.is_none() {
            return self.reply(425, "Use PASV or EPSV first.").await;
        }
        let Some(path) = self.resolve(argument).await? else { return Ok(None) };
        let Some(user) = self.user() else { return self.reply(530, text::NOT_LOGGED_IN).await };
        let size = match self.backend.metadata(&user, &path).await {
            Ok(entry) if entry.kind == EntryKind::File => entry.size,
            Ok(_) => return self.reply(550, "Not a plain file.").await,
            Err(error) => return self.file_error(error).await,
        };
        if offset > size {
            return self.reply(554, "Requested action not taken: invalid REST parameter.").await;
        }
        match self.backend.read(&user, &path, offset).await {
            Ok(reader) => self.start_transfer(Work::Download(reader), TransferInfo { direction: Direction::Download, path }).await,
            Err(error) => self.file_error(error).await,
        }
    }

    async fn store(&mut self, argument: &str, offset: u64) -> Outcome {
        if self.passive.is_none() {
            return self.reply(425, "Use PASV or EPSV first.").await;
        }
        let Some(path) = self.resolve(argument).await? else { return Ok(None) };
        if path.is_root() {
            return self.reply(553, text::NAME_NOT_ALLOWED).await;
        }
        // The backend stores a whole file: there is no way to continue one
        if offset != 0 {
            return self.reply(554, "Requested action not taken: invalid REST parameter.").await;
        }
        self.start_transfer(Work::Upload(path.clone()), TransferInfo { direction: Direction::Upload, path }).await
    }

    /// Starts the task of a transfer: it waits for the data connection, and the session goes on with the control connection
    async fn start_transfer(&mut self, work: Work, info: TransferInfo) -> Outcome {
        let Some(listener) = self.passive.take() else { return self.reply(425, "Use PASV or EPSV first.").await };
        let Some(user) = self.user() else { return self.reply(530, text::NOT_LOGGED_IN).await };
        let (sender, receiver) = mpsc::channel(4);
        let progress = Arc::new(AtomicU64::new(0));
        let job = Job {
            backend: self.backend.clone(),
            user,
            listener,
            client: self.peer.ip(),
            accept_timeout: self.config.limits.data_accept_timeout,
            idle_timeout: self.config.limits.transfer_idle_timeout,
            progress: progress.clone(),
            events: sender,
        };
        let handle = tokio::spawn(transfer::run(job, work));
        self.transfer = Some(Running { handle, events: receiver, progress, info });
        Ok(None)
    }
}

/// The commands that need a signed-in user. The others are answered at any time (RFC 959: STAT and ABOR at any time; FEAT, HELP, OPTS, AUTH and the rest of
/// what a client does before it signs in)
fn needs_login(command: &Command) -> bool {
    !matches!(
        command,
        Command::User(_)
            | Command::Pass(_)
            | Command::Acct
            | Command::Quit
            | Command::Noop
            | Command::Syst
            | Command::Feat
            | Command::Opts { .. }
            | Command::Help(_)
            | Command::Stat(None)
            | Command::Auth(_)
            | Command::Pbsz(_)
            | Command::Prot(_)
            | Command::Ccc
            | Command::Abor
            | Command::Unsupported(_)
    )
}

/// A path in the text of a reply: in double quotes, and a double quote in it doubled (RFC 959 appendix II)
fn quoted(path: &FtpPath) -> String {
    format!("\"{}\"", path.to_string().replace('"', "\"\""))
}

fn file_error_reply(error: &FsError) -> Reply {
    match error {
        FsError::NotFound => Reply::new(550, text::FILE_UNAVAILABLE),
        FsError::PermissionDenied => Reply::new(550, "Permission denied."),
        FsError::AlreadyExists => Reply::new(550, "Already exists."),
        FsError::WrongType => Reply::new(550, "Not the right type of file."),
        FsError::NameNotAllowed => Reply::new(553, text::NAME_NOT_ALLOWED),
        FsError::QuotaExceeded => Reply::new(552, text::NO_SPACE),
        FsError::Unavailable => Reply::new(450, text::FILE_BUSY),
        FsError::Local(_) => Reply::new(451, text::LOCAL_ERROR),
    }
}

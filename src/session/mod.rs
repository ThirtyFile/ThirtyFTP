//! One control connection: the state of the session, the loop that reads the commands, and how a transfer that runs is handled (RFC 959 section 5,
//! RFC 1123 section 4.1).
//!
//! The commands are in the modules of this one: `auth` (sign-in, `AUTH TLS`, `PBSZ`, `PROT`), `info` (`FEAT`, `HELP`, `STAT`, `OPTS`, `TYPE`), `files`
//! (the working directory and the metadata of a path) and `data` (`PASV`, `PORT`, the transfers).

mod auth;
mod data;
mod files;
mod info;

use crate::backend::{Backend, FsError};
use crate::clock;
use crate::codec::{Line, LineReader};
use crate::command::{self, Command, ParseError};
use crate::config::Config;
use crate::events::{Direction, Events, TransferEnd, TransferInfo};
use crate::listing::Facts;
use crate::path::FtpPath;
use crate::reply::{Reply, text};
use crate::tls::{self, Stream};
use crate::transfer::{DataPort, Event, Failure};
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
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
    /// The client did not sign in within [`Limits::login_timeout`](crate::Limits::login_timeout). The connection was closed without a reply
    LoginTimeout,
    /// The client failed to sign in [`Limits::max_login_attempts`](crate::Limits::max_login_attempts) times
    TooManyLoginFailures,
    /// The backend couldn't decide on a sign-in ([`LoginError::Unavailable`](crate::LoginError::Unavailable))
    LoginUnavailable,
    /// The TLS handshake after `AUTH TLS` failed. The connection was closed
    TlsHandshakeFailed,
    /// Reading or writing the connection failed
    Io(io::Error),
}

/// Serves one control connection until it ends.
///
/// The host accepts the connection, and decides who may connect and how many may at once; this does the protocol. A session never panics on what a
/// client sends. It ends when the client quits or closes the connection, when it is idle for too long, when the connection fails, or when the
/// future is dropped (the host's way to stop a session). A transfer that runs then is aborted: [`Backend::write`] is dropped, which is how it learns
/// that the upload did not complete. When the client quits, or closes the control connection, while a transfer runs, the transfer is given the time
/// to end (at most [`Limits::transfer_idle_timeout`](crate::Limits::transfer_idle_timeout) without a byte), as RFC 959 asks of `QUIT`.
pub async fn serve<B: Backend>(stream: TcpStream, peer: SocketAddr, config: Arc<Config>, backend: Arc<B>, events: Arc<dyn Events>) -> SessionEnd {
    let local = match stream.local_addr() {
        Ok(local) => local,
        Err(error) => return SessionEnd::Io(error),
    };
    // A reply and the reply after it (the 150 and the 226 of a small file) are not to wait for the acknowledgement of the first: that is 40 ms or more
    let _ = stream.set_nodelay(true);
    let span = tracing::info_span!("ftp_session", %peer, user = tracing::field::Empty);
    let data_tls = config.tls.as_ref().map(tls::for_data);
    let mut session = Session {
        span: span.clone(),
        stream: Stream::Plain(stream),
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
        data_port: None,
        epsv_all: false,
        rest: None,
        transfer: None,
        quitting: false,
        pbsz: false,
        data_private: false,
        data_tls,
    };
    async move {
        let end = session.run().await;
        debug!(?end, "session ended");
        session.close().await;
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
    stream: Stream,
    lines: LineReader,
    config: Arc<Config>,
    backend: Arc<B>,
    events: Arc<dyn Events>,
    peer: SocketAddr,
    local: SocketAddr,
    login: Login<B::User>,
    failed_logins: u32,
    cwd: FtpPath,
    /// `TYPE A` is set: with `Config::ascii_conversion` the transfers convert the line ends
    ascii: bool,
    /// The facts MLSD and MLST give (`OPTS MLST`)
    facts: Facts,
    /// Where the next data connection comes from: the listener of PASV or EPSV, or the address of PORT or EPRT. A session has one: a new command
    /// replaces it, and a listener is closed at once
    data_port: Option<DataPort>,
    /// `EPSV ALL` was sent: PASV is refused from then on (RFC 2428 section 4)
    epsv_all: bool,
    /// The offset of `REST`, for the next command
    rest: Option<u64>,
    transfer: Option<Running>,
    /// `QUIT` came while a transfer ran: the session ends when the transfer has
    quitting: bool,
    /// `PBSZ` was sent (RFC 4217 section 8)
    pbsz: bool,
    /// The protection level of the data connections is `P` (private: TLS). It is `C` (clear) until `PROT P`
    data_private: bool,
    /// The TLS settings of data connections
    data_tls: Option<Arc<rustls::ServerConfig>>,
    /// The span of the session's log lines; the user is added when they sign in
    span: tracing::Span,
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
    LoginTimeout,
    Idle,
}

/// What the transfer says next, or nothing ever when there is none
async fn next_event(transfer: &mut Option<Running>) -> Option<Event> {
    match transfer {
        Some(running) => running.events.recv().await,
        None => std::future::pending().await,
    }
}

impl<B: Backend> Session<B> {
    async fn run(&mut self) -> SessionEnd {
        info!("connected");
        let greeting = Reply::new(220, &self.config.greeting);
        if let Err(error) = self.send(greeting).await {
            return SessionEnd::Io(error);
        }
        let login_deadline = clock::after(self.config.limits.login_timeout);
        let mut last_activity = Instant::now();
        loop {
            // The time to wait is for the whole line: a client that sends a byte now and then doesn't keep the connection open. It doesn't run while a
            // transfer does: the client waits for its end
            let idle_deadline = clock::from(last_activity, self.config.idle_timeout);
            let waiting = self.transfer.is_none();
            let signing_in = !self.signed_in();
            let wake = tokio::select! {
                // What a transfer has to say goes before the next command
                biased;
                event = next_event(&mut self.transfer) => Wake::Transfer(event),
                line = self.lines.next_line(&mut self.stream) => Wake::Line(line),
                // The time to sign in is from the start: a client that does nothing but NOOP is not signing in
                () = sleep_until(login_deadline), if signing_in => Wake::LoginTimeout,
                () = sleep_until(idle_deadline), if waiting => Wake::Idle,
            };
            let outcome = match wake {
                Wake::Idle => return SessionEnd::IdleTimeout,
                Wake::LoginTimeout => return SessionEnd::LoginTimeout,
                Wake::Transfer(event) => self.transfer_event(event).await,
                Wake::Line(Err(error)) => return SessionEnd::Io(error),
                Wake::Line(Ok(None)) => return self.control_closed().await,
                Wake::Line(Ok(Some(Line::TooLong))) => self.reply(500, "Command line too long.").await,
                Wake::Line(Ok(Some(Line::Invalid))) => self.reply(501, "The command line is not UTF-8.").await,
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

    /// Ends the connection: over TLS with a `close_notify`, so the client can tell the end from a cut
    async fn close(&mut self) {
        let _ = timeout(Duration::from_secs(2), self.stream.shutdown()).await;
    }

    /// The client closed the control connection. A camera that sends the last byte of a file, closes the data connection and the control connection
    /// at once has finished its upload, whether or not it waited for the `226`: a transfer that runs is given the time to end, as long as it moves
    async fn control_closed(&mut self) -> SessionEnd {
        if let Some(mut running) = self.transfer.take() {
            let wait = self.config.limits.transfer_idle_timeout;
            let result = timeout(wait, async {
                loop {
                    match running.events.recv().await {
                        Some(Event::Started) => {}
                        Some(Event::Done(result)) => break Some(result),
                        None => break None,
                    }
                }
            })
            .await;
            match result {
                Ok(Some(result)) => {
                    // The client is gone: there is nobody to send the reply to
                    let _ = self.conclude(&running, result);
                }
                _ => {
                    running.handle.abort();
                    info!(direction = ?running.info.direction, path = %running.info.path, "transfer aborted");
                    self.events.transfer_ended(self.peer, self.user_name(), &running.info, &TransferEnd::Aborted);
                    let _ = running.handle.await;
                }
            }
        }
        SessionEnd::ClientClosed
    }

    /// Sends a reply. A client that doesn't read it can't keep the session waiting longer than the idle time
    async fn send(&mut self, reply: Reply) -> io::Result<()> {
        self.send_all(&[reply]).await
    }

    /// Sends replies in one write: two replies that follow each other (`426` and `226`) reach the client together
    async fn send_all(&mut self, replies: &[Reply]) -> io::Result<()> {
        let bytes: Vec<u8> = replies.iter().flat_map(Reply::encode).collect();
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

    /// A call of the backend, which gives up when the backend takes too long: a storage that hangs doesn't hang the session
    async fn within<T>(&self, call: impl Future<Output = Result<T, FsError>>) -> Result<T, FsError> {
        timeout(self.config.limits.backend_timeout, call).await.unwrap_or(Err(FsError::Unavailable))
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
        if self.transfer.is_some() {
            return self.during_transfer(command).await;
        }
        // REST is for the transfer command that follows it. Clients send PASV or EPSV between the two, and any other command cancels it
        let rest = if matches!(command, Command::Rest(_) | Command::Pasv | Command::Epsv(_)) { None } else { self.rest.take() };
        let command = match self.open_command(command).await {
            Ok(outcome) => return outcome,
            Err(command) => command,
        };
        let Some(user) = self.user() else { return self.reply(530, text::NOT_LOGGED_IN).await };
        self.signed_in_command(&user, command, rest).await
    }

    /// The commands that are answered at any time (RFC 959: `STAT` and `ABOR`; and what a client does before it signs in: `FEAT`, `HELP`, `OPTS`, `AUTH`).
    /// The others are given back
    async fn open_command(&mut self, command: Command) -> Result<Outcome, Command> {
        let outcome = match command {
            Command::User(name) => self.user_command(name).await,
            Command::Pass(password) => self.pass(password.0).await,
            Command::Acct => self.reply(202, text::SUPERFLUOUS).await,
            Command::Quit => self.send(Reply::new(221, text::CLOSING)).await.map(|()| Some(SessionEnd::Quit)),
            Command::Noop => self.reply(200, text::COMMAND_OK).await,
            Command::Syst => self.reply(215, "UNIX Type: L8").await,
            Command::Feat => self.feat().await,
            Command::Opts { name, value } => self.opts(&name, value.as_deref()).await,
            Command::Help(topic) => self.help(topic).await,
            Command::Stat(None) => self.status().await,
            Command::Auth(mechanism) => self.auth(&mechanism).await,
            Command::Pbsz(_) => self.protection_buffer().await,
            Command::Prot(level) => self.protection(&level).await,
            Command::Ccc => self.reply(534, "Request denied for policy reasons.").await,
            Command::Abor => self.reply(226, "No transfer in progress.").await,
            Command::Unsupported(_) => self.reply(502, text::NOT_IMPLEMENTED).await,
            other => return Err(other),
        };
        Ok(outcome)
    }

    /// The commands of a user who has signed in
    async fn signed_in_command(&mut self, user: &Arc<B::User>, command: Command, rest: Option<u64>) -> Outcome {
        match command {
            Command::Stat(Some(argument)) => self.stat_path(user, &argument).await,
            Command::Pwd => {
                let reply = format!("{} is the current directory.", files::quoted(&self.cwd));
                self.reply(257, &reply).await
            }
            Command::Cwd(argument) => self.change_dir(user, &argument).await,
            Command::Cdup => self.change_dir(user, "..").await,
            Command::Mkd(argument) => self.make_dir(user, &argument).await,
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
            Command::Port(argument) => self.active_mode(crate::active::parse_port(&argument)).await,
            Command::Eprt(argument) => self.active_mode(crate::active::parse_eprt(&argument)).await,
            Command::Site(_) => self.reply(502, "SITE commands are not supported.").await,
            Command::Pasv => self.passive_mode(false).await,
            Command::Epsv(argument) => self.epsv(argument.as_deref()).await,
            Command::List(argument) => self.listing(user, data::ListKind::List, argument).await,
            Command::Nlst(argument) => self.listing(user, data::ListKind::Nlst, argument).await,
            Command::Mlsd(argument) => self.listing(user, data::ListKind::Mlsd, argument).await,
            Command::Retr(argument) => self.retrieve(user, &argument, rest.unwrap_or(0)).await,
            Command::Stor(argument) => self.store(user, &argument, rest.unwrap_or(0)).await,
            Command::Rest(offset) => {
                self.rest = Some(offset);
                self.reply(350, &format!("Restarting at {offset}. Send STORE or RETRIEVE to initiate transfer.")).await
            }
            Command::Size(argument) => self.size(user, &argument).await,
            Command::Mdtm(argument) => self.modification_time(user, &argument).await,
            Command::Mlst(argument) => self.mlst(user, argument.as_deref()).await,
            // The commands that need no sign-in were answered before
            _ => self.reply(500, text::SYNTAX_COMMAND).await,
        }
    }

    /// While a transfer runs, the control connection answers ABOR and STAT at any time (RFC 959 section 4.1.3, RFC 1123 section 4.1.3.3). `QUIT` waits
    /// for the end of the transfer, and then closes (RFC 959 section 4.1.3). The other commands wait for the transfer to end: they are refused, and may
    /// be sent again
    async fn during_transfer(&mut self, command: Command) -> Outcome {
        match command {
            Command::Abor => {
                self.abort_transfer().await;
                let replies = [Reply::new(426, "Connection closed; transfer aborted."), Reply::new(226, text::DATA_CLOSED)];
                self.send_all(&replies).await?;
                self.end_if_quitting().await
            }
            Command::Stat(None) => {
                let Some(running) = &self.transfer else { return Ok(None) };
                let what = match running.info.direction {
                    Direction::Upload => "Receiving",
                    Direction::Download => "Sending",
                    _ => "Sending a listing of",
                };
                let lines = [
                    "FTP server status:".to_string(),
                    format!("{what} {}: {} bytes so far", running.info.path, running.progress.load(Ordering::Relaxed)),
                    "End of status".to_string(),
                ];
                self.send_reply(Reply::multi(211, lines)).await
            }
            Command::Stat(Some(argument)) => match self.user() {
                Some(user) => self.stat_path(&user, &argument).await,
                None => self.reply(530, text::NOT_LOGGED_IN).await,
            },
            Command::Quit => {
                self.quitting = true;
                Ok(None)
            }
            Command::Noop => self.reply(200, text::COMMAND_OK).await,
            _ => self.reply(450, "A transfer is in progress.").await,
        }
    }

    /// After the transfer that ran when `QUIT` came: the reply to `QUIT`, and the end of the session
    async fn end_if_quitting(&mut self) -> Outcome {
        if !self.quitting {
            return Ok(None);
        }
        self.reply(221, text::CLOSING).await?;
        Ok(Some(SessionEnd::Quit))
    }

    /// Stops the transfer and waits until it has let go of everything: the upload the backend was storing is dropped, not finished
    async fn abort_transfer(&mut self) {
        if let Some(running) = self.transfer.take() {
            running.handle.abort();
            info!(direction = ?running.info.direction, path = %running.info.path, "transfer aborted");
            // Before the wait: if the host drops the session now, it has been told
            self.events.transfer_ended(self.peer, self.user_name(), &running.info, &TransferEnd::Aborted);
            let _ = running.handle.await;
        }
    }

    /// The transfer says something: its data connection is open (`150`), or it is over (the final reply)
    async fn transfer_event(&mut self, event: Option<Event>) -> Outcome {
        match event {
            Some(Event::Started) => self.reply(150, "File status okay; about to open data connection.").await,
            done => {
                // A task that ended without saying how (it panicked) is a failure of the storage
                let result = match done {
                    Some(Event::Done(result)) => result,
                    _ => Err(Failure::Storage(FsError::Local("the transfer task failed".to_string()))),
                };
                let Some(running) = self.transfer.take() else { return Ok(None) };
                let reply = self.conclude(&running, result);
                self.send_reply(reply).await?;
                self.end_if_quitting().await
            }
        }
    }

    /// Tells the host and the log how a transfer ended, and gives the final reply for the client
    fn conclude(&self, running: &Running, result: Result<u64, Failure>) -> Reply {
        let end = match &result {
            Ok(bytes) => TransferEnd::Completed(*bytes),
            Err(_) => TransferEnd::Failed,
        };
        self.events.transfer_ended(self.peer, self.user_name(), &running.info, &end);
        match &end {
            TransferEnd::Completed(bytes) => info!(direction = ?running.info.direction, path = %running.info.path, bytes, "transfer completed"),
            _ => info!(direction = ?running.info.direction, path = %running.info.path, "transfer failed"),
        }
        match result {
            Ok(_) => Reply::new(226, text::DATA_CLOSED),
            Err(Failure::NoConnection) => Reply::new(425, "Can't open data connection."),
            Err(Failure::Tls) => Reply::new(425, "Can't open data connection: the TLS handshake failed."),
            Err(Failure::Aborted) => Reply::new(426, "Connection closed; transfer aborted."),
            Err(Failure::Storage(error)) => {
                if let FsError::Local(message) = &error {
                    warn!(%message, "storage error in a transfer");
                }
                file_error_reply(&error)
            }
        }
    }
}

fn file_error_reply(error: &FsError) -> Reply {
    match error {
        FsError::NotFound => Reply::new(550, text::FILE_UNAVAILABLE),
        FsError::PermissionDenied => Reply::new(550, "Permission denied."),
        FsError::AlreadyExists => Reply::new(550, "Already exists."),
        FsError::WrongType => Reply::new(550, "Not the right type of file."),
        FsError::NameNotAllowed => Reply::new(553, text::NAME_NOT_ALLOWED),
        FsError::QuotaExceeded => Reply::new(552, text::NO_SPACE),
        FsError::Unsupported => Reply::new(504, text::NOT_IMPLEMENTED_PARAMETER),
        FsError::Unavailable => Reply::new(450, text::FILE_BUSY),
        _ => Reply::new(451, text::LOCAL_ERROR),
    }
}

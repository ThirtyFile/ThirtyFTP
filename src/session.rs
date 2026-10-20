//! One control connection: the state of the session and what each command does (RFC 959 section 5, RFC 1123 section 4.1).

use crate::backend::{Backend, FsError, LoginContext, LoginError};
use crate::codec::{Line, LineReader};
use crate::command::{self, Command, ParseError, TypeArg};
use crate::config::Config;
use crate::events::Events;
use crate::path::FtpPath;
use crate::reply::{Reply, text};
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::time::{Instant, timeout, timeout_at};
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
/// future is dropped (the host's way to stop a session: nothing is left behind that the backend has to clean up beyond what [`Backend::write`] says).
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
        user: U,
    },
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
    /// TYPE A: kept for the transfers, which treat the bytes the same either way
    ascii: bool,
}

/// What a command leaves to do
type Outcome = io::Result<Option<SessionEnd>>;

impl<B: Backend> Session<B> {
    async fn run(mut self) -> SessionEnd {
        info!("connected");
        let greeting = Reply::new(220, &self.config.greeting);
        if let Err(error) = self.send(greeting).await {
            return SessionEnd::Io(error);
        }
        loop {
            // The time to wait is for the whole line: a client that sends a byte now and then doesn't keep the connection open
            let deadline = Instant::now() + self.config.idle_timeout;
            let line = match timeout_at(deadline, self.lines.next_line(&mut self.stream)).await {
                Err(_) => return SessionEnd::IdleTimeout,
                Ok(Err(error)) => return SessionEnd::Io(error),
                Ok(Ok(None)) => return SessionEnd::ClientClosed,
                Ok(Ok(Some(line))) => line,
            };
            let outcome = match line {
                Line::TooLong => self.send(Reply::new(500, "Command line too long.")).await.map(|()| None),
                Line::Text(line) => match command::parse(&line) {
                    Ok(command) => {
                        debug!(verb = command.verb(), "command");
                        trace!(?command, "command arguments");
                        self.handle(command).await
                    }
                    Err(ParseError::Unknown) => self.send(Reply::new(500, text::SYNTAX_COMMAND)).await.map(|()| None),
                    Err(ParseError::Syntax) => self.send(Reply::new(501, text::SYNTAX_PARAMETERS)).await.map(|()| None),
                },
            };
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

    fn signed_in(&self) -> bool {
        matches!(self.login, Login::SignedIn { .. })
    }

    async fn handle(&mut self, command: Command) -> Outcome {
        if !self.signed_in() && needs_login(&command) {
            return self.reply(530, text::NOT_LOGGED_IN).await;
        }
        match command {
            Command::User(name) => self.user(name).await,
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
                lines.extend(features().iter().map(|feature| feature.to_string()));
                lines.push("End".to_string());
                self.send(Reply::multi(211, lines)).await.map(|()| None)
            }
            Command::Opts { name, value } => self.opts(&name, value.as_deref()).await,
            Command::Help(topic) => self.help(topic).await,
            Command::Stat(None) => self.status().await,
            Command::Stat(Some(_)) => self.reply(502, text::NOT_IMPLEMENTED).await,
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
            Command::Stor(_) | Command::Retr(_) | Command::List(_) | Command::Nlst(_) | Command::Mlsd(_) => self.reply(425, "Use PASV or EPSV first.").await,
            // Later milestones
            Command::Auth(_) | Command::Pasv | Command::Epsv(_) | Command::Mlst(_) | Command::Size(_) | Command::Mdtm(_) | Command::Rest(_) => {
                self.reply(502, text::NOT_IMPLEMENTED).await
            }
            Command::Pbsz(_) | Command::Prot(_) => self.reply(503, text::BAD_SEQUENCE).await,
            Command::Unsupported(_) => self.reply(502, text::NOT_IMPLEMENTED).await,
        }
    }

    async fn user(&mut self, name: String) -> Outcome {
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
                self.login = Login::SignedIn { name, user };
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

    async fn opts(&mut self, name: &str, value: Option<&str>) -> Outcome {
        match (name, value.map(str::to_ascii_uppercase).as_deref()) {
            ("UTF8", Some("ON")) => self.reply(200, "UTF8 is always on.").await,
            ("UTF8", Some("OFF")) => self.reply(504, "UTF8 can't be turned off.").await,
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
                self.send(Reply::multi(214, lines)).await.map(|()| None)
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
        self.send(Reply::multi(211, lines)).await.map(|()| None)
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

    /// Resolves a path of the client. A path that can't be used is answered, and `None` returned
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
        let Login::SignedIn { user, .. } = &self.login else { return self.reply(530, text::NOT_LOGGED_IN).await };
        match self.backend.change_dir(user, &path).await {
            Ok(()) => {
                self.cwd = path;
                self.reply(250, text::FILE_ACTION_OK).await
            }
            Err(error) => self.file_error(error).await,
        }
    }

    async fn make_dir(&mut self, argument: &str) -> Outcome {
        let Some(path) = self.resolve(argument).await? else { return Ok(None) };
        let Login::SignedIn { user, .. } = &self.login else { return self.reply(530, text::NOT_LOGGED_IN).await };
        match self.backend.make_dir(user, &path).await {
            Ok(()) => {
                let reply = format!("{} created.", quoted(&path));
                self.reply(257, &reply).await
            }
            Err(error) => self.file_error(error).await,
        }
    }

    async fn file_error(&mut self, error: FsError) -> Outcome {
        let reply = file_error_reply(&error);
        if let FsError::Local(message) = &error {
            warn!(%message, "storage error");
        }
        self.send(reply).await.map(|()| None)
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

/// The lines of FEAT (RFC 2389), for what is done
fn features() -> &'static [&'static str] {
    &["UTF8"]
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

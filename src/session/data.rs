//! Data connections and transfers: `PASV`, `EPSV`, `PORT`, `EPRT`, `LIST`, `NLST`, `MLSD`, `RETR`, `STOR` (RFC 959 section 4.1.2 and 4.1.3, RFC 2428,
//! RFC 2577)

use super::{Outcome, Running, Session};
use crate::active::{self, ActiveError};
use crate::backend::{Backend, Entry, EntryKind, FsError};
use crate::config::PassiveHost;
use crate::events::{Direction, TransferInfo};
use crate::listing;
use crate::passive;
use crate::path::FtpPath;
use crate::reply::{Reply, text};
use crate::transfer::{self, DataPort, Job, Work};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use std::time::SystemTime;
use tokio::sync::mpsc;
use tracing::warn;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum ListKind {
    List,
    Nlst,
    Mlsd,
}

impl<B: Backend> Session<B> {
    /// PASV and EPSV: a new listener, and the old one is closed first, so a session never holds two ports (RFC 959 section 4.1.2, RFC 2428)
    pub(super) async fn passive_mode(&mut self, extended: bool) -> Outcome {
        if let Some(reply) = self.data_policy() {
            self.data_port = None;
            return self.send_reply(reply).await;
        }
        if !extended && self.epsv_all {
            return self.reply(501, "PASV is not allowed after EPSV ALL.").await;
        }
        // Before the new port is bound: with a small range the old port may be the only one free
        self.data_port = None;
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
        self.data_port = Some(DataPort::Passive(listener));
        match address {
            Some(ip) => self.reply(227, &passive::pasv_text(ip, port)).await,
            None => self.reply(229, &passive::epsv_text(port)).await,
        }
    }

    /// The address a PASV reply tells (RFC 959 has IPv4 only)
    async fn passive_address(&self) -> Result<Ipv4Addr, Reply> {
        match &self.config.passive_host {
            PassiveHost::Ip(ip) => Ok(*ip),
            PassiveHost::Dns(name) => passive::resolve_ipv4(name).await.ok_or_else(|| Reply::new(425, "Can't open data connection.")),
            _ => match passive::canonical(self.local.ip()) {
                IpAddr::V4(ip) => Ok(ip),
                IpAddr::V6(_) => Err(Reply::new(501, "PASV is for IPv4. Use EPSV.")),
            },
        }
    }

    /// The text of the 425 for a data command without a data connection announced
    fn use_pasv_first(&self) -> &'static str {
        if self.config.active_mode { "Use PORT, PASV or EPSV first." } else { "Use PASV or EPSV first." }
    }

    /// PORT and EPRT (RFC 959, RFC 2428): where the server connects to for the data connection. Only to the address of the client and only to ports from
    /// 1024 up (RFC 2577 section 3), and with the policy of the data connections
    pub(super) async fn active_mode(&mut self, parsed: Result<SocketAddr, ActiveError>) -> Outcome {
        if !self.config.active_mode {
            return self.reply(502, "Active mode is not supported.").await;
        }
        if let Some(reply) = self.data_policy() {
            self.data_port = None;
            return self.send_reply(reply).await;
        }
        if self.epsv_all {
            return self.reply(501, "PORT and EPRT are not allowed after EPSV ALL.").await;
        }
        let address = match parsed {
            Ok(address) => address,
            Err(ActiveError::Syntax) => return self.reply(501, text::SYNTAX_PARAMETERS).await,
            Err(ActiveError::Protocol) => {
                let version = if self.peer.is_ipv4() { "1" } else { "2" };
                return self.reply(522, &format!("Network protocol not supported, use ({version})")).await;
            }
        };
        if passive::canonical(address.ip()) != passive::canonical(self.peer.ip()) || address.port() < active::FIRST_PORT {
            warn!(%address, "an active data connection to another address or a low port was refused");
            self.data_port = None;
            return self.reply(504, "The data connection can only go to your own address and to a port from 1024 up.").await;
        }
        self.data_port = Some(DataPort::Active(address));
        self.reply(200, "PORT command successful.").await
    }

    pub(super) async fn epsv(&mut self, argument: Option<&str>) -> Outcome {
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

    /// The entries of a directory, and whether the path is one. `LIST` and `NLST` of a file give that file (the backend says so with `WrongType`).
    /// A listing is built in memory, so it has a limit
    pub(super) async fn entries(&self, user: &Arc<B::User>, path: &FtpPath, kind: ListKind) -> Result<(Vec<Entry>, bool), FsError> {
        let (entries, is_directory) = match self.within(self.backend.list(user, path)).await {
            Ok(entries) => (entries, true),
            Err(FsError::WrongType) if kind != ListKind::Mlsd => match self.within(self.backend.metadata(user, path)).await {
                Ok(entry) if entry.kind == EntryKind::File => (vec![entry], false),
                Ok(_) => return Err(FsError::WrongType),
                Err(error) => return Err(error),
            },
            Err(error) => return Err(error),
        };
        if entries.len() > self.config.limits.max_list_entries {
            return Err(FsError::Local(format!("the listing has {} entries, the most is {}", entries.len(), self.config.limits.max_list_entries)));
        }
        Ok((entries, is_directory))
    }

    pub(super) async fn listing(&mut self, user: &Arc<B::User>, kind: ListKind, argument: Option<String>) -> Outcome {
        if let Some(reply) = self.data_policy() {
            return self.send_reply(reply).await;
        }
        if self.data_port.is_none() {
            return self.reply(425, self.use_pasv_first()).await;
        }
        let path = match &argument {
            Some(argument) => match self.resolve(argument).await? {
                Some(path) => path,
                None => return Ok(None),
            },
            None => self.cwd.clone(),
        };
        let (entries, is_directory) = match self.entries(user, &path, kind).await {
            Ok(found) => found,
            Err(error) => return self.file_error(error).await,
        };
        let listing = match kind {
            ListKind::List => listing::list(&entries, SystemTime::now()),
            // The names as the client wrote the path, as other servers give them: `NLST sub` lists `sub/a.txt`, and the name of a file is the path
            ListKind::Nlst => match (&argument, is_directory) {
                (Some(argument), true) => {
                    let directory = argument.trim_end_matches('/');
                    listing::lines(&entries.iter().map(|entry| format!("{directory}/{}", entry.name)).collect::<Vec<_>>())
                }
                (Some(argument), false) => listing::lines(std::slice::from_ref(argument)),
                (None, _) => listing::names(&entries),
            },
            ListKind::Mlsd => listing::mlsd(&entries, self.facts),
        };
        self.start_transfer(user, Work::Listing(listing.into_bytes()), TransferInfo::new(Direction::Listing, path)).await
    }

    pub(super) async fn retrieve(&mut self, user: &Arc<B::User>, argument: &str, offset: u64) -> Outcome {
        if let Some(reply) = self.data_policy() {
            return self.send_reply(reply).await;
        }
        if self.data_port.is_none() {
            return self.reply(425, self.use_pasv_first()).await;
        }
        let Some(path) = self.resolve(argument).await? else { return Ok(None) };
        let size = match self.within(self.backend.metadata(user, &path)).await {
            Ok(entry) if entry.kind == EntryKind::File => entry.size,
            Ok(_) => return self.reply(550, "Not a plain file.").await,
            Err(error) => return self.file_error(error).await,
        };
        if offset > size {
            return self.reply(554, "Requested action not taken: invalid REST parameter.").await;
        }
        match self.within(self.backend.read(user, &path, offset)).await {
            Ok(reader) => self.start_transfer(user, Work::Download(reader), TransferInfo::new(Direction::Download, path)).await,
            Err(error) => self.file_error(error).await,
        }
    }

    pub(super) async fn store(&mut self, user: &Arc<B::User>, argument: &str, offset: u64) -> Outcome {
        if let Some(reply) = self.data_policy() {
            return self.send_reply(reply).await;
        }
        if self.data_port.is_none() {
            return self.reply(425, self.use_pasv_first()).await;
        }
        let Some(path) = self.resolve(argument).await? else { return Ok(None) };
        if path.is_root() {
            return self.reply(553, text::NAME_NOT_ALLOWED).await;
        }
        // The backend stores a whole file: there is no way to continue one
        if offset != 0 {
            return self.reply(554, "Requested action not taken: invalid REST parameter.").await;
        }
        self.start_transfer(user, Work::Upload(path.clone()), TransferInfo::new(Direction::Upload, path)).await
    }

    /// Starts the task of a transfer: it waits for the data connection, and the session goes on with the control connection
    async fn start_transfer(&mut self, user: &Arc<B::User>, work: Work, info: TransferInfo) -> Outcome {
        let Some(port) = self.data_port.take() else { return self.reply(425, self.use_pasv_first()).await };
        let limits = &self.config.limits;
        let (sender, receiver) = mpsc::channel(4);
        let progress = Arc::new(AtomicU64::new(0));
        let job = Job {
            backend: self.backend.clone(),
            user: user.clone(),
            port,
            local: self.local.ip(),
            client: self.peer.ip(),
            accept_timeout: limits.data_accept_timeout,
            idle_timeout: limits.transfer_idle_timeout,
            tls: if self.data_private { self.data_tls.clone() } else { None },
            handshake_timeout: limits.tls_handshake_timeout,
            close_wait: limits.tls_close_wait,
            max_time: limits.max_transfer_time,
            ascii: self.ascii && self.config.ascii_conversion,
            progress: progress.clone(),
            events: sender,
        };
        self.events.transfer_started(self.peer, self.user_name(), &info);
        let handle = tokio::spawn(transfer::run(job, work));
        self.transfer = Some(Running { handle, events: receiver, progress, info });
        Ok(None)
    }
}

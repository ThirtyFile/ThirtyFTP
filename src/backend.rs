//! What the host provides: who may sign in, and the files.
//!
//! The library does the protocol; the [`Backend`] does everything that touches a user or storage. It is told what the client asked for as an
//! [`FtpPath`] (never the text the client sent), and it answers with an error that the library turns into the reply that fits.

use crate::path::FtpPath;
use async_trait::async_trait;
use std::net::SocketAddr;
use std::time::SystemTime;
use tokio::io::AsyncRead;

/// What the backend may know about a sign-in
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct LoginContext {
    /// The address the client connected from
    pub peer: SocketAddr,
    /// The address the client connected to
    pub local: SocketAddr,
    /// Whether the control connection is encrypted (after `AUTH TLS`)
    pub encrypted: bool,
}

/// Why a sign-in failed
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum LoginError {
    /// The name or the password is wrong, or the user may not sign in: `530 Login incorrect.`
    #[error("login incorrect")]
    Incorrect,
    /// Refused with a reason the client may read (a closing server, a wrong address): `530` with the text
    #[error("login refused: {0}")]
    Refused(String),
    /// The backend can't decide now (its user store is down): `421`, and the connection closes. The client may try again later
    #[error("login unavailable")]
    Unavailable,
}

/// Why a file operation failed. Each is a reply: the ones that may succeed later are 4xx, the others 5xx (RFC 1123 section 4.1.2.11)
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum FsError {
    /// It doesn't exist: `550`
    #[error("not found")]
    NotFound,
    /// The user may not do this: `550`
    #[error("permission denied")]
    PermissionDenied,
    /// It exists already: `550`
    #[error("already exists")]
    AlreadyExists,
    /// It is not what the command needs (a file where a directory is needed, or the other way round): `550`
    #[error("wrong type")]
    WrongType,
    /// The name can't be used: `553`
    #[error("name not allowed")]
    NameNotAllowed,
    /// The storage is full or the user's quota is used: `552`
    #[error("storage full")]
    QuotaExceeded,
    /// The file is in use, or the storage is busy or offline. It may work later: `450`
    #[error("temporarily unavailable")]
    Unavailable,
    /// Any other failure of the storage: `451`
    #[error("local error: {0}")]
    Local(String),
}

/// What a path is
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryKind {
    /// A file
    File,
    /// A directory
    Directory,
}

/// A file or a directory, as a listing and `SIZE`, `MDTM` and `MLST` show it
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Entry {
    /// The name, without a path
    pub name: String,
    /// A file or a directory
    pub kind: EntryKind,
    /// The size in bytes (0 for a directory when it has none)
    pub size: u64,
    /// When it was last changed
    pub modified: Option<SystemTime>,
}

impl Entry {
    /// A file
    pub fn file(name: impl Into<String>, size: u64, modified: Option<SystemTime>) -> Entry {
        Entry { name: name.into(), kind: EntryKind::File, size, modified }
    }

    /// A directory
    pub fn directory(name: impl Into<String>, modified: Option<SystemTime>) -> Entry {
        Entry { name: name.into(), kind: EntryKind::Directory, size: 0, modified }
    }
}

/// The host's users and storage. One backend serves all the sessions; `User` is what [`Backend::login`] returns for one of them, and is passed to
/// every other call of that session, so the backend needs no table of sessions.
///
/// The paths are absolute and normalised, with the session's root as `/`. A backend maps them to its storage and has to keep a path from leaving
/// the area of the user.
#[async_trait]
pub trait Backend: Send + Sync + 'static {
    /// What the backend keeps for a signed-in user
    type User: Send + Sync + 'static;

    /// Checks a name and a password. The library has not told the client yet; the backend may take its time, and may count failures
    async fn login(&self, context: &LoginContext, user: &str, password: &str) -> Result<Self::User, LoginError>;

    /// What a path is: for `SIZE`, `MDTM`, `MLST`, and to check a path before a transfer
    async fn metadata(&self, user: &Self::User, path: &FtpPath) -> Result<Entry, FsError>;

    /// The entries of a directory
    async fn list(&self, user: &Self::User, path: &FtpPath) -> Result<Vec<Entry>, FsError>;

    /// Opens a file for download, from an offset (`REST`). A backend that can't start in the middle returns [`FsError::PermissionDenied`] for an offset
    /// that is not 0
    async fn read(&self, user: &Self::User, path: &FtpPath, offset: u64) -> Result<Box<dyn AsyncRead + Send + Unpin>, FsError>;

    /// Stores what `data` delivers until its end, and returns the number of bytes stored.
    ///
    /// When this future is dropped before it is done, or `data` fails, the upload did not complete (the client aborted, the connection was cut, the
    /// server is stopping): the backend must not keep a partial file, and must keep a file that was there before.
    async fn write(&self, user: &Self::User, path: &FtpPath, data: &mut (dyn AsyncRead + Send + Unpin)) -> Result<u64, FsError>;

    /// Makes a directory
    async fn make_dir(&self, user: &Self::User, path: &FtpPath) -> Result<(), FsError>;

    /// Checks that a directory exists and the user may enter it
    async fn change_dir(&self, user: &Self::User, path: &FtpPath) -> Result<(), FsError>;
}

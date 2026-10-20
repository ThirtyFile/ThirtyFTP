//! What the host provides: who may sign in, and the files.
//!
//! The library does the protocol; the [`Backend`] does everything that touches a user or storage. It is told what the client asked for as an
//! [`FtpPath`] (never the text the client sent), and it answers with an error that the library turns into the reply that fits.

use crate::path::FtpPath;
use std::future::Future;
use std::io;
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

impl LoginContext {
    /// A context, for a host that tests its [`Backend::login`]
    pub fn new(peer: SocketAddr, local: SocketAddr, encrypted: bool) -> LoginContext {
        LoginContext { peer, local, encrypted }
    }
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
    /// The backend can't do this, for example a `REST` offset in [`Backend::read`]: `504`
    #[error("not supported")]
    Unsupported,
    /// The file is in use, or the storage is busy or offline. It may work later: `450`
    #[error("temporarily unavailable")]
    Unavailable,
    /// Any other failure of the storage: `451`. The text goes to the log, not to the client
    #[error("local error: {0}")]
    Local(String),
}

impl From<io::Error> for FsError {
    /// The error of the file system as the error of the backend
    fn from(error: io::Error) -> FsError {
        match error.kind() {
            io::ErrorKind::NotFound => FsError::NotFound,
            io::ErrorKind::PermissionDenied => FsError::PermissionDenied,
            io::ErrorKind::AlreadyExists => FsError::AlreadyExists,
            io::ErrorKind::StorageFull | io::ErrorKind::QuotaExceeded => FsError::QuotaExceeded,
            io::ErrorKind::NotADirectory | io::ErrorKind::IsADirectory => FsError::WrongType,
            io::ErrorKind::InvalidFilename => FsError::NameNotAllowed,
            io::ErrorKind::ResourceBusy | io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut => FsError::Unavailable,
            _ => FsError::Local(error.to_string()),
        }
    }
}

/// What a path is
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
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
    /// The name, without a path. For the root, `/`
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
/// the area of the user: [`FtpPath::to_native`] does that for a folder on disk, including the names that Windows treats in its own way.
///
/// Every method is an `async fn` (the trait uses `impl Future + Send`, so an implementation is written with `async fn`, or with `#[async_trait]`).
/// The library gives each call [`Limits::backend_timeout`](crate::Limits::backend_timeout), except [`Backend::write`], which ends with the upload.
/// A call that panics ends the session; a panic in [`Backend::write`] is a `451`.
pub trait Backend: Send + Sync + 'static {
    /// What the backend keeps for a signed-in user
    type User: Send + Sync + 'static;

    /// Checks a name and a password. The library has not told the client yet; the backend may take its time, and may count failures. A name has no
    /// control characters (the library refuses those before it asks)
    fn login(&self, context: &LoginContext, user: &str, password: &str) -> impl Future<Output = Result<Self::User, LoginError>> + Send;

    /// What a path is: for `SIZE`, `MDTM`, `MLST`, `RETR` (a download needs a file) and to check a path for `LIST`, `NLST` and `STAT` of a file. The root
    /// is a directory named `/`
    fn metadata(&self, user: &Self::User, path: &FtpPath) -> impl Future<Output = Result<Entry, FsError>> + Send;

    /// The entries of a directory. For a path that is a file, return [`FsError::WrongType`]: `LIST` and `NLST` of a file then show that file, with the
    /// entry of [`Backend::metadata`]
    fn list(&self, user: &Self::User, path: &FtpPath) -> impl Future<Output = Result<Vec<Entry>, FsError>> + Send;

    /// Opens a file for download, from an offset (`REST`). A backend that can't start in the middle returns [`FsError::Unsupported`] for an offset that
    /// is not 0
    fn read(&self, user: &Self::User, path: &FtpPath, offset: u64) -> impl Future<Output = Result<Box<dyn AsyncRead + Send + Unpin>, FsError>> + Send;

    /// Stores what `data` delivers until its end, and returns the number of bytes stored.
    ///
    /// - Read `data` to its end. A backend that returns `Ok` before the end (a size limit, for example) has not stored the upload: the library sees data
    ///   left, and answers the client with an error. To refuse an upload that is too big, return [`FsError::QuotaExceeded`].
    /// - When this future is dropped before it is done, or `data` fails, the upload did not complete (the client aborted it, the connection was cut, the
    ///   server is stopping): the backend must not keep a partial file, and must keep a file that was there before.
    /// - Refuse early what can be refused before the first byte (a name, a missing directory, a quota): the client has been told `150` by then, but
    ///   it has not sent the file yet.
    fn write(&self, user: &Self::User, path: &FtpPath, data: &mut (dyn AsyncRead + Send + Unpin)) -> impl Future<Output = Result<u64, FsError>> + Send;

    /// Makes a directory
    fn make_dir(&self, user: &Self::User, path: &FtpPath) -> impl Future<Output = Result<(), FsError>> + Send;

    /// Checks that a directory exists and the user may enter it
    fn change_dir(&self, user: &Self::User, path: &FtpPath) -> impl Future<Output = Result<(), FsError>> + Send;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn io_errors_become_the_errors_of_the_backend() {
        let convert = |kind| FsError::from(io::Error::from(kind));
        assert_eq!(convert(io::ErrorKind::NotFound), FsError::NotFound);
        assert_eq!(convert(io::ErrorKind::PermissionDenied), FsError::PermissionDenied);
        assert_eq!(convert(io::ErrorKind::AlreadyExists), FsError::AlreadyExists);
        assert_eq!(convert(io::ErrorKind::StorageFull), FsError::QuotaExceeded);
        assert_eq!(convert(io::ErrorKind::NotADirectory), FsError::WrongType);
        assert_eq!(convert(io::ErrorKind::IsADirectory), FsError::WrongType);
        assert_eq!(convert(io::ErrorKind::InvalidFilename), FsError::NameNotAllowed);
        assert_eq!(convert(io::ErrorKind::ResourceBusy), FsError::Unavailable);
        assert!(matches!(convert(io::ErrorKind::BrokenPipe), FsError::Local(_)));
    }
}

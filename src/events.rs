//! What the host is told about a session, for its own activity log and deadlines.

use crate::path::FtpPath;
use std::net::SocketAddr;

/// What a transfer moves, in which direction
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Direction {
    /// The client sends a file (`STOR`)
    Upload,
    /// The client receives a file (`RETR`)
    Download,
    /// The client receives a listing (`LIST`, `NLST`, `MLSD`)
    Listing,
}

/// A transfer, as the events tell about it
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct TransferInfo {
    /// Upload, download or listing
    pub direction: Direction,
    /// The file, or the directory of a listing
    pub path: FtpPath,
}

impl TransferInfo {
    /// A transfer, for a host that tests its [`Events`]
    pub fn new(direction: Direction, path: FtpPath) -> TransferInfo {
        TransferInfo { direction, path }
    }
}

/// How a transfer ended
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum TransferEnd {
    /// It completed, with the number of bytes moved
    Completed(u64),
    /// The client aborted it, or the session was dropped while it ran
    Aborted,
    /// It failed: the client did not connect, the data connection failed or stood still, or the storage failed
    Failed,
}

/// Notifications from a session. Every method does nothing by default, so a host implements the ones it needs. They are called from the session's
/// task and have to return at once.
pub trait Events: Send + Sync {
    /// The client signed in. The host can end its deadline for signing in
    fn signed_in(&self, _peer: SocketAddr, _user: &str) {}

    /// A sign-in failed (wrong name or password, or refused)
    fn login_failed(&self, _peer: SocketAddr, _user: &str) {}

    /// A transfer was accepted: the command was fine, and the session waits for the data connection. Every transfer that starts ends with one
    /// [`Events::transfer_ended`], also one that never gets its data connection
    fn transfer_started(&self, _peer: SocketAddr, _user: &str, _transfer: &TransferInfo) {}

    /// A transfer is over
    fn transfer_ended(&self, _peer: SocketAddr, _user: &str, _transfer: &TransferInfo, _end: &TransferEnd) {}
}

/// Events that are ignored
#[derive(Debug, Clone, Copy, Default)]
pub struct NoEvents;

impl Events for NoEvents {}

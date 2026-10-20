//! ThirtyFTP: a small FTP and FTPS server library for receive folders.
//!
//! It serves passive-mode FTP and explicit FTPS (`AUTH TLS`) with uploads, optional listing and downloads, and folder
//! creation. Active mode, deleting, renaming and implicit FTPS are not supported.
//!
//! The host accepts the TCP connections and calls [`serve`] for each one, with a [`Backend`] that knows its users and storage.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod active;
mod backend;
mod codec;
mod command;
mod config;
mod events;
mod listing;
mod passive;
mod path;
mod reply;
mod session;
mod time;
mod tls;
mod transfer;

pub use backend::{Backend, Entry, EntryKind, FsError, LoginContext, LoginError};
pub use config::{Config, Limits, PassiveHost};
pub use events::{Direction, Events, NoEvents, TransferEnd, TransferInfo};
pub use path::{FtpPath, PathError};
pub use session::{SessionEnd, serve};

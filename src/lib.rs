//! ThirtyFTP: a small FTP and FTPS server library for receive folders.
//!
//! It serves passive-mode FTP and explicit FTPS (`AUTH TLS`) with uploads, optional listing and downloads, and folder
//! creation. Active mode, deleting, renaming and implicit FTPS are not supported.
//!
//! The host accepts the TCP connections and calls [`serve`] for each one, with a [`Backend`] that knows its users and storage.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
// What a client sends is never a reason to panic: a line, a path, a number, an early close are a reply or a closed connection. The code that is not
// a test has no unwrap, expect, panic or unchecked index; the few indexes that are proved by the code around them say so
#![cfg_attr(
    not(test),
    deny(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing, clippy::unreachable, clippy::todo, clippy::unimplemented)
)]

mod active;
mod ascii;
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

#[cfg(test)]
mod properties;

/// Entry points for the fuzz targets in `fuzz/`: built only when fuzzing (`--cfg fuzzing`, which cargo-fuzz sets), and not part of the library
#[cfg(fuzzing)]
#[doc(hidden)]
pub mod fuzzing {
    use crate::codec::{Line, LineReader};
    use crate::path::FtpPath;

    /// Parses a command line; the verb of the command, when it is one
    pub fn parse_command(line: &str) -> Option<&'static str> {
        let parsed = crate::command::parse(line).ok().map(|command| command.verb());
        let _ = crate::active::parse_port(line);
        let _ = crate::active::parse_eprt(line);
        parsed
    }

    /// Reads the lines of a control connection that delivers `chunks`; the number of lines
    pub fn read_lines(chunks: &[&[u8]], max_line: usize) -> usize {
        let runtime = match tokio::runtime::Builder::new_current_thread().build() {
            Ok(runtime) => runtime,
            Err(_) => return 0,
        };
        runtime.block_on(async {
            let (mut client, mut server) = tokio::io::duplex(1 << 20);
            for chunk in chunks {
                if tokio::io::AsyncWriteExt::write_all(&mut client, chunk).await.is_err() {
                    break;
                }
            }
            drop(client);
            let mut reader = LineReader::new(max_line.clamp(1, 4096));
            let mut count = 0;
            while let Ok(Some(line)) = reader.next_line(&mut server).await {
                if let Line::Text(text) = &line {
                    let _ = crate::command::parse(text);
                }
                count += 1;
            }
            count
        })
    }

    /// Resolves a path against another; the result, when the paths are acceptable
    pub fn resolve_path(current: &str, requested: &str) -> Option<String> {
        let current = FtpPath::resolve(&FtpPath::root(), current).ok()?;
        FtpPath::resolve(&current, requested).ok().map(|path| path.to_string())
    }
}

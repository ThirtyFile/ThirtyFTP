//! The working directory and the facts of a path: `CWD`, `CDUP`, `MKD`, `SIZE`, `MDTM`, `MLST` (RFC 959 section 4.1.1 and 4.1.3, RFC 3659)

use super::{Outcome, Session, file_error_reply};
use crate::backend::{Backend, Entry, EntryKind, FsError};
use crate::listing;
use crate::path::FtpPath;
use crate::reply::{Reply, text};
use crate::time;
use std::io;
use std::sync::Arc;
use tracing::warn;

/// A path in the text of a reply: in double quotes, and a double quote in it doubled (RFC 959 appendix II)
pub(super) fn quoted(path: &FtpPath) -> String {
    format!("\"{}\"", path.to_string().replace('"', "\"\""))
}

impl<B: Backend> Session<B> {
    /// Resolves a path of the client. A path that can't be used is answered (553), and `None` returned
    pub(super) async fn resolve(&mut self, argument: &str) -> io::Result<Option<FtpPath>> {
        match FtpPath::resolve(&self.cwd, argument) {
            Ok(path) => Ok(Some(path)),
            Err(_) => {
                self.reply(553, text::NAME_NOT_ALLOWED).await?;
                Ok(None)
            }
        }
    }

    pub(super) async fn file_error(&mut self, error: FsError) -> Outcome {
        let reply: Reply = file_error_reply(&error);
        if let FsError::Local(message) = &error {
            warn!(%message, "storage error");
        }
        self.send_reply(reply).await
    }

    pub(super) async fn change_dir(&mut self, user: &Arc<B::User>, argument: &str) -> Outcome {
        let Some(path) = self.resolve(argument).await? else { return Ok(None) };
        match self.within(self.backend.change_dir(user, &path)).await {
            Ok(()) => {
                self.cwd = path;
                self.reply(250, text::FILE_ACTION_OK).await
            }
            Err(error) => self.file_error(error).await,
        }
    }

    pub(super) async fn make_dir(&mut self, user: &Arc<B::User>, argument: &str) -> Outcome {
        let Some(path) = self.resolve(argument).await? else { return Ok(None) };
        match self.within(self.backend.make_dir(user, &path)).await {
            Ok(()) => {
                let reply = format!("{} created.", quoted(&path));
                self.reply(257, &reply).await
            }
            Err(error) => self.file_error(error).await,
        }
    }

    pub(super) async fn size(&mut self, user: &Arc<B::User>, argument: &str) -> Outcome {
        let Some(path) = self.resolve(argument).await? else { return Ok(None) };
        match self.within(self.backend.metadata(user, &path)).await {
            Ok(entry) if entry.kind == EntryKind::File => self.reply(213, &entry.size.to_string()).await,
            Ok(_) => self.reply(550, "Not a plain file.").await,
            Err(error) => self.file_error(error).await,
        }
    }

    pub(super) async fn modification_time(&mut self, user: &Arc<B::User>, argument: &str) -> Outcome {
        let Some(path) = self.resolve(argument).await? else { return Ok(None) };
        match self.within(self.backend.metadata(user, &path)).await {
            Ok(Entry { modified: Some(modified), .. }) => self.reply(213, &time::mlsx(modified)).await,
            Ok(_) => self.reply(550, "Modification time is not available.").await,
            Err(error) => self.file_error(error).await,
        }
    }

    /// MLST (RFC 3659 section 7.2): the facts of one path, on the control connection
    pub(super) async fn mlst(&mut self, user: &Arc<B::User>, argument: Option<&str>) -> Outcome {
        let path = match argument {
            Some(argument) => match self.resolve(argument).await? {
                Some(path) => path,
                None => return Ok(None),
            },
            None => self.cwd.clone(),
        };
        match self.within(self.backend.metadata(user, &path)).await {
            Ok(entry) => {
                let lines = [format!("Listing {path}"), listing::mlst(&entry, &path.to_string(), self.facts), "End".to_string()];
                self.send_reply(Reply::multi(250, lines)).await
            }
            Err(error) => self.file_error(error).await,
        }
    }
}

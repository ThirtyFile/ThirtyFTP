//! What the server says about itself and the session: `FEAT`, `OPTS`, `HELP`, `STAT`, `TYPE` (RFC 959 section 4.1.3, RFC 2389)

use super::{Login, Outcome, Session};
use crate::backend::Backend;
use crate::command::{self, TypeArg};
use crate::listing::{self, Facts};
use crate::reply::{Reply, text};
use std::sync::Arc;
use std::time::SystemTime;

impl<B: Backend> Session<B> {
    /// The lines of FEAT (RFC 2389), for what is done
    fn features(&self) -> Vec<String> {
        let mut features = vec![
            "EPSV".to_string(),
            "MDTM".to_string(),
            format!("MLST {}", self.facts.names(true)),
            "PASV".to_string(),
            "REST STREAM".to_string(),
            "SIZE".to_string(),
            "UTF8".to_string(),
        ];
        if self.config.tls.is_some() {
            features.extend(["AUTH TLS".to_string(), "PBSZ".to_string(), "PROT".to_string()]);
        }
        features
    }

    pub(super) async fn feat(&mut self) -> Outcome {
        let mut lines = vec!["Extensions supported:".to_string()];
        lines.extend(self.features());
        lines.push("End".to_string());
        self.send_reply(Reply::multi(211, lines)).await
    }

    pub(super) async fn opts(&mut self, name: &str, value: Option<&str>) -> Outcome {
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

    pub(super) async fn help(&mut self, topic: Option<String>) -> Outcome {
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
    pub(super) async fn status(&mut self) -> Outcome {
        let user = match &self.login {
            Login::SignedIn { name, .. } => format!("Logged in as {name}"),
            _ => "Not logged in".to_string(),
        };
        let lines = [
            "FTP server status:".to_string(),
            format!("Connected from {}", self.peer.ip()),
            format!("Control connection is {}", if self.stream.is_encrypted() { "encrypted" } else { "not encrypted" }),
            format!("Data connections are {}", if self.data_private { "encrypted" } else { "not encrypted" }),
            user,
            format!("TYPE: {}, STRU: File, MODE: Stream", if self.ascii { "ASCII" } else { "BINARY" }),
            "End of status".to_string(),
        ];
        self.send_reply(Reply::multi(211, lines)).await
    }

    /// STAT with a path (RFC 959 section 4.1.3): the listing of LIST, on the control connection. `212` for a directory, `213` for a file
    pub(super) async fn stat_path(&mut self, user: &Arc<B::User>, argument: &str) -> Outcome {
        let Some(path) = self.resolve(argument).await? else { return Ok(None) };
        match self.entries(user, &path, super::data::ListKind::List).await {
            Ok((entries, is_directory)) => {
                let listing = listing::list(&entries, SystemTime::now());
                let mut lines = vec![format!("Status of {path}:")];
                lines.extend(listing.lines().map(str::to_string));
                lines.push("End of status".to_string());
                self.send_reply(Reply::multi(if is_directory { 212 } else { 213 }, lines)).await
            }
            Err(error) => self.file_error(error).await,
        }
    }

    pub(super) async fn data_type(&mut self, argument: TypeArg) -> Outcome {
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
}

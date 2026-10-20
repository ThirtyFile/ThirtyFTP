//! Signing in and the protection of the connections: `USER`, `PASS`, `AUTH TLS`, `PBSZ`, `PROT` (RFC 959 section 4.1.1, RFC 4217)

use super::{Login, Outcome, Session, SessionEnd};
use crate::backend::{Backend, LoginContext, LoginError};
use crate::reply::{Reply, text};
use std::sync::Arc;
use tracing::{debug, info};

impl<B: Backend> Session<B> {
    pub(super) async fn user_command(&mut self, name: String) -> Outcome {
        if self.signed_in() {
            return self.reply(503, "Already logged in.").await;
        }
        if self.config.require_tls && !self.stream.is_encrypted() {
            return self.reply(530, "Login needs an encrypted connection. Use AUTH TLS.").await;
        }
        // The name goes to the backend, the log and the host's events: no control characters in it
        if name.chars().any(char::is_control) {
            return self.reply(501, "Invalid user name.").await;
        }
        self.login = Login::UserGiven(name);
        self.reply(331, text::NEED_PASSWORD).await
    }

    pub(super) async fn pass(&mut self, password: String) -> Outcome {
        let name = match std::mem::replace(&mut self.login, Login::New) {
            Login::UserGiven(name) => name,
            signed_in @ Login::SignedIn { .. } => {
                self.login = signed_in;
                return self.reply(503, "Already logged in.").await;
            }
            Login::New => return self.reply(503, text::BAD_SEQUENCE).await,
        };
        let context = LoginContext::new(self.peer, self.local, self.stream.is_encrypted());
        let attempt = tokio::time::timeout(self.config.limits.backend_timeout, self.backend.login(&context, &name, &password)).await;
        match attempt.unwrap_or(Err(LoginError::Unavailable)) {
            Ok(user) => {
                info!(user = %name, "signed in");
                self.span.record("user", name.as_str());
                self.events.signed_in(self.peer, &name);
                self.login = Login::SignedIn { name, user: Arc::new(user) };
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

    /// AUTH TLS (RFC 4217 section 4): the TLS handshake starts right after the reply, on the same connection
    pub(super) async fn auth(&mut self, mechanism: &str) -> Outcome {
        let Some(tls) = self.config.tls.clone() else { return self.reply(502, "TLS is not available.").await };
        if self.signed_in() || self.stream.is_encrypted() {
            return self.reply(503, "TLS can't be started now.").await;
        }
        if !matches!(mechanism.to_ascii_uppercase().as_str(), "TLS" | "TLS-C") {
            return self.reply(504, text::NOT_IMPLEMENTED_PARAMETER).await;
        }
        self.reply(234, "AUTH TLS successful.").await?;
        // Whatever the client sent after AUTH TLS was sent before it saw the 234, in plain text: it is never read, and never answered. The sign-in
        // that began before is forgotten (RFC 4217 section 4); PBSZ and PROT are still at their start, as they need TLS
        self.lines.discard_buffered();
        self.login = Login::New;
        match self.stream.accept_tls(tls, self.config.limits.tls_handshake_timeout).await {
            Ok(()) => {
                debug!("control connection is encrypted");
                Ok(None)
            }
            Err(error) => {
                debug!(%error, "TLS handshake on the control connection failed");
                Ok(Some(SessionEnd::TlsHandshakeFailed))
            }
        }
    }

    /// PBSZ (RFC 4217 section 8): TLS has no protection buffer, so the size is 0
    pub(super) async fn protection_buffer(&mut self) -> Outcome {
        if !self.stream.is_encrypted() {
            return self.reply(503, "PBSZ needs AUTH TLS first.").await;
        }
        self.pbsz = true;
        self.reply(200, "PBSZ=0").await
    }

    /// PROT (RFC 4217 section 9): whether the data connections are protected
    pub(super) async fn protection(&mut self, level: &str) -> Outcome {
        if !self.stream.is_encrypted() || !self.pbsz {
            return self.reply(503, "PROT needs AUTH TLS and PBSZ first.").await;
        }
        match level.to_ascii_uppercase().as_str() {
            "P" => {
                self.data_private = true;
                self.reply(200, "PROT now Private.").await
            }
            "C" => {
                self.data_private = false;
                self.reply(200, "PROT now Clear.").await
            }
            "S" | "E" => self.reply(536, "Requested PROT level not supported by mechanism.").await,
            _ => self.reply(504, text::NOT_IMPLEMENTED_PARAMETER).await,
        }
    }

    /// The policy for data connections: a host that requires TLS has them encrypted. It is checked whenever a data connection is about to be used, not
    /// only when it is announced: the level can change in between, and `PROT C` after `PASV` must not give a transfer in plain text
    pub(super) fn data_policy(&self) -> Option<Reply> {
        (self.config.require_tls && !self.data_private).then(|| Reply::new(534, "Data connections must be encrypted. Use PROT P."))
    }
}

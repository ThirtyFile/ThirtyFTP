//! What the host is told about a session, for its own activity log and deadlines.

use std::net::SocketAddr;

/// Notifications from a session. Every method does nothing by default, so a host implements the ones it needs. They are called from the session's
/// task and have to return at once.
pub trait Events: Send + Sync {
    /// The client signed in. The host can end its deadline for signing in
    fn signed_in(&self, _peer: SocketAddr, _user: &str) {}

    /// A sign-in failed (wrong name or password, or refused)
    fn login_failed(&self, _peer: SocketAddr, _user: &str) {}
}

/// Events that are ignored
#[derive(Debug, Clone, Copy, Default)]
pub struct NoEvents;

impl Events for NoEvents {}

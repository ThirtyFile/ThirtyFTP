//! Settings of a session.

use std::time::Duration;

/// Settings of a session. Make one with `Config::default()` and set the fields to change.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Config {
    /// The text of the `220` reply that opens the connection
    pub greeting: String,
    /// How long a connection may wait for a command before it is closed. The connection is closed without a reply (RFC 1123 section 4.1.2.11 allows
    /// no reply that isn't an answer to a command). RFC 1123 section 4.1.3.2 asks for a default of at least 5 minutes: 300 seconds
    pub idle_timeout: Duration,
    /// Whether signing in needs an encrypted control connection. With `true` and no `AUTH TLS` done, `USER` is answered with `530`
    pub require_tls: bool,
    /// Limits against clients that send too much
    pub limits: Limits,
}

/// Limits of a session
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Limits {
    /// The longest command line, in bytes, without its line end. A longer line is answered with `500` and dropped. Default 4096: a path of 255
    /// characters in a script that uses three bytes for each still fits
    pub max_line: usize,
    /// How many wrong sign-ins a connection may try before it is closed with `421`. Default 3
    pub max_login_attempts: u32,
}

impl Default for Config {
    fn default() -> Config {
        Config { greeting: crate::reply::text::READY.to_string(), idle_timeout: Duration::from_secs(300), require_tls: false, limits: Limits::default() }
    }
}

impl Default for Limits {
    fn default() -> Limits {
        Limits { max_line: 4096, max_login_attempts: 3 }
    }
}

//! Settings of a session.

use std::net::Ipv4Addr;
use std::ops::RangeInclusive;
use std::sync::Arc;
use std::time::Duration;

/// Settings of a session. Make one with `Config::default()` and set the fields to change.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Config {
    /// The text of the `220` reply that opens the connection
    pub greeting: String,
    /// How long a connection may wait for a command before it is closed. The connection is closed without a reply (RFC 1123 section 4.1.2.11 allows
    /// no reply that isn't an answer to a command). RFC 1123 section 4.1.3.2 asks for a default of at least 5 minutes: 300 seconds. The time doesn't
    /// run while a transfer does
    pub idle_timeout: Duration,
    /// The TLS settings for explicit FTPS (RFC 4217): `AUTH TLS` upgrades the control connection, and `PROT P` protects the data connections. The
    /// host makes it (certificate, protocols, session resumption); without it `AUTH` is answered with `502`. The library uses it for the control
    /// connection as it is, and for data connections without TLS 1.3 session tickets
    pub tls: Option<Arc<rustls::ServerConfig>>,
    /// Whether the connection must be encrypted. With `true`, `USER` is answered with `530` until `AUTH TLS` is done, and `PASV`, `EPSV` and every
    /// transfer with `534` until `PROT P` is. A host that allows plain FTP on a private network sets it to `false` for those connections. It
    /// needs `tls`: without it nobody can sign in
    pub require_tls: bool,
    /// The ports a passive data connection may listen on. A session takes one at random and gives it back when it is done with it. The range
    /// `0..=0` lets the operating system choose. Default 49152 to 65535
    pub passive_ports: RangeInclusive<u16>,
    /// The address `PASV` tells the client to connect to
    pub passive_host: PassiveHost,
    /// Whether the line ends of a transfer with `TYPE A` are converted: CRLF to LF in an upload, LF to CRLF in a download. Off by default: the bytes of
    /// an ASCII transfer are not changed, as in vsftpd, so a file sent by a client that forgot `TYPE I` arrives whole. `SIZE` is the size of the stored
    /// file, whatever the type
    pub ascii_conversion: bool,
    /// Whether `PORT` and `EPRT` are done: the server then connects to the client for the data connection. Off by default: a client behind NAT or a
    /// firewall can't use it, and it asks the server to open connections. When on, the server connects only to the address the control connection
    /// comes from and only to ports from 1024 up (RFC 2577 section 3), and the TLS policy of the data connections applies as it does to passive mode
    pub active_mode: bool,
    /// Limits against clients that send too much or too little
    pub limits: Limits,
}

/// The address a client is told to connect its passive data connection to. `EPSV` tells no address: the client uses the one of the control connection
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum PassiveHost {
    /// The address the client connected the control connection to. This is right when the client reaches the server directly
    #[default]
    FromConnection,
    /// This IPv4 address: for a server behind NAT, the address of the router
    Ip(Ipv4Addr),
    /// The IPv4 address of this name: for a server behind NAT with a name that follows a changing address. The answer is kept for 30 seconds
    /// (a failed lookup for 5), so a stalled resolver can't tie up a thread for every `PASV`
    Dns(String),
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
    /// How long a connection has to sign in, from the moment it is opened. Commands that need no sign-in (`NOOP`, `FEAT`) don't extend it. The
    /// connection is closed without a reply. Default 60 seconds. A host that has a deadline of its own can set it longer
    pub login_timeout: Duration,
    /// How long a call of the [`Backend`](crate::Backend) (not the upload itself) may take. After it the client gets `450`, or `421` for a sign-in.
    /// Default 60 seconds
    pub backend_timeout: Duration,
    /// The most entries a listing may have. A longer one is refused with `451`: the listing is built in memory. Default 100,000
    pub max_list_entries: usize,
    /// How long a transfer waits for the client to connect to the passive port. Default 30 seconds
    pub data_accept_timeout: Duration,
    /// How long a TLS handshake may take, on the control connection and on a data connection. Default 30 seconds
    pub tls_handshake_timeout: Duration,
    /// How long a transfer may stand still, with no byte moved, before it is aborted. Default 60 seconds. It is also how long a session that is told
    /// to end (`QUIT`, or a closed control connection) waits for the transfer that runs
    pub transfer_idle_timeout: Duration,
    /// The longest a transfer may take in all, whatever it moves: a client that sends a byte every 59 seconds is not standing still. `None`, the
    /// default, sets no limit
    pub max_transfer_time: Option<Duration>,
    /// How long the server waits for the client's `close_notify` after the last byte of a download over TLS, before it closes the connection. Closing
    /// at once could reset the connection and take the end of the data from the client. Default 3 seconds
    pub tls_close_wait: Duration,
}

impl Default for Config {
    fn default() -> Config {
        Config {
            greeting: crate::reply::text::READY.to_string(),
            idle_timeout: Duration::from_secs(300),
            tls: None,
            require_tls: false,
            passive_ports: 49152..=65535,
            passive_host: PassiveHost::default(),
            ascii_conversion: false,
            active_mode: false,
            limits: Limits::default(),
        }
    }
}

impl Default for Limits {
    fn default() -> Limits {
        Limits {
            max_line: 4096,
            max_login_attempts: 3,
            login_timeout: Duration::from_secs(60),
            backend_timeout: Duration::from_secs(60),
            max_list_entries: 100_000,
            data_accept_timeout: Duration::from_secs(30),
            tls_handshake_timeout: Duration::from_secs(30),
            transfer_idle_timeout: Duration::from_secs(60),
            max_transfer_time: None,
            tls_close_wait: Duration::from_secs(3),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_defaults_follow_rfc_1123() {
        let config = Config::default();
        // Section 4.1.3.2: the idle time is configurable and by default at least 5 minutes
        assert!(config.idle_timeout >= Duration::from_secs(300));
        // Active mode is off, TLS is not required without settings for it, and the bytes of an ASCII transfer are not changed
        assert!(!config.active_mode && !config.require_tls && !config.ascii_conversion && config.tls.is_none());
        assert_eq!(config.passive_ports, 49152..=65535);
        assert_eq!(config.passive_host, PassiveHost::FromConnection);
    }
}

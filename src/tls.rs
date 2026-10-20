//! A connection that is plain TCP, or TLS on TCP (RFC 4217: explicit FTPS)
//!
//! The control connection starts plain and becomes TLS after `AUTH TLS`. A data connection is plain, or TLS when the protection level is `P`.

use rustls::ServerConfig;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::server::TlsStream;

pub(crate) enum Stream {
    Plain(TcpStream),
    Tls(Box<TlsStream<TcpStream>>),
    /// The connection is being upgraded, or the upgrade failed: nothing can be read or written
    Taken,
}

impl Stream {
    pub(crate) fn is_encrypted(&self) -> bool {
        matches!(self, Stream::Tls(_))
    }

    /// Does the server side of the TLS handshake on a plain connection. On failure the connection is gone (`Taken`)
    pub(crate) async fn accept_tls(&mut self, config: Arc<ServerConfig>, handshake_timeout: Duration) -> io::Result<()> {
        let Stream::Plain(tcp) = std::mem::replace(self, Stream::Taken) else {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "the connection is not plain"));
        };
        let tls = timeout(handshake_timeout, TlsAcceptor::from(config).accept(tcp)).await.map_err(|_| io::Error::from(io::ErrorKind::TimedOut))??;
        *self = Stream::Tls(Box::new(tls));
        Ok(())
    }
}

fn gone() -> io::Error {
    io::Error::from(io::ErrorKind::NotConnected)
}

impl AsyncRead for Stream {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Stream::Plain(stream) => Pin::new(stream).poll_read(cx, buf),
            Stream::Tls(stream) => Pin::new(&mut **stream).poll_read(cx, buf),
            Stream::Taken => Poll::Ready(Err(gone())),
        }
    }
}

impl AsyncWrite for Stream {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Stream::Plain(stream) => Pin::new(stream).poll_write(cx, buf),
            Stream::Tls(stream) => Pin::new(&mut **stream).poll_write(cx, buf),
            Stream::Taken => Poll::Ready(Err(gone())),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Stream::Plain(stream) => Pin::new(stream).poll_flush(cx),
            Stream::Tls(stream) => Pin::new(&mut **stream).poll_flush(cx),
            Stream::Taken => Poll::Ready(Err(gone())),
        }
    }

    /// For TLS this sends `close_notify`, and then closes the sending side of the TCP connection
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Stream::Plain(stream) => Pin::new(stream).poll_shutdown(cx),
            Stream::Tls(stream) => Pin::new(&mut **stream).poll_shutdown(cx),
            Stream::Taken => Poll::Ready(Err(gone())),
        }
    }
}

/// The TLS settings of data connections: the same as the control connection's, and no TLS 1.3 session tickets. A client resumes the session of the
/// control connection; tickets sent on every data connection are no use, and an upload that has finished has no time to read them
pub(crate) fn for_data(config: &Arc<ServerConfig>) -> Arc<ServerConfig> {
    let mut data = (**config).clone();
    data.send_tls13_tickets = 0;
    Arc::new(data)
}

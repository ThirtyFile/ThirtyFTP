//! A transfer on the data connection: the task that accepts the connection and moves the bytes (RFC 959 section 3.3 and 3.4 stream mode, RFC 1123
//! section 4.1.2.12).
//!
//! A transfer runs in its own task, so the session goes on reading the control connection while it runs (ABOR and STAT at any time, RFC 1123
//! section 4.1.3.3). The task never writes to the control connection: it tells the session with [`Event`]s, and the session sends the replies.
//! Aborting the task drops everything it holds, including the backend's `write`, which is how an upload that did not complete is discarded.

use crate::active;
use crate::ascii::{Converting, Direction};
use crate::backend::{Backend, FsError};
use crate::passive;
use crate::path::FtpPath;
use crate::tls::Stream;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio::time::{Instant, Sleep, timeout};
use tracing::debug;

/// What a transfer tells the session
#[derive(Debug)]
pub(crate) enum Event {
    /// The data connection is open: `150`
    Started,
    /// The transfer is over, with the number of bytes moved, or why it failed: the final reply
    Done(Result<u64, Failure>),
}

/// Why a transfer failed
#[derive(Debug)]
pub(crate) enum Failure {
    /// The client did not connect to the passive port in time: `425`
    NoConnection,
    /// The TLS handshake on the data connection failed: `425`. Nothing was transferred, and nothing is stored
    Tls,
    /// The data connection failed or stood still, or the session went: `426`
    Aborted,
    /// The storage failed: the reply for it
    Storage(FsError),
}

/// What a transfer moves
pub(crate) enum Work {
    /// STOR: what the client sends goes to this path
    Upload(FtpPath),
    /// RETR: the client receives what this delivers
    Download(Box<dyn AsyncRead + Send + Unpin>),
    /// LIST, NLST, MLSD: the client receives this text
    Listing(Vec<u8>),
}

/// Where the data connection comes from: the client connects to a port of ours (PASV, EPSV), or we connect to the client (PORT, EPRT)
pub(crate) enum DataPort {
    Passive(TcpListener),
    Active(SocketAddr),
}

/// What a transfer needs
pub(crate) struct Job<B: Backend> {
    pub(crate) backend: Arc<B>,
    pub(crate) user: Arc<B::User>,
    pub(crate) port: DataPort,
    /// The address of the client: a data connection from another address is closed
    pub(crate) client: IpAddr,
    /// The address of the server the control connection came to: an active connection starts from it
    pub(crate) local: IpAddr,
    pub(crate) accept_timeout: Duration,
    pub(crate) idle_timeout: Duration,
    /// The TLS settings of the data connection when its protection level is `P`
    pub(crate) tls: Option<Arc<rustls::ServerConfig>>,
    pub(crate) handshake_timeout: Duration,
    /// Convert the line ends (`TYPE A` with the conversion on)
    pub(crate) ascii: bool,
    /// The bytes moved so far, for STAT
    pub(crate) progress: Arc<AtomicU64>,
    pub(crate) events: mpsc::Sender<Event>,
}

/// Runs a transfer to its end and tells the session how it ended
pub(crate) async fn run<B: Backend>(job: Job<B>, work: Work) {
    let events = job.events.clone();
    let result = transfer(job, work).await;
    let _ = events.send(Event::Done(result)).await;
}

async fn transfer<B: Backend>(job: Job<B>, work: Work) -> Result<u64, Failure> {
    let deadline = Instant::now() + job.accept_timeout;
    let tcp = match job.port {
        DataPort::Passive(listener) => match passive::accept_from(&listener, job.client, deadline).await {
            // One data connection for one transfer: the port is not needed any more
            Ok(stream) => stream,
            Err(_) => return Err(Failure::NoConnection),
        },
        DataPort::Active(address) => match active::connect(job.local, address, deadline).await {
            Ok(stream) => stream,
            Err(error) => {
                debug!(%error, %address, "no active data connection");
                return Err(Failure::NoConnection);
            }
        },
    };
    if job.events.send(Event::Started).await.is_err() {
        return Err(Failure::Aborted);
    }
    let mut stream = Stream::Plain(tcp);
    // The handshake comes after the 150: a client may wait for it, and one that does not just has its handshake answered a moment later. A handshake
    // that fails ends the transfer here, before the backend is asked for anything
    if let Some(config) = job.tls
        && let Err(error) = stream.accept_tls(config, job.handshake_timeout).await
    {
        debug!(%error, "TLS handshake on the data connection failed");
        return Err(Failure::Tls);
    }
    match work {
        Work::Upload(path) => upload(&*job.backend, &*job.user, &path, stream, job.idle_timeout, job.progress, job.ascii).await,
        Work::Download(reader) if job.ascii => send(Converting::new(reader, Direction::ToNetwork), stream, job.idle_timeout, job.progress).await,
        Work::Download(reader) => send(reader, stream, job.idle_timeout, job.progress).await,
        Work::Listing(text) => send(std::io::Cursor::new(text), stream, job.idle_timeout, job.progress).await,
    }
}

/// The client sends a file: the backend stores what the data connection delivers until its end
///
/// Over TLS the end of the data is the client's `close_notify`. A connection that ends without it was cut short, and the upload is not complete
/// (RFC 8446 section 6.1): the read fails, and `226` is never sent for it
async fn upload<B: Backend>(
    backend: &B,
    user: &B::User,
    path: &FtpPath,
    stream: Stream,
    idle: Duration,
    progress: Arc<AtomicU64>,
    ascii: bool,
) -> Result<u64, Failure> {
    let failed = Arc::new(AtomicBool::new(false));
    let close_on_eof = stream.is_encrypted();
    let mut reader = IdleRead { inner: stream, idle, sleep: Box::pin(tokio::time::sleep(idle)), progress, failed: failed.clone(), close_on_eof, closed: false };
    let stored = if ascii {
        let mut converting = Converting::new(&mut reader, Direction::FromNetwork);
        backend.write(user, path, &mut converting).await
    } else {
        backend.write(user, path, &mut reader).await
    };
    // A connection that failed or stood still is an upload that did not complete, whatever the backend made of it
    if failed.load(Ordering::Relaxed) {
        return Err(Failure::Aborted);
    }
    stored.map_err(Failure::Storage)
}

/// The client receives what `reader` delivers
async fn send<R: AsyncRead + Unpin>(mut reader: R, mut stream: Stream, idle: Duration, progress: Arc<AtomicU64>) -> Result<u64, Failure> {
    let mut buffer = vec![0u8; 64 * 1024];
    let mut total = 0u64;
    loop {
        let read = reader.read(&mut buffer).await.map_err(|error| Failure::Storage(FsError::Local(error.to_string())))?;
        if read == 0 {
            break;
        }
        match timeout(idle, stream.write_all(&buffer[..read])).await {
            Ok(Ok(())) => {}
            _ => return Err(Failure::Aborted),
        }
        total += read as u64;
        progress.store(total, Ordering::Relaxed);
    }
    // The end of the data: over TLS a close_notify, then the end of the TCP connection
    match timeout(idle, stream.shutdown()).await {
        Ok(Ok(())) => {}
        _ => return Err(Failure::Aborted),
    }
    if stream.is_encrypted() {
        // Closing now, with the client's close_notify not read yet, would reset the connection and could take the end of the data from the client
        let _ = timeout(Duration::from_secs(3), tokio::io::copy(&mut stream, &mut tokio::io::sink())).await;
    }
    Ok(total)
}

/// Reads from the data connection, and fails when nothing arrives for `idle`, and says so. The time is for the wait for data, not for the whole
/// transfer: a transfer that moves goes on as long as it needs.
struct IdleRead<R> {
    inner: R,
    idle: Duration,
    sleep: Pin<Box<Sleep>>,
    progress: Arc<AtomicU64>,
    /// Set when the read failed or timed out. A clean end of the data is not a failure
    failed: Arc<AtomicBool>,
    /// Answer the end of the data with the end of ours (TLS: our `close_notify`) before the reader tells it to its caller
    close_on_eof: bool,
    closed: bool,
}

impl<R: AsyncRead + AsyncWrite + Unpin> AsyncRead for IdleRead<R> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        let before = buf.filled().len();
        match Pin::new(&mut this.inner).poll_read(cx, buf) {
            Poll::Ready(Ok(())) => {
                let read = buf.filled().len() - before;
                if read > 0 {
                    this.progress.fetch_add(read as u64, Ordering::Relaxed);
                    let next = Instant::now() + this.idle;
                    this.sleep.as_mut().reset(next);
                } else if this.close_on_eof && !this.closed {
                    // The client has ended its data: our close_notify goes to it now, before the backend is told that the upload is over and spends
                    // its time on the file. The client may be waiting for it to finish. An error here is the client having gone: the data is complete
                    if Pin::new(&mut this.inner).poll_shutdown(cx).is_pending() {
                        return Poll::Pending;
                    }
                    this.closed = true;
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(error)) => {
                this.failed.store(true, Ordering::Relaxed);
                Poll::Ready(Err(error))
            }
            Poll::Pending => match this.sleep.as_mut().poll(cx) {
                Poll::Ready(()) => {
                    this.failed.store(true, Ordering::Relaxed);
                    Poll::Ready(Err(io::ErrorKind::TimedOut.into()))
                }
                Poll::Pending => Poll::Pending,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    #[tokio::test]
    async fn idle_read_passes_data_counts_it_and_ends_cleanly() {
        let (mut client, server) = tokio::io::duplex(1024);
        let progress = Arc::new(AtomicU64::new(0));
        let failed = Arc::new(AtomicBool::new(false));
        let mut reader = IdleRead {
            inner: server,
            idle: Duration::from_secs(5),
            sleep: Box::pin(tokio::time::sleep(Duration::from_secs(5))),
            progress: progress.clone(),
            failed: failed.clone(),
            close_on_eof: false,
            closed: false,
        };
        client.write_all(b"hello").await.unwrap();
        drop(client);
        let mut text = String::new();
        reader.read_to_string(&mut text).await.unwrap();
        assert_eq!(text, "hello");
        assert_eq!(progress.load(Ordering::Relaxed), 5);
        assert!(!failed.load(Ordering::Relaxed), "a clean end is not a failure");
    }

    #[tokio::test(start_paused = true)]
    async fn idle_read_times_out_when_nothing_arrives_and_not_while_data_moves() {
        let (mut client, server) = tokio::io::duplex(1024);
        let failed = Arc::new(AtomicBool::new(false));
        let idle = Duration::from_secs(10);
        let mut reader = IdleRead {
            inner: server,
            idle,
            sleep: Box::pin(tokio::time::sleep(idle)),
            progress: Arc::new(AtomicU64::new(0)),
            failed: failed.clone(),
            close_on_eof: false,
            closed: false,
        };
        // Data every 6 s for a minute: more than the idle time in all, never the idle time in a row
        for _ in 0..10 {
            tokio::time::sleep(Duration::from_secs(6)).await;
            client.write_all(b"x").await.unwrap();
            let mut byte = [0u8; 1];
            reader.read_exact(&mut byte).await.unwrap();
        }
        assert!(!failed.load(Ordering::Relaxed));
        let mut byte = [0u8; 1];
        let error = reader.read_exact(&mut byte).await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(failed.load(Ordering::Relaxed));
    }

    #[tokio::test]
    async fn idle_read_answers_the_end_of_the_data_with_the_end_of_its_own_before_it_reports_it() {
        let (mut client, server) = tokio::io::duplex(1024);
        let idle = Duration::from_secs(5);
        let mut reader = IdleRead {
            inner: server,
            idle,
            sleep: Box::pin(tokio::time::sleep(idle)),
            progress: Arc::new(AtomicU64::new(0)),
            failed: Arc::new(AtomicBool::new(false)),
            close_on_eof: true,
            closed: false,
        };
        client.write_all(b"data").await.unwrap();
        client.shutdown().await.unwrap();
        let mut bytes = Vec::new();
        reader.read_to_end(&mut bytes).await.unwrap();
        assert_eq!(bytes, b"data");
        // Our side is ended too: the client reads its end of the data
        let mut rest = Vec::new();
        tokio::time::timeout(Duration::from_secs(2), client.read_to_end(&mut rest)).await.expect("the end was not sent").unwrap();
        assert!(rest.is_empty());
    }
}

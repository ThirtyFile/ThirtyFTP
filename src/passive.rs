//! Passive mode (RFC 959 section 4.1.2 PASV, RFC 2428 EPSV, RFC 2577 section 3): the listener a client connects its data connection to.
//!
//! A session has at most one listener, and a data connection is accepted from the client's own address only.

use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, Hasher};
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::ops::RangeInclusive;
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{Instant, timeout_at};

/// An address with an IPv4-mapped IPv6 address (`::ffff:1.2.3.4`) as the IPv4 address, so two forms of one address compare equal
pub(crate) fn canonical(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
        v4 => v4,
    }
}

/// A random number, without a crate for it: the standard library seeds its hash maps from the operating system
fn random() -> u64 {
    RandomState::new().build_hasher().finish()
}

/// Listens on a port of the range, on the address the control connection came to. The first port tried is a random one, so sessions don't all
/// go for the same. The range `0..=0` lets the operating system choose.
pub(crate) async fn bind(ip: IpAddr, ports: &RangeInclusive<u16>) -> io::Result<TcpListener> {
    let (first, last) = (*ports.start(), *ports.end());
    if first > last {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "the passive port range is empty"));
    }
    let count = u32::from(last - first) + 1;
    let start = (random() % u64::from(count)) as u32;
    let mut last_error = io::Error::from(io::ErrorKind::AddrInUse);
    for step in 0..count {
        let port = first + ((start + step) % count) as u16;
        match TcpListener::bind(SocketAddr::new(ip, port)).await {
            Ok(listener) => return Ok(listener),
            Err(error) if error.kind() == io::ErrorKind::AddrInUse || error.kind() == io::ErrorKind::PermissionDenied => last_error = error,
            Err(error) => return Err(error),
        }
    }
    Err(last_error)
}

/// Accepts the data connection of the client, until `deadline`.
///
/// A connection from another address is closed at once and the listener keeps waiting for the client: a stray connection can't use up the port, and
/// can't be the data connection of someone else (RFC 2577 section 3, the "port stealing" attack).
pub(crate) async fn accept_from(listener: &TcpListener, client: IpAddr, deadline: Instant) -> io::Result<TcpStream> {
    let client = canonical(client);
    loop {
        let (stream, address) = match timeout_at(deadline, listener.accept()).await {
            Err(_) => return Err(io::ErrorKind::TimedOut.into()),
            Ok(accepted) => accepted?,
        };
        if canonical(address.ip()) == client {
            return Ok(stream);
        }
        tracing::warn!(%address, "a data connection from another address was closed");
        drop(stream);
    }
}

/// The text of the `227` reply: `Entering Passive Mode (h1,h2,h3,h4,p1,p2).`
pub(crate) fn pasv_text(ip: Ipv4Addr, port: u16) -> String {
    let [a, b, c, d] = ip.octets();
    format!("Entering Passive Mode ({a},{b},{c},{d},{},{}).", port >> 8, port & 0xff)
}

/// The text of the `229` reply: `Entering Extended Passive Mode (|||port|).`
pub(crate) fn epsv_text(port: u16) -> String {
    format!("Entering Extended Passive Mode (|||{port}|).")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    const LOOPBACK: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

    #[test]
    fn canonical_makes_the_two_forms_of_an_address_equal() {
        let mapped: IpAddr = "::ffff:192.168.1.5".parse().unwrap();
        assert_eq!(canonical(mapped), "192.168.1.5".parse::<IpAddr>().unwrap());
        let v6: IpAddr = "2001:db8::1".parse().unwrap();
        assert_eq!(canonical(v6), v6);
    }

    #[test]
    fn reply_texts() {
        assert_eq!(pasv_text(Ipv4Addr::new(192, 168, 1, 5), 49_152 + 258), "Entering Passive Mode (192,168,1,5,193,2).");
        assert_eq!(epsv_text(50_000), "Entering Extended Passive Mode (|||50000|).");
    }

    #[tokio::test]
    async fn bind_takes_a_port_of_the_range() {
        let listener = bind(LOOPBACK, &(41_000..=41_009)).await.unwrap();
        assert!((41_000..=41_009).contains(&listener.local_addr().unwrap().port()));
    }

    #[tokio::test]
    async fn bind_skips_the_ports_in_use_and_fails_when_all_are() {
        let first = bind(LOOPBACK, &(41_020..=41_021)).await.unwrap();
        let second = bind(LOOPBACK, &(41_020..=41_021)).await.unwrap();
        assert_ne!(first.local_addr().unwrap().port(), second.local_addr().unwrap().port());
        assert!(bind(LOOPBACK, &(41_020..=41_021)).await.is_err());
        // A port is free again as soon as its listener is dropped
        let port = first.local_addr().unwrap().port();
        drop(first);
        assert_eq!(bind(LOOPBACK, &(41_020..=41_021)).await.unwrap().local_addr().unwrap().port(), port);
    }

    #[tokio::test]
    async fn bind_with_zero_lets_the_system_choose_and_an_empty_range_is_an_error() {
        assert_ne!(bind(LOOPBACK, &(0..=0)).await.unwrap().local_addr().unwrap().port(), 0);
        #[allow(clippy::reversed_empty_ranges)]
        let empty = 5..=4;
        assert!(bind(LOOPBACK, &empty).await.is_err());
    }

    #[tokio::test]
    async fn accept_from_closes_a_stranger_and_keeps_waiting_for_the_client() {
        let listener = bind(LOOPBACK, &(0..=0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        // 127.0.0.2 is not the client (127.0.0.1)
        let stranger = tokio::net::TcpSocket::new_v4().unwrap();
        stranger.bind("127.0.0.2:0".parse().unwrap()).unwrap();
        let mut stranger = stranger.connect(address).await.unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        let accepting = tokio::spawn(async move { accept_from(&listener, LOOPBACK, deadline).await });
        // The stranger is closed
        let mut byte = [0u8; 1];
        let read = tokio::time::timeout(Duration::from_secs(5), tokio::io::AsyncReadExt::read(&mut stranger, &mut byte)).await.unwrap();
        assert!(matches!(read, Ok(0) | Err(_)));
        assert!(!accepting.is_finished(), "the port keeps waiting");
        // And the client is accepted afterwards
        let client = TcpStream::connect(address).await.unwrap();
        let accepted = accepting.await.unwrap().unwrap();
        assert_eq!(accepted.peer_addr().unwrap(), client.local_addr().unwrap());
    }

    #[tokio::test]
    async fn accept_from_times_out() {
        let listener = bind(LOOPBACK, &(0..=0)).await.unwrap();
        let error = accept_from(&listener, LOOPBACK, Instant::now() + Duration::from_millis(100)).await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    }
}

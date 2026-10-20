//! Passive mode (RFC 959 section 4.1.2 PASV, RFC 2428 EPSV, RFC 2577 section 3): the listener a client connects its data connection to.
//!
//! A session has at most one listener, and a data connection is accepted from the client's own address only.

use std::collections::HashMap;
use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, Hasher};
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::ops::RangeInclusive;
use std::sync::{Mutex, OnceLock};
use std::time::Duration;
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

/// How many ports `bind` tries at most: with a range of thousands of ports that are nearly all in use, a failure should be quick (a reply of `425`), not
/// a hundred milliseconds of system calls on the thread of the runtime
const MAX_TRIES: u32 = 256;

/// A random number, without a crate for it: the standard library seeds its hash maps from the operating system
fn random() -> u64 {
    RandomState::new().build_hasher().finish()
}

/// Listens on a port of the range, on the address the control connection came to. The first port tried is a random one, so sessions don't all
/// go for the same. A small range is tried port by port; of a large one, 256 random ports are tried at most. The range `0..=0` lets the operating
/// system choose.
pub(crate) async fn bind(ip: IpAddr, ports: &RangeInclusive<u16>) -> io::Result<TcpListener> {
    let (first, last) = (*ports.start(), *ports.end());
    if first > last {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "the passive port range is empty"));
    }
    let count = u32::from(last - first) + 1;
    let start = (random() % u64::from(count)) as u32;
    let mut last_error = io::Error::from(io::ErrorKind::AddrInUse);
    for step in 0..count.min(MAX_TRIES) {
        // Every port of a small range once; random ports of a large one
        let offset = if count <= MAX_TRIES { (start + step) % count } else { (random() % u64::from(count)) as u32 };
        let port = first + offset as u16;
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

/// How long an answer of the resolver is kept, and a failure
const DNS_KEEP: Duration = Duration::from_secs(30);
const DNS_KEEP_FAILURE: Duration = Duration::from_secs(5);

type DnsCache = Mutex<HashMap<String, (std::time::Instant, Option<Ipv4Addr>)>>;

/// The IPv4 address of a name, for `PASV` behind NAT. The answer is kept: a resolver that stalls would otherwise tie up a thread of the blocking pool for
/// every `PASV` of every session. When a new lookup fails, the last answer that worked is still used
pub(crate) async fn resolve_ipv4(name: &str) -> Option<Ipv4Addr> {
    static CACHE: OnceLock<DnsCache> = OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    let remembered = cache.lock().ok().and_then(|map| map.get(name).copied());
    if let Some((when, address)) = remembered {
        let keep = if address.is_some() { DNS_KEEP } else { DNS_KEEP_FAILURE };
        if when.elapsed() < keep {
            return address;
        }
    }
    let found = match tokio::time::timeout(Duration::from_secs(5), tokio::net::lookup_host((name, 0))).await {
        Ok(Ok(addresses)) => addresses
            .filter_map(|address| match address.ip() {
                IpAddr::V4(ip) => Some(ip),
                IpAddr::V6(_) => None,
            })
            .next(),
        _ => None,
    };
    let answer = found.or_else(|| remembered.and_then(|(_, address)| address));
    if let Ok(mut map) = cache.lock() {
        map.insert(name.to_string(), (std::time::Instant::now(), answer));
    }
    answer
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

    /// Two listeners on ports the system chose, and the range that is exactly those two ports. No fixed port: the ports of the tests would be taken by the
    /// connections of the other tests that run at the same time
    async fn two_ports() -> (TcpListener, TcpListener, RangeInclusive<u16>) {
        for _ in 0..50 {
            let first = TcpListener::bind((LOOPBACK, 0)).await.unwrap();
            let port = first.local_addr().unwrap().port();
            // The next port, if it is free
            if let Some(next) = port.checked_add(1)
                && let Ok(second) = TcpListener::bind((LOOPBACK, next)).await
            {
                return (first, second, port..=next);
            }
        }
        panic!("no two ports in a row were free");
    }

    #[tokio::test]
    async fn bind_takes_a_port_of_the_range() {
        let (first, second, range) = two_ports().await;
        let (a, b) = (first.local_addr().unwrap().port(), second.local_addr().unwrap().port());
        drop((first, second));
        let listener = bind(LOOPBACK, &range).await.unwrap();
        assert!([a, b].contains(&listener.local_addr().unwrap().port()));
    }

    #[tokio::test]
    async fn bind_skips_the_ports_in_use_and_fails_when_all_are() {
        let (first, second, range) = two_ports().await;
        let (a, b) = (first.local_addr().unwrap().port(), second.local_addr().unwrap().port());
        drop(first);
        // Only the first port is free
        let taken = bind(LOOPBACK, &range).await.unwrap();
        assert_eq!(taken.local_addr().unwrap().port(), a);
        assert!(bind(LOOPBACK, &range).await.is_err());
        // A port is free again as soon as its listener is dropped
        drop(taken);
        drop(second);
        let again = bind(LOOPBACK, &range).await.unwrap();
        assert!([a, b].contains(&again.local_addr().unwrap().port()));
    }

    #[tokio::test]
    async fn a_name_is_resolved_and_remembered() {
        assert_eq!(resolve_ipv4("localhost").await, Some(Ipv4Addr::LOCALHOST));
        assert_eq!(resolve_ipv4("localhost").await, Some(Ipv4Addr::LOCALHOST));
        assert_eq!(resolve_ipv4("no-such-name.invalid").await, None);
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

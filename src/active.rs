//! Active mode (RFC 959 section 4.1.2 PORT, RFC 2428 EPRT, RFC 2577 section 3): the server connects to the client for the data connection.
//!
//! It is off unless the host turns it on. When on, it is restricted as RFC 2577 asks: the server connects only to the address the client's control
//! connection comes from (a client can't have the server connect to someone else: the "bounce attack"), and only to ports from 1024 up (a client can't
//! have the server connect to a well-known service).

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use tokio::net::{TcpSocket, TcpStream};
use tokio::time::{Instant, timeout_at};

/// Why the argument of PORT or EPRT is not used
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ActiveError {
    /// It is not a PORT or EPRT argument: `501`
    Syntax,
    /// EPRT with a network protocol that is not IPv4 or IPv6: `522`
    Protocol,
}

/// The ports below this are not connected to
pub(crate) const FIRST_PORT: u16 = 1024;

/// `h1,h2,h3,h4,p1,p2`: six numbers from 0 to 255 (RFC 959 section 4.1.2)
pub(crate) fn parse_port(argument: &str) -> Result<SocketAddr, ActiveError> {
    let mut numbers = [0u8; 6];
    let mut parts = argument.trim().split(',');
    for number in &mut numbers {
        let part = parts.next().ok_or(ActiveError::Syntax)?.trim();
        if part.is_empty() || part.len() > 3 || !part.bytes().all(|b| b.is_ascii_digit()) {
            return Err(ActiveError::Syntax);
        }
        *number = part.parse().map_err(|_| ActiveError::Syntax)?;
    }
    if parts.next().is_some() {
        return Err(ActiveError::Syntax);
    }
    let ip = Ipv4Addr::new(numbers[0], numbers[1], numbers[2], numbers[3]);
    Ok(SocketAddr::new(IpAddr::V4(ip), (u16::from(numbers[4]) << 8) | u16::from(numbers[5])))
}

/// `<d><protocol><d><address><d><port><d>`, where `<d>` is a delimiter character, protocol 1 is IPv4 and 2 is IPv6 (RFC 2428 section 2)
pub(crate) fn parse_eprt(argument: &str) -> Result<SocketAddr, ActiveError> {
    let argument = argument.trim();
    let delimiter = argument.chars().next().filter(|c| ('\x21'..='\x7e').contains(c)).ok_or(ActiveError::Syntax)?;
    let fields: Vec<&str> = argument.split(delimiter).collect();
    // An empty text before the first delimiter, three fields, an empty text after the last
    let [empty_before, protocol, address, port, empty_after] = fields.as_slice() else { return Err(ActiveError::Syntax) };
    if !empty_before.is_empty() || !empty_after.is_empty() {
        return Err(ActiveError::Syntax);
    }
    if port.is_empty() || port.len() > 5 || !port.bytes().all(|b| b.is_ascii_digit()) {
        return Err(ActiveError::Syntax);
    }
    let port: u16 = port.parse().map_err(|_| ActiveError::Syntax)?;
    let ip = match *protocol {
        "1" => IpAddr::V4(address.parse::<Ipv4Addr>().map_err(|_| ActiveError::Syntax)?),
        "2" => IpAddr::V6(address.parse::<Ipv6Addr>().map_err(|_| ActiveError::Syntax)?),
        protocol if !protocol.is_empty() && protocol.bytes().all(|b| b.is_ascii_digit()) => return Err(ActiveError::Protocol),
        _ => return Err(ActiveError::Syntax),
    };
    Ok(SocketAddr::new(ip, port))
}

/// Connects to the client's data port, from the address the control connection came to, until `deadline`
pub(crate) async fn connect(local: IpAddr, remote: SocketAddr, deadline: Instant) -> io::Result<TcpStream> {
    let socket = if remote.is_ipv4() { TcpSocket::new_v4()? } else { TcpSocket::new_v6()? };
    // The same address the client reached the server at, so that the connection comes from where the client expects (a firewall may check). With a
    // control connection over IPv6 and a client address that is IPv4, the system chooses
    if local.is_ipv4() == remote.is_ipv4() {
        socket.bind(SocketAddr::new(local, 0))?;
    }
    match timeout_at(deadline, socket.connect(remote)).await {
        Ok(result) => result,
        Err(_) => Err(io::ErrorKind::TimedOut.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn port_takes_six_numbers() {
        assert_eq!(parse_port("127,0,0,1,4,1"), Ok("127.0.0.1:1025".parse().unwrap()));
        assert_eq!(parse_port(" 192,168,1,5,255,255 "), Ok("192.168.1.5:65535".parse().unwrap()));
        assert_eq!(parse_port("10,0,0,1,0,0"), Ok("10.0.0.1:0".parse().unwrap()));
    }

    #[test]
    fn port_refuses_what_is_not_six_numbers() {
        for bad in [
            "",
            "1,2,3,4,5",
            "1,2,3,4,5,6,7",
            "1,2,3,4,5,256",
            "256,0,0,1,4,1",
            "a,b,c,d,e,f",
            "1,2,3,,5,6",
            "-1,2,3,4,5,6",
            "1,2,3,4,5,+6",
            "1.2.3.4.5.6",
            "1,2,3,4,5,0006",
        ] {
            assert_eq!(parse_port(bad), Err(ActiveError::Syntax), "{bad:?}");
        }
    }

    #[test]
    fn eprt_takes_a_protocol_an_address_and_a_port() {
        assert_eq!(parse_eprt("|1|132.235.1.2|6275|"), Ok("132.235.1.2:6275".parse().unwrap()));
        assert_eq!(parse_eprt("|2|1080::8:800:200C:417A|5282|"), Ok("[1080::8:800:200c:417a]:5282".parse().unwrap()));
        // Any delimiter from ! to ~
        assert_eq!(parse_eprt("!1!10.0.0.1!2000!"), Ok("10.0.0.1:2000".parse().unwrap()));
        assert_eq!(parse_eprt("|1|127.0.0.1|65535|"), Ok("127.0.0.1:65535".parse().unwrap()));
    }

    #[test]
    fn eprt_refuses_what_is_not_an_eprt_argument() {
        for bad in [
            "",
            "|",
            "||||",
            "|1|127.0.0.1|",
            "|1|127.0.0.1|2000",
            "1|127.0.0.1|2000|",
            "|1|127.0.0.1|2000|x",
            "|1|127.0.0.1|70000|",
            "|1|127.0.0.1|-1|",
            "|1|::1|2000|",
            "|2|127.0.0.1|2000|",
            "|1|999.0.0.1|2000|",
            " 1 127.0.0.1 2000 ",
            "|a|127.0.0.1|2000|",
            "|1|127.0.0.1|2000|3|",
            "|1|127.0.0.1|0x10|",
        ] {
            assert_eq!(parse_eprt(bad), Err(ActiveError::Syntax), "{bad:?}");
        }
        assert_eq!(parse_eprt("|3|whatever|2000|"), Err(ActiveError::Protocol));
        assert_eq!(parse_eprt("|99|x|1|"), Err(ActiveError::Protocol));
    }

    #[tokio::test]
    async fn connect_reaches_a_listener_from_the_given_address() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let remote = listener.local_addr().unwrap();
        let accepting = tokio::spawn(async move { listener.accept().await.unwrap().1 });
        let stream = connect("127.0.0.1".parse().unwrap(), remote, Instant::now() + Duration::from_secs(5)).await.unwrap();
        assert_eq!(accepting.await.unwrap(), stream.local_addr().unwrap());
    }

    #[tokio::test]
    async fn connect_fails_when_nobody_listens() {
        // A port that is ours and not listening: nobody else can be given it while the socket is held (a port that was freed a moment before could be),
        // and a connection to it is refused
        let socket = tokio::net::TcpSocket::new_v4().unwrap();
        socket.bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let address = socket.local_addr().unwrap();
        let result = connect("127.0.0.1".parse().unwrap(), address, Instant::now() + Duration::from_secs(5)).await;
        assert!(result.is_err());
        drop(socket);
    }
}

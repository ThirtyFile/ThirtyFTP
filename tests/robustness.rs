//! Sessions with commands that are made up: nothing a client sends may panic the server, leave a session that does not end, or stop it for the
//! next client. The same inputs a fuzzer would try, from a fixed seed so that a failure can be repeated

mod common;

use common::*;
use std::sync::atomic::Ordering;
use std::time::Duration;
use thirtyftp::Config;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

struct Random(u64);

impl Random {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }

    fn pick<'a>(&mut self, items: &[&'a str]) -> &'a str {
        items[self.below(items.len())]
    }
}

const VERBS: &[&str] = &[
    "USER", "PASS", "ACCT", "QUIT", "NOOP", "SYST", "FEAT", "OPTS", "HELP", "STAT", "PWD", "XPWD", "CWD", "XCWD", "CDUP", "XCUP", "MKD", "XMKD", "RMD", "XRMD",
    "DELE", "RNFR", "RNTO", "TYPE", "MODE", "STRU", "ALLO", "AUTH", "PBSZ", "PROT", "CCC", "PASV", "EPSV", "PORT", "EPRT", "STOR", "APPE", "RETR", "LIST", "NLST",
    "MLSD", "MLST", "SIZE", "MDTM", "REST", "ABOR", "SITE", "REIN", "SMNT", "STOU", "LPSV", "FOO",
];

const ARGUMENTS: &[&str] = &[
    "",
    "alice",
    "secret",
    "/",
    "..",
    "../../..",
    "/a/b/c",
    "a b c",
    "dir",
    "file.txt",
    "f",
    "-la",
    "-",
    "*",
    "?",
    "0",
    "1",
    "2",
    "-1",
    "4096",
    "99999999999999999999",
    "A",
    "I",
    "L 8",
    "E",
    "S",
    "B",
    "C",
    "P",
    "R",
    "F",
    "ON",
    "OFF",
    "UTF8 ON",
    "MLST type;size;",
    "ALL",
    "TLS",
    "SSL",
    "TLS-C",
    "127,0,0,1,200,1",
    "1,2,3",
    "|1|127.0.0.1|5000|",
    "|2|::1|5000|",
    "|||",
    "||||",
    "caf\u{e9}",
    "\u{65b0}\u{6587}\u{4ef6}",
    "a\u{1}b",
    "a\u{7f}b",
    "\u{fffd}",
    "x/../y",
    "./.",
    "...",
    "\"quoted\"",
    "a;b",
    "%00",
    "$(x)",
    "`x`",
];

/// A line: a verb, with its case changed now and then, and an argument
fn command(random: &mut Random) -> Vec<u8> {
    let mut verb = random.pick(VERBS).to_string();
    if random.below(5) == 0 {
        verb = verb.to_ascii_lowercase();
    }
    let mut line = verb.into_bytes();
    if random.below(6) != 0 {
        line.push(b' ');
        match random.below(12) {
            0 => line.extend(std::iter::repeat_n(b'a', random.below(9000))),
            1 => line.extend((0..random.below(40)).map(|_| random.next() as u8)),
            _ => line.extend_from_slice(random.pick(ARGUMENTS).as_bytes()),
        }
    }
    match random.below(10) {
        0 => line.extend_from_slice(b"\n"),
        1 => line.extend_from_slice(b"\r\r\n"),
        2 => drop(line.splice(0..0, [0xff, 0xf4, 0xff, 0xf2])),
        _ => line.extend_from_slice(b"\r\n"),
    }
    line
}

/// Reads what the server has to say, for a moment, and returns the port of a PASV or EPSV reply when there is one
async fn drain(stream: &mut TcpStream) -> (Vec<u8>, Option<u16>) {
    let mut all = Vec::new();
    let mut buffer = [0u8; 4096];
    while let Ok(Ok(read)) = tokio::time::timeout(Duration::from_millis(8), stream.read(&mut buffer)).await {
        if read == 0 {
            break;
        }
        all.extend_from_slice(&buffer[..read]);
    }
    let text = String::from_utf8_lossy(&all).into_owned();
    let port = text.lines().find_map(|line| {
        if let Some(rest) = line.strip_prefix("227 ") {
            let numbers: Vec<u16> = rest.split(['(', ')']).nth(1)?.split(',').filter_map(|n| n.parse().ok()).collect();
            (numbers.len() == 6).then(|| numbers[4] * 256 + numbers[5])
        } else if let Some(rest) = line.strip_prefix("229 ") {
            rest.split('|').nth(3)?.parse().ok()
        } else {
            None
        }
    });
    (all, port)
}

async fn one_session(server: &Server, random: &mut Random, with_tls: bool) {
    let Ok(mut stream) = TcpStream::connect(server.address).await else { return };
    let _ = drain(&mut stream).await;
    if random.below(4) != 0 {
        let _ = stream.write_all(b"USER alice\r\nPASS secret\r\n").await;
        let _ = drain(&mut stream).await;
    }
    if with_tls && random.below(3) == 0 {
        // A TLS handshake that is junk, or no handshake at all
        let _ = stream.write_all(b"AUTH TLS\r\n").await;
        let _ = drain(&mut stream).await;
        let junk: Vec<u8> = (0..random.below(300)).map(|_| random.next() as u8).collect();
        let _ = stream.write_all(&junk).await;
        let _ = drain(&mut stream).await;
        return;
    }
    for _ in 0..random.below(25) {
        let line = command(random);
        if stream.write_all(&line).await.is_err() {
            return;
        }
        let (_, port) = drain(&mut stream).await;
        if let Some(port) = port {
            // A data connection, with junk, or nothing, or closed at once
            if let Ok(mut data) = TcpStream::connect(("127.0.0.1", port)).await {
                match random.below(3) {
                    0 => {
                        let junk: Vec<u8> = (0..random.below(2000)).map(|_| random.next() as u8).collect();
                        let _ = data.write_all(&junk).await;
                    }
                    1 => {}
                    _ => drop(data),
                }
            }
        }
    }
}

#[tokio::test]
async fn made_up_commands_never_panic_or_hang_a_session() {
    let tls = tls();
    let server = start_with({
        let mut config = Config::default();
        config.tls = Some(tls.server.clone());
        config.active_mode = true;
        config.passive_ports = 0..=0;
        config.limits.data_accept_timeout = Duration::from_millis(100);
        config.limits.transfer_idle_timeout = Duration::from_millis(100);
        config.limits.tls_handshake_timeout = Duration::from_millis(200);
        config
    })
    .await;
    let mut random = Random(0x9e37_79b9_7f4a_7c15);
    for round in 0..80 {
        one_session(&server, &mut random, round % 2 == 0).await;
    }
    // Every session ended, and none by a panic (a session that panics never reports its end)
    let accepted = server.accepted.load(Ordering::SeqCst);
    eventually(|| server.ends.lock().unwrap().len() == accepted).await;
    // And the server serves the next client
    let mut client = Client::connect(&server).await;
    client.login().await;
    assert_eq!(client.command("PWD").await.0, 257);
}

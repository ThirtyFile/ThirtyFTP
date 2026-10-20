//! Reading lines from the control connection (RFC 959 section 2.3 and 4.1.3 "Telnet", RFC 1123 section 4.1.2.10).
//!
//! The control connection follows the Telnet protocol. Lines end with CRLF; a lone LF from a careless client is accepted too. A client may send
//! Telnet commands in between: before an ABOR sent during a transfer it sends Interrupt Process and Data Mark (`IAC IP IAC DM`). The reader
//! removes every Telnet command and keeps the text; `IAC IAC` is one byte 255. It answers none of them (an FTP server may refuse every option).
//!
//! A line longer than the limit is dropped, and the reader tells so once it reaches the end of that line, so the next line is read as usual.
//! Text that isn't UTF-8 is read lossily: the bytes that aren't UTF-8 become U+FFFD.

use std::io;
use tokio::io::{AsyncRead, AsyncReadExt};

const IAC: u8 = 255;
const DONT: u8 = 254;
const WILL: u8 = 251;
const SB: u8 = 250;
const SE: u8 = 240;

/// How much is read from the connection at a time
const CHUNK: usize = 2048;

/// What was read
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Line {
    /// A line, without its line end
    Text(String),
    /// A line longer than the limit, which has been dropped
    TooLong,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Telnet {
    /// Text
    Data,
    /// After IAC
    Command,
    /// After IAC and WILL, WONT, DO or DONT: the option follows
    Option,
    /// Inside a sub-negotiation (IAC SB ... IAC SE)
    Subnegotiation,
    /// Inside a sub-negotiation, after IAC
    SubnegotiationCommand,
}

/// Splits what the control connection delivers into lines. It keeps what it read and didn't use, so a read that is cancelled (by a timeout, or because
/// something else happened first) loses nothing.
pub(crate) struct LineReader {
    max_line: usize,
    buffer: Box<[u8; CHUNK]>,
    position: usize,
    length: usize,
    line: Vec<u8>,
    too_long: bool,
    telnet: Telnet,
}

impl LineReader {
    pub(crate) fn new(max_line: usize) -> LineReader {
        LineReader { max_line, buffer: Box::new([0; CHUNK]), position: 0, length: 0, line: Vec::new(), too_long: false, telnet: Telnet::Data }
    }

    /// Reads the next line, or `None` when the other side has closed the connection. A line that is not ended yet when the connection closes is
    /// dropped. Cancel-safe.
    pub(crate) async fn next_line<R: AsyncRead + Unpin>(&mut self, reader: &mut R) -> io::Result<Option<Line>> {
        loop {
            if let Some(line) = self.take_line() {
                return Ok(Some(line));
            }
            let read = reader.read(&mut self.buffer[..]).await?;
            if read == 0 {
                return Ok(None);
            }
            self.position = 0;
            self.length = read;
        }
    }

    /// Drops what was read and not used. A switch to TLS does this: bytes the client sent in plaintext before the upgrade are never used (RFC 4217)
    #[allow(dead_code)] // The TLS upgrade (a later milestone)
    pub(crate) fn discard_buffered(&mut self) {
        self.position = 0;
        self.length = 0;
        self.line.clear();
        self.too_long = false;
        self.telnet = Telnet::Data;
    }

    // `position` is below `length`, which is at most the size of the buffer
    #[allow(clippy::indexing_slicing)]
    fn take_line(&mut self) -> Option<Line> {
        while self.position < self.length {
            let byte = self.buffer[self.position];
            self.position += 1;
            match self.telnet {
                Telnet::Data => {
                    if byte == IAC {
                        self.telnet = Telnet::Command;
                    } else if let Some(line) = self.text_byte(byte) {
                        return Some(line);
                    }
                }
                Telnet::Command => {
                    if byte == IAC {
                        // The byte 255 as text
                        self.telnet = Telnet::Data;
                        self.text_byte(IAC);
                    } else {
                        self.telnet = match byte {
                            WILL..=DONT => Telnet::Option,
                            SB => Telnet::Subnegotiation,
                            // IP, DM, NOP, GA and the others are a command of two bytes
                            _ => Telnet::Data,
                        };
                    }
                }
                Telnet::Option => self.telnet = Telnet::Data,
                Telnet::Subnegotiation => {
                    if byte == IAC {
                        self.telnet = Telnet::SubnegotiationCommand;
                    }
                }
                Telnet::SubnegotiationCommand => {
                    self.telnet = if byte == SE { Telnet::Data } else { Telnet::Subnegotiation };
                }
            }
        }
        None
    }

    /// One byte of text. At the end of a line, the line
    fn text_byte(&mut self, byte: u8) -> Option<Line> {
        if byte == b'\n' {
            let too_long = std::mem::take(&mut self.too_long);
            let mut line = std::mem::take(&mut self.line);
            if line.last() == Some(&b'\r') {
                line.pop();
            }
            return Some(if too_long || line.len() > self.max_line { Line::TooLong } else { Line::Text(String::from_utf8_lossy(&line).into_owned()) });
        }
        // The CR of the line end is kept until the LF shows that it was one, so the limit allows it
        if self.line.len() < self.max_line + 1 {
            self.line.push(byte);
        } else {
            self.too_long = true;
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn lines(chunks: &[&[u8]], max: usize) -> Vec<Line> {
        let (mut client, mut server) = tokio::io::duplex(65536);
        let mut reader = LineReader::new(max);
        let mut out = Vec::new();
        for chunk in chunks {
            tokio::io::AsyncWriteExt::write_all(&mut client, chunk).await.unwrap();
        }
        drop(client);
        while let Some(line) = reader.next_line(&mut server).await.unwrap() {
            out.push(line);
        }
        out
    }

    fn text(s: &str) -> Line {
        Line::Text(s.to_string())
    }

    #[tokio::test]
    async fn crlf_and_lone_lf() {
        assert_eq!(lines(&[b"USER a\r\nPASS b\nNOOP\r\n"], 100).await, [text("USER a"), text("PASS b"), text("NOOP")]);
    }

    #[tokio::test]
    async fn a_line_split_over_reads() {
        assert_eq!(lines(&[b"US", b"ER a", b"\r", b"\nNOOP\r\n"], 100).await, [text("USER a"), text("NOOP")]);
    }

    #[tokio::test]
    async fn a_line_not_ended_when_the_connection_closes_is_dropped() {
        assert_eq!(lines(&[b"NOOP\r\nQUI"], 100).await, [text("NOOP")]);
    }

    #[tokio::test]
    async fn an_empty_line_is_a_line() {
        assert_eq!(lines(&[b"\r\n\n"], 100).await, [text(""), text("")]);
    }

    #[tokio::test]
    async fn a_carriage_return_inside_a_line_is_kept() {
        assert_eq!(lines(&[b"A\rB\r\n"], 100).await, [text("A\rB")]);
    }

    #[tokio::test]
    async fn telnet_interrupt_and_data_mark_before_abor_are_removed() {
        assert_eq!(lines(&[b"\xff\xf4\xff\xf2ABOR\r\n"], 100).await, [text("ABOR")]);
        assert_eq!(lines(&[b"\xff", b"\xf4\xff", b"\xf2AB", b"OR\r\n"], 100).await, [text("ABOR")]);
    }

    #[tokio::test]
    async fn telnet_options_and_sub_negotiations_are_removed() {
        assert_eq!(lines(&[b"\xff\xfb\x01NOOP\xff\xfd\x03\r\n"], 100).await, [text("NOOP")]);
        assert_eq!(lines(&[b"\xff\xfa\x18\x00xterm\xff\xf0NOOP\r\n"], 100).await, [text("NOOP")]);
        // An IAC inside the sub-negotiation that does not end it
        assert_eq!(lines(&[b"\xff\xfa\x18\xff\xff\xff\xf0NOOP\r\n"], 100).await, [text("NOOP")]);
    }

    #[tokio::test]
    async fn iac_iac_is_the_byte_255() {
        // 255 isn't UTF-8 by itself, so it is read as U+FFFD
        assert_eq!(lines(&[b"A\xff\xffB\r\n"], 100).await, [text("A\u{fffd}B")]);
    }

    #[tokio::test]
    async fn a_telnet_command_at_the_end_of_the_input_is_not_a_panic() {
        assert_eq!(lines(&[b"NOOP\r\n\xff"], 100).await, [text("NOOP")]);
        assert_eq!(lines(&[b"NOOP\r\n\xff\xfa"], 100).await, [text("NOOP")]);
    }

    #[tokio::test]
    async fn a_line_that_is_too_long_is_dropped_and_the_next_is_read() {
        let long = "A".repeat(200);
        let input = format!("{long}\r\nNOOP\r\n");
        assert_eq!(lines(&[input.as_bytes()], 100).await, [Line::TooLong, text("NOOP")]);
    }

    #[tokio::test]
    async fn the_limit_is_in_bytes_and_a_line_of_exactly_the_limit_is_kept() {
        let exact = "A".repeat(100);
        let input = format!("{exact}\r\n{exact}A\r\n{exact}\n{exact}A\n");
        assert_eq!(lines(&[input.as_bytes()], 100).await, [text(&exact), Line::TooLong, text(&exact), Line::TooLong]);
    }

    #[tokio::test]
    async fn a_line_too_long_over_many_reads_does_not_grow_the_buffer() {
        let mut reader = LineReader::new(50);
        let (mut client, mut server) = tokio::io::duplex(1024);
        // More than the pipe holds: the writer waits for the reader
        let writer = tokio::spawn(async move {
            let chunk = vec![b'A'; 10_000];
            for _ in 0..10 {
                tokio::io::AsyncWriteExt::write_all(&mut client, &chunk).await.unwrap();
            }
            tokio::io::AsyncWriteExt::write_all(&mut client, b"\r\nNOOP\r\n").await.unwrap();
        });
        assert_eq!(reader.next_line(&mut server).await.unwrap(), Some(Line::TooLong));
        assert!(reader.line.len() <= 51);
        assert_eq!(reader.next_line(&mut server).await.unwrap(), Some(text("NOOP")));
        assert_eq!(reader.next_line(&mut server).await.unwrap(), None);
        writer.await.unwrap();
    }

    #[tokio::test]
    async fn bytes_that_are_not_utf8_are_read_lossily() {
        assert_eq!(lines(&[b"CWD \xe6\x96\xb0\xe6\x96\r\n"], 100).await, [text("CWD \u{65b0}\u{fffd}")]);
    }

    #[tokio::test]
    async fn discarding_what_was_read_drops_the_rest_of_the_chunk() {
        let (mut client, mut server) = tokio::io::duplex(65536);
        tokio::io::AsyncWriteExt::write_all(&mut client, b"AUTH TLS\r\nUSER secret\r\n").await.unwrap();
        let mut reader = LineReader::new(100);
        assert_eq!(reader.next_line(&mut server).await.unwrap(), Some(text("AUTH TLS")));
        reader.discard_buffered();
        drop(client);
        assert_eq!(reader.next_line(&mut server).await.unwrap(), None);
    }
}

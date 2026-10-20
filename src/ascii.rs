//! Line ends of ASCII transfers (RFC 959 section 3.1.1.1: the network ASCII form ends lines with CR LF).
//!
//! With `TYPE A`, and when the host turns the conversion on, a file is stored with LF line ends and sent with CRLF. Without the conversion (the
//! default) the bytes of an ASCII transfer are not changed, as in vsftpd: a file that is not text, sent with `TYPE A` by a careless client, stays what it
//! is.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, ReadBuf};

const CR: u8 = b'\r';
const LF: u8 = b'\n';
const CHUNK: usize = 8192;

/// Which way the line ends are converted
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Direction {
    /// From the network form to the stored form: CRLF becomes LF (upload)
    FromNetwork,
    /// From the stored form to the network form: LF becomes CRLF (download)
    ToNetwork,
}

/// Reads from `inner` and delivers the bytes with their line ends converted
pub(crate) struct Converting<R> {
    inner: R,
    direction: Direction,
    /// Converted bytes not delivered yet
    out: Vec<u8>,
    position: usize,
    scratch: Box<[u8; CHUNK]>,
    /// FromNetwork: a CR was the last byte, and what follows decides whether it is kept. ToNetwork: the last byte was a CR
    after_cr: bool,
    done: bool,
}

impl<R> Converting<R> {
    pub(crate) fn new(inner: R, direction: Direction) -> Converting<R> {
        Converting { inner, direction, out: Vec::new(), position: 0, scratch: Box::new([0; CHUNK]), after_cr: false, done: false }
    }

    // The index is below `input_length`, which is at most the size of the scratch buffer
    #[allow(clippy::indexing_slicing)]
    fn convert(&mut self, input_length: usize) {
        for index in 0..input_length {
            let byte = self.scratch[index];
            match self.direction {
                Direction::FromNetwork => {
                    if self.after_cr {
                        self.after_cr = false;
                        if byte == LF {
                            // CR LF is one LF
                            self.out.push(LF);
                            continue;
                        }
                        self.out.push(CR);
                    }
                    if byte == CR {
                        self.after_cr = true;
                    } else {
                        self.out.push(byte);
                    }
                }
                Direction::ToNetwork => {
                    if byte == LF && !self.after_cr {
                        self.out.push(CR);
                    }
                    self.out.push(byte);
                    self.after_cr = byte == CR;
                }
            }
        }
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for Converting<R> {
    // `position` is below the length of `out`, and `count` is at most what is left of it
    #[allow(clippy::indexing_slicing)]
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        loop {
            if this.position < this.out.len() {
                let count = buf.remaining().min(this.out.len() - this.position);
                buf.put_slice(&this.out[this.position..this.position + count]);
                this.position += count;
                return Poll::Ready(Ok(()));
            }
            if this.done {
                return Poll::Ready(Ok(()));
            }
            this.out.clear();
            this.position = 0;
            let mut read_buf = ReadBuf::new(&mut this.scratch[..]);
            match Pin::new(&mut this.inner).poll_read(cx, &mut read_buf) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(())) => {
                    let length = read_buf.filled().len();
                    if length == 0 {
                        this.done = true;
                        // A CR at the very end has no LF after it
                        if this.direction == Direction::FromNetwork && this.after_cr {
                            this.after_cr = false;
                            this.out.push(CR);
                        }
                    } else {
                        this.convert(length);
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;

    /// Delivers its pieces one by one, so that the conversion sees every kind of split
    struct Pieces(std::collections::VecDeque<Vec<u8>>);

    impl AsyncRead for Pieces {
        fn poll_read(mut self: Pin<&mut Self>, _: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
            if let Some(piece) = self.0.pop_front() {
                buf.put_slice(&piece);
            }
            Poll::Ready(Ok(()))
        }
    }

    async fn convert(input: &[u8], split: usize, direction: Direction) -> Vec<u8> {
        let (first, second) = input.split_at(split);
        let pieces = [first.to_vec(), second.to_vec()].into_iter().filter(|piece| !piece.is_empty()).collect();
        let mut out = Vec::new();
        Converting::new(Pieces(pieces), direction).read_to_end(&mut out).await.unwrap();
        out
    }

    async fn check(input: &[u8], expected: &[u8], direction: Direction) {
        for split in 0..=input.len() {
            assert_eq!(convert(input, split, direction).await, expected, "{input:?} split at {split}");
        }
    }

    #[tokio::test]
    async fn crlf_becomes_lf_on_the_way_in() {
        check(b"a\r\nb\r\n", b"a\nb\n", Direction::FromNetwork).await;
        check(b"a\nb", b"a\nb", Direction::FromNetwork).await;
        check(b"", b"", Direction::FromNetwork).await;
        check(b"\r\n", b"\n", Direction::FromNetwork).await;
        check(b"\r\r\n", b"\r\n", Direction::FromNetwork).await;
        check(b"a\rb", b"a\rb", Direction::FromNetwork).await;
        check(b"a\r", b"a\r", Direction::FromNetwork).await;
        check(b"\r\n\r\n\r", b"\n\n\r", Direction::FromNetwork).await;
        check(&[0, 255, b'\r', b'\n', 128], &[0, 255, b'\n', 128], Direction::FromNetwork).await;
    }

    #[tokio::test]
    async fn lf_becomes_crlf_on_the_way_out() {
        check(b"a\nb\n", b"a\r\nb\r\n", Direction::ToNetwork).await;
        check(b"a\r\nb", b"a\r\nb", Direction::ToNetwork).await;
        check(b"", b"", Direction::ToNetwork).await;
        check(b"\n", b"\r\n", Direction::ToNetwork).await;
        check(b"\n\n", b"\r\n\r\n", Direction::ToNetwork).await;
        check(b"a\rb", b"a\rb", Direction::ToNetwork).await;
        check(b"\r\r\n\n", b"\r\r\n\r\n", Direction::ToNetwork).await;
    }

    #[tokio::test]
    async fn a_long_input_is_converted_in_chunks() {
        let input: Vec<u8> = (0..100_000).flat_map(|i| if i % 7 == 0 { vec![b'x', LF] } else { vec![b'y'] }).collect();
        let expected: Vec<u8> = input.iter().flat_map(|&b| if b == LF { vec![CR, LF] } else { vec![b] }).collect();
        let mut out = Vec::new();
        Converting::new(std::io::Cursor::new(input.clone()), Direction::ToNetwork).read_to_end(&mut out).await.unwrap();
        assert_eq!(out, expected);
        let mut back = Vec::new();
        Converting::new(std::io::Cursor::new(out), Direction::FromNetwork).read_to_end(&mut back).await.unwrap();
        assert_eq!(back, input);
    }

    #[tokio::test]
    async fn a_small_buffer_gets_the_rest_later() {
        let mut converting = Converting::new(std::io::Cursor::new(b"a\nb\nc\n".to_vec()), Direction::ToNetwork);
        let mut out = Vec::new();
        let mut one = [0u8; 1];
        while converting.read(&mut one).await.unwrap() == 1 {
            out.push(one[0]);
        }
        assert_eq!(out, b"a\r\nb\r\nc\r\n");
    }
}

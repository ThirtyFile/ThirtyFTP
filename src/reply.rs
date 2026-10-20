//! Replies on the control connection (RFC 959 section 4.2, RFC 1123 section 4.1.2.11).
//!
//! A reply is a three-digit code and text. A reply with several lines starts with `ddd-`, and ends with a line that starts with `ddd `, the same
//! code and a space. The lines in between are indented with a space, so a line of text that starts with digits can't be taken for the end.
//! The texts in [`text`] are the ones RFC 959 gives; the others say what happened where nothing in the RFC fits.

/// A reply to one command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Reply {
    pub(crate) code: u16,
    /// Never empty
    lines: Vec<String>,
}

/// The reply texts of RFC 959 section 4.2.2, for the replies whose meaning matches
pub(crate) mod text {
    pub(crate) const COMMAND_OK: &str = "Command okay.";
    pub(crate) const SUPERFLUOUS: &str = "Command not implemented, superfluous at this site.";
    pub(crate) const HELP: &str = "Help message.";
    pub(crate) const DATA_CLOSED: &str = "Closing data connection. Requested file action successful (for example, file transfer or file abort).";
    pub(crate) const READY: &str = "Service ready for new user.";
    pub(crate) const CLOSING: &str = "Service closing control connection.";
    pub(crate) const LOGGED_IN: &str = "User logged in, proceed.";
    pub(crate) const FILE_ACTION_OK: &str = "Requested file action okay, completed.";
    pub(crate) const NEED_PASSWORD: &str = "User name okay, need password.";
    pub(crate) const UNAVAILABLE: &str = "Service not available, closing control connection.";
    pub(crate) const SYNTAX_COMMAND: &str = "Syntax error, command unrecognized.";
    pub(crate) const SYNTAX_PARAMETERS: &str = "Syntax error in parameters or arguments.";
    pub(crate) const NOT_IMPLEMENTED: &str = "Command not implemented.";
    pub(crate) const BAD_SEQUENCE: &str = "Bad sequence of commands.";
    pub(crate) const NOT_IMPLEMENTED_PARAMETER: &str = "Command not implemented for that parameter.";
    pub(crate) const NOT_LOGGED_IN: &str = "Not logged in.";
    pub(crate) const FILE_UNAVAILABLE: &str = "Requested action not taken. File unavailable (e.g., file not found, no access).";
    pub(crate) const NAME_NOT_ALLOWED: &str = "Requested action not taken. File name not allowed.";
    pub(crate) const LOCAL_ERROR: &str = "Requested action aborted. Local error in processing.";
    pub(crate) const NO_SPACE: &str = "Requested file action not taken. Exceeded storage allocation.";
    pub(crate) const FILE_BUSY: &str = "Requested file action not taken. File unavailable (e.g., file busy).";
}

impl Reply {
    /// A reply of one line
    pub(crate) fn new(code: u16, text: &str) -> Reply {
        Reply { code, lines: vec![clean(text)] }
    }

    /// A reply of several lines. With one line it is a reply of one line, and with none it has an empty text
    pub(crate) fn multi<I, S>(code: u16, lines: I) -> Reply
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut lines: Vec<String> = lines.into_iter().map(|line| clean(line.as_ref())).collect();
        if lines.is_empty() {
            lines.push(String::new());
        }
        Reply { code, lines }
    }

    /// The bytes sent on the control connection, each line ended with CRLF
    pub(crate) fn encode(&self) -> Vec<u8> {
        let mut out = String::new();
        let last = self.lines.len() - 1;
        for (index, line) in self.lines.iter().enumerate() {
            if index == last {
                out.push_str(&format!("{} {}\r\n", self.code, line));
            } else if index == 0 {
                out.push_str(&format!("{}-{}\r\n", self.code, line));
            } else {
                out.push_str(&format!(" {line}\r\n"));
            }
        }
        out.into_bytes()
    }
}

/// Line ends and NUL inside a text would end the reply, or the line, early
fn clean(text: &str) -> String {
    text.chars().map(|c| if matches!(c, '\r' | '\n' | '\0') { ' ' } else { c }).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_reply_of_one_line() {
        assert_eq!(Reply::new(200, "Command okay.").encode(), b"200 Command okay.\r\n");
    }

    #[test]
    fn a_reply_of_several_lines_ends_with_the_code_and_a_space() {
        let reply = Reply::multi(211, ["Features:", "UTF8", "SIZE", "End"]);
        assert_eq!(reply.encode(), b"211-Features:\r\n UTF8\r\n SIZE\r\n211 End\r\n");
    }

    #[test]
    fn a_line_in_the_middle_that_starts_with_digits_cannot_end_the_reply() {
        let reply = Reply::multi(211, ["Start", "211 not the end", "End"]);
        assert_eq!(reply.encode(), b"211-Start\r\n 211 not the end\r\n211 End\r\n");
    }

    #[test]
    fn line_ends_in_the_text_are_replaced() {
        assert_eq!(Reply::new(257, "a\r\nb\0c").encode(), b"257 a  b c\r\n");
        assert_eq!(Reply::multi(211, ["a\nb", "c"]).encode(), b"211-a b\r\n211 c\r\n");
    }

    #[test]
    fn no_lines_gives_an_empty_text() {
        assert_eq!(Reply::multi(214, Vec::<String>::new()).encode(), b"214 \r\n");
    }
}

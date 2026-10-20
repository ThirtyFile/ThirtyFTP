//! The text of listings: LIST in the `ls -l` style that every client reads, NLST, and the facts of MLSD and MLST (RFC 959 section 4.1.3, RFC 3659 section 7).

use crate::backend::{Entry, EntryKind};
use crate::time;
use std::time::SystemTime;

/// The facts of MLSD and MLST that the library can give, and which of them are on (`OPTS MLST` chooses)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Facts {
    pub(crate) kind: bool,
    pub(crate) size: bool,
    pub(crate) modify: bool,
}

impl Default for Facts {
    fn default() -> Facts {
        Facts { kind: true, size: true, modify: true }
    }
}

impl Facts {
    /// The facts that `OPTS MLST` names, in the order of the request. The ones the library doesn't know are left out (RFC 3659 section 7.9.1)
    pub(crate) fn select(request: &str) -> Facts {
        let mut facts = Facts { kind: false, size: false, modify: false };
        for name in request.split(';') {
            match name.trim().to_ascii_lowercase().as_str() {
                "type" => facts.kind = true,
                "size" => facts.size = true,
                "modify" => facts.modify = true,
                _ => {}
            }
        }
        facts
    }

    /// The text of `OPTS MLST` replies and of the FEAT line, `type;size;`. With `marks`, the facts that are on have a `*` (the FEAT line)
    pub(crate) fn names(&self, marks: bool) -> String {
        let star = if marks { "*" } else { "" };
        let mut out = String::new();
        for (on, name) in [(self.kind, "type"), (self.size, "size"), (self.modify, "modify")] {
            if on {
                out.push_str(name);
                out.push_str(star);
                out.push(';');
            }
        }
        out
    }
}

/// A name in a listing can't hold a line end or another control character: they are shown as `?`
fn safe(name: &str) -> String {
    name.chars().map(|c| if c.is_control() { '?' } else { c }).collect()
}

/// A listing for LIST: a line for each entry, in the `ls -l` style
pub(crate) fn list(entries: &[Entry], now: SystemTime) -> String {
    let mut out = String::new();
    for entry in entries {
        let (kind, mode, links) = match entry.kind {
            EntryKind::Directory => ('d', "rwxr-xr-x", 2),
            EntryKind::File => ('-', "rw-r--r--", 1),
        };
        let date = time::ls(entry.modified.unwrap_or(SystemTime::UNIX_EPOCH), now);
        out.push_str(&format!("{kind}{mode} {links:>3} ftp      ftp      {:>12} {date} {}\r\n", entry.size, safe(&entry.name)));
    }
    out
}

/// A listing for NLST: the names
pub(crate) fn names(entries: &[Entry]) -> String {
    entries.iter().map(|entry| format!("{}\r\n", safe(&entry.name))).collect()
}

/// A listing for NLST of a path: the names as they are written to the client, a line for each
pub(crate) fn lines(names: &[String]) -> String {
    names.iter().map(|name| format!("{}\r\n", safe(name))).collect()
}

/// The facts of an entry, `type=file;size=12;modify=20260101000000;`
fn facts_of(entry: &Entry, facts: Facts) -> String {
    let mut out = String::new();
    if facts.kind {
        out.push_str(match entry.kind {
            EntryKind::File => "type=file;",
            EntryKind::Directory => "type=dir;",
        });
    }
    if facts.size && entry.kind == EntryKind::File {
        out.push_str(&format!("size={};", entry.size));
    }
    if facts.modify
        && let Some(modified) = entry.modified
    {
        out.push_str(&format!("modify={};", time::mlsx(modified)));
    }
    out
}

/// A listing for MLSD: a line for each entry, the facts, a space, the name (RFC 3659 section 7.2)
pub(crate) fn mlsd(entries: &[Entry], facts: Facts) -> String {
    entries.iter().map(|entry| format!("{} {}\r\n", facts_of(entry, facts), safe(&entry.name))).collect()
}

/// The line of MLST for one path: the facts, a space, the path
pub(crate) fn mlst(entry: &Entry, path: &str, facts: Facts) -> String {
    format!("{} {}", facts_of(entry, facts), safe(path))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, UNIX_EPOCH};

    fn at(seconds: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(seconds)
    }

    fn entries() -> Vec<Entry> {
        vec![Entry::file("a b.pdf", 1234, Some(at(1_781_959_845))), Entry::directory("sub", Some(at(1_000_000_000))), Entry::file("none", 0, None)]
    }

    #[test]
    fn list_is_the_ls_format() {
        let text = list(&entries(), at(1_781_959_845));
        assert_eq!(
            text,
            "-rw-r--r--   1 ftp      ftp              1234 Jun 20 12:50 a b.pdf\r\n\
             drwxr-xr-x   2 ftp      ftp                 0 Sep  9  2001 sub\r\n\
             -rw-r--r--   1 ftp      ftp                 0 Jan  1  1970 none\r\n"
        );
    }

    #[test]
    fn nlst_is_the_names() {
        assert_eq!(names(&entries()), "a b.pdf\r\nsub\r\nnone\r\n");
    }

    #[test]
    fn mlsd_has_the_facts_and_the_name() {
        assert_eq!(
            mlsd(&entries(), Facts::default()),
            "type=file;size=1234;modify=20260620125045; a b.pdf\r\ntype=dir;modify=20010909014640; sub\r\ntype=file;size=0; none\r\n"
        );
    }

    #[test]
    fn lines_are_the_names_given() {
        assert_eq!(lines(&["sub/a.txt".to_string(), "sub/b".to_string()]), "sub/a.txt\r\nsub/b\r\n");
        assert_eq!(lines(&[]), "");
        assert_eq!(lines(&["a\nb".to_string()]), "a?b\r\n");
    }

    #[test]
    fn a_name_cannot_break_a_line() {
        let bad = [Entry::file("a\r\nb\0c", 1, None)];
        assert_eq!(names(&bad), "a??b?c\r\n");
        assert!(list(&bad, at(0)).ends_with(" a??b?c\r\n"));
        assert_eq!(mlsd(&bad, Facts::default()), "type=file;size=1; a??b?c\r\n");
    }

    #[test]
    fn opts_mlst_chooses_the_facts() {
        let facts = Facts::select("type;size;perm;unix.mode;");
        assert_eq!(facts, Facts { kind: true, size: true, modify: false });
        assert_eq!(facts.names(false), "type;size;");
        assert_eq!(Facts::default().names(true), "type*;size*;modify*;");
        assert_eq!(Facts::select("").names(false), "");
        assert_eq!(mlsd(&entries()[..1], Facts::select("size")), "size=1234; a b.pdf\r\n");
    }

    #[test]
    fn mlst_is_one_line_with_the_path() {
        assert_eq!(mlst(&entries()[0], "/in/a b.pdf", Facts::default()), "type=file;size=1234;modify=20260620125045; /in/a b.pdf");
    }
}

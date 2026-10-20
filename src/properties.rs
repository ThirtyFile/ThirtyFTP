//! Properties that must hold for any input: nothing panics, and what is promised about lines, paths, replies and conversions holds

use crate::ascii::{Conversion, Converting, Pieces};
use crate::codec::{Line, LineReader};
use crate::command::{self, Command};
use crate::path::FtpPath;
use crate::reply::Reply;
use crate::{active, listing};
use proptest::prelude::*;
use tokio::io::AsyncReadExt;

fn block_on<F: std::future::Future>(future: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(future)
}

/// Reads all lines from `chunks`, delivered one by one
fn read_lines(chunks: &[Vec<u8>], max: usize) -> Vec<Line> {
    block_on(async {
        let (mut client, mut server) = tokio::io::duplex(1 << 20);
        for chunk in chunks {
            tokio::io::AsyncWriteExt::write_all(&mut client, chunk).await.unwrap();
        }
        drop(client);
        let mut reader = LineReader::new(max);
        let mut lines = Vec::new();
        while let Some(line) = reader.next_line(&mut server).await.unwrap() {
            lines.push(line);
        }
        lines
    })
}

/// Bytes that make lines and Telnet commands often
fn wire_bytes() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(prop_oneof![Just(b'\r'), Just(b'\n'), Just(0xffu8), Just(b' '), 0xf0u8..=0xfe, b'A'..=b'Z', any::<u8>()], 0..400)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(300))]

    #[test]
    fn the_codec_gives_the_same_lines_however_the_input_is_split(bytes in wire_bytes(), cuts in prop::collection::vec(any::<usize>(), 0..6), max in 1usize..64) {
        let whole = read_lines(std::slice::from_ref(&bytes), max);
        let mut points: Vec<usize> = cuts.iter().map(|cut| cut % (bytes.len() + 1)).collect();
        points.sort_unstable();
        let mut chunks = Vec::new();
        let mut start = 0;
        for point in points {
            chunks.push(bytes[start..point].to_vec());
            start = point;
        }
        chunks.push(bytes[start..].to_vec());
        prop_assert_eq!(read_lines(&chunks, max), whole);
    }

    #[test]
    fn a_line_from_the_codec_is_within_the_limit_and_has_no_line_end(bytes in wire_bytes(), max in 1usize..64) {
        for line in read_lines(&[bytes], max) {
            if let Line::Text(text) = line {
                // The text is read lossily: a character is at least a byte of the line
                prop_assert!(text.chars().count() <= max);
                prop_assert!(!text.contains('\n'));
            }
        }
    }

    #[test]
    fn the_parser_never_panics_and_the_verb_is_not_case_sensitive(line in "\\PC{0,80}") {
        let parsed = command::parse(&line);
        let lower = line.to_ascii_lowercase();
        // The verb's case, not the argument's
        if let Some((verb, rest)) = line.split_once(' ') {
            let changed = format!("{}{}{}", verb.to_ascii_lowercase(), ' ', rest);
            prop_assert_eq!(command::parse(&changed).is_ok(), parsed.is_ok());
        } else {
            prop_assert_eq!(command::parse(&lower).is_ok(), parsed.is_ok());
        }
        if let Ok(command) = parsed {
            prop_assert!(!command.verb().is_empty());
        }
    }

    #[test]
    fn the_parser_never_panics_on_bytes_read_lossily(bytes in prop::collection::vec(any::<u8>(), 0..120)) {
        let line = String::from_utf8_lossy(&bytes).into_owned();
        let _ = command::parse(&line);
        let _ = active::parse_port(&line);
        let _ = active::parse_eprt(&line);
    }

    #[test]
    fn a_pass_command_is_never_in_the_debug_text(password in "[a-zA-Z0-9]{6,20}") {
        let parsed = command::parse(&format!("PASS {password}")).unwrap();
        prop_assert!(matches!(parsed, Command::Pass(_)));
        let debug = format!("{parsed:?}");
        prop_assert!(!debug.contains(&password));
    }

    #[test]
    fn a_resolved_path_stays_under_the_root_and_resolves_to_itself(current in "[a-z./]{0,30}", requested in "[a-z./ ]{0,40}") {
        let current = FtpPath::resolve(&FtpPath::root(), &current).unwrap();
        if let Ok(path) = FtpPath::resolve(&current, &requested) {
            for component in path.components() {
                prop_assert!(!component.is_empty() && component != "." && component != ".." && !component.contains('/'));
            }
            // An absolute path gives the same path from anywhere
            let again = FtpPath::resolve(&FtpPath::root(), &path.to_string()).unwrap();
            prop_assert_eq!(&again, &path);
            prop_assert_eq!(FtpPath::resolve(&current, &path.to_string()).unwrap(), path);
        }
    }

    #[test]
    fn a_path_never_panics(current in "\\PC{0,40}", requested in "\\PC{0,5000}") {
        if let Ok(current) = FtpPath::resolve(&FtpPath::root(), &current) {
            let _ = FtpPath::resolve(&current, &requested);
        }
    }

    #[test]
    fn a_reply_is_made_of_whole_lines(code in 100u16..600, lines in prop::collection::vec("\\PC{0,30}|[\\r\\n\\x00 0-9a-z]{0,30}", 0..5)) {
        let encoded = Reply::multi(code, &lines).encode();
        let text = String::from_utf8(encoded).unwrap();
        prop_assert!(text.ends_with("\r\n"));
        let physical: Vec<&str> = text.split("\r\n").collect();
        // The last element is empty (after the final CRLF), and there is no CR or LF inside a line
        prop_assert_eq!(physical.last().copied(), Some(""));
        for line in &physical[..physical.len() - 1] {
            prop_assert!(!line.contains('\r') && !line.contains('\n'));
        }
        // The first line has the code and "-" or " ", only the last has the code and " "
        let prefix = format!("{code} ");
        let first = physical.first().copied().unwrap_or("");
        let count = physical.len() - 1;
        if count == 1 {
            prop_assert!(first.starts_with(&prefix));
        } else {
            let dash = format!("{code}-");
            prop_assert!(first.starts_with(&dash));
            prop_assert!(physical[count - 1].starts_with(&prefix));
            for middle in &physical[1..count - 1] {
                prop_assert!(!middle.starts_with(&prefix) && middle.starts_with(' '));
            }
        }
    }

    #[test]
    fn listings_have_a_line_for_each_entry_and_no_stray_line_ends(names in prop::collection::vec("\\PC{0,20}|[\\r\\n\\x00a-z]{0,20}", 0..6)) {
        let entries: Vec<_> = names.iter().map(|name| crate::backend::Entry::file(name.clone(), 1, None)).collect();
        for text in [listing::list(&entries, std::time::SystemTime::now()), listing::names(&entries), listing::mlsd(&entries, listing::Facts::default())] {
            prop_assert_eq!(text.matches("\r\n").count(), entries.len());
            prop_assert_eq!(text.matches('\n').count(), entries.len());
            prop_assert_eq!(text.matches('\r').count(), entries.len());
        }
    }

    #[test]
    fn ascii_conversion_is_the_same_however_the_input_is_split(bytes in prop::collection::vec(prop_oneof![Just(b'\r'), Just(b'\n'), any::<u8>()], 0..200), cut in any::<usize>()) {
        for direction in [Conversion::FromNetwork, Conversion::ToNetwork] {
            let whole = block_on(async {
                let mut out = Vec::new();
                Converting::new(std::io::Cursor::new(bytes.clone()), direction).read_to_end(&mut out).await.unwrap();
                out
            });
            let (first, second) = bytes.split_at(cut % (bytes.len() + 1));
            let split = block_on(async {
                let pieces = [first.to_vec(), second.to_vec()].into_iter().filter(|piece| !piece.is_empty()).collect();
                let mut out = Vec::new();
                Converting::new(Pieces(pieces), direction).read_to_end(&mut out).await.unwrap();
                out
            });
            prop_assert_eq!(split, whole);
        }
    }

    #[test]
    fn text_without_a_cr_goes_out_and_back_unchanged(bytes in prop::collection::vec(any::<u8>().prop_filter("no CR", |b| *b != b'\r'), 0..300)) {
        let result = block_on(async {
            let mut network = Vec::new();
            Converting::new(std::io::Cursor::new(bytes.clone()), Conversion::ToNetwork).read_to_end(&mut network).await.unwrap();
            let mut back = Vec::new();
            Converting::new(std::io::Cursor::new(network), Conversion::FromNetwork).read_to_end(&mut back).await.unwrap();
            back
        });
        prop_assert_eq!(result, bytes);
    }
}

//! Commands from the client: the text of one line parsed into a [`Command`] (RFC 959 section 4.1 and 5.3, RFC 1123 section 4.1.2.13 and 4.1.3.1,
//! RFC 2228 and 4217 for AUTH, PBSZ and PROT, RFC 2428 for EPSV and EPRT, RFC 2389 for FEAT and OPTS, RFC 3659 for SIZE, MDTM, MLST, MLSD and REST).
//!
//! The verb is case-insensitive. What follows the first space is the argument, kept as it is (a path may hold spaces, and a password too).
//! The parser decides only whether the line is a command and has the arguments it needs: what the command then does is the session's.

use std::fmt;

/// A password. It is never written by `Debug`, so a log of the commands can't hold one.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct Secret(pub(crate) String);

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(***)")
    }
}

/// The representation type of TYPE (RFC 959 section 3.1.1)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TypeArg {
    /// `A` or `A N`
    Ascii,
    /// `I`, and `L 8` (the same bytes)
    Image,
    /// A type that is understood and not supported: `A T`, `A C`, `E`, `L` with a byte size other than 8
    Unsupported,
}

/// A command, with its argument
#[derive(Debug, Clone, PartialEq, Eq)]
// The commands that are refused (RMD, DELE, RNFR, RNTO, APPE, SITE) are parsed with their arguments, which nothing reads
#[allow(dead_code)]
pub(crate) enum Command {
    User(String),
    Pass(Secret),
    Acct,
    Quit,
    Noop,
    Syst,
    Feat,
    Opts {
        name: String,
        value: Option<String>,
    },
    Help(Option<String>),
    Stat(Option<String>),
    Pwd,
    Cwd(String),
    Cdup,
    Mkd(String),
    Rmd(String),
    Dele(String),
    Rnfr(String),
    Rnto(String),
    Type(TypeArg),
    Mode(char),
    Stru(char),
    Allo,
    Auth(String),
    Pbsz(String),
    Prot(String),
    Ccc,
    Pasv,
    Epsv(Option<String>),
    Port(String),
    Eprt(String),
    Stor(String),
    Appe(String),
    Retr(String),
    List(Option<String>),
    Nlst(Option<String>),
    Mlsd(Option<String>),
    Mlst(Option<String>),
    Size(String),
    Mdtm(String),
    Rest(u64),
    Abor,
    Site(String),
    /// A command of RFC 959 that this library doesn't do (REIN, SMNT, STOU), with its verb
    Unsupported(&'static str),
}

/// Why a line is not a command
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ParseError {
    /// Not a command the library knows: 500
    Unknown,
    /// A command with arguments it doesn't take, or without those it needs: 501
    Syntax,
}

/// The commands the library recognises, with their syntax, for HELP
pub(crate) const SYNTAX: &[(&str, &str)] = &[
    ("ABOR", "ABOR"),
    ("ACCT", "ACCT <account>"),
    ("ALLO", "ALLO <size>"),
    ("APPE", "APPE <file>"),
    ("AUTH", "AUTH TLS"),
    ("CCC", "CCC"),
    ("CDUP", "CDUP"),
    ("CWD", "CWD <directory>"),
    ("DELE", "DELE <file>"),
    ("EPRT", "EPRT |<af>|<address>|<port>|"),
    ("EPSV", "EPSV [<af> | ALL]"),
    ("FEAT", "FEAT"),
    ("HELP", "HELP [<command>]"),
    ("LIST", "LIST [<path>]"),
    ("MDTM", "MDTM <file>"),
    ("MKD", "MKD <directory>"),
    ("MLSD", "MLSD [<directory>]"),
    ("MLST", "MLST [<path>]"),
    ("MODE", "MODE S"),
    ("NLST", "NLST [<path>]"),
    ("NOOP", "NOOP"),
    ("OPTS", "OPTS <command> [<options>]"),
    ("PASS", "PASS <password>"),
    ("PASV", "PASV"),
    ("PBSZ", "PBSZ 0"),
    ("PORT", "PORT <h1,h2,h3,h4,p1,p2>"),
    ("PROT", "PROT C | P"),
    ("PWD", "PWD"),
    ("QUIT", "QUIT"),
    ("REST", "REST <offset>"),
    ("RETR", "RETR <file>"),
    ("RMD", "RMD <directory>"),
    ("RNFR", "RNFR <file>"),
    ("RNTO", "RNTO <file>"),
    ("SITE", "SITE <command>"),
    ("SIZE", "SIZE <file>"),
    ("STAT", "STAT [<path>]"),
    ("STOR", "STOR <file>"),
    ("STRU", "STRU F"),
    ("SYST", "SYST"),
    ("TYPE", "TYPE A | I | L 8"),
    ("USER", "USER <name>"),
];

impl Command {
    /// The verb, in capitals, as the logs write it
    pub(crate) fn verb(&self) -> &'static str {
        match self {
            Command::User(_) => "USER",
            Command::Pass(_) => "PASS",
            Command::Acct => "ACCT",
            Command::Quit => "QUIT",
            Command::Noop => "NOOP",
            Command::Syst => "SYST",
            Command::Feat => "FEAT",
            Command::Opts { .. } => "OPTS",
            Command::Help(_) => "HELP",
            Command::Stat(_) => "STAT",
            Command::Pwd => "PWD",
            Command::Cwd(_) => "CWD",
            Command::Cdup => "CDUP",
            Command::Mkd(_) => "MKD",
            Command::Rmd(_) => "RMD",
            Command::Dele(_) => "DELE",
            Command::Rnfr(_) => "RNFR",
            Command::Rnto(_) => "RNTO",
            Command::Type(_) => "TYPE",
            Command::Mode(_) => "MODE",
            Command::Stru(_) => "STRU",
            Command::Allo => "ALLO",
            Command::Auth(_) => "AUTH",
            Command::Pbsz(_) => "PBSZ",
            Command::Prot(_) => "PROT",
            Command::Ccc => "CCC",
            Command::Pasv => "PASV",
            Command::Epsv(_) => "EPSV",
            Command::Port(_) => "PORT",
            Command::Eprt(_) => "EPRT",
            Command::Stor(_) => "STOR",
            Command::Appe(_) => "APPE",
            Command::Retr(_) => "RETR",
            Command::List(_) => "LIST",
            Command::Nlst(_) => "NLST",
            Command::Mlsd(_) => "MLSD",
            Command::Mlst(_) => "MLST",
            Command::Size(_) => "SIZE",
            Command::Mdtm(_) => "MDTM",
            Command::Rest(_) => "REST",
            Command::Abor => "ABOR",
            Command::Site(_) => "SITE",
            Command::Unsupported(verb) => verb,
        }
    }
}

/// Parses one line (without its line end)
pub(crate) fn parse(line: &str) -> Result<Command, ParseError> {
    let (verb, rest) = match line.split_once(' ') {
        Some((verb, rest)) => (verb, Some(rest)),
        None => (line, None),
    };
    if verb.is_empty() || !verb.bytes().all(|b| b.is_ascii_alphabetic()) {
        return Err(ParseError::Unknown);
    }
    let verb = verb.to_ascii_uppercase();
    let command = match verb.as_str() {
        "USER" => Command::User(required(rest)?),
        // A password may be empty (some devices send none) and may hold spaces
        "PASS" => Command::Pass(Secret(rest.map(str::to_string).unwrap_or_default())),
        "ACCT" => {
            required(rest)?;
            Command::Acct
        }
        "QUIT" => Command::Quit,
        "NOOP" => Command::Noop,
        "SYST" => no_argument(rest, Command::Syst)?,
        "FEAT" => no_argument(rest, Command::Feat)?,
        "OPTS" => {
            let rest = required(rest)?;
            match rest.split_once(' ') {
                Some((name, value)) => Command::Opts { name: name.to_ascii_uppercase(), value: Some(value.trim().to_string()) },
                None => Command::Opts { name: rest.to_ascii_uppercase(), value: None },
            }
        }
        "HELP" => Command::Help(optional(rest)),
        "STAT" => Command::Stat(optional(rest)),
        "PWD" | "XPWD" => no_argument(rest, Command::Pwd)?,
        "CWD" | "XCWD" => Command::Cwd(required(rest)?),
        "CDUP" | "XCUP" => no_argument(rest, Command::Cdup)?,
        "MKD" | "XMKD" => Command::Mkd(required(rest)?),
        "RMD" | "XRMD" => Command::Rmd(required(rest)?),
        "DELE" => Command::Dele(required(rest)?),
        "RNFR" => Command::Rnfr(required(rest)?),
        "RNTO" => Command::Rnto(required(rest)?),
        "TYPE" => Command::Type(type_argument(rest)?),
        "MODE" => Command::Mode(one_letter(rest)?),
        "STRU" => Command::Stru(one_letter(rest)?),
        "ALLO" => {
            required(rest)?;
            Command::Allo
        }
        "AUTH" => Command::Auth(required(rest)?),
        "PBSZ" => Command::Pbsz(required(rest)?),
        "PROT" => Command::Prot(required(rest)?),
        "CCC" => no_argument(rest, Command::Ccc)?,
        "PASV" => no_argument(rest, Command::Pasv)?,
        "EPSV" => Command::Epsv(optional(rest)),
        "PORT" => Command::Port(required(rest)?),
        "EPRT" => Command::Eprt(required(rest)?),
        "STOR" => Command::Stor(required(rest)?),
        "APPE" => Command::Appe(required(rest)?),
        "RETR" => Command::Retr(required(rest)?),
        "LIST" => Command::List(path_after_options(rest)),
        "NLST" => Command::Nlst(path_after_options(rest)),
        "MLSD" => Command::Mlsd(optional(rest)),
        "MLST" => Command::Mlst(optional(rest)),
        "SIZE" => Command::Size(required(rest)?),
        "MDTM" => Command::Mdtm(required(rest)?),
        "REST" => Command::Rest(required(rest)?.trim().parse().map_err(|_| ParseError::Syntax)?),
        "ABOR" => no_argument(rest, Command::Abor)?,
        "SITE" => Command::Site(rest.unwrap_or("").to_string()),
        "REIN" => Command::Unsupported("REIN"),
        "SMNT" => Command::Unsupported("SMNT"),
        "STOU" => Command::Unsupported("STOU"),
        _ => return Err(ParseError::Unknown),
    };
    Ok(command)
}

fn required(rest: Option<&str>) -> Result<String, ParseError> {
    match rest {
        Some(rest) if !rest.is_empty() => Ok(rest.to_string()),
        _ => Err(ParseError::Syntax),
    }
}

fn optional(rest: Option<&str>) -> Option<String> {
    rest.filter(|rest| !rest.is_empty()).map(str::to_string)
}

/// Spaces after a command that takes no argument are not an argument
fn no_argument(rest: Option<&str>, command: Command) -> Result<Command, ParseError> {
    match rest {
        Some(rest) if !rest.trim().is_empty() => Err(ParseError::Syntax),
        _ => Ok(command),
    }
}

/// Clients send `LIST -la` and `NLST -a /dir`: the options are dropped (the listing has one format), what follows them is the path
fn path_after_options(rest: Option<&str>) -> Option<String> {
    let mut rest = rest.unwrap_or("");
    while rest.starts_with('-') {
        rest = match rest.split_once(' ') {
            Some((_, after)) => after.trim_start_matches(' '),
            None => "",
        };
    }
    (!rest.is_empty()).then(|| rest.to_string())
}

fn one_letter(rest: Option<&str>) -> Result<char, ParseError> {
    let mut chars = rest.unwrap_or("").trim().chars();
    match (chars.next(), chars.next()) {
        (Some(letter), None) if letter.is_ascii_alphabetic() => Ok(letter.to_ascii_uppercase()),
        _ => Err(ParseError::Syntax),
    }
}

fn type_argument(rest: Option<&str>) -> Result<TypeArg, ParseError> {
    let upper = rest.unwrap_or("").to_ascii_uppercase();
    let mut parts = upper.split_whitespace();
    let parsed = match (parts.next(), parts.next(), parts.next()) {
        (Some("A"), None | Some("N"), None) => TypeArg::Ascii,
        (Some("A"), Some("T" | "C"), None) => TypeArg::Unsupported,
        (Some("I"), None, None) => TypeArg::Image,
        (Some("L"), Some("8"), None) => TypeArg::Image,
        (Some("L"), Some(size), None) if size.bytes().all(|b| b.is_ascii_digit()) => TypeArg::Unsupported,
        (Some("E"), None | Some("N" | "T" | "C"), None) => TypeArg::Unsupported,
        _ => return Err(ParseError::Syntax),
    };
    Ok(parsed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok(line: &str) -> Command {
        parse(line).unwrap_or_else(|e| panic!("{line:?}: {e:?}"))
    }

    fn s(text: &str) -> String {
        text.to_string()
    }

    #[test]
    fn the_verb_is_case_insensitive() {
        assert_eq!(ok("noop"), Command::Noop);
        assert_eq!(ok("NoOp"), Command::Noop);
        assert_eq!(ok("user Alice"), Command::User(s("Alice")));
        assert_eq!(ok("Cwd /a"), Command::Cwd(s("/a")));
    }

    #[test]
    fn user_and_pass() {
        assert_eq!(ok("USER alice"), Command::User(s("alice")));
        assert_eq!(ok("USER a b"), Command::User(s("a b")));
        assert_eq!(parse("USER"), Err(ParseError::Syntax));
        assert_eq!(parse("USER "), Err(ParseError::Syntax));
        assert_eq!(ok("PASS  secret with spaces "), Command::Pass(Secret(s(" secret with spaces "))));
        assert_eq!(ok("PASS"), Command::Pass(Secret(String::new())));
        assert_eq!(ok("PASS "), Command::Pass(Secret(String::new())));
    }

    #[test]
    fn a_password_is_not_in_the_debug_text() {
        let text = format!("{:?}", ok("PASS hunter2"));
        assert!(!text.contains("hunter2"), "{text}");
    }

    #[test]
    fn commands_without_an_argument() {
        for (line, command) in [
            ("PWD", Command::Pwd),
            ("XPWD", Command::Pwd),
            ("CDUP", Command::Cdup),
            ("XCUP", Command::Cdup),
            ("SYST", Command::Syst),
            ("FEAT", Command::Feat),
            ("PASV", Command::Pasv),
            ("ABOR", Command::Abor),
            ("CCC", Command::Ccc),
            ("QUIT", Command::Quit),
            ("NOOP", Command::Noop),
        ] {
            assert_eq!(ok(line), command, "{line}");
            assert_eq!(ok(&format!("{line} ")), command, "{line} with a space");
        }
        for line in ["PWD x", "CDUP ..", "SYST x", "FEAT x", "PASV 1", "ABOR now", "CCC x", "XPWD /"] {
            assert_eq!(parse(line), Err(ParseError::Syntax), "{line}");
        }
    }

    #[test]
    fn noop_and_quit_take_what_a_client_adds() {
        assert_eq!(ok("NOOP anything"), Command::Noop);
        assert_eq!(ok("QUIT now"), Command::Quit);
    }

    #[test]
    fn commands_with_a_path() {
        assert_eq!(ok("CWD /a b/c"), Command::Cwd(s("/a b/c")));
        assert_eq!(ok("XCWD x"), Command::Cwd(s("x")));
        assert_eq!(ok("MKD  two spaces"), Command::Mkd(s(" two spaces")));
        assert_eq!(ok("XMKD d"), Command::Mkd(s("d")));
        assert_eq!(ok("RMD d"), Command::Rmd(s("d")));
        assert_eq!(ok("XRMD d"), Command::Rmd(s("d")));
        assert_eq!(ok("DELE f"), Command::Dele(s("f")));
        assert_eq!(ok("RNFR f"), Command::Rnfr(s("f")));
        assert_eq!(ok("RNTO g"), Command::Rnto(s("g")));
        assert_eq!(ok("STOR 文件 1.pdf"), Command::Stor(s("文件 1.pdf")));
        assert_eq!(ok("APPE f"), Command::Appe(s("f")));
        assert_eq!(ok("RETR f"), Command::Retr(s("f")));
        assert_eq!(ok("SIZE f"), Command::Size(s("f")));
        assert_eq!(ok("MDTM f"), Command::Mdtm(s("f")));
        for verb in ["CWD", "XCWD", "MKD", "XMKD", "RMD", "XRMD", "DELE", "RNFR", "RNTO", "STOR", "APPE", "RETR", "SIZE", "MDTM"] {
            assert_eq!(parse(verb), Err(ParseError::Syntax), "{verb}");
            assert_eq!(parse(&format!("{verb} ")), Err(ParseError::Syntax), "{verb} with a space");
        }
    }

    #[test]
    fn listings_drop_the_options_and_keep_the_path() {
        assert_eq!(ok("LIST"), Command::List(None));
        assert_eq!(ok("LIST -la"), Command::List(None));
        assert_eq!(ok("LIST -a -l /dir with space"), Command::List(Some(s("/dir with space"))));
        assert_eq!(ok("LIST /dir"), Command::List(Some(s("/dir"))));
        assert_eq!(ok("NLST -a"), Command::Nlst(None));
        assert_eq!(ok("NLST sub"), Command::Nlst(Some(s("sub"))));
        assert_eq!(ok("MLSD"), Command::Mlsd(None));
        assert_eq!(ok("MLSD sub"), Command::Mlsd(Some(s("sub"))));
        assert_eq!(ok("MLST"), Command::Mlst(None));
        assert_eq!(ok("MLST -x"), Command::Mlst(Some(s("-x"))));
    }

    #[test]
    fn type_mode_and_structure() {
        assert_eq!(ok("TYPE A"), Command::Type(TypeArg::Ascii));
        assert_eq!(ok("TYPE a n"), Command::Type(TypeArg::Ascii));
        assert_eq!(ok("TYPE I"), Command::Type(TypeArg::Image));
        assert_eq!(ok("TYPE L 8"), Command::Type(TypeArg::Image));
        assert_eq!(ok("TYPE L 7"), Command::Type(TypeArg::Unsupported));
        assert_eq!(ok("TYPE A T"), Command::Type(TypeArg::Unsupported));
        assert_eq!(ok("TYPE A C"), Command::Type(TypeArg::Unsupported));
        assert_eq!(ok("TYPE E"), Command::Type(TypeArg::Unsupported));
        for line in ["TYPE", "TYPE X", "TYPE A X", "TYPE I I", "TYPE L", "TYPE L x", "TYPE A N N"] {
            assert_eq!(parse(line), Err(ParseError::Syntax), "{line}");
        }
        assert_eq!(ok("MODE S"), Command::Mode('S'));
        assert_eq!(ok("mode b"), Command::Mode('B'));
        assert_eq!(ok("STRU F"), Command::Stru('F'));
        assert_eq!(ok("STRU r"), Command::Stru('R'));
        for line in ["MODE", "MODE SS", "MODE 1", "STRU", "STRU FF", "STRU "] {
            assert_eq!(parse(line), Err(ParseError::Syntax), "{line}");
        }
    }

    #[test]
    fn features_and_options() {
        assert_eq!(ok("OPTS UTF8 ON"), Command::Opts { name: s("UTF8"), value: Some(s("ON")) });
        assert_eq!(ok("opts utf8 on"), Command::Opts { name: s("UTF8"), value: Some(s("on")) });
        assert_eq!(ok("OPTS MLST type;size;"), Command::Opts { name: s("MLST"), value: Some(s("type;size;")) });
        assert_eq!(ok("OPTS X"), Command::Opts { name: s("X"), value: None });
        assert_eq!(parse("OPTS"), Err(ParseError::Syntax));
    }

    #[test]
    fn help_stat_acct_allo_site() {
        assert_eq!(ok("HELP"), Command::Help(None));
        assert_eq!(ok("HELP STOR"), Command::Help(Some(s("STOR"))));
        assert_eq!(ok("STAT"), Command::Stat(None));
        assert_eq!(ok("STAT /a"), Command::Stat(Some(s("/a"))));
        assert_eq!(ok("ACCT x"), Command::Acct);
        assert_eq!(parse("ACCT"), Err(ParseError::Syntax));
        assert_eq!(ok("ALLO 1000"), Command::Allo);
        assert_eq!(ok("ALLO 1000 R 4096"), Command::Allo);
        assert_eq!(parse("ALLO"), Err(ParseError::Syntax));
        assert_eq!(ok("SITE CHMOD 755 f"), Command::Site(s("CHMOD 755 f")));
        assert_eq!(ok("SITE"), Command::Site(String::new()));
    }

    #[test]
    fn tls_commands() {
        assert_eq!(ok("AUTH TLS"), Command::Auth(s("TLS")));
        assert_eq!(ok("AUTH SSL"), Command::Auth(s("SSL")));
        assert_eq!(ok("PBSZ 0"), Command::Pbsz(s("0")));
        assert_eq!(ok("PROT P"), Command::Prot(s("P")));
        for verb in ["AUTH", "PBSZ", "PROT"] {
            assert_eq!(parse(verb), Err(ParseError::Syntax), "{verb}");
        }
    }

    #[test]
    fn data_connection_commands() {
        assert_eq!(ok("EPSV"), Command::Epsv(None));
        assert_eq!(ok("EPSV ALL"), Command::Epsv(Some(s("ALL"))));
        assert_eq!(ok("EPSV 2"), Command::Epsv(Some(s("2"))));
        assert_eq!(ok("PORT 127,0,0,1,4,1"), Command::Port(s("127,0,0,1,4,1")));
        assert_eq!(ok("EPRT |1|127.0.0.1|1025|"), Command::Eprt(s("|1|127.0.0.1|1025|")));
        assert_eq!(parse("PORT"), Err(ParseError::Syntax));
        assert_eq!(parse("EPRT"), Err(ParseError::Syntax));
    }

    #[test]
    fn rest_takes_a_decimal_number() {
        assert_eq!(ok("REST 0"), Command::Rest(0));
        assert_eq!(ok("REST 1234567890123"), Command::Rest(1_234_567_890_123));
        for line in ["REST", "REST -1", "REST x", "REST 1.5", "REST 99999999999999999999999"] {
            assert_eq!(parse(line), Err(ParseError::Syntax), "{line}");
        }
    }

    #[test]
    fn commands_the_library_knows_and_does_not_do() {
        assert_eq!(ok("REIN"), Command::Unsupported("REIN"));
        assert_eq!(ok("SMNT /x"), Command::Unsupported("SMNT"));
        assert_eq!(ok("STOU"), Command::Unsupported("STOU"));
        assert_eq!(ok("REIN").verb(), "REIN");
    }

    #[test]
    fn what_is_not_a_command() {
        for line in ["", " ", " NOOP", "N0OP", "NOOP\0", "\u{fffd}", "FOO", "LPRT 1", "1234", "-", "NO-OP", "文件"] {
            assert_eq!(parse(line), Err(ParseError::Unknown), "{line:?}");
        }
    }

    #[test]
    fn every_verb_in_the_help_table_is_a_command_with_that_verb() {
        for (verb, syntax) in SYNTAX {
            assert!(syntax.starts_with(verb), "{verb}");
            // Some of them need an argument to be a command
            let parsed = ["", " x", " 1", " 1,2,3,4,5,6", " A", " S", " F", " 0", " P"].iter().find_map(|argument| parse(&format!("{verb}{argument}")).ok());
            assert_eq!(parsed.map(|c| c.verb()), Some(*verb), "{verb}");
        }
    }

    #[test]
    fn the_help_table_is_in_order() {
        let verbs: Vec<_> = SYNTAX.iter().map(|(verb, _)| *verb).collect();
        let mut sorted = verbs.clone();
        sorted.sort();
        assert_eq!(verbs, sorted);
    }
}

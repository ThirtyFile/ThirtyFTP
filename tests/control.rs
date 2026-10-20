//! The control connection over plain FTP: sign-in, navigation, the settings commands, and what a client may send that it should not

mod common;

use common::*;
use std::time::{Duration, Instant};
use thirtyftp::{Config, SessionEnd};

fn texts(reply: &(u16, Vec<String>)) -> String {
    reply.1.join("\n")
}

#[tokio::test]
async fn the_greeting_comes_first_and_can_be_set() {
    let server = start_with({
        let mut config = Config::default();
        config.greeting = "Scan here".to_string();
        config
    })
    .await;
    let mut client = Client::connect_silent(&server).await;
    assert_eq!(client.reply().await, (220, vec!["Scan here".to_string()]));
    let server = start().await;
    let mut client = Client::connect_silent(&server).await;
    assert_eq!(client.reply().await, (220, vec!["Service ready for new user.".to_string()]));
}

#[tokio::test]
async fn signing_in() {
    let server = start().await;
    let mut client = Client::connect(&server).await;
    assert_eq!(client.command("USER alice").await.0, 331);
    assert_eq!(client.command("PASS secret").await, (230, vec!["User logged in, proceed.".to_string()]));
    assert_eq!(server.events.signed_in.lock().unwrap().as_slice(), ["alice"]);
    let (context, user) = server.backend.logins.lock().unwrap()[0].clone();
    assert_eq!(user, "alice");
    assert!(context.peer.ip().is_loopback());
    assert_eq!(context.local, server.address);
    assert!(!context.encrypted);
}

#[tokio::test]
async fn a_password_may_hold_spaces_or_be_empty() {
    let server = start().await;
    let mut client = Client::connect(&server).await;
    assert_eq!(client.code("USER space").await, 331);
    assert_eq!(client.code("PASS  pass word ").await, 230);
    let mut client = Client::connect(&server).await;
    assert_eq!(client.code("USER empty").await, 331);
    assert_eq!(client.code("PASS").await, 230);
}

#[tokio::test]
async fn a_wrong_password_is_530_and_the_next_try_starts_with_user() {
    let server = start().await;
    let mut client = Client::connect(&server).await;
    assert_eq!(client.code("USER alice").await, 331);
    assert_eq!(client.command("PASS wrong").await, (530, vec!["Login incorrect.".to_string()]));
    // The failed attempt used the name: PASS alone is a bad sequence
    assert_eq!(client.code("PASS secret").await, 503);
    assert_eq!(client.code("USER alice").await, 331);
    assert_eq!(client.code("PASS secret").await, 230);
    assert_eq!(server.events.failed.lock().unwrap().as_slice(), ["alice"]);
}

#[tokio::test]
async fn pass_before_user_is_a_bad_sequence() {
    let server = start().await;
    let mut client = Client::connect(&server).await;
    assert_eq!(client.code("PASS secret").await, 503);
    assert!(server.backend.logins.lock().unwrap().is_empty(), "the backend must not be asked");
}

#[tokio::test]
async fn the_backend_can_refuse_with_a_reason() {
    let server = start().await;
    let mut client = Client::connect(&server).await;
    assert_eq!(client.code("USER blocked").await, 331);
    assert_eq!(client.command("PASS x").await, (530, vec!["This user is blocked.".to_string()]));
}

#[tokio::test]
async fn too_many_wrong_passwords_close_the_connection_with_421() {
    let server = start().await;
    let mut client = Client::connect(&server).await;
    for _ in 0..2 {
        assert_eq!(client.code("USER alice").await, 331);
        assert_eq!(client.code("PASS wrong").await, 530);
    }
    assert_eq!(client.code("USER alice").await, 331);
    assert_eq!(client.code("PASS wrong").await, 421);
    assert!(client.closed().await);
    eventually(|| matches!(server.ends.lock().unwrap().first(), Some(SessionEnd::TooManyLoginFailures))).await;
}

#[tokio::test]
async fn a_backend_that_is_down_gives_421_and_closes() {
    let server = start().await;
    *server.backend.down.lock().unwrap() = true;
    let mut client = Client::connect(&server).await;
    assert_eq!(client.code("USER alice").await, 331);
    assert_eq!(client.code("PASS secret").await, 421);
    assert!(client.closed().await);
}

#[tokio::test]
async fn a_signed_in_user_cannot_sign_in_again() {
    let server = start().await;
    let mut client = Client::connect(&server).await;
    client.login().await;
    assert_eq!(client.code("USER bob").await, 503);
    assert_eq!(client.code("PASS hunter2").await, 503);
    assert_eq!(client.command("PWD").await.0, 257);
}

#[tokio::test]
async fn commands_that_need_a_user_are_530_before_signing_in() {
    let server = start().await;
    let mut client = Client::connect(&server).await;
    for line in [
        "PWD",
        "CWD /",
        "CDUP",
        "MKD x",
        "RMD x",
        "DELE x",
        "RNFR x",
        "RNTO x",
        "TYPE I",
        "MODE S",
        "STRU F",
        "ALLO 1",
        "PASV",
        "EPSV",
        "PORT 1,2,3,4,5,6",
        "STOR x",
        "RETR x",
        "LIST",
        "NLST",
        "MLSD",
        "SIZE x",
        "MDTM x",
        "REST 1",
        "STAT /",
        "SITE X",
    ] {
        assert_eq!(client.code(line).await, 530, "{line}");
    }
    // A user name is not a sign-in
    assert_eq!(client.code("USER alice").await, 331);
    assert_eq!(client.code("PWD").await, 530);
}

#[tokio::test]
async fn commands_that_do_not_need_a_user() {
    let server = start().await;
    let mut client = Client::connect(&server).await;
    for line in ["NOOP", "SYST", "FEAT", "OPTS UTF8 ON", "HELP", "STAT", "ABOR", "ACCT x"] {
        let code = client.code(line).await;
        assert!(code < 400, "{line}: {code}");
    }
}

#[tokio::test]
async fn the_working_directory() {
    let server = start().await;
    let mut client = Client::connect(&server).await;
    client.login().await;
    assert_eq!(client.command("PWD").await, (257, vec!["\"/\" is the current directory.".to_string()]));
    assert_eq!(client.command("MKD scans").await, (257, vec!["\"/scans\" created.".to_string()]));
    assert_eq!(client.command("MKD scans/2026").await.0, 257);
    assert_eq!(client.code("CWD scans").await, 250);
    assert_eq!(client.command("PWD").await.1, ["\"/scans\" is the current directory."]);
    assert_eq!(client.code("CWD 2026").await, 250);
    assert_eq!(client.command("PWD").await.1, ["\"/scans/2026\" is the current directory."]);
    assert_eq!(client.code("CDUP").await, 250);
    assert_eq!(client.command("PWD").await.1, ["\"/scans\" is the current directory."]);
    assert_eq!(client.code("CWD /scans/2026/../..").await, 250);
    assert_eq!(client.command("PWD").await.1, ["\"/\" is the current directory."]);
}

#[tokio::test]
async fn nothing_goes_above_the_root() {
    let server = start().await;
    let mut client = Client::connect(&server).await;
    client.login().await;
    assert_eq!(client.code("CDUP").await, 250);
    assert_eq!(client.code("CWD ../../..").await, 250);
    assert_eq!(client.command("PWD").await.1, ["\"/\" is the current directory."]);
    assert_eq!(client.code("CWD /../../etc").await, 550);
}

#[tokio::test]
async fn a_directory_that_is_not_there_is_550_and_the_directory_stays() {
    let server = start().await;
    let mut client = Client::connect(&server).await;
    client.login().await;
    assert_eq!(client.code("MKD a").await, 257);
    assert_eq!(client.code("CWD a").await, 250);
    assert_eq!(client.code("CWD nowhere").await, 550);
    assert_eq!(client.command("PWD").await.1, ["\"/a\" is the current directory."]);
    assert_eq!(client.code("MKD /a").await, 550, "it exists already");
    assert_eq!(client.code("MKD /nowhere/b").await, 550, "its parent doesn't exist");
}

#[tokio::test]
async fn a_name_with_spaces_unicode_and_quotes() {
    let server = start().await;
    let mut client = Client::connect(&server).await;
    client.login().await;
    assert_eq!(client.command("MKD My Scans 文件").await.1, ["\"/My Scans 文件\" created."]);
    assert_eq!(client.code("CWD My Scans 文件").await, 250);
    // A double quote in the name is doubled in the reply (RFC 959 appendix II)
    assert_eq!(client.command("MKD say \"hi\"").await.1, ["\"/My Scans 文件/say \"\"hi\"\"\" created."]);
}

#[tokio::test]
async fn the_x_forms_are_the_same_commands() {
    let server = start().await;
    let mut client = Client::connect(&server).await;
    client.login().await;
    assert_eq!(client.code("XMKD d").await, 257);
    assert_eq!(client.code("XCWD d").await, 250);
    assert_eq!(client.command("XPWD").await.0, 257);
    assert_eq!(client.code("XCUP").await, 250);
    assert_eq!(client.code("XRMD d").await, 550, "removing is refused on purpose");
}

#[tokio::test]
async fn control_characters_in_a_path_are_553() {
    let server = start_with({
        let mut config = Config::default();
        config.limits.max_line = 10_000;
        config
    })
    .await;
    let mut client = Client::connect(&server).await;
    client.login().await;
    assert_eq!(client.code("MKD a\u{1}b").await, 553);
    assert_eq!(client.code("CWD a\0b").await, 553);
    let long = format!("MKD {}", "a/".repeat(2100));
    assert_eq!(client.code(&long).await, 553, "a path over 4096 bytes");
    assert_eq!(client.command("PWD").await.0, 257, "and the session goes on");
}

#[tokio::test]
async fn what_ftp_refuses_on_purpose_is_550_and_not_502() {
    let server = start().await;
    let mut client = Client::connect(&server).await;
    client.login().await;
    for line in ["DELE f", "RMD d", "XRMD d", "RNFR f", "RNTO g", "APPE f"] {
        assert_eq!(client.command(line).await, (550, vec!["Permission denied.".to_string()]), "{line}");
    }
}

#[tokio::test]
async fn commands_that_are_not_done() {
    let server = start().await;
    let mut client = Client::connect(&server).await;
    client.login().await;
    for line in ["REIN", "SMNT /x", "STOU", "PORT 127,0,0,1,4,1", "EPRT |1|127.0.0.1|4000|", "SITE CHMOD 777 f"] {
        assert_eq!(client.code(line).await, 502, "{line}");
    }
    assert_eq!(client.code("CCC").await, 534);
}

#[tokio::test]
async fn type_mode_structure_and_allocation() {
    let server = start().await;
    let mut client = Client::connect(&server).await;
    client.login().await;
    for line in ["TYPE A", "TYPE A N", "TYPE I", "TYPE L 8", "type i", "MODE S", "STRU F"] {
        assert_eq!(client.code(line).await, 200, "{line}");
    }
    for line in ["TYPE E", "TYPE A T", "TYPE A C", "TYPE L 7", "MODE B", "MODE C", "STRU R", "STRU P"] {
        assert_eq!(client.code(line).await, 504, "{line}");
    }
    for line in ["TYPE", "TYPE Q", "MODE", "MODE X", "MODE SS", "STRU", "STRU X"] {
        assert_eq!(client.code(line).await, 501, "{line}");
    }
    assert_eq!(client.code("ALLO 100").await, 202);
    assert_eq!(client.code("ALLO 100 R 200").await, 202);
    assert_eq!(client.code("ALLO").await, 501);
    assert_eq!(client.code("ACCT any").await, 202);
}

#[tokio::test]
async fn the_information_commands() {
    let server = start().await;
    let mut client = Client::connect(&server).await;
    assert_eq!(client.command("SYST").await, (215, vec!["UNIX Type: L8".to_string()]));
    let feat = client.command("FEAT").await;
    assert_eq!(feat.0, 211);
    assert_eq!(feat.1.first().map(String::as_str), Some("Extensions supported:"));
    assert!(feat.1.contains(&"UTF8".to_string()) || feat.1.contains(&" UTF8".to_string()), "{feat:?}");
    assert_eq!(client.code("OPTS UTF8 ON").await, 200);
    assert_eq!(client.code("opts utf8 on").await, 200);
    assert_eq!(client.code("OPTS UTF8 OFF").await, 504);
    assert_eq!(client.code("OPTS MLST type;").await, 200);
    assert_eq!(client.code("OPTS NOTHING x").await, 501);
    assert_eq!(client.code("OPTS").await, 501);
    let help = client.command("HELP").await;
    assert_eq!(help.0, 214);
    assert!(texts(&help).contains("USER") && texts(&help).contains("STOR"), "{help:?}");
    assert_eq!(client.command("HELP stor").await, (214, vec!["Syntax: STOR <file>".to_string()]));
    assert_eq!(client.code("HELP nothing").await, 501);
}

#[tokio::test]
async fn stat_shows_the_connection() {
    let server = start().await;
    let mut client = Client::connect(&server).await;
    let before = client.command("STAT").await;
    assert_eq!(before.0, 211);
    assert!(texts(&before).contains("Not logged in"), "{before:?}");
    client.login().await;
    assert_eq!(client.code("TYPE A").await, 200);
    let after = client.command("STAT").await;
    assert!(texts(&after).contains("Logged in as alice"), "{after:?}");
    assert!(texts(&after).contains("TYPE: ASCII"), "{after:?}");
}

#[tokio::test]
async fn quit_closes_the_connection() {
    let server = start().await;
    let mut client = Client::connect(&server).await;
    assert_eq!(client.command("QUIT").await, (221, vec!["Service closing control connection.".to_string()]));
    assert!(client.closed().await);
    eventually(|| matches!(server.ends.lock().unwrap().first(), Some(SessionEnd::Quit))).await;
}

#[tokio::test]
async fn abor_without_a_transfer_is_answered() {
    let server = start().await;
    let mut client = Client::connect(&server).await;
    client.login().await;
    assert_eq!(client.code("ABOR").await, 226);
    // The Telnet sequence a client sends before ABOR (RFC 959 section 4.1.3)
    client.send_bytes(b"\xff\xf4\xff\xf2ABOR\r\n").await;
    assert_eq!(client.reply().await.0, 226);
}

#[tokio::test]
async fn unknown_commands_are_500_and_missing_arguments_501() {
    let server = start().await;
    let mut client = Client::connect(&server).await;
    client.login().await;
    for line in ["FOO", "", " ", "NOOP\0", "LPRT x", "1234", "文件", "- -"] {
        assert_eq!(client.code(line).await, 500, "{line:?}");
    }
    for line in ["USER", "CWD", "MKD", "PWD x", "CDUP x", "SYST x", "REST", "REST x", "TYPE", "PORT", "AUTH"] {
        assert_eq!(client.code(line).await, 501, "{line:?}");
    }
    assert_eq!(client.code("NOOP").await, 200, "and the session goes on");
}

#[tokio::test]
async fn commands_are_case_insensitive_and_a_lone_lf_ends_a_line() {
    let server = start().await;
    let mut client = Client::connect(&server).await;
    client.send_bytes(b"user alice\npass secret\nPwd\n").await;
    assert_eq!(client.reply().await.0, 331);
    assert_eq!(client.reply().await.0, 230);
    assert_eq!(client.reply().await.0, 257);
}

#[tokio::test]
async fn telnet_commands_are_removed_from_a_line() {
    let server = start().await;
    let mut client = Client::connect(&server).await;
    client.send_bytes(b"\xff\xfb\x01\xff\xfd\x03NOOP\r\n").await;
    assert_eq!(client.reply().await.0, 200);
    client.send_bytes(b"\xff\xfa\x18\x00xterm\xff\xf0USER ali\xff\xf1ce\r\n").await;
    assert_eq!(client.reply().await.0, 331);
    assert_eq!(client.code("PASS secret").await, 230, "the name was alice");
}

#[tokio::test]
async fn a_line_that_is_too_long_is_500_and_the_session_goes_on() {
    let server = start().await;
    let mut client = Client::connect(&server).await;
    client.login().await;
    client.send(&format!("MKD {}", "a".repeat(100_000))).await;
    assert_eq!(client.reply().await, (500, vec!["Command line too long.".to_string()]));
    assert_eq!(client.code("MKD fine").await, 257);
    assert!(!server.backend.directories.lock().unwrap().iter().any(|d| d.len() > 100), "nothing of the long line may be used");
}

#[tokio::test]
async fn bytes_that_are_not_utf8_do_not_stop_the_session() {
    let server = start().await;
    let mut client = Client::connect(&server).await;
    client.login().await;
    client.send_bytes(b"MKD caf\xe9 \xff\xfe\r\n").await;
    // The name has U+FFFD in it, which is not a control character: it is a directory
    assert_eq!(client.reply().await.0, 257);
    client.send_bytes(b"\x80\x81\x82\r\n").await;
    assert_eq!(client.reply().await.0, 500);
    assert_eq!(client.code("NOOP").await, 200);
}

#[tokio::test]
async fn random_bytes_never_stop_the_server() {
    let server = start().await;
    let mut state = 0x2545_f491_4f6c_dd1du64;
    let mut next = move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    for round in 0..20 {
        let mut client = Client::connect(&server).await;
        let mut junk = Vec::new();
        for _ in 0..4000 {
            // Many of them line ends, spaces, letters and Telnet bytes, so that lines and commands are formed
            junk.push(match next() % 8 {
                0 => b'\n',
                1 => b' ',
                2 => 0xff,
                3 => b'A' + (next() % 26) as u8,
                _ => next() as u8,
            });
        }
        let _ = tokio::io::AsyncWriteExt::write_all(client.reader.get_mut(), &junk).await;
        // Close in the middle of whatever it was
        drop(client);
        if round % 5 == 0 {
            let mut check = Client::connect(&server).await;
            check.login().await;
        }
    }
    let mut client = Client::connect(&server).await;
    client.login().await;
    assert_eq!(client.command("PWD").await.0, 257);
}

#[tokio::test]
async fn a_connection_that_closes_in_the_middle_of_a_line_is_not_a_problem() {
    let server = start().await;
    let mut client = Client::connect(&server).await;
    client.send_bytes(b"USER ali").await;
    drop(client);
    eventually(|| matches!(server.ends.lock().unwrap().first(), Some(SessionEnd::ClientClosed))).await;
}

#[tokio::test]
async fn an_idle_connection_is_closed_without_a_reply() {
    let server = start_with({
        let mut config = Config::default();
        config.idle_timeout = Duration::from_millis(300);
        config
    })
    .await;
    let mut client = Client::connect(&server).await;
    let start = Instant::now();
    // Nothing is sent to the client (RFC 1123 section 4.1.2.11): the next thing it sees is the end of the connection
    assert!(client.closed().await);
    assert!(start.elapsed() >= Duration::from_millis(250) && start.elapsed() < Duration::from_secs(3), "{:?}", start.elapsed());
    eventually(|| matches!(server.ends.lock().unwrap().first(), Some(SessionEnd::IdleTimeout))).await;
}

#[tokio::test]
async fn a_client_that_sends_a_byte_now_and_then_is_still_idle() {
    let server = start_with({
        let mut config = Config::default();
        config.idle_timeout = Duration::from_millis(500);
        config
    })
    .await;
    let mut client = Client::connect(&server).await;
    let start = Instant::now();
    // One byte every 100 ms and never a line end: the time to wait is for the whole line
    for _ in 0..30 {
        if tokio::io::AsyncWriteExt::write_all(client.reader.get_mut(), b"N").await.is_err() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
        if start.elapsed() > Duration::from_secs(4) {
            break;
        }
    }
    assert!(client.closed().await);
    assert!(start.elapsed() < Duration::from_millis(2500), "{:?}", start.elapsed());
}

#[tokio::test]
async fn every_command_resets_the_idle_time() {
    let server = start_with({
        let mut config = Config::default();
        config.idle_timeout = Duration::from_millis(600);
        config
    })
    .await;
    let mut client = Client::connect(&server).await;
    for _ in 0..6 {
        tokio::time::sleep(Duration::from_millis(250)).await;
        assert_eq!(client.code("NOOP").await, 200);
    }
}

#[tokio::test]
async fn sign_in_is_refused_when_tls_is_required_and_the_connection_is_not_encrypted() {
    let server = start_with({
        let mut config = Config::default();
        config.require_tls = true;
        config
    })
    .await;
    let mut client = Client::connect(&server).await;
    assert_eq!(client.code("USER alice").await, 530);
    assert_eq!(client.code("PASS secret").await, 503);
    assert!(server.backend.logins.lock().unwrap().is_empty());
}

#[tokio::test]
async fn many_sessions_at_once() {
    let server = start().await;
    let mut tasks = Vec::new();
    for _ in 0..50 {
        let address = server.address;
        tasks.push(tokio::spawn(async move {
            let mut client = Client { reader: tokio::io::BufReader::new(tokio::net::TcpStream::connect(address).await.unwrap()) };
            assert_eq!(client.reply().await.0, 220);
            client.login().await;
            assert_eq!(client.command("PWD").await.0, 257);
            assert_eq!(client.code("QUIT").await, 221);
        }));
    }
    for task in tasks {
        task.await.unwrap();
    }
}

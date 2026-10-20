//! What the library does, requirement by requirement, and the tests that show it.
//!
//! [RFC 959](https://www.rfc-editor.org/info/rfc959/) and section 4.1 of [RFC 1123](https://www.freesoft.org/CIE/RFC/1123/57.htm) are the base. The
//! tables say, for each requirement, what the library does. Every row names the tests that show it, and a test of this repository checks that those tests
//! exist.
//!
//! # RFC 1123 section 4.1 and RFC 959
//!
//! | Requirement | Source | Status | Tests |
//! | --- | --- | --- | --- |
//! | Only correctly formatted replies: three digits and a space, or the multi-line form that ends with the same code and a space | 1123 4.1.2.11 | done | `a_reply_is_made_of_whole_lines`, `a_reply_of_several_lines_ends_with_the_code_and_a_space`, `a_line_in_the_middle_that_starts_with_digits_cannot_end_the_reply` |
//! | No spontaneous replies: an idle connection is closed, not written to | 1123 4.1.2.11 | done | `an_idle_connection_is_closed_without_a_reply` |
//! | Failures that may succeed later are 4xx, the others 5xx | 1123 4.1.2.11 | done | `what_may_work_later_is_4xx_and_what_will_not_is_5xx`, `a_backend_that_is_down_gives_421_and_closes`, `no_data_connection_in_time_is_425_and_the_session_goes_on`, `a_transfer_that_stands_still_is_aborted_with_426` |
//! | The RFC 959 reply texts where the meaning matches | 1123 4.1.2.11 | done | `the_greeting_comes_first_and_can_be_set`, `signing_in`, `quit_closes_the_connection` |
//! | Lines end with CRLF; a lone LF from a careless client is accepted; replies always use CRLF | 1123 4.1.2.10 | done | `commands_are_case_insensitive_and_a_lone_lf_ends_a_line`, `crlf_and_lone_lf` |
//! | Telnet commands (`IAC`) on the control connection are removed; `IAC IAC` is the byte 255 | 959 4.1.3 | done | `telnet_commands_are_removed_from_a_line`, `telnet_options_and_sub_negotiations_are_removed`, `iac_iac_is_the_byte_255` |
//! | `ABOR` and `STAT` at any time, also during a transfer | 959 4.1.3, 1123 4.1.3.3 | done | `abor_during_an_upload_is_answered_at_once_and_the_upload_is_dropped`, `abor_during_a_download`, `stat_during_a_transfer_shows_the_progress`, `stat_with_a_path_during_a_transfer_is_answered` |
//! | `QUIT` while a transfer runs: the transfer ends, then the connection closes | 959 4.1.3 | done | `quit_during_a_transfer_waits_for_it_and_then_closes`, `quit_during_a_transfer_that_stands_still_ends_it_and_then_closes`, `abor_and_then_quit_in_one_go` |
//! | The data connection is closed after each transfer in stream mode | 1123 4.1.2.12 | done | `a_data_connection_is_for_one_transfer` |
//! | `USER`, `PASS`, `ACCT` | 1123 4.1.2.13 | done (`ACCT` is `202`) | `signing_in`, `type_mode_structure_and_allocation` |
//! | `TYPE A N`, `I`, `L 8`; `MODE S`; `STRU F` (`STRU R`, `MODE B` and `C` are `504`) | 1123 4.1.2.13 | done | `type_mode_structure_and_allocation` |
//! | `PORT` | 1123 4.1.2.13 | option, off by default | `it_is_off_by_default`, `upload_download_and_listing` |
//! | `PASV` | 1123 4.1.2.13 | done | `pasv_tells_the_address_of_the_connection_and_a_port_that_listens`, `the_passive_host_can_be_set` |
//! | `RETR`, `STOR` | 1123 4.1.2.13 | done | `upload_and_download`, `the_working_directory_is_where_a_file_goes` |
//! | `APPE`, `RNFR`, `RNTO`, `DELE`, `RMD` | 1123 4.1.2.13 | recognised and refused on purpose (`550`: a receive folder keeps what it is sent) | `what_ftp_refuses_on_purpose_is_550_and_not_502` |
//! | `CWD`, `CDUP`, `MKD`, `PWD` | 1123 4.1.2.13 | done | `the_working_directory`, `nothing_goes_above_the_root` |
//! | `LIST`, `NLST` | 1123 4.1.2.13 | done (the backend decides whether listing is allowed); `NLST dir` gives `dir/name` as other servers do | `listings`, `list_is_the_ls_format`, `nlst_is_the_names`, `nlst_of_a_directory_gives_the_names_with_the_path_as_written`, `a_listing_that_is_too_long_is_451` |
//! | `SYST`, `STAT`, `HELP`, `NOOP`, `QUIT` | 1123 4.1.2.13 | done (`STAT path` is `212` for a directory, `213` for a file) | `the_information_commands`, `stat_shows_the_connection`, `stat_with_a_path_lists_on_the_control_connection`, `quit_closes_the_connection` |
//! | `REIN`, `SMNT`, `STOU`, `SITE` | 959 | recognised and refused (`502`) | `commands_that_are_not_done` |
//! | The X forms `XMKD`, `XRMD`, `XPWD`, `XCUP`, `XCWD` | 1123 4.1.3.1 | done | `the_x_forms_are_the_same_commands` |
//! | Idle timeout, configurable, by default at least 5 minutes | 1123 4.1.3.2 | done (300 s) | `the_defaults_follow_rfc_1123`, `every_command_resets_the_idle_time`, `a_client_that_sends_a_byte_now_and_then_is_still_idle` |
//! | Restart: `554` for an invalid `REST` | 1123 4.1.3.4 | done for `RETR`; `STOR` with an offset is `554` (the backend stores whole files) | `rest_is_for_retr_and_for_the_next_command_only` |
//! | Restart markers (`110`) | 959 3.5 | not applicable: there is no block mode | |
//! | `TYPE A` transfers | 1123 4.1.2.13 | bytes unchanged by default; the conversion of line ends is an option | `by_default_ascii_transfers_do_not_change_the_bytes`, `with_the_conversion_on_ascii_files_are_stored_with_lf_and_sent_with_crlf` |
//!
//! # Other specifications
//!
//! | Requirement | Source | Status | Tests |
//! | --- | --- | --- | --- |
//! | `AUTH TLS`, `PBSZ 0`, `PROT P` and `C`; `PROT S` and `E` are `536`; `CCC` is refused | RFC 2228, 4217 | done | `auth_tls_upgrades_the_control_connection`, `the_mechanisms_and_when_auth_is_allowed`, `pbsz_and_prot_need_their_order`, `upload_download_and_listings_over_tls` |
//! | `EPSV`, `EPSV ALL`, the protocol argument; `EPRT` | RFC 2428 | done | `epsv_tells_only_the_port`, `epsv_all_and_the_protocol_argument`, `eprt_does_the_same`, `eprt_takes_a_protocol_an_address_and_a_port` |
//! | `FEAT` and `OPTS` | RFC 2389 | done | `the_information_commands` |
//! | `SIZE`, `MDTM`, `MLST`, `MLSD`, `OPTS MLST`, `REST STREAM` | RFC 3659 | done | `size_mdtm_and_mlst`, `opts_mlst_chooses_the_facts`, `known_dates` |
//! | UTF-8 names and `OPTS UTF8 ON`; a line that is not UTF-8 is refused | RFC 2640 | done | `a_name_with_spaces_unicode_and_quotes`, `the_information_commands`, `bytes_that_are_not_utf8_do_not_stop_the_session`, `a_line_that_is_not_utf8_is_not_used_and_the_next_is_read` |
//! | The server connects only to the address of the client and to ports from 1024 up | RFC 2577 | done | `the_server_connects_to_the_address_of_the_client_only`, `the_server_connects_to_ports_from_1024_up_only` |
//! | A data connection from another address is not the data connection | RFC 2577 | done | `a_data_connection_from_another_address_is_closed_and_the_port_keeps_waiting`, `nothing_is_stored_from_a_stranger` |
//! | Failed sign-ins are limited | RFC 2577 | done | `too_many_wrong_passwords_close_the_connection_with_421` |
//! | A TLS connection ends with a `close_notify`; one that ends without it was cut | RFC 8446 6.1 | done | `an_upload_that_ends_without_a_close_notify_is_a_truncation_not_a_226`, `the_server_answers_the_end_of_an_upload_before_the_storage_is_done`, `the_control_connection_ends_with_a_close_notify` |
//! | Implicit FTPS (port 990) | | not provided: the host accepts the connections | |
//!
//! # Behaviours designed in
//!
//! These are mistakes that other servers made. Each has a test that fails when the behaviour is taken out.
//!
//! | Behaviour | Tests |
//! | --- | --- |
//! | `AUTH TLS` switches to TLS right after the `234`; what the client sent in plain text before it saw the reply is never answered | `what_the_client_sent_after_auth_tls_in_plain_text_is_never_answered`, `discarding_what_was_read_drops_the_rest_of_the_chunk` |
//! | One passive port per session: a new `PASV` or `EPSV` closes the previous one at once | `a_new_pasv_closes_the_previous_port_at_once`, `bind_skips_the_ports_in_use_and_fails_when_all_are` |
//! | A data connection from another address is closed and the port keeps waiting for the client; addresses are compared in canonical form | `a_data_connection_from_another_address_is_closed_and_the_port_keeps_waiting`, `accept_from_closes_a_stranger_and_keeps_waiting_for_the_client`, `canonical_makes_the_two_forms_of_an_address_equal` |
//! | The TLS policy is checked when the data connection is used, not only when it is announced; `EPSV` like `PASV`; `PROT C` after `PASV` can't give a plain transfer | `with_tls_required_pasv_and_epsv_are_refused_until_prot_p`, `prot_c_after_pasv_cannot_give_a_transfer_in_plain_text` |
//! | A failed TLS handshake on a data connection refuses the transfer; it is never an empty transfer | `a_data_connection_that_is_not_tls_is_refused_and_nothing_is_stored`, `a_data_connection_that_never_starts_the_handshake_is_given_up` |
//! | `ABOR` works during a transfer: nothing is locked across it, the transfer is dropped and a partial upload is discarded | `abor_during_an_upload_is_answered_at_once_and_the_upload_is_dropped`, `abor_during_a_tls_upload`, `quit_during_a_transfer_that_stands_still_ends_it_and_then_closes` |
//! | A client that sends the end of the data and then quits or closes the control connection does not lose the upload | `a_control_connection_that_closes_after_the_data_does_not_lose_the_upload`, `quit_during_a_transfer_waits_for_it_and_then_closes`, `a_control_connection_that_closes_while_the_upload_stands_still_drops_the_upload` |
//! | A backend that returns before it has read the whole upload does not get a `226` | `a_backend_that_returns_before_the_end_of_the_upload_is_not_a_226` |
//! | A backend call that hangs, a client that never signs in, and settings of `Duration::MAX` don't hang or panic a session | `a_backend_call_that_takes_too_long_is_450_and_the_session_goes_on`, `a_sign_in_that_takes_too_long_is_421`, `the_time_to_sign_in_is_from_the_start_and_noop_does_not_extend_it`, `settings_with_huge_values_do_not_panic`, `a_huge_duration_is_far_away_and_does_not_panic` |
//! | The longest a transfer may take can be limited, whatever it moves | `the_longest_a_transfer_may_take_is_limited_whatever_it_moves` |
//! | The end of an FTPS upload: our `close_notify` before the storage is told, a missing one is a truncation and never a `226`; no TLS 1.3 tickets on data connections | `the_server_answers_the_end_of_an_upload_before_the_storage_is_done`, `an_upload_that_ends_without_a_close_notify_is_a_truncation_not_a_226`, `data_connections_get_no_session_tickets`, `idle_read_answers_the_end_of_the_data_with_the_end_of_its_own_before_it_reports_it` |
//! | No panics on input: a malformed or huge line, a bad path, an early close | `made_up_commands_never_panic_or_hang_a_session`, `random_bytes_never_stop_the_server`, `a_line_that_is_too_long_is_500_and_the_session_goes_on`, `the_parser_never_panics_and_the_verb_is_not_case_sensitive`, `a_path_never_panics` |
//!
//! # Tested with
//!
//! The tests (about 230) run against [suppaftp](https://crates.io/crates/suppaftp) (plain FTP and FTPS, passive and extended passive mode). `scripts/interop.sh`
//! runs `curl` (`ftp://` and `--ssl-reqd`), Python's `ftplib` (`FTP` and `FTP_TLS`) and `lftp` (plain and with TLS) against the example server: it passes
//! on Linux (lftp 4.9 in Debian bookworm) and on Windows without lftp. Not tested yet: FileZilla, Windows Explorer and real scanners and cameras.
//!
//! The four fuzz targets (in a Linux container, on this version) ran for 60 seconds each: about 8.9 million inputs for the parser, 1.2 million for the
//! codec, 2.5 million for paths and 60 thousand whole sessions, without a crash or a hang.
//!
//! The tests are in `src/` and `tests/` of the repository. A test of the repository (`tests/conformance.rs`) reads this page, and fails when a row names a
//! test that does not exist, is not a test, or is ignored. A new behaviour gets its row here.

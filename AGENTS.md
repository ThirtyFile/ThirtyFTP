# ThirtyFTP: notes for coding agents

This file is local (it is listed in `.gitignore`) and is not part of the repository.

## The project

A small FTP and FTPS server library for Rust (crate `thirtyftp`, Tokio, rustls), used by ThirtyFile for receive folders and written to be general. The host
accepts connections and calls `serve`; a `Backend` it writes knows the users and the storage.

| Path | Contents |
| --- | --- |
| `src/` | The library. `session/` the control connection (`mod.rs` loop and dispatch, `auth.rs`, `info.rs`, `files.rs`, `data.rs`); `transfer.rs` the data connection task; `codec.rs` lines and Telnet; `command.rs` the parser; `reply.rs`; `path.rs` (`FtpPath`); `passive.rs`, `active.rs`; `tls.rs`; `listing.rs`, `time.rs`, `ascii.rs`; `config.rs`, `events.rs`, `backend.rs`; `conformance.rs` the conformance tables (docs only) |
| `tests/` | Integration tests with an in-memory backend (`common/mod.rs`) and a raw FTP client: `control`, `transfer`, `ftps`, `active`, `ascii`, `ipv6`, `suppaftp`, `robustness`, `conformance` |
| `examples/` | `receive_folder.rs` (real, published), `memory.rs` (for the interop script, not published) |
| `fuzz/` | cargo-fuzz targets (parser, codec, path, session). libFuzzer does not link on Windows: run them in the Linux container |
| `scripts/interop.sh` | curl, ftplib and lftp against the example server |
| `.github/` | Workflows (`checks.yml`, `fuzz.yml`), issue forms, pull request template, Dependabot, release notes |

Repository: <https://github.com/ThirtyFile/ThirtyFTP> (public, Apache-2.0). Not published on crates.io yet; the name `thirtyftp` is free.

## Rules

- Talk to the user in Traditional Chinese. Everything in the repository is English: code, comments, commit messages, pull requests, documentation.
- `README.md` is short: what it is, how to use it, with examples. Its Rust examples are compiled by `cargo test --doc`: keep them working. The conformance
  tables are the docs of `src/conformance.rs`; a test (`tests/conformance.rs`) fails when a row names a test that does not exist.
- No other documents in the repository: review reports, plans and notes stay local (scratchpad). No CHANGELOG (release notes come from the pull request
  titles and labels). `AGENTS.md` and `CLAUDE.md` are ignored by git.
- Every fix has a test that fails without it: check by taking the fix out (a mutation) before pushing.
- No `unwrap`, `expect`, `panic`, unchecked index or `unreachable` in the library (lints deny them outside tests); a client's input is a reply or a closed connection.
- Examples and tests use `example.com` or `localhost`, never a real company domain.
- Ask the user before: downloading a crate or tool for the first time, creating a repository, pushing a tag, publishing to crates.io. Never fork, open pull
  requests, issues or comments in repositories the user doesn't own.
- Git author for this repository: `thirtyfile <thirtyfile@gmail.com>`.

## Workflow

Nothing is pushed to `main`. A ruleset on GitHub enforces it.

1. **Issue first** for anything larger than a small fix.
2. **Branch** from an up-to-date `main`: `feat/…`, `fix/…`, `docs/…` or `chore/…`.
3. **Commit** in English, saying what changes. Small commits are fine: the pull request is squashed.
4. **Checks** before pushing (the same run in CI on Linux and Windows):
   ```bash
   cargo fmt --check
   cargo clippy --all-targets --locked -- -D warnings
   cargo test --locked
   RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --locked
   cargo deny check
   ```
   `rustfmt.toml` sets a width of 165. CI also builds the fuzz crate (`RUSTFLAGS="--cfg fuzzing" cargo check --locked --manifest-path fuzz/Cargo.toml`), runs
   `cargo package --locked`, and runs `scripts/interop.sh` with lftp.
5. **Pull request** with `gh pr create`. The title is a plain sentence about what changes (it becomes the commit on `main` and the line in the release notes).
   Add one label: `enhancement`, `bug`, `performance`, `documentation`, `dependencies` or `maintenance`. Write `Closes #123` in the description.
6. **Required check**: `Checks passed`, tied to GitHub Actions (Linux and Windows checks, real clients, dependencies).
7. **Merge** with squash, only when the user asked for it. The branch is deleted by GitHub.

### Releases

No release workflow yet. A release is cut only when the user asks:

1. The version in `Cargo.toml` is the release (changed by a pull request).
2. Tag `vX.Y.Z` on `main` (`git tag -a`, then push it). The ruleset "Release tags" lets `v*` tags be created, never deleted, moved or force-pushed: check the
   commit before pushing.
3. `gh release create vX.Y.Z --generate-notes`.
4. `cargo publish --locked` (the user sets up the crates.io token; ask before the first publish). First number for changes that break the API or what a client sees,
   second for new things, third for repairs; while the version starts with 0, a breaking change raises the second number.

`v0.1.0` exists only as a local tag until the user says to push it.

### Repository settings (set on 2026-10-20, as in ThirtyFile)

- Merging: squash only, title and description taken from the pull request, branches deleted after merging. Auto-merge is allowed; use it only when the user asked to merge.
- Ruleset "main": pull request required (0 approvals), conversations resolved, `Checks passed` required, no force pushes, no deletion.
- Ruleset "Release tags": `v*` tags can be created but never deleted, moved or force-pushed, no bypass.
- Dependabot: weekly updates (Cargo in `/` and `/fuzz`, Actions), security updates on. Private vulnerability reporting on; secret scanning with push protection on.
- Labels: `bug`, `enhancement`, `performance`, `documentation`, `dependencies`, `maintenance`, `skip-release-notes` and GitHub's defaults.

## Working locally

- Verify changes for real before saying they work: run the tests, and for protocol behaviour run a real client (`cargo run --example memory`, port from `PORT`, `-- tls`
  for FTPS; `bash scripts/interop.sh`).
- Shell: Git Bash on Windows. Bash heredocs with quotes and backslashes break the tool: write files with the Write tool, or a Python script file in the scratchpad.
  `docker` paths need PowerShell (Git Bash rewrites `/x` arguments).
- Docker image `thirtyftp-linux` (Rust, nightly, cargo-fuzz, lftp, python3, curl; built from a Dockerfile in the scratchpad) runs the Linux checks and the fuzz targets:
  mount the source read-only at `/src`, copy it to `/work`, use the volumes `thirtyftp-target`, `thirtyftp-registry`, `thirtyftp-rustup`.
- Tests use real sockets and real time: keep the margins wide (CI runners are slow), and never a fixed port (use port 0 or ask the system).
- The 8 behaviours the library must get right are listed in the conformance page ("Behaviours designed in"), each with a test: AUTH TLS switches right after the 234, one passive
  port per session, data connections only from the client's address, TLS policy checked when the data connection is used, a failed data handshake refuses the transfer, ABOR
  during a transfer, the end of an FTPS upload (close_notify, truncation), no panics on input.
- ThirtyFile (`F:\StartrustDrive`) uses this library (`server/src/ftp/`); another Claude session owns that repository. Read it only; tell that session about API changes
  through a message, never edit its files.

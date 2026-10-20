# Contributing to ThirtyFTP

Thank you for helping.

## Problems and ideas

[Open an issue](https://github.com/ThirtyFile/ThirtyFTP/issues/new/choose) and pick the form that fits: a problem, an idea, the documentation, or an improvement to the code. Look through the [existing issues](https://github.com/ThirtyFile/ThirtyFTP/issues) first.

Security problems are reported privately: see the [security policy](SECURITY.md).

## Changing the code

1. For anything larger than a small fix, agree on the idea in an issue first.
2. Create a branch from `main`: `feat/…`, `fix/…`, `docs/…` or `chore/…`.
3. Every fix comes with a test that fails without it. Format the code and run the checks:
   ```bash
   cargo fmt
   cargo clippy --all-targets --locked -- -D warnings
   cargo test --locked
   RUSTDOCFLAGS="-D warnings" cargo doc --no-deps
   ```
   Pull requests run the same on Linux and Windows, real clients (curl, Python's ftplib and lftp) against the example server, the build of the fuzz crate, `cargo package` and `cargo deny`. The fuzz targets run weekly (**Actions > Fuzz > Run workflow** runs them now).
4. Open a pull request with a title that says what changes, one label (`enhancement`, `bug`, `performance`, `documentation`, `dependencies` or `maintenance`), and `Closes #123` in the description. Pull requests are squash-merged.

Code, comments and documentation are written in English. A new command or behaviour gets its row in the conformance tables of the README, with the tests that show it (a test of this repository checks that they exist). The documentation of a module names the sections of the RFCs it follows.

By contributing, you agree that your contribution is licensed under the [Apache License 2.0](../LICENSE), and you agree to follow the [code of conduct](CODE_OF_CONDUCT.md).

# ThirtyFTP

A small FTP and FTPS server library for Rust, made for receive folders: devices such as scanners and cameras upload files
into one folder.

- Passive mode and explicit FTPS (`AUTH TLS`), on Tokio and rustls
- Uploads, and optionally listing and downloads, and making folders
- Not supported, and refused: active mode, deleting, renaming, `SITE`, implicit FTPS

The library is under development and has no release yet.

## Development

```sh
cargo fmt --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --locked
```

## Licence

[Apache-2.0](LICENSE)

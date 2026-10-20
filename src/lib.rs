//! ThirtyFTP: a small FTP and FTPS server library for receive folders.
//!
//! It serves passive-mode FTP and explicit FTPS (`AUTH TLS`) with uploads, optional listing and downloads, and folder
//! creation. Active mode, deleting, renaming and implicit FTPS are not supported.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

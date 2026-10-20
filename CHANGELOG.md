# Changelog

## 0.1.0

The first release.

- The control connection of RFC 959 with the requirements of RFC 1123 section 4.1: replies, Telnet commands, `ABOR` and `STAT` during transfers,
  the minimum implementation, the X forms, and an idle timeout of 5 minutes by default.
- Passive mode (`PASV`, `EPSV`) with a port range, one port for a session, and data connections accepted from the address of the client only.
  Active mode (`PORT`, `EPRT`) as an option, off by default.
- `STOR`, `RETR`, `LIST`, `NLST`, `MLSD`, `MLST`, `SIZE`, `MDTM` and `REST` for downloads; deleting, renaming and `SITE` are refused.
- Explicit FTPS (`AUTH TLS`, `PBSZ`, `PROT`) on the control connection and the data connections, with a policy for hosts that require TLS, a clean end
  of an upload with `close_notify`, and a truncated upload is never a success.
- `Backend` for users and storage, `Events` for an activity log, `Config` and `Limits`.
- Tests with suppaftp, curl, Python's ftplib and lftp; property tests; fuzz targets; a conformance table in the README with a test for every row.

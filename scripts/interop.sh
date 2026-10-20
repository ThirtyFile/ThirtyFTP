#!/usr/bin/env bash
# Runs real clients against the in-memory example server: curl (FTP and FTPS), Python's ftplib (FTP and FTP_TLS) and lftp (when it is installed; set
# INTEROP_REQUIRE_LFTP=1 to fail without it). Each client uploads a file, lists, downloads it and compares.
set -euo pipefail

cd "$(dirname "$0")/.."
work="$(mktemp -d)"
server_pid=""
port=2200
cleanup() {
  [ -n "$server_pid" ] && kill "$server_pid" 2>/dev/null || true
  rm -rf "$work"
}
trap cleanup EXIT

cargo build --locked --example memory
binary="target/debug/examples/memory"
[ -x "$binary" ] || binary="target/debug/examples/memory.exe"

start_server() {
  [ -n "$server_pid" ] && kill "$server_pid" 2>/dev/null || true
  # Each server has a port of its own: one that was stopped may still hold its port for a moment
  port=$((port + 1))
  PORT="$port" "$binary" "$@" >"$work/server.log" 2>&1 &
  server_pid=$!
  for _ in $(seq 1 50); do
    grep -q "Listening on" "$work/server.log" && return 0
    sleep 0.1
  done
  echo "the server did not start" >&2
  cat "$work/server.log" >&2
  exit 1
}

head -c 3000000 /dev/urandom >"$work/up.bin"
same() { cmp "$work/up.bin" "$1" && echo "  same file"; }

echo "== curl, plain FTP"
start_server
curl -sS -m 30 -u alice:secret -T "$work/up.bin" ftp://127.0.0.1:$port/curl-plain.bin
curl -sS -m 30 -u alice:secret ftp://127.0.0.1:$port/ | grep -q curl-plain.bin
curl -sS -m 30 -u alice:secret ftp://127.0.0.1:$port/curl-plain.bin -o "$work/down.bin"
same "$work/down.bin"
curl -sS -m 30 -u alice:secret --disable-epsv ftp://127.0.0.1:$port/curl-plain.bin -o "$work/down2.bin"
same "$work/down2.bin"

echo "== Python ftplib, plain FTP"
python3 - "$work/up.bin" "$port" <<'PY'
import ftplib, sys
data = open(sys.argv[1], 'rb').read()
f = ftplib.FTP()
f.connect('127.0.0.1', int(sys.argv[2]))
f.login('alice', 'secret')
f.mkd('docs')
f.cwd('docs')
with open(sys.argv[1], 'rb') as handle:
    f.storbinary('STOR ftplib.bin', handle)
assert f.nlst() == ['ftplib.bin'], f.nlst()
assert f.size('ftplib.bin') == len(data)
received = bytearray()
f.retrbinary('RETR ftplib.bin', received.extend)
assert bytes(received) == data
assert [name for name, _ in f.mlsd()] == ['ftplib.bin']
f.quit()
print('  ok')
PY

echo "== curl and ftplib, explicit FTPS"
start_server tls
curl -sS -m 30 --ssl-reqd --insecure -u alice:secret -T "$work/up.bin" ftp://127.0.0.1:$port/curl-tls.bin
curl -sS -m 30 --ssl-reqd --insecure -u alice:secret ftp://127.0.0.1:$port/ | grep -q curl-tls.bin
curl -sS -m 30 --ssl-reqd --insecure -u alice:secret ftp://127.0.0.1:$port/curl-tls.bin -o "$work/down-tls.bin"
same "$work/down-tls.bin"
python3 - "$work/up.bin" "$port" <<'PY'
import ftplib, ssl, sys
data = open(sys.argv[1], 'rb').read()
context = ssl.create_default_context()
context.check_hostname = False
context.verify_mode = ssl.CERT_NONE
f = ftplib.FTP_TLS(context=context)
f.connect('127.0.0.1', int(sys.argv[2]))
f.login('alice', 'secret')
f.prot_p()
with open(sys.argv[1], 'rb') as handle:
    f.storbinary('STOR ftplib-tls.bin', handle)
received = bytearray()
f.retrbinary('RETR ftplib-tls.bin', received.extend)
assert bytes(received) == data
assert 'ftplib-tls.bin' in f.nlst()
f.quit()
print('  ok')
PY

if command -v lftp >/dev/null 2>&1; then
  echo "== lftp, plain FTP and explicit FTPS"
  start_server
  lftp -u alice,secret -e "set ftp:ssl-allow no; put $work/up.bin -o lftp-plain.bin; get lftp-plain.bin -o $work/lftp-down.bin; cls; bye" ftp://127.0.0.1:$port
  same "$work/lftp-down.bin"
  start_server tls
  lftp -u alice,secret -e "set ftp:ssl-force true; set ftp:ssl-protect-data true; set ssl:verify-certificate no; put $work/up.bin -o lftp-tls.bin; get lftp-tls.bin -o $work/lftp-down-tls.bin; cls; bye" ftp://127.0.0.1:$port
  same "$work/lftp-down-tls.bin"
elif [ "${INTEROP_REQUIRE_LFTP:-0}" = 1 ]; then
  echo "lftp is not installed" >&2
  exit 1
else
  echo "== lftp is not installed: skipped"
fi

echo "All clients passed"

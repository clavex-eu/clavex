#!/usr/bin/env bash
# Local laboratory CA only. Never replace existing keys or rotate trust implicitly.
set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)/.local/tls"
umask 077
mkdir -p "$DIR"
if [[ -f "$DIR/ca.pem" && -f "$DIR/ca.key" && -f "$DIR/tls.crt" && -f "$DIR/tls.key" ]]; then
  openssl x509 -in "$DIR/ca.pem" -checkend 0 -noout >/dev/null
  openssl x509 -in "$DIR/tls.crt" -checkend 0 -noout >/dev/null
  openssl verify -CAfile "$DIR/ca.pem" -verify_hostname localhost.emobix.co.uk "$DIR/tls.crt" >/dev/null
  echo "Existing local suite certificates retained."
  exit 0
fi
if [[ -n "$(find "$DIR" -mindepth 1 -maxdepth 1 -print -quit)" ]]; then
  echo "Incomplete TLS material in $DIR; refusing to overwrite it." >&2
  exit 1
fi
openssl req -x509 -newkey rsa:3072 -nodes -sha256 -days 365 \
  -subj '/CN=Clavex Local Conformance CA' \
  -addext 'basicConstraints=critical,CA:TRUE' -addext 'keyUsage=critical,keyCertSign,cRLSign' \
  -keyout "$DIR/ca.key" -out "$DIR/ca.pem" 2>/dev/null
openssl req -new -newkey rsa:2048 -nodes -sha256 \
  -subj '/CN=localhost.emobix.co.uk' -keyout "$DIR/tls.key" -out "$DIR/tls.csr" 2>/dev/null
cat > "$DIR/leaf.ext" <<'EXT'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:localhost.emobix.co.uk,DNS:localhost,IP:127.0.0.1
EXT
openssl x509 -req -in "$DIR/tls.csr" -CA "$DIR/ca.pem" -CAkey "$DIR/ca.key" \
  -CAcreateserial -days 90 -sha256 -extfile "$DIR/leaf.ext" -out "$DIR/leaf.pem" 2>/dev/null
cat "$DIR/leaf.pem" "$DIR/ca.pem" > "$DIR/tls.crt"
echo "Local CA and 90-day TLS certificate created. Trust ca.pem explicitly in clients."
echo "For a remote backend, review/update its CA ConfigMap before running tests."

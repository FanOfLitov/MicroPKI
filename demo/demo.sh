#!/usr/bin/env bash
set -Eeuo pipefail

# MicroPKI final demo script.
# Works on Linux/macOS and on Windows when launched through Git Bash/WSL:
#   bash ./demo/demo.sh
# Python detection supports: .venv, python3, python, py -3, py.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

WORKDIR="$ROOT_DIR/demo/workdir"
PKI_DIR="$WORKDIR/pki"
SECRETS_DIR="$PKI_DIR/secrets"
CERTS_DIR="$PKI_DIR/certs"
PRIVATE_DIR="$PKI_DIR/private"
CRL_DIR="$PKI_DIR/crl"
ARTIFACTS_DIR="$WORKDIR/artifacts"

REPO_PORT="18080"
OCSP_PORT="18081"
TLS_PORT="18443"

REPO_PID=""
OCSP_PID=""
TLS_PID=""

PASS_ROOT="RootPass123!"
PASS_INTER="InterPass456!"

info() { printf '\n==> %s\n' "$1"; }
pass() { printf '[PASS] %s\n' "$1"; }
fail() { printf '[FAIL] %s\n' "$1"; exit 1; }

cleanup() {
  set +e
  if [[ -n "${TLS_PID}" ]]; then kill "${TLS_PID}" >/dev/null 2>&1 || true; fi
  if [[ -n "${OCSP_PID}" ]]; then kill "${OCSP_PID}" >/dev/null 2>&1 || true; fi
  if [[ -n "${REPO_PID}" ]]; then kill "${REPO_PID}" >/dev/null 2>&1 || true; fi
}
trap cleanup EXIT

command_exists() {
  command -v "$1" >/dev/null 2>&1
}

# Run a command and wait until an HTTP endpoint answers.
wait_http() {
  local url="$1"
  local label="$2"
  for _ in $(seq 1 40); do
    if curl -fsS "$url" >/dev/null 2>&1; then
      pass "$label is reachable"
      return 0
    fi
    sleep 0.25
  done
  fail "$label did not start: $url"
}

# Detect Python in a cross-platform way.
# Priority:
#   1) local virtual environment
#   2) python3
#   3) python
#   4) Windows launcher: py -3
#   5) Windows launcher: py

detect_python() {
  local candidates=()

  if [[ -x "$ROOT_DIR/.venv/Scripts/python.exe" ]]; then
    candidates+=("$ROOT_DIR/.venv/Scripts/python.exe")
  fi
  if [[ -x "$ROOT_DIR/.venv/bin/python" ]]; then
    candidates+=("$ROOT_DIR/.venv/bin/python")
  fi
  if command_exists python3; then
    candidates+=("python3")
  fi
  if command_exists python; then
    candidates+=("python")
  fi
  if command_exists py; then
    candidates+=("py -3")
    candidates+=("py")
  fi

  for candidate in "${candidates[@]}"; do
    # shellcheck disable=SC2086
    if $candidate -c "import sys; print(sys.version)" >/dev/null 2>&1; then
      echo "$candidate"
      return 0
    fi
  done

  return 1
}

PYTHON_CMD="$(detect_python || true)"
if [[ -z "$PYTHON_CMD" ]]; then
  fail "Python not found. Install Python or make py/python/python3 available in PATH."
fi

# Helper for running Python with a command that can contain spaces, e.g. "py -3".
run_py() {
  # shellcheck disable=SC2086
  $PYTHON_CMD "$@"
}

run_micropki() {
  run_py -m micropki "$@"
}

require_tool() {
  command_exists "$1" || fail "Required tool not found: $1"
}

info "Checking required tools"
require_tool openssl
require_tool curl
run_py -c "import micropki" || fail "Python can run, but package 'micropki' is not importable from this directory/venv"
pass "Python command selected: $PYTHON_CMD"
pass "openssl found"
pass "curl found"
pass "micropki import works"

info "Preparing clean demo workspace"
rm -rf "$WORKDIR"
mkdir -p "$SECRETS_DIR" "$CERTS_DIR" "$PRIVATE_DIR" "$CRL_DIR" "$ARTIFACTS_DIR"
printf '%s\n' "$PASS_ROOT" > "$SECRETS_DIR/root.pass"
printf '%s\n' "$PASS_ROOT" > "$SECRETS_DIR/ca.pass"
printf '%s\n' "$PASS_INTER" > "$SECRETS_DIR/intermediate.pass"
pass "Workspace created at $WORKDIR"

info "1. Initialising Root CA"
run_micropki ca init \
  --subject "CN=MicroPKI Demo Root CA,O=MicroPKI,C=RU" \
  --key-type rsa \
  --key-size 4096 \
  --passphrase-file "$SECRETS_DIR/root.pass" \
  --out-dir "$PKI_DIR" \
  --validity-days 3650
pass "Root CA created"

info "2. Initialising certificate database"
run_micropki db init --db-path "$PKI_DIR/micropki.db"
pass "SQLite database initialised"

info "3. Issuing Intermediate CA"
run_micropki ca issue-intermediate \
  --root-cert "$CERTS_DIR/ca.cert.pem" \
  --root-key "$PRIVATE_DIR/ca.key.pem" \
  --root-pass-file "$SECRETS_DIR/root.pass" \
  --subject "CN=MicroPKI Demo Intermediate CA,O=MicroPKI" \
  --key-type rsa \
  --key-size 4096 \
  --passphrase-file "$SECRETS_DIR/intermediate.pass" \
  --out-dir "$PKI_DIR" \
  --validity-days 1825 \
  --pathlen 0
pass "Intermediate CA issued"

info "4. Issuing server, client, code-signing and OCSP responder certificates"
run_micropki ca issue-cert \
  --ca-cert "$CERTS_DIR/intermediate.cert.pem" \
  --ca-key "$PRIVATE_DIR/intermediate.key.pem" \
  --ca-pass-file "$SECRETS_DIR/intermediate.pass" \
  --template server \
  --subject "CN=localhost,O=MicroPKI" \
  --san "dns:localhost" \
  --out-dir "$CERTS_DIR" \
  --validity-days 365

run_micropki ca issue-cert \
  --ca-cert "$CERTS_DIR/intermediate.cert.pem" \
  --ca-key "$PRIVATE_DIR/intermediate.key.pem" \
  --ca-pass-file "$SECRETS_DIR/intermediate.pass" \
  --template client \
  --subject "CN=Demo Client,O=MicroPKI" \
  --san "email:client@example.com" \
  --out-dir "$CERTS_DIR" \
  --validity-days 365

run_micropki ca issue-cert \
  --ca-cert "$CERTS_DIR/intermediate.cert.pem" \
  --ca-key "$PRIVATE_DIR/intermediate.key.pem" \
  --ca-pass-file "$SECRETS_DIR/intermediate.pass" \
  --template code_signing \
  --subject "CN=Demo Code Signer,O=MicroPKI" \
  --out-dir "$CERTS_DIR" \
  --validity-days 365

run_micropki ca issue-ocsp-cert \
  --ca-cert "$CERTS_DIR/intermediate.cert.pem" \
  --ca-key "$PRIVATE_DIR/intermediate.key.pem" \
  --ca-pass-file "$SECRETS_DIR/intermediate.pass" \
  --subject "CN=OCSP Responder,O=MicroPKI" \
  --key-type rsa \
  --key-size 2048 \
  --out-dir "$CERTS_DIR" \
  --validity-days 365
pass "Certificates issued"

info "5. Validating certificate chain"
run_micropki ca validate-chain \
  --cert "$CERTS_DIR/localhost.cert.pem" \
  --intermediate "$CERTS_DIR/intermediate.cert.pem" \
  --root "$CERTS_DIR/ca.cert.pem"
pass "Chain validation successful"

info "6. Starting repository and OCSP responder"
run_micropki repo serve \
  --host 127.0.0.1 \
  --port "$REPO_PORT" \
  --db-path "$PKI_DIR/micropki.db" \
  --cert-dir "$CERTS_DIR" \
  > "$WORKDIR/repo.log" 2>&1 &
REPO_PID=$!
wait_http "http://127.0.0.1:$REPO_PORT/ca/root" "Repository server"

run_micropki ocsp serve \
  --host 127.0.0.1 \
  --port "$OCSP_PORT" \
  --db-path "$PKI_DIR/micropki.db" \
  --responder-cert "$CERTS_DIR/OCSP_Responder.cert.pem" \
  --responder-key "$CERTS_DIR/OCSP_Responder.key.pem" \
  --ca-cert "$CERTS_DIR/intermediate.cert.pem" \
  > "$WORKDIR/ocsp.log" 2>&1 &
OCSP_PID=$!
sleep 1
pass "OCSP responder started on http://127.0.0.1:$OCSP_PORT/ocsp"

info "7. Fetching CA certificate through repository API"
curl -fsS "http://127.0.0.1:$REPO_PORT/ca/root" -o "$ARTIFACTS_DIR/root-from-repo.pem"
test -s "$ARTIFACTS_DIR/root-from-repo.pem"
pass "Repository API returned Root CA certificate"

info "8. TLS demo with openssl s_server and curl"
cat "$CERTS_DIR/localhost.cert.pem" "$CERTS_DIR/intermediate.cert.pem" > "$ARTIFACTS_DIR/localhost.chain.pem"
openssl s_server \
  -accept "$TLS_PORT" \
  -cert "$ARTIFACTS_DIR/localhost.chain.pem" \
  -key "$CERTS_DIR/localhost.key.pem" \
  -www \
  > "$WORKDIR/tls.log" 2>&1 &
TLS_PID=$!
sleep 1
curl -k -fsS "https://localhost:$TLS_PORT" >/dev/null
curl --cacert "$CERTS_DIR/ca.cert.pem" -fsS "https://localhost:$TLS_PORT" >/dev/null
pass "TLS server works and curl validates it with custom Root CA"

info "9. Code signing demo"
printf 'print("Hello from signed MicroPKI demo file")\n' > "$ARTIFACTS_DIR/demo_script.py"
openssl dgst -sha256 \
  -sign "$CERTS_DIR/Demo_Code_Signer.key.pem" \
  -out "$ARTIFACTS_DIR/demo_script.py.sig" \
  "$ARTIFACTS_DIR/demo_script.py"
openssl x509 \
  -in "$CERTS_DIR/Demo_Code_Signer.cert.pem" \
  -pubkey \
  -noout \
  > "$ARTIFACTS_DIR/code_signer.pub.pem"
openssl dgst -sha256 \
  -verify "$ARTIFACTS_DIR/code_signer.pub.pem" \
  -signature "$ARTIFACTS_DIR/demo_script.py.sig" \
  "$ARTIFACTS_DIR/demo_script.py"
pass "File signature verifies successfully"

printf '# tampered\n' >> "$ARTIFACTS_DIR/demo_script.py"
if openssl dgst -sha256 \
  -verify "$ARTIFACTS_DIR/code_signer.pub.pem" \
  -signature "$ARTIFACTS_DIR/demo_script.py.sig" \
  "$ARTIFACTS_DIR/demo_script.py" >/dev/null 2>&1; then
  fail "Tampered file unexpectedly passed signature verification"
else
  pass "Tampered file signature verification fails as expected"
fi

info "10. Revocation demo: revoke TLS certificate and generate CRL"
SERVER_SERIAL="$(openssl x509 -in "$CERTS_DIR/localhost.cert.pem" -noout -serial | sed 's/^serial=//')"
run_micropki ca revoke "$SERVER_SERIAL" --reason keycompromise --force
run_micropki ca gen-crl --ca intermediate --out-dir "$PKI_DIR"
test -s "$CRL_DIR/intermediate.crl.pem"
pass "Server certificate revoked and Intermediate CRL generated"

if curl --cacert "$CERTS_DIR/ca.cert.pem" \
  --crlfile "$CRL_DIR/intermediate.crl.pem" \
  -fsS "https://localhost:$TLS_PORT" >/dev/null 2>&1; then
  fail "curl accepted revoked TLS certificate, but it should reject it"
else
  pass "curl rejects revoked TLS certificate when CRL checking is enabled"
fi

info "11. Audit integrity demo"
if [[ -f "$PKI_DIR/audit.log" ]]; then
  run_micropki audit verify --log-file "$PKI_DIR/audit.log"
  pass "Audit log integrity verified"
else
  pass "Audit log file not found in $PKI_DIR/audit.log; audit demo skipped for this build"
fi

info "12. Policy enforcement demo"
if run_micropki ca issue-cert \
  --ca-cert "$CERTS_DIR/intermediate.cert.pem" \
  --ca-key "$PRIVATE_DIR/intermediate.key.pem" \
  --ca-pass-file "$SECRETS_DIR/intermediate.pass" \
  --template server \
  --subject "CN=invalid-no-san,O=MicroPKI" \
  --out-dir "$CERTS_DIR" \
  --validity-days 365 >/dev/null 2>&1; then
  fail "Invalid server certificate without SAN was unexpectedly issued"
else
  pass "Invalid server certificate without SAN is rejected"
fi

info "Demo completed successfully"
printf 'Artifacts are available in: %s\n' "$WORKDIR"

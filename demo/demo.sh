#!/usr/bin/env bash
set -Eeuo pipefail


GREEN="\033[0;32m"
RED="\033[0;31m"
YELLOW="\033[1;33m"
NC="\033[0m"

PASS_COUNT=0
FAIL_COUNT=0

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK_DIR="${MICROPKI_DEMO_DIR:-$ROOT_DIR/demo/workdir}"
PKI_DIR="$WORK_DIR/pki"
SECRETS_DIR="$PKI_DIR/secrets"
CERTS_DIR="$PKI_DIR/certs"
PRIVATE_DIR="$PKI_DIR/private"
CRL_DIR="$PKI_DIR/crl"
OCSP_DIR="$PKI_DIR/ocsp"
ARTIFACTS_DIR="$WORK_DIR/artifacts"

REPO_PORT="${MICROPKI_REPO_PORT:-18080}"
OCSP_PORT="${MICROPKI_OCSP_PORT:-18081}"
TLS_PORT="${MICROPKI_TLS_PORT:-18443}"
HOST="127.0.0.1"

# Override this if your project is installed as a console command:
#   MICROPKI_CMD="micropki" ./demo/demo.sh
MICROPKI_CMD="${MICROPKI_CMD:-python -m micropki}"

REPO_PID=""
OCSP_PID=""
TLS_PID=""

step() {
  echo -e "\n${YELLOW}==>${NC} $*"
}

pass() {
  PASS_COUNT=$((PASS_COUNT + 1))
  echo -e "${GREEN}[PASS]${NC} $*"
}

fail() {
  FAIL_COUNT=$((FAIL_COUNT + 1))
  echo -e "${RED}[FAIL]${NC} $*"
  exit 1
}

run() {
  echo "+ $*"
  eval "$@"
}

cleanup() {
  set +e
  [[ -n "$TLS_PID" ]] && kill "$TLS_PID" 2>/dev/null || true
  [[ -n "$OCSP_PID" ]] && kill "$OCSP_PID" 2>/dev/null || true
  [[ -n "$REPO_PID" ]] && kill "$REPO_PID" 2>/dev/null || true
  wait "$TLS_PID" 2>/dev/null || true
  wait "$OCSP_PID" 2>/dev/null || true
  wait "$REPO_PID" 2>/dev/null || true
}
trap cleanup EXIT

wait_for_port() {
  local port="$1"
  local name="$2"
  for _ in $(seq 1 80); do
    if python - <<PY >/dev/null 2>&1
import socket
s=socket.socket()
s.settimeout(0.25)
s.connect(("$HOST", int("$port")))
s.close()
PY
    then
      pass "$name is listening on $HOST:$port"
      return 0
    fi
    sleep 0.25
  done
  fail "$name did not start on $HOST:$port"
}

require_tool() {
  command -v "$1" >/dev/null 2>&1 || fail "Required tool not found: $1"
}

get_serial_by_subject() {
  local subject_part="$1"
  python - <<PY
import sqlite3
conn = sqlite3.connect(r"$PKI_DIR/micropki.db")
conn.row_factory = sqlite3.Row
row = conn.execute("SELECT serial_hex FROM certificates WHERE subject LIKE ? ORDER BY id DESC LIMIT 1", ("%" + "$subject_part" + "%",)).fetchone()
conn.close()
if not row:
    raise SystemExit("serial not found for subject: $subject_part")
print(row["serial_hex"])
PY
}

step "Checking required tools"
require_tool python
require_tool openssl
require_tool curl
pass "python, openssl and curl are available"

step "Cleaning and preparing demo workspace"
rm -rf "$WORK_DIR"
mkdir -p "$SECRETS_DIR" "$CERTS_DIR" "$PRIVATE_DIR" "$CRL_DIR" "$OCSP_DIR" "$ARTIFACTS_DIR"
printf "RootPass123!\n" > "$SECRETS_DIR/root.pass"
printf "InterPass456!\n" > "$SECRETS_DIR/intermediate.pass"
pass "Workspace prepared at $WORK_DIR"

step "Initialising Root CA"
run "$MICROPKI_CMD ca init \
  --subject 'CN=MicroPKI Demo Root CA,O=MicroPKI,C=US' \
  --key-type rsa \
  --key-size 4096 \
  --passphrase-file '$SECRETS_DIR/root.pass' \
  --out-dir '$PKI_DIR' \
  --validity-days 3650 \
  --log-file '$WORK_DIR/root-ca.log'"
pass "Root CA created"

step "Initialising SQLite certificate database"
run "$MICROPKI_CMD db init --db-path '$PKI_DIR/micropki.db'"
pass "Database initialised"

step "Issuing Intermediate CA signed by Root CA"
run "$MICROPKI_CMD ca issue-intermediate \
  --root-cert '$CERTS_DIR/ca.cert.pem' \
  --root-key '$PRIVATE_DIR/ca.key.pem' \
  --root-pass-file '$SECRETS_DIR/root.pass' \
  --subject 'CN=MicroPKI Demo Intermediate CA,O=MicroPKI' \
  --key-type rsa \
  --key-size 4096 \
  --passphrase-file '$SECRETS_DIR/intermediate.pass' \
  --out-dir '$PKI_DIR' \
  --validity-days 1825 \
  --pathlen 0 \
  --log-file '$WORK_DIR/intermediate-ca.log'"
pass "Intermediate CA created"

step "Issuing server, client, code signing and OCSP responder certificates"
run "$MICROPKI_CMD ca issue-cert \
  --ca-cert '$CERTS_DIR/intermediate.cert.pem' \
  --ca-key '$PRIVATE_DIR/intermediate.key.pem' \
  --ca-pass-file '$SECRETS_DIR/intermediate.pass' \
  --template server \
  --subject 'CN=localhost,O=MicroPKI Demo' \
  --san dns:localhost \
  --san ip:127.0.0.1 \
  --out-dir '$CERTS_DIR' \
  --validity-days 365 \
  --log-file '$WORK_DIR/server-cert.log'"

run "$MICROPKI_CMD ca issue-cert \
  --ca-cert '$CERTS_DIR/intermediate.cert.pem' \
  --ca-key '$PRIVATE_DIR/intermediate.key.pem' \
  --ca-pass-file '$SECRETS_DIR/intermediate.pass' \
  --template client \
  --subject 'CN=Demo Client,O=MicroPKI Demo' \
  --san email:client@example.local \
  --out-dir '$CERTS_DIR' \
  --validity-days 365 \
  --log-file '$WORK_DIR/client-cert.log'"

run "$MICROPKI_CMD ca issue-cert \
  --ca-cert '$CERTS_DIR/intermediate.cert.pem' \
  --ca-key '$PRIVATE_DIR/intermediate.key.pem' \
  --ca-pass-file '$SECRETS_DIR/intermediate.pass' \
  --template code_signing \
  --subject 'CN=Demo Code Signer,O=MicroPKI Demo' \
  --out-dir '$CERTS_DIR' \
  --validity-days 365 \
  --log-file '$WORK_DIR/code-signing-cert.log'"

run "$MICROPKI_CMD ca issue-ocsp-cert \
  --ca-cert '$CERTS_DIR/intermediate.cert.pem' \
  --ca-key '$PRIVATE_DIR/intermediate.key.pem' \
  --ca-pass-file '$SECRETS_DIR/intermediate.pass' \
  --subject 'CN=OCSP Responder,O=MicroPKI Demo' \
  --key-type rsa \
  --key-size 2048 \
  --out-dir '$CERTS_DIR' \
  --validity-days 365 \
  --log-file '$WORK_DIR/ocsp-cert.log'"
pass "All demo certificates issued"

step "Generating initial Intermediate CRL"
run "$MICROPKI_CMD ca gen-crl \
  --ca intermediate \
  --out-dir '$PKI_DIR' \
  --ca-pass-file '$SECRETS_DIR/intermediate.pass'"
pass "Initial CRL generated"

step "Starting repository server"
$MICROPKI_CMD repo serve \
  --host "$HOST" \
  --port "$REPO_PORT" \
  --db-path "$PKI_DIR/micropki.db" \
  --cert-dir "$CERTS_DIR" \
  --log-file "$WORK_DIR/repo.log" > "$WORK_DIR/repo.stdout.log" 2>&1 &
REPO_PID=$!
wait_for_port "$REPO_PORT" "Repository server"

step "Starting OCSP responder"
$MICROPKI_CMD ocsp serve \
  --host "$HOST" \
  --port "$OCSP_PORT" \
  --db-path "$PKI_DIR/micropki.db" \
  --responder-cert "$CERTS_DIR/OCSP_Responder.cert.pem" \
  --responder-key "$CERTS_DIR/OCSP_Responder.key.pem" \
  --ca-cert "$CERTS_DIR/intermediate.cert.pem" \
  --cache-ttl 60 \
  --log-file "$WORK_DIR/ocsp.log" > "$WORK_DIR/ocsp.stdout.log" 2>&1 &
OCSP_PID=$!
wait_for_port "$OCSP_PORT" "OCSP responder"

step "Validating certificate chain before revocation"
run "$MICROPKI_CMD ca validate-chain \
  --cert '$CERTS_DIR/localhost.cert.pem' \
  --intermediate '$CERTS_DIR/intermediate.cert.pem' \
  --root '$CERTS_DIR/ca.cert.pem'"
pass "Leaf -> Intermediate -> Root chain is valid"

step "Fetching CA certificate and CRL from repository API"
run "curl -fsS 'http://$HOST:$REPO_PORT/ca/root' -o '$ARTIFACTS_DIR/root-from-repo.pem'"
run "curl -fsS 'http://$HOST:$REPO_PORT/crl?ca=intermediate' -o '$ARTIFACTS_DIR/intermediate-from-repo.crl.pem'"
pass "Repository API returned Root CA and Intermediate CRL"

step "Starting TLS server with issued server certificate"
S_SERVER_CHAIN_ARGS=""
if openssl s_server -help 2>&1 | grep -q -- '-cert_chain'; then
  S_SERVER_CHAIN_ARGS="-cert_chain '$CERTS_DIR/intermediate.cert.pem'"
else
  cat "$CERTS_DIR/localhost.cert.pem" "$CERTS_DIR/intermediate.cert.pem" > "$ARTIFACTS_DIR/localhost.chain.cert.pem"
  S_SERVER_CHAIN_ARGS="-cert '$ARTIFACTS_DIR/localhost.chain.cert.pem'"
fi

if [[ -n "$S_SERVER_CHAIN_ARGS" && "$S_SERVER_CHAIN_ARGS" == -cert* ]]; then
  eval "openssl s_server -quiet -WWW -accept '$TLS_PORT' $S_SERVER_CHAIN_ARGS -key '$CERTS_DIR/localhost.key.pem'" > "$WORK_DIR/tls.stdout.log" 2>&1 &
else
  eval "openssl s_server -quiet -WWW -accept '$TLS_PORT' -cert '$CERTS_DIR/localhost.cert.pem' -key '$CERTS_DIR/localhost.key.pem' $S_SERVER_CHAIN_ARGS" > "$WORK_DIR/tls.stdout.log" 2>&1 &
fi
TLS_PID=$!
wait_for_port "$TLS_PORT" "OpenSSL TLS server"

step "TLS-1: connecting with curl using Root CA trust anchor"
run "curl -fsS --cacert '$CERTS_DIR/ca.cert.pem' 'https://localhost:$TLS_PORT/' -o '$ARTIFACTS_DIR/tls-index.html'"
pass "curl connected successfully when Root CA was trusted"

step "Code signing demo: sign and verify a script"
cat > "$ARTIFACTS_DIR/hello.sh" <<'SCRIPT'
#!/usr/bin/env bash
echo "Hello from signed MicroPKI demo script"
SCRIPT
chmod +x "$ARTIFACTS_DIR/hello.sh"
run "openssl dgst -sha256 -sign '$CERTS_DIR/Demo_Code_Signer.key.pem' -out '$ARTIFACTS_DIR/hello.sh.sig' '$ARTIFACTS_DIR/hello.sh'"
run "openssl x509 -in '$CERTS_DIR/Demo_Code_Signer.cert.pem' -pubkey -noout > '$ARTIFACTS_DIR/code-signing.pub.pem'"
run "openssl dgst -sha256 -verify '$ARTIFACTS_DIR/code-signing.pub.pem' -signature '$ARTIFACTS_DIR/hello.sh.sig' '$ARTIFACTS_DIR/hello.sh'"
pass "Code signature verifies for original file"

step "Code signing negative demo: tampered file must fail verification"
echo '# tampered' >> "$ARTIFACTS_DIR/hello.sh"
if openssl dgst -sha256 -verify "$ARTIFACTS_DIR/code-signing.pub.pem" -signature "$ARTIFACTS_DIR/hello.sh.sig" "$ARTIFACTS_DIR/hello.sh" >/dev/null 2>&1; then
  fail "Tampered file unexpectedly passed signature verification"
else
  pass "Tampered file is rejected by signature verification"
fi

step "Policy enforcement demo: server certificate without SAN must be rejected"
if $MICROPKI_CMD ca issue-cert \
  --ca-cert "$CERTS_DIR/intermediate.cert.pem" \
  --ca-key "$PRIVATE_DIR/intermediate.key.pem" \
  --ca-pass-file "$SECRETS_DIR/intermediate.pass" \
  --template server \
  --subject 'CN=invalid-no-san.example' \
  --out-dir "$CERTS_DIR" \
  --validity-days 365 >/dev/null 2>&1; then
  fail "Policy violation unexpectedly succeeded"
else
  pass "Policy violation was blocked"
fi

step "Revoking server certificate and regenerating CRL"
SERVER_SERIAL="$(get_serial_by_subject 'CN=localhost')"
run "$MICROPKI_CMD ca revoke '$SERVER_SERIAL' --reason keycompromise --force"
run "$MICROPKI_CMD ca gen-crl \
  --ca intermediate \
  --out-dir '$PKI_DIR' \
  --ca-pass-file '$SECRETS_DIR/intermediate.pass'"
pass "Server certificate revoked and fresh CRL generated"

step "TLS-3: curl must reject revoked TLS certificate with CRL checking"
if curl --help all 2>/dev/null | grep -q -- '--crlfile'; then
  if curl -fsS --cacert "$CERTS_DIR/ca.cert.pem" --crlfile "$CRL_DIR/intermediate.crl.pem" "https://localhost:$TLS_PORT/" -o "$ARTIFACTS_DIR/tls-after-revocation.html" >/dev/null 2>&1; then
    fail "curl accepted a revoked certificate even with --crlfile"
  else
    pass "curl rejected the revoked certificate with --crlfile"
  fi
else
  echo "curl in this environment does not expose --crlfile; using openssl verify fallback"
  if openssl verify -crl_check \
      -CAfile "$CERTS_DIR/ca.cert.pem" \
      -untrusted "$CERTS_DIR/intermediate.cert.pem" \
      -CRLfile "$CRL_DIR/intermediate.crl.pem" \
      "$CERTS_DIR/localhost.cert.pem" >/dev/null 2>&1; then
    fail "openssl verify accepted revoked certificate"
  else
    pass "OpenSSL CRL check rejected the revoked certificate"
  fi
fi

step "Audit log integrity verification"
if [[ -f "$PKI_DIR/audit.log" ]]; then
  run "$MICROPKI_CMD audit verify --log-file '$PKI_DIR/audit.log'"
  pass "Audit log hash chain verified"
else
  echo "Audit log not found at $PKI_DIR/audit.log; skipping audit verification for this code version"
fi

step "Demo summary"
echo -e "${GREEN}Completed successfully:${NC} $PASS_COUNT checks"
echo "Artifacts are stored in: $WORK_DIR"
echo "Repository URL was: http://$HOST:$REPO_PORT"
echo "OCSP URL was:       http://$HOST:$OCSP_PORT/ocsp"
echo "TLS URL was:        https://localhost:$TLS_PORT/"

.PHONY: help install test clean run-rsa run-ecc verify

help:
@echo "MicroPKI Makefile"
@echo ""
@echo "Available targets:"
@echo "  install    - Install dependencies and package"
@echo "  test       - Run tests"
@echo "  test-cov   - Run tests with coverage report"
@echo "  clean      - Clean generated files"
@echo "  run-rsa    - Generate RSA Root CA (example)"
@echo "  run-ecc    - Generate ECC Root CA (example)"
@echo "  verify     - Verify generated certificate"

install:
python3 -m pip install --upgrade pip
pip install -r requirements.txt
pip install -e .

test:
pytest -v

test-cov:
pytest --cov=micropki --cov-report=html --cov-report=term
@echo "Coverage report generated in htmlcov/index.html"

clean:
rm -rf pki/ logs/ secrets/*.pass
rm -rf build/ dist/ *.egg-info
rm -rf htmlcov/ .coverage .pytest_cache
find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
find . -type f -name "*.pyc" -delete

run-rsa:
@mkdir -p secrets
@echo "SuperSecurePassword123" > secrets/ca.pass
micropki ca init \
--subject "/CN=Demo Root CA/O=MicroPKI/C=RU" \
--key-type rsa \
--key-size 4096 \
--passphrase-file ./secrets/ca.pass \
--out-dir ./pki \
--validity-days 3650 \
--log-file ./logs/ca-init.log

run-ecc:
@mkdir -p secrets
@echo "SuperSecurePassword123" > secrets/ca.pass
micropki ca init \
--subject "CN=ECC Root CA,O=MicroPKI,C=RU" \
--key-type ecc \
--key-size 384 \
--passphrase-file ./secrets/ca.pass \
--out-dir ./pki \
--log-file ./logs/ca-init.log

verify:
@echo "=== OpenSSL Verification ==="
openssl x509 -in pki/certs/ca.cert.pem -text -noout
@echo ""
@echo "=== Self-verification ==="
openssl verify -CAfile pki/certs/ca.cert.pem pki/certs/ca.cert.pem
@echo ""
@echo "=== MicroPKI Verification ==="
micropki ca verify --cert pki/certs/ca.cert.pem

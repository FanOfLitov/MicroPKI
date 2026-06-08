from pathlib import Path

ROOT = Path.cwd()
PKG = ROOT / "micropki"

def read(path: Path) -> str:
    return path.read_text(encoding="utf-8")

def write(path: Path, text: str) -> None:
    path.write_text(text, encoding="utf-8")
    print(f"[OK] patched {path}")

def patch_main():
    p = PKG / "__main__.py"
    text = "from micropki.cli import main\nimport sys\n\nif __name__ == \"__main__\":\n    sys.exit(main())\n"
    write(p, text)

def patch_certificates():
    p = PKG / "certificates.py"
    text = read(p)

    if "def cert_not_before_utc(" not in text:
        marker = """_OID_MAP = {
    "CN": NameOID.COMMON_NAME,
    "O": NameOID.ORGANIZATION_NAME,
    "OU": NameOID.ORGANIZATIONAL_UNIT_NAME,
    "C": NameOID.COUNTRY_NAME,
    "ST": NameOID.STATE_OR_PROVINCE_NAME,
    "L": NameOID.LOCALITY_NAME,
    "EMAIL": NameOID.EMAIL_ADDRESS,
    "EMAILADDRESS": NameOID.EMAIL_ADDRESS,
}
"""
        helpers = """
def _ensure_utc(dt: datetime.datetime) -> datetime.datetime:
    \"\"\"Return timezone-aware UTC datetime for old/new cryptography versions.\"\"\"
    if dt.tzinfo is None:
        return dt.replace(tzinfo=datetime.timezone.utc)
    return dt.astimezone(datetime.timezone.utc)


def cert_not_before_utc(cert: x509.Certificate) -> datetime.datetime:
    \"\"\"Compatibility wrapper for cert.not_valid_before_utc / cert.not_valid_before.\"\"\"
    value = getattr(cert, "not_valid_before_utc", None)
    if value is None:
        value = cert.not_valid_before
    return _ensure_utc(value)


def cert_not_after_utc(cert: x509.Certificate) -> datetime.datetime:
    \"\"\"Compatibility wrapper for cert.not_valid_after_utc / cert.not_valid_after.\"\"\"
    value = getattr(cert, "not_valid_after_utc", None)
    if value is None:
        value = cert.not_valid_after
    return _ensure_utc(value)
"""
        if marker not in text:
            raise RuntimeError("Cannot find _OID_MAP marker in certificates.py")
        text = text.replace(marker, marker + helpers + "\n")

    write(p, text)

def patch_ca():
    p = PKG / "ca.py"
    text = read(p)

    if "from cryptography import x509" not in text:
        text = text.replace("import re\n", "import re\nfrom cryptography import x509\n")

    if "cert_not_before_utc" not in text.split("from .csr import", 1)[0]:
        text = text.replace(
            "    load_certificate,\n    save_certificate,\n    serialize_certificate,\n",
            "    load_certificate,\n    save_certificate,\n    serialize_certificate,\n    cert_not_before_utc,\n    cert_not_after_utc,\n",
        )

    text = text.replace("inter_cert.not_valid_before_utc", "cert_not_before_utc(inter_cert)")
    text = text.replace("inter_cert.not_valid_after_utc", "cert_not_after_utc(inter_cert)")
    text = text.replace("cert.not_valid_before_utc", "cert_not_before_utc(cert)")
    text = text.replace("cert.not_valid_after_utc", "cert_not_after_utc(cert)")

    text = text.replace("cert_not_before_utc(cert)(cert)", "cert_not_before_utc(cert)")
    text = text.replace("cert_not_after_utc(cert)(cert)", "cert_not_after_utc(cert)")
    text = text.replace("cert_not_before_utc(inter_cert)(inter_cert)", "cert_not_before_utc(inter_cert)")
    text = text.replace("cert_not_after_utc(inter_cert)(inter_cert)", "cert_not_after_utc(inter_cert)")

    write(p, text)

def patch_chain():
    p = PKG / "chain.py"
    text = read(p)

    if "cert_not_before_utc" not in text:
        text = text.replace(
            "from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding\n",
            "from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding\nfrom .certificates import cert_not_before_utc, cert_not_after_utc\n",
        )

    text = text.replace("cert.not_valid_before_utc", "cert_not_before_utc(cert)")
    text = text.replace("cert.not_valid_after_utc", "cert_not_after_utc(cert)")
    text = text.replace("cert_not_before_utc(cert)(cert)", "cert_not_before_utc(cert)")
    text = text.replace("cert_not_after_utc(cert)(cert)", "cert_not_after_utc(cert)")

    write(p, text)

def patch_revocation_check():
    p = PKG / "revocation_check.py"
    text = read(p)

    if "from cryptography.x509.oid import AuthorityInformationAccessOID" not in text:
        text = text.replace(
            "from cryptography.x509 import ocsp as x509_ocsp\n",
            "from cryptography.x509 import ocsp as x509_ocsp\nfrom cryptography.x509.oid import AuthorityInformationAccessOID\n",
        )

    text = text.replace("x509.AuthorityInformationAccessOID.OCSP", "AuthorityInformationAccessOID.OCSP")

    if "def _crl_next_update_utc(" not in text:
        marker = "logger = logging.getLogger(__name__)\n"
        helpers = """
def _crl_next_update_utc(crl: x509.CertificateRevocationList):
    value = getattr(crl, "next_update_utc", None)
    if value is None:
        value = crl.next_update
        if value is not None and value.tzinfo is None:
            value = value.replace(tzinfo=datetime.timezone.utc)
    return value


def _revoked_date_utc(revoked_cert: x509.RevokedCertificate):
    value = getattr(revoked_cert, "revocation_date_utc", None)
    if value is None:
        value = revoked_cert.revocation_date
        if value is not None and value.tzinfo is None:
            value = value.replace(tzinfo=datetime.timezone.utc)
    return value
"""
        text = text.replace(marker, marker + helpers + "\n")

    text = text.replace("crl.next_update_utc", "_crl_next_update_utc(crl)")
    text = text.replace("revoked_cert.revocation_date_utc", "_revoked_date_utc(revoked_cert)")
    text = text.replace("_crl_next_update_utc(crl)(crl)", "_crl_next_update_utc(crl)")
    text = text.replace("_revoked_date_utc(revoked_cert)(revoked_cert)", "_revoked_date_utc(revoked_cert)")

    write(p, text)

def main():
    if not PKG.exists():
        raise SystemExit("[FAIL] Run this script from the project root where the micropki/ folder exists.")

    patch_main()
    patch_certificates()
    patch_ca()
    patch_chain()
    patch_revocation_check()

    print("\nDone. Now run:")
    print("  python -m pytest -q")
    print("  bash ./demo/demo.sh")

if __name__ == "__main__":
    main()

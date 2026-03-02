import pytest
import os
from pathlib import Path

from micropki.csr import generate_csr, load_csr, verify_csr
from micropki.templates import (
    get_template,
    parse_san_entry,
    build_san_extension,
    ServerTemplate,
    ClientTemplate,
    CodeSigningTemplate
)
from micropki.crypto_utils import generate_rsa_key, generate_ecc_key
from micropki.chain import verify_certificate_signature, check_validity_period


class TestCSR:
    """Test CSR generation and handling."""

    def test_generate_rsa_csr(self):
        """Test generating RSA CSR."""
        key = generate_rsa_key(4096)
        csr_pem = generate_csr(key, "CN=Test,O=MicroPKI", is_ca=False)

        assert b"BEGIN CERTIFICATE REQUEST" in csr_pem
        assert b"END CERTIFICATE REQUEST" in csr_pem

    def test_generate_ca_csr_with_pathlen(self):
        """Test generating CA CSR with path length."""
        key = generate_rsa_key(4096)
        csr_pem = generate_csr(key, "CN=Intermediate CA", is_ca=True, path_length=0)

        # Load and check
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend
        csr = x509.load_pem_x509_csr(csr_pem, default_backend())

        # Check for BasicConstraints extension
        extensions = list(csr.extensions)
        assert len(extensions) > 0


class TestTemplates:
    """Test certificate templates."""

    def test_get_server_template(self):
        """Test getting server template."""
        template = get_template('server')
        assert isinstance(template, ServerTemplate)
        assert template.name == 'server'

    def test_get_client_template(self):
        """Test getting client template."""
        template = get_template('client')
        assert isinstance(template, ClientTemplate)

    def test_get_code_signing_template(self):
        """Test getting code signing template."""
        template = get_template('code_signing')
        assert isinstance(template, CodeSigningTemplate)

    def test_unknown_template(self):
        """Test that unknown template raises error."""
        with pytest.raises(ValueError, match="Unknown template"):
            get_template('unknown')

    def test_parse_san_dns(self):
        """Test parsing DNS SAN."""
        entry = parse_san_entry("dns:example.com")
        assert entry['type'] == 'dns'
        assert entry['value'] == 'example.com'

    def test_parse_san_ip(self):
        """Test parsing IP SAN."""
        entry = parse_san_entry("ip:192.168.1.1")
        assert entry['type'] == 'ip'
        from ipaddress import IPv4Address
        assert isinstance(entry['value'], IPv4Address)

    def test_parse_san_email(self):
        """Test parsing email SAN."""
        entry = parse_san_entry("email:user@example.com")
        assert entry['type'] == 'email'
        assert entry['value'] == 'user@example.com'

    def test_parse_san_uri(self):
        """Test parsing URI SAN."""
        entry = parse_san_entry("uri:https://example.com")
        assert entry['type'] == 'uri'

    def test_parse_san_invalid_format(self):
        """Test that invalid SAN format raises error."""
        with pytest.raises(ValueError, match="Invalid SAN format"):
            parse_san_entry("invalid")

    def test_parse_san_invalid_type(self):
        """Test that invalid SAN type raises error."""
        with pytest.raises(ValueError, match="Invalid SAN type"):
            parse_san_entry("bad:value")

    def test_server_template_validate_san_valid(self):
        """Test server template accepts DNS and IP."""
        template = ServerTemplate()
        san_entries = [
            {'type': 'dns', 'value': 'example.com'},
            {'type': 'ip', 'value': '192.168.1.1'}
        ]
        assert template.validate_san(san_entries) is True

    def test_server_template_validate_san_no_dns_or_ip(self):
        """Test server template rejects entries without DNS or IP."""
        template = ServerTemplate()
        san_entries = [{'type': 'email', 'value': 'user@example.com'}]
        # Should fail because no DNS or IP present
        with pytest.raises(ValueError, match="requires at least one"):
            template.validate_san(san_entries)

    def test_server_template_validate_san_unsupported_type(self):
        """Test server template with both valid and invalid types."""
        template = ServerTemplate()
        # Has DNS (valid) but also URI (invalid for server)
        san_entries = [
            {'type': 'dns', 'value': 'example.com'},
            {'type': 'uri', 'value': 'https://example.com'}
        ]
        with pytest.raises(ValueError, match="does not support"):
            template.validate_san(san_entries)

    def test_client_template_validate_san(self):
        """Test client template accepts email and DNS."""
        template = ClientTemplate()
        san_entries = [
            {'type': 'email', 'value': 'user@example.com'},
            {'type': 'dns', 'value': 'client.example.com'}
        ]
        assert template.validate_san(san_entries) is True

    def test_code_signing_template_validate_san(self):
        """Test code signing template accepts DNS and URI."""
        template = CodeSigningTemplate()
        san_entries = [
            {'type': 'dns', 'value': 'signer.example.com'},
            {'type': 'uri', 'value': 'https://example.com'}
        ]
        assert template.validate_san(san_entries) is True

    def test_build_san_extension(self):
        """Test building SAN extension."""
        from ipaddress import ip_address
        san_entries = [
            {'type': 'dns', 'value': 'example.com'},
            {'type': 'ip', 'value': ip_address('192.168.1.1')},
            {'type': 'email', 'value': 'user@example.com'}
        ]

        san_ext = build_san_extension(san_entries)

        from cryptography import x509
        assert isinstance(san_ext, x509.SubjectAlternativeName)
        assert len(list(san_ext)) == 3


class TestChain:
    """Test certificate chain validation."""

    def test_verify_certificate_signature(self, tmp_path):
        """Test signature verification (basic smoke test)."""
        from micropki.certificates import create_root_ca_certificate, parse_subject_dn
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend

        # Create a self-signed cert
        key = generate_rsa_key(4096)
        subject = parse_subject_dn("CN=Test CA")
        cert_der = create_root_ca_certificate(key, subject, 365)

        cert = x509.load_der_x509_certificate(cert_der, default_backend())

        # Self-signature should verify
        from micropki.chain import verify_certificate_signature
        assert verify_certificate_signature(cert, cert) is True


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
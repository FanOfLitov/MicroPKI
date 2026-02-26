import os
import tempfile
import shutil
from pathlib import Path
import pytest

from micropki.crypto_utils import (
    read_passphrase_file,
    generate_rsa_key,
    generate_ecc_key,
    save_encrypted_private_key
)
from micropki.certificates import (
    parse_subject_dn,
    generate_serial_number,
    create_root_ca_certificate
)
from micropki.ca import init_root_ca
from micropki.logger import setup_logger


class TestCryptoUtils:
    """Test cryptographic utility functions."""
    
    def test_read_passphrase_file(self, tmp_path):
        """Test reading passphrase from file."""
        passphrase_file = tmp_path / "passphrase.txt"
        passphrase_file.write_bytes(b"test-passphrase\n")
        
        passphrase = read_passphrase_file(str(passphrase_file))
        assert passphrase == b"test-passphrase"
    
    def test_read_passphrase_empty_file(self, tmp_path):
        """Test reading empty passphrase file raises error."""
        passphrase_file = tmp_path / "empty.txt"
        passphrase_file.write_bytes(b"")
        
        with pytest.raises(ValueError, match="empty"):
            read_passphrase_file(str(passphrase_file))
    
    def test_generate_rsa_key(self):
        """Test RSA key generation."""
        key = generate_rsa_key(4096)
        assert key.key_size == 4096
    
    def test_generate_rsa_key_wrong_size(self):
        """Test RSA key generation with wrong size raises error."""
        with pytest.raises(ValueError, match="4096"):
            generate_rsa_key(2048)
    
    def test_generate_ecc_key(self):
        """Test ECC key generation."""
        key = generate_ecc_key(384)
        assert key.curve.name == "secp384r1"
    
    def test_generate_ecc_key_wrong_size(self):
        """Test ECC key generation with wrong size raises error."""
        with pytest.raises(ValueError, match="384"):
            generate_ecc_key(256)
    
    def test_save_encrypted_private_key_rsa(self, tmp_path):
        """Test saving encrypted RSA private key."""
        key = generate_rsa_key(4096)
        key_file = tmp_path / "test.key"
        passphrase = b"test-password"
        
        save_encrypted_private_key(key, str(key_file), passphrase)
        
        assert key_file.exists()
        # Verify it's encrypted (contains ENCRYPTED)
        content = key_file.read_text()
        assert "ENCRYPTED" in content
    
    def test_save_encrypted_private_key_ecc(self, tmp_path):
        """Test saving encrypted ECC private key."""
        key = generate_ecc_key(384)
        key_file = tmp_path / "test.key"
        passphrase = b"test-password"
        
        save_encrypted_private_key(key, str(key_file), passphrase)
        
        assert key_file.exists()
        content = key_file.read_text()
        assert "ENCRYPTED" in content


class TestCertificates:
    """Test certificate operations."""
    
    def test_parse_subject_slash_notation(self):
        """Test parsing subject DN in slash notation."""
        subject = parse_subject_dn("/CN=Test CA/O=MicroPKI/C=US")
        assert subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value == "Test CA"
        assert subject.get_attributes_for_oid(x509.NameOID.ORGANIZATION_NAME)[0].value == "MicroPKI"
        assert subject.get_attributes_for_oid(x509.NameOID.COUNTRY_NAME)[0].value == "US"
    
    def test_parse_subject_comma_notation(self):
        """Test parsing subject DN in comma notation."""
        subject = parse_subject_dn("CN=Test CA,O=MicroPKI,C=US")
        assert subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value == "Test CA"
    
    def test_parse_subject_no_cn(self):
        """Test parsing subject without CN raises error."""
        with pytest.raises(ValueError, match="Common Name"):
            parse_subject_dn("O=MicroPKI,C=US")
    
    def test_parse_subject_invalid_format(self):
        """Test parsing invalid subject format."""
        with pytest.raises(ValueError):
            parse_subject_dn("InvalidFormat")
    
    def test_generate_serial_number(self):
        """Test serial number generation."""
        serial1 = generate_serial_number()
        serial2 = generate_serial_number()
        
        assert serial1 > 0
        assert serial2 > 0
        assert serial1 != serial2  # Should be different
    
    def test_create_root_ca_certificate_rsa(self):
        """Test creating Root CA certificate with RSA key."""
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend
        
        private_key = generate_rsa_key(4096)
        subject = parse_subject_dn("CN=Test Root CA,O=MicroPKI")
        
        cert_der = create_root_ca_certificate(private_key, subject, 365)
        
        # Parse and verify certificate
        cert = x509.load_der_x509_certificate(cert_der, default_backend())
        
        assert cert.subject == cert.issuer  # Self-signed
        assert cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value == "Test Root CA"
        
        # Check extensions
        basic_constraints = cert.extensions.get_extension_for_oid(
            x509.oid.ExtensionOID.BASIC_CONSTRAINTS
        )
        assert basic_constraints.value.ca is True
        assert basic_constraints.critical is True
    
    def test_create_root_ca_certificate_ecc(self):
        """Test creating Root CA certificate with ECC key."""
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend
        
        private_key = generate_ecc_key(384)
        subject = parse_subject_dn("CN=Test ECC Root CA")
        
        cert_der = create_root_ca_certificate(private_key, subject, 365)
        
        cert = x509.load_der_x509_certificate(cert_der, default_backend())
        assert cert.subject == cert.issuer


class TestCAOperations:
    """Test full CA initialization."""
    
    def test_init_root_ca_rsa(self, tmp_path):
        """Test complete Root CA initialization with RSA."""
        # Create passphrase file
        passphrase_file = tmp_path / "passphrase.txt"
        passphrase_file.write_bytes(b"test-password")
        
        # Create log file path
        log_file = tmp_path / "test.log"
        
        # Setup config
        config = {
            'subject': '/CN=Test Root CA/O=MicroPKI/C=US',
            'key_type': 'rsa',
            'key_size': 4096,
            'passphrase': b'test-password',
            'out_dir': str(tmp_path / 'pki'),
            'validity_days': 365,
            'force': False,
            'logger': setup_logger(str(log_file))
        }
        
        # Initialize CA
        init_root_ca(config)
        
        # Verify output files
        pki_dir = tmp_path / 'pki'
        assert (pki_dir / 'private' / 'ca.key.pem').exists()
        assert (pki_dir / 'certs' / 'ca.cert.pem').exists()
        assert (pki_dir / 'policy.txt').exists()
        
        # Verify log file
        assert log_file.exists()
        log_content = log_file.read_text()
        assert "Root CA initialization completed successfully" in log_content
    
    def test_init_root_ca_ecc(self, tmp_path):
        """Test complete Root CA initialization with ECC."""
        passphrase_file = tmp_path / "passphrase.txt"
        passphrase_file.write_bytes(b"test-password")
        
        config = {
            'subject': 'CN=Test ECC Root CA,O=MicroPKI',
            'key_type': 'ecc',
            'key_size': 384,
            'passphrase': b'test-password',
            'out_dir': str(tmp_path / 'pki'),
            'validity_days': 3650,
            'force': False,
            'logger': setup_logger()  # Log to stderr
        }
        
        init_root_ca(config)
        
        pki_dir = tmp_path / 'pki'
        assert (pki_dir / 'private' / 'ca.key.pem').exists()
        assert (pki_dir / 'certs' / 'ca.cert.pem').exists()
    
    def test_init_root_ca_existing_files_no_force(self, tmp_path):
        """Test that initialization fails if files exist without --force."""
        passphrase_file = tmp_path / "passphrase.txt"
        passphrase_file.write_bytes(b"test-password")
        
        config = {
            'subject': 'CN=Test CA',
            'key_type': 'rsa',
            'key_size': 4096,
            'passphrase': b'test-password',
            'out_dir': str(tmp_path / 'pki'),
            'validity_days': 365,
            'force': False,
            'logger': setup_logger()
        }
        
        # First initialization
        init_root_ca(config)
        
        # Second initialization without force should fail
        with pytest.raises(FileExistsError, match="already exists"):
            init_root_ca(config)
    
    def test_init_root_ca_force_overwrite(self, tmp_path):
        """Test that --force allows overwriting existing files."""
        passphrase_file = tmp_path / "passphrase.txt"
        passphrase_file.write_bytes(b"test-password")
        
        config = {
            'subject': 'CN=Test CA',
            'key_type': 'rsa',
            'key_size': 4096,
            'passphrase': b'test-password',
            'out_dir': str(tmp_path / 'pki'),
            'validity_days': 365,
            'force': False,
            'logger': setup_logger()
        }
        
        # First initialization
        init_root_ca(config)
        
        # Second initialization with force should succeed
        config['force'] = True
        init_root_ca(config)  # Should not raise


# Import required for tests
from cryptography import x509


if __name__ == '__main__':
    pytest.main([__file__, '-v'])

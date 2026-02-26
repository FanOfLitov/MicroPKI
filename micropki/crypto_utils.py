import os
from pathlib import Path
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.backends import default_backend
from cryptography import x509


def read_passphrase_file(filepath):
    """
    Read and sanitize passphrase from file.
    
    Args:
        filepath: Path to passphrase file
    
    Returns:
        bytes: Passphrase bytes
    
    Raises:
        ValueError: If passphrase is empty
        IOError: If file cannot be read
    """
    with open(filepath, 'rb') as f:
        passphrase = f.read()
    
    # Strip trailing newline/whitespace
    passphrase = passphrase.strip()
    
    if not passphrase:
        raise ValueError("Passphrase file is empty")
    
    return passphrase


def generate_rsa_key(key_size=4096):
    """
    Generate RSA private key.
    
    Args:
        key_size: Key size in bits (must be 4096)
    
    Returns:
        RSAPrivateKey instance
    
    Raises:
        ValueError: If key_size is not 4096
    """
    if key_size != 4096:
        raise ValueError("RSA key size must be 4096 bits")
    
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend()
    )
    
    return private_key


def generate_ecc_key(key_size=384):
    """
    Generate ECC private key on P-384 curve.
    
    Args:
        key_size: Key size in bits (must be 384 for P-384)
    
    Returns:
        EllipticCurvePrivateKey instance
    
    Raises:
        ValueError: If key_size is not 384
    """
    if key_size != 384:
        raise ValueError("ECC key size must be 384 bits (P-384)")
    
    private_key = ec.generate_private_key(
        ec.SECP384R1(),  # P-384 curve
        backend=default_backend()
    )
    
    return private_key


def save_encrypted_private_key(private_key, filepath, passphrase):
    """
    Save private key encrypted with passphrase.
    
    Args:
        private_key: Private key object (RSA or ECC)
        filepath: Path where to save the encrypted key
        passphrase: Passphrase for encryption (bytes)
    
    The key is encrypted using PKCS#8 format with AES-256-CBC.
    File permissions are set to 0600 (owner read/write only).
    """
    # Ensure parent directory exists with secure permissions
    parent_dir = Path(filepath).parent
    parent_dir.mkdir(parents=True, exist_ok=True)
    
    # Set directory permissions to 0700 on Unix-like systems
    try:
        os.chmod(parent_dir, 0o700)
    except Exception:
        # Windows doesn't support chmod in the same way
        pass
    
    # Serialize private key with encryption
    encrypted_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(passphrase)
    )
    
    # Write to file with secure permissions
    with open(filepath, 'wb') as f:
        f.write(encrypted_pem)
    
    # Set file permissions to 0600 on Unix-like systems
    try:
        os.chmod(filepath, 0o600)
    except Exception:
        # Windows doesn't support chmod in the same way
        pass


def save_certificate_pem(certificate_der, filepath):
    """
    Save certificate in PEM format.
    
    Args:
        certificate_der: Certificate in DER format (bytes)
        filepath: Path where to save the certificate
    """
    # Parse certificate from DER
    cert = x509.load_der_x509_certificate(certificate_der, default_backend())
    
    # Serialize to PEM
    pem = cert.public_bytes(serialization.Encoding.PEM)
    
    # Ensure parent directory exists
    Path(filepath).parent.mkdir(parents=True, exist_ok=True)
    
    # Write to file
    with open(filepath, 'wb') as f:
        f.write(pem)


def load_certificate_pem(filepath):
    """
    Load certificate from PEM file.
    
    Args:
        filepath: Path to PEM certificate file
    
    Returns:
        x509.Certificate object
    """
    with open(filepath, 'rb') as f:
        pem_data = f.read()
    
    cert = x509.load_pem_x509_certificate(pem_data, default_backend())
    return cert

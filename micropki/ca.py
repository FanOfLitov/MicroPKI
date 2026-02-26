import os
from pathlib import Path
from datetime import datetime

from micropki.crypto_utils import (
    generate_rsa_key,
    generate_ecc_key,
    save_encrypted_private_key,
    save_certificate_pem,
    load_certificate_pem
)
from micropki.certificates import (
    parse_subject_dn,
    create_root_ca_certificate,
    get_certificate_info
)


def init_root_ca(config):
    """
    Initialize Root CA with given configuration.
    
    Args:
        config: Dictionary with keys:
            - subject: DN string
            - key_type: 'rsa' or 'ecc'
            - key_size: Key size in bits
            - passphrase: Passphrase bytes
            - out_dir: Output directory path
            - validity_days: Certificate validity in days
            - force: Overwrite existing files
            - logger: Logger instance
    
    Raises:
        Exception: If CA initialization fails
    """
    logger = config['logger']
    
    logger.info("Starting Root CA initialization")
    logger.info("Subject: %s", config['subject'])
    logger.info("Key type: %s-%d", config['key_type'], config['key_size'])
    
    # Create directory structure
    out_dir = Path(config['out_dir'])
    private_dir = out_dir / 'private'
    certs_dir = out_dir / 'certs'
    
    _create_directory_structure(out_dir, private_dir, certs_dir, config['force'], logger)
    
    # Parse subject DN
    try:
        subject = parse_subject_dn(config['subject'])
        logger.info("Subject DN parsed successfully")
    except Exception as e:
        logger.error("Failed to parse subject DN: %s", str(e))
        raise
    
    # Generate private key
    logger.info("Generating %s private key (%d bits)...", config['key_type'], config['key_size'])
    try:
        if config['key_type'] == 'rsa':
            private_key = generate_rsa_key(config['key_size'])
        elif config['key_type'] == 'ecc':
            private_key = generate_ecc_key(config['key_size'])
        else:
            raise ValueError(f"Unsupported key type: {config['key_type']}")
        
        logger.info("Private key generated successfully")
    except Exception as e:
        logger.error("Failed to generate private key: %s", str(e))
        raise
    
    # Create self-signed certificate
    logger.info("Creating self-signed Root CA certificate...")
    try:
        cert_der = create_root_ca_certificate(
            private_key,
            subject,
            config['validity_days']
        )
        logger.info("Certificate created successfully")
    except Exception as e:
        logger.error("Failed to create certificate: %s", str(e))
        raise
    
    # Save encrypted private key
    key_path = private_dir / 'ca.key.pem'
    logger.info("Saving encrypted private key to %s", key_path)
    try:
        save_encrypted_private_key(
            private_key,
            str(key_path),
            config['passphrase']
        )
        logger.info("Private key saved successfully")
    except Exception as e:
        logger.error("Failed to save private key: %s", str(e))
        raise
    
    # Save certificate
    cert_path = certs_dir / 'ca.cert.pem'
    logger.info("Saving certificate to %s", cert_path)
    try:
        save_certificate_pem(cert_der, str(cert_path))
        logger.info("Certificate saved successfully")
    except Exception as e:
        logger.error("Failed to save certificate: %s", str(e))
        raise
    
    # Generate policy document
    policy_path = out_dir / 'policy.txt'
    logger.info("Generating policy document at %s", policy_path)
    try:
        _generate_policy_document(policy_path, cert_der, config)
        logger.info("Policy document generated successfully")
    except Exception as e:
        logger.error("Failed to generate policy document: %s", str(e))
        raise
    
    logger.info("Root CA initialization completed successfully")


def _create_directory_structure(out_dir, private_dir, certs_dir, force, logger):
    """Create PKI directory structure with appropriate permissions."""
    # Check for existing files
    if not force:
        key_file = private_dir / 'ca.key.pem'
        cert_file = certs_dir / 'ca.cert.pem'
        
        if key_file.exists():
            raise FileExistsError(
                f"CA key already exists at {key_file} (use --force to overwrite)"
            )
        if cert_file.exists():
            raise FileExistsError(
                f"CA certificate already exists at {cert_file} (use --force to overwrite)"
            )
    
    # Create directories
    for directory in [out_dir, private_dir, certs_dir]:
        directory.mkdir(parents=True, exist_ok=True)
    
    # Set permissions on private directory
    try:
        os.chmod(private_dir, 0o700)
        logger.info("Set permissions 0700 on %s", private_dir)
    except Exception as e:
        logger.warning("Could not set directory permissions: %s", str(e))
    
    logger.info("Created directory structure in %s", out_dir)


def _generate_policy_document(policy_path, cert_der, config):
    """Generate certificate policy document."""
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    
    cert = x509.load_der_x509_certificate(cert_der, default_backend())
    cert_info = get_certificate_info(cert)
    
    policy_content = f"""MicroPKI Certificate Policy Document
========================================

Policy Version: 1.0
Creation Date: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}

CA Information
--------------
CA Name: {cert_info['subject']}
Serial Number: {cert_info['serial_number']}
Key Algorithm: {cert_info['key_algorithm']}
Signature Algorithm: {cert_info['signature_algorithm']}

Validity Period
---------------
Not Before: {cert_info['not_before']}
Not After: {cert_info['not_after']}

Purpose
-------
This is a Root Certificate Authority for the MicroPKI demonstration project.
It serves as the trust anchor for all certificates issued within this PKI.

Key Usage
---------
- Certificate Signing (keyCertSign)
- CRL Signing (cRLSign)
- Digital Signature (digitalSignature)

Certificate Policy
------------------
- Minimum key sizes: RSA-4096, ECC-P384
- Maximum certificate validity:
  * Root CA: 10 years (3650 days)
  * Intermediate CA: 5 years (1825 days)
  * End-entity: 1 year (365 days)
- All private keys must be encrypted at rest
- Revocation checking via CRL and OCSP is mandatory

Security Controls
-----------------
- Private keys stored encrypted with AES-256-CBC (PKCS#8)
- File permissions: private keys (0600), private directory (0700)
- Cryptographically secure random number generation (secrets module)
- Comprehensive audit logging of all operations
- Passphrase protection for all private keys

Compliance
----------
- X.509 v3 certificate format (RFC 5280)
- PKCS#8 encrypted private key storage
- SHA-256 signature algorithm for RSA keys
- SHA-384 signature algorithm for ECC keys

Limitations
-----------
This PKI implementation is for EDUCATIONAL PURPOSES ONLY.
It is not intended for production use.

Contact Information
-------------------
Project: MicroPKI
Repository: https://github.com/FanOfLitov/MicroPKI
Author: FanOfLitov
"""
    
    with open(policy_path, 'w', encoding='utf-8') as f:
        f.write(policy_content)


def verify_certificate(cert_path):
    """
    Verify a certificate (self-signed for Root CA).
    
    Args:
        cert_path: Path to certificate file
    
    Raises:
        Exception: If verification fails
    """
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.asymmetric import rsa, ec
    from cryptography.exceptions import InvalidSignature
    
    # Load certificate
    cert = load_certificate_pem(cert_path)
    
    # Check if it's a CA certificate
    try:
        basic_constraints = cert.extensions.get_extension_for_oid(
            x509.oid.ExtensionOID.BASIC_CONSTRAINTS
        )
        if not basic_constraints.value.ca:
            raise ValueError("Certificate is not a CA certificate")
    except x509.ExtensionNotFound:
        raise ValueError("Certificate does not have Basic Constraints extension")
    
    # For self-signed certificate, verify signature using its own public key
    public_key = cert.public_key()
    
    try:
        if isinstance(public_key, rsa.RSAPublicKey):
            from cryptography.hazmat.primitives.asymmetric import padding
            from cryptography.hazmat.primitives import hashes
            
            public_key.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                cert.signature_hash_algorithm
            )
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            from cryptography.hazmat.primitives import hashes
            
            public_key.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                ec.ECDSA(cert.signature_hash_algorithm)
            )
        else:
            raise ValueError("Unsupported key type")
    except InvalidSignature:
        raise ValueError("Certificate signature verification failed")
    
    # Check validity period
    now = datetime.utcnow()
    if now < cert.not_valid_before:
        raise ValueError(f"Certificate not yet valid (valid from {cert.not_valid_before})")
    if now > cert.not_valid_after:
        raise ValueError(f"Certificate expired (valid until {cert.not_valid_after})")
    
    # Additional checks
    cert_info = get_certificate_info(cert)
    print(f"\nCertificate Details:")
    print(f"  Subject: {cert_info['subject']}")
    print(f"  Issuer: {cert_info['issuer']}")
    print(f"  Serial: {cert_info['serial_number']}")
    print(f"  Valid from: {cert_info['not_before']}")
    print(f"  Valid until: {cert_info['not_after']}")
    print(f"  Key algorithm: {cert_info['key_algorithm']}")
    print(f"  Signature algorithm: {cert_info['signature_algorithm']}")
    print(f"  Is CA: Yes")

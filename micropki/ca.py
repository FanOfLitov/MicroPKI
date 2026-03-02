import os
from pathlib import Path
from datetime import datetime, timezone

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
Creation Date: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}

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
    now = datetime.now(timezone.utc)
    if now < cert.not_valid_before_utc:
        raise ValueError(f"Certificate not yet valid (valid from {cert.not_valid_before_utc})")
    if now > cert.not_valid_after_utc:
        raise ValueError(f"Certificate expired (valid until {cert.not_valid_after_utc})")
    
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


def create_intermediate_ca(root_cert_path, root_key_path, root_passphrase,
                           subject, key_type, key_size, passphrase,
                           out_dir, validity_days, path_length, logger):
    """
    Create an Intermediate CA signed by Root CA.

    Args:
        root_cert_path: Path to Root CA certificate
        root_key_path: Path to Root CA private key
        root_passphrase: Root CA key passphrase
        subject: Intermediate CA subject DN
        key_type: Key type (rsa/ecc)
        key_size: Key size
        passphrase: Intermediate CA key passphrase
        out_dir: Output directory
        validity_days: Certificate validity in days
        path_length: Path length constraint
        logger: Logger instance

    Returns:
        dict: Paths to created files
    """
    from pathlib import Path
    from cryptography.hazmat.primitives import serialization

    logger.info("Starting Intermediate CA creation")
    logger.info("Subject: %s", subject)
    logger.info("Key type: %s-%d", key_type, key_size)
    logger.info("Path length constraint: %s", path_length)

    # Load Root CA certificate and key
    logger.info("Loading Root CA certificate from %s", root_cert_path)
    root_cert = load_certificate_pem(root_cert_path)

    logger.info("Loading Root CA private key")
    with open(root_key_path, 'rb') as f:
        root_key_pem = f.read()

    # Decrypt Root CA private key
    root_key = serialization.load_pem_private_key(
        root_key_pem,
        password=root_passphrase,
        backend=default_backend()
    )
    logger.info("Root CA private key loaded successfully")

    # Generate Intermediate CA key pair
    logger.info("Generating Intermediate CA private key...")
    if key_type == 'rsa':
        from micropki.crypto_utils import generate_rsa_key
        intermediate_key = generate_rsa_key(key_size)
    elif key_type == 'ecc':
        from micropki.crypto_utils import generate_ecc_key
        intermediate_key = generate_ecc_key(key_size)
    else:
        raise ValueError(f"Unsupported key type: {key_type}")

    logger.info("Intermediate CA private key generated")

    # Generate CSR
    logger.info("Generating CSR for Intermediate CA...")
    from micropki.csr import generate_csr
    csr_pem = generate_csr(
        intermediate_key,
        subject,
        is_ca=True,
        path_length=path_length
    )

    # Save CSR
    out_path = Path(out_dir)
    csr_dir = out_path / 'csrs'
    csr_dir.mkdir(parents=True, exist_ok=True)
    csr_path = csr_dir / 'intermediate.csr.pem'

    with open(csr_path, 'wb') as f:
        f.write(csr_pem)
    logger.info("CSR saved to %s", csr_path)

    # Sign CSR with Root CA
    logger.info("Signing Intermediate CA certificate with Root CA...")
    from micropki.certificates import (
        parse_subject_dn,
        generate_serial_number,
        compute_ski
    )
    from datetime import timedelta

    # Parse CSR
    csr = x509.load_pem_x509_csr(csr_pem, default_backend())
    intermediate_subject = parse_subject_dn(subject)
    intermediate_public_key = csr.public_key()

    # Generate serial number
    serial_number = generate_serial_number()

    # Compute SKI and AKI
    intermediate_ski = compute_ski(intermediate_public_key)

    # Get Root CA SKI for AKI
    try:
        root_ski_ext = root_cert.extensions.get_extension_for_oid(
            x509.oid.ExtensionOID.SUBJECT_KEY_IDENTIFIER
        )
        root_ski = root_ski_ext.value.digest
    except x509.ExtensionNotFound:
        root_ski = compute_ski(root_cert.public_key())

    # Set validity
    not_valid_before = datetime.now(timezone.utc)
    not_valid_after = not_valid_before + timedelta(days=validity_days)

    # Determine signature algorithm
    from cryptography.hazmat.primitives.asymmetric import rsa, ec
    if isinstance(root_key, rsa.RSAPrivateKey):
        signature_algorithm = hashes.SHA256()
    elif isinstance(root_key, ec.EllipticCurvePrivateKey):
        signature_algorithm = hashes.SHA384()
    else:
        raise ValueError("Unsupported Root CA key type")

    # Build certificate
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(intermediate_subject)
    builder = builder.issuer_name(root_cert.subject)
    builder = builder.public_key(intermediate_public_key)
    builder = builder.serial_number(serial_number)
    builder = builder.not_valid_before(not_valid_before)
    builder = builder.not_valid_after(not_valid_after)

    # Add extensions
    builder = builder.add_extension(
        x509.BasicConstraints(ca=True, path_length=path_length),
        critical=True
    )

    builder = builder.add_extension(
        x509.KeyUsage(
            digital_signature=True,
            key_encipherment=False,
            content_commitment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=True,
            crl_sign=True,
            encipher_only=False,
            decipher_only=False
        ),
        critical=True
    )

    builder = builder.add_extension(
        x509.SubjectKeyIdentifier(intermediate_ski),
        critical=False
    )

    builder = builder.add_extension(
        x509.AuthorityKeyIdentifier(
            key_identifier=root_ski,
            authority_cert_issuer=None,
            authority_cert_serial_number=None
        ),
        critical=False
    )

    # Sign certificate
    intermediate_cert = builder.sign(
        private_key=root_key,
        algorithm=signature_algorithm,
        backend=default_backend()
    )

    logger.info("Intermediate CA certificate signed successfully")

    # Save intermediate certificate
    cert_path = out_path / 'certs' / 'intermediate.cert.pem'
    cert_path.parent.mkdir(parents=True, exist_ok=True)

    cert_pem = intermediate_cert.public_bytes(serialization.Encoding.PEM)
    with open(cert_path, 'wb') as f:
        f.write(cert_pem)
    logger.info("Intermediate CA certificate saved to %s", cert_path)

    # Save intermediate private key (encrypted)
    key_path = out_path / 'private' / 'intermediate.key.pem'
    key_path.parent.mkdir(parents=True, exist_ok=True)

    from micropki.crypto_utils import save_encrypted_private_key
    save_encrypted_private_key(intermediate_key, str(key_path), passphrase)
    logger.info("Intermediate CA private key saved to %s", key_path)

    # Update policy document
    _update_policy_intermediate(out_path / 'policy.txt', intermediate_cert, path_length)
    logger.info("Policy document updated")

    logger.info("Intermediate CA creation completed successfully")

    return {
        'cert': str(cert_path),
        'key': str(key_path),
        'csr': str(csr_path)
    }


def _update_policy_intermediate(policy_path, cert, path_length):
    """Append Intermediate CA information to policy document."""
    from micropki.certificates import get_certificate_info

    cert_info = get_certificate_info(cert)

    update = f"""

Intermediate CA Information
===========================
Added: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}

Subject: {cert_info['subject']}
Issuer: {cert_info['issuer']}
Serial Number: {cert_info['serial_number']}
Key Algorithm: {cert_info['key_algorithm']}
Signature Algorithm: {cert_info['signature_algorithm']}
Path Length Constraint: {path_length}

Validity Period:
  Not Before: {cert_info['not_before']}
  Not After: {cert_info['not_after']}

Purpose:
  This Intermediate CA is authorized to issue end-entity certificates
  (server, client, code signing) on behalf of the Root CA.
"""

    with open(policy_path, 'a', encoding='utf-8') as f:
        f.write(update)


def issue_certificate(ca_cert_path, ca_key_path, ca_passphrase,
                      template_name, subject, san_list,
                      out_dir, validity_days, logger,
                      csr_path=None):
    """
    Issue an end-entity certificate from Intermediate CA.

    Args:
        ca_cert_path: Path to CA certificate
        ca_key_path: Path to CA private key
        ca_passphrase: CA key passphrase
        template_name: Certificate template (server/client/code_signing)
        subject: Certificate subject DN
        san_list: List of SAN strings (type:value)
        out_dir: Output directory
        validity_days: Certificate validity in days
        logger: Logger instance
        csr_path: Optional path to CSR file

    Returns:
        dict: Paths to created files
    """
    from pathlib import Path
    from cryptography.hazmat.primitives import serialization
    from micropki.templates import get_template, parse_san_entry, build_san_extension
    from micropki.certificates import parse_subject_dn, generate_serial_number, compute_ski
    from datetime import timedelta

    logger.info("Starting certificate issuance")
    logger.info("Template: %s", template_name)
    logger.info("Subject: %s", subject)
    logger.info("SAN entries: %s", san_list)

    # Get template
    template = get_template(template_name)
    logger.info("Using template: %s", template.name)

    # Parse SAN entries
    san_entries = []
    if san_list:
        for san_str in san_list:
            san_entry = parse_san_entry(san_str)
            san_entries.append(san_entry)
        logger.info("Parsed %d SAN entries", len(san_entries))

    # Validate SAN for template
    if san_entries:
        template.validate_san(san_entries)
        logger.info("SAN entries validated for template '%s'", template_name)
    elif template_name == 'server':
        raise ValueError("Server certificate requires at least one SAN entry")

    # Load CA certificate and key
    logger.info("Loading CA certificate from %s", ca_cert_path)
    ca_cert = load_certificate_pem(ca_cert_path)

    logger.info("Loading CA private key")
    with open(ca_key_path, 'rb') as f:
        ca_key_pem = f.read()

    ca_key = serialization.load_pem_private_key(
        ca_key_pem,
        password=ca_passphrase,
        backend=default_backend()
    )
    logger.info("CA private key loaded successfully")

    # Determine key type from CA
    from cryptography.hazmat.primitives.asymmetric import rsa, ec
    if isinstance(ca_key, rsa.RSAPrivateKey):
        key_type_str = "rsa"
    elif isinstance(ca_key, ec.EllipticCurvePrivateKey):
        key_type_str = "ecc"
    else:
        key_type_str = "unknown"

    # Generate or load end-entity key pair
    if csr_path:
        logger.info("Loading CSR from %s", csr_path)
        from micropki.csr import load_csr, verify_csr
        csr = load_csr(csr_path)
        verify_csr(csr)
        end_entity_public_key = csr.public_key()
        end_entity_key = None  # No private key when using CSR
        logger.info("CSR loaded and verified")
    else:
        logger.info("Generating new key pair for end-entity")
        # Use RSA-2048 for end-entity by default
        from micropki.crypto_utils import generate_rsa_key
        end_entity_key = generate_rsa_key(2048)
        end_entity_public_key = end_entity_key.public_key()
        logger.info("End-entity key pair generated (RSA-2048)")

    # Parse subject
    cert_subject = parse_subject_dn(subject)

    # Generate serial number
    serial_number = generate_serial_number()

    # Compute SKI
    cert_ski = compute_ski(end_entity_public_key)

    # Get CA SKI for AKI
    try:
        ca_ski_ext = ca_cert.extensions.get_extension_for_oid(
            x509.oid.ExtensionOID.SUBJECT_KEY_IDENTIFIER
        )
        ca_ski = ca_ski_ext.value.digest
    except x509.ExtensionNotFound:
        ca_ski = compute_ski(ca_cert.public_key())

    # Set validity
    not_valid_before = datetime.now(timezone.utc)
    not_valid_after = not_valid_before + timedelta(days=validity_days)

    # Determine signature algorithm
    if isinstance(ca_key, rsa.RSAPrivateKey):
        signature_algorithm = hashes.SHA256()
    elif isinstance(ca_key, ec.EllipticCurvePrivateKey):
        signature_algorithm = hashes.SHA384()
    else:
        raise ValueError("Unsupported CA key type")

    # Build certificate
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(cert_subject)
    builder = builder.issuer_name(ca_cert.subject)
    builder = builder.public_key(end_entity_public_key)
    builder = builder.serial_number(serial_number)
    builder = builder.not_valid_before(not_valid_before)
    builder = builder.not_valid_after(not_valid_after)

    # Add extensions from template
    builder = builder.add_extension(
        template.get_basic_constraints(),
        critical=True
    )

    builder = builder.add_extension(
        template.get_key_usage(key_type_str),
        critical=True
    )

    from cryptography.x509.oid import ExtendedKeyUsageOID
    eku_oids = template.get_extended_key_usage()
    builder = builder.add_extension(
        x509.ExtendedKeyUsage(eku_oids),
        critical=False
    )

    if san_entries:
        san_extension = build_san_extension(san_entries)
        builder = builder.add_extension(san_extension, critical=False)
        logger.info("Added SAN extension with %d entries", len(san_entries))

    builder = builder.add_extension(
        x509.SubjectKeyIdentifier(cert_ski),
        critical=False
    )

    builder = builder.add_extension(
        x509.AuthorityKeyIdentifier(
            key_identifier=ca_ski,
            authority_cert_issuer=None,
            authority_cert_serial_number=None
        ),
        critical=False
    )

    # Sign certificate
    logger.info("Signing certificate...")
    end_entity_cert = builder.sign(
        private_key=ca_key,
        algorithm=signature_algorithm,
        backend=default_backend()
    )
    logger.info("Certificate signed successfully")

    # Determine output filename from CN
    try:
        cn = cert_subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value
        # Sanitize filename
        safe_cn = cn.replace(' ', '_').replace('/', '_').replace('\\', '_')
        cert_filename = f"{safe_cn}.cert.pem"
        key_filename = f"{safe_cn}.key.pem"
    except (IndexError, AttributeError):
        # Fallback to serial number
        cert_filename = f"{serial_number:x}.cert.pem"
        key_filename = f"{serial_number:x}.key.pem"

    # Save certificate
    out_path = Path(out_dir)
    out_path.mkdir(parents=True, exist_ok=True)

    cert_path = out_path / cert_filename
    cert_pem = end_entity_cert.public_bytes(serialization.Encoding.PEM)
    with open(cert_path, 'wb') as f:
        f.write(cert_pem)
    logger.info("Certificate saved to %s", cert_path)

    # Save private key (unencrypted) if we generated it
    key_path = None
    if end_entity_key:
        key_path = out_path / key_filename
        key_pem = end_entity_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
        with open(key_path, 'wb') as f:
            f.write(key_pem)

        # Set permissions
        import os
        try:
            os.chmod(key_path, 0o600)
            logger.warning("Private key saved UNENCRYPTED to %s (permissions: 0600)", key_path)
        except Exception as e:
            logger.warning("Could not set file permissions: %s", e)

    logger.info("Certificate issuance completed successfully")
    logger.info("  Serial: %x", serial_number)
    logger.info("  Subject: %s", cert_subject.rfc4514_string())
    logger.info("  Template: %s", template_name)

    return {
        'cert': str(cert_path),
        'key': str(key_path) if key_path else None,
        'serial': format(serial_number, 'x')
    }
"""Certificate generation and handling for MicroPKI."""

import re
from datetime import datetime, timedelta
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
import secrets


def parse_subject_dn(subject_string):
    """
    Parse subject Distinguished Name from string.
    
    Supports both formats:
    - Slash notation: /CN=Root CA/O=MicroPKI/C=US
    - Comma notation: CN=Root CA,O=MicroPKI,C=US
    
    Args:
        subject_string: DN string
    
    Returns:
        x509.Name object
    
    Raises:
        ValueError: If DN is invalid or CN is missing
    """
    # Remove leading slash if present
    subject_string = subject_string.lstrip('/')
    
    # Determine separator
    if '/' in subject_string:
        components = subject_string.split('/')
    else:
        components = subject_string.split(',')
    
    attributes = []
    
    for component in components:
        component = component.strip()
        if not component:
            continue
        
        if '=' not in component:
            raise ValueError(f"Invalid DN component: {component}")
        
        key, value = component.split('=', 1)
        key = key.strip().upper()
        value = value.strip()
        
        if not value:
            raise ValueError(f"Empty value for {key}")
        
        # Map to OIDs
        oid_map = {
            'CN': NameOID.COMMON_NAME,
            'O': NameOID.ORGANIZATION_NAME,
            'OU': NameOID.ORGANIZATIONAL_UNIT_NAME,
            'C': NameOID.COUNTRY_NAME,
            'ST': NameOID.STATE_OR_PROVINCE_NAME,
            'L': NameOID.LOCALITY_NAME,
        }
        
        if key not in oid_map:
            raise ValueError(f"Unsupported DN attribute: {key}")
        
        attributes.append(x509.NameAttribute(oid_map[key], value))
    
    if not any(attr.oid == NameOID.COMMON_NAME for attr in attributes):
        raise ValueError("CN (Common Name) is required in subject DN")
    
    return x509.Name(attributes)


def generate_serial_number():
    """
    Generate cryptographically secure serial number.
    
    Returns 20 bytes (160 bits) of randomness.
    
    Returns:
        int: Serial number
    """
    # Generate 20 bytes of randomness
    random_bytes = secrets.token_bytes(20)
    # Convert to integer
    serial = int.from_bytes(random_bytes, byteorder='big')
    # Ensure it's positive
    return serial


def compute_ski(public_key):
    """
    Compute Subject Key Identifier from public key.
    
    Uses SHA-1 hash of the public key as per RFC 5280.
    
    Args:
        public_key: Public key object
    
    Returns:
        bytes: SKI value
    """
    # Serialize public key to DER
    public_key_der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    # Compute SHA-1 hash
    digest = hashes.Hash(hashes.SHA1(), backend=default_backend())
    digest.update(public_key_der)
    ski = digest.finalize()
    
    return ski


def create_root_ca_certificate(private_key, subject, validity_days):
    """
    Create self-signed Root CA certificate.
    
    Args:
        private_key: Private key (RSA or ECC)
        subject: x509.Name object
        validity_days: Certificate validity period in days
    
    Returns:
        bytes: Certificate in DER format
    """
    from cryptography.hazmat.primitives.asymmetric import rsa, ec
    
    public_key = private_key.public_key()
    
    # Generate serial number
    serial_number = generate_serial_number()
    
    # Compute SKI
    ski = compute_ski(public_key)
    
    # Set validity period
    not_valid_before = datetime.utcnow()
    not_valid_after = not_valid_before + timedelta(days=validity_days)
    
    # Determine signature algorithm
    if isinstance(private_key, rsa.RSAPrivateKey):
        signature_algorithm = hashes.SHA256()
    elif isinstance(private_key, ec.EllipticCurvePrivateKey):
        signature_algorithm = hashes.SHA384()
    else:
        raise ValueError("Unsupported key type")
    
    # Build certificate
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(subject)
    builder = builder.issuer_name(subject)  # Self-signed
    builder = builder.public_key(public_key)
    builder = builder.serial_number(serial_number)
    builder = builder.not_valid_before(not_valid_before)
    builder = builder.not_valid_after(not_valid_after)
    
    # Add extensions
    # Basic Constraints (critical)
    builder = builder.add_extension(
        x509.BasicConstraints(ca=True, path_length=None),
        critical=True
    )
    
    # Key Usage (critical)
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
    
    # Subject Key Identifier
    builder = builder.add_extension(
        x509.SubjectKeyIdentifier(ski),
        critical=False
    )
    
    # Authority Key Identifier (same as SKI for self-signed)
    builder = builder.add_extension(
        x509.AuthorityKeyIdentifier(
            key_identifier=ski,
            authority_cert_issuer=None,
            authority_cert_serial_number=None
        ),
        critical=False
    )
    
    # Sign certificate
    certificate = builder.sign(
        private_key=private_key,
        algorithm=signature_algorithm,
        backend=default_backend()
    )
    
    # Return DER encoding
    return certificate.public_bytes(serialization.Encoding.DER)


def get_certificate_info(cert):
    """
    Extract key information from certificate.
    
    Args:
        cert: x509.Certificate object
    
    Returns:
        dict: Certificate information
    """
    from cryptography.hazmat.primitives.asymmetric import rsa, ec
    
    info = {
        'subject': cert.subject.rfc4514_string(),
        'issuer': cert.issuer.rfc4514_string(),
        'serial_number': format(cert.serial_number, 'x'),
        'not_before': cert.not_valid_before.isoformat(),
        'not_after': cert.not_valid_after.isoformat(),
        'signature_algorithm': cert.signature_algorithm_oid._name,
    }
    
    # Determine key algorithm
    public_key = cert.public_key()
    if isinstance(public_key, rsa.RSAPublicKey):
        info['key_algorithm'] = f"RSA-{public_key.key_size}"
    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        info['key_algorithm'] = f"ECC-{public_key.curve.name}"
    else:
        info['key_algorithm'] = "Unknown"
    
    return info

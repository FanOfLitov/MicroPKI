from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

from micropki.certificates import parse_subject_dn


def generate_csr(private_key, subject_string, is_ca=False, path_length=None):
    """
    Generate a PKCS#10 Certificate Signing Request.

    Args:
        private_key: Private key (RSA or ECC)
        subject_string: Subject DN string
        is_ca: If True, include BasicConstraints with CA=True
        path_length: Path length constraint (only if is_ca=True)

    Returns:
        bytes: CSR in PEM format
    """
    # Parse subject
    subject = parse_subject_dn(subject_string)

    # Build CSR
    builder = x509.CertificateSigningRequestBuilder()
    builder = builder.subject_name(subject)

    # Add BasicConstraints if CA
    if is_ca:
        builder = builder.add_extension(
            x509.BasicConstraints(ca=True, path_length=path_length),
            critical=True
        )

    # Sign CSR with private key
    from cryptography.hazmat.primitives.asymmetric import rsa, ec

    if isinstance(private_key, rsa.RSAPrivateKey):
        csr = builder.sign(private_key, hashes.SHA256(), default_backend())
    elif isinstance(private_key, ec.EllipticCurvePrivateKey):
        csr = builder.sign(private_key, hashes.SHA384(), default_backend())
    else:
        raise ValueError("Unsupported key type")

    # Return PEM encoding
    from cryptography.hazmat.primitives import serialization
    return csr.public_bytes(serialization.Encoding.PEM)


def load_csr(csr_path):
    """
    Load CSR from PEM file.

    Args:
        csr_path: Path to CSR file

    Returns:
        x509.CertificateSigningRequest object
    """
    with open(csr_path, 'rb') as f:
        csr_pem = f.read()

    csr = x509.load_pem_x509_csr(csr_pem, default_backend())
    return csr


def verify_csr(csr):
    """
    Verify CSR signature.

    Args:
        csr: x509.CertificateSigningRequest object

    Returns:
        bool: True if signature is valid

    Raises:
        ValueError: If signature is invalid
    """
    if not csr.is_signature_valid:
        raise ValueError("CSR signature is invalid")
    return True


def get_csr_info(csr):
    """
    Extract information from CSR.

    Args:
        csr: x509.CertificateSigningRequest object

    Returns:
        dict: CSR information
    """
    from cryptography.hazmat.primitives.asymmetric import rsa, ec

    info = {
        'subject': csr.subject.rfc4514_string(),
        'signature_algorithm': csr.signature_algorithm_oid._name,
    }

    # Determine key algorithm
    public_key = csr.public_key()
    if isinstance(public_key, rsa.RSAPublicKey):
        info['key_algorithm'] = f"RSA-{public_key.key_size}"
    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        info['key_algorithm'] = f"ECC-{public_key.curve.name}"
    else:
        info['key_algorithm'] = "Unknown"

    # Check for extensions
    try:
        extensions = csr.extensions
        info['extensions'] = len(extensions)
    except ValueError:
        info['extensions'] = 0

    return info
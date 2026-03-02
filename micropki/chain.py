from datetime import datetime, timezone
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.exceptions import InvalidSignature

from micropki.crypto_utils import load_certificate_pem


def verify_certificate_signature(cert, issuer_cert):
    """
    Verify that cert was signed by issuer_cert.

    Args:
        cert: Certificate to verify
        issuer_cert: Issuer's certificate

    Returns:
        bool: True if signature is valid

    Raises:
        ValueError: If signature verification fails
    """
    issuer_public_key = issuer_cert.public_key()

    try:
        if isinstance(issuer_public_key, rsa.RSAPublicKey):
            issuer_public_key.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                cert.signature_hash_algorithm
            )
        elif isinstance(issuer_public_key, ec.EllipticCurvePublicKey):
            issuer_public_key.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                ec.ECDSA(cert.signature_hash_algorithm)
            )
        else:
            raise ValueError("Unsupported issuer key type")
    except InvalidSignature:
        raise ValueError(f"Certificate signature verification failed")

    return True


def check_validity_period(cert, check_time=None):
    """
    Check if certificate is within its validity period.

    Args:
        cert: Certificate to check
        check_time: Time to check (default: now)

    Returns:
        bool: True if valid

    Raises:
        ValueError: If certificate is not yet valid or has expired
    """
    if check_time is None:
        check_time = datetime.now(timezone.utc)

    not_before = cert.not_valid_before_utc
    not_after = cert.not_valid_after_utc

    if check_time < not_before:
        raise ValueError(f"Certificate not yet valid. Valid from: {not_before}")

    if check_time > not_after:
        raise ValueError(f"Certificate has expired. Valid until: {not_after}")

    return True


def check_basic_constraints(cert, is_ca_expected, max_path_length=None):
    """
    Check BasicConstraints extension.

    Args:
        cert: Certificate to check
        is_ca_expected: Whether CA=True is expected
        max_path_length: Expected maximum path length (for CA certs)

    Returns:
        bool: True if constraints are satisfied

    Raises:
        ValueError: If constraints are not met
    """
    try:
        bc_ext = cert.extensions.get_extension_for_oid(
            x509.oid.ExtensionOID.BASIC_CONSTRAINTS
        )
        bc = bc_ext.value

        if bc.ca != is_ca_expected:
            raise ValueError(f"BasicConstraints CA mismatch: expected {is_ca_expected}, got {bc.ca}")

        if is_ca_expected and max_path_length is not None:
            if bc.path_length is not None and bc.path_length > max_path_length:
                raise ValueError(f"Path length {bc.path_length} exceeds maximum {max_path_length}")

        return True

    except x509.ExtensionNotFound:
        raise ValueError("BasicConstraints extension not found")


def check_key_usage(cert, required_usages):
    """
    Check KeyUsage extension.

    Args:
        cert: Certificate to check
        required_usages: List of required key usage flags

    Returns:
        bool: True if all required usages are present

    Raises:
        ValueError: If required usages are missing
    """
    try:
        ku_ext = cert.extensions.get_extension_for_oid(
            x509.oid.ExtensionOID.KEY_USAGE
        )
        ku = ku_ext.value

        usage_map = {
            'digital_signature': ku.digital_signature,
            'key_encipherment': ku.key_encipherment,
            'key_cert_sign': ku.key_cert_sign,
            'crl_sign': ku.crl_sign,
        }

        for usage in required_usages:
            if usage not in usage_map:
                continue
            if not usage_map[usage]:
                raise ValueError(f"Required key usage '{usage}' is not set")

        return True

    except x509.ExtensionNotFound:
        raise ValueError("KeyUsage extension not found")


def validate_certificate_chain(leaf_cert_path, intermediate_cert_path, root_cert_path):
    """
    Validate a certificate chain: leaf -> intermediate -> root.

    Args:
        leaf_cert_path: Path to leaf certificate
        intermediate_cert_path: Path to intermediate CA certificate
        root_cert_path: Path to root CA certificate

    Returns:
        dict: Validation results

    Raises:
        ValueError: If chain validation fails
    """
    # Load certificates
    leaf_cert = load_certificate_pem(leaf_cert_path)
    intermediate_cert = load_certificate_pem(intermediate_cert_path)
    root_cert = load_certificate_pem(root_cert_path)

    results = {
        'leaf': {},
        'intermediate': {},
        'root': {},
        'chain_valid': False
    }

    # Validate root (self-signed)
    print("Validating Root CA certificate...")
    try:
        verify_certificate_signature(root_cert, root_cert)
        check_validity_period(root_cert)
        check_basic_constraints(root_cert, is_ca_expected=True)
        check_key_usage(root_cert, ['key_cert_sign', 'crl_sign'])
        results['root']['status'] = 'valid'
        results['root']['subject'] = root_cert.subject.rfc4514_string()
        print("  ✓ Root CA is valid (self-signed)")
    except ValueError as e:
        results['root']['status'] = 'invalid'
        results['root']['error'] = str(e)
        raise ValueError(f"Root CA validation failed: {e}")

    # Validate intermediate (signed by root)
    print("\nValidating Intermediate CA certificate...")
    try:
        verify_certificate_signature(intermediate_cert, root_cert)
        check_validity_period(intermediate_cert)
        check_basic_constraints(intermediate_cert, is_ca_expected=True)
        check_key_usage(intermediate_cert, ['key_cert_sign', 'crl_sign'])

        # Check that issuer matches root subject
        if intermediate_cert.issuer != root_cert.subject:
            raise ValueError("Intermediate issuer does not match Root subject")

        results['intermediate']['status'] = 'valid'
        results['intermediate']['subject'] = intermediate_cert.subject.rfc4514_string()
        results['intermediate']['issuer'] = intermediate_cert.issuer.rfc4514_string()
        print("  ✓ Intermediate CA is valid")
        print(f"  ✓ Signed by: {root_cert.subject.rfc4514_string()}")
    except ValueError as e:
        results['intermediate']['status'] = 'invalid'
        results['intermediate']['error'] = str(e)
        raise ValueError(f"Intermediate CA validation failed: {e}")

    # Validate leaf (signed by intermediate)
    print("\nValidating Leaf certificate...")
    try:
        verify_certificate_signature(leaf_cert, intermediate_cert)
        check_validity_period(leaf_cert)
        check_basic_constraints(leaf_cert, is_ca_expected=False)

        # Check that issuer matches intermediate subject
        if leaf_cert.issuer != intermediate_cert.subject:
            raise ValueError("Leaf issuer does not match Intermediate subject")

        results['leaf']['status'] = 'valid'
        results['leaf']['subject'] = leaf_cert.subject.rfc4514_string()
        results['leaf']['issuer'] = leaf_cert.issuer.rfc4514_string()
        print("  ✓ Leaf certificate is valid")
        print(f"  ✓ Signed by: {intermediate_cert.subject.rfc4514_string()}")

        # Check for SAN
        try:
            san_ext = leaf_cert.extensions.get_extension_for_oid(
                x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME
            )
            san_values = []
            for name in san_ext.value:
                san_values.append(str(name.value))
            results['leaf']['san'] = san_values
            print(f"  ✓ SAN entries: {', '.join(san_values)}")
        except x509.ExtensionNotFound:
            results['leaf']['san'] = []

    except ValueError as e:
        results['leaf']['status'] = 'invalid'
        results['leaf']['error'] = str(e)
        raise ValueError(f"Leaf certificate validation failed: {e}")

    results['chain_valid'] = True
    print("\n✓ Certificate chain is valid: Leaf → Intermediate → Root")

    return results


def build_certificate_bundle(leaf_cert_path, intermediate_cert_path, output_path):
    """
    Build a certificate bundle (chain file) for use with web servers.

    Args:
        leaf_cert_path: Path to leaf certificate
        intermediate_cert_path: Path to intermediate certificate
        output_path: Output path for bundle
    """
    import shutil

    with open(output_path, 'wb') as bundle:
        # Leaf certificate first
        with open(leaf_cert_path, 'rb') as f:
            bundle.write(f.read())

        # Intermediate certificate second
        with open(intermediate_cert_path, 'rb') as f:
            bundle.write(f.read())

    print(f"Certificate bundle created: {output_path}")
    print("  Order: Leaf → Intermediate")
    print("  Use with: nginx, apache, etc.")
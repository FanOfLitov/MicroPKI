
from cryptography import x509
from cryptography.x509.oid import ExtensionOID, ExtendedKeyUsageOID
from ipaddress import IPv4Address, IPv6Address, ip_address


class CertificateTemplate:
    """Base class for certificate templates."""

    def __init__(self, name):
        self.name = name

    def get_key_usage(self, key_type):
        """Get KeyUsage extension based on template and key type."""
        raise NotImplementedError

    def get_extended_key_usage(self):
        """Get ExtendedKeyUsage OIDs."""
        raise NotImplementedError

    def get_basic_constraints(self):
        """Get BasicConstraints extension."""
        return x509.BasicConstraints(ca=False, path_length=None)

    def validate_san(self, san_entries):
        """Validate SAN entries for this template."""
        raise NotImplementedError


class ServerTemplate(CertificateTemplate):
    """Template for TLS server certificates."""

    def __init__(self):
        super().__init__("server")

    def get_key_usage(self, key_type):
        """Server: digitalSignature + keyEncipherment (RSA only)."""
        if key_type == "rsa":
            return x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False
            )
        else:  # ECC
            return x509.KeyUsage(
                digital_signature=True,
                key_encipherment=False,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False
            )

    def get_extended_key_usage(self):
        """Server authentication."""
        return [ExtendedKeyUsageOID.SERVER_AUTH]

    def validate_san(self, san_entries):
        """Server requires at least one DNS or IP."""
        valid_types = {'dns', 'ip'}
        san_types = {entry['type'] for entry in san_entries}

        if not san_types.intersection(valid_types):
            raise ValueError("Server certificate requires at least one DNS name or IP address in SAN")

        # Check for invalid types
        invalid = san_types - valid_types
        if invalid:
            raise ValueError(f"Server certificate does not support SAN types: {invalid}")

        return True


class ClientTemplate(CertificateTemplate):
    """Template for TLS client certificates."""

    def __init__(self):
        super().__init__("client")

    def get_key_usage(self, key_type):
        """Client: digitalSignature (+ optional keyAgreement for ECC)."""
        if key_type == "ecc":
            return x509.KeyUsage(
                digital_signature=True,
                key_encipherment=False,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=True,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False
            )
        else:  # RSA
            return x509.KeyUsage(
                digital_signature=True,
                key_encipherment=False,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False
            )

    def get_extended_key_usage(self):
        """Client authentication."""
        return [ExtendedKeyUsageOID.CLIENT_AUTH]

    def validate_san(self, san_entries):
        """Client should have email or DNS."""
        valid_types = {'email', 'dns', 'uri'}
        san_types = {entry['type'] for entry in san_entries}

        invalid = san_types - valid_types
        if invalid:
            raise ValueError(f"Client certificate does not support SAN types: {invalid}")

        return True


class CodeSigningTemplate(CertificateTemplate):
    """Template for code signing certificates."""

    def __init__(self):
        super().__init__("code_signing")

    def get_key_usage(self, key_type):
        """Code signing: digitalSignature only."""
        return x509.KeyUsage(
            digital_signature=True,
            key_encipherment=False,
            content_commitment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=False,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False
        )

    def get_extended_key_usage(self):
        """Code signing."""
        return [ExtendedKeyUsageOID.CODE_SIGNING]

    def validate_san(self, san_entries):
        """Code signing: DNS and URI allowed, no IP or email."""
        valid_types = {'dns', 'uri'}
        san_types = {entry['type'] for entry in san_entries}

        invalid = san_types - valid_types
        if invalid:
            raise ValueError(f"Code signing certificate does not support SAN types: {invalid}")

        return True


def get_template(template_name):
    """
    Get certificate template by name.

    Args:
        template_name: Template name (server, client, code_signing)

    Returns:
        CertificateTemplate instance

    Raises:
        ValueError: If template name is unknown
    """
    templates = {
        'server': ServerTemplate,
        'client': ClientTemplate,
        'code_signing': CodeSigningTemplate,
    }

    if template_name not in templates:
        raise ValueError(f"Unknown template: {template_name}. Valid templates: {list(templates.keys())}")

    return templates[template_name]()


def parse_san_entry(san_string):
    """
    Parse SAN entry from string format (type:value).

    Args:
        san_string: String in format "type:value" (e.g., "dns:example.com")

    Returns:
        dict: {'type': str, 'value': str/IPAddress}

    Raises:
        ValueError: If format is invalid
    """
    if ':' not in san_string:
        raise ValueError(f"Invalid SAN format: {san_string}. Expected 'type:value'")

    san_type, san_value = san_string.split(':', 1)
    san_type = san_type.lower().strip()
    san_value = san_value.strip()

    valid_types = ['dns', 'ip', 'email', 'uri']
    if san_type not in valid_types:
        raise ValueError(f"Invalid SAN type: {san_type}. Valid types: {valid_types}")

    # Validate and convert IP addresses
    if san_type == 'ip':
        try:
            san_value = ip_address(san_value)
        except ValueError as e:
            raise ValueError(f"Invalid IP address: {san_value}: {e}")

    return {'type': san_type, 'value': san_value}


def build_san_extension(san_entries):
    """
    Build SubjectAlternativeName extension from parsed entries.

    Args:
        san_entries: List of dicts with 'type' and 'value'

    Returns:
        x509.SubjectAlternativeName extension
    """
    general_names = []

    for entry in san_entries:
        san_type = entry['type']
        san_value = entry['value']

        if san_type == 'dns':
            general_names.append(x509.DNSName(san_value))
        elif san_type == 'ip':
            general_names.append(x509.IPAddress(san_value))
        elif san_type == 'email':
            general_names.append(x509.RFC822Name(san_value))
        elif san_type == 'uri':
            general_names.append(x509.UniformResourceIdentifier(san_value))

    if not general_names:
        raise ValueError("At least one SAN entry is required")

    return x509.SubjectAlternativeName(general_names)



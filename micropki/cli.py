import argparse
import sys
import os
from pathlib import Path

from micropki import __version__
from micropki.ca import (
    init_root_ca,
    verify_certificate,
    create_intermediate_ca,
    issue_certificate
)
from micropki.crypto_utils import read_passphrase_file
from micropki.logger import setup_logger
from micropki.chain import validate_certificate_chain


def main():
    """Main entry point for the CLI."""
    parser = argparse.ArgumentParser(
        prog='micropki',
        description='MicroPKI - A minimal PKI implementation',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Sprint 1: Initialize Root CA
  micropki ca init \\
    --subject "/CN=Root CA/O=MicroPKI/C=US" \\
    --key-type rsa --key-size 4096 \\
    --passphrase-file ./secrets/root.pass \\
    --out-dir ./pki

  # Sprint 2: Create Intermediate CA
  micropki ca issue-intermediate \\
    --root-cert ./pki/certs/ca.cert.pem \\
    --root-key ./pki/private/ca.key.pem \\
    --root-pass-file ./secrets/root.pass \\
    --subject "CN=Intermediate CA,O=MicroPKI" \\
    --key-type rsa --key-size 4096 \\
    --passphrase-file ./secrets/intermediate.pass \\
    --out-dir ./pki --validity-days 1825

  # Issue server certificate
  micropki ca issue-cert \\
    --ca-cert ./pki/certs/intermediate.cert.pem \\
    --ca-key ./pki/private/intermediate.key.pem \\
    --ca-pass-file ./secrets/intermediate.pass \\
    --template server \\
    --subject "CN=example.com" \\
    --san dns:example.com --san dns:www.example.com \\
    --out-dir ./pki/certs

  # Validate certificate chain
  micropki chain validate \\
    --leaf ./pki/certs/example.com.cert.pem \\
    --intermediate ./pki/certs/intermediate.cert.pem \\
    --root ./pki/certs/ca.cert.pem
        """
    )

    parser.add_argument('--version', action='version', version=f'%(prog)s {__version__}')

    subparsers = parser.add_subparsers(dest='command', help='Available commands')

    # CA command
    ca_parser = subparsers.add_parser('ca', help='Certificate Authority operations')
    ca_subparsers = ca_parser.add_subparsers(dest='ca_command', help='CA subcommands')

    # CA init (Sprint 1)
    setup_ca_init_parser(ca_subparsers)

    # CA verify (Sprint 1)
    setup_ca_verify_parser(ca_subparsers)

    # CA issue-intermediate (Sprint 2)
    setup_ca_issue_intermediate_parser(ca_subparsers)

    # CA issue-cert (Sprint 2)
    setup_ca_issue_cert_parser(ca_subparsers)

    # Chain command (Sprint 2)
    chain_parser = subparsers.add_parser('chain', help='Certificate chain operations')
    chain_subparsers = chain_parser.add_subparsers(dest='chain_command', help='Chain subcommands')
    setup_chain_validate_parser(chain_subparsers)

    # Parse arguments
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 1

    if args.command == 'ca':
        if not args.ca_command:
            ca_parser.print_help()
            return 1

        if args.ca_command == 'init':
            return handle_ca_init(args)
        elif args.ca_command == 'verify':
            return handle_ca_verify(args)
        elif args.ca_command == 'issue-intermediate':
            return handle_ca_issue_intermediate(args)
        elif args.ca_command == 'issue-cert':
            return handle_ca_issue_cert(args)

    elif args.command == 'chain':
        if not args.chain_command:
            chain_parser.print_help()
            return 1

        if args.chain_command == 'validate':
            return handle_chain_validate(args)

    return 0


def setup_ca_init_parser(subparsers):
    """Setup parser for 'ca init' command."""
    init_parser = subparsers.add_parser('init', help='Initialize Root CA')
    init_parser.add_argument('--subject', required=True,
                             help='Distinguished Name (e.g., "/CN=Root CA/O=Org/C=US")')
    init_parser.add_argument('--key-type', choices=['rsa', 'ecc'], default='rsa',
                             help='Key type: rsa or ecc (default: rsa)')
    init_parser.add_argument('--key-size', type=int, default=4096,
                             help='Key size: 4096 for RSA, 384 for ECC (default: 4096)')
    init_parser.add_argument('--passphrase-file', required=True,
                             help='Path to file containing passphrase for key encryption')
    init_parser.add_argument('--out-dir', default='./pki',
                             help='Output directory (default: ./pki)')
    init_parser.add_argument('--validity-days', type=int, default=3650,
                             help='Certificate validity in days (default: 3650)')
    init_parser.add_argument('--log-file', help='Log file path (default: stderr)')
    init_parser.add_argument('--force', action='store_true',
                             help='Overwrite existing files')


def setup_ca_verify_parser(subparsers):
    """Setup parser for 'ca verify' command."""
    verify_parser = subparsers.add_parser('verify', help='Verify certificate')
    verify_parser.add_argument('--cert', required=True,
                               help='Path to certificate to verify')


def setup_ca_issue_intermediate_parser(subparsers):
    """Setup parser for 'ca issue-intermediate' command."""
    intermediate_parser = subparsers.add_parser('issue-intermediate',
                                                help='Issue Intermediate CA certificate')
    intermediate_parser.add_argument('--root-cert', required=True,
                                     help='Path to Root CA certificate (PEM)')
    intermediate_parser.add_argument('--root-key', required=True,
                                     help='Path to Root CA private key (PEM)')
    intermediate_parser.add_argument('--root-pass-file', required=True,
                                     help='File containing Root CA key passphrase')
    intermediate_parser.add_argument('--subject', required=True,
                                     help='Distinguished Name for Intermediate CA')
    intermediate_parser.add_argument('--key-type', choices=['rsa', 'ecc'], default='rsa',
                                     help='Key type: rsa or ecc (default: rsa)')
    intermediate_parser.add_argument('--key-size', type=int, default=4096,
                                     help='Key size: 4096 for RSA, 384 for ECC')
    intermediate_parser.add_argument('--passphrase-file', required=True,
                                     help='File containing Intermediate CA key passphrase')
    intermediate_parser.add_argument('--out-dir', default='./pki',
                                     help='Output directory (default: ./pki)')
    intermediate_parser.add_argument('--validity-days', type=int, default=1825,
                                     help='Certificate validity in days (default: 1825, ~5 years)')
    intermediate_parser.add_argument('--pathlen', type=int, default=0,
                                     help='Path length constraint (default: 0)')
    intermediate_parser.add_argument('--log-file', help='Log file path')


def setup_ca_issue_cert_parser(subparsers):
    """Setup parser for 'ca issue-cert' command."""
    cert_parser = subparsers.add_parser('issue-cert',
                                        help='Issue end-entity certificate')
    cert_parser.add_argument('--ca-cert', required=True,
                             help='Intermediate CA certificate (PEM)')
    cert_parser.add_argument('--ca-key', required=True,
                             help='Intermediate CA private key (PEM)')
    cert_parser.add_argument('--ca-pass-file', required=True,
                             help='File containing CA key passphrase')
    cert_parser.add_argument('--template', required=True,
                             choices=['server', 'client', 'code_signing'],
                             help='Certificate template')
    cert_parser.add_argument('--subject', required=True,
                             help='Distinguished Name for certificate')
    cert_parser.add_argument('--san', action='append',
                             help='Subject Alternative Name (format: type:value, e.g., dns:example.com)')
    cert_parser.add_argument('--out-dir', default='./pki/certs',
                             help='Output directory (default: ./pki/certs)')
    cert_parser.add_argument('--validity-days', type=int, default=365,
                             help='Certificate validity in days (default: 365)')
    cert_parser.add_argument('--csr', help='Path to CSR file (optional)')
    cert_parser.add_argument('--log-file', help='Log file path')


def setup_chain_validate_parser(subparsers):
    """Setup parser for 'chain validate' command."""
    validate_parser = subparsers.add_parser('validate',
                                            help='Validate certificate chain')
    validate_parser.add_argument('--leaf', required=True,
                                 help='Path to leaf certificate')
    validate_parser.add_argument('--intermediate', required=True,
                                 help='Path to intermediate CA certificate')
    validate_parser.add_argument('--root', required=True,
                                 help='Path to root CA certificate')


def handle_ca_init(args):
    """Handle 'ca init' command."""
    # Validate inputs
    if args.key_type == 'rsa' and args.key_size != 4096:
        print("Error: RSA key size must be 4096 bits", file=sys.stderr)
        return 1

    if args.key_type == 'ecc' and args.key_size != 384:
        print("Error: ECC key size must be 384 bits (P-384)", file=sys.stderr)
        return 1

    if not os.path.isfile(args.passphrase_file):
        print(f"Error: Passphrase file not found: {args.passphrase_file}", file=sys.stderr)
        return 1

    if args.validity_days <= 0:
        print("Error: --validity-days must be positive", file=sys.stderr)
        return 1

    try:
        passphrase = read_passphrase_file(args.passphrase_file)
        logger = setup_logger(args.log_file)

        config = {
            'subject': args.subject,
            'key_type': args.key_type,
            'key_size': args.key_size,
            'passphrase': passphrase,
            'out_dir': args.out_dir,
            'validity_days': args.validity_days,
            'force': args.force,
            'logger': logger
        }

        init_root_ca(config)

        print("✓ Root CA initialized successfully!")
        print(f"  Certificate: {args.out_dir}/certs/ca.cert.pem")
        print(f"  Private key: {args.out_dir}/private/ca.key.pem (encrypted)")
        print(f"  Policy: {args.out_dir}/policy.txt")

        return 0

    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


def handle_ca_verify(args):
    """Handle 'ca verify' command."""
    try:
        verify_certificate(args.cert)
        print("✓ Certificate verified successfully!")
        return 0
    except Exception as e:
        print(f"Verification failed: {e}", file=sys.stderr)
        return 1


def handle_ca_issue_intermediate(args):
    """Handle 'ca issue-intermediate' command."""
    # Validate inputs
    if args.key_type == 'rsa' and args.key_size != 4096:
        print("Error: RSA key size must be 4096 bits", file=sys.stderr)
        return 1

    if args.key_type == 'ecc' and args.key_size != 384:
        print("Error: ECC key size must be 384 bits", file=sys.stderr)
        return 1

    for path, name in [(args.root_cert, 'Root certificate'),
                       (args.root_key, 'Root private key'),
                       (args.root_pass_file, 'Root passphrase file'),
                       (args.passphrase_file, 'Intermediate passphrase file')]:
        if not os.path.isfile(path):
            print(f"Error: {name} not found: {path}", file=sys.stderr)
            return 1

    try:
        root_passphrase = read_passphrase_file(args.root_pass_file)
        intermediate_passphrase = read_passphrase_file(args.passphrase_file)
        logger = setup_logger(args.log_file)

        result = create_intermediate_ca(
            root_cert_path=args.root_cert,
            root_key_path=args.root_key,
            root_passphrase=root_passphrase,
            subject=args.subject,
            key_type=args.key_type,
            key_size=args.key_size,
            passphrase=intermediate_passphrase,
            out_dir=args.out_dir,
            validity_days=args.validity_days,
            path_length=args.pathlen,
            logger=logger
        )

        print("✓ Intermediate CA created successfully!")
        print(f"  Certificate: {result['cert']}")
        print(f"  Private key: {result['key']} (encrypted)")
        print(f"  CSR: {result['csr']}")

        return 0

    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        return 1


def handle_ca_issue_cert(args):
    """Handle 'ca issue-cert' command."""
    for path, name in [(args.ca_cert, 'CA certificate'),
                       (args.ca_key, 'CA private key'),
                       (args.ca_pass_file, 'CA passphrase file')]:
        if not os.path.isfile(path):
            print(f"Error: {name} not found: {path}", file=sys.stderr)
            return 1

    if args.csr and not os.path.isfile(args.csr):
        print(f"Error: CSR file not found: {args.csr}", file=sys.stderr)
        return 1

    try:
        ca_passphrase = read_passphrase_file(args.ca_pass_file)
        logger = setup_logger(args.log_file)

        result = issue_certificate(
            ca_cert_path=args.ca_cert,
            ca_key_path=args.ca_key,
            ca_passphrase=ca_passphrase,
            template_name=args.template,
            subject=args.subject,
            san_list=args.san,
            out_dir=args.out_dir,
            validity_days=args.validity_days,
            logger=logger,
            csr_path=args.csr
        )

        print(f"✓ Certificate issued successfully!")
        print(f"  Template: {args.template}")
        print(f"  Serial: {result['serial']}")
        print(f"  Certificate: {result['cert']}")
        if result['key']:
            print(f"  Private key: {result['key']} (⚠️  UNENCRYPTED)")

        return 0

    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        return 1


def handle_chain_validate(args):
    """Handle 'chain validate' command."""
    for path, name in [(args.leaf, 'Leaf certificate'),
                       (args.intermediate, 'Intermediate certificate'),
                       (args.root, 'Root certificate')]:
        if not os.path.isfile(path):
            print(f"Error: {name} not found: {path}", file=sys.stderr)
            return 1

    try:
        result = validate_certificate_chain(args.leaf, args.intermediate, args.root)
        print("\n✓ Certificate chain validation successful!")
        return 0

    except Exception as e:
        print(f"\n✗ Chain validation failed: {e}", file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
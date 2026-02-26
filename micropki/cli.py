#!/usr/bin/env python3
"""Command-line interface for MicroPKI."""

import argparse
import sys
import os
from pathlib import Path

from micropki import __version__
from micropki.ca import init_root_ca, verify_certificate
from micropki.crypto_utils import read_passphrase_file
from micropki.logger import setup_logger


def main():
    """Main entry point for the CLI."""
    parser = argparse.ArgumentParser(
        prog='micropki',
        description='MicroPKI - A minimal PKI implementation',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Initialize RSA Root CA
  micropki ca init \\
    --subject "/CN=Root CA/O=MicroPKI/C=US" \\
    --key-type rsa \\
    --key-size 4096 \\
    --passphrase-file ./secrets/ca.pass \\
    --out-dir ./pki

  # Initialize ECC Root CA
  micropki ca init \\
    --subject "CN=Root CA,O=MicroPKI" \\
    --key-type ecc \\
    --key-size 384 \\
    --passphrase-file ./secrets/ca.pass

  # Verify certificate
  micropki ca verify --cert ./pki/certs/ca.cert.pem
        """
    )
    
    parser.add_argument('--version', action='version', version=f'%(prog)s {__version__}')
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # CA command
    ca_parser = subparsers.add_parser('ca', help='Certificate Authority operations')
    ca_subparsers = ca_parser.add_subparsers(dest='ca_command', help='CA subcommands')
    
    # CA init subcommand
    init_parser = ca_subparsers.add_parser('init', help='Initialize Root CA')
    init_parser.add_argument(
        '--subject',
        required=True,
        help='Distinguished Name (e.g., "/CN=Root CA/O=Org/C=US" or "CN=Root CA,O=Org")'
    )
    init_parser.add_argument(
        '--key-type',
        choices=['rsa', 'ecc'],
        default='rsa',
        help='Key type: rsa or ecc (default: rsa)'
    )
    init_parser.add_argument(
        '--key-size',
        type=int,
        default=4096,
        help='Key size: 4096 for RSA, 384 for ECC (default: 4096)'
    )
    init_parser.add_argument(
        '--passphrase-file',
        required=True,
        help='Path to file containing passphrase for key encryption'
    )
    init_parser.add_argument(
        '--out-dir',
        default='./pki',
        help='Output directory (default: ./pki)'
    )
    init_parser.add_argument(
        '--validity-days',
        type=int,
        default=3650,
        help='Certificate validity in days (default: 3650, ~10 years)'
    )
    init_parser.add_argument(
        '--log-file',
        help='Log file path (default: stderr)'
    )
    init_parser.add_argument(
        '--force',
        action='store_true',
        help='Overwrite existing files'
    )
    
    # CA verify subcommand
    verify_parser = ca_subparsers.add_parser('verify', help='Verify certificate')
    verify_parser.add_argument(
        '--cert',
        required=True,
        help='Path to certificate to verify'
    )
    
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
    
    return 0


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
        # Read passphrase
        passphrase = read_passphrase_file(args.passphrase_file)
        
        # Setup logger
        logger = setup_logger(args.log_file)
        
        # Initialize CA
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
        
        print("Root CA initialized successfully!")
        print(f"Certificate: {args.out_dir}/certs/ca.cert.pem")
        print(f"Private key: {args.out_dir}/private/ca.key.pem (encrypted)")
        print(f"Policy: {args.out_dir}/policy.txt")
        
        return 0
        
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


def handle_ca_verify(args):
    """Handle 'ca verify' command."""
    try:
        verify_certificate(args.cert)
        print("Certificate verified successfully!")
        return 0
    except Exception as e:
        print(f"Verification failed: {e}", file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())

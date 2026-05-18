from __future__ import annotations

from importlib import import_module
from typing import Any

__version__ = "0.7.0"


_LAZY_EXPORTS: dict[str, tuple[str, str]] = {
    # CA / core operations
    "init_root_ca": ("micropki.ca", "init_root_ca"),
    "issue_intermediate_ca": ("micropki.ca", "issue_intermediate_ca"),
    "issue_certificate": ("micropki.ca", "issue_certificate"),
    "issue_ocsp_certificate": ("micropki.ca", "issue_ocsp_certificate"),

    # Optional compatibility names
    "RootCA": ("micropki.ca", "RootCA"),
    "IntermediateCA": ("micropki.intermediate", "IntermediateCA"),
    "IssueCertificate": ("micropki.intermediate", "IssueCertificate"),

    # Database
    "CertificateDatabase": ("micropki.database", "CertificateDatabase"),
    "Database": ("micropki.database", "CertificateDatabase"),

    # Serial
    "SerialNumberGenerator": ("micropki.serial", "SerialNumberGenerator"),
    "SerialGenerator": ("micropki.serial", "SerialNumberGenerator"),

    # Certificates
    "load_certificate": ("micropki.certificates", "load_certificate"),
    "save_certificate": ("micropki.certificates", "save_certificate"),
    "serialize_certificate": ("micropki.certificates", "serialize_certificate"),
    "compute_certificate_fingerprint": (
        "micropki.certificates",
        "compute_certificate_fingerprint",
    ),

    # Crypto utils
    "generate_key": ("micropki.crypto_utils", "generate_key"),
    "generate_rsa_key": ("micropki.crypto_utils", "generate_rsa_key"),
    "generate_ecc_key": ("micropki.crypto_utils", "generate_ecc_key"),
    "load_private_key": ("micropki.crypto_utils", "load_private_key"),
    "parse_subject_dn": ("micropki.crypto_utils", "parse_subject_dn"),
    "serialize_private_key": ("micropki.crypto_utils", "serialize_private_key"),
    "serialize_private_key_unencrypted": (
        "micropki.crypto_utils",
        "serialize_private_key_unencrypted",
    ),

    # Revocation
    "get_reason_flag": ("micropki.revocation", "get_reason_flag"),
    "revoke_certificate": ("micropki.revocation", "revoke_certificate"),

    # OCSP real API
    "process_ocsp_request": ("micropki.ocsp", "process_ocsp_request"),
    "build_ocsp_response": ("micropki.ocsp", "build_ocsp_response"),
    "parse_ocsp_request": ("micropki.ocsp", "parse_ocsp_request"),
    "OCSPServer": ("micropki.ocsp_responder", "OCSPServer"),
    "OCSPHandler": ("micropki.ocsp_responder", "OCSPHandler"),

    # Repository
    "RepositoryServer": ("micropki.repository", "RepositoryServer"),
    "RepositoryHandler": ("micropki.repository", "RepositoryHandler"),

    # Audit: только то, что реально используется в проекте
    "AuditLogger": ("micropki.audit", "AuditLogger"),
}


def __getattr__(name: str) -> Any:
    """
    Lazy public API loader.

    Это позволяет писать `from micropki import CertificateDatabase`,
    но не ломает импорт всего пакета, если какой-то опциональный модуль
    отсутствует или ещё не реализован.
    """
    if name not in _LAZY_EXPORTS:
        raise AttributeError(f"module 'micropki' has no attribute '{name}'")

    module_name, attr_name = _LAZY_EXPORTS[name]
    module = import_module(module_name)
    value = getattr(module, attr_name)

    globals()[name] = value
    return value


def get_validation_module():
    from .validation import (
        PathValidator,
        ChainBuilder,
        ChainValidationResult,
        CertificateValidationResult,
        ValidationStatus,
    )

    return (
        PathValidator,
        ChainBuilder,
        ChainValidationResult,
        CertificateValidationResult,
        ValidationStatus,
    )


def get_revocation_check_module():
    from .revocation_check import check_status, extract_crl_urls, extract_ocsp_url

    return check_status, extract_crl_urls, extract_ocsp_url


def get_client_module():
    from .client import (
        handle_client_gen_csr,
        handle_client_request_cert,
        handle_client_validate,
        handle_client_check_status,
    )

    return (
        handle_client_gen_csr,
        handle_client_request_cert,
        handle_client_validate,
        handle_client_check_status,
    )


__all__ = [
    "__version__",
    *_LAZY_EXPORTS.keys(),
    "get_validation_module",
    "get_revocation_check_module",
    "get_client_module",
]
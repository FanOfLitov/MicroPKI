# micropki/intermediate.py

from .ca import issue_intermediate_ca, issue_certificate

class IntermediateCA:
    """
    Обёртка для совместимости с тестами.
    """
    def __init__(self, root_cert_path, root_key_path, root_passphrase,
                 subject_str, key_type, key_size, passphrase,
                 out_dir, validity_days, path_length=0, logger=None):
        import logging
        self.logger = logger or logging.getLogger("IntermediateCA")
        self.root_cert_path = root_cert_path
        self.root_key_path = root_key_path
        self.root_passphrase = root_passphrase
        self.subject_str = subject_str
        self.key_type = key_type
        self.key_size = key_size
        self.passphrase = passphrase
        self.out_dir = out_dir
        self.validity_days = validity_days
        self.path_length = path_length

        # Вызов функции из ca.py
        issue_intermediate_ca(
            root_cert_path=root_cert_path,
            root_key_path=root_key_path,
            root_passphrase=root_passphrase,
            subject_str=subject_str,
            key_type=key_type,
            key_size=key_size,
            passphrase=passphrase,
            out_dir=out_dir,
            validity_days=validity_days,
            path_length=path_length,
            logger=self.logger,
        )


class IssueCertificate:
    """
    Обёртка для вызова issue_certificate через объект IntermediateCA
    """
    @staticmethod
    def issue(ca_cert_path, ca_key_path, ca_passphrase,
              template_name, subject_str, san_strings,
              out_dir, validity_days, logger=None):
        issue_certificate(
            ca_cert_path, ca_key_path, ca_passphrase,
            template_name, subject_str, san_strings,
            out_dir, validity_days,
            logger or logging.getLogger("IssueCertificate"),
        )
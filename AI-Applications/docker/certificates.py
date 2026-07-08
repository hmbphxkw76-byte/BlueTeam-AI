"""Generate a local self-signed TLS certificate for the lab."""

from __future__ import annotations

import ipaddress
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CERT_DIR = PROJECT_ROOT / ".tmp-certs"
DEFAULT_CERT_FILE = DEFAULT_CERT_DIR / "lab.crt"
DEFAULT_KEY_FILE = DEFAULT_CERT_DIR / "lab.key"
DEFAULT_HOSTS = ["localhost", "127.0.0.1", "0.0.0.0"]
TEN_YEARS_DAYS = 3650


def certificate_paths() -> tuple[Path, Path]:
    cert_file = Path(os.getenv("LAB_TLS_CERT_FILE", str(DEFAULT_CERT_FILE)))
    key_file = Path(os.getenv("LAB_TLS_KEY_FILE", str(DEFAULT_KEY_FILE)))
    return cert_file, key_file


def certificate_hosts() -> list[str]:
    configured = [
        item.strip()
        for item in os.getenv("LAB_TLS_HOSTS", "").split(",")
        if item.strip()
    ]
    hosts = configured or DEFAULT_HOSTS
    return sorted(set(hosts))


def subject_alt_names(hosts: list[str]) -> list[x509.GeneralName]:
    names: list[x509.GeneralName] = []
    for host in hosts:
        try:
            names.append(x509.IPAddress(ipaddress.ip_address(host)))
        except ValueError:
            names.append(x509.DNSName(host))
    return names


def ensure_self_signed_certificate() -> tuple[Path, Path]:
    cert_file, key_file = certificate_paths()
    if cert_file.exists() and key_file.exists():
        return cert_file, key_file

    cert_file.parent.mkdir(parents=True, exist_ok=True)
    key_file.parent.mkdir(parents=True, exist_ok=True)

    hosts = certificate_hosts()
    primary_host = hosts[0] if hosts else "localhost"
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "CN"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "LlamaFW AI-300 Local Lab"),
            x509.NameAttribute(NameOID.COMMON_NAME, primary_host),
        ]
    )
    now = datetime.now(timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=TEN_YEARS_DAYS))
        .add_extension(x509.SubjectAlternativeName(subject_alt_names(hosts)), critical=False)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(private_key, hashes.SHA256())
    )

    key_file.write_bytes(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    cert_file.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    key_file.chmod(0o600)
    cert_file.chmod(0o644)
    return cert_file, key_file

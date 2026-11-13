"""Local sanity checks of certificate files before they are uploaded.

Uses the ``openssl`` binary if available. Without openssl only the existence
and the PEM format of the files are checked.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional, Tuple

from .config import CertificateConfig

EXPIRY_WARNING_DAYS = 30


@dataclass
class CheckResult:
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    subject: Optional[str] = None
    issuer: Optional[str] = None
    not_after: Optional[datetime] = None
    has_ca_chain: bool = True
    # number of CA certificates appended to the certificate file itself (e.g. fullchain.pem)
    bundled_chain: int = 0
    self_signed: bool = False

    @property
    def ok(self) -> bool:
        return not self.errors


def _openssl(args: List[str]) -> Optional[str]:
    try:
        proc = subprocess.run(["openssl"] + args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              text=True, stdin=subprocess.DEVNULL)
    except OSError:
        return None
    return proc.stdout if proc.returncode == 0 else None


_PEM_CERT = re.compile(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", re.S)


def certificate_blocks(text: str) -> List[str]:
    """All PEM certificate blocks of a file, in file order."""
    return [m.group(0) + "\n" for m in _PEM_CERT.finditer(text)]


def upload_parts(cert: CertificateConfig) -> Tuple[Optional[str], str]:
    """Contents to upload: (leaf if it has to be split off the certificate file, CA chain).

    A certificate file containing the full chain (leaf first) is split: the leaf is uploaded as
    certificate, the remaining certificates (plus ``ca-chain.pem`` if present) as CA chain.
    """
    blocks = certificate_blocks(cert.certificate.read_text(encoding="utf-8", errors="replace"))
    chain = "".join(blocks[1:])
    if cert.ca_chain.is_file():
        chain += cert.ca_chain.read_text(encoding="utf-8", errors="replace")
    return (blocks[0] if len(blocks) > 1 else None), chain


def certificate_domains(path: Path) -> List[str]:
    """DNS names a certificate is valid for (subjectAltName, CN as fallback). Empty if unknown."""
    if not path.is_file() or shutil.which("openssl") is None:
        return []
    text = _openssl(["x509", "-in", str(path), "-noout", "-text"]) or ""
    names = re.findall(r"DNS:([^\s,]+)", text)
    if not names:
        match = re.search(r"Subject:.*?CN\s*=\s*([^,/\n]+)", text)
        names = [match.group(1).strip()] if match else []
    return list(dict.fromkeys(n.lower() for n in names))


def domain_covered(domain: str, names: List[str]) -> bool:
    """True if ``domain`` matches one of the certificate names (``*`` covers exactly one label)."""
    domain = domain.lower().rstrip(".")
    for name in names:
        if name == domain:
            return True
        if name.startswith("*.") and "." in domain and domain.split(".", 1)[1] == name[2:]:
            return True
    return False


def _non_ascii(value: str) -> str:
    """Characters outside printable ASCII (the Cloud Portal rejects e.g. umlauts)."""
    return "".join(dict.fromkeys(ch for ch in value if not (32 <= ord(ch) < 127)))


def check_certificate(cert: CertificateConfig) -> CheckResult:
    result = CheckResult()
    invalid = _non_ascii(cert.name)
    if invalid:
        result.errors.append(
            f"Name contains characters the Cloud Portal rejects: {' '.join(repr(c) for c in invalid)} "
            "- use printable ASCII only (e.g. 'ue' instead of 'ü')")
    files = {
        "Certificate": cert.certificate,
        "Private Key": cert.private_key,
    }
    # ca-chain.pem is optional: the chain may also be appended to the certificate file (fullchain).
    if cert.ca_chain.is_file():
        files["CA chain"] = cert.ca_chain
    for label, path in files.items():
        if not path.is_file():
            result.errors.append(f"{label} missing: {path}")
        elif "-----BEGIN" not in path.read_text(encoding="utf-8", errors="replace"):
            result.errors.append(f"{label} is not a PEM file: {path}")
    if result.errors:
        return result

    result.bundled_chain = max(0, len(certificate_blocks(cert.certificate.read_text(
        encoding="utf-8", errors="replace"))) - 1)
    result.has_ca_chain = cert.ca_chain.is_file() or result.bundled_chain > 0

    if "ENCRYPTED" in cert.private_key.read_text(encoding="utf-8", errors="replace"):
        result.errors.append(f"Private key is password protected, sapccm requires an unencrypted key: {cert.private_key}")
        return result

    if shutil.which("openssl") is None:
        result.warnings.append("openssl not found - file contents were not checked.")
        return result

    cert_path = str(cert.certificate)
    info = _openssl(["x509", "-in", cert_path, "-noout", "-subject", "-issuer", "-enddate"])
    if info is None:
        result.errors.append(f"Certificate cannot be read: {cert.certificate}")
        return result
    for line in info.splitlines():
        if line.startswith("subject="):
            result.subject = line[len("subject="):].strip()
        elif line.startswith("issuer="):
            result.issuer = line[len("issuer="):].strip()
        elif line.startswith("notAfter="):
            raw = line[len("notAfter="):].strip()
            try:
                result.not_after = datetime.strptime(raw.replace("  ", " "), "%b %d %H:%M:%S %Y %Z") \
                    .replace(tzinfo=timezone.utc)
            except ValueError:
                result.warnings.append(f"Cannot evaluate expiry date: {raw}")

    if result.not_after:
        days = (result.not_after - datetime.now(timezone.utc)).days
        if days < 0:
            result.errors.append(f"Certificate has expired ({result.not_after:%Y-%m-%d}).")
        elif days < EXPIRY_WARNING_DAYS:
            result.warnings.append(f"Certificate expires in {days} days ({result.not_after:%Y-%m-%d}).")

    cert_pub = _openssl(["x509", "-in", cert_path, "-noout", "-pubkey"])
    key_pub = _openssl(["pkey", "-in", str(cert.private_key), "-pubout"])
    if key_pub is None:
        result.errors.append(f"Private key cannot be read: {cert.private_key}")
    elif cert_pub is not None and cert_pub.strip() != key_pub.strip():
        result.errors.append("Private key does not match the certificate.")

    if cert.ca_chain.is_file() and _openssl(["x509", "-in", str(cert.ca_chain), "-noout"]) is None:
        result.errors.append(f"CA chain cannot be read: {cert.ca_chain}")

    result.self_signed = bool(result.subject) and result.subject == result.issuer
    if not result.has_ca_chain and result.issuer and not result.self_signed:
        # The Cloud Portal verifies the certification path and rejects a leaf without its
        # intermediates ("Certification path could not be verified").
        result.errors.append(
            f"CA chain missing: the Cloud Portal has to verify the certification path up to "
            f"'{result.issuer}'. Put the intermediate certificate(s) into {cert.ca_chain} "
            f"or append them to {cert.certificate} (full chain, leaf first).")
    return result

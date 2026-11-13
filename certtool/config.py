"""Loading and validation of the certtool configuration (JSON)."""

from __future__ import annotations

import fnmatch
import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

# Installation directory of certtool (bin/, tools/ with the SAP CLI, the example configuration).
PROJECT_ROOT = Path(__file__).resolve().parent.parent
# The configuration is project specific: certtool.json in the current directory by default.
CONFIG_FILE_NAME = "certtool.json"
EXAMPLE_CONFIG = PROJECT_ROOT / "certtool.example.json"
DEFAULT_CERTIFICATES_PATH = "./certificates"

DEFAULT_CERT_FILE = "certificate.pem"
DEFAULT_KEY_FILE = "private-key.pem"
DEFAULT_CA_FILE = "ca-chain.pem"

# Certificates managed by SAP are named "<environment>-public - <YYYY-MM-DD> (Let's Encrypt)",
# e.g. "d1-public - 2026-11-19 (Let's Encrypt)". They are always excluded from cleanup,
# independent of the configuration.
SAP_MANAGED_MARKER = "let's encrypt"

# Endpoint target in "environments.<env>.endpoints" that selects the SAP-managed certificate of the
# environment (its name and code change with every renewal).
SAP_MANAGED_TARGET = "sap-managed"
# Endpoint target for endpoints whose certificate is not managed by certtool (ignored by rollout).
UNMANAGED_TARGET = "unmanaged"
RESERVED_TARGETS = (SAP_MANAGED_TARGET, UNMANAGED_TARGET)

# Fields of a "credentials" block, named like the Cloud Portal "Client Credentials" dialog.
CREDENTIAL_FIELDS = ("tokenEndpoint", "clientId", "clientSecret", "clientResource", "clientExpires")


def is_sap_managed(name: str) -> bool:
    """True for SAP managed (Let's Encrypt) certificates; tolerant of case and typographic apostrophes."""
    normalized = name.replace("\u2019", "'").replace("\u00b4", "'").replace("`", "'").lower()
    return SAP_MANAGED_MARKER in normalized


class ConfigError(Exception):
    """Raised for invalid or incomplete configuration."""


@dataclass
class CertificateConfig:
    name: str
    certificate: Path
    private_key: Path
    ca_chain: Path


@dataclass
class EnvironmentConfig:
    key: str
    code: str
    description: str
    endpoints: Dict[str, str]  # endpoint code -> certificate name, "sap-managed" or "unmanaged"
    domains: Dict[str, str] = field(default_factory=dict)  # endpoint code -> expected domain (optional)
    credentials: Dict[str, str] = field(default_factory=dict)  # environment specific technical user


@dataclass
class Config:
    path: Path
    subscription_code: str
    sapccm_home: Path
    sapccm_zip_dir: Path
    certificates: Dict[str, CertificateConfig]
    environments: Dict[str, EnvironmentConfig]
    protected_certificates: List[str] = field(default_factory=list)
    credentials_expires_format: Optional[str] = None
    credentials: Dict[str, str] = field(default_factory=dict)  # subscription wide technical user

    def environment(self, name: str) -> EnvironmentConfig:
        if name in self.environments:
            return self.environments[name]
        for env in self.environments.values():
            if env.code == name:
                return env
        known = ", ".join(sorted(self.environments)) or "-"
        raise ConfigError(
            f"Environment '{name}' is not configured. Known environments: {known}"
        )

    def is_protected(self, code: str, name: str) -> bool:
        """True if a certificate (by code or name, glob patterns allowed) is protected."""
        for pattern in self.protected_certificates:
            if fnmatch.fnmatchcase(code, pattern) or fnmatch.fnmatchcase(name, pattern):
                return True
        return False


def _credentials(raw, where: str, errors: List[str]) -> Dict[str, str]:
    """Validate a "credentials" block (missing block = empty dict)."""
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        errors.append(f"{where}: expected an object with {', '.join(CREDENTIAL_FIELDS)}.")
        return {}
    unknown = sorted(set(raw) - set(CREDENTIAL_FIELDS))
    if unknown:
        errors.append(f"{where}: unknown field(s) {', '.join(unknown)} (allowed: {', '.join(CREDENTIAL_FIELDS)}).")
    return {k: str(v).strip() for k, v in raw.items() if k in CREDENTIAL_FIELDS and v is not None and str(v).strip()}


def display_path(text: str) -> str:
    """Shorten absolute paths below the current directory in messages."""
    return str(text).replace(str(Path.cwd()) + os.sep, "")


def _resolve(base: Path, value: str) -> Path:
    path = Path(os.path.expanduser(value))
    return path if path.is_absolute() else (base / path)


def load_config(path: Optional[str] = None) -> Config:
    config_path = Path(path).expanduser().resolve() if path else Path.cwd() / CONFIG_FILE_NAME
    if not config_path.is_file():
        raise ConfigError(
            f"Configuration file not found: {config_path}\n"
            f"Run certtool in the project directory that contains {CONFIG_FILE_NAME}, or pass --config <file>.\n"
            f"A template is available at {EXAMPLE_CONFIG}."
        )
    try:
        raw = json.loads(config_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ConfigError(f"Invalid JSON in {config_path}: {exc}") from exc

    # Project data (certificates) is resolved relative to the configuration file, the SAP CLI
    # relative to the certtool installation.
    base = config_path.parent

    subscription = str(raw.get("subscriptionCode") or "").strip()
    if not subscription or subscription.startswith("<"):
        raise ConfigError(
            "'subscriptionCode' is missing in the configuration."
        )

    if "certificatesDir" in raw:
        raise ConfigError("'certificatesDir' was renamed to 'certificatesPath' (relative to the configuration file).")
    certs_dir = _resolve(base, raw.get("certificatesPath", DEFAULT_CERTIFICATES_PATH))
    certificates: Dict[str, CertificateConfig] = {}
    for name, spec in (raw.get("certificates") or {}).items():
        spec = spec or {}
        cert_dir = _resolve(certs_dir, spec.get("directory", name))
        certificates[name] = CertificateConfig(
            name=name,
            certificate=_resolve(cert_dir, spec.get("certificate", DEFAULT_CERT_FILE)),
            private_key=_resolve(cert_dir, spec.get("privateKey", DEFAULT_KEY_FILE)),
            ca_chain=_resolve(cert_dir, spec.get("caChain", DEFAULT_CA_FILE)),
        )

    environments: Dict[str, EnvironmentConfig] = {}
    errors: List[str] = []
    credentials = _credentials(raw.get("credentials"), "credentials", errors)
    for reserved in RESERVED_TARGETS:
        if reserved in certificates:
            errors.append(f"'{reserved}' is a reserved endpoint target and cannot be used as certificate name.")
    for key, spec in (raw.get("environments") or {}).items():
        spec = spec or {}
        endpoints: Dict[str, str] = {}
        domains: Dict[str, str] = {}
        for endpoint, value in (spec.get("endpoints") or {}).items():
            where = f"Environment '{key}', endpoint '{endpoint}'"
            # short form: "endpoint": "<certificate>"; long form: {"domain": ..., "certificate": ...}
            if isinstance(value, dict):
                unknown = sorted(set(value) - {"domain", "certificate"})
                if unknown:
                    errors.append(f"{where}: unknown field(s) {', '.join(unknown)} (allowed: domain, certificate).")
                cert_name = value.get("certificate") or UNMANAGED_TARGET
                if value.get("domain"):
                    domains[endpoint] = str(value["domain"]).strip().lower().rstrip(".")
            elif isinstance(value, str):
                cert_name = value
            else:
                errors.append(f"{where}: expected a certificate name or an object with 'domain' and 'certificate'.")
                continue
            endpoints[endpoint] = cert_name
            if cert_name not in RESERVED_TARGETS and cert_name not in certificates:
                errors.append(f"{where}: certificate '{cert_name}' is not defined under 'certificates' "
                              f"(or use '{SAP_MANAGED_TARGET}' / '{UNMANAGED_TARGET}').")
        environments[key] = EnvironmentConfig(
            key=key,
            code=spec.get("code", key),
            description=spec.get("description", ""),
            endpoints=endpoints,
            domains=domains,
            credentials=_credentials(spec.get("credentials"), f"environments.{key}.credentials", errors),
        )
    if errors:
        raise ConfigError("Invalid configuration:\n  - " + "\n  - ".join(errors))

    cleanup = raw.get("cleanup") or {}
    return Config(
        path=config_path,
        subscription_code=subscription,
        sapccm_home=_resolve(PROJECT_ROOT, raw.get("sapccmHome", "tools/sapccm")),
        sapccm_zip_dir=_resolve(PROJECT_ROOT, raw.get("sapccmZipDir", "tools")),
        certificates=certificates,
        environments=environments,
        protected_certificates=list(cleanup.get("protectedCertificates") or []),
        credentials_expires_format=raw.get("credentialsExpiresFormat"),
        credentials=credentials,
    )

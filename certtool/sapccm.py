"""Thin wrapper around the sapccm CLI.

Credentials are never written to the user's global sapccm configuration
(~/.config/sapccm/config.properties). Instead every certtool run creates a
private temporary directory, points the CLI at it (Java system property
``user.home`` on Linux/macOS, ``LOCALAPPDATA`` on Windows), writes the
credentials taken from the certtool configuration into it and deletes it
again when the run ends.
"""

from __future__ import annotations

import os
import re
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
import zipfile
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from .config import PROJECT_ROOT, Config, ConfigError, EnvironmentConfig

EXPIRY_WARNING_DAYS = 14

# Format of the "Expiration Date" in the Cloud Portal dialog: DD/MM/YYYY hh:mm:ss AM/PM,
# e.g. "11/05/2027 10:51:04 AM" = 11 May 2027 (secrets are valid for 6 months).
# Variants without seconds/time and ISO 8601 are accepted as well.
_EXPIRY_FORMATS = ("%d/%m/%Y %I:%M:%S %p", "%d/%m/%Y %I:%M %p", "%d/%m/%Y %H:%M:%S", "%d/%m/%Y")

# Environment variable that overrides the sapccm executable (used by the tests).
SAPCCM_OVERRIDE_VAR = "CERTTOOL_SAPCCM"


class SapCcmError(Exception):
    """Raised when a sapccm command fails.

    ``str(exc)`` contains the command; ``summary`` only exit code and CLI output (for tables).
    """

    def __init__(self, message: str, output: str = "", exit_code: Optional[int] = None):
        super().__init__(message)
        self.output = output
        self.exit_code = exit_code

    @property
    def summary(self) -> str:
        if self.exit_code is None:
            return str(self)
        return f"sapccm exit code {self.exit_code}" + (f"\n{self.output}" if self.output else "")


def parse_expiry(value: str, fmt: Optional[str] = None) -> Tuple[datetime, Optional[str]]:
    """Parse the secret expiration date as copied from the Cloud Portal. Returns (date, note).

    With an explicit ``fmt`` (config ``credentialsExpiresFormat``) only that format is used,
    otherwise ISO 8601 and the portal format DD/MM/YYYY hh:mm:ss AM/PM.
    """
    value = " ".join(value.split())
    formats = (fmt,) if fmt else _EXPIRY_FORMATS
    if not fmt:
        try:
            return datetime.fromisoformat(value), None
        except ValueError:
            pass
    for candidate in formats:
        try:
            return datetime.strptime(value, candidate), None
        except ValueError:
            continue
    expected = f"Format '{fmt}'" if fmt else "e.g. '11/05/2027 10:51:04 AM' (DD/MM/YYYY) or '2027-05-11'"
    raise ConfigError(f"Cannot interpret expiration date '{value}' (expected {expected}).")


@dataclass
class Credentials:
    client_id: str
    client_secret: str
    token_url: str
    expires: Optional[datetime] = None
    source: str = ""  # configuration block the client id/secret were taken from

    @classmethod
    def from_config(cls, cfg: Config, env: Optional[EnvironmentConfig] = None,
                    now: Optional[datetime] = None) -> "Credentials":
        """Resolve the technical user from the configuration.

        Lookup order: ``environments.<key>.credentials`` (only if ``env`` is given), then the
        subscription wide ``credentials``. The block is selected by the first one that defines
        ``clientId``; ``clientSecret`` and ``clientExpires`` are only read from that same block, so
        an id and a secret of different technical users can never be mixed. ``tokenEndpoint`` is not
        user specific and falls back to the subscription block.
        """
        scopes = []
        if env is not None:
            scopes.append((f"environments.{env.key}.credentials", env.credentials))
        scopes.append(("credentials", cfg.credentials))

        if env is not None and not env.credentials.get("clientId"):
            stray = [f for f in ("clientSecret", "clientExpires") if env.credentials.get(f)]
            if stray:
                raise ConfigError(
                    f"environments.{env.key}.credentials defines {', '.join(stray)} but no clientId. Add the "
                    "environment specific clientId or remove the field(s), so that credentials of different "
                    "technical users are never mixed."
                )

        source, block = next(((name, b) for name, b in scopes if b.get("clientId")), (None, None))
        if block is None:
            raise ConfigError(_missing_message(cfg, ["clientId", "clientSecret", "tokenEndpoint"]))
        token_url = next((b["tokenEndpoint"] for _, b in scopes if b.get("tokenEndpoint")), "")
        missing = [name for name, value in (("clientSecret", block.get("clientSecret")),
                                            ("tokenEndpoint", token_url)) if not value]
        if missing:
            raise ConfigError(_missing_message(cfg, missing, source))

        expires = None
        raw_expiry = block.get("clientExpires", "")
        if raw_expiry:
            expires, note = parse_expiry(raw_expiry, cfg.credentials_expires_format)
            if note:
                print(f"Note {source}.clientExpires: {note}", file=sys.stderr)
            now = now or datetime.now()
            if expires <= now:
                raise ConfigError(
                    f"The client secret has expired ({source}.clientExpires = '{raw_expiry}', "
                    f"interpreted as {expires:%Y-%m-%d %H:%M}). Please create a new secret for the "
                    "technical user in the Cloud Portal and update the configuration."
                )
            days = (expires - now).days
            if days < EXPIRY_WARNING_DAYS:
                print(f"WARNING: The client secret expires in {days} day(s) ({expires:%Y-%m-%d}).",
                      file=sys.stderr)
        return cls(block["clientId"], block["clientSecret"], token_url, expires, source)


def _missing_message(cfg: Config, names: List[str], source: str = "credentials") -> str:
    return (
        f"Technical user credentials are missing in {cfg.path.name}: {source}.{', '.join(names)}\n"
        "Add them as copied from the Cloud Portal (\"Client Credentials\"), e.g.:\n"
        '  "credentials": {\n'
        '    "tokenEndpoint": "https://...",\n'
        '    "clientId": "...",\n'
        '    "clientSecret": "...",\n'
        '    "clientExpires": "11/05/2027 10:51:04 AM"\n'
        "  }\n"
        "(see README, section 'Providing the credentials')"
    )


def _escape_property(value: str) -> str:
    """Escape a value for java.util.Properties#load."""
    out = []
    for i, ch in enumerate(value):
        if ch == "\\":
            out.append("\\\\")
        elif ch in "=:#!":
            out.append("\\" + ch)
        elif ch == " " and i == 0:
            out.append("\\ ")
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\r":
            out.append("\\r")
        elif ch == "\t":
            out.append("\\t")
        elif ord(ch) > 0x7E or ord(ch) < 0x20:
            out.append("\\u%04x" % ord(ch))
        else:
            out.append(ch)
    return "".join(out)


def locate_sapccm(home: Path, zip_dir: Path) -> List[str]:
    """Return the command used to start sapccm, extracting the ZIP if needed."""
    override = os.environ.get(SAPCCM_OVERRIDE_VAR)
    if override:
        return shlex.split(override)

    script = home / "bin" / ("sapccm.bat" if os.name == "nt" else "sapccm")
    if not script.is_file():
        archives = sorted(
            p for p in zip_dir.glob("*") if p.is_file() and p.suffix.lower() == ".zip"
            and p.name.upper().startswith("CXCOMMCLI")
        )
        if not archives:
            raise ConfigError(
                f"sapccm not found ({script}) and no CLI archive (CXCOMMCLI*.ZIP) in {zip_dir}. "
                "Download it from SAP Software Downloads, see README section 'Installing the SAP CLI'."
            )
        archive = archives[-1]
        print(f"Extracting {archive.name} to {home} ...", file=sys.stderr)
        with zipfile.ZipFile(archive) as zf:
            zf.extractall(home)
        if not script.is_file():
            raise ConfigError(f"{script} not found after extracting the archive.")
    if os.name != "nt":
        mode = script.stat().st_mode
        script.chmod(mode | stat.S_IXUSR | stat.S_IXGRP)
    return [str(script)]


MIN_JAVA = 21


@dataclass
class JavaInfo:
    """The Java runtime the sapccm launcher will use."""
    command: Optional[str]
    version: Optional[str]
    major: Optional[int]

    def describe(self) -> str:
        if not self.command:
            return "not found"
        return f"{self.version or 'unknown version'} ({self.command})"

    def quiet_options(self) -> List[str]:
        """JVM options that silence harmless warnings of the bundled netty (see README).

        Only options supported by the detected Java version are returned, unknown launcher
        options would abort the JVM (e.g. --sun-misc-unsafe-memory-access on Java 21).
        """
        options = ["-Dlogging.level.io.netty=OFF"]  # netty DNS message on macOS
        if self.major and self.major >= 21:
            options.append("--enable-native-access=ALL-UNNAMED")  # System::loadLibrary warnings
        if self.major and self.major >= 23:
            options.append("--sun-misc-unsafe-memory-access=allow")  # sun.misc.Unsafe warnings
        return options


def detect_java() -> JavaInfo:
    """Resolve java like bin/sapccm(.bat): JAVACMD, JAVA_HOME (not on Windows), macOS java_home, PATH."""
    command = os.environ.get("JAVACMD") or None
    if not command and os.name != "nt":
        java_home = os.environ.get("JAVA_HOME")
        if not java_home and sys.platform == "darwin" and Path("/usr/libexec/java_home").exists():
            try:
                java_home = subprocess.run(["/usr/libexec/java_home"], stdout=subprocess.PIPE,
                                           stderr=subprocess.DEVNULL, text=True).stdout.strip() or None
            except OSError:
                java_home = None
        if java_home:
            command = str(Path(java_home, "bin", "java"))
    command = command or shutil.which("java")
    if not command:
        return JavaInfo(None, None, None)
    try:
        out = subprocess.run([command, "-version"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                             text=True, errors="replace").stdout
    except OSError:
        return JavaInfo(command, None, None)
    match = re.search(r'version "([^"]+)"', out)
    version = match.group(1) if match else None
    major = None
    if version:
        parts = version.split(".")
        major = int(parts[1]) if parts[0] == "1" and len(parts) > 1 else int(re.match(r"\d+", parts[0]).group(0))
    return JavaInfo(command, version, major)


def check_java(java: JavaInfo) -> None:
    if not java.command:
        raise ConfigError(f"No Java runtime found. sapccm requires Java {MIN_JAVA} (SapMachine {MIN_JAVA} "
                          "recommended); set JAVA_HOME or add java to the PATH.")
    if java.major is not None and java.major < MIN_JAVA:
        raise ConfigError(f"sapccm requires Java {MIN_JAVA} or newer, found {java.describe()}. "
                          "Set JAVA_HOME to a newer JDK (e.g. SapMachine 21).")


def sapccm_description(home: Path) -> str:
    """Location and version of the sapccm CLI for the context header."""
    override = os.environ.get(SAPCCM_OVERRIDE_VAR)
    if override:
        return f"{override} (via {SAPCCM_OVERRIDE_VAR})"
    jars = sorted((home / "lib").glob("cli-*.jar"))
    version = jars[-1].stem[len("cli-"):] if jars else "unknown version"
    return f"{home} (version {version})"


class SapCcm:
    """Runs sapccm commands with an isolated, temporary CLI configuration."""

    def __init__(self, command: List[str], credentials: Credentials, subscription_code: str,
                 verbose: bool = False, jvm_options: Optional[List[str]] = None):
        self.command = command
        self.jvm_options = list(jvm_options or [])
        self.credentials = credentials
        self.subscription_code = subscription_code
        self.verbose = verbose
        self._tmp: Optional[str] = None
        self._env: Dict[str, str] = {}

    # -- lifecycle ---------------------------------------------------------
    def __enter__(self) -> "SapCcm":
        self._tmp = tempfile.mkdtemp(prefix="certtool-")
        os.chmod(self._tmp, 0o700)
        props = {
            "client-id": self.credentials.client_id,
            "client-secret": self.credentials.client_secret,
            "token-url": self.credentials.token_url,
            "subscription-code": self.subscription_code,
        }
        content = "".join(f"{k}={_escape_property(v)}\n" for k, v in props.items())
        # Linux/macOS: ${user.home}/.config/sapccm/config.properties
        # Windows:     %LOCALAPPDATA%\sapccm\config.properties
        for cfg_dir in (Path(self._tmp, ".config", "sapccm"), Path(self._tmp, "sapccm")):
            cfg_dir.mkdir(parents=True, exist_ok=True)
            cfg_file = cfg_dir / "config.properties"
            fd = os.open(str(cfg_file), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w", encoding="latin-1") as fh:
                fh.write(content)

        env = dict(os.environ)
        options = [env.get("JAVA_OPTS", "")] + self.jvm_options
        if os.name == "nt":
            env["LOCALAPPDATA"] = self._tmp
        else:
            # mkdtemp paths contain no spaces, so the unquoted $JAVA_OPTS in bin/sapccm is safe
            options.append(f"-Duser.home={self._tmp}")
        env["JAVA_OPTS"] = " ".join(o for o in options if o).strip()
        env["CERTTOOL_SAPCCM_HOME"] = self._tmp  # informational, used by the test mock
        self._env = env
        return self

    def __exit__(self, *exc) -> None:
        if self._tmp:
            shutil.rmtree(self._tmp, ignore_errors=True)
            self._tmp = None

    def temp_file(self, name: str, content: str) -> Path:
        """Write a helper file into the private temporary directory of this run."""
        if self._tmp is None:
            raise RuntimeError("SapCcm must be used as context manager")
        path = Path(self._tmp, name)
        fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(content)
        return path

    # -- execution ---------------------------------------------------------
    def run(self, args: List[str], mutating: bool = False) -> str:
        """Run ``sapccm <args>`` and return stdout. Raises SapCcmError on failure."""
        if self._tmp is None:
            raise RuntimeError("SapCcm must be used as context manager")
        printable = "sapccm " + " ".join(shlex.quote(a) for a in args)
        shown = printable.replace(str(PROJECT_ROOT) + os.sep, "")
        if self.verbose or mutating:  # changing calls are always shown
            print(f"  $ {shown}")
        proc = subprocess.run(
            self.command + args, env=self._env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, encoding="utf-8", errors="replace",
        )
        stderr = _filter_jvm_warnings(proc.stderr)
        stdout = _filter_jvm_warnings(proc.stdout)
        if self.verbose:
            if stdout.strip():
                print(_indent(stdout))
            if stderr.strip():
                print(_indent(stderr), file=sys.stderr)
        if proc.returncode != 0:
            # sapccm echoes the files it reads - drop those lines, they are not part of the error
            paths = {a.split("=", 1)[1] for a in args if a.startswith("--") and a.endswith(".pem") and "=" in a}
            lines = [line for part in (stderr, stdout) for line in part.splitlines()
                     if line.strip() and line.strip() not in paths]
            details = "\n".join(lines) or "(no output)"
            if re.search(r"\b(401|403)\b|Authorization Failed", details):
                details += "\n" + _AUTH_HINT
            raise SapCcmError(f"{shown} failed (exit code {proc.returncode}):\n{_indent(details)}",
                              output=details, exit_code=proc.returncode)
        return stdout


_NOISE_PREFIXES = (
    "WARNING:",  # JDK 24+ sun.misc.Unsafe deprecation warnings caused by netty
)
_NOISE_FRAGMENTS = (
    "io.netty.resolver.dns.macos",  # "Unable to load ... MacOSDnsServerAddressStreamProvider" on Apple Silicon
)
_ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")

_AUTH_HINT = (
    "Hint: the portal denied access. Check that the environment code in the configuration matches "
    "the code in the Cloud Portal (e.g. 'd1', not a display name) and that the technical user has "
    "access to this environment and a sufficient role."
)


def _is_noise(line: str) -> bool:
    plain = _ANSI.sub("", line).strip()
    return plain.startswith(_NOISE_PREFIXES) or any(f in plain for f in _NOISE_FRAGMENTS)


def _filter_jvm_warnings(text: str) -> str:
    """Remove harmless JVM/netty noise; sapccm writes it to stdout as well as stderr."""
    return "\n".join(line for line in text.splitlines() if not _is_noise(line))


def _indent(text: str) -> str:
    return "\n".join("    " + line for line in text.strip().splitlines())

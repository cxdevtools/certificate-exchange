"""Implementation of the certtool sub commands."""

from __future__ import annotations

import json
import os
from urllib.parse import urlsplit
from dataclasses import dataclass
from typing import Callable, ContextManager, Dict, List, Optional

from .config import (PROJECT_ROOT, SAP_MANAGED_TARGET, UNMANAGED_TARGET, Config, ConfigError, EnvironmentConfig,
                     is_sap_managed)
from .output import Cell, heading, problems, style, summary, table
from .pem import certificate_domains, check_certificate, domain_covered, upload_parts
from .sapccm import SapCcm, SapCcmError
from .tables import parse_details, parse_table


@dataclass
class RemoteCertificate:
    code: str
    name: str
    issuer: str
    expiration: str
    endpoints_count: int


# -- remote queries ----------------------------------------------------------

def list_remote_certificates(ccm: SapCcm) -> List[RemoteCertificate]:
    out = ccm.run(["certificate", "list", f"--subscription-code={ccm.subscription_code}"])
    rows = parse_table(out, "CERTIFICATE CODE")
    if rows is None:
        if "No certificates found" in out or not out.strip():
            return []
        raise SapCcmError("Could not interpret the output of 'certificate list':\n" + out)
    result = []
    for row in rows:
        try:
            count = int(row.get("ENDPOINTS COUNT") or 0)
        except ValueError:
            count = -1  # unknown -> treated as "in use" by cleanup
        result.append(RemoteCertificate(
            code=row.get("CERTIFICATE CODE", ""),
            name=row.get("NAME", ""),
            issuer=row.get("ISSUER", ""),
            expiration=row.get("EXPIRATION DATE", ""),
            endpoints_count=count,
        ))
    return result


def _by_name(remote: List[RemoteCertificate]) -> Dict[str, List[RemoteCertificate]]:
    index: Dict[str, List[RemoteCertificate]] = {}
    for cert in remote:
        index.setdefault(cert.name, []).append(cert)
    return index


def _host(url: str) -> str:
    """Domain of an endpoint URL as shown by sapccm (with or without protocol/path)."""
    url = url.strip()
    if not url:
        return ""
    return (urlsplit(url if "//" in url else "//" + url).hostname or "").lower()


def list_endpoints(ccm: SapCcm, environment_code: str) -> Dict[str, str]:
    """Endpoint code -> domain (empty if sapccm does not show it)."""
    out = ccm.run(["endpoint", "list", f"--subscription-code={ccm.subscription_code}",
                   f"--environment-code={environment_code}"])
    rows = parse_table(out, "ENDPOINT CODE") or []
    return {row["ENDPOINT CODE"]: _host(row.get("URL") or row.get("DOMAIN NAME") or "")
            for row in rows if row.get("ENDPOINT CODE")}


@dataclass
class Target:
    """Resolved target certificate of an endpoint."""
    candidates: List[RemoteCertificate]  # uploaded certificates matching the target (normally one)
    accepted: set                        # codes/names that count as "already in place"
    text: str                            # table text
    missing: str                         # state if no certificate was found


def sap_managed_certificates(env: EnvironmentConfig, remote: List[RemoteCertificate]) -> List[RemoteCertificate]:
    """SAP-managed certificates of an environment ("<env>-public - <date> (Let's Encrypt)"), newest first."""
    prefix = f"{env.code.lower()}-public"
    certs = [c for c in remote if is_sap_managed(c.name) and c.name.lower().startswith(prefix)]
    return sorted(certs, key=lambda c: (c.expiration, c.name), reverse=True)


def resolve_target(target: str, env: EnvironmentConfig, remote: List[RemoteCertificate]) -> Target:
    if target == SAP_MANAGED_TARGET:
        # SAP renews these certificates itself: any SAP-managed certificate of the environment counts
        # as in place, a switch uses the newest one.
        certs = sap_managed_certificates(env, remote)
        text = SAP_MANAGED_TARGET + (f"\n{certs[0].name} [{certs[0].code}]" if certs else "")
        return Target(certs[:1], {v for c in certs for v in (c.code, c.name)}, text,
                      f"no SAP-managed certificate for '{env.code}' found")
    candidates = _by_name(remote).get(target, [])
    accepted = {candidates[0].code, candidates[0].name} if len(candidates) == 1 else set()
    text = f"{target} [{candidates[0].code}]" if len(candidates) == 1 else target
    return Target(candidates, accepted, text, "target not uploaded")


def domain_drift(env: EnvironmentConfig, endpoint: str, actual: str) -> Optional[str]:
    """Message if the domain in the portal differs from the domain in the configuration, else None."""
    expected = env.domains.get(endpoint)
    if not expected or not actual or expected == actual:
        return None
    return (f"the endpoint domain in the portal is '{actual}', the configuration expects '{expected}'. "
            "Check the endpoint in the Cloud Portal or update the domain in the configuration.")


def effective_domain(env: EnvironmentConfig, endpoint: str, actual: str) -> str:
    """Domain used for the certificate check: from the portal, else from the configuration."""
    return actual or env.domains.get(endpoint, "")


def domain_mismatch(cfg: Config, cert_name: str, domain: str) -> Optional[str]:
    """Message if the local certificate does not cover the endpoint domain, else None.

    The Cloud Portal rejects such an assignment ("does not match the domain name"). The check is
    skipped if the domain or the local certificate file is unknown.
    """
    cert = cfg.certificates.get(cert_name)
    if not domain or cert is None:
        return None
    names = certificate_domains(cert.certificate)
    if not names or domain_covered(domain, names):
        return None
    return (f"certificate '{cert_name}' ({', '.join(names)}) does not cover the endpoint domain '{domain}'. "
            "The endpoint domain is not changed by certtool - use an endpoint with a matching domain.")


def show_endpoint(ccm: SapCcm, environment_code: str, endpoint_code: str) -> Dict[str, str]:
    out = ccm.run(["endpoint", "show", f"--subscription-code={ccm.subscription_code}",
                   f"--environment-code={environment_code}", f"--code={endpoint_code}"])
    return parse_details(out)


# -- helpers -----------------------------------------------------------------

EnvSession = Callable[[EnvironmentConfig], ContextManager[SapCcm]]


def _relative(text: str) -> str:
    """Shorten absolute project paths in messages."""
    return text.replace(str(PROJECT_ROOT) + os.sep, "")


def _describe(value: str, remote: List[RemoteCertificate]) -> str:
    """Render a certificate reference (code or name) as 'name [code]'."""
    if not value:
        return "(no certificate)"
    for cert in remote:
        if value in (cert.code, cert.name):
            return f"{cert.name} [{cert.code}]"
    return value


def _date(value: str) -> str:
    """'2027-02-05T05:33:21Z' -> '2027-02-05 05:33' (other formats unchanged)."""
    if len(value) >= 16 and value[4] == "-" and value[10] == "T":
        return f"{value[:10]} {value[11:16]}"
    return value or "-"


def _endpoints(cert: RemoteCertificate) -> str:
    return "?" if cert.endpoints_count < 0 else str(cert.endpoints_count)


def _execute_heading(ccm: SapCcm) -> None:
    heading("Executing")


def classify(cfg: Config, cert: RemoteCertificate, include_unused: bool = False) -> str:
    """Cleanup class of a certificate. With ``include_unused`` configured certificates that are not
    assigned to any endpoint become deletable as well (SAP-managed and protected ones never)."""
    if is_sap_managed(cert.name):
        return "SAP-managed"
    if cert.name in cfg.certificates:
        if include_unused and cert.endpoints_count == 0 and not cfg.is_protected(cert.code, cert.name):
            return "configured, unused"
        return "configured"
    if cfg.is_protected(cert.code, cert.name):
        return "protected"
    if cert.endpoints_count != 0:
        return "in use"
    return "deletable"


_CLASS_COLORS = {"SAP-managed": "cyan", "configured": "green", "protected": "cyan",
                 "in use": "yellow", "deletable": "red", "configured, unused": "red"}
_DELETABLE = ("deletable", "configured, unused")


def _subscription_table(cfg: Config, remote: List[RemoteCertificate]) -> None:
    table(["Certificate", "Code", "Status", "Endpoints", "Expires"],
          [[c.name or "(no name)", c.code, (classify(cfg, c), _CLASS_COLORS[classify(cfg, c)]),
            _endpoints(c), _date(c.expiration)] for c in remote])


# -- upload ------------------------------------------------------------------

def cmd_upload(cfg: Config, ccm: SapCcm, only: Optional[List[str]] = None, apply: bool = False) -> int:
    names = only or list(cfg.certificates)
    unknown = [n for n in names if n not in cfg.certificates]
    if unknown:
        print(f"ERROR: Certificates not configured: {', '.join(unknown)}")
        return 2
    if not names:
        print("No certificates configured - nothing to do.")
        return 0

    remote = _by_name(list_remote_certificates(ccm))
    rows: List[List[Cell]] = []
    details = []
    todo = []
    for name in names:
        cert = cfg.certificates[name]
        check = check_certificate(cert)
        valid = f"{check.not_after:%Y-%m-%d}" if check.not_after else "-"
        existing = remote.get(name, [])
        notes = [f"warning: {_relative(w)}" for w in check.warnings]
        if check.ok and check.bundled_chain:
            notes.append(f"note: CA chain taken from certificate file ({check.bundled_chain} certificate(s))")
        if check.ok and not check.has_ca_chain:
            notes.append("note: self-signed, no CA chain")
        if existing:
            text = "skip - already uploaded [" + ", ".join(c.code for c in existing) + "]"
            if len(existing) > 1:
                notes.append("warning: name exists more than once")
            rows.append([name, valid, ("\n".join([text] + notes), "yellow" if notes else "green")])
        elif not check.ok:
            rows.append([name, valid, ("blocked - local check failed", "red")])
            details += [(name, _relative(e)) for e in check.errors]
        else:
            action = "upload" if apply else "would upload"
            rows.append([name, valid, ("\n".join([action] + notes), "yellow")])
            todo.append(cert)

    heading("Upload plan" + ("" if apply else " (preview)"))
    table(["Certificate", "Valid until", "Action"], rows)

    failures = len({n for n, _ in details})
    if not apply:
        problems(details)
        summary(f"{len(todo)} certificate(s) would be uploaded"
                + (f", {failures} blocked" if failures else "")
                + (". Use 'upload --apply' to upload them." if todo else "."), ok=not failures)
        return 1 if failures else 0

    uploaded = 0
    if todo:
        _execute_heading(ccm)
        for cert in todo:
            leaf, chain = upload_parts(cert)
            certificate = ccm.temp_file(f"{cert.name}-certificate.pem", leaf) if leaf else cert.certificate
            # sapccm requires --ca-certificate-path. A file that equals ca-chain.pem is passed as is;
            # otherwise (full chain split off, or self-signed without chain: a single line break,
            # accepted by the CLI validation) a temporary file is used.
            if cert.ca_chain.is_file() and not leaf:
                ca_chain = cert.ca_chain
            else:
                ca_chain = ccm.temp_file(f"{cert.name}-ca-chain.pem", chain or "\n")
            args = ["certificate", "create", f"--subscription-code={ccm.subscription_code}",
                    f"--name={cert.name}",
                    f"--certificate-path={certificate}",
                    f"--certificate-key-path={cert.private_key}",
                    f"--ca-certificate-path={ca_chain}"]
            try:
                ccm.run(args, mutating=True)
                uploaded += 1
            except SapCcmError as exc:
                failures += 1
                message = f"upload failed\n{_relative(exc.summary)}"
                if "Certification path could not be verified" in exc.summary:
                    message += ("\nThe CA chain is incomplete: provide all intermediate certificates "
                                "(ca-chain.pem or a full-chain certificate file).")
                details.append((cert.name, message))

    problems(details)
    summary(f"Upload finished: {uploaded} certificate(s) uploaded"
            + (f", {failures} error(s)." if failures else "."), ok=not failures)
    return 1 if failures else 0


# -- rollout -----------------------------------------------------------------

def cmd_rollout(cfg: Config, ccm: SapCcm, env: EnvironmentConfig,
                only_endpoints: Optional[List[str]] = None, apply: bool = False) -> int:
    mapping = env.endpoints
    if only_endpoints:
        missing = [e for e in only_endpoints if e not in mapping]
        if missing:
            print(f"ERROR: Endpoints not configured for environment '{env.key}': {', '.join(missing)}")
            return 2
        mapping = {e: mapping[e] for e in only_endpoints}
    if not mapping:
        print(f"No endpoints configured for environment '{env.key}' - nothing to do.")
        return 0

    all_remote = list_remote_certificates(ccm)
    existing_endpoints = list_endpoints(ccm, env.code)

    rows: List[List[Cell]] = []
    details = []
    todo = []
    failures = 0
    for endpoint, cert_name in mapping.items():
        if cert_name == UNMANAGED_TARGET:
            rows.append([endpoint, "-", UNMANAGED_TARGET, ("skip - unmanaged", "dim")])
            continue
        resolved = resolve_target(cert_name, env, all_remote)
        candidates, target_text = resolved.candidates, resolved.text
        current = "-"
        if not candidates:
            result: Cell = (resolved.missing + ("" if cert_name == SAP_MANAGED_TARGET else " - run 'upload' first"),
                            "red")
        elif len(candidates) > 1:
            result = ("target name exists more than once", "red")
            details.append((endpoint, f"certificate name '{cert_name}' exists more than once ("
                            + ", ".join(c.code for c in candidates) + ") - please clean up in the Cloud Portal"))
        elif endpoint not in existing_endpoints:
            result = (f"endpoint does not exist in '{env.code}'", "red")
        elif (drift := domain_drift(env, endpoint, existing_endpoints[endpoint])):
            result = ("blocked - domain differs from configuration", "red")
            details.append((endpoint, drift))
        elif (mismatch := domain_mismatch(cfg, cert_name,
                                          effective_domain(env, endpoint, existing_endpoints[endpoint]))):
            result = ("blocked - domain not covered", "red")
            details.append((endpoint, mismatch))
        else:
            try:
                value = show_endpoint(ccm, env.code, endpoint).get("SSL CERTIFICATE", "")
            except SapCcmError as exc:
                rows.append([endpoint, "?", target_text, ("could not read endpoint", "red")])
                details.append((endpoint, _relative(exc.summary)))
                failures += 1
                continue
            current = _describe(value, all_remote)
            if value in resolved.accepted:
                result = ("unchanged - already in place", "green")
            else:
                result = ("switch" if apply else "would switch", "yellow")
                todo.append((endpoint, candidates[0]))
        if result[1] == "red":
            failures += 1
        rows.append([endpoint, current, target_text, result])

    heading(f"Rollout plan - environment {env.code}" + (f" ({env.description})" if env.description else "")
            + ("" if apply else " (preview)"))
    table(["Endpoint", "Current certificate", "Target certificate", "Action"], rows)

    if not apply:
        problems(details)
        summary(f"{len(todo)} endpoint(s) would be switched"
                + (f", {failures} problem(s)" if failures else "")
                + (f". Use 'rollout {env.key} --apply' to switch them." if todo else "."), ok=not failures)
        return 1 if failures else 0

    changed = 0
    if todo:
        _execute_heading(ccm)
        for endpoint, target in todo:
            try:
                ccm.run(["endpoint", "update", f"--subscription-code={ccm.subscription_code}",
                         f"--environment-code={env.code}", f"--code={endpoint}",
                         f"--ssl-certificate={target.code}"], mutating=True)
                changed += 1
            except SapCcmError as exc:
                failures += 1
                details.append((endpoint, f"update failed\n{_relative(exc.summary)}"))

    problems(details)
    summary(f"Rollout finished: {changed} endpoint(s) switched"
            + (f", {failures} error(s)." if failures else "."), ok=not failures)
    return 1 if failures else 0


# -- cleanup -----------------------------------------------------------------

def cmd_cleanup(cfg: Config, ccm: SapCcm, apply: bool, include_unused: bool = False) -> int:
    remote = list_remote_certificates(ccm)
    rows: List[List[Cell]] = []
    deletable = []
    for cert in remote:
        state = classify(cfg, cert, include_unused)
        if state in _DELETABLE:
            deletable.append(cert)
            action: Cell = ("delete" if apply else "would delete", "red" if apply else "yellow")
        elif state == "in use":
            action = ("keep - still assigned to endpoints", "yellow")
        else:
            action = ("keep", "dim")
        rows.append([cert.name or "(no name)", cert.code, (state, _CLASS_COLORS[state]),
                     _endpoints(cert), _date(cert.expiration), action])

    heading("Cleanup plan" + (" - including unused configured certificates" if include_unused else "")
            + ("" if apply else " (preview)"))
    table(["Certificate", "Code", "Status", "Endpoints", "Expires", "Action"], rows)

    if not deletable:
        summary("Cleanup finished: no deletable certificates found.")
        return 0
    if not apply:
        command = "cleanup --include-unused --apply" if include_unused else "cleanup --apply"
        summary(f"{len(deletable)} certificate(s) would be deleted. Use '{command}' to delete them.")
        return 0

    details = []
    _execute_heading(ccm)
    for cert in deletable:
        try:
            ccm.run(["certificate", "delete", f"--subscription-code={ccm.subscription_code}",
                     f"--certificate-code={cert.code}"], mutating=True)
        except SapCcmError as exc:
            details.append((cert.name, f"deletion failed\n{_relative(exc.summary)}"))
    problems(details)
    summary(f"Cleanup finished: {len(deletable) - len(details)} deleted"
            + (f", {len(details)} error(s)." if details else "."), ok=not details)
    return 1 if details else 0


# -- status ------------------------------------------------------------------

def _status_environment(cfg: Config, env: EnvironmentConfig, ccm: SapCcm, remote: List[RemoteCertificate],
                        details: list) -> int:
    """Table of actual vs. configured certificate per endpoint. Returns the number of problems."""
    try:
        existing = list_endpoints(ccm, env.code)
    except SapCcmError as exc:
        print(style("  could not list endpoints - see details", "red"))
        details.append((f"environment {env.code}", _relative(exc.summary)))
        return 1

    rows: List[List[Cell]] = []
    found = 0
    for endpoint in list(env.endpoints) + [e for e in existing if e not in env.endpoints]:
        target = env.endpoints.get(endpoint)
        resolved = resolve_target(target, env, remote) if target and target != UNMANAGED_TARGET else None
        target_text = resolved.text if resolved else (target or "-")
        candidates = resolved.candidates if resolved else []
        if endpoint not in existing:
            found += 1
            rows.append([endpoint, "-", target_text, ("endpoint does not exist", "red")])
            continue
        try:
            value = show_endpoint(ccm, env.code, endpoint).get("SSL CERTIFICATE", "")
        except SapCcmError as exc:
            found += 1
            rows.append([endpoint, "?", target_text, ("could not read endpoint", "red")])
            details.append((f"{env.code}/{endpoint}", _relative(exc.summary)))
            continue
        current = _describe(value, remote)
        if target is None:
            state: Cell = ("not configured", "dim")
        elif (drift := domain_drift(env, endpoint, existing[endpoint])):
            found += 1
            state = ("domain differs from configuration", "red")
            details.append((f"{env.code}/{endpoint}", drift))
        elif target == UNMANAGED_TARGET:
            state = ("unmanaged", "dim")
        elif not candidates:
            found += 1
            state = (resolved.missing, "red")
        elif value in resolved.accepted:
            state = ("OK - target in place", "green")
        elif (mismatch := domain_mismatch(cfg, target, effective_domain(env, endpoint, existing[endpoint]))):
            found += 1
            state = ("domain not covered", "red")
            details.append((f"{env.code}/{endpoint}", mismatch))
        else:
            state = ("rollout pending", "yellow")
        rows.append([endpoint, current, target_text, state])
    table(["Endpoint", "Current certificate", "Target certificate", "State"], rows)
    return found


def cmd_status(cfg: Config, ccm: SapCcm, env_session: Optional[EnvSession] = None,
               environment: Optional[EnvironmentConfig] = None) -> int:
    remote = list_remote_certificates(ccm)
    remote_names = _by_name(remote)
    details: list = []
    found = 0

    heading("Configured certificates (local)")
    rows: List[List[Cell]] = []
    for name, cert in cfg.certificates.items():
        check = check_certificate(cert)
        if check.ok:
            notes = [f"warning: {_relative(w)}" for w in check.warnings]
            if not check.has_ca_chain:
                notes.append("self-signed, no CA chain")
            local: Cell = ("\n".join(["OK"] + notes), "yellow" if check.warnings else "green")
        else:
            found += 1
            local = ("check failed - see Details", "red")
            details += [(name, _relative(e)) for e in check.errors]
        uploaded = remote_names.get(name, [])
        portal: Cell = (", ".join(f"uploaded [{c.code}]" for c in uploaded), "green") if uploaded \
            else ("not uploaded", "yellow")
        rows.append([name, local, f"{check.not_after:%Y-%m-%d}" if check.not_after else "-", portal])
    table(["Certificate", "Local check", "Valid until", "Portal"], rows)

    heading(f"Certificates in subscription {cfg.subscription_code}")
    _subscription_table(cfg, remote)

    envs = [environment] if environment else list(cfg.environments.values())
    if not envs:
        heading("Environments")
        print("  (none configured)")
    for env in envs:
        title = f"Environment {env.code}" + (f" ({env.description})" if env.description else "")
        if env_session is None:
            heading(title)
            found += _status_environment(cfg, env, ccm, remote, details)
            continue
        try:
            with env_session(env) as env_ccm:
                heading(f"{title} - credentials {env_ccm.credentials.source}*")
                found += _status_environment(cfg, env, env_ccm, remote, details)
        except ConfigError as exc:
            heading(title)
            found += 1
            print(style("  credentials not available - see details", "red"))
            details.append((f"environment {env.code}", str(exc)))

    problems(details)
    summary("Status: no problems found." if not found else f"Status: {found} problem(s) found.",
            ok=not found)
    return 1 if found else 0


# -- fetch -------------------------------------------------------------------

def list_environments(ccm: SapCcm) -> Dict[str, str]:
    """Environment code -> name of all environments of the subscription."""
    out = ccm.run(["environment", "list", f"--subscription-code={ccm.subscription_code}"])
    rows = parse_table(out, "CODE") or []
    return {row["CODE"]: row.get("NAME", "") for row in rows if row.get("CODE")}


def fetched_target(cfg: Config, value: str, remote: List[RemoteCertificate]) -> str:
    """Configuration target for the certificate currently assigned to an endpoint."""
    cert = next((c for c in remote if value in (c.code, c.name)), None)
    name = cert.name if cert else value
    if name and is_sap_managed(name):
        return SAP_MANAGED_TARGET
    if name in cfg.certificates:
        return name
    return UNMANAGED_TARGET


def _write_config(path, raw: dict) -> None:
    """Write the configuration atomically (2-space indentation, key order preserved)."""
    # The file contains the client secret: the new file is created owner-only and keeps the mode
    # of the original file.
    mode = path.stat().st_mode & 0o777 if path.exists() else 0o600
    tmp = path.with_name(path.name + ".tmp")
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(json.dumps(raw, indent=2, ensure_ascii=False) + "\n")
    os.chmod(tmp, mode)
    os.replace(tmp, path)


def cmd_fetch(cfg: Config, ccm: SapCcm, env_session: EnvSession, only: Optional[str] = None,
              apply: bool = False) -> int:
    """Add endpoints of the portal that are missing in the configuration. Existing entries are kept."""
    raw = json.loads(cfg.path.read_text(encoding="utf-8"))
    raw_envs = raw.setdefault("environments", {})
    portal_envs = list_environments(ccm)
    remote = list_remote_certificates(ccm)

    by_code = {env.code: env for env in cfg.environments.values()}
    codes = list(portal_envs) + [c for c in by_code if c not in portal_envs]
    if only:
        wanted = cfg.environments[only].code if only in cfg.environments else only
        if wanted not in codes:
            print(f"ERROR: Environment '{only}' exists neither in the configuration nor in the portal "
                  f"(portal: {', '.join(portal_envs) or '-'}).")
            return 2
        codes = [wanted]

    rows: List[List[Cell]] = []
    details = []
    added = 0
    for code in codes:
        env = by_code.get(code) or EnvironmentConfig(key=code, code=code, description=portal_envs.get(code, ""),
                                                     endpoints={})
        if code not in portal_envs:
            rows.append([env.key, "-", "-", "-", ("environment not found in portal", "yellow")])
            continue
        try:
            with env_session(env) as session:
                endpoints = list_endpoints(session, code)
                new = {}
                for endpoint, domain in endpoints.items():
                    if endpoint in env.endpoints:
                        continue
                    value = show_endpoint(session, code, endpoint).get("SSL CERTIFICATE", "")
                    new[endpoint] = (domain, value)
        except SapCcmError as exc:
            rows.append([env.key, "?", "-", "-", ("could not read endpoints", "red")])
            details.append((f"environment {code}", _relative(exc.summary)))
            continue

        for endpoint in env.endpoints:
            if endpoint in endpoints:
                rows.append([env.key, endpoint, endpoints[endpoint] or "-", env.endpoints[endpoint],
                             ("keep - already configured", "dim")])
            else:
                rows.append([env.key, endpoint, env.domains.get(endpoint, "-"), env.endpoints[endpoint],
                             ("configured, but not in portal", "yellow")])
        if not new:
            continue
        target_env = raw_envs.setdefault(env.key, {})
        if not isinstance(target_env, dict):
            target_env = raw_envs[env.key] = {}
        if env.key not in cfg.environments and env.description:
            target_env.setdefault("description", env.description)
        target_endpoints = target_env.setdefault("endpoints", {})
        for endpoint, (domain, value) in new.items():
            target = fetched_target(cfg, value, remote)
            entry = {"domain": domain, "certificate": target} if domain else {"certificate": target}
            target_endpoints[endpoint] = entry
            note = "" if target != UNMANAGED_TARGET or not value else f"\ncurrently {_describe(value, remote)}"
            rows.append([env.key, endpoint, domain or "-", target + note,
                         ("add" if apply else "would add", "yellow")])
            added += 1

    heading("Fetch plan - " + _relative(str(cfg.path)) + ("" if apply else " (preview)"))
    table(["Environment", "Endpoint", "Domain", "Certificate", "Action"], rows)
    problems(details)

    failures = len(details)
    if not apply:
        summary(f"{added} endpoint(s) would be added to the configuration"
                + (f", {failures} error(s)" if failures else "")
                + (". Use 'fetch --apply' to write them." if added else "."), ok=not failures)
        return 1 if failures else 0
    if added:
        _write_config(cfg.path, raw)
    summary(f"Fetch finished: {added} endpoint(s) added to {_relative(str(cfg.path))}"
            + (f", {failures} error(s)." if failures else "."), ok=not failures)
    return 1 if failures else 0

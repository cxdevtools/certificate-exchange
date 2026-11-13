"""Tests for certtool against a mocked sapccm CLI.

Run from the project root:  python3 -m unittest discover -s tests -v
"""

import contextlib
from datetime import datetime, timedelta
import io
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from certtool.__main__ import main  # noqa: E402
from certtool.tables import parse_details, parse_table  # noqa: E402

MOCK = Path(__file__).resolve().parent / "mock_sapccm.py"
HAS_OPENSSL = shutil.which("openssl") is not None


def make_certificate(directory: Path, cn: str) -> None:
    """Create CA + leaf certificate with openssl (PEM, unencrypted key)."""
    directory.mkdir(parents=True, exist_ok=True)
    run = lambda *a: subprocess.run(["openssl", *a], check=True, capture_output=True, cwd=directory)  # noqa: E731
    run("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "ca.key", "-out", "ca-chain.pem",
        "-days", "30", "-subj", "/CN=Test CA")
    run("req", "-newkey", "rsa:2048", "-nodes", "-keyout", "private-key.pem", "-out", "leaf.csr",
        "-subj", f"/CN={cn}")
    (directory / "san.ext").write_text(f"subjectAltName=DNS:{cn},DNS:*.example.com\n")
    run("x509", "-req", "-in", "leaf.csr", "-CA", "ca-chain.pem", "-CAkey", "ca.key", "-CAcreateserial",
        "-out", "certificate.pem", "-days", "365", "-extfile", "san.ext")


class DomainMatchTest(unittest.TestCase):
    def test_wildcard_covers_exactly_one_label(self):
        from certtool.pem import domain_covered
        names = ["*.local.cxdev.me", "local.cxdev.me"]
        self.assertTrue(domain_covered("www.local.cxdev.me", names))
        self.assertTrue(domain_covered("WWW.Local.cxdev.me.", names))
        self.assertTrue(domain_covered("local.cxdev.me", names))
        self.assertFalse(domain_covered("a.b.local.cxdev.me", names))
        self.assertFalse(domain_covered("jsapps.d1-public.model-t.cc.commerce.ondemand.com", names))

    @unittest.skipUnless(HAS_OPENSSL, "openssl required")
    def test_certificate_domains_reads_san(self):
        from certtool.pem import certificate_domains
        with tempfile.TemporaryDirectory() as tmp:
            make_certificate(Path(tmp), "shop.example.org")
            self.assertEqual(certificate_domains(Path(tmp) / "certificate.pem"),
                             ["shop.example.org", "*.example.com"])


class ExpiryParserTest(unittest.TestCase):
    def test_formats(self):
        from certtool.config import ConfigError
        from certtool.sapccm import parse_expiry
        # value exactly as shown in the Cloud Portal dialog: 11 May 2027
        self.assertEqual(parse_expiry("11/05/2027 10:51:04 AM"), (datetime(2027, 5, 11, 10, 51, 4), None))
        self.assertEqual(parse_expiry("25/11/2027 10:51:04 PM")[0], datetime(2027, 11, 25, 22, 51, 4))
        self.assertEqual(parse_expiry("11/05/2027")[0], datetime(2027, 5, 11))
        self.assertEqual(parse_expiry("2027-05-11")[0], datetime(2027, 5, 11))
        self.assertEqual(parse_expiry("05/11/2027 10:51:04 AM", "%m/%d/%Y %I:%M:%S %p")[0],
                         datetime(2027, 5, 11, 10, 51, 4))
        with self.assertRaises(ConfigError):
            parse_expiry("11/25/2027 10:51:04 AM")  # month 25 does not exist


class SapManagedTest(unittest.TestCase):
    def test_detection(self):
        from certtool.config import is_sap_managed
        self.assertTrue(is_sap_managed("d1-public - 2026-11-19 (Let's Encrypt)"))
        self.assertTrue(is_sap_managed("p1-public - 2027-02-05 (LET'S ENCRYPT)"))
        self.assertTrue(is_sap_managed("s1-public - 2027-02-05 (Let\u2019s Encrypt)"))
        self.assertFalse(is_sap_managed("www-example-com-2026"))

    def test_example_pattern_matches(self):
        import fnmatch
        cfg = json.loads((ROOT / "certtool.example.json").read_text(encoding="utf-8"))
        patterns = cfg["cleanup"]["protectedCertificates"]
        self.assertTrue(any(fnmatch.fnmatchcase("d1-public - 2026-11-19 (Let's Encrypt)", p) for p in patterns))


class OutputTest(unittest.TestCase):
    class _Utf8(io.StringIO):
        encoding = "utf-8"

    def render(self, stream):
        from certtool.output import table
        with contextlib.redirect_stdout(stream):
            table(["Name", "State"], [["a", ("line 1\nline 2", "red")], ["long name", "ok"]])
        return stream.getvalue()

    def test_ascii_without_utf8(self):
        out = self.render(io.StringIO())
        self.assertIn("  | Name      | State  |", out)
        self.assertIn("  |           | line 2 |", out)
        self.assertNotIn("\x1b[", out)  # no colors when not a terminal

    def test_unicode_with_utf8(self):
        out = self.render(self._Utf8())
        self.assertIn("\u250c", out)  # box drawing top left corner
        self.assertIn("\u2502 long name \u2502 ok     \u2502", out)


class JavaTest(unittest.TestCase):
    def fake_java(self, version_line):
        tmp = Path(tempfile.mkdtemp(prefix="certtool-java-"))
        self.addCleanup(shutil.rmtree, tmp, True)
        script = tmp / "java"
        script.write_text(f"#!/bin/sh\necho '{version_line}' >&2\n")
        script.chmod(0o755)
        return str(script)

    def detect(self, version_line):
        from certtool.sapccm import detect_java
        with mock.patch.dict(os.environ, {"JAVACMD": self.fake_java(version_line)}):
            return detect_java()

    @unittest.skipIf(os.name == "nt", "shell script")
    def test_versions_and_options(self):
        java25 = self.detect('openjdk version "25.0.4" 2026-07-21 LTS')
        self.assertEqual(java25.major, 25)
        self.assertIn("--sun-misc-unsafe-memory-access=allow", java25.quiet_options())
        java21 = self.detect('openjdk version "21.0.12" 2026-07-21 LTS')
        self.assertEqual(java21.major, 21)
        self.assertIn("--enable-native-access=ALL-UNNAMED", java21.quiet_options())
        self.assertNotIn("--sun-misc-unsafe-memory-access=allow", java21.quiet_options())
        java8 = self.detect('java version "1.8.0_392"')
        self.assertEqual(java8.major, 8)
        self.assertEqual(java8.quiet_options(), ["-Dlogging.level.io.netty=OFF"])

    @unittest.skipIf(os.name == "nt", "shell script")
    def test_old_java_is_rejected(self):
        from certtool.config import ConfigError
        from certtool.sapccm import check_java
        with self.assertRaises(ConfigError):
            check_java(self.detect('openjdk version "17.0.14" 2025-01-21 LTS'))


class TableParserTest(unittest.TestCase):
    def test_parses_values_with_spaces(self):
        text = (
            "CERTIFICATE CODE  NAME          ISSUER            EXPIRATION DATE\n"
            "abc123            my cert name  Let's Encrypt R3  2027-01-01T00:00Z\n"
            "x                 short                           n/a\n"
        )
        rows = parse_table(text, "CERTIFICATE CODE")
        self.assertEqual(rows[0]["NAME"], "my cert name")
        self.assertEqual(rows[0]["ISSUER"], "Let's Encrypt R3")
        self.assertEqual(rows[1]["ISSUER"], "")
        self.assertEqual(rows[1]["EXPIRATION DATE"], "n/a")

    def test_missing_table(self):
        self.assertIsNone(parse_table("No certificates found for subscription.\n", "CERTIFICATE CODE"))

    def test_details(self):
        text = "PROPERTY         VALUE\nSSL CERTIFICATE  cert001\nNAME             a b\n"
        self.assertEqual(parse_details(text), {"SSL CERTIFICATE": "cert001", "NAME": "a b"})


@unittest.skipUnless(HAS_OPENSSL, "openssl required")
class CommandTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="certtool-test-"))
        certs_dir = self.tmp / "certs"
        make_certificate(certs_dir / "new-cert", "new.example.com")
        make_certificate(certs_dir / "current-cert", "current.example.com")
        self.config = self.tmp / "certtool.json"
        self.config.write_text(json.dumps({
            "subscriptionCode": "sub123",
            "credentials": {
                "tokenEndpoint": "https://ycloud.accounts.ondemand.com/oauth2/token",
                "clientId": "client-id-value",
                "clientSecret": "s3cr=t:with#chars",
                "clientResource": "urn:sap:identity:application:provider:name:cp-dependency",
            },
            "certificatesPath": "certs",  # relative to the configuration file
            "certificates": {"new-cert": {}, "current-cert": {}},
            "environments": {
                "d1": {"endpoints": {"storefront": "new-cert", "backoffice": "current-cert"}},
                "s1": {"endpoints": {"unknown-endpoint": "new-cert"}},
            },
            "cleanup": {"protectedCertificates": ["sap-*", "cert900"]},
        }))
        self.state = self.tmp / "state.json"
        self.write_state({
            "certificates": [
                {"code": "cert100", "name": "current-cert"},
                {"code": "cert101", "name": "old-cert"},
                {"code": "cert102", "name": "old-but-in-use"},
                {"code": "cert900", "name": "SAP provided"},
                {"code": "cert901", "name": "sap-default"},
                {"code": "cert902", "name": "d1-public - 2026-11-19 (Let's Encrypt)"},
                {"code": "cert903", "name": "d1-public - 2027-02-05 (Let\u2019s Encrypt)"},
            ],
            "endpoints": {
                "d1": {"storefront": {"ssl": "cert102"}, "backoffice": {"ssl": "cert100"}},
                "s1": {"storefront": {"ssl": ""}},
            },
        })
        self.env = mock.patch.dict(os.environ, {
            "CERTTOOL_SAPCCM": f"{shlex.quote(sys.executable)} {shlex.quote(str(MOCK))}",
            "MOCK_SAPCCM_STATE": str(self.state),
        })
        self.config.chmod(0o600)
        self.env.start()

    def tearDown(self):
        self.env.stop()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def update_config(self, change):
        cfg = json.loads(self.config.read_text())
        change(cfg)
        self.config.write_text(json.dumps(cfg))

    def set_credentials(self, path, **values):
        """Set credential fields, e.g. set_credentials(("environments", "d1"), clientId="x")."""
        def change(cfg):
            node = cfg
            for key in path:
                node = node[key]
            node.setdefault("credentials", {}).update(values)
        self.update_config(change)

    def write_state(self, state):
        self.state.write_text(json.dumps(state))

    def read_state(self):
        return json.loads(self.state.read_text())

    def run_tool(self, *args):
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
            rc = main(["--config", str(self.config), *args])
        return rc, out.getvalue()

    def assertRow(self, out, *cells):
        """Assert that a table row starts with the given cells (None matches any cell, a str
        starting with '~' matches by prefix)."""
        for line in out.splitlines():
            parts = [p.strip() for p in re.split(r"[|\u2502]", line)][1:-1]
            if len(parts) < len(cells):
                continue
            if all(c is None or (c.startswith("~") and parts[i].startswith(c[1:])) or parts[i] == c
                   for i, c in enumerate(cells)):
                return
        self.fail(f"no table row {cells} in output:\n{out}")

    def names(self):
        return sorted(c["name"] for c in self.read_state()["certificates"])

    # -- credentials -----------------------------------------------------
    def test_credentials_are_isolated_and_removed(self):
        rc, _ = self.run_tool("cleanup")
        self.assertEqual(rc, 0)
        call = self.read_state()["calls"][0]
        self.assertEqual(call["config"]["client-id"], "client-id-value")
        self.assertEqual(call["config"]["client-secret"], "s3cr=t:with#chars")
        self.assertEqual(call["config"]["token-url"], "https://ycloud.accounts.ondemand.com/oauth2/token")
        self.assertEqual(call["config"]["subscription-code"], "sub123")
        self.assertFalse(Path(call["config"]["_path"]).exists(), "temporary CLI configuration was not deleted")
        self.assertFalse(str(Path.home()) in call["config"]["_path"])

    def test_missing_credentials(self):
        self.set_credentials((), clientSecret="")
        rc, out = self.run_tool("cleanup")
        self.assertEqual(rc, 2)
        self.assertIn("credentials are missing in certtool.json: credentials.clientSecret", out)
        self.assertNotIn("calls", self.read_state())

    def test_unknown_credential_field_is_rejected(self):
        self.set_credentials((), client_secret="x")
        rc, out = self.run_tool("cleanup")
        self.assertEqual(rc, 2)
        self.assertIn("credentials: unknown field(s) client_secret", out)

    def test_environment_variables_are_not_used(self):
        self.update_config(lambda cfg: cfg.pop("credentials"))
        with mock.patch.dict(os.environ, {"CXDEV_CCM_sub123_CLIENT_ID": "x", "CXDEV_CCM_sub123_CLIENT_SECRET": "y",
                                          "CXDEV_CCM_sub123_TOKEN_ENDPOINT": "z"}):
            rc, out = self.run_tool("cleanup")
        self.assertEqual(rc, 2)
        self.assertIn("credentials.clientId, clientSecret, tokenEndpoint", out)

    def test_secret_is_never_printed(self):
        rc, out = self.run_tool("status", "-v")
        self.assertNotIn("s3cr=t:with#chars", out)
        self.assertIn("Credentials    credentials ·", out)

    def test_config_readable_by_others_warns(self):
        self.config.chmod(0o644)
        rc, out = self.run_tool("cleanup")
        self.assertEqual(rc, 0, out)
        self.assertIn("certtool.json contains credentials but is accessible by other users", out)
        self.config.chmod(0o600)
        rc, out = self.run_tool("cleanup")
        self.assertNotIn("accessible by other users", out)

    def test_environment_specific_credentials_take_precedence(self):
        self.run_tool("upload", "--apply")
        self.set_credentials(("environments", "d1"), clientId="d1-client", clientSecret="d1-secret")
        rc, out = self.run_tool("rollout", "d1", "--apply")
        self.assertEqual(rc, 0, out)
        self.assertIn("environments.d1.credentials ·", out)
        # commands without an environment keep using the subscription credentials
        self.run_tool("cleanup")
        calls = self.read_state()["calls"]
        rollout_calls = [c for c in calls if c["args"][:2] == ["endpoint", "update"]]
        self.assertEqual(rollout_calls[0]["config"]["client-id"], "d1-client")
        self.assertEqual(rollout_calls[0]["config"]["client-secret"], "d1-secret")
        # token endpoint falls back to the subscription credentials
        self.assertEqual(rollout_calls[0]["config"]["token-url"], "https://ycloud.accounts.ondemand.com/oauth2/token")
        self.assertEqual(calls[-1]["config"]["client-id"], "client-id-value")

    def test_rollout_falls_back_to_subscription_credentials(self):
        self.run_tool("upload", "--apply")
        rc, out = self.run_tool("rollout", "d1", "--apply")
        self.assertEqual(rc, 0, out)
        self.assertIn("Credentials    credentials ·", out)

    def test_environment_secret_without_id_is_rejected(self):
        self.set_credentials(("environments", "d1"), clientSecret="d1-secret")
        rc, out = self.run_tool("rollout", "d1", "--apply")
        self.assertEqual(rc, 2)
        self.assertIn("environments.d1.credentials defines clientSecret but no clientId", out)
        self.assertNotIn("calls", self.read_state())

    def test_environment_id_without_secret_does_not_mix(self):
        self.set_credentials(("environments", "d1"), clientId="d1-client")
        rc, out = self.run_tool("rollout", "d1", "--apply")
        self.assertEqual(rc, 2)
        self.assertIn("environments.d1.credentials.clientSecret", out)

    # -- secret expiration -----------------------------------------------
    def test_expired_secret_aborts_before_cli_call(self):
        self.set_credentials((), clientExpires="01/02/2020 10:51:04 AM")
        rc, out = self.run_tool("cleanup")
        self.assertEqual(rc, 2)
        self.assertIn("client secret has expired (credentials.clientExpires = '01/02/2020 10:51:04 AM'", out)
        self.assertNotIn("calls", self.read_state())

    def test_valid_secret_runs(self):
        for value in ("11/05/2099 10:51:04 AM", "11/05/2099", "2099-05-11"):
            self.set_credentials((), clientExpires=value)
            rc, out = self.run_tool("cleanup")
            self.assertEqual(rc, 0, f"{value}: {out}")
        self.assertIn("secret expires 2099-05-11", out)

    def test_expiring_soon_warns(self):
        self.set_credentials((), clientExpires=(datetime.now() + timedelta(days=3)).strftime("%Y-%m-%d"))
        rc, out = self.run_tool("cleanup")
        self.assertEqual(rc, 0)
        self.assertIn("expires in", out)

    def test_wrapper_runs_with_config_credentials(self):
        env = {k: v for k, v in os.environ.items() if not k.startswith("CXDEV_CCM_")}
        proc = subprocess.run([str(ROOT / "bin" / "cxdev-certificates"), "cleanup", "--config", str(self.config)],
                              env=env, capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertNotIn("s3cr=t:with#chars", proc.stdout + proc.stderr)
        self.assertEqual(self.read_state()["calls"][0]["config"]["client-id"], "client-id-value")

    # -- configuration location -------------------------------------------
    def run_in(self, directory, *args):
        cwd = os.getcwd()
        os.chdir(directory)
        try:
            out = io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
                rc = main(list(args))
        finally:
            os.chdir(cwd)
        return rc, out.getvalue()

    def test_config_from_current_directory(self):
        rc, out = self.run_in(self.tmp, "upload")
        self.assertEqual(rc, 0, out)
        self.assertIn("Configuration  certtool.json", out)
        self.assertRow(out, "new-cert", None, "would upload")

    def test_missing_config_in_current_directory(self):
        rc, out = self.run_in(self.tmp / "certs", "status")
        self.assertEqual(rc, 2)
        self.assertIn("Run certtool in the project directory that contains certtool.json", out)

    def test_certificates_path_is_relative_to_config_not_cwd(self):
        (self.tmp / "certs").rename(self.tmp / "certificates")
        self.update_config(lambda cfg: cfg.pop("certificatesPath"))  # default ./certificates
        rc, out = self.run_in(ROOT, "--config", str(self.config), "upload")
        self.assertEqual(rc, 0, out)
        self.assertRow(out, "new-cert", None, "would upload")

    def test_old_certificates_dir_key_is_rejected(self):
        self.update_config(lambda cfg: cfg.update(certificatesDir="certs"))
        rc, out = self.run_tool("status")
        self.assertEqual(rc, 2)
        self.assertIn("'certificatesDir' was renamed to 'certificatesPath'", out)

    def test_wrapper_works_through_symlink(self):
        link_dir = self.tmp / "path-bin"
        link_dir.mkdir()
        (link_dir / "cxdev-certificates").symlink_to(ROOT / "bin" / "cxdev-certificates")
        proc = subprocess.run([str(link_dir / "cxdev-certificates"), "cleanup"], cwd=self.tmp,
                              capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("Configuration  certtool.json", proc.stdout)

    # -- help ------------------------------------------------------------
    def test_overview_without_arguments(self):
        for argv in ([], ["--help"]):
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                rc = main(argv)
            self.assertEqual(rc, 0)
            text = out.getvalue()
            for part in ("Usage", "Commands", "Examples:", "Typical certificate exchange", "Global options",
                         "status [environment]", "upload [--certificate NAME] [--apply]",
                         "rollout <environment> [--endpoint CODE] [--apply]",
                         "cleanup [--include-unused] [--apply]", "certtool rollout d1 --apply"):
                self.assertIn(part, text)
        self.assertEqual(self.read_state().get("calls", []), [])

    def test_usage_error_shows_command_help(self):
        cases = [(["cleanup", "--unknown-param"], "certtool cleanup", "unrecognized arguments: --unknown-param"),
                 (["rollout"], "certtool rollout", "the following arguments are required: environment"),
                 (["upload", "--apply", "extra"], "certtool upload", "unrecognized arguments: extra")]
        for argv, prog, message in cases:
            err = io.StringIO()
            with contextlib.redirect_stdout(err), contextlib.redirect_stderr(err), \
                    self.assertRaises(SystemExit) as exit_:
                main(argv)
            self.assertEqual(exit_.exception.code, 2)
            text = err.getvalue()
            self.assertIn(f"usage: {prog}", text)
            self.assertIn("examples:", text)
            self.assertTrue(text.rstrip().endswith(f"{prog}: error: {message}"), text)

    def test_unknown_command_shows_overview(self):
        err = io.StringIO()
        with contextlib.redirect_stdout(err), contextlib.redirect_stderr(err), self.assertRaises(SystemExit):
            main(["deploy"])
        self.assertIn("Commands", err.getvalue())
        self.assertIn("invalid choice: 'deploy'", err.getvalue())

    def test_command_help_shows_examples(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out), self.assertRaises(SystemExit):
            main(["cleanup", "--help"])
        self.assertIn("examples:", out.getvalue())
        self.assertIn("certtool cleanup --include-unused", out.getvalue())

    # -- upload ----------------------------------------------------------
    def test_upload_creates_only_missing(self):
        rc, out = self.run_tool("upload", "--apply")
        self.assertEqual(rc, 0, out)
        self.assertRow(out, "current-cert", None, "skip - already uploaded [cert100]")
        self.assertIn("new-cert", self.names())
        creates = [c for c in self.read_state()["calls"] if c["args"][:2] == ["certificate", "create"]]
        self.assertEqual(len(creates), 1)
        self.assertFalse(any(a.startswith("--description") for a in creates[0]["args"]))
        # second run is idempotent
        rc, out = self.run_tool("upload", "--apply")
        self.assertEqual(rc, 0)
        self.assertRow(out, "new-cert", None, "~skip - already uploaded")

    def test_upload_preview_by_default(self):
        rc, out = self.run_tool("upload")
        self.assertEqual(rc, 0, out)
        self.assertIn("Upload plan (preview)", out)
        self.assertIn("preview (use --apply to upload)", out)
        self.assertRow(out, "new-cert", None, "would upload")
        self.assertIn("Use 'upload --apply' to upload them.", out)
        self.assertNotIn("certificate create", out)
        self.assertNotIn("new-cert", self.names())

    def test_upload_rejects_mismatching_key(self):
        cert_dir = self.tmp / "certs" / "new-cert"
        shutil.copy(self.tmp / "certs" / "current-cert" / "private-key.pem", cert_dir / "private-key.pem")
        rc, out = self.run_tool("upload", "--apply")
        self.assertEqual(rc, 1)
        self.assertIn("Private key does not match the certificate", out)
        self.assertNotIn("new-cert", self.names())

    def test_upload_blocks_non_ascii_name(self):
        cfg = json.loads(self.config.read_text())
        cfg["certificates"]["zertifikat-für-test"] = {"directory": "new-cert"}
        self.config.write_text(json.dumps(cfg))
        rc, out = self.run_tool("upload", "--certificate", "zertifikat-für-test", "--apply")
        self.assertEqual(rc, 1)
        self.assertRow(out, "zertifikat-für-test", None, "blocked - local check failed")
        self.assertIn("Name contains characters the Cloud Portal rejects: 'ü'", out)
        creates = [c for c in self.read_state()["calls"] if c["args"][:2] == ["certificate", "create"]]
        self.assertEqual(creates, [])

    def test_upload_blocks_missing_ca_chain(self):
        (self.tmp / "certs" / "new-cert" / "ca-chain.pem").unlink()
        rc, out = self.run_tool("upload", "--apply")
        self.assertEqual(rc, 1, out)
        self.assertRow(out, "new-cert", None, "blocked - local check failed")
        self.assertIn("CA chain missing: the Cloud Portal has to verify the certification path up to 'CN=Test CA'", out)
        self.assertNotIn("new-cert", self.names())

    def test_upload_splits_full_chain_certificate_file(self):
        cert_dir = self.tmp / "certs" / "new-cert"
        leaf = (cert_dir / "certificate.pem").read_text()
        ca = (cert_dir / "ca-chain.pem").read_text()
        (cert_dir / "certificate.pem").write_text(leaf + ca)
        (cert_dir / "ca-chain.pem").unlink()
        rc, out = self.run_tool("upload", "--apply")
        self.assertEqual(rc, 0, out)
        self.assertIn("CA chain taken from certificate file (1 certificate(s))", out)
        uploaded = next(c for c in self.read_state()["certificates"] if c["name"] == "new-cert")
        self.assertEqual(uploaded["certificate"].count("BEGIN CERTIFICATE"), 1)
        self.assertEqual(uploaded["certificate"].strip(), leaf.strip())
        self.assertEqual(uploaded["ca"].strip(), ca.strip())
        self.assertFalse(Path(uploaded["ca_path"]).exists(), "temporary CA file was not removed")

    def test_upload_self_signed_without_ca_chain(self):
        cert_dir = self.tmp / "certs" / "new-cert"
        (cert_dir / "ca-chain.pem").unlink()
        subprocess.run(["openssl", "req", "-x509", "-key", "private-key.pem", "-out", "certificate.pem",
                        "-days", "30", "-subj", "/CN=self.example.com"], check=True, capture_output=True,
                       cwd=cert_dir)
        rc, out = self.run_tool("upload", "--apply")
        self.assertEqual(rc, 0, out)
        self.assertIn("self-signed, no CA chain", out)
        uploaded = next(c for c in self.read_state()["certificates"] if c["name"] == "new-cert")
        self.assertEqual(uploaded["ca"], "\n")
        self.assertNotIn(str(cert_dir), uploaded["ca_path"])

    def test_status_reports_missing_ca_chain(self):
        self.run_tool("upload", "--apply")
        (self.tmp / "certs" / "new-cert" / "ca-chain.pem").unlink()
        rc, out = self.run_tool("status", "d1")
        self.assertEqual(rc, 1, out)
        self.assertRow(out, "new-cert", "check failed - see Details", None, None)
        self.assertIn("new-cert: CA chain missing", out)

    # -- rollout ---------------------------------------------------------
    def test_rollout_blocks_endpoint_with_uncovered_domain(self):
        self.run_tool("upload", "--apply")
        state = self.read_state()
        state["endpoints"]["d1"]["storefront"]["domain"] = "jsapps.d1-public.model-t.cc.commerce.ondemand.com"
        self.write_state(state)
        rc, out = self.run_tool("rollout", "d1", "--apply")
        self.assertEqual(rc, 1, out)
        self.assertRow(out, "storefront", "-", None, "blocked - domain not covered")
        self.assertIn("does not cover the endpoint domain 'jsapps.d1-public.model-t.cc.commerce.ondemand.com'", out)
        self.assertEqual(self.read_state()["endpoints"]["d1"]["storefront"]["ssl"], "cert102")
        self.assertFalse(any(c["args"][:2] == ["endpoint", "update"] for c in self.read_state()["calls"]))

        rc, out = self.run_tool("status", "d1")
        self.assertEqual(rc, 1, out)
        self.assertRow(out, "storefront", None, None, "domain not covered")

    def test_rollout_accepts_url_with_protocol(self):
        self.run_tool("upload", "--apply")
        state = self.read_state()
        state["endpoints"]["d1"]["storefront"]["domain"] = "https://Shop.Example.com/"
        self.write_state(state)
        rc, out = self.run_tool("rollout", "d1", "--apply")
        self.assertEqual(rc, 0, out)

    def test_rollout_requires_upload(self):
        rc, out = self.run_tool("rollout", "d1", "--apply")
        self.assertEqual(rc, 1)
        self.assertIn("run 'upload' first", out)

    def test_rollout_updates_changed_endpoints(self):
        self.run_tool("upload", "--apply")
        new_code = next(c["code"] for c in self.read_state()["certificates"] if c["name"] == "new-cert")
        rc, out = self.run_tool("rollout", "d1", "--apply")
        self.assertEqual(rc, 0, out)
        endpoints = self.read_state()["endpoints"]["d1"]
        self.assertEqual(endpoints["storefront"]["ssl"], new_code)
        self.assertEqual(endpoints["backoffice"]["ssl"], "cert100")
        self.assertRow(out, "backoffice", "current-cert [cert100]", "current-cert [cert100]", "unchanged - already in place")
        updates = [c for c in self.read_state()["calls"] if c["args"][:2] == ["endpoint", "update"]]
        self.assertEqual(len(updates), 1)

    def test_rollout_preview_by_default_and_unknown_endpoint(self):
        self.run_tool("upload", "--apply")
        rc, out = self.run_tool("rollout", "d1")
        self.assertEqual(rc, 0, out)
        self.assertIn("Rollout plan - environment d1 (preview)", out)
        self.assertIn("preview (use --apply to switch the endpoints)", out)
        self.assertRow(out, "storefront", None, None, "would switch")
        self.assertIn("Use 'rollout d1 --apply' to switch them.", out)
        self.assertNotIn("endpoint update", out)
        self.assertEqual(self.read_state()["endpoints"]["d1"]["storefront"]["ssl"], "cert102")
        self.assertFalse(any(c["args"][:2] == ["endpoint", "update"] for c in self.read_state()["calls"]))
        rc, out = self.run_tool("rollout", "s1", "--apply")
        self.assertEqual(rc, 1)
        self.assertIn("endpoint does not exist", out)

    def _map_storefront_to_sap_managed(self):
        cfg = json.loads(self.config.read_text())
        cfg["environments"]["d1"]["endpoints"]["storefront"] = "sap-managed"
        cfg["environments"]["s1"]["endpoints"] = {"storefront": "sap-managed"}
        self.config.write_text(json.dumps(cfg))

    def test_rollout_sap_managed_switches_to_newest_sap_certificate(self):
        self._map_storefront_to_sap_managed()
        rc, out = self.run_tool("rollout", "d1", "--endpoint", "storefront", "--apply")
        self.assertEqual(rc, 0, out)
        self.assertRow(out, "storefront", "old-but-in-use [cert102]", "sap-managed", "switch")
        self.assertIn("d1-public - 2027-02-05 (Let\u2019s Encrypt) [cert903]", out)
        self.assertEqual(self.read_state()["endpoints"]["d1"]["storefront"]["ssl"], "cert903")

        rc, out = self.run_tool("status", "d1")
        self.assertEqual(rc, 0, out)
        self.assertRow(out, "storefront", None, "sap-managed", "OK - target in place")

    def test_rollout_sap_managed_accepts_any_sap_certificate_of_the_environment(self):
        self._map_storefront_to_sap_managed()
        state = self.read_state()
        state["endpoints"]["d1"]["storefront"]["ssl"] = "cert902"  # older SAP certificate, renewed by SAP
        self.write_state(state)
        rc, out = self.run_tool("rollout", "d1", "--endpoint", "storefront", "--apply")
        self.assertEqual(rc, 0, out)
        self.assertRow(out, "storefront", None, "sap-managed", "unchanged - already in place")
        self.assertFalse(any(c["args"][:2] == ["endpoint", "update"] for c in self.read_state()["calls"]))

    def test_rollout_sap_managed_without_sap_certificate(self):
        self._map_storefront_to_sap_managed()
        rc, out = self.run_tool("rollout", "s1", "--apply")
        self.assertEqual(rc, 1, out)
        self.assertRow(out, "storefront", "-", "sap-managed", "no SAP-managed certificate for 's1' found")

    def test_sap_managed_is_reserved_as_certificate_name(self):
        cfg = json.loads(self.config.read_text())
        cfg["certificates"]["sap-managed"] = {"directory": "new-cert"}
        self.config.write_text(json.dumps(cfg))
        rc, out = self.run_tool("status")
        self.assertEqual(rc, 2)
        self.assertIn("'sap-managed' is a reserved endpoint target", out)

    def test_rollout_unknown_environment(self):
        rc, out = self.run_tool("rollout", "x9")
        self.assertEqual(rc, 2)
        self.assertIn("is not configured", out)

    # -- endpoint objects / domains ---------------------------------------
    def test_configured_domain_must_match_portal(self):
        self.run_tool("upload", "--apply")
        cfg = json.loads(self.config.read_text())
        cfg["environments"]["d1"]["endpoints"]["storefront"] = {"domain": "shop.example.com",
                                                                "certificate": "new-cert"}
        self.config.write_text(json.dumps(cfg))
        rc, out = self.run_tool("rollout", "d1", "--apply")
        self.assertEqual(rc, 1, out)
        self.assertRow(out, "storefront", "-", None, "blocked - domain differs from configuration")
        self.assertIn("the endpoint domain in the portal is 'storefront.example.com', "
                      "the configuration expects 'shop.example.com'", out)
        self.assertEqual(self.read_state()["endpoints"]["d1"]["storefront"]["ssl"], "cert102")
        rc, out = self.run_tool("status", "d1")
        self.assertEqual(rc, 1, out)
        self.assertRow(out, "storefront", None, None, "domain differs from configuration")

    def test_endpoint_object_with_matching_domain_and_unmanaged(self):
        self.run_tool("upload", "--apply")
        cfg = json.loads(self.config.read_text())
        cfg["environments"]["d1"]["endpoints"] = {
            "storefront": {"domain": "Storefront.Example.com", "certificate": "new-cert"},
            "backoffice": {"domain": "backoffice.example.com", "certificate": "unmanaged"},
        }
        self.config.write_text(json.dumps(cfg))
        rc, out = self.run_tool("rollout", "d1", "--apply")
        self.assertEqual(rc, 0, out)
        self.assertRow(out, "storefront", None, None, "switch")
        self.assertRow(out, "backoffice", "-", "unmanaged", "skip - unmanaged")
        self.assertEqual(self.read_state()["endpoints"]["d1"]["backoffice"]["ssl"], "cert100")
        rc, out = self.run_tool("status", "d1")
        self.assertEqual(rc, 0, out)
        self.assertRow(out, "backoffice", "current-cert [cert100]", "unmanaged", "unmanaged")

    def test_endpoint_object_validation(self):
        cfg = json.loads(self.config.read_text())
        cfg["environments"]["d1"]["endpoints"]["storefront"] = {"domain": "x.example.com", "cert": "new-cert"}
        self.config.write_text(json.dumps(cfg))
        rc, out = self.run_tool("status")
        self.assertEqual(rc, 2)
        self.assertIn("unknown field(s) cert (allowed: domain, certificate)", out)

    # -- fetch -----------------------------------------------------------
    def _portal_with_extra_endpoints(self):
        state = self.read_state()
        state["endpoints"]["d1"].update({"api": {"ssl": "cert903"}, "jsapps": {"ssl": "cert100"},
                                         "solr": {"ssl": "cert101", "domain": "https://solr.example.com"}})
        state["endpoints"]["p1"] = {"storefront": {"ssl": "cert902"}}
        state["environment_names"] = {"p1": "Production"}
        self.write_state(state)

    def test_fetch_preview_changes_nothing(self):
        self._portal_with_extra_endpoints()
        before = self.config.read_text()
        rc, out = self.run_tool("fetch")
        self.assertEqual(rc, 0, out)
        self.assertIn("(preview)", out)
        self.assertRow(out, "d1", "storefront", "storefront.example.com", "new-cert", "keep - already configured")
        self.assertRow(out, "d1", "api", "api.example.com", "sap-managed", "would add")
        self.assertRow(out, "d1", "jsapps", "jsapps.example.com", "current-cert", "would add")
        self.assertRow(out, "d1", "solr", "solr.example.com", "unmanaged", "would add")
        self.assertRow(out, "s1", "unknown-endpoint", "-", "new-cert", "configured, but not in portal")
        self.assertRow(out, "s1", "storefront", "storefront.example.com", "unmanaged", "would add")
        self.assertRow(out, "p1", "storefront", None, "sap-managed", "would add")
        self.assertIn("5 endpoint(s) would be added", out)
        self.assertEqual(self.config.read_text(), before)

    def test_fetch_apply_adds_only_missing_endpoints(self):
        self._portal_with_extra_endpoints()
        rc, out = self.run_tool("fetch", "--apply")
        self.assertEqual(rc, 0, out)
        cfg = json.loads(self.config.read_text())
        d1 = cfg["environments"]["d1"]["endpoints"]
        self.assertEqual(d1["storefront"], "new-cert")  # existing entries are kept unchanged
        self.assertEqual(d1["backoffice"], "current-cert")
        self.assertEqual(d1["api"], {"domain": "api.example.com", "certificate": "sap-managed"})
        self.assertEqual(d1["solr"], {"domain": "solr.example.com", "certificate": "unmanaged"})
        self.assertEqual(cfg["environments"]["p1"], {"description": "Production", "endpoints": {
            "storefront": {"domain": "storefront.example.com", "certificate": "sap-managed"}}})
        self.assertEqual(cfg["certificates"], {"new-cert": {}, "current-cert": {}})
        self.assertEqual(cfg["credentials"]["clientId"], "client-id-value")  # credentials are kept
        self.assertEqual(self.config.stat().st_mode & 0o777, 0o600)  # permissions are kept
        # the written configuration is valid and unmanaged endpoints are ignored by rollout
        rc, out = self.run_tool("rollout", "d1")
        self.assertRow(out, "solr", "-", "unmanaged", "skip - unmanaged")
        # second run: nothing left to add
        rc, out = self.run_tool("fetch", "--apply")
        self.assertIn("0 endpoint(s) added", out)

    def test_fetch_single_environment(self):
        self._portal_with_extra_endpoints()
        rc, out = self.run_tool("fetch", "p1", "--apply")
        self.assertEqual(rc, 0, out)
        cfg = json.loads(self.config.read_text())
        self.assertIn("p1", cfg["environments"])
        self.assertNotIn("api", cfg["environments"]["d1"]["endpoints"])
        rc, out = self.run_tool("fetch", "x9")
        self.assertEqual(rc, 2)
        self.assertIn("Environment 'x9' exists neither in the configuration nor in the portal", out)

    # -- status ----------------------------------------------------------
    def test_status_shows_actual_endpoint_certificates(self):
        rc, out = self.run_tool("status")
        self.assertEqual(rc, 1, out)  # problems: target not uploaded, endpoint missing in s1
        self.assertRow(out, "storefront", "old-but-in-use [cert102]", "new-cert", "target not uploaded")
        self.assertRow(out, "backoffice", "current-cert [cert100]", "current-cert [cert100]", "OK - target in place")
        self.assertRow(out, "unknown-endpoint", "-", "new-cert", "endpoint does not exist")
        self.assertRow(out, "storefront", "(no certificate)", "-", "not configured")
        self.assertRow(out, "new-cert", "OK", None, "not uploaded")

    def test_status_after_upload_and_rollout(self):
        self.run_tool("upload", "--apply")
        rc, out = self.run_tool("status", "d1")
        self.assertEqual(rc, 0, out)
        self.assertRow(out, "storefront", "old-but-in-use [cert102]", "~new-cert [cert", "rollout pending")
        self.assertNotIn("s1 (code s1)", out)
        self.run_tool("rollout", "d1", "--apply")
        rc, out = self.run_tool("status", "d1")
        self.assertEqual(rc, 0, out)
        self.assertRow(out, "storefront", "~new-cert [cert", "~new-cert [cert", "OK - target in place")

    def test_status_uses_environment_credentials(self):
        self.set_credentials(("environments", "s1"), clientId="s1-client", clientSecret="s1-secret")
        self.run_tool("status")
        calls = self.read_state()["calls"]
        by_env = {c["args"][3].split("=", 1)[1]: c["config"]["client-id"]
                  for c in calls if c["args"][:2] == ["endpoint", "list"]}
        self.assertEqual(by_env, {"d1": "client-id-value", "s1": "s1-client"})
        self.assertEqual(calls[0]["config"]["client-id"], "client-id-value")  # certificate list

    def test_status_reports_missing_environment_credentials_and_continues(self):
        self.set_credentials(("environments", "s1"), clientSecret="stray")
        rc, out = self.run_tool("status")
        self.assertEqual(rc, 1)
        self.assertIn("environments.s1.credentials defines clientSecret but no clientId", out)
        self.assertRow(out, "backoffice", None, None, "OK - target in place")  # d1 still evaluated

    def test_status_forbidden_environment_shows_hint_without_noise(self):
        state = self.read_state()
        state["forbidden"] = ["s1"]
        self.write_state(state)
        rc, out = self.run_tool("status")
        self.assertEqual(rc, 1)
        self.assertIn("403 FORBIDDEN", out)
        self.assertIn("Hint: the portal denied access", out)
        self.assertNotIn("io.netty", out)
        self.assertRow(out, "backoffice", None, None, "OK - target in place")  # d1 still evaluated

    # -- cleanup ---------------------------------------------------------
    def test_cleanup_preview_and_apply(self):
        rc, out = self.run_tool("cleanup")
        self.assertEqual(rc, 0)
        self.assertIn("1 certificate(s) would be deleted", out)
        self.assertIn("old-cert", self.names())

        rc, out = self.run_tool("cleanup", "--apply")
        self.assertEqual(rc, 0, out)
        # deleted: old-cert; kept: configured, protected (by code and by pattern), in use
        self.assertEqual(self.names(), ["SAP provided", "current-cert",
                                        "d1-public - 2026-11-19 (Let's Encrypt)",
                                        "d1-public - 2027-02-05 (Let\u2019s Encrypt)",
                                        "old-but-in-use", "sap-default"])
        self.assertIn("SAP-managed", out)

    def test_cleanup_include_unused_deletes_unassigned_configured_certificates(self):
        self.run_tool("upload", "--apply")  # new-cert: configured, not assigned to any endpoint
        rc, out = self.run_tool("cleanup", "--include-unused")
        self.assertEqual(rc, 0, out)
        self.assertIn("Cleanup plan - including unused configured certificates (preview)", out)
        self.assertRow(out, "new-cert", None, "configured, unused", "0", None, "would delete")
        self.assertIn("Use 'cleanup --include-unused --apply' to delete them.", out)
        self.assertIn("new-cert", self.names())

        rc, out = self.run_tool("cleanup", "--include-unused", "--apply")
        self.assertEqual(rc, 0, out)
        # deleted: new-cert (configured, unused) and old-cert; kept: in use, protected, SAP-managed
        self.assertEqual(self.names(), ["SAP provided", "current-cert",
                                        "d1-public - 2026-11-19 (Let's Encrypt)",
                                        "d1-public - 2027-02-05 (Let\u2019s Encrypt)",
                                        "old-but-in-use", "sap-default"])

    def test_cleanup_include_unused_keeps_protected_configured_certificates(self):
        cfg = json.loads(self.config.read_text())
        cfg["cleanup"]["protectedCertificates"].append("new-*")
        self.config.write_text(json.dumps(cfg))
        self.run_tool("upload", "--apply")
        rc, out = self.run_tool("cleanup", "--include-unused", "--apply")
        self.assertEqual(rc, 0, out)
        self.assertIn("new-cert", self.names())
        self.assertNotIn("old-cert", self.names())

    def test_cleanup_without_include_unused_keeps_configured_certificates(self):
        self.run_tool("upload", "--apply")
        rc, out = self.run_tool("cleanup", "--apply")
        self.assertEqual(rc, 0, out)
        self.assertRow(out, "new-cert", None, "configured", "0", None, "keep")
        self.assertIn("new-cert", self.names())

    def test_cleanup_after_rollout_removes_replaced_certificate(self):
        self.run_tool("upload", "--apply")
        self.run_tool("rollout", "d1", "--apply")
        rc, out = self.run_tool("cleanup", "--apply")
        self.assertEqual(rc, 0, out)
        self.assertNotIn("old-but-in-use", self.names())
        self.assertNotIn("old-cert", self.names())


if __name__ == "__main__":
    unittest.main()

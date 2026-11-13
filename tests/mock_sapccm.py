"""Minimal stand-in for the sapccm CLI used by the tests.

State is kept in the JSON file named by MOCK_SAPCCM_STATE. Output tables use
the same layout as sapccm's AsciiTable (cell padded to column width + 2).
Every call is appended to state["calls"] together with the credentials found
in the isolated config.properties, so tests can verify the isolation.
"""

import json
import os
import re
import sys
from pathlib import Path


def ascii_table(header, rows):
    widths = [max(len(str(r[i])) for r in [header] + rows) for i in range(len(header))]
    lines = []
    for row in [header] + rows:
        lines.append("".join(str(c).ljust(widths[i] + 2) if i < len(row) - 1 else str(c)
                             for i, c in enumerate(row)))
    return "\n".join(lines) + "\n"


def read_cli_config():
    m = re.search(r"-Duser\.home=(\S+)", os.environ.get("JAVA_OPTS", ""))
    if not m:
        return {}
    path = Path(m.group(1), ".config", "sapccm", "config.properties")
    if not path.is_file():
        return {}
    props = {}
    for line in path.read_text(encoding="latin-1").splitlines():
        key, _, value = line.partition("=")
        props[key] = re.sub(r"\\(.)", r"\1", value)
    props["_path"] = str(path)
    return props


def opts(argv):
    result = {}
    for arg in argv:
        if arg.startswith("--") and "=" in arg:
            k, v = arg[2:].split("=", 1)
            result[k] = v
    return result


def main(argv):
    state_file = Path(os.environ["MOCK_SAPCCM_STATE"])
    state = json.loads(state_file.read_text())
    cfg = read_cli_config()
    state.setdefault("calls", []).append({"args": argv, "config": cfg})
    o = opts(argv)
    cmd = " ".join(a for a in argv[:2])
    rc = 0
    certs = state.setdefault("certificates", [])

    def endpoints_count(code):
        return sum(1 for env in state.get("endpoints", {}).values()
                   for ep in env.values() if ep.get("ssl") == code)

    if not cfg.get("client-id"):
        print("Authentication failed", file=sys.stderr)
        rc = 1
    elif cmd == "certificate list":
        if not certs:
            print("No certificates found for subscription.")
        else:
            print(ascii_table(
                ["CERTIFICATE CODE", "NAME", "ISSUER", "DOMAINS COUNT", "EXPIRATION DATE",
                 "DESCRIPTION", "ENDPOINTS COUNT"],
                [[c["code"], c["name"], "Test CA", 1, "2027-11-11T10:00:00Z", "",
                  endpoints_count(c["code"])] for c in certs]))
    elif cmd == "certificate create":
        for key in ("certificate-path", "certificate-key-path", "ca-certificate-path"):
            if not Path(o[key]).is_file():
                print(f"File {o[key]} not found", file=sys.stderr)
                rc = 1
        if rc == 0:
            # same content validation as the real CLI (CertificateCreateCommand)
            for key in ("certificate-path", "certificate-key-path", "ca-certificate-path"):
                if not re.fullmatch(r"[-A-Za-z0-9/+=\s]+", Path(o[key]).read_text()):
                    print(f"Invalid certificate content in {o[key]}", file=sys.stderr)
                    rc = 11
        if rc == 0:
            code = "cert%03d" % (len(certs) + 1)
            certs.append({"code": code, "name": o["name"],
                          "certificate": Path(o["certificate-path"]).read_text(),
                          "ca": Path(o["ca-certificate-path"]).read_text(),
                          "ca_path": o["ca-certificate-path"]})
            print(f"Certificate {code} created.")
    elif cmd == "certificate delete":
        code = o["certificate-code"]
        if endpoints_count(code):
            print("Certificate is in use", file=sys.stderr)
            rc = 1
        else:
            state["certificates"] = [c for c in certs if c["code"] != code]
            print(f"The certificate {code} was deleted from subscription {o['subscription-code']}.")
    elif cmd == "environment list":
        names = state.get("environment_names", {})
        print(ascii_table(["CODE", "NAME", "TYPE", "STATUS", "DEPLOYMENT STATUS"],
                          [[code, names.get(code, code + " name"), "DEVELOPMENT", "AVAILABLE", "DEPLOYED"]
                           for code in state.get("endpoints", {})]))
    elif cmd == "endpoint list" and o["environment-code"] in state.get("forbidden", []):
        print("Unable to load io.netty.resolver.dns.macos.MacOSDnsServerAddressStreamProvider, fallback "
              "to system defaults.")
        print("Network request failed with status code: 403 FORBIDDEN")
        print("Authorization Failed.")
        rc = 10
    elif cmd == "endpoint list":
        env = state.get("endpoints", {}).get(o["environment-code"])
        if env is None:
            print("Environment not found", file=sys.stderr)
            rc = 1
        else:
            print(ascii_table(["ENDPOINT CODE", "NAME", "WEB PROXY", "SERVICE", "URL"],
                              [[code, code + " name", "default", "jsapps",
                                ep.get("domain", f"{code}.example.com")]
                               for code, ep in env.items()]))
    elif cmd == "endpoint show":
        ep = state["endpoints"][o["environment-code"]][o["code"]]
        print(ascii_table(["PROPERTY", "VALUE"],
                          [["ENDPOINT CODE", o["code"]], ["NAME", o["code"] + " name"],
                           ["SSL CERTIFICATE", ep.get("ssl", "")], ["ACCESS", "ALLOW_ALL"]]))
    elif cmd == "endpoint update":
        state["endpoints"][o["environment-code"]][o["code"]]["ssl"] = o["ssl-certificate"]
        print("Endpoint updated.")
    else:
        print(f"mock: unsupported command {argv}", file=sys.stderr)
        rc = 2

    state_file.write_text(json.dumps(state, indent=2))
    return rc


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

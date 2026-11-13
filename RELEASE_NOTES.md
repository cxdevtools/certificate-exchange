# certtool 0.1.0 – first release

`certtool` automates SSL certificate exchange in **SAP Commerce Cloud (CCv2)**. It drives the official
SAP Commerce Cloud Management CLI (`sapccm`), so there are no click paths in the Cloud Portal and no
direct REST calls. It is installed once and used per project via `cxdev-certificates <command>` (shell script for
macOS/Linux, `cxdev-certificates.bat` for Windows).

## Highlights

- **One command, five sub commands**: `status`, `fetch`, `upload`, `rollout`, `cleanup`.
- **Safe by default**: `fetch`, `upload`, `rollout` and `cleanup` only show a plan. Changes are made
  only with `--apply`.
- **Install once, use per project**: `certtool.json` is read from the current directory. Certificates
  are resolved relative to the configuration file (`certificatesPath`, default `./certificates`).
- **Clear console output**: a context header (subscription, environment, credentials scope, secret
  expiry, CLI and Java version), bordered plan/result tables, a `Details` block for errors and a
  one-line summary.

## Commands

| Command | What it does |
|---|---|
| `status [environment]` | Compares local certificates, certificates in the subscription and the certificate **actually assigned** to every endpoint. Read-only; exit code 1 if problems are found. |
| `fetch [environment] [--apply]` | Reads environments, endpoints and domains from the portal and adds **missing** endpoints to `certtool.json`. Existing entries are never changed. |
| `upload [--certificate NAME] [--apply]` | Uploads configured certificates that are missing in the subscription (idempotent), after local checks. |
| `rollout <environment> [--endpoint CODE] [--apply]` | Switches the endpoints of one environment to their target certificates. Endpoints already in place are left untouched. |
| `cleanup [--include-unused] [--apply]` | Deletes certificates that are no longer needed. `--include-unused` also removes configured certificates that are not assigned to any endpoint. |

Running the tool without arguments prints a structured overview with examples. Invalid parameters
print the help of the affected command.

## Configuration

- Endpoint targets are a configured certificate name, `"sap-managed"` or `"unmanaged"`:
  - `"sap-managed"` selects the SAP-managed Let's Encrypt certificate of the environment, even though
    its name and code change with every renewal.
  - `"unmanaged"` is ignored by `rollout`.
- Endpoints can be written in a short form (`"jsapps": "<certificate>"`) or a long form with the
  expected domain:
  `"jsapps": { "domain": "www.example.com", "certificate": "<certificate>" }`.
- `cleanup.protectedCertificates` holds names or codes (wildcards allowed) that are never deleted.

## Safety checks

- **Local certificate checks** (with `openssl`) before upload:
  - PEM format, unencrypted key, key matches certificate, expiry (warning below 30 days)
  - ASCII-only names
  - **CA chain present.** The portal rejects a leaf without its intermediates. Full-chain files
    (leaf first) are split automatically.
- **Domain checks** before rollout:
  - The certificate must cover the endpoint domain (SAN/CN, wildcards for exactly one label).
  - A configured domain must match the domain shown in the portal.
  - Mismatching endpoints are blocked and never sent to the portal. `certtool` never changes
    endpoint domains.
- **Cleanup never deletes** SAP-managed certificates (built-in protection, independent of the
  configuration), protected certificates or certificates still assigned to endpoints.

## Credentials

- **Where they live**: the technical user is configured in `certtool.json` (`credentials` block, as
  copied from the Cloud Portal "Client Credentials" dialog).
- **Per environment**: a separate user can be set in `environments.<key>.credentials`. Id and secret
  of different users are never mixed.
- **Secret expiry**: `clientExpires` (portal format `DD/MM/YYYY hh:mm:ss AM/PM`) is checked before
  every run. An expired secret aborts the run; you are warned 14 days in advance.
- **Isolation**: credentials are passed to `sapccm` through a private, temporary configuration
  (`0700`/`0600`) that is deleted after the run. The global `~/.config/sapccm/config.properties` is
  never read or modified.
- **Exposure**: secrets never appear in output or on the command line. A warning is shown if
  `certtool.json` is readable by other users.

## Requirements

- Python 3.9+ (standard library only)
- Java 21+ for the SAP CLI. JVM/Netty warnings of the CLI are suppressed.
- OpenSSL (recommended, used for the local checks)
- SAP Commerce Cloud Management CLI. It is **not included** (proprietary SAP software): place the
  `CXCOMMCLI*.ZIP` in `tools/` and it is extracted automatically on the first run.
- A technical user of the subscription

## Getting started

```bash
ln -s /path/to/certtool/bin/cxdev-certificates ~/bin/cxdev-certificates
cd ~/projects/my-project          # contains certtool.json (chmod 600) and certificates/
cxdev-certificates fetch          # preview, then: cxdev-certificates fetch --apply
cxdev-certificates status
```

See the [README](README.md) for the full documentation, including how to create the technical user.

## License

Apache License 2.0 · © cxdevtools

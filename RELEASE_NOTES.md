# certtool 1.0.0

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
- **Console output**: all commands show a loading step and bordered tables. Rollout shows live
  progress and retry status in supported terminals. Use `--verbose` for SAP calls and full update errors.
- **Domain changes in rollout**: certtool can update the endpoint domain and certificate together
  after checking certificate coverage.
- **Retries for environment locks**: each SAP change can make up to 20 attempts, including the first
  call. certtool waits 15 seconds between attempts when SAP reports the lock.

## Commands

| Command | What it does |
|---|---|
| `status [environment]` | Compares local certificates, certificates in the subscription and the certificate **actually assigned** to every endpoint. Read-only; exit code 1 if problems are found. |
| `fetch [environment] [--apply]` | Reads environments, endpoints and domains from the portal and adds **missing** endpoints to `certtool.json`. Existing entries are never changed. |
| `upload [--certificate NAME] [--apply]` | Uploads configured certificates that are missing in the subscription (idempotent), after local checks. |
| `rollout <environment> [--endpoint CODE] [--apply]` | Applies the configured certificates and domain changes for one environment. |
| `cleanup [--include-unused] [--apply]` | Deletes certificates that are no longer needed. `--include-unused` also removes configured certificates that are not assigned to any endpoint. |

Running the tool without arguments prints a structured overview with examples. Invalid parameters
print the help of the affected command.

## Configuration

- Endpoint targets are a configured certificate name, `"sap-managed"` or `"unmanaged"`:
  - `"sap-managed"` selects the SAP-managed Let's Encrypt certificate of the environment, even though
    its name and code change with every renewal.
  - `"unmanaged"` is ignored by `rollout`.
- Endpoints can be written in a short form (`"jsapps": "<certificate>"`) or a long form with the
  desired domain:
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
  - For a domain change, the uploaded certificate must cover the new hostname. For custom
    certificates, the local leaf certificate must also cover it. Missing or unverifiable coverage
    blocks the change.
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

- Java 21+ for certtool and the SAP CLI. JVM/Netty warnings of the CLI are suppressed.
- Gson JSON library, bundled in `lib/` by the release build.
- OpenSSL (recommended, used for the local checks)
- SAP Commerce Cloud Management CLI. It is **not included** (proprietary SAP software): place the
  `CXCOMMCLI*.ZIP` in `tools/` and it is extracted automatically on the first run.
- A technical user of the subscription

## Getting started

Download and extract the ZIP attached to the GitHub release. It includes the application JAR, Gson,
and launchers for macOS/Linux and Windows. Java 21+ must be installed; Python is not required.

```bash
ln -s /path/to/certtool/bin/cxdev-certificates ~/bin/cxdev-certificates
cd ~/projects/my-project          # contains certtool.json (chmod 600) and certificates/
cxdev-certificates fetch          # preview, then: cxdev-certificates fetch --apply
cxdev-certificates status
```

See the [README](README.md) for the full documentation, including how to create the technical user.

## License

Apache License 2.0 · © cxdevtools

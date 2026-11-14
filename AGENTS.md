# AGENTS.md

Guidance for AI agents and developers working on this repository. The functional description
(goal, process, configuration, technical user) lives in the [README.md](README.md) – keep it in sync
when changing behavior.

## Project in brief

- `certtool` exchanges SSL certificates in SAP Commerce Cloud (CCv2): **upload** (upload missing
  certificates), **rollout `<env>`** (switch the endpoints of one environment), **cleanup** (delete
  certificates no longer needed, respecting the protection list; `--include-unused` also removes
  configured certificates without endpoint), **status**, **fetch** (add missing endpoints from the portal to the configuration).
- The only interface to the portal is the SAP CLI `sapccm`. It is proprietary SAP software and is
  **not** part of the repository: users place `CXCOMMCLI*.ZIP` in `tools/`, it is extracted
  automatically to `tools/sapccm/`. If there is no local archive, certtool searches
  `$CXDEVHOME/dependencies/sapccm*/` recursively. No direct REST calls.
- Installed once, used per project: `certtool.json` is read from the **current directory** (or `--config`);
  `certificatesPath` (default `./certificates`) is resolved relative to the config file, `sapccmHome`/
  `sapccmZipDir` relative to the installation (`config.PROJECT_ROOT`). `bin/cxdev-certificates` resolves symlinks
  so it can be linked into the PATH; `bin/cxdev-certificates.bat` is the Windows wrapper (CRLF, see
  `.gitattributes`) – keep both wrappers in sync. Messages shorten paths relative to the current directory
  (`config.display_path`).
- Java ≥ 21. Gson is the only runtime dependency; Gradle copies it to `lib/` for releases.
- Open source under the Apache License 2.0 (`LICENSE`), copyright cxdevtools.

## Commands

```bash
gradle test                               # JUnit tests
gradle releaseZip                         # release ZIP with runtime libraries
bin/cxdev-certificates status -v           # in a project directory with certtool.json (real portal)
```

## Architecture

| File | Responsibility |
|---|---|
| `src/main/java/me/cxdev/certtool/CertTool.java` | CLI, config, commands, sapccm integration, output and PEM checks |
| `test/java/me/cxdev/certtool/CertToolTest.java` | JUnit tests |
| `build.gradle.kts` | Gson/JUnit dependencies and release ZIP packaging |

## Key facts about the sapccm CLI (from analysing the jar, version 20261022)

- Configuration file: `${user.home}/.config/sapccm/config.properties` or
  `%LOCALAPPDATA%\sapccm\config.properties`. Keys: `client-id`, `client-secret`, `token-url`,
  `subscription-code`, `cpapi-server`. No support for environment variables.
- Output only as ASCII tables (no JSON). Columns are padded to max width + 2 spaces.
  `certificate list`: `CERTIFICATE CODE, NAME, ISSUER, DOMAINS COUNT, EXPIRATION DATE, DESCRIPTION,
  ENDPOINTS COUNT`. `endpoint show`: `PROPERTY / VALUE` table, relevant row `SSL CERTIFICATE`. `endpoint list` shows the
  endpoint domain in column `URL`. The portal rejects certificates that do not cover the endpoint domain;
  `commands.domain_mismatch` checks this locally. Never change endpoint domains (`--domain-name`).
- `--help` works per sub command (`sapccm certificate create --help`). In zsh, do not pass command
  strings as a single variable (no word splitting).
- The CLI requires Java ≥ 21 (class files fail on 17). Netty noise is suppressed at the source via
  JVM options (`-Dlogging.level.io.netty=OFF`, `--enable-native-access=ALL-UNNAMED` on 21+,
  `--sun-misc-unsafe-memory-access=allow` only on 23+ – it aborts the JVM on 21). Remaining noise is
  filtered from stdout and stderr in `sapccm.py`. sapccm prints errors and the files it reads on stdout.
- `certificate create` requires `--ca-certificate-path`. The portal verifies the certification path and
  rejects a leaf without intermediates ("Certification path could not be verified"); `pem.check_certificate`
  therefore blocks non-self-signed certificates without chain, `pem.upload_parts` splits full-chain files.
- The portal shows the secret expiration date as `DD/MM/YYYY hh:mm:ss AM/PM`
  (`11/05/2027 10:51:04 AM` = 11 May 2027).

## Security rules (mandatory)

- Credentials live **only** in the local configuration `certtool.json` (git-ignored, like the
  private keys): `credentials` (subscription wide) and optionally `environments.<key>.credentials`, fields
  `tokenEndpoint`, `clientId`, `clientSecret` (required), `clientResource` (unused), `clientExpires`
  (checked before execution, expired → abort). No environment variables, no credential/.env files.
  Never print secret values, never put them on command lines, logs or tests (tests use dummy values),
  and never read or print the user's `certtool.json` contents in a conversation.
- Lookup (`sapccm.Credentials.from_config`): `rollout` (and `status`/`fetch` per environment) use the
  environment block if it defines `clientId`, else the subscription block. `clientSecret`/`clientExpires`
  are only read from the selected block (never mix id and secret of different users), `tokenEndpoint`
  falls back. `certtool` warns if the configuration is accessible by other users; `fetch` keeps the file
  mode when it rewrites the file. Keep these rules when changing the code.
- **Do not** use `sapccm config set`, and neither read nor modify the user's global
  `~/.config/sapccm/config.properties`.
- Never commit or print private keys (`certificates/**/private-key.pem`, `*.key`).
- Never commit the SAP CLI (`tools/*.zip`, `tools/sapccm/`) – it is proprietary SAP software.
- Test against the real portal read-only (`status`, or `upload`/`rollout`/`cleanup` without `--apply`)
  unless
  the user explicitly asks for a change.
- `cleanup` must never delete certificates that are protected, SAP-managed or assigned to endpoints.
  Configured certificates are only deleted with `--include-unused` (and only if assigned to no endpoint).
- SAP-managed certificates (`<env>-public - <YYYY-MM-DD> (Let's Encrypt)`) are protected in code
  (`config.is_sap_managed`, name contains "Let's Encrypt"). Do not remove this protection or make it
  depend on the configuration.
- Endpoint entries: short form `"<code>": "<target>"` or long form `{"domain", "certificate"}`; targets are a
  configured certificate, `"sap-managed"` or `"unmanaged"` (`config.RESERVED_TARGETS`, ignored by rollout).
  A configured `domain` must equal the portal domain (`commands.domain_drift`). `fetch` only adds missing
  endpoints/environments and must never change existing entries.
- The endpoint target `"sap-managed"` (`config.SAP_MANAGED_TARGET`) selects the SAP-managed certificate of
  the environment (`commands.resolve_target`): rollout picks the newest, any SAP-managed certificate of
  the environment counts as in place. Never reference SAP-managed certificates by name or code.

## Conventions

- Everything is in English: documentation, code, identifiers, comments and user-facing CLI output
  (tests assert on output strings – update them together).
- Output structure: context header (`__main__.print_context`) → plan/result tables via
  Java CLI context → plan/result tables → executed sapccm calls → `Details` block for errors → one-line summary. Never print
  secret values; long multi-line errors go to `Details`, not into table cells. Tests assert table rows via
  `assertRow`.
- `upload`, `rollout` and `cleanup` only print their plan without `--apply` and must not run any
  changing sapccm call then. Run changing calls via `SapCcm.run(..., mutating=True)` (always echoed).
- Cover new features with tests under `test/java`.
- Open functional points are listed in the README section "Open points" – update it once clarified.

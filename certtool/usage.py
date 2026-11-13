"""Help texts: the command overview shown without arguments and the examples of each command."""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Tuple

from . import __version__
from .output import heading, style


@dataclass
class CommandHelp:
    name: str
    synopsis: str
    summary: str
    details: List[str]
    examples: List[Tuple[str, str]]  # (arguments, comment)


COMMANDS = [
    CommandHelp(
        "status", "[environment]",
        "Compare local, uploaded and actually assigned certificates",
        ["Checks the local certificate files, lists all certificates of the subscription and shows,",
         "per environment, the certificate actually assigned to every endpoint next to the configured",
         "target. Read-only. Exit code 1 if problems were found."],
        [("status", "all configured environments"),
         ("status d1", "only environment d1")],
    ),
    CommandHelp(
        "upload", "[--certificate NAME] [--apply]",
        "Upload configured certificates that are missing in the subscription",
        ["Runs the local checks (PEM files, key matches, expiry, CA chain) and uploads every configured",
         "certificate whose name does not exist in the subscription yet (idempotent).",
         "Without --apply only the plan is shown."],
        [("upload", "preview incl. local checks"),
         ("upload --apply", "upload all missing certificates"),
         ("upload --certificate www-example-com-2026 --apply", "upload only this certificate")],
    ),
    CommandHelp(
        "rollout", "<environment> [--endpoint CODE] [--apply]",
        "Assign the configured certificates to the endpoints of one environment",
        ["Switches every configured endpoint of the environment to its target certificate.",
         "Endpoints that already use it are left untouched. The certificates must be uploaded first.",
         "Without --apply only the plan is shown."],
        [("rollout d1", "preview: which endpoints would be switched"),
         ("rollout d1 --apply", "switch environment d1"),
         ("rollout d1 --endpoint api --apply", "switch only the endpoint 'api'")],
    ),
    CommandHelp(
        "cleanup", "[--include-unused] [--apply]",
        "Delete certificates that are no longer needed",
        ["Deletes certificates that are neither configured nor assigned to an endpoint.",
         "--include-unused also deletes configured certificates without endpoint.",
         "SAP-managed and protected certificates are never deleted. Without --apply only the plan is shown."],
        [("cleanup", "preview"),
         ("cleanup --apply", "delete"),
         ("cleanup --include-unused", "preview incl. configured certificates without endpoint")],
    ),
]

COMMANDS.insert(1, CommandHelp(
    "fetch", "[environment] [--apply]",
    "Add endpoints of the portal that are missing in the configuration",
    ["Reads the environments and endpoints of the subscription and adds missing endpoints with their",
     "domain to 'environments' in the configuration. Existing entries are never changed. The certificate",
     "is set to the configured certificate in use, 'sap-managed' or 'unmanaged' (ignored by rollout).",
     "Without --apply only the plan is shown."],
    [("fetch", "preview: which endpoints would be added"),
     ("fetch --apply", "add missing endpoints of all environments"),
     ("fetch d1 --apply", "only environment d1")],
))

GLOBAL_OPTIONS = [
    ("-c, --config FILE", "Configuration file (default: ./certtool.json)"),
    ("-v, --verbose", "Show every sapccm call and its output"),
    ("-h, --help", "Help for a command, e.g. 'upload --help'"),
    ("--version", "Show the version"),
]

WORKFLOW = [
    "Once: fetch  ->  fetch --apply  (take over environments, endpoints and domains from the portal)",
    "Add the new certificate to certificates/ and certtool.json",
    "upload  ->  upload --apply",
    "rollout d1  ->  rollout d1 --apply  ->  verify  ->  next environment",
    "Remove the old certificate from the configuration  ->  cleanup  ->  cleanup --apply",
]


def command_epilog(name: str, prog: str) -> str:
    """Examples block for ``<command> --help``."""
    cmd = next(c for c in COMMANDS if c.name == name)
    width = max(len(f"{prog} {args}") for args, _ in cmd.examples)
    lines = ["examples:"] + [f"  {f'{prog} {args}'.ljust(width)}  # {comment}" for args, comment in cmd.examples]
    return "\n".join(lines)


def print_overview(prog: str) -> None:
    """Structured help shown when no command is given (and for --help)."""
    print(style(f"SAP Commerce Cloud Certificate Exchange · certtool {__version__}", "bold+cyan"))
    print("Uploads, rolls out and cleans up SSL certificates in SAP Commerce Cloud using the sapccm CLI.")

    heading("Usage")
    print(f"  {prog} <command> [options]")
    print("  Run it in the project directory: certtool.json and certificates/ are read from there.")

    heading("Commands")
    for cmd in COMMANDS:
        print()
        print(f"  {style(cmd.name, 'bold+cyan')} {cmd.synopsis}")
        print(f"      {cmd.summary}.")
        for line in cmd.details:
            print(style(f"      {line}", "dim"))
        width = max(len(f"{prog} {args}") for args, _ in cmd.examples)
        print("      Examples:")
        for args, comment in cmd.examples:
            print(f"        {f'{prog} {args}'.ljust(width)}  {style('# ' + comment, 'dim')}")

    heading("Typical certificate exchange")
    for n, step in enumerate(WORKFLOW, 1):
        print(f"  {n}. {step}")

    heading("Global options")
    width = max(len(o) for o, _ in GLOBAL_OPTIONS)
    for option, text in GLOBAL_OPTIONS:
        print(f"  {option.ljust(width)}  {text}")

    heading("Credentials")
    print("  Taken from the configuration: \"credentials\" (tokenEndpoint, clientId, clientSecret,")
    print("  clientExpires), optionally per environment in environments.<key>.credentials.")
    print("  Keep certtool.json private (chmod 600). Details: README.md")

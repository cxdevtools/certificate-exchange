"""Command line entry point: ``python3 -m certtool <command> [...]``."""

from __future__ import annotations

import argparse
import contextlib
import os
import platform
import sys
from datetime import datetime
from contextlib import nullcontext
from typing import ContextManager, List, Optional

from . import __version__
from .commands import cmd_cleanup, cmd_fetch, cmd_rollout, cmd_status, cmd_upload
from .config import PROJECT_ROOT, ConfigError, EnvironmentConfig, load_config
from .output import key_values, style
from .usage import COMMANDS, command_epilog, print_overview
from .sapccm import (SAPCCM_OVERRIDE_VAR, Credentials, JavaInfo, SapCcm, SapCcmError, check_java, detect_java,
                     locate_sapccm, sapccm_description)


class _CommandParser(argparse.ArgumentParser):
    """Sub command parser: on a usage error, print the full help of the command, then the error."""

    def error(self, message: str):  # type: ignore[override]
        self.print_help(sys.stderr)
        self.exit(2, f"\n{self.prog}: error: {message}\n")


class _MainParser(argparse.ArgumentParser):
    """Top-level parser: on a usage error (e.g. unknown command), print the command overview."""

    def error(self, message: str):  # type: ignore[override]
        with contextlib.redirect_stdout(sys.stderr):
            print_overview(self.prog)
        self.exit(2, f"\n{self.prog}: error: {message}\n")


def build_parser() -> argparse.ArgumentParser:
    # Global options are accepted before and after the sub command
    # (bin/certificates puts the sub command first).
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("-c", "--config", default=argparse.SUPPRESS,
                        help="Path to the configuration (default: config/certtool.json)")
    common.add_argument("-v", "--verbose", action="store_true", default=argparse.SUPPRESS,
                        help="Show sapccm calls and their output")

    parser = _MainParser(
        prog=os.environ.get("CERTTOOL_PROG", "certtool"),
        description="Certificate exchange for SAP Commerce Cloud using the sapccm CLI.",
        parents=[common],
    )
    parser.add_argument("--version", action="version", version=f"certtool {__version__}")

    sub = parser.add_subparsers(dest="command", metavar="COMMAND", parser_class=_CommandParser)
    sub.required = True

    summaries = {c.name: c for c in COMMANDS}

    def add(name: str, help_text: str) -> argparse.ArgumentParser:
        cmd = summaries[name]
        return sub.add_parser(name, help=help_text, parents=[common],
                              description=cmd.summary + ".\n\n" + "\n".join(cmd.details),
                              epilog=command_epilog(name, parser.prog),
                              formatter_class=argparse.RawDescriptionHelpFormatter)

    p_upload = add("upload", "Upload missing certificates to the subscription")
    p_upload.add_argument("--certificate", action="append", metavar="NAME",
                          help="Only this certificate (can be repeated)")
    p_upload.add_argument("--apply", action="store_true",
                          help="Actually upload (without: preview only)")

    p_rollout = add("rollout", "Roll out certificates to the endpoints of an environment")
    p_rollout.add_argument("environment", help="Environment key or code from the configuration")
    p_rollout.add_argument("--endpoint", action="append", metavar="CODE",
                           help="Only this endpoint (can be repeated)")
    p_rollout.add_argument("--apply", action="store_true",
                           help="Actually switch the endpoints (without: preview only)")

    p_cleanup = add("cleanup", "Remove certificates that are no longer needed")
    p_cleanup.add_argument("--apply", action="store_true",
                           help="Actually delete (without: preview only)")
    p_cleanup.add_argument("--include-unused", action="store_true",
                           help="Also delete configured certificates that are not assigned to any endpoint "
                                "(SAP-managed and protected certificates are still kept)")

    p_fetch = add("fetch", "Add endpoints of the portal that are missing in the configuration")
    p_fetch.add_argument("environment", nargs="?",
                         help="Only this environment (key or code); default: all environments of the subscription")
    p_fetch.add_argument("--apply", action="store_true",
                         help="Actually write the configuration (without: preview only)")

    p_status = add("status", "Compare local, uploaded and actually assigned certificates")
    p_status.add_argument("environment", nargs="?",
                          help="Only this environment (key or code); default: all configured environments")
    return parser


_APPLY_VERBS = {"upload": ("upload", "certificates will be uploaded"),
                "rollout": ("switch the endpoints", "endpoints will be switched"),
                "cleanup": ("delete", "certificates will be deleted"),
                "fetch": ("write the configuration", "the configuration will be updated")}


def _mode(args: argparse.Namespace) -> str:
    if args.command not in _APPLY_VERBS:
        return "read-only"
    preview, apply = _APPLY_VERBS[args.command]
    return style(f"apply - {apply}", "yellow") if args.apply else f"preview (use --apply to {preview})"


def _warn_if_readable_by_others(path) -> None:
    """The configuration contains the client secret: it should only be readable by its owner."""
    if os.name == "nt":
        return
    try:
        mode = path.stat().st_mode
    except OSError:
        return
    if mode & 0o077:
        print(f"WARNING: {path.name} contains credentials but is accessible by other users "
              f"(mode {mode & 0o777:o}). Restrict it with: chmod 600 {path}", file=sys.stderr)


def _expiry(credentials: Credentials) -> str:
    if not credentials.expires:
        return "secret expiry not set"
    days = (credentials.expires - datetime.now()).days
    return f"secret expires {credentials.expires:%Y-%m-%d} ({days} days)"


def print_context(args: argparse.Namespace, cfg, env_cfg: Optional[EnvironmentConfig],
                  credentials: Credentials, java: Optional[JavaInfo]) -> None:
    """Header with the context of the run (never prints secret values)."""
    print(style(f"SAP Commerce Cloud Certificate Exchange · certtool {__version__}", "bold+cyan"))
    if env_cfg:
        environment = f"{env_cfg.code}" + (f" ({env_cfg.description})" if env_cfg.description else "")
    elif args.command == "fetch":
        environment = getattr(args, "environment", None) or "all of the subscription"
    elif args.command == "status":
        environment = f"all configured ({', '.join(e.code for e in cfg.environments.values()) or '-'})"
    else:
        environment = "- (subscription wide)"
    try:
        config_path = str(cfg.path.relative_to(PROJECT_ROOT))
    except ValueError:  # configuration outside the project
        config_path = str(cfg.path)
    key_values([
        ("Command", args.command),
        ("Mode", _mode(args)),
        ("Configuration", config_path),
        ("Subscription", cfg.subscription_code),
        ("Environment", environment),
        ("Credentials", f"{credentials.source} · {_expiry(credentials)}"),
        ("sapccm CLI", sapccm_description(cfg.sapccm_home)),
        ("Java", java.describe() if java else f"- (sapccm replaced via {SAPCCM_OVERRIDE_VAR})"),
        ("Runtime", f"Python {platform.python_version()} · {platform.system()} {platform.machine()}"),
        ("Started", datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
    ])


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    argv = sys.argv[1:] if argv is None else argv
    if not argv or argv[0] in ("-h", "--help", "help"):
        # no command (or top-level help): structured overview of all commands with examples
        print_overview(parser.prog)
        return 0
    # Unknown options are reported by the sub command parser, so that its help is shown.
    args, unknown = parser.parse_known_args(argv)
    if unknown:
        sub = next(a for a in parser._actions if isinstance(a, argparse._SubParsersAction))
        sub.choices[args.command].error(f"unrecognized arguments: {' '.join(unknown)}")
    try:
        cfg = load_config(getattr(args, "config", None))
        env_name = getattr(args, "environment", None)
        # fetch may name environments that are not configured yet
        env_cfg = cfg.environment(env_name) if env_name and args.command != "fetch" else None
        # rollout uses the environment scope; all other commands the subscription scope
        credentials = Credentials.from_config(cfg, env_cfg if env_cfg and args.command == "rollout" else None)
        _warn_if_readable_by_others(cfg.path)
        command = locate_sapccm(cfg.sapccm_home, cfg.sapccm_zip_dir)
        java = None if os.environ.get(SAPCCM_OVERRIDE_VAR) else detect_java()
        if java:
            check_java(java)
        jvm_options = java.quiet_options() if java else []
        verbose = getattr(args, "verbose", False)
        print_context(args, cfg, env_cfg, credentials, java)
        with SapCcm(command, credentials, cfg.subscription_code, verbose=verbose,
                    jvm_options=jvm_options) as ccm:

            def env_session(env: EnvironmentConfig) -> ContextManager[SapCcm]:
                """Session with the credentials of one environment (reuses ccm if identical)."""
                env_credentials = Credentials.from_config(cfg, env)
                if env_credentials.client_id == credentials.client_id:
                    return nullcontext(ccm)
                return SapCcm(command, env_credentials, cfg.subscription_code, verbose=verbose,
                              jvm_options=jvm_options)

            if args.command == "upload":
                return cmd_upload(cfg, ccm, args.certificate, args.apply)
            if args.command == "rollout":
                return cmd_rollout(cfg, ccm, env_cfg, args.endpoint, args.apply)
            if args.command == "cleanup":
                return cmd_cleanup(cfg, ccm, args.apply, args.include_unused)
            if args.command == "status":
                return cmd_status(cfg, ccm, env_session, env_cfg)
            if args.command == "fetch":
                return cmd_fetch(cfg, ccm, env_session, env_name, args.apply)
    except ConfigError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    except SapCcmError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("Aborted.", file=sys.stderr)
        return 130
    return 2


if __name__ == "__main__":
    sys.exit(main())

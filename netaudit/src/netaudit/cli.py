"""Command line entry point: ``netaudit analyze|discover|known-hosts|credentials-import|lab``."""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import UTC
from pathlib import Path

from . import __version__

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]


def cmd_analyze(args: argparse.Namespace) -> int:
    from .analysis import analyze
    from .parsers import load_devices
    from .report import split_raw, write_reports

    run_dir = Path(args.run_dir)
    raw_dir = run_dir / "raw"
    if not raw_dir.is_dir():
        print(f"error: {raw_dir} does not exist (expected <host>.json files from the audit playbook)", file=sys.stderr)
        return 2
    devices = load_devices(raw_dir)
    if not devices:
        print(f"error: no collected data in {raw_dir}", file=sys.stderr)
        return 2
    if not args.no_split:
        split_raw(raw_dir)
    previous_dir = _previous_run(run_dir, args.previous)
    previous = load_devices(previous_dir / "raw") if previous_dir else None
    result = analyze(devices, previous)
    if previous_dir:
        print(f"Compared topology-change counters with {previous_dir.name}")
    paths = write_reports(result, run_dir, title=args.title)
    print_summary(result, paths["html"])
    if args.fail_on:
        limit = SEVERITY_ORDER.index(args.fail_on)
        if any(SEVERITY_ORDER.index(f.severity) <= limit for f in result.findings):
            return 3
    return 0


def _previous_run(run_dir: Path, choice: str | None) -> Path | None:
    """The run to compare counters with: --previous, or the newest older sibling run."""
    if choice:
        if choice.lower() == "none":
            return None
        path = Path(choice)
        return path if (path / "raw").is_dir() else None
    here = run_dir.resolve()
    candidates = [
        p
        for p in here.parent.iterdir()
        if p.is_dir() and not p.is_symlink() and p.name < here.name and any((p / "raw").glob("*.json"))
    ]
    return max(candidates, key=lambda p: p.name) if candidates else None


def print_summary(result, report_path: Path) -> None:
    counts = result.counts()
    devices = result.devices
    unreachable = [h for h, d in devices.items() if not d.reachable]
    print(
        f"Audited {len(devices)} switch(es)"
        + (f", {len(unreachable)} unreachable: {', '.join(unreachable)}" if unreachable else "")
    )
    print("Findings: " + ", ".join(f"{counts[s]} {s}" for s in SEVERITY_ORDER))
    for finding in [f for f in result.findings if f.severity in ("critical", "high")][:12]:
        where = finding.host or f"site {finding.site}"
        flag = " [plan]" if finding.planned else ""
        print(f"  - {finding.severity.upper():8} {where}: {finding.title}{flag}")
    plan = result.plan
    if plan.apply_order:
        lines = sum(len(c.lines) for h in plan.apply_order for c in plan.hosts[h].changes)
        print(
            f"Plan: {len(plan.apply_order)} switch(es), {lines} config line(s); order: {', '.join(plan.apply_order[:10])}"
            + (" ..." if len(plan.apply_order) > 10 else "")
        )
    else:
        print("Plan: no changes needed")
    for warning in plan.warnings:
        print(f"  ! {warning}")
    print(f"Report: {report_path}")


def cmd_discover(args: argparse.Namespace) -> int:
    from dataclasses import replace

    from .credentials import CredentialsError, default_login, load_credentials
    from .discover import crawl, write_inventory

    login = default_login()
    if args.username:
        login = replace(login, username=args.username)
    try:
        credentials = load_credentials(args.credentials)
    except CredentialsError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if not (login.username and login.password) and not credentials:
        print("error: set NET_USERNAME and NET_PASSWORD (e.g. in .env)", file=sys.stderr)
        return 2
    if credentials:
        print(f"Using the logins in {args.credentials} for the switches it lists", file=sys.stderr)
    result = crawl(
        seeds=args.seed,
        login=login,
        credentials=credentials,
        site=args.site,
        max_hosts=args.max_hosts,
        workers=args.workers,
        exclude_platforms=args.exclude_platform,
        port=args.port,
    )
    text = write_inventory(result, site=args.site)
    if args.out:
        out = Path(args.out)
        if out.exists() and not args.force:
            print(f"error: {out} exists (use --force to overwrite)", file=sys.stderr)
            return 2
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(text, encoding="utf-8")
        print(f"Wrote {out}: {len(result.switches)} switch(es), {len(result.failures)} failure(s)")
    else:
        print(text)
    return 0 if result.switches else 1


def cmd_known_hosts(args: argparse.Namespace) -> int:
    from .hostkeys import DEFAULT_FILE, parse_target, update_known_hosts

    targets = [parse_target(t) for t in args.target]
    results = update_known_hosts(args.file or DEFAULT_FILE, targets, timeout=args.timeout)
    for r in results:
        print(f"{r.status:8} {r.target:28} {r.key_type:20} {r.fingerprint}{'  ' + r.detail if r.detail else ''}")
    return 3 if any(r.status == "changed" for r in results) else 0


def cmd_credentials_import(args: argparse.Namespace) -> int:
    from .credentials import CredentialsError, merge_into, read_csv

    try:
        entries = read_csv(args.csv)
        added, updated = merge_into(args.file, entries)
    except (CredentialsError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(f"{args.file}: {added} added, {updated} updated ({len(entries)} rows read).")
    print(f"Delete {args.csv} now - it holds the passwords in plain text.")
    return 0


def cmd_lab_generate(args: argparse.Namespace) -> int:
    from datetime import datetime

    from .lab.sim import load_lab
    from .parsers import AUDIT_COMMANDS
    from .sanitize import remove_secrets

    lab = load_lab(args.topology)
    raw_dir = Path(args.out) / "raw"
    raw_dir.mkdir(parents=True, exist_ok=True)
    roles = dict(r.split("=", 1) for r in args.role)
    for name, sw in lab.switches.items():
        outputs, errors = {}, {}
        for command in AUDIT_COMMANDS:
            output = lab.run(name, command)
            if output is None:
                errors[command] = "% Invalid input detected at '^' marker."
            else:
                outputs[command] = remove_secrets(output)
        payload = {
            "host": name,
            "collected_at": datetime.now(UTC).isoformat(timespec="seconds"),
            "intent": {"site": lab.site, "stp_role": roles.get(name, "access"), "ansible_host": sw.mgmt_ip},
            "outputs": outputs,
            "errors": errors,
        }
        (raw_dir / f"{name}.json").write_text(json.dumps(payload, indent=1), encoding="utf-8")
    print(f"Wrote simulated outputs for {len(lab.switches)} switches to {raw_dir}")
    return 0


def cmd_lab_serve(args: argparse.Namespace) -> int:
    from .lab.server import serve

    key_file = (
        args.host_key or os.environ.get("LAB_HOST_KEY") or str(Path(args.topology).resolve().parent / ".lab_host_key")
    )
    return serve(args.topology, listen=args.listen, base_port=args.base_port, host_key_file=key_file)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="netaudit", description="Spanning-tree audit and remediation planning for Cisco switches"
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("analyze", help="analyse a run directory written by the audit playbook")
    p.add_argument("run_dir")
    p.add_argument("--title")
    p.add_argument("--no-split", action="store_true", help="do not write raw/<host>/<command>.txt files")
    p.add_argument("--fail-on", choices=SEVERITY_ORDER, help="exit 3 if a finding of this severity or worse exists")
    p.add_argument(
        "--previous",
        help="run directory to compare topology-change counters with "
        "(default: the newest older run next to RUN_DIR; 'none' disables)",
    )
    p.set_defaults(func=cmd_analyze)

    p = sub.add_parser("discover", help="crawl CDP from seed switches and write an Ansible inventory")
    p.add_argument("--seed", action="append", required=True, help="IP/hostname of a switch to start from (repeatable)")
    p.add_argument("--site", required=True, help="site/group name for the inventory")
    p.add_argument("--out", help="inventory file to write (default: print)")
    p.add_argument("--force", action="store_true")
    p.add_argument("--username", help="default: $NET_USERNAME")
    p.add_argument(
        "--credentials",
        help="credentials.yml with per-switch / per-site logins (keys: switch name, address or site)",
    )
    p.add_argument("--port", type=int, default=22)
    p.add_argument("--max-hosts", type=int, default=500)
    p.add_argument("--workers", type=int, default=8)
    p.add_argument(
        "--exclude-platform",
        action="append",
        default=[],
        help="regex of CDP platforms to skip (APs and phones are skipped already)",
    )
    p.set_defaults(func=cmd_discover)

    p = sub.add_parser("known-hosts", help="record switches' SSH host keys (trust on first use), report changes")
    p.add_argument("target", nargs="+", help="host or host:port")
    p.add_argument("--file", help="known_hosts file (default: ~/.ssh/known_hosts)")
    p.add_argument("--timeout", type=float, default=10.0)
    p.set_defaults(func=cmd_known_hosts)

    p = sub.add_parser("credentials-import", help="add logins from a CSV export to credentials.yml")
    p.add_argument("csv", help="CSV with a header row: switch (or name/host/ip/site), username, password, enable")
    p.add_argument("--file", required=True, help="credentials.yml to create or update")
    p.set_defaults(func=cmd_credentials_import)

    lab = sub.add_parser("lab", help="simulated switches for testing").add_subparsers(dest="lab_command", required=True)
    p = lab.add_parser("generate", help="write simulated audit outputs (no SSH needed)")
    p.add_argument("--topology", default="lab/topology.yml")
    p.add_argument("--out", required=True)
    p.add_argument("--role", action="append", default=["core-01=root_primary", "core-02=root_secondary"])
    p.set_defaults(func=cmd_lab_generate)
    p = lab.add_parser("serve", help="run the simulated switches as SSH servers")
    p.add_argument("--topology", default="lab/topology.yml")
    p.add_argument("--listen", default="0.0.0.0")
    p.add_argument("--base-port", type=int)
    p.add_argument("--host-key", help="SSH host key file, created if missing (default: <topology dir>/.lab_host_key)")
    p.set_defaults(func=cmd_lab_serve)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())

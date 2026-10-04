"""Write the audit results as HTML, Markdown and JSON."""

from __future__ import annotations

import json
import re
from collections import Counter, defaultdict
from dataclasses import asdict
from html import escape
from pathlib import Path
from typing import Any

from jinja2 import Environment, PackageLoader, select_autoescape
from markupsafe import Markup

from ..analysis import AuditResult
from ..analysis.findings import SEVERITIES
from ..analysis.topology import VlanView
from ..sanitize import remove_secrets
from ..util import compress_vlans, format_duration, short_interface, slugify
from . import diagram


def _env() -> Environment:
    env = Environment(
        loader=PackageLoader("netaudit", "report/templates"),
        autoescape=select_autoescape(["html", "j2"]),
        trim_blocks=True,
        lstrip_blocks=True,
    )
    env.filters["short"] = short_interface
    env.filters["duration"] = format_duration
    env.filters["vlans"] = lambda v: compress_vlans([x for x in v if x is not None]) if v else "-"
    env.filters["code"] = _code_spans
    return env


def _code_spans(text: object) -> Markup:
    """Escape text and turn `backtick` spans into <code> elements."""
    return Markup(re.sub(r"`([^`]+)`", r"<code>\1</code>", escape(str(text))))


def _priority_base(priority: int | None, vlan: int | None) -> int | None:
    if priority is None:
        return None
    base = priority - (vlan or 0)
    return base if base >= 0 and base % 4096 == 0 else priority


def _views_by_site(result: AuditResult) -> dict[str, list[VlanView]]:
    by_site: dict[str, list[VlanView]] = defaultdict(list)
    for (site, _), view in result.views.items():
        by_site[site].append(view)
    for views in by_site.values():
        views.sort(key=lambda v: (v.vlan is None, v.vlan or 0, v.instance))
    return dict(sorted(by_site.items()))


def _root_rows(result: AuditResult) -> list[dict[str, Any]]:
    rows = []
    for site, views in _views_by_site(result).items():
        groups: dict[tuple, list[VlanView]] = defaultdict(list)
        for view in views:
            label = view.root_host or (f"unknown {view.root_mac}" if view.root_mac else "?")
            key = (
                label,
                _priority_base(view.root_priority, view.vlan),
                view.expected_root,
                len(view.roots_seen) > 1,
            )
            groups[key].append(view)
        for (label, base, expected, split), vs in groups.items():
            ok = expected is None or label == expected
            rows.append(
                {
                    "site": site,
                    "vlans": compress_vlans([v.vlan for v in vs if v.vlan is not None])
                    or ", ".join(v.instance for v in vs),
                    "root": label,
                    "priority": base,
                    "default_priority": base == 32768,
                    "expected": expected,
                    "status": "split" if split else ("ok" if ok and expected else ("wrong" if not ok else "undefined")),
                    "switches": max(len(v.switches) for v in vs),
                }
            )
    return rows


def _diagrams(result: AuditResult, limit: int = 6) -> list[dict[str, Any]]:
    out = []
    for site, views in _views_by_site(result).items():
        groups: dict[frozenset, list[VlanView]] = defaultdict(list)
        for view in views:
            signature = frozenset((h, n.parent) for h, n in view.tree.items()) | frozenset(
                (h, p) for h, p, _, _ in view.blocked_links
            )
            groups[signature].append(view)
        ordered = sorted(groups.values(), key=lambda vs: (-max(len(v.switches) for v in vs), vs[0].vlan or 0))
        for vs in ordered[:limit]:
            view = vs[0]
            vlans = compress_vlans([v.vlan for v in vs if v.vlan is not None]) or view.instance
            out.append(
                {
                    "site": site,
                    "vlans": vlans,
                    "root": view.root_host or view.root_mac,
                    "expected": view.expected_root,
                    "svg": diagram.svg(result.topology, view),
                    "mermaid": diagram.mermaid(view),
                    "blocked": len({(h, p) for h, p, _, _ in view.blocked_links}),
                    "switches": len(view.switches),
                }
            )
        if len(ordered) > limit:
            out[-1]["more"] = len(ordered) - limit
    return out


def _tc_rows(result: AuditResult) -> list[dict[str, Any]]:
    from ..analysis.checks import tc_rates

    rows = []
    for trace in result.traces:
        view = result.views[(trace.site, trace.instance)]
        rates = tc_rates(result.topology, view)
        rows.append(
            {
                "site": trace.site,
                "vlan": trace.vlan if trace.vlan is not None else trace.instance,
                "count": rates["count"],
                "rate": rates["lifetime"],
                "delta": rates["delta"],
                "window": rates["window"],
                "current": rates["current"],
                "last": trace.last_seconds,
                "origin": (
                    f"{trace.origin_host} {short_interface(trace.origin_port or '')}".strip()
                    if trace.origin_host
                    else "?"
                ),
                "kind": trace.origin_kind,
                "neighbor": trace.origin_neighbor,
                "path": trace.path,
                "consistent": trace.consistent,
                "active": bool(
                    (rates["current"] or 0) >= 1
                    or (rates["current"] is None and rates["lifetime"] >= 1)
                    or (trace.last_seconds is not None and trace.last_seconds <= 86400)
                ),
            }
        )
    rows.sort(
        key=lambda r: (-(r["current"] if r["current"] is not None else r["rate"] or 0), r["site"], str(r["vlan"]))
    )
    return rows


def _switch_rows(result: AuditResult) -> list[dict[str, Any]]:
    findings_by_host = Counter(f.host for f in result.findings if f.host)
    worst: dict[str, str] = {}
    for finding in result.findings:
        if finding.host and finding.host not in worst:
            worst[finding.host] = finding.severity
    rows = []
    for host, device in sorted(result.devices.items()):
        edge = result.edge.get(host, [])
        access = [e for e in edge if not e.trunk]
        blocked = {p.port for inst in device.stp.values() for p in inst.ports.values() if p.state in ("BLK", "BKN")}
        plan = result.plan.hosts.get(host)
        rows.append(
            {
                "host": host,
                "site": device.site,
                "role": device.role,
                "ip": device.intent.get("ansible_host", ""),
                "model": device.version.model,
                "version": device.version.os_version,
                "uptime": device.version.uptime_seconds,
                "mode": device.stp_summary.mode or device.config.stp_mode or "?",
                "vlans": len([i for i in device.stp.values() if i.vlan is not None]),
                "root_for": len([i for i in device.stp.values() if i.is_root]),
                "blocked": len(blocked),
                "edge_ok": len([e for e in access if e.compliant]),
                "edge_total": len(access),
                "errdisabled": len([s for s in device.interfaces.values() if s.status == "err-disabled"]),
                "findings": findings_by_host.get(host, 0),
                "worst": worst.get(host),
                "reachable": device.reachable,
                "changes": len(plan.changes) if plan else 0,
            }
        )
    return rows


def _actions(result: AuditResult) -> list[dict[str, Any]]:
    """A short, ordered to-do list for humans."""
    actions = []
    plan = result.plan
    changing = [plan.hosts[h] for h in plan.apply_order]
    root_fix = [p for p in changing if any(c.kind == "priority" for c in p.changes)]
    mode_fix = [p for p in changing if any(c.kind == "mode" for c in p.changes)]
    edge_fix = [p for p in changing if any(c.kind in ("portfast", "bpduguard") for c in p.changes)]
    ports = len({(p.host, c.parent) for p in edge_fix for c in p.changes if c.kind in ("portfast", "bpduguard")})
    wrong_root = [f for f in result.findings if f.category == "root-bridge" and f.title.startswith("Root bridge is")]
    if wrong_root or root_fix:
        actions.append(
            {
                "title": "Pin the root bridge",
                "text": (
                    f"Set bridge priority on {', '.join(p.host for p in root_fix)}"
                    if root_fix
                    else "Set stp_role: root_primary / root_secondary in the inventory"
                ),
                "planned": bool(root_fix),
            }
        )
    if edge_fix:
        actions.append(
            {
                "title": "Harden edge ports",
                "text": f"PortFast + BPDU Guard on {ports} access port(s) across {len(edge_fix)} switch(es)",
                "planned": True,
            }
        )
    if mode_fix:
        target = result.policies[mode_fix[0].host].get("stp_mode")
        actions.append(
            {
                "title": f"Move to {target}",
                "text": f"{len(mode_fix)} switch(es): {', '.join(p.host for p in mode_fix[:8])}{'...' if len(mode_fix) > 8 else ''}",
                "planned": True,
            }
        )
    # Manual follow-ups, merged when the same problem shows up on several switches
    # (e.g. both ends of a link).
    grouped: dict[tuple[str, str], list] = defaultdict(list)
    for finding in result.findings:
        if finding.severity in ("critical", "high") and not finding.planned:
            title = re.sub(r"^\d+ ", "", finding.title)
            grouped[(finding.category, title)].append(finding)
    for (_, title), items in list(grouped.items())[:8]:
        hosts = sorted({f.host for f in items if f.host})
        first = items[0]
        actions.append(
            {
                "title": first.title if len(items) == 1 else title[:1].upper() + title[1:],
                "text": (", ".join(hosts) + ": " if hosts else "") + (first.recommendation or first.detail),
                "planned": False,
            }
        )
    return actions


def build_context(result: AuditResult, title: str | None = None) -> dict[str, Any]:
    devices = result.devices
    sites = sorted({d.site or "default" for d in devices.values()})
    modes = Counter((d.stp_summary.mode or d.config.stp_mode or "unknown") for d in devices.values() if d.reachable)
    tc_rows = _tc_rows(result)
    plan = result.plan
    changing = [plan.hosts[h] for h in plan.apply_order]
    return {
        "title": title or f"STP audit - {', '.join(sites)}",
        "generated_at": result.generated_at,
        "sites": sites,
        "severities": SEVERITIES,
        "counts": result.counts(),
        "total_switches": len(devices),
        "unreachable": [h for h, d in devices.items() if not d.reachable],
        "modes": modes.most_common(),
        "roots": _root_rows(result),
        "diagrams": _diagrams(result),
        "tc_rows": tc_rows,
        "max_rate": max((r["rate"] or 0 for r in tc_rows), default=0),
        "max_current": max((r["current"] for r in tc_rows if r["current"] is not None), default=None),
        "previous_run": result.topology.previous_run,
        "findings": [dict(asdict(f), rank=f.rank) for f in result.findings],
        "actions": _actions(result),
        "plan": {
            "order": plan.apply_order,
            "warnings": plan.warnings,
            "hosts": [
                {
                    "host": p.host,
                    "order": p.order,
                    "role": p.role,
                    "summary": p.summary(),
                    "disruptive": p.disruptive,
                    "config_safe": p.config_text(disruptive=False),
                    "config_disruptive": p.config_text(disruptive=True),
                    "rollback": p.rollback_text(),
                    "skipped": p.skipped,
                    "blockers": p.blockers,
                    "notes": p.notes,
                    "lines": sum(len(c.lines) for c in p.changes),
                }
                for p in changing
            ],
            "blocked_hosts": [
                {"host": p.host, "blockers": p.blockers} for p in plan.hosts.values() if p.blockers and p.has_changes
            ],
            "total_lines": sum(len(c.lines) for p in changing for c in p.changes),
        },
        "switches": _switch_rows(result),
        "errors": {h: d.errors for h, d in devices.items() if d.errors},
    }


def summary_dict(result: AuditResult, context: dict[str, Any]) -> dict[str, Any]:
    return {
        "generated_at": result.generated_at,
        "switches": context["total_switches"],
        "unreachable": context["unreachable"],
        "counts": context["counts"],
        "modes": dict(context["modes"]),
        "roots": context["roots"],
        "plan": {
            "apply_order": result.plan.apply_order,
            "warnings": result.plan.warnings,
            "total_lines": context["plan"]["total_lines"],
        },
        "top_findings": [
            {k: f[k] for k in ("severity", "category", "site", "host", "title")} for f in context["findings"][:15]
        ],
    }


def write_reports(result: AuditResult, out_dir: Path, title: str | None = None) -> dict[str, Path]:
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    context = build_context(result, title)
    env = _env()
    paths = {
        "html": out_dir / "report.html",
        "markdown": out_dir / "report.md",
        "findings": out_dir / "findings.json",
        "plan": out_dir / "plan.json",
        "summary": out_dir / "summary.json",
    }
    paths["html"].write_text(env.get_template("report.html.j2").render(**context), encoding="utf-8")
    paths["markdown"].write_text(env.get_template("report.md.j2").render(**context), encoding="utf-8")
    paths["findings"].write_text(json.dumps(context["findings"], indent=2), encoding="utf-8")
    paths["plan"].write_text(json.dumps(result.plan.to_dict(), indent=2), encoding="utf-8")
    paths["summary"].write_text(json.dumps(summary_dict(result, context), indent=2), encoding="utf-8")
    plan_dir = out_dir / "plan"
    plan_dir.mkdir(exist_ok=True)
    for host, host_plan in result.plan.hosts.items():
        (plan_dir / f"{slugify(host)}.json").write_text(json.dumps(host_plan.to_dict(), indent=2), encoding="utf-8")
        text = host_plan.config_text()
        cfg_path = plan_dir / f"{slugify(host)}.cfg"
        if text:
            cfg_path.write_text(
                f"! Planned changes for {host} (apply order {host_plan.order or '-'})\n"
                f"! Rollback:\n" + "".join(f"!   {line}\n" for line in host_plan.rollback_text().splitlines()) + text,
                encoding="utf-8",
            )
        elif cfg_path.exists():
            cfg_path.unlink()
    return paths


def split_raw(raw_dir: Path) -> None:
    """Write each collected command output to raw/<host>/<command>.txt for easy grepping."""
    raw_dir = Path(raw_dir)
    for path in sorted(raw_dir.glob("*.json")):
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        host_dir = raw_dir / path.stem
        host_dir.mkdir(exist_ok=True)
        for command, output in (payload.get("outputs") or {}).items():
            (host_dir / f"{slugify(command)}.txt").write_text(remove_secrets(output), encoding="utf-8")

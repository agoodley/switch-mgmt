"""The individual audit checks.  Each returns a list of findings."""

from __future__ import annotations

from collections import Counter, defaultdict
from typing import Any

from ..model import Device
from ..util import (
    canonical_interface,
    compress_vlans,
    expand_vlans,
    format_duration,
    interface_sort_key,
    short_interface,
)
from .edge import EdgePort
from .findings import Finding
from .tc import TcTrace
from .topology import Topology, VlanView

INCONSISTENT_HELP = {
    "ROOT": "Root Guard is blocking: a downstream device advertised a better root bridge.",
    "LOOP": "Loop Guard is blocking: BPDUs stopped arriving (unidirectional link or BPDU loss).",
    "TYPE": "Port type inconsistent: one side is a trunk, the other an access port.",
    "PVID": "Native VLAN mismatch between the two ends of a trunk.",
    "PVST": "PVST simulation inconsistent at an MST boundary.",
    "BKN": "Port is in a broken (inconsistent) state.",
}

SERIOUS_ERRDISABLE = {"bpduguard", "loopback", "udld", "channel-misconfig", "link-flap", "loopdetect"}


def _plist(ports: list[str], limit: int = 12) -> str:
    names = [short_interface(p) for p in sorted(set(ports), key=interface_sort_key)]
    if len(names) > limit:
        return ", ".join(names[:limit]) + f" (+{len(names) - limit} more)"
    return ", ".join(names)


def _vlist(vlans) -> str:
    vlans = [v for v in vlans if v is not None]
    return compress_vlans(vlans) if vlans else "-"


def _label(topology: Topology, view: VlanView) -> str:
    if view.root_host:
        return view.root_host
    return f"unknown device {view.root_mac}" if view.root_mac else "unknown"


def _priority_base(priority: int | None, vlan: int | None) -> int | None:
    if priority is None:
        return None
    base = priority - (vlan or 0)
    return base if base >= 0 and base % 4096 == 0 else priority


# ---------------------------------------------------------------------------
def check_collection(topology: Topology) -> list[Finding]:
    findings = []
    for device in topology.devices.values():
        if not device.reachable:
            findings.append(
                Finding(
                    "high",
                    "collection",
                    "No data collected from this switch",
                    host=device.host,
                    site=device.site,
                    detail="; ".join(f"{k}: {v}" for k, v in device.errors.items())[:600],
                    recommendation="Check reachability, SSH credentials and enable secret, then re-run the audit.",
                )
            )
            continue
        if device.errors:
            findings.append(
                Finding(
                    "info",
                    "collection",
                    f"{len(device.errors)} command(s) not supported or failed",
                    host=device.host,
                    site=device.site,
                    detail="; ".join(f"{k}: {v.splitlines()[0] if v else ''}" for k, v in device.errors.items())[:600],
                )
            )
        if device.parse_errors:
            findings.append(
                Finding(
                    "low",
                    "collection",
                    "Some output could not be parsed",
                    host=device.host,
                    site=device.site,
                    detail="; ".join(f"{k}: {v}" for k, v in device.parse_errors.items()),
                    recommendation="Please report this with the raw output from the run directory.",
                )
            )
        if not device.stp and "show spanning-tree" not in device.errors:
            findings.append(
                Finding(
                    "medium",
                    "collection",
                    "No spanning-tree instances found",
                    host=device.host,
                    site=device.site,
                    detail="`show spanning-tree` returned no VLAN instances. STP may be disabled or no ports are up.",
                )
            )
    return findings


# ---------------------------------------------------------------------------
def _mode_of(device: Device) -> str | None:
    return device.stp_summary.mode or device.config.stp_mode


def check_modes(topology: Topology, policies: dict[str, dict[str, Any]]) -> list[Finding]:
    findings = []
    for site, devices in topology.by_site.items():
        modes = {d.host: _mode_of(d) for d in devices if d.reachable and _mode_of(d)}
        if not modes:
            continue
        counts = Counter(modes.values())
        targets = {policies[d.host].get("stp_mode") for d in devices if d.host in policies} - {None}
        target = next(iter(targets)) if len(targets) == 1 else None
        to_migrate = sorted(h for h, m in modes.items() if policies[h].get("stp_mode") and m != policies[h]["stp_mode"])
        if len(counts) > 1:
            by_mode = defaultdict(list)
            for host, mode in modes.items():
                by_mode[mode].append(host)
            findings.append(
                Finding(
                    "high",
                    "stp-mode",
                    "Mixed spanning-tree modes: " + ", ".join(f"{m} x{c}" for m, c in counts.most_common()),
                    site=site,
                    detail="; ".join(f"{m}: {', '.join(sorted(h))}" for m, h in sorted(by_mode.items())),
                    recommendation=(
                        "Run a single mode site-wide. Where a Rapid-PVST+ switch meets a PVST+ neighbour the "
                        "port falls back to legacy 802.1D timers (30-50 s to forward after a change)."
                        + (
                            f" Policy is '{target}': the plan migrates {len(to_migrate)} switch(es) one at a time."
                            if target
                            else ""
                        )
                    ),
                    planned=bool(to_migrate),
                )
            )
        elif to_migrate:
            mode = next(iter(counts))
            findings.append(
                Finding(
                    "medium",
                    "stp-mode",
                    f"All switches run {mode}; policy is {target or 'different'}",
                    site=site,
                    detail=f"{len(to_migrate)} switch(es) will be migrated: {', '.join(to_migrate[:20])}",
                    recommendation="Rapid-PVST+ converges in about a second instead of 30-50 s.",
                    planned=True,
                )
            )
        # MST region consistency
        mst = [d for d in devices if _mode_of(d) == "mst"]
        regions = {
            (d.config.mst_name, d.config.mst_revision, tuple(sorted(d.config.mst_instances.items()))) for d in mst
        }
        if len(regions) > 1:
            findings.append(
                Finding(
                    "high",
                    "stp-mode",
                    "MST region configuration differs between switches",
                    site=site,
                    detail="; ".join(
                        f"{d.host}: name={d.config.mst_name} rev={d.config.mst_revision} "
                        f"map={dict(d.config.mst_instances)}"
                        for d in mst
                    )[:800],
                    recommendation="Every switch in one MST region needs identical name, revision and VLAN mapping.",
                )
            )
    return findings


# ---------------------------------------------------------------------------
def check_roots(topology: Topology, policies: dict[str, dict[str, Any]]) -> list[Finding]:
    findings: list[Finding] = []
    views_by_site: dict[str, list[VlanView]] = defaultdict(list)
    for (site, _), view in sorted(topology.views.items(), key=lambda kv: (kv[0][0], kv[1].vlan or 0)):
        views_by_site[site].append(view)

    for site, views in views_by_site.items():
        expected = views[0].expected_root if views else None
        backup = views[0].expected_backup if views else None

        # 1. split STP domains: switches disagree about who the root is
        split = [v for v in views if len(v.roots_seen) > 1]
        if split:
            lines = []
            for v in split[:10]:
                parts = []
                for mac, hosts in v.roots_seen.items():
                    who = topology.mac_to_host.get(mac, mac)
                    parts.append(
                        f"{who} seen by {len(hosts)} ({', '.join(sorted(hosts)[:4])}{'...' if len(hosts) > 4 else ''})"
                    )
                lines.append(f"VLAN {v.vlan if v.vlan is not None else v.instance}: " + "; ".join(parts))
            findings.append(
                Finding(
                    "high",
                    "root-bridge",
                    f"Switches disagree about the root bridge in {len(split)} VLAN(s)",
                    site=site,
                    vlans=[v.vlan for v in split if v.vlan is not None],
                    detail=" | ".join(lines),
                    recommendation=(
                        "Each VLAN is split into separate spanning trees. Expected only if the VLAN is "
                        "deliberately not trunked between those switches; otherwise look for BPDU Filter, "
                        "a VLAN missing from a trunk's allowed list, or a non-Cisco device dropping PVST+ BPDUs."
                    ),
                )
            )

        # 2. roots that are not where they should be
        wrong: dict[str, list[VlanView]] = defaultdict(list)
        unknown: dict[str, list[VlanView]] = defaultdict(list)
        for v in views:
            if not v.root_mac:
                continue
            if v.root_host is None:
                unknown[v.root_mac].append(v)
            if expected and v.root_host != expected and expected in v.switches:
                wrong[_label(topology, v)].append(v)

        for label, vs in wrong.items():
            sample = vs[0]
            base = _priority_base(sample.root_priority, sample.vlan)
            reason = (
                f"{label} has priority {base} (default) and wins on lowest MAC address {sample.root_mac}"
                if base == 32768
                else f"{label} has priority {base}"
            )
            planned = any(
                d.host == expected and policies[d.host].get("stp_priority_root_primary") is not None
                for d in topology.by_site[site]
            )
            findings.append(
                Finding(
                    "high",
                    "root-bridge",
                    f"Root bridge is {label}, expected {expected}",
                    site=site,
                    host=expected,
                    vlans=[v.vlan for v in vs if v.vlan is not None],
                    detail=f"VLANs {_vlist(v.vlan for v in vs)}: {reason}.",
                    recommendation=(
                        f"Give {expected} the lowest priority (stp_role: root_primary). Traffic between access "
                        f"switches currently takes the path through {label}, and the root moves whenever a "
                        "switch with a lower MAC address joins."
                    ),
                    planned=planned,
                )
            )

        for mac, vs in unknown.items():
            entry_points = []
            for v in vs:
                for host, node in v.tree.items():
                    if node.parent and node.parent.startswith("external:"):
                        entry_points.append(f"{host} {short_interface(node.via_port or '')} -> {node.parent[9:]}")
            sample = vs[0]
            findings.append(
                Finding(
                    "high",
                    "root-bridge",
                    f"Root bridge {mac} is not an audited switch",
                    site=site,
                    vlans=[v.vlan for v in vs if v.vlan is not None],
                    detail=(
                        f"VLANs {_vlist(v.vlan for v in vs)} use root {mac} (priority {sample.root_priority}). "
                        + ("Reached via: " + "; ".join(sorted(set(entry_points))[:6]) if entry_points else "")
                    ),
                    recommendation=(
                        "Find the device with that MAC (follow the listed ports). If it should not be root, "
                        "it needs a higher priority, or Root Guard on the port facing it."
                    ),
                )
            )

        # 3. nothing is designated as root
        if not expected:
            roots = Counter(_label(topology, v) for v in views if v.root_mac)
            defaults = [v for v in views if v.root_mac and _priority_base(v.root_priority, v.vlan) == 32768]
            findings.append(
                Finding(
                    "medium",
                    "root-bridge",
                    "No root bridge is designated for this site",
                    site=site,
                    detail=(
                        "Current roots: "
                        + ", ".join(f"{name} ({n} VLANs)" for name, n in roots.most_common(6))
                        + (
                            f". {len(defaults)} VLAN(s) use the default priority, so the root is simply the oldest "
                            "switch (lowest MAC)."
                            if defaults
                            else ""
                        )
                    ),
                    recommendation="Set `stp_role: root_primary` on the core switch and `root_secondary` on its peer.",
                )
            )

        # 4. backup root
        if expected and backup:
            wrong_backup: dict[str, list[int]] = defaultdict(list)
            for v in views:
                if v.root_host != expected or backup not in v.switches:
                    continue
                others = [s for h, s in v.switches.items() if h != expected and s.bridge_priority is not None]
                if not others:
                    continue
                best = min(others, key=lambda s: (s.bridge_priority, s.bridge_mac))
                if best.host != backup and v.vlan is not None:
                    wrong_backup[best.host].append(v.vlan)
            for host, vlans in wrong_backup.items():
                findings.append(
                    Finding(
                        "medium",
                        "root-bridge",
                        f"If {expected} fails, {host} would become root instead of {backup}",
                        site=site,
                        host=backup,
                        vlans=vlans,
                        detail=f"VLANs {_vlist(vlans)}",
                        recommendation=f"Give {backup} the second-lowest priority (stp_role: root_secondary).",
                        planned=policies.get(backup, {}).get("stp_priority_root_secondary") is not None,
                    )
                )
    return findings


# ---------------------------------------------------------------------------
def tc_rates(topology: Topology, view: VlanView) -> dict[str, Any]:
    """Lifetime and (when a previous audit exists) current topology-change rates for a VLAN."""
    lifetime, counts, measured = [], [], []
    for state in view.switches.values():
        device = topology.devices[state.host]
        if state.tc_count is None:
            continue
        counts.append(state.tc_count)
        uptime = device.version.uptime_seconds
        if uptime:
            lifetime.append(state.tc_count / max(uptime / 86400, 1 / 24))
        if state.tc_delta is not None and state.tc_delta_seconds:
            measured.append((state.tc_delta, state.tc_delta_seconds))
    delta, window = max(measured, key=lambda m: m[0]) if measured else (None, None)
    return {
        "lifetime": max(lifetime) if lifetime else 0.0,
        "count": max(counts) if counts else None,
        "delta": delta,
        "window": window,
        "current": (delta / window * 86400) if delta is not None and window else None,
    }


MIN_WINDOW = 1800  # seconds between audits before the measured rate is trusted


def check_topology_changes(
    topology: Topology,
    traces: list[TcTrace],
    policies: dict[str, dict[str, Any]],
    edge_map: dict[str, list[EdgePort]],
) -> list[Finding]:
    findings = []
    groups: dict[tuple, list[tuple[TcTrace, dict[str, Any], str]]] = defaultdict(list)
    for trace in traces:
        view = topology.views[(trace.site, trace.instance)]
        rates = tc_rates(topology, view)
        pol = policies.get(next(iter(view.switches)), {})
        warn, high = pol.get("audit_tc_warn_per_day", 24), pol.get("audit_tc_high_per_day", 240)
        last = trace.last_seconds
        edge = next((e for e in edge_map.get(trace.origin_host or "", []) if e.port == trace.origin_port), None)
        flapping_edge = trace.origin_kind == "access-port" and (edge is None or not edge.portfast_ok)
        if rates["current"] is not None and rates["window"] >= MIN_WINDOW:
            # Measured since the previous audit: the most reliable signal.
            current = rates["current"]
            severity = "high" if current >= high else "medium" if current >= warn else "low" if rates["delta"] else None
        elif last is not None and last <= 3600 and flapping_edge and rates["lifetime"] >= warn:
            severity = "high" if rates["lifetime"] >= high else "medium"
        elif (
            last is not None
            and last <= 86400
            and rates["lifetime"] >= warn
            and trace.origin_kind in ("access-port", "external")
        ):
            severity = "medium"
        elif last is not None and last <= pol.get("audit_tc_recent_seconds", 600):
            severity = "low"
        else:
            severity = None
        if severity is None:
            continue
        key = (trace.site, trace.origin_host, trace.origin_port, trace.origin_kind, trace.origin_neighbor)
        groups[key].append((trace, rates, severity))

    order = {"high": 0, "medium": 1, "low": 2}
    for (site, host, port, kind, neighbor), items in groups.items():
        traces_ = [t for t, _, _ in items]
        severity = min((s for _, _, s in items), key=order.get)
        lifetime = max(r["lifetime"] for _, r, _ in items)
        count = max((r["count"] for _, r, _ in items if r["count"] is not None), default=None)
        measured = [r for _, r, _ in items if r["current"] is not None]
        last = min((t.last_seconds for t in traces_ if t.last_seconds is not None), default=None)
        vlans = [t.vlan for t in traces_ if t.vlan is not None]
        where = f"{host} {short_interface(port)}" if port else (host or "unknown")
        edge = next((e for e in edge_map.get(host or "", []) if e.port == port), None)
        planned = False
        if kind == "access-port":
            if edge is not None and not edge.portfast_ok:
                advice = (
                    f"{short_interface(port)} is an access port without PortFast: every time the attached "
                    "device restarts or the cable is moved, all switches flush their MAC tables for "
                    f"VLAN {_vlist(vlans)} and flood traffic."
                    + (
                        " The plan enables PortFast here."
                        if edge.exclude_reason is None
                        else f" Not in the plan: {edge.exclude_reason}."
                    )
                )
                planned = edge.exclude_reason is None
            else:
                advice = (
                    f"Check the device on {short_interface(port)} (flapping link, NIC power saving, "
                    "or a bridge/switch sending BPDUs so the port is not treated as an edge port)."
                )
        elif kind == "switch-link":
            advice = (
                f"The link {where} <-> {neighbor} changed state. A single change after maintenance is normal; "
                "if it repeats, check optics, cabling and interface errors on both ends (consider UDLD on fibre)."
            )
        elif kind == "external":
            advice = f"Topology changes arrive from {neighbor}, which is not in the inventory."
        else:
            advice = "The trail could not be followed to a single port (missing CDP data or a newer change)."
        rate_text = f"~{lifetime:.0f}/day since boot"
        if measured:
            best = max(measured, key=lambda r: r["current"])
            rate_text = (
                f"{best['delta']} since the previous audit {format_duration(best['window'])} ago "
                f"(~{best['current']:.0f}/day), {rate_text}"
            )
        findings.append(
            Finding(
                severity,
                "topology-change",
                (
                    f"Topology changes originate at {where}"
                    if severity != "low"
                    else f"Recent topology change from {where}"
                ),
                host=host,
                site=site,
                ports=[port] if port else [],
                vlans=vlans,
                detail=(
                    f"VLAN {_vlist(vlans)}: {count} changes ({rate_text}), last {format_duration(last)} ago. "
                    f"Trail: {traces_[0].path}."
                    + (
                        ""
                        if all(t.consistent for t in traces_)
                        else " Timestamps along the trail do not line up; "
                        "a newer change may have overwritten part of it, re-run the audit to confirm."
                    )
                ),
                recommendation=advice,
                planned=planned,
            )
        )

    # flapping access ports, independent of the TC trail
    for host, ports in edge_map.items():
        pol = policies.get(host, {})
        threshold = pol.get("audit_flap_transitions", 100)
        flappers = [p for p in ports if p.transitions and p.transitions >= threshold]
        if flappers:
            device = topology.devices[host]
            findings.append(
                Finding(
                    "medium",
                    "topology-change",
                    f"{len(flappers)} access port(s) transitioned to forwarding {threshold}+ times",
                    host=host,
                    site=device.site,
                    ports=[p.port for p in flappers],
                    detail=", ".join(
                        f"{short_interface(p.port)} ({p.transitions}x)"
                        for p in sorted(flappers, key=lambda p: -(p.transitions or 0))[:12]
                    ),
                    recommendation="Flapping host links; with PortFast they stop causing topology changes, "
                    "but the link itself should still be checked.",
                )
            )
    return findings


# ---------------------------------------------------------------------------
def check_edge_ports(
    topology: Topology, edge_map: dict[str, list[EdgePort]], policies: dict[str, dict[str, Any]]
) -> list[Finding]:
    findings = []
    unhardened: dict[str, list[tuple[str, int, int, int, int, int]]] = defaultdict(list)
    for host, ports in edge_map.items():
        device = topology.devices[host]
        pol = policies[host]
        candidates = [p for p in ports if not p.trunk]
        no_portfast = [p for p in candidates if not p.portfast_ok]
        no_guard = [p for p in candidates if not p.bpduguard_ok]
        bad = [p for p in candidates if not p.compliant]
        if bad:
            fixable = [
                p
                for p in bad
                if p.exclude_reason is None
                and (
                    (not p.portfast_ok and pol.get("stp_edge_portfast"))
                    or (not p.bpduguard_ok and pol.get("stp_edge_bpduguard"))
                )
            ]
            unhardened[device.site].append(
                (host, len(candidates), len(no_portfast), len(no_guard), len(bad), len(fixable))
            )
        bridges = [
            p for p in candidates if p.switch_neighbor or p.bpdu_received or (p.roles & {"Root", "Altn", "Back"})
        ]
        if bridges:
            details = []
            for p in bridges:
                bits = []
                if p.switch_neighbor:
                    bits.append(f"neighbour {p.switch_neighbor}")
                if p.bpdu_received:
                    bits.append(f"{p.bpdu_received} BPDUs received")
                if p.roles & {"Root", "Altn", "Back"}:
                    bits.append("role " + "/".join(sorted(p.roles & {"Root", "Altn", "Back"})))
                details.append(f"{short_interface(p.port)}: {', '.join(bits)}")
            findings.append(
                Finding(
                    "high",
                    "edge-ports",
                    f"{len(bridges)} access port(s) have a switch or bridge behind them",
                    host=host,
                    site=device.site,
                    ports=[p.port for p in bridges],
                    detail="; ".join(details)[:900],
                    recommendation=(
                        "Unmanaged or rogue switches on access ports are a common source of loops and topology "
                        "changes. These ports are excluded from the BPDU Guard rollout (it would shut them down); "
                        "identify the device, then either convert the port to a proper trunk or remove the device."
                    ),
                )
            )
        filtered = [p for p in ports if p.bpdufilter]
        if filtered:
            findings.append(
                Finding(
                    "high",
                    "edge-ports",
                    f"BPDU Filter enabled on {len(filtered)} port(s)",
                    host=host,
                    site=device.site,
                    ports=[p.port for p in filtered],
                    detail=_plist([p.port for p in filtered]),
                    recommendation="BPDU Filter stops STP on the port entirely, so a loop through it is never "
                    "blocked. Replace it with BPDU Guard.",
                )
            )
        if device.config.bpdufilter_default:
            findings.append(
                Finding(
                    "medium",
                    "edge-ports",
                    "Global PortFast BPDU Filter default is enabled",
                    host=host,
                    site=device.site,
                    recommendation="Prefer BPDU Guard on edge ports; BPDU Filter hides loops created through them.",
                )
            )
        dtp = [
            name
            for name, iface in device.config.interfaces.items()
            if iface.mode is None
            and name in device.interfaces
            and device.interfaces[name].status == "connected"
            and device.interfaces[name].vlan not in ("routed", "")
        ]
        if dtp:
            findings.append(
                Finding(
                    "low",
                    "edge-ports",
                    f"{len(dtp)} connected port(s) have no explicit switchport mode",
                    host=host,
                    site=device.site,
                    ports=dtp,
                    detail=_plist(dtp),
                    recommendation="Set `switchport mode access` or `switchport mode trunk` explicitly; DTP "
                    "negotiation makes port roles unpredictable and these ports are skipped by the plan.",
                )
            )
    for site, rows in unhardened.items():
        total = sum(r[4] for r in rows)
        fixable = sum(r[5] for r in rows)
        rows.sort(key=lambda r: (-r[4], r[0]))
        findings.append(
            Finding(
                "medium",
                "edge-ports",
                f"{total} access port(s) on {len(rows)} switch(es) lack PortFast and/or BPDU Guard",
                site=site,
                detail="; ".join(
                    f"{h}: {bad}/{n} (PortFast missing {pf}, BPDU Guard missing {bg})"
                    for h, n, pf, bg, bad, _ in rows[:25]
                )
                + (" ..." if len(rows) > 25 else ""),
                recommendation=(
                    "Without PortFast a host port takes 30 s to forward and every link change triggers a "
                    "site-wide topology change; BPDU Guard shuts the port if someone plugs in a switch. "
                    f"The plan fixes {fixable} port(s); the rest are skipped for safety (see the plan)."
                ),
                planned=fixable > 0,
            )
        )
    return findings


# ---------------------------------------------------------------------------
def check_port_states(topology: Topology) -> list[Finding]:
    findings = []
    for device in topology.devices.values():
        inconsistent: dict[str, list[str]] = defaultdict(list)
        for inst in device.stp.values():
            for port in inst.ports.values():
                if port.inconsistent:
                    inconsistent[port.inconsistent].append(
                        f"{short_interface(port.port)} (VLAN {inst.vlan or inst.name})"
                    )
        for kind, items in inconsistent.items():
            findings.append(
                Finding(
                    "high",
                    "inconsistent-ports",
                    f"{len(items)} port/VLAN(s) blocked as {kind} inconsistent",
                    host=device.host,
                    site=device.site,
                    detail=", ".join(items[:15]),
                    recommendation=INCONSISTENT_HELP.get(kind, "Port is blocked by an STP consistency check."),
                )
            )
        errdis = [(p, s.errdisable_reason) for p, s in device.interfaces.items() if s.status == "err-disabled"]
        if errdis:
            serious = any(reason in SERIOUS_ERRDISABLE for _, reason in errdis)
            findings.append(
                Finding(
                    "high" if serious else "medium",
                    "errdisable",
                    f"{len(errdis)} err-disabled port(s)",
                    host=device.host,
                    site=device.site,
                    ports=[p for p, _ in errdis],
                    detail=", ".join(f"{short_interface(p)} ({r or '?'})" for p, r in errdis[:15]),
                    recommendation="bpduguard = a switch was plugged into an edge port; loopback/udld/link-flap "
                    "point to cabling or loops. Fix the cause, then `shutdown` / `no shutdown` the port.",
                )
            )
        blocked_access = []
        for inst in device.stp.values():
            for port in inst.ports.values():
                iface = device.config.interfaces.get(port.port)
                if iface is not None and iface.mode == "access" and port.role in ("Altn", "Back"):
                    blocked_access.append(f"{short_interface(port.port)} (VLAN {inst.vlan})")
        if blocked_access:
            findings.append(
                Finding(
                    "high",
                    "loop",
                    "Access port(s) blocking: a redundant path exists through host ports",
                    host=device.host,
                    site=device.site,
                    detail=", ".join(blocked_access[:15]),
                    recommendation="Two access ports lead to the same bridged network (often a small switch "
                    "patched twice, or a hub). STP is currently containing the loop; remove the extra path.",
                )
            )
        facing = topology.switch_facing_ports(device.host)
        shared = sorted(
            {p.port for inst in device.stp.values() for p in inst.ports.values() if not p.p2p and p.port in facing}
        )
        if shared:
            findings.append(
                Finding(
                    "medium",
                    "link-type",
                    f"{len(shared)} switch link(s) run as STP 'shared' (half duplex)",
                    host=device.host,
                    site=device.site,
                    ports=shared,
                    detail=_plist(shared),
                    recommendation="Shared links cannot use Rapid-PVST+'s fast handshake. Fix the duplex setting "
                    "(both ends auto, or both fixed).",
                )
            )
    return findings


# ---------------------------------------------------------------------------
LOG_RULES = [
    # mnemonic substring, severity, title, recommendation
    (
        "MAX_INSTANCE",
        "critical",
        "Spanning-tree instance limit exceeded",
        "Some VLANs have NO spanning tree on this switch. Prune VLANs from trunks or move to MST.",
    ),
    (
        "MACFLAP",
        "high",
        "MAC address flapping",
        "MAC flapping between ports is the classic symptom of a bridging loop (or a mis-configured "
        "dual-homed server). Check the ports named in the messages.",
    ),
    ("ROOTGUARD_BLOCK", "high", "Root Guard blocked a port", INCONSISTENT_HELP["ROOT"]),
    ("LOOPGUARD_BLOCK", "high", "Loop Guard blocked a port", INCONSISTENT_HELP["LOOP"]),
    ("CHNL_MISCFG", "high", "EtherChannel misconfiguration detected", "The two ends of a port-channel do not agree."),
    ("LOOP_BACK", "high", "Loopback detected on a port", "A cable or device is looping traffic back to the switch."),
    ("BLOCK_BPDUGUARD", "medium", "BPDU Guard shut down ports", "Someone connected a switch to an edge port."),
    ("RECV_PVID_ERR", "medium", "BPDUs with a different native VLAN", INCONSISTENT_HELP["PVID"]),
    ("RECV_1Q_NON_TRUNK", "medium", "802.1Q BPDUs on an access port", INCONSISTENT_HELP["TYPE"]),
    ("NATIVE_VLAN_MISMATCH", "medium", "Native VLAN mismatch reported by CDP", INCONSISTENT_HELP["PVID"]),
    ("DUPLEX_MISMATCH", "medium", "Duplex mismatch reported by CDP", "Set both ends to auto (or both fixed)."),
    ("STORM_CONTROL", "medium", "Storm control triggered", "Broadcast/multicast storms usually mean a loop."),
    (
        "ROOTCHANGE",
        "low",
        "Root bridge changed",
        "Expected right after a planned root change; otherwise the root should not move in a stable network.",
    ),
]


def check_logs(topology: Topology) -> list[Finding]:
    findings = []
    for device in topology.devices.values():
        if not device.logs:
            continue
        for needle, severity, title, advice in LOG_RULES:
            events = [e for e in device.logs if needle in e.mnemonic or needle in e.facility]
            if not events:
                continue
            findings.append(
                Finding(
                    severity,
                    "logs",
                    f"{title} ({len(events)} log message{'s' if len(events) != 1 else ''})",
                    host=device.host,
                    site=device.site,
                    detail=" | ".join(e.raw for e in events[-3:])[:900],
                    recommendation=advice,
                )
            )
        flaps = Counter()
        for event in device.logs:
            if event.facility == "LINK" and event.mnemonic == "UPDOWN":
                parts = event.message.split(",")[0].split()
                if len(parts) >= 2:
                    flaps[parts[1]] += 1
        noisy = [(port, n) for port, n in flaps.items() if n >= 10]
        if noisy:
            findings.append(
                Finding(
                    "medium",
                    "logs",
                    f"{len(noisy)} interface(s) flapping in the log buffer",
                    host=device.host,
                    site=device.site,
                    detail=", ".join(
                        f"{short_interface(p)} ({n} up/down)" for p, n in sorted(noisy, key=lambda x: -x[1])[:10]
                    ),
                    recommendation="Check cabling/optics; flapping switch links cause topology changes.",
                )
            )
    return findings


# ---------------------------------------------------------------------------
def check_config(topology: Topology, policies: dict[str, dict[str, Any]]) -> list[Finding]:
    findings = []
    for site, devices in topology.by_site.items():
        methods = {
            d.host: (d.stp_summary.pathcost_method or d.config.pathcost_method or "short")
            for d in devices
            if d.reachable
        }
        if len(set(methods.values())) > 1:
            findings.append(
                Finding(
                    "low",
                    "config",
                    "Path cost method differs between switches",
                    site=site,
                    detail="; ".join(f"{h}: {m}" for h, m in sorted(methods.items()))[:600],
                    recommendation="Use the same `spanning-tree pathcost method` everywhere, or path selection "
                    "becomes unpredictable.",
                )
            )
    for site, devices in topology.by_site.items():
        missing = sorted(
            d.host for d in devices if d.config.global_lines and "bpduguard" not in d.config.errdisable_recovery_causes
        )
        if missing:
            planned = all(policies[h].get("stp_errdisable_recovery") for h in missing)
            findings.append(
                Finding(
                    "info",
                    "config",
                    f"{len(missing)} switch(es) without automatic recovery for BPDU Guard",
                    site=site,
                    detail=", ".join(missing[:30]) + (" ..." if len(missing) > 30 else ""),
                    recommendation="`errdisable recovery cause bpduguard` re-enables a port after the interval "
                    "(default 300 s); if the switch is still attached it is shut again.",
                    planned=planned,
                )
            )
    for device in topology.devices.values():
        cfg = device.config
        pol = policies[device.host]
        mode = _mode_of(device)
        if cfg.stp_disabled_vlans:
            findings.append(
                Finding(
                    "critical",
                    "config",
                    f"Spanning tree disabled for VLAN(s) {_vlist(cfg.stp_disabled_vlans)}",
                    host=device.host,
                    site=device.site,
                    vlans=sorted(cfg.stp_disabled_vlans),
                    recommendation="`no spanning-tree vlan X` removes all loop protection in those VLANs. "
                    "Re-enable it (`spanning-tree vlan X`) unless there is a very good reason.",
                )
            )
        if cfg.extend_system_id is False:
            findings.append(
                Finding(
                    "low",
                    "config",
                    "Extended system ID is disabled",
                    host=device.host,
                    site=device.site,
                    recommendation="Enable `spanning-tree extend system-id`.",
                )
            )
        if mode in ("rapid-pvst", "mst") and (cfg.uplinkfast or cfg.backbonefast):
            findings.append(
                Finding(
                    "low",
                    "config",
                    "Legacy UplinkFast/BackboneFast configured",
                    host=device.host,
                    site=device.site,
                    recommendation="They are inactive with Rapid-PVST+/MST (built in). UplinkFast also raises the "
                    "bridge priority to 49152; remove them once the migration is complete.",
                )
            )
        active = len([i for i in device.stp.values() if i.vlan is not None])
        limit = pol.get("audit_max_pvst_instances", 128)
        if mode in ("pvst", "rapid-pvst") and active > limit:
            findings.append(
                Finding(
                    "medium",
                    "config",
                    f"{active} PVST instances active (many Catalyst models support {limit})",
                    host=device.host,
                    site=device.site,
                    recommendation="Prune unused VLANs from trunks or move to MST.",
                )
            )
        root_states = [i for i in device.stp.values() if i.is_root and i.hello]
        odd = [i for i in root_states if (i.hello, i.max_age, i.forward_delay) != (2, 20, 15)]
        if odd:
            findings.append(
                Finding(
                    "low",
                    "config",
                    "Non-default STP timers on the root bridge",
                    host=device.host,
                    site=device.site,
                    detail=", ".join(
                        f"VLAN {i.vlan}: hello {i.hello} max-age {i.max_age} fwd {i.forward_delay}" for i in odd[:8]
                    ),
                    recommendation="Tuned timers are rarely needed with Rapid-PVST+ and can cause instability.",
                )
            )
    return findings


# ---------------------------------------------------------------------------
def check_trunks(topology: Topology) -> list[Finding]:
    findings = []
    seen: set[frozenset] = set()
    for host, links in topology.links.items():
        device = topology.devices[host]
        for link in links:
            if not link.neighbor_host:
                continue
            other = topology.devices[link.neighbor_host]
            other_port = canonical_interface(link.neighbor_port)
            other_stp_port = other.channel_of(other_port) or other_port
            pair = frozenset({(host, link.stp_port), (other.host, other_stp_port)})
            if pair in seen:
                continue
            seen.add(pair)
            a_trunk = device.trunks.get(link.stp_port)
            b_trunk = other.trunks.get(other_stp_port)
            a_cfg = device.config.interfaces.get(link.stp_port)
            b_cfg = other.config.interfaces.get(other_stp_port)
            label = f"{host} {short_interface(link.stp_port)} <-> {other.host} {short_interface(other_stp_port)}"
            if (
                a_trunk
                and b_trunk
                and a_trunk.native_vlan
                and b_trunk.native_vlan
                and a_trunk.native_vlan != b_trunk.native_vlan
            ):
                findings.append(
                    Finding(
                        "medium",
                        "trunks",
                        f"Native VLAN mismatch on {label}",
                        host=host,
                        site=device.site,
                        detail=f"{a_trunk.native_vlan} vs {b_trunk.native_vlan}",
                        recommendation=INCONSISTENT_HELP["PVID"] + " Traffic leaks between the two VLANs.",
                    )
                )
            if (a_trunk and b_cfg and b_cfg.mode == "access") or (b_trunk and a_cfg and a_cfg.mode == "access"):
                findings.append(
                    Finding(
                        "high",
                        "trunks",
                        f"Trunk connected to an access port: {label}",
                        host=host,
                        site=device.site,
                        recommendation=INCONSISTENT_HELP["TYPE"],
                    )
                )
            if a_trunk and b_trunk and a_trunk.allowed and b_trunk.allowed:
                a_set, b_set = expand_vlans(a_trunk.allowed), expand_vlans(b_trunk.allowed)
                if a_set != b_set:
                    only_a, only_b = a_set - b_set, b_set - a_set
                    findings.append(
                        Finding(
                            "low",
                            "trunks",
                            f"Allowed VLANs differ on {label}",
                            host=host,
                            site=device.site,
                            detail=(f"only on {host}: {_vlist(only_a)}; " if only_a else "")
                            + (f"only on {other.host}: {_vlist(only_b)}" if only_b else ""),
                            recommendation="Keep allowed VLAN lists identical on both ends of a trunk.",
                        )
                    )
    return findings

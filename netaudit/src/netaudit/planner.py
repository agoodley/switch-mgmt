"""Turn the audited state plus the inventory policy into per-switch config changes.

The plan is deliberately conservative:

* only explicit ``switchport mode access`` ports are hardened, and any port that
  has received BPDUs, has a switch neighbour or holds a non-designated STP role
  is skipped (BPDU Guard would shut it down);
* changes that make spanning tree recalculate (mode, priority, path cost) are
  kept separate so the playbook can apply them last, with a longer timeout;
* every change carries the lines needed to undo it.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import asdict, dataclass, field
from typing import Any

from .analysis.edge import EdgePort
from .analysis.policy import target_priority, valid_priority
from .analysis.topology import Topology
from .model import Device
from .util import compress_vlans, expand_vlans, interface_sort_key, short_interface

VALID_MODES = ("pvst", "rapid-pvst")


@dataclass
class Change:
    kind: str
    lines: list[str]
    reason: str
    parent: str | None = None
    rollback: list[str] = field(default_factory=list)
    disruptive: bool = False


@dataclass
class HostPlan:
    host: str
    site: str
    role: str
    changes: list[Change] = field(default_factory=list)
    skipped: list[dict[str, str]] = field(default_factory=list)
    blockers: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    verify_ports: list[str] = field(default_factory=list)
    order: int = 0

    @property
    def has_changes(self) -> bool:
        return bool(self.changes)

    @property
    def disruptive(self) -> bool:
        return any(c.disruptive for c in self.changes)

    def config_text(self, disruptive: bool | None = None) -> str:
        """IOS configuration for the selected changes, grouped by parent."""
        changes = [c for c in self.changes if disruptive is None or c.disruptive == disruptive]
        return _render(changes, rollback=False)

    def rollback_text(self) -> str:
        return _render(list(reversed(self.changes)), rollback=True)

    def summary(self) -> str:
        counts: dict[str, int] = defaultdict(int)
        for change in self.changes:
            counts[change.kind] += 1
        return ", ".join(f"{k} x{v}" if v > 1 else k for k, v in counts.items()) or "no changes"

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["config_safe"] = self.config_text(disruptive=False)
        data["config_disruptive"] = self.config_text(disruptive=True)
        data["rollback"] = self.rollback_text()
        data["summary"] = self.summary()
        data["has_changes"] = self.has_changes
        return data


def _render(changes: list[Change], rollback: bool) -> str:
    """Render changes as IOS config text: interface blocks first, then global lines in order."""
    out: list[str] = []
    by_parent: dict[str, list[str]] = {}
    parent_order: list[str] = []
    for change in changes:
        lines = change.rollback if rollback else change.lines
        if not lines:
            continue
        if change.parent:
            if change.parent not in by_parent:
                by_parent[change.parent] = []
                parent_order.append(change.parent)
            by_parent[change.parent].extend(line for line in lines if line not in by_parent[change.parent])
        else:
            out.extend(lines)
    interface_parents = sorted(
        (p for p in parent_order if p.startswith("interface ")), key=lambda p: interface_sort_key(p.split(None, 1)[1])
    )
    other_parents = [p for p in parent_order if not p.startswith("interface ")]
    body: list[str] = []
    for parent in other_parents + interface_parents:
        body.append(parent)
        body.extend(f" {line}" for line in by_parent[parent])
    text = "\n".join(body + out)
    return text + "\n" if text else ""


@dataclass
class SitePlan:
    hosts: dict[str, HostPlan]
    apply_order: list[str]
    warnings: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "apply_order": self.apply_order,
            "warnings": self.warnings,
            "hosts": {h: p.to_dict() for h, p in self.hosts.items()},
        }


def _current_mode(device: Device) -> str | None:
    return device.stp_summary.mode or device.config.stp_mode


def _configured_priorities(device: Device, vlans: set[int]) -> dict[int, int]:
    """Configured bridge priority per VLAN (explicit config or 32768 default)."""
    cfg = device.config
    if cfg.global_lines:
        return {v: cfg.stp_vlan_priority.get(v, 32768) for v in vlans}
    # No config captured: fall back to what the STP output reports.
    result = {}
    for inst in device.stp.values():
        if inst.vlan in vlans and inst.bridge_priority_base is not None:
            result[inst.vlan] = inst.bridge_priority_base
    return result


def _active_vlans(device: Device) -> set[int]:
    return {inst.vlan for inst in device.stp.values() if inst.vlan is not None}


def plan_host(
    device: Device,
    topology: Topology,
    policy: dict[str, Any],
    edge: list[EdgePort],
) -> HostPlan:
    plan = HostPlan(host=device.host, site=device.site or "default", role=policy.get("stp_role") or "access")
    if not device.reachable or not device.config.global_lines:
        plan.blockers.append("no running-config collected; nothing can be planned for this switch")
        return plan

    # 1. edge ports -----------------------------------------------------------
    portfast_cmd = (policy.get("stp_portfast_command") or "spanning-tree portfast").strip()
    portfast_trunk_cmd = (policy.get("stp_portfast_trunk_command") or "spanning-tree portfast trunk").strip()
    for port in edge:
        if port.compliant:
            continue
        if port.exclude_reason:
            plan.skipped.append({"port": short_interface(port.port), "reason": port.exclude_reason})
            continue
        parent = f"interface {port.port}"
        if not port.portfast_ok and policy.get("stp_edge_portfast"):
            cmd = portfast_trunk_cmd if port.trunk else portfast_cmd
            plan.changes.append(
                Change(
                    kind="portfast-trunk" if port.trunk else "portfast",
                    lines=[cmd],
                    parent=parent,
                    rollback=[f"no {cmd}"],
                    reason="edge port without PortFast",
                )
            )
        if not port.bpduguard_ok and policy.get("stp_edge_bpduguard"):
            plan.changes.append(
                Change(
                    kind="bpduguard",
                    lines=["spanning-tree bpduguard enable"],
                    parent=parent,
                    rollback=["no spanning-tree bpduguard"],
                    reason="edge port without BPDU Guard",
                )
            )

    # 2. root guard on the core's downlinks ------------------------------------
    if policy.get("stp_rootguard_downlinks") and plan.role in ("root_primary", "root_secondary"):
        root_ports = {inst.root_port for inst in device.stp.values() if inst.root_port}
        done = set()
        for link in topology.links.get(device.host, []):
            port = link.stp_port
            if port in done:
                continue
            done.add(port)
            neighbor = topology.devices.get(link.neighbor_host or "")
            if neighbor is None or neighbor.role in ("root_primary", "root_secondary"):
                continue
            iface = device.config.interfaces.get(port)
            if iface is None or iface.guard == "root":
                continue
            if port in root_ports:
                plan.skipped.append(
                    {"port": short_interface(port), "reason": "is currently a root port; Root Guard would block it"}
                )
                continue
            plan.changes.append(
                Change(
                    kind="rootguard",
                    lines=["spanning-tree guard root"],
                    parent=f"interface {port}",
                    rollback=["no spanning-tree guard root"],
                    reason=f"downlink to {neighbor.host}",
                )
            )

    # 3. global protections ------------------------------------------------------
    cfg = device.config
    if policy.get("stp_errdisable_recovery"):
        if "bpduguard" not in cfg.errdisable_recovery_causes:
            plan.changes.append(
                Change(
                    kind="errdisable-recovery",
                    lines=["errdisable recovery cause bpduguard"],
                    rollback=["no errdisable recovery cause bpduguard"],
                    reason="re-enable BPDU Guard err-disabled ports automatically",
                )
            )
        interval = policy.get("stp_errdisable_recovery_interval")
        current_interval = cfg.errdisable_recovery_interval or 300  # IOS default
        if interval and int(interval) != current_interval:
            plan.changes.append(
                Change(
                    kind="errdisable-recovery",
                    lines=[f"errdisable recovery interval {int(interval)}"],
                    rollback=[f"errdisable recovery interval {current_interval}"],
                    reason="recovery interval",
                )
            )
    if policy.get("stp_loopguard_default") and not cfg.loopguard_default:
        plan.changes.append(
            Change(
                kind="loopguard",
                lines=["spanning-tree loopguard default"],
                rollback=["no spanning-tree loopguard default"],
                reason="Loop Guard on non-designated ports",
            )
        )

    # 4. changes that make STP recalculate -----------------------------------------
    current_mode = _current_mode(device)
    target_mode = policy.get("stp_mode")
    if target_mode:
        if target_mode not in VALID_MODES:
            plan.blockers.append(f"stp_mode '{target_mode}' is not automated (supported: {', '.join(VALID_MODES)})")
        elif current_mode is None:
            plan.notes.append("current STP mode unknown; mode not changed")
        elif current_mode == "mst":
            plan.blockers.append("switch runs MST; moving away from MST needs a manual design")
        elif current_mode != target_mode:
            plan.changes.append(
                Change(
                    kind="mode",
                    lines=[f"spanning-tree mode {target_mode}"],
                    rollback=[f"spanning-tree mode {current_mode}"],
                    reason=f"{current_mode} -> {target_mode}",
                    disruptive=True,
                )
            )

    priority = target_priority(policy)
    if priority is not None:
        if not valid_priority(priority):
            plan.blockers.append(f"bridge priority {priority!r} is invalid (0-61440 in steps of 4096)")
        elif (current_mode or target_mode) == "mst":
            plan.notes.append("MST priorities are not managed by this tool")
        else:
            vlan_spec = str(policy.get("stp_vlans") or "1-4094")
            vlans = expand_vlans(vlan_spec)
            current = _configured_priorities(device, vlans)
            differs = sorted(v for v, p in current.items() if p != priority)
            if differs:
                original = [
                    line for line in cfg.global_lines if line.startswith("spanning-tree vlan ") and " priority " in line
                ]
                plan.changes.append(
                    Change(
                        kind="priority",
                        lines=[f"spanning-tree vlan {vlan_spec} priority {priority}"],
                        rollback=[f"no spanning-tree vlan {vlan_spec} priority"] + original,
                        reason=f"bridge priority {priority} ({plan.role}); "
                        f"{len(differs)} VLAN(s) differ, e.g. {compress_vlans(differs[:20])}",
                        disruptive=True,
                    )
                )

    method = policy.get("stp_pathcost_method")
    if method:
        current_method = device.stp_summary.pathcost_method or cfg.pathcost_method or "short"
        if current_method != method:
            plan.changes.append(
                Change(
                    kind="pathcost",
                    lines=[f"spanning-tree pathcost method {method}"],
                    rollback=[f"spanning-tree pathcost method {current_method}"],
                    reason=f"path cost method {current_method} -> {method}",
                    disruptive=True,
                )
            )

    # ports that must still be up after the change
    facing = topology.switch_facing_ports(device.host)
    root_ports = {inst.root_port for inst in device.stp.values() if inst.root_port}
    verify = set()
    for port in facing | root_ports:
        status = device.interfaces.get(port)
        if status is not None and status.status == "connected":
            verify.add(port)
    plan.verify_ports = sorted((short_interface(p) for p in verify), key=interface_sort_key)
    return plan


def plan_site(
    topology: Topology,
    policies: dict[str, dict[str, Any]],
    edge_map: dict[str, list[EdgePort]],
) -> SitePlan:
    hosts: dict[str, HostPlan] = {}
    warnings: list[str] = []
    for host, device in sorted(topology.devices.items()):
        hosts[host] = plan_host(device, topology, policies[host], edge_map.get(host, []))

    # Cross-switch sanity: will the intended root actually win after the change?
    for site, devices in topology.by_site.items():
        primary = next((d for d in devices if policies[d.host].get("stp_role") == "root_primary"), None)
        secondaries = [d for d in devices if policies[d.host].get("stp_role") == "root_secondary"]
        if len([d for d in devices if policies[d.host].get("stp_role") == "root_primary"]) > 1:
            warnings.append(f"site {site}: more than one switch has stp_role root_primary")
        if primary is None:
            continue
        p_target = target_priority(policies[primary.host])
        if not valid_priority(p_target):
            continue
        vlans = expand_vlans(str(policies[primary.host].get("stp_vlans") or "1-4094"))
        for device in devices:
            if device is primary:
                continue
            pol = policies[device.host]
            future = target_priority(pol)
            active = _active_vlans(device) & vlans
            if future is not None and valid_priority(future):
                conflicts = sorted(active) if future <= p_target else []
            else:
                current = _configured_priorities(device, active)
                conflicts = sorted(v for v, p in current.items() if p <= p_target)
            if conflicts:
                msg = (
                    f"site {site}: {device.host} has priority <= {p_target} on VLAN(s) {compress_vlans(conflicts)}; "
                    f"{primary.host} would not become root there. Set stp_priority_other (or stp_priority on "
                    f"{device.host}) to a higher value."
                )
                warnings.append(msg)
                hosts[primary.host].blockers.append(msg)
        for secondary in secondaries:
            s_target = target_priority(policies[secondary.host])
            if valid_priority(s_target) and s_target <= p_target:
                warnings.append(
                    f"site {site}: root_secondary {secondary.host} priority {s_target} is not higher than "
                    f"root_primary {primary.host} ({p_target})"
                )

    # Apply order: one access switch as canary, then the primary root, the
    # secondary, then everything else.
    order: list[str] = []
    changing = {h for h, p in hosts.items() if p.has_changes and not p.blockers}
    by_role = defaultdict(list)
    for host in sorted(changing):
        by_role[hosts[host].role].append(host)
    canary_pool = [h for h in by_role.get("access", []) if not hosts[h].disruptive] or by_role.get("access", [])
    if canary_pool:
        order.append(canary_pool[0])
    order += by_role.get("root_primary", []) + by_role.get("root_secondary", [])
    order += [h for h in sorted(changing) if h not in order]
    for index, host in enumerate(order, 1):
        hosts[host].order = index
    return SitePlan(hosts=hosts, apply_order=order, warnings=warnings)

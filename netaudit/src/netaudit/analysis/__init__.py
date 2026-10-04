"""Run every check over a set of parsed devices."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from ..model import Device
from . import checks
from .edge import EdgePort, edge_ports
from .findings import SEVERITIES, Finding
from .policy import policy_for
from .tc import TcTrace, trace_all
from .topology import Topology, VlanView

if TYPE_CHECKING:  # pragma: no cover - the planner imports this package
    from ..planner import SitePlan


@dataclass
class AuditResult:
    topology: Topology
    policies: dict[str, dict[str, Any]]
    edge: dict[str, list[EdgePort]]
    traces: list[TcTrace]
    findings: list[Finding]
    plan: SitePlan
    generated_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat(timespec="seconds"))

    @property
    def devices(self) -> dict[str, Device]:
        return self.topology.devices

    @property
    def views(self) -> dict[tuple[str, str], VlanView]:
        return self.topology.views

    def counts(self) -> dict[str, int]:
        counts = {s: 0 for s in SEVERITIES}
        for finding in self.findings:
            counts[finding.severity] = counts.get(finding.severity, 0) + 1
        return counts


def analyze(devices: list[Device], previous: list[Device] | None = None) -> AuditResult:
    from ..planner import plan_site

    topology = Topology(devices, previous)
    policies = {d.host: policy_for(d) for d in devices}
    edge = {d.host: edge_ports(d, topology, policies[d.host]) for d in devices if d.reachable}
    traces = trace_all(topology)
    findings: list[Finding] = []
    findings += checks.check_collection(topology)
    findings += checks.check_modes(topology, policies)
    findings += checks.check_roots(topology, policies)
    findings += checks.check_topology_changes(topology, traces, policies, edge)
    findings += checks.check_edge_ports(topology, edge, policies)
    findings += checks.check_port_states(topology)
    findings += checks.check_logs(topology)
    findings += checks.check_config(topology, policies)
    findings += checks.check_trunks(topology)
    findings.sort(key=lambda f: (f.rank, f.site, f.host or "", f.category, f.title))
    plan = plan_site(topology, policies, edge)
    return AuditResult(
        topology=topology,
        policies=policies,
        edge=edge,
        traces=traces,
        findings=findings,
        plan=plan,
    )

"""Edge (host-facing) port compliance: PortFast + BPDU Guard, and when NOT to touch a port."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from ..model import Device
from ..util import interface_sort_key

if TYPE_CHECKING:  # pragma: no cover
    from .topology import Topology


@dataclass
class EdgePort:
    port: str
    vlan: int | None
    status: str
    portfast_ok: bool
    bpduguard_ok: bool
    bpdu_received: int = 0
    roles: set[str] = field(default_factory=set)
    switch_neighbor: str | None = None
    bpdufilter: bool = False
    transitions: int | None = None
    exclude_reason: str | None = None
    trunk: bool = False

    @property
    def compliant(self) -> bool:
        return self.portfast_ok and self.bpduguard_ok


def edge_ports(device: Device, topology: Topology, policy: dict[str, Any]) -> list[EdgePort]:
    """Return every explicitly configured access port (plus opted-in edge trunks)."""
    cfg = device.config
    results = []
    switch_ports = {link.port: link.neighbor_name for link in topology.links.get(device.host, [])} | {
        link.stp_port: link.neighbor_name for link in topology.links.get(device.host, [])
    }
    edge_trunks = set(policy.get("stp_edge_trunks") or [])
    for name, iface in sorted(cfg.interfaces.items(), key=lambda kv: interface_sort_key(kv[0])):
        is_access = iface.mode == "access"
        is_edge_trunk = name in edge_trunks
        if not (is_access or is_edge_trunk) or iface.channel_group is not None:
            continue
        details = [inst.port_details[name] for inst in device.stp.values() if name in inst.port_details]
        rows = [inst.ports[name] for inst in device.stp.values() if name in inst.ports]
        oper_portfast = any(d.portfast for d in details) or any(r.edge for r in rows)
        oper_bpduguard = any(d.bpduguard for d in details)
        if is_edge_trunk:
            portfast_ok = iface.portfast == "trunk"
        else:
            portfast_ok = iface.portfast in ("edge", "trunk") or (
                cfg.portfast_default and iface.portfast not in ("disable", "network")
            )
            portfast_ok = portfast_ok or oper_portfast
        bpduguard_ok = (
            iface.bpduguard == "enable"
            or (cfg.bpduguard_default and portfast_ok and iface.bpduguard != "disable")
            or oper_bpduguard
        )
        status = device.interfaces.get(name)
        port = EdgePort(
            port=name,
            vlan=iface.access_vlan if is_access else None,
            status=status.status if status else ("disabled" if iface.shutdown else ""),
            portfast_ok=portfast_ok,
            bpduguard_ok=bpduguard_ok,
            bpdu_received=max((d.bpdu_received or 0 for d in details), default=0),
            roles={r.role for r in rows},
            switch_neighbor=switch_ports.get(name),
            bpdufilter=iface.bpdufilter == "enable" or any(d.bpdufilter for d in details),
            transitions=max((d.transitions for d in details if d.transitions is not None), default=None),
            trunk=is_edge_trunk,
        )
        port.exclude_reason = _exclude_reason(port, iface, policy)
        results.append(port)
    return results


def _exclude_reason(port: EdgePort, iface, policy: dict[str, Any]) -> str | None:
    if port.port in policy.get("stp_edge_exclude", set()):
        return "excluded by policy (stp_edge_exclude)"
    if port.switch_neighbor:
        return f"CDP/LLDP shows a switch here ({port.switch_neighbor})"
    if port.bpdu_received and policy.get("stp_edge_skip_bpdu_seen", True):
        return f"has received {port.bpdu_received} BPDUs - something running STP is attached"
    blocking_roles = port.roles & {"Root", "Altn", "Back"}
    if blocking_roles:
        return f"STP role {'/'.join(sorted(blocking_roles))} means BPDUs are arriving on this port"
    if iface.portfast == "disable":
        return "PortFast explicitly disabled on the interface"
    if iface.bpduguard == "disable":
        return "BPDU Guard explicitly disabled on the interface"
    return None

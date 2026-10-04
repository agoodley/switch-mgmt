"""Follow spanning-tree topology changes back to the port that caused them.

Every switch records, per VLAN, how many topology changes (TCs) it has seen,
when the last one happened and on which port it arrived ("from Gi1/0/49").
Starting anywhere in the VLAN and repeatedly hopping to the switch on that
port leads to the switch where the TC originated; there "from" is the local
port whose state changed - typically a flapping host port without PortFast.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..util import short_interface
from .topology import Topology, VlanView, _parse_time


@dataclass
class TcHop:
    host: str
    tc_count: int | None
    tc_last_seconds: int | None
    from_port: str | None


@dataclass
class TcTrace:
    site: str
    instance: str
    vlan: int | None
    hops: list[TcHop] = field(default_factory=list)
    origin_host: str | None = None
    origin_port: str | None = None
    origin_kind: str = "unknown"  # access-port | switch-link | external | unknown | loop
    origin_neighbor: str | None = None
    last_seconds: int | None = None
    consistent: bool = True

    @property
    def path(self) -> str:
        return " → ".join(
            f"{h.host}" + (f" ({short_interface(h.from_port)})" if h.from_port else "") for h in self.hops
        )


def trace_view(topology: Topology, view: VlanView) -> TcTrace | None:
    candidates = [s for s in view.switches.values() if s.tc_from and s.tc_count]
    if not candidates:
        return None
    root_state = view.switches.get(view.root_host or "")
    start = (
        root_state
        if root_state in candidates
        else min(candidates, key=lambda s: s.tc_last_seconds if s.tc_last_seconds is not None else 1 << 62)
    )
    trace = TcTrace(site=view.site, instance=view.instance, vlan=view.vlan)
    visited: set[str] = set()
    state = start
    event_times: list[float] = []
    while state is not None:
        visited.add(state.host)
        trace.hops.append(TcHop(state.host, state.tc_count, state.tc_last_seconds, state.tc_from))
        device = topology.devices[state.host]
        collected = _parse_time(device.collected_at)
        if collected is not None and state.tc_last_seconds is not None:
            event_times.append(collected.timestamp() - state.tc_last_seconds)
        port = state.tc_from
        if not port:
            trace.origin_host, trace.origin_kind = state.host, "unknown"
            break
        neighbor_host, link = topology.neighbor_host_on(state.host, port)
        if neighbor_host and neighbor_host in view.switches:
            previous = trace.hops[-2].host if len(trace.hops) > 1 else None
            if neighbor_host == previous:
                # Both ends point at each other: the link between them changed state.
                trace.origin_host, trace.origin_port, trace.origin_kind = state.host, port, "switch-link"
                trace.origin_neighbor = neighbor_host
                break
            if neighbor_host in visited:
                trace.origin_host, trace.origin_port, trace.origin_kind = state.host, port, "loop"
                break
            state = view.switches[neighbor_host]
            continue
        trace.origin_host, trace.origin_port = state.host, port
        if link is not None:
            trace.origin_kind = "external"
            trace.origin_neighbor = link.neighbor_name
        else:
            iface = device.config.interfaces.get(port)
            trace.origin_kind = "switch-link" if iface is not None and iface.mode == "trunk" else "access-port"
        break
    last = [h.tc_last_seconds for h in trace.hops if h.tc_last_seconds is not None]
    trace.last_seconds = min(last) if last else None
    if len(event_times) > 1:
        trace.consistent = max(event_times) - min(event_times) <= 180
    return trace


def trace_all(topology: Topology) -> list[TcTrace]:
    traces = []
    for view in topology.views.values():
        trace = trace_view(topology, view)
        if trace is not None:
            traces.append(trace)
    return traces

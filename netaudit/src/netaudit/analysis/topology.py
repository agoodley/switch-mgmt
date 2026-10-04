"""Cross-switch views: who is connected to whom, and what each VLAN's STP tree looks like."""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import UTC, datetime

from ..model import Device, Neighbor
from ..util import canonical_interface, short_hostname, vlan_from_instance


@dataclass
class Link:
    """A switch-to-switch adjacency learned from CDP/LLDP, seen from ``host``."""

    host: str
    port: str  # physical port on host (canonical)
    stp_port: str  # port STP runs on (the port-channel for bundled links)
    neighbor_name: str  # as advertised
    neighbor_host: str | None  # audited host name, if we know it
    neighbor_port: str
    neighbor: Neighbor


@dataclass
class SwitchVlanState:
    host: str
    protocol: str
    root_mac: str
    root_priority: int | None
    root_cost: int | None
    root_port: str | None
    is_root: bool
    bridge_mac: str
    bridge_priority: int | None
    bridge_priority_base: int | None
    tc_count: int | None
    tc_last_seconds: int | None
    tc_from: str | None
    blocked_ports: list[str] = field(default_factory=list)
    # topology changes since the previous audit run (None = no comparable data)
    tc_delta: int | None = None
    tc_delta_seconds: float | None = None


@dataclass
class TreeNode:
    host: str
    parent: str | None = None  # audited host, "external:<name>" or None for the root
    via_port: str | None = None  # this host's root port
    parent_port: str | None = None  # port on the parent facing this host
    depth: int = 0


@dataclass
class VlanView:
    site: str
    instance: str
    vlan: int | None
    switches: dict[str, SwitchVlanState] = field(default_factory=dict)
    roots_seen: dict[str, list[str]] = field(default_factory=dict)  # root mac -> hosts
    root_mac: str = ""
    root_priority: int | None = None
    root_host: str | None = None
    expected_root: str | None = None
    expected_backup: str | None = None
    tree: dict[str, TreeNode] = field(default_factory=dict)
    blocked_links: list[tuple[str, str, str | None, str]] = field(default_factory=list)


class Topology:
    """Indexes over all audited devices, shared by every check."""

    def __init__(self, devices: list[Device], previous: list[Device] | None = None):
        self.devices: dict[str, Device] = {d.host: d for d in devices}
        self.by_site: dict[str, list[Device]] = defaultdict(list)
        for device in devices:
            self.by_site[device.site or "default"].append(device)
        self._name_index = self._build_name_index()
        self.mac_to_host: dict[str, str] = {}
        for device in devices:
            for inst in device.stp.values():
                if inst.bridge_mac:
                    self.mac_to_host.setdefault(inst.bridge_mac, device.host)
        self.links: dict[str, list[Link]] = {d.host: self._links_for(d) for d in devices}
        self.views: dict[tuple[str, str], VlanView] = self._build_views()
        self.previous_run: str | None = None
        if previous:
            self._attach_previous(previous)

    # -- neighbour resolution -------------------------------------------------
    def _build_name_index(self) -> dict[str, str]:
        index: dict[str, str] = {}
        for device in self.devices.values():
            for name in (device.host, device.version.hostname, device.config.hostname):
                if name:
                    index.setdefault(short_hostname(name), device.host)
            ip = str(device.intent.get("ansible_host") or "")
            if ip:
                index.setdefault(ip, device.host)
        return index

    def resolve(self, neighbor: Neighbor) -> str | None:
        """Map a CDP/LLDP neighbour onto an audited host, by name then by IP."""
        host = self._name_index.get(short_hostname(neighbor.remote_name))
        if host is None and neighbor.mgmt_ip:
            host = self._name_index.get(neighbor.mgmt_ip)
        return host

    def _links_for(self, device: Device) -> list[Link]:
        links = []
        for neighbor in device.neighbors:
            if not neighbor.local_port:
                continue
            resolved = self.resolve(neighbor)
            if resolved is None and not neighbor.is_switch:
                continue
            if resolved == device.host:
                continue
            links.append(
                Link(
                    host=device.host,
                    port=neighbor.local_port,
                    stp_port=device.channel_of(neighbor.local_port) or neighbor.local_port,
                    neighbor_name=neighbor.remote_name,
                    neighbor_host=resolved,
                    neighbor_port=neighbor.remote_port,
                    neighbor=neighbor,
                )
            )
        return links

    def links_on(self, host: str, stp_port: str) -> list[Link]:
        return [link for link in self.links.get(host, []) if link.stp_port == stp_port or link.port == stp_port]

    def neighbor_host_on(self, host: str, stp_port: str | None) -> tuple[str | None, Link | None]:
        if not stp_port:
            return None, None
        links = self.links_on(host, stp_port)
        for link in links:
            if link.neighbor_host:
                return link.neighbor_host, link
        return (None, links[0]) if links else (None, None)

    def switch_facing_ports(self, host: str) -> set[str]:
        """STP ports (canonical) that face another switch according to CDP/LLDP."""
        return {link.stp_port for link in self.links.get(host, [])}

    # -- per-VLAN views ---------------------------------------------------------
    def _build_views(self) -> dict[tuple[str, str], VlanView]:
        views: dict[tuple[str, str], VlanView] = {}
        for site, devices in self.by_site.items():
            primary = next((d.host for d in devices if d.role == "root_primary"), None)
            backup = next((d.host for d in devices if d.role == "root_secondary"), None)
            for device in devices:
                for name, inst in device.stp.items():
                    key = (site, name)
                    view = views.get(key)
                    if view is None:
                        view = views[key] = VlanView(
                            site=site,
                            instance=name,
                            vlan=vlan_from_instance(name),
                            expected_root=primary,
                            expected_backup=backup,
                        )
                    blocked = sorted(
                        p.port for p in inst.ports.values() if p.state in ("BLK", "BKN") or p.role in ("Altn", "Back")
                    )
                    view.switches[device.host] = SwitchVlanState(
                        host=device.host,
                        protocol=inst.protocol,
                        root_mac=inst.root_mac,
                        root_priority=inst.root_priority,
                        root_cost=inst.root_cost,
                        root_port=inst.root_port,
                        is_root=inst.is_root,
                        bridge_mac=inst.bridge_mac,
                        bridge_priority=inst.bridge_priority,
                        bridge_priority_base=inst.bridge_priority_base,
                        tc_count=inst.tc_count,
                        tc_last_seconds=inst.tc_last_seconds,
                        tc_from=inst.tc_from,
                        blocked_ports=blocked,
                    )
                    if inst.root_mac:
                        view.roots_seen.setdefault(inst.root_mac, []).append(device.host)
        for view in views.values():
            self._resolve_root(view)
            self._build_tree(view)
        return views

    def _attach_previous(self, previous: list[Device]) -> None:
        """Topology-change counters of the previous audit give the *current* rate."""
        before = {d.host: d for d in previous if d.reachable}
        for view in self.views.values():
            for host, state in view.switches.items():
                old = before.get(host)
                now = self.devices[host]
                if old is None or state.tc_count is None:
                    continue
                old_inst = old.stp.get(view.instance)
                t_old, t_now = _parse_time(old.collected_at), _parse_time(now.collected_at)
                if old_inst is None or old_inst.tc_count is None or t_old is None or t_now is None:
                    continue
                elapsed = (t_now - t_old).total_seconds()
                uptime = now.version.uptime_seconds
                if elapsed <= 0 or state.tc_count < old_inst.tc_count or (uptime is not None and uptime < elapsed):
                    continue  # counters were reset (reload or STP restart)
                state.tc_delta = state.tc_count - old_inst.tc_count
                state.tc_delta_seconds = elapsed
                self.previous_run = old.collected_at

    def _resolve_root(self, view: VlanView) -> None:
        if not view.roots_seen:
            return
        counts = Counter({mac: len(hosts) for mac, hosts in view.roots_seen.items()})
        view.root_mac = counts.most_common(1)[0][0]
        view.root_host = self.mac_to_host.get(view.root_mac)
        priorities = [s.root_priority for s in view.switches.values() if s.root_mac == view.root_mac]
        view.root_priority = priorities[0] if priorities else None

    def _build_tree(self, view: VlanView) -> None:
        for host, state in view.switches.items():
            node = TreeNode(host=host)
            if state.is_root:
                view.tree[host] = node
                continue
            node.via_port = state.root_port
            parent, link = self.neighbor_host_on(host, state.root_port)
            if parent and parent in view.switches:
                node.parent = parent
                node.parent_port = self._reverse_port(parent, host, link)
            elif link is not None:
                node.parent = f"external:{link.neighbor_name}"
                node.parent_port = link.neighbor_port
            else:
                node.parent = f"external:unknown via {state.root_port or '?'}"
            view.tree[host] = node
        # depth, guarding against loops in inconsistent snapshots
        for host, node in view.tree.items():
            depth, seen, cur = 0, {host}, node
            while cur.parent and cur.parent in view.tree and cur.parent not in seen:
                seen.add(cur.parent)
                cur = view.tree[cur.parent]
                depth += 1
            node.depth = depth + (1 if cur.parent and cur.parent.startswith("external:") else 0)
        # blocked links: (host, port, neighbour host or None, neighbour name)
        for host, state in view.switches.items():
            for port in state.blocked_ports:
                neighbor_host, link = self.neighbor_host_on(host, port)
                view.blocked_links.append((host, port, neighbor_host, link.neighbor_name if link else ""))

    def _reverse_port(self, parent: str, child: str, link: Link | None) -> str | None:
        """The parent's STP port that faces ``child`` (the far end of the child's root port)."""
        if link is not None and link.neighbor_port:
            port = canonical_interface(link.neighbor_port)
            parent_device = self.devices.get(parent)
            return (parent_device.channel_of(port) if parent_device else None) or port
        for candidate in self.links.get(parent, []):
            if candidate.neighbor_host == child:
                return candidate.stp_port
        return None


def _parse_time(stamp: str) -> datetime | None:
    if not stamp:
        return None
    stamp = stamp.strip()
    if stamp.endswith("Z") and ("+" in stamp[10:] or stamp.count("-") > 2):
        stamp = stamp[:-1]
    try:
        value = datetime.fromisoformat(stamp.replace("Z", "+00:00"))
    except ValueError:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value

"""Parsers for Cisco IOS / IOS-XE spanning-tree show commands.

Written to be lenient: unknown lines are ignored rather than raising, because
output differs slightly between 12.2, 15.x and IOS-XE 16/17 trains.
"""

from __future__ import annotations

import re

from ..model import StpInstance, StpPort, StpPortDetail, StpSummary
from ..util import canonical_interface, normalize_mac, parse_ios_duration, vlan_from_instance

_INSTANCE_HEADER = re.compile(r"^(VLAN\d+|MST\d+)\s*$")
_PROTOCOL = re.compile(r"Spanning tree enabled protocol (\S+)", re.I)
_ROOT_ID = re.compile(r"Root ID\s+Priority\s+(\d+)")
_BRIDGE_ID = re.compile(r"Bridge ID\s+Priority\s+(\d+)(?:\s+\(priority (\d+) sys-id-ext (\d+)\))?")
_ADDRESS = re.compile(r"^\s+Address\s+([0-9a-fA-F.:\-]+)")
_COST = re.compile(r"^\s+Cost\s+(\d+)")
_PORT = re.compile(r"^\s+Port\s+\d+\s+\((\S+)\)")
_TIMERS = re.compile(r"Hello Time\s+(\d+) sec\s+Max Age\s+(\d+) sec\s+Forward Delay\s+(\d+) sec")
_PORT_ROW = re.compile(
    r"^(?P<port>\S+)\s+(?P<role>[A-Z][a-z]{3})\s+(?P<state>[A-Z]{3})(?P<star>\*)?\s*"
    r"(?P<cost>\d+)\s+(?P<prio>\d+)\.(?P<num>\d+)\s*(?P<type>.*?)\s*$"
)
_INCONSISTENT = re.compile(r"\*(\w+?)(?:_Inc)?\b")


def parse_spanning_tree(text: str) -> dict[str, StpInstance]:
    """Parse plain `show spanning-tree` output into instances keyed by name."""
    instances: dict[str, StpInstance] = {}
    current: StpInstance | None = None
    section = None  # "root" | "bridge" | "ports"
    for line in text.splitlines():
        header = _INSTANCE_HEADER.match(line.strip()) if not line.startswith(" ") else None
        if header:
            name = header.group(1)
            current = instances.setdefault(name, StpInstance(name=name, vlan=vlan_from_instance(name)))
            section = None
            continue
        if current is None:
            continue
        if m := _PROTOCOL.search(line):
            current.protocol = m.group(1).lower()
            continue
        if m := _ROOT_ID.search(line):
            current.root_priority = int(m.group(1))
            section = "root"
            continue
        if m := _BRIDGE_ID.search(line):
            current.bridge_priority = int(m.group(1))
            if m.group(2) is not None:
                current.bridge_priority_base = int(m.group(2))
                current.bridge_sysid = int(m.group(3))
            section = "bridge"
            continue
        if m := _ADDRESS.match(line):
            mac = normalize_mac(m.group(1))
            if section == "root":
                current.root_mac = mac
            elif section == "bridge":
                current.bridge_mac = mac
            continue
        if section == "root":
            if m := _COST.match(line):
                current.root_cost = int(m.group(1))
                continue
            if m := _PORT.match(line):
                current.root_port = canonical_interface(m.group(1))
                continue
            if "This bridge is the root" in line:
                current.is_root = True
                current.root_cost = 0
                continue
        if m := _TIMERS.search(line):
            if section == "root" or current.hello is None:
                current.hello, current.max_age, current.forward_delay = (int(x) for x in m.groups())
            continue
        if line.startswith("Interface") and "Role" in line:
            section = "ports"
            continue
        if section == "ports" and (m := _PORT_ROW.match(line)):
            port = _port_from_row(current.name, m)
            current.ports[port.port] = port
    for inst in instances.values():
        _finalise_instance(inst)
    return instances


def _port_from_row(instance: str, m: re.Match) -> StpPort:
    type_text = m.group("type") or ""
    state = m.group("state")
    inconsistent = None
    inc = _INCONSISTENT.search(type_text)
    if inc:
        inconsistent = inc.group(1).upper()
    elif m.group("star") or state == "BKN":
        inconsistent = "BKN"
    peer = None
    peer_match = re.search(r"((?:Peer|Bound)\(\w+\))", type_text)
    if peer_match:
        peer = peer_match.group(1)
    return StpPort(
        instance=instance,
        port=canonical_interface(m.group("port")),
        role=m.group("role"),
        state=state,
        cost=int(m.group("cost")),
        priority=int(m.group("prio")),
        number=int(m.group("num")),
        type=type_text,
        edge="Edge" in type_text,
        p2p="Shr" not in type_text,
        inconsistent=inconsistent,
        peer=peer,
    )


def _finalise_instance(inst: StpInstance) -> None:
    if inst.root_mac and inst.bridge_mac and inst.root_mac == inst.bridge_mac:
        inst.is_root = True
    if inst.bridge_priority is not None and inst.bridge_priority_base is None:
        # Older output without "(priority X sys-id-ext Y)": derive it.
        sysid = inst.vlan if inst.vlan is not None else 0
        if inst.bridge_priority - sysid >= 0 and (inst.bridge_priority - sysid) % 4096 == 0:
            inst.bridge_priority_base = inst.bridge_priority - sysid
            inst.bridge_sysid = sysid
        else:
            inst.bridge_priority_base = inst.bridge_priority


_DETAIL_HEADER = re.compile(r"^\s*(VLAN\d+|MST\d+) is executing the (\S+) compatible Spanning Tree protocol", re.I)
_DETAIL_BRIDGE = re.compile(r"Bridge Identifier has priority (\d+), sysid (\d+), address ([0-9a-fA-F.]+)")
_DETAIL_ROOT = re.compile(r"Current root has priority (\d+), address ([0-9a-fA-F.]+)")
_DETAIL_ROOT_PORT = re.compile(r"Root port is \d+ \((\S+)\), cost of root path is (\d+)")
_DETAIL_TC = re.compile(r"Number of topology changes (\d+) last change occurred (\S+)(?: ago)?")
_DETAIL_FROM = re.compile(r"^\s+from (\S+)\s*$")
_DETAIL_PORT = re.compile(r"^\s*Port \d+ \((\S+)\) of (VLAN\d+|MST\d+) is (.+?)\s*$")
_DETAIL_BPDU = re.compile(r"BPDU: sent (\d+), received (\d+)")
_DETAIL_TRANSITIONS = re.compile(r"Number of transitions to forwarding state: (\d+)")
_DETAIL_DESIG_BRIDGE = re.compile(r"Designated bridge has priority (\d+), address ([0-9a-fA-F.]+)")


def parse_spanning_tree_detail(text: str, instances: dict[str, StpInstance] | None = None) -> dict[str, StpInstance]:
    """Parse `show spanning-tree detail`.

    Merges into ``instances`` (from :func:`parse_spanning_tree`) when given so
    that the topology-change counters and per-port BPDU counters end up on the
    same objects.
    """
    instances = instances if instances is not None else {}
    current: StpInstance | None = None
    port: StpPortDetail | None = None
    expect_from = False
    for line in text.splitlines():
        if m := _DETAIL_HEADER.match(line):
            name = m.group(1)
            current = instances.setdefault(name, StpInstance(name=name, vlan=vlan_from_instance(name)))
            if not current.protocol:
                current.protocol = m.group(2).lower()
            port = None
            expect_from = False
            continue
        if m := _DETAIL_PORT.match(line):
            name = m.group(2)
            current = instances.setdefault(name, StpInstance(name=name, vlan=vlan_from_instance(name)))
            iface = canonical_interface(m.group(1))
            port = current.port_details.setdefault(iface, StpPortDetail(instance=name, port=iface))
            port.status = m.group(3)
            expect_from = False
            continue
        if current is None:
            continue
        if port is None:
            # Bridge-level section.
            if m := _DETAIL_BRIDGE.search(line):
                base, sysid, mac = int(m.group(1)), int(m.group(2)), normalize_mac(m.group(3))
                current.bridge_priority_base = current.bridge_priority_base or base
                current.bridge_sysid = current.bridge_sysid if current.bridge_sysid is not None else sysid
                if current.bridge_priority is None:
                    current.bridge_priority = base + sysid
                current.bridge_mac = current.bridge_mac or mac
                continue
            if m := _DETAIL_ROOT.search(line):
                if current.root_priority is None:
                    current.root_priority = int(m.group(1))
                current.root_mac = current.root_mac or normalize_mac(m.group(2))
                continue
            if "We are the root of the spanning tree" in line:
                current.is_root = True
                current.root_cost = 0
                continue
            if m := _DETAIL_ROOT_PORT.search(line):
                current.root_port = current.root_port or canonical_interface(m.group(1))
                if current.root_cost is None:
                    current.root_cost = int(m.group(2))
                continue
            if "Topology change flag set" in line:
                current.tc_in_progress = True
                continue
            if m := _DETAIL_TC.search(line):
                current.tc_count = int(m.group(1))
                current.tc_last_seconds = parse_ios_duration(m.group(2))
                expect_from = True
                continue
            if expect_from:
                expect_from = False
                if m := _DETAIL_FROM.match(line):
                    current.tc_from = canonical_interface(m.group(1))
                    continue
            continue
        # Port-level section.
        lower = line.lower()
        if m := _DETAIL_BPDU.search(line):
            port.bpdu_sent, port.bpdu_received = int(m.group(1)), int(m.group(2))
        elif m := _DETAIL_TRANSITIONS.search(line):
            port.transitions = int(m.group(1))
        elif m := _DETAIL_DESIG_BRIDGE.search(line):
            port.designated_bridge_priority = int(m.group(1))
            port.designated_bridge_mac = normalize_mac(m.group(2))
        elif "the port is in the portfast" in lower and "network" not in lower:
            port.portfast = True
        elif lower.strip().startswith("bpdu guard is enabled"):
            port.bpduguard = True
        elif lower.strip().startswith("bpdu filter is enabled"):
            port.bpdufilter = True
        elif lower.strip().startswith("root guard is enabled"):
            port.root_guard = True
        elif lower.strip().startswith("loop guard is enabled"):
            port.loop_guard = True
    for inst in instances.values():
        _finalise_instance(inst)
    return instances


_SUMMARY_MODE = re.compile(r"Switch is in (\S+) mode", re.I)
_SUMMARY_FLAG = re.compile(r"^(?P<key>[A-Za-z][A-Za-z /\-]*?)\s+is\s+(?P<value>.+?)\s*$")
_SUMMARY_COUNTS = re.compile(r"^(VLAN\d+|MST\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*$")


def _flag_value(value: str) -> str:
    value = value.lower()
    if "inactive" in value:
        return "inactive"
    if value.startswith("enabled"):
        return "enabled"
    if value.startswith("disabled"):
        return "disabled"
    return value.split()[0] if value else value


def parse_spanning_tree_summary(text: str) -> StpSummary:
    summary = StpSummary()
    root_lines: list[str] = []
    in_root = False
    for line in text.splitlines():
        if m := _SUMMARY_MODE.search(line):
            summary.mode = m.group(1).lower()
            continue
        stripped = line.strip()
        if stripped.lower().startswith("root bridge for:"):
            in_root = True
            root_lines.append(stripped.split(":", 1)[1])
            continue
        if in_root:
            if line.startswith(" ") and not _SUMMARY_FLAG.match(stripped):
                root_lines.append(stripped)
                continue
            in_root = False
        if m := _SUMMARY_COUNTS.match(stripped):
            summary.instance_counts[m.group(1)] = {
                "blocking": int(m.group(2)),
                "listening": int(m.group(3)),
                "learning": int(m.group(4)),
                "forwarding": int(m.group(5)),
                "active": int(m.group(6)),
            }
            continue
        if m := _SUMMARY_FLAG.match(stripped):
            key = re.sub(r"\s+", " ", m.group("key").strip().lower())
            raw_value = m.group("value").strip()
            summary.raw_flags[key] = raw_value
            value = _flag_value(raw_value)
            if "pathcost" in key:
                summary.pathcost_method = raw_value.split()[0].lower()
            elif "bpdu guard" in key:
                summary.bpduguard_default = value
            elif "bpdu filter" in key:
                summary.bpdufilter_default = value
            elif "portfast" in key and "default" in key:
                summary.portfast_default = value
            elif "loopguard" in key:
                summary.loopguard_default = value
            elif "uplinkfast" in key:
                summary.uplinkfast = value
            elif "backbonefast" in key:
                summary.backbonefast = value
            elif "extended system id" in key:
                summary.extended_system_id = value
            elif "etherchannel misconfig" in key:
                summary.etherchannel_guard = value
    roots = ",".join(root_lines)
    summary.root_for = [r.strip() for r in roots.split(",") if r.strip() and r.strip().lower() != "none"]
    return summary


def parse_mst_configuration(text: str) -> dict:
    """Parse `show spanning-tree mst configuration`."""
    result: dict = {"name": None, "revision": None, "instances": {}}
    in_table = False
    last_instance = None
    for line in text.splitlines():
        if m := re.match(r"^Name\s+\[(.*)\]", line):
            result["name"] = m.group(1)
            continue
        if m := re.match(r"^Revision\s+(\d+)", line):
            result["revision"] = int(m.group(1))
            continue
        if line.startswith("Instance") and "Vlans" in line:
            in_table = True
            continue
        if not in_table or line.startswith("---"):
            continue
        if m := re.match(r"^(\d+)\s+(\S+)\s*$", line):
            last_instance = int(m.group(1))
            result["instances"][last_instance] = m.group(2)
        elif last_instance is not None and line.startswith(" ") and line.strip():
            result["instances"][last_instance] += line.strip()
    return result

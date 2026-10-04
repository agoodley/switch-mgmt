"""A tiny editable model of an IOS running-config, used by the lab's fake switches."""

from __future__ import annotations

import re

from ..parsers.config import split_sections
from ..util import canonical_interface, compress_vlans, expand_vlans, interface_sort_key

# Global commands where a new value replaces the old one.
_GLOBAL_SINGLE = [
    r"hostname ",
    r"spanning-tree mode ",
    r"spanning-tree pathcost method ",
    r"errdisable recovery interval ",
    r"logging trap ",
    r"logging buffered",
    r"logging source-interface ",
    r"snmp-server location ",
    r"snmp-server contact ",
    r"service timestamps log ",
    r"service timestamps debug ",
    r"vtp mode ",
    r"vtp domain ",
    r"ip default-gateway ",
    r"clock timezone ",
]
# Interface commands where a new value replaces the old one.
_IFACE_SINGLE = [
    r"description ",
    r"switchport mode ",
    r"switchport access vlan ",
    r"switchport voice vlan ",
    r"switchport trunk native vlan ",
    r"switchport trunk allowed vlan ",
    r"spanning-tree portfast",
    r"spanning-tree bpduguard ",
    r"spanning-tree bpdufilter ",
    r"spanning-tree guard ",
    r"spanning-tree link-type ",
    r"spanning-tree cost ",
    r"spanning-tree port-priority ",
    r"speed ",
    r"duplex ",
    r"channel-group ",
    r"storm-control broadcast level",
    r"storm-control multicast level",
    r"storm-control action ",
    r"udld port",
    r"power inline ",
]

KNOWN_GLOBAL_KEYWORDS = {
    "aaa",
    "access-list",
    "alias",
    "archive",
    "banner",
    "boot",
    "cdp",
    "class-map",
    "clock",
    "crypto",
    "default",
    "device-tracking",
    "diagnostic",
    "do",
    "dot1x",
    "enable",
    "end",
    "errdisable",
    "exit",
    "hostname",
    "interface",
    "ip",
    "ipv6",
    "license",
    "line",
    "lldp",
    "logging",
    "mac",
    "macro",
    "mls",
    "monitor",
    "no",
    "ntp",
    "policy-map",
    "port-channel",
    "power",
    "redundancy",
    "router",
    "service",
    "snmp-server",
    "spanning-tree",
    "switch",
    "system",
    "tacacs",
    "tacacs-server",
    "radius",
    "radius-server",
    "udld",
    "username",
    "version",
    "vlan",
    "vtp",
    "file",
    "control-plane",
    "transceiver",
    "authentication",
    "call-home",
    "event",
    "track",
    "key",
    "login",
    "memory",
    "qos",
    "auto",
    "sdm",
    "stack-mac",
    "storm-control",
}


class ConfigTree:
    """Ordered (parent line, [children]) list with IOS-like editing semantics."""

    def __init__(self, text: str = ""):
        self.sections: list[tuple[str, list[str]]] = [(p, list(c)) for p, c in split_sections(text)]
        self.version = 0
        self._normalise_stp_priorities()

    # -- queries -----------------------------------------------------------------
    def text(self) -> str:
        globals_, interfaces, others = [], [], []
        for parent, children in self.sections:
            if parent.startswith("interface "):
                interfaces.append((parent, children))
            elif children:
                others.append((parent, children))
            else:
                globals_.append(parent)
        interfaces.sort(key=lambda pc: interface_sort_key(pc[0].split(None, 1)[1]))
        out: list[str] = []
        for line in globals_:
            if line in ("end",):
                continue
            out.append(line)
        out.append("!")
        trailing = [pc for pc in others if pc[0].startswith("line ")]
        others = [pc for pc in others if not pc[0].startswith("line ")]
        for parent, children in others + interfaces + trailing:
            out.append(parent)
            out.extend(f" {c}" for c in children)
            out.append("!")
        out.append("end")
        return "\n".join(out) + "\n"

    def interface(self, name: str) -> list[str] | None:
        parent = f"interface {canonical_interface(name)}"
        for p, children in self.sections:
            if p == parent:
                return children
        return None

    def section(self, parent: str, create: bool = False) -> list[str] | None:
        for p, children in self.sections:
            if p == parent:
                return children
        if create:
            children: list[str] = []
            self.sections.append((parent, children))
            return children
        return None

    def global_lines(self) -> list[str]:
        return [p for p, c in self.sections if not c]

    # -- edits -------------------------------------------------------------------
    def set_global(self, line: str) -> None:
        self.version += 1
        line = line.strip()
        if re.match(r"^spanning-tree vlan \S+ priority \d+$", line):
            vlans, priority = re.match(r"^spanning-tree vlan (\S+) priority (\d+)$", line).groups()
            self._set_stp_priority(expand_vlans(vlans), int(priority))
            return
        key = next((k for k in _GLOBAL_SINGLE if re.match(k, line)), None)
        if key:
            for i, (parent, children) in enumerate(self.sections):
                if not children and re.match(key, parent):
                    self.sections[i] = (line, children)
                    return
        if any(p == line and not c for p, c in self.sections):
            return
        self._insert_global(line)

    def remove_global(self, line: str) -> None:
        self.version += 1
        line = line.strip()
        if m := re.match(r"^spanning-tree vlan (\S+) priority(?: \d+)?$", line):
            self._set_stp_priority(expand_vlans(m.group(1)), None)
            return
        self.sections = [(p, c) for p, c in self.sections if c or not (p == line or p.startswith(line + " "))]

    def set_child(self, parent: str, line: str, edge_portfast: bool = False) -> None:
        self.version += 1
        children = self.section(parent, create=True)
        line = line.strip()
        if edge_portfast and line == "spanning-tree portfast":
            line = "spanning-tree portfast edge"
        key = next((k for k in _IFACE_SINGLE if re.match(k, line)), None)
        if line.startswith("spanning-tree portfast") and ("trunk" in line or "disable" in line or "network" in line):
            key = None
        if key:
            for i, child in enumerate(children):
                if re.match(key, child) and not (
                    key == "spanning-tree portfast" and ("trunk" in child or "disable" in child)
                ):
                    children[i] = line
                    return
        if line not in children:
            children.append(line)

    def remove_child(self, parent: str, line: str) -> None:
        self.version += 1
        children = self.section(parent)
        if children is None:
            return
        line = line.strip()
        prefix = line
        if line in ("spanning-tree bpduguard", "spanning-tree portfast", "spanning-tree guard root"):
            prefix = line.split(" ")[0] + " " + line.split(" ")[1]
        children[:] = [c for c in children if not (c == line or c.startswith(prefix + " ") or c == prefix)]

    # -- helpers -------------------------------------------------------------------
    def _insert_global(self, line: str) -> None:
        first = line.split()[0]
        insert_at = None
        for i, (parent, children) in enumerate(self.sections):
            if not children and parent.split()[0] == first:
                insert_at = i + 1
        if insert_at is None:
            insert_at = next(
                (i for i, (p, c) in enumerate(self.sections) if p.startswith("interface ")), len(self.sections)
            )
        self.sections.insert(insert_at, (line, []))

    def stp_priorities(self) -> dict[int, int]:
        result: dict[int, int] = {}
        for parent, children in self.sections:
            if children:
                continue
            if m := re.match(r"^spanning-tree vlan (\S+) priority (\d+)$", parent):
                for vlan in expand_vlans(m.group(1)):
                    result[vlan] = int(m.group(2))
        return result

    def _set_stp_priority(self, vlans: set[int], priority: int | None) -> None:
        current = self.stp_priorities()
        for vlan in vlans:
            if priority is None:
                current.pop(vlan, None)
            else:
                current[vlan] = priority
        self._write_stp_priorities(current)

    def _normalise_stp_priorities(self) -> None:
        self._write_stp_priorities(self.stp_priorities())

    def _write_stp_priorities(self, mapping: dict[int, int]) -> None:
        """IOS shows per-VLAN priorities grouped by value as compressed ranges."""
        position = None
        kept = []
        for parent, children in self.sections:
            if not children and re.match(r"^spanning-tree vlan \S+ priority \d+$", parent):
                if position is None:
                    position = len(kept)
                continue
            kept.append((parent, children))
        by_value: dict[int, list[int]] = {}
        for vlan, value in mapping.items():
            by_value.setdefault(value, []).append(vlan)
        lines = [
            (f"spanning-tree vlan {compress_vlans(v)} priority {value}", [])
            for value, v in sorted(by_value.items(), key=lambda kv: min(kv[1]))
        ]
        if position is None:
            position = next((i for i, (p, c) in enumerate(kept) if not c and p.startswith("spanning-tree")), None)
            position = position + 1 if position is not None else len(kept)
        self.sections = kept[:position] + lines + kept[position:]

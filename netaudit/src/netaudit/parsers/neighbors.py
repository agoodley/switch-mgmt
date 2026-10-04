"""Parsers for `show cdp neighbors detail` and `show lldp neighbors detail`."""

from __future__ import annotations

import re

from ..model import Neighbor
from ..util import canonical_interface

_IPV4 = re.compile(r"IP(?:v4)? [Aa]ddress\s*:\s*(\d+\.\d+\.\d+\.\d+)")


def _split_entries(text: str, marker: str) -> list[str]:
    entries: list[list[str]] = []
    current: list[str] | None = None
    for line in text.splitlines():
        if line.strip().startswith(marker):
            current = [line]
            entries.append(current)
        elif current is not None:
            current.append(line)
    return ["\n".join(e) for e in entries]


def parse_cdp_neighbors_detail(text: str) -> list[Neighbor]:
    neighbors = []
    for entry in _split_entries(text, "Device ID:"):
        name = re.search(r"Device ID:\s*(\S+)", entry)
        if not name:
            continue
        local = re.search(r"Interface:\s*([^,]+),\s*Port ID \(outgoing port\):\s*(.+)", entry)
        platform = re.search(r"Platform:\s*(.+?),\s*Capabilities:\s*(.*)", entry)
        mgmt_block = re.search(r"(?:Management|Mgmt) address\(es\)\s*:(.*?)(?=\n\S|\Z)", entry, re.S)
        mgmt_ip = ""
        if mgmt_block:
            ip = _IPV4.search(mgmt_block.group(1))
            mgmt_ip = ip.group(1) if ip else ""
        if not mgmt_ip:
            ip = _IPV4.search(entry)
            mgmt_ip = ip.group(1) if ip else ""
        native = re.search(r"Native VLAN:\s*(\d+)", entry)
        duplex = re.search(r"Duplex:\s*(\S+)", entry)
        version = re.search(r"Version\s*:\s*\n\s*(.+)", entry)
        neighbors.append(
            Neighbor(
                protocol="cdp",
                local_port=canonical_interface(local.group(1).strip()) if local else "",
                remote_name=name.group(1).strip(),
                remote_port=local.group(2).strip() if local else "",
                platform=platform.group(1).strip() if platform else "",
                capabilities=platform.group(2).split() if platform else [],
                mgmt_ip=mgmt_ip,
                native_vlan=int(native.group(1)) if native else None,
                duplex=duplex.group(1).strip().lower() if duplex else "",
                software=version.group(1).strip() if version else "",
            )
        )
    return neighbors


def parse_lldp_neighbors_detail(text: str) -> list[Neighbor]:
    neighbors = []
    for entry in _split_entries(text, "Local Intf:"):
        local = re.search(r"Local Intf:\s*(\S+)", entry)
        name = re.search(r"System Name:\s*(.+)", entry)
        port = re.search(r"Port id:\s*(.+)", entry)
        port_descr = re.search(r"Port Description:\s*(.+)", entry)
        caps = re.search(r"Enabled Capabilities:\s*(.+)", entry) or re.search(r"System Capabilities:\s*(.+)", entry)
        mgmt = re.search(r"Management Addresses:\s*\n\s*IP(?:v4)?:\s*(\d+\.\d+\.\d+\.\d+)", entry)
        vlan = re.search(r"Vlan ID:\s*(\d+)", entry)
        descr = re.search(r"System Description:\s*\n(.+)", entry)
        chassis = re.search(r"Chassis id:\s*(\S+)", entry)
        system_name = name.group(1).strip() if name else ""
        if "not advertised" in system_name:
            system_name = ""
        remote_name = system_name or (chassis.group(1) if chassis else "")
        if not local or not remote_name:
            continue
        remote_port = port.group(1).strip() if port else ""
        # Port id is sometimes a MAC; the description is then more useful.
        if port_descr and re.fullmatch(r"[0-9a-fA-F.:\-]{12,17}", remote_port):
            remote_port = port_descr.group(1).strip()
        capabilities = []
        if caps and caps.group(1).strip().lower() not in ("not advertised", "none"):
            capabilities = [c.strip().lower() for c in caps.group(1).split(",") if c.strip()]
        neighbors.append(
            Neighbor(
                protocol="lldp",
                local_port=canonical_interface(local.group(1)),
                remote_name=remote_name,
                remote_port=remote_port,
                platform=(descr.group(1).strip() if descr else ""),
                capabilities=capabilities,
                mgmt_ip=mgmt.group(1) if mgmt else "",
                native_vlan=int(vlan.group(1)) if vlan else None,
            )
        )
    return neighbors

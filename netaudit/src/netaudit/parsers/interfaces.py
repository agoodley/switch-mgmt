"""Parsers for `show interfaces status`, `... err-disabled` and `show interfaces trunk`."""

from __future__ import annotations

from ..model import InterfaceStatus, TrunkInfo
from ..util import canonical_interface

_KNOWN_STATUS = {
    "connected",
    "notconnect",
    "disabled",
    "err-disabled",
    "inactive",
    "monitoring",
    "suspended",
    "sfpabsent",
    "xcvrabsent",
    "noopermem",
    "faulty",
    "down",
    "up",
}


def _vlan_like(token: str) -> bool:
    return token in ("trunk", "routed", "unassigned", "pvlan") or token.replace(",", "").isdigit()


def _header_columns(header: str, names: list[str]) -> dict[str, int]:
    cols = {}
    for name in names:
        idx = header.find(name)
        if idx >= 0:
            cols[name] = idx
    return cols


def parse_interfaces_status(text: str) -> dict[str, InterfaceStatus]:
    """Parse `show interfaces status` using the header's column positions."""
    result: dict[str, InterfaceStatus] = {}
    cols: dict[str, int] | None = None
    for line in text.splitlines():
        if line.startswith("Port") and "Status" in line and "Vlan" in line:
            cols = _header_columns(line, ["Port", "Name", "Status", "Vlan", "Duplex", "Speed", "Type"])
            continue
        if cols is None or not line.strip() or line.startswith("-"):
            continue
        tokens = line.split()
        port = tokens[0]
        status_col = cols.get("Status", 0)
        name = line[len(port) : status_col].strip() if len(line) > status_col else ""
        rest = line[status_col:].split() if len(line) > status_col else []
        if not rest or rest[0].lower().rstrip(":") not in _KNOWN_STATUS:
            # Column drift (very long names): find the first known status word.
            idx = next((i for i, t in enumerate(tokens[1:], 1) if t.lower().rstrip(":") in _KNOWN_STATUS), None)
            if idx is None:
                continue
            name = " ".join(tokens[1:idx])
            rest = tokens[idx:]
        status_token = rest[0]
        status = status_token.rstrip(":")
        rest = rest[1:]
        if status_token.endswith(":"):
            # "notconnect: TDR 1 a-full ..." -> skip the extra status words.
            while rest and not _vlan_like(rest[0]):
                rest = rest[1:]
        if len(rest) > 1 and rest[0] == "pvlan":
            rest = [f"{rest[0]} {rest[1]}"] + rest[2:]
        vlan = rest[0] if len(rest) > 0 else ""
        duplex = rest[1] if len(rest) > 1 else ""
        speed = rest[2] if len(rest) > 2 else ""
        type_ = " ".join(rest[3:]) if len(rest) > 3 else ""
        iface = canonical_interface(port)
        result[iface] = InterfaceStatus(
            port=iface, name=name, status=status, vlan=vlan, duplex=duplex, speed=speed, type=type_
        )
    return result


def parse_errdisabled(text: str) -> dict[str, str]:
    """Parse `show interfaces status err-disabled` -> {port: reason}."""
    result: dict[str, str] = {}
    cols: dict[str, int] | None = None
    for line in text.splitlines():
        if line.startswith("Port") and "Reason" in line:
            cols = _header_columns(line, ["Port", "Name", "Status", "Reason"])
            continue
        if cols is None or not line.strip() or line.startswith("-"):
            continue
        tokens = line.split()
        if "err-disabled" not in tokens:
            continue
        idx = tokens.index("err-disabled")
        reason = tokens[idx + 1] if len(tokens) > idx + 1 else ""
        result[canonical_interface(tokens[0])] = reason
    return result


_TRUNK_SECTIONS = {
    "Vlans allowed on trunk": "allowed",
    "Vlans allowed and active in management domain": "active",
    "Vlans in spanning tree forwarding state and not pruned": "forwarding",
}


def parse_interfaces_trunk(text: str) -> dict[str, TrunkInfo]:
    result: dict[str, TrunkInfo] = {}
    section = None
    last_port = None
    for line in text.splitlines():
        if not line.strip():
            continue
        if line.startswith("Port") and "Mode" in line and "Encapsulation" in line:
            section = "mode"
            continue
        if line.startswith("Port"):
            section = next((v for k, v in _TRUNK_SECTIONS.items() if k in line), None)
            continue
        if section is None:
            continue
        if line.startswith((" ", "\t")) and last_port and section != "mode":
            info = result[last_port]
            setattr(info, section, getattr(info, section) + line.strip())
            continue
        tokens = line.split()
        port = canonical_interface(tokens[0])
        info = result.setdefault(port, TrunkInfo(port=port))
        last_port = port
        if section == "mode":
            if len(tokens) >= 5:
                info.mode, info.encapsulation, info.status = tokens[1], tokens[2], tokens[3]
                info.native_vlan = int(tokens[4]) if tokens[4].isdigit() else None
        else:
            setattr(info, section, tokens[1] if len(tokens) > 1 else "")
    return result

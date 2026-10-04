"""Turn raw command outputs collected by Ansible into :class:`~netaudit.model.Device` objects."""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from pathlib import Path
from typing import Any

from ..model import Device, InterfaceStatus
from .config import parse_running_config
from .interfaces import parse_errdisabled, parse_interfaces_status, parse_interfaces_trunk
from .neighbors import parse_cdp_neighbors_detail, parse_lldp_neighbors_detail
from .platform import parse_etherchannel_summary, parse_logging, parse_version, parse_vlan_brief
from .stp import (
    parse_mst_configuration,
    parse_spanning_tree,
    parse_spanning_tree_detail,
    parse_spanning_tree_summary,
)

# The commands the audit playbook runs.  Keep in sync with
# ansible/inventory/group_vars/switches.yml (audit_commands); unknown commands
# are still stored raw, they are just not parsed.
AUDIT_COMMANDS = [
    "show version",
    "show running-config",
    "show spanning-tree summary",
    "show spanning-tree",
    "show spanning-tree detail",
    "show spanning-tree mst configuration",
    "show interfaces status",
    "show interfaces status err-disabled",
    "show interfaces trunk",
    "show etherchannel summary",
    "show cdp neighbors detail",
    "show lldp neighbors detail",
    "show vlan brief",
    "show logging | include SPANTREE|MACFLAP|ERR_DISABLE|NATIVE_VLAN|DUPLEX_MISMATCH|LINK-3-UPDOWN|LOOP_BACK|STORM",
]


# Every keyword of the commands above; abbreviations are expanded to these.
_KEYWORDS = sorted({word for command in AUDIT_COMMANDS for word in command.split("|")[0].split()})


def _normalise_command(command: str) -> str:
    """Expand IOS-style abbreviations: "sh int status" -> "show interfaces status"."""
    head, pipe, tail = re.sub(r"\s+", " ", command.strip().lower()).partition("|")
    words = []
    for word in head.split():
        matches = [k for k in _KEYWORDS if k.startswith(word)]
        words.append(matches[0] if word not in _KEYWORDS and len(matches) == 1 else word)
    return " ".join(words) + (f" |{tail}" if pipe else "")


def _find(outputs: dict[str, str], *candidates: str, prefix: bool = False) -> str | None:
    normalised = {_normalise_command(k): v for k, v in outputs.items()}
    for candidate in candidates:
        if candidate in normalised:
            return normalised[candidate]
    if prefix:
        for candidate in candidates:
            for key, value in normalised.items():
                if key.startswith(candidate):
                    return value
    return None


def build_device(host: str, outputs: dict[str, str], intent: dict[str, Any] | None = None) -> Device:
    """Parse every known command output for one switch."""
    device = Device(host=host, intent=dict(intent or {}), raw=dict(outputs))

    steps: list[tuple[str, Callable[[], None]]] = []

    def add(name: str, func: Callable[[], None]) -> None:
        steps.append((name, func))

    if (text := _find(outputs, "show version")) is not None:
        add("show version", lambda t=text: setattr(device, "version", parse_version(t)))
    if (text := _find(outputs, "show running-config", prefix=True)) is not None:
        add("show running-config", lambda t=text: setattr(device, "config", parse_running_config(t)))
    if (text := _find(outputs, "show spanning-tree summary")) is not None:
        add("show spanning-tree summary", lambda t=text: setattr(device, "stp_summary", parse_spanning_tree_summary(t)))
    if (text := _find(outputs, "show spanning-tree")) is not None:
        add("show spanning-tree", lambda t=text: device.stp.update(parse_spanning_tree(t)))
    if (text := _find(outputs, "show spanning-tree detail")) is not None:
        add("show spanning-tree detail", lambda t=text: parse_spanning_tree_detail(t, device.stp))
    if (text := _find(outputs, "show spanning-tree mst configuration")) is not None:
        add("show spanning-tree mst configuration", lambda t=text: _apply_mst(device, parse_mst_configuration(t)))
    if (text := _find(outputs, "show interfaces status")) is not None:
        add("show interfaces status", lambda t=text: device.interfaces.update(parse_interfaces_status(t)))
    if (text := _find(outputs, "show interfaces status err-disabled")) is not None:
        add("show interfaces status err-disabled", lambda t=text: _apply_errdisabled(device, parse_errdisabled(t)))
    if (text := _find(outputs, "show interfaces trunk")) is not None:
        add("show interfaces trunk", lambda t=text: device.trunks.update(parse_interfaces_trunk(t)))
    if (text := _find(outputs, "show etherchannel summary")) is not None:
        add("show etherchannel summary", lambda t=text: device.etherchannels.update(parse_etherchannel_summary(t)))
    if (text := _find(outputs, "show cdp neighbors detail")) is not None:
        add("show cdp neighbors detail", lambda t=text: device.neighbors.extend(parse_cdp_neighbors_detail(t)))
    if (text := _find(outputs, "show lldp neighbors detail")) is not None:
        add("show lldp neighbors detail", lambda t=text: _merge_lldp(device, parse_lldp_neighbors_detail(t)))
    if (text := _find(outputs, "show vlan brief", "show vlan")) is not None:
        add("show vlan brief", lambda t=text: device.vlans.update(parse_vlan_brief(t)))
    if (text := _find(outputs, "show logging", prefix=True)) is not None:
        add("show logging", lambda t=text: device.logs.extend(parse_logging(t)))

    for name, func in steps:
        try:
            func()
        except Exception as exc:  # pragma: no cover - defensive: never abort the whole audit
            device.parse_errors[name] = f"{type(exc).__name__}: {exc}"
    if not device.config.hostname and device.version.hostname:
        device.config.hostname = device.version.hostname
    return device


def _apply_mst(device: Device, mst: dict) -> None:
    if mst.get("name") is not None and device.config.mst_name is None:
        device.config.mst_name = mst["name"]
    if mst.get("revision") is not None and device.config.mst_revision is None:
        device.config.mst_revision = mst["revision"]
    if mst.get("instances") and not device.config.mst_instances:
        device.config.mst_instances = dict(mst["instances"])


def _apply_errdisabled(device: Device, reasons: dict[str, str]) -> None:
    for port, reason in reasons.items():
        status = device.interfaces.get(port)
        if status is not None:
            status.errdisable_reason = reason
            status.status = "err-disabled"
        else:
            device.interfaces[port] = InterfaceStatus(port=port, status="err-disabled", errdisable_reason=reason)


def _merge_lldp(device: Device, lldp: list) -> None:
    """Add LLDP neighbours unless CDP already reported a neighbour on that port."""
    cdp_ports = {n.local_port for n in device.neighbors if n.protocol == "cdp"}
    device.neighbors.extend(n for n in lldp if n.local_port not in cdp_ports)


def load_payload(path: Path) -> dict[str, Any]:
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


def load_devices(raw_dir: Path) -> list[Device]:
    """Load every ``<host>.json`` payload written by the audit playbook."""
    devices = []
    for path in sorted(Path(raw_dir).glob("*.json")):
        payload = load_payload(path)
        host = payload.get("host") or path.stem
        outputs = payload.get("outputs") or {}
        device = build_device(host, outputs, payload.get("intent"))
        device.collected_at = payload.get("collected_at", "")
        device.errors = dict(payload.get("errors") or {})
        device.reachable = bool(outputs) and not payload.get("unreachable", False)
        devices.append(device)
    return devices

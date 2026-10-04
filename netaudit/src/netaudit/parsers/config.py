"""Parser for `show running-config` focused on switching / spanning-tree settings."""

from __future__ import annotations

import re

from ..model import InterfaceConfig, RunningConfig
from ..util import canonical_interface, expand_vlans


def split_sections(text: str) -> list[tuple[str, list[str]]]:
    """Split IOS config text into (top-level line, [child lines]) tuples.

    Banners are skipped because their body is free text that can look like
    configuration commands.
    """
    sections: list[tuple[str, list[str]]] = []
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        line = lines[i].rstrip()
        i += 1
        if not line.strip() or line.startswith("!"):
            continue
        if line.startswith("banner "):
            i = _skip_banner(line, lines, i)
            continue
        if line.startswith((" ", "\t")):
            if sections:
                sections[-1][1].append(line.strip())
            continue
        sections.append((line.strip(), []))
    return sections


def _skip_banner(line: str, lines: list[str], i: int) -> int:
    match = re.match(r"^banner\s+\S+\s+(\^C|\S)(.*)$", line)
    if not match:
        return i
    delimiter, rest = match.groups()
    if delimiter in rest:
        return i
    while i < len(lines):
        if delimiter in lines[i]:
            return i + 1
        i += 1
    return i


def parse_running_config(text: str) -> RunningConfig:
    cfg = RunningConfig()
    for parent, children in split_sections(text):
        if parent.startswith("interface "):
            name = canonical_interface(parent.split(None, 1)[1])
            cfg.interfaces[name] = _parse_interface(name, children)
            continue
        if children:
            cfg.sections[parent] = children
        cfg.global_lines.append(parent)
        _parse_global(cfg, parent, children)
    return cfg


def _parse_global(cfg: RunningConfig, line: str, children: list[str]) -> None:
    if line.startswith("hostname "):
        cfg.hostname = line.split(None, 1)[1].strip()
    elif m := re.match(r"^spanning-tree mode (\S+)", line):
        cfg.stp_mode = m.group(1)
    elif m := re.match(r"^spanning-tree vlan (\S+) priority (\d+)", line):
        for vlan in expand_vlans(m.group(1)):
            cfg.stp_vlan_priority[vlan] = int(m.group(2))
    elif m := re.match(r"^no spanning-tree vlan (\S+)\s*$", line):
        cfg.stp_disabled_vlans |= expand_vlans(m.group(1))
    elif re.match(r"^spanning-tree portfast (?:edge )?default", line):
        cfg.portfast_default = True
    elif re.match(r"^spanning-tree portfast (?:edge )?bpduguard default", line):
        cfg.bpduguard_default = True
    elif re.match(r"^spanning-tree portfast (?:edge )?bpdufilter default", line):
        cfg.bpdufilter_default = True
    elif line == "spanning-tree loopguard default":
        cfg.loopguard_default = True
    elif m := re.match(r"^spanning-tree pathcost method (\S+)", line):
        cfg.pathcost_method = m.group(1)
    elif line.startswith("spanning-tree uplinkfast"):
        cfg.uplinkfast = True
    elif line.startswith("spanning-tree backbonefast"):
        cfg.backbonefast = True
    elif line == "spanning-tree extend system-id":
        cfg.extend_system_id = True
    elif line == "no spanning-tree extend system-id":
        cfg.extend_system_id = False
    elif m := re.match(r"^errdisable recovery cause (\S+)", line):
        cfg.errdisable_recovery_causes.add(m.group(1))
    elif m := re.match(r"^errdisable recovery interval (\d+)", line):
        cfg.errdisable_recovery_interval = int(m.group(1))
    elif line == "spanning-tree mst configuration":
        for child in children:
            if m := re.match(r"^name (\S+)", child):
                cfg.mst_name = m.group(1)
            elif m := re.match(r"^revision (\d+)", child):
                cfg.mst_revision = int(m.group(1))
            elif m := re.match(r"^instance (\d+) vlan (.+)$", child):
                # IOS prints "instance 1 vlan 10, 20"
                cfg.mst_instances[int(m.group(1))] = re.sub(r"\s+", "", m.group(2))


def _parse_interface(name: str, children: list[str]) -> InterfaceConfig:
    iface = InterfaceConfig(name=name, lines=list(children))
    allowed: list[str] = []
    for line in children:
        if line.startswith("description "):
            iface.description = line.split(None, 1)[1]
        elif line == "no switchport":
            iface.mode = "routed"
        elif m := re.match(r"^switchport mode (.+)$", line):
            iface.mode = m.group(1).strip()
        elif m := re.match(r"^switchport access vlan (\d+)", line):
            iface.access_vlan = int(m.group(1))
        elif m := re.match(r"^switchport voice vlan (\d+)", line):
            iface.voice_vlan = int(m.group(1))
        elif m := re.match(r"^switchport trunk native vlan (\d+)", line):
            iface.native_vlan = int(m.group(1))
        elif m := re.match(r"^switchport trunk allowed vlan add (\S+)", line):
            allowed.append(m.group(1))
        elif m := re.match(r"^switchport trunk allowed vlan (\S+)", line):
            allowed = [m.group(1)]
        elif line == "switchport nonegotiate":
            iface.nonegotiate = True
        elif line == "shutdown":
            iface.shutdown = True
        elif m := re.match(r"^channel-group (\d+)", line):
            iface.channel_group = int(m.group(1))
        elif m := re.match(r"^spanning-tree portfast(?: (.+))?$", line):
            arg = (m.group(1) or "").strip()
            if arg in ("", "edge"):
                iface.portfast = "edge"
            elif "trunk" in arg:
                iface.portfast = "trunk"
            elif arg.startswith("disable"):
                iface.portfast = "disable"
            elif arg.startswith("network"):
                iface.portfast = "network"
            else:
                iface.portfast = arg
        elif m := re.match(r"^spanning-tree bpduguard (enable|disable)", line):
            iface.bpduguard = m.group(1)
        elif m := re.match(r"^spanning-tree bpdufilter (enable|disable)", line):
            iface.bpdufilter = m.group(1)
        elif m := re.match(r"^spanning-tree guard (root|loop|none)", line):
            iface.guard = m.group(1)
        elif m := re.match(r"^spanning-tree link-type (\S+)", line):
            iface.link_type = m.group(1)
    if allowed:
        iface.allowed_vlans = ",".join(allowed)
    return iface

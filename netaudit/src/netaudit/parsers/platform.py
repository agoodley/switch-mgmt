"""Parsers for `show version`, `show vlan brief`, `show etherchannel summary` and logs."""

from __future__ import annotations

import re

from ..model import EtherChannel, LogEvent, VersionInfo
from ..util import canonical_interface, parse_uptime


def parse_version(text: str) -> VersionInfo:
    info = VersionInfo()
    if m := re.search(r"^(\S+) uptime is (.+)$", text, re.M):
        info.hostname = m.group(1)
        info.uptime_seconds = parse_uptime(m.group(2))
    info.is_iosxe = "IOS XE" in text or "IOS-XE" in text
    if m := re.search(r"Cisco IOS XE Software, Version (\S+)", text):
        info.os_version = m.group(1).strip(",")
    elif m := re.search(r"Version (\S+?),? ", text):
        info.os_version = m.group(1).strip(",")
    if m := re.search(r"^Model [Nn]umber\s*:\s*(\S+)", text, re.M):
        info.model = m.group(1)
    elif m := re.search(r"^[Cc]isco (\S+) \(.+?\) processor", text, re.M):
        info.model = m.group(1)
    if m := re.search(r"^System [Ss]erial [Nn]umber\s*:\s*(\S+)", text, re.M):
        info.serial = m.group(1).strip(",")
    elif m := re.search(r"^Processor board ID (\S+)", text, re.M):
        info.serial = m.group(1).strip(",")
    if m := re.search(r'System image file is "([^"]+)"', text):
        info.image = m.group(1)
    return info


def parse_vlan_brief(text: str) -> dict[int, str]:
    vlans: dict[int, str] = {}
    for line in text.splitlines():
        if m := re.match(r"^(\d{1,4})\s+(\S+)\s+(active|act/\S+|suspended|sus/\S+)", line):
            vlans[int(m.group(1))] = m.group(2)
    return vlans


def parse_etherchannel_summary(text: str) -> dict[str, EtherChannel]:
    channels: dict[str, EtherChannel] = {}
    current: EtherChannel | None = None
    member_re = re.compile(r"(\S+?)\(([A-Za-z]+)\)")
    for line in text.splitlines():
        if m := re.match(r"^(\d+)\s+(Po\d+)\((\w+)\)\s+(\S+)\s*(.*)$", line):
            po = canonical_interface(m.group(2))
            current = EtherChannel(group=int(m.group(1)), port_channel=po, flags=m.group(3), protocol=m.group(4))
            channels[po] = current
            rest = m.group(5)
        elif current is not None and line.startswith(" ") and member_re.search(line):
            rest = line
        else:
            if line.strip() and not line.startswith(" "):
                current = None
            continue
        for member, flags in member_re.findall(rest):
            current.members[canonical_interface(member)] = flags
    return channels


_LOG_RE = re.compile(r"%(?P<facility>[A-Z0-9_]+)-(?P<severity>\d)-(?P<mnemonic>[A-Z0-9_]+):\s*(?P<message>.*)")


def parse_logging(text: str) -> list[LogEvent]:
    events = []
    for line in text.splitlines():
        m = _LOG_RE.search(line)
        if not m:
            continue
        events.append(
            LogEvent(
                raw=line.strip(),
                facility=m.group("facility"),
                severity=int(m.group("severity")),
                mnemonic=m.group("mnemonic"),
                message=m.group("message").strip(),
            )
        )
    return events

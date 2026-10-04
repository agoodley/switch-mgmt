"""Small helpers shared by the parsers, the analysis and the lab simulator."""

from __future__ import annotations

import re
from collections.abc import Iterable

# Short form -> long form, as Cisco IOS / IOS-XE print them.  Order matters for
# the prefix fallback: longer abbreviations must be tried before shorter ones
# ("Twe" before "Tw", "Te" before "T").
_IFACE_ABBREV = [
    ("AppGigabitEthernet", "Ap"),
    ("TwentyFiveGigE", "Twe"),
    ("TwoGigabitEthernet", "Tw"),
    ("FiveGigabitEthernet", "Fi"),
    ("TenGigabitEthernet", "Te"),
    ("FortyGigabitEthernet", "Fo"),
    ("HundredGigE", "Hu"),
    ("GigabitEthernet", "Gi"),
    ("FastEthernet", "Fa"),
    ("Ethernet", "Et"),
    ("Port-channel", "Po"),
    ("Vlan", "Vl"),
    ("Loopback", "Lo"),
    ("Tunnel", "Tu"),
]
_SHORT_TO_LONG = {short.lower(): long for long, short in _IFACE_ABBREV}
_LONG_NAMES = {long.lower(): long for long, _ in _IFACE_ABBREV}
_LONG_TO_SHORT = {long: short for long, short in _IFACE_ABBREV}
_IFACE_SPLIT = re.compile(r"^([A-Za-z][A-Za-z\-]*?)\s*(\d.*)$")


def canonical_interface(name: str | None) -> str:
    """Return the long IOS interface name ("Gi1/0/1" -> "GigabitEthernet1/0/1").

    Unknown names are returned unchanged (stripped) so callers can still use
    them as dictionary keys.
    """
    if not name:
        return ""
    name = name.strip()
    match = _IFACE_SPLIT.match(name)
    if not match:
        return name
    prefix, rest = match.groups()
    low = prefix.lower()
    if low in _LONG_NAMES:
        return _LONG_NAMES[low] + rest
    if low in _SHORT_TO_LONG:
        return _SHORT_TO_LONG[low] + rest
    # Partial forms such as "Gig1/0/1", "TenGig1/1/1", "Port-ch1".
    for long, short in _IFACE_ABBREV:
        if long.lower().startswith(low) and len(low) > len(short):
            return long + rest
    return name


def short_interface(name: str | None) -> str:
    """Return the short IOS interface name ("GigabitEthernet1/0/1" -> "Gi1/0/1")."""
    long = canonical_interface(name)
    match = _IFACE_SPLIT.match(long)
    if not match:
        return long
    prefix, rest = match.groups()
    short = _LONG_TO_SHORT.get(prefix)
    return f"{short}{rest}" if short else long


def is_physical_ethernet(name: str) -> bool:
    long = canonical_interface(name)
    return any(
        long.startswith(prefix)
        for prefix in (
            "GigabitEthernet",
            "FastEthernet",
            "TenGigabitEthernet",
            "TwoGigabitEthernet",
            "FiveGigabitEthernet",
            "TwentyFiveGigE",
            "FortyGigabitEthernet",
            "HundredGigE",
            "Ethernet",
            "AppGigabitEthernet",
        )
    )


def interface_sort_key(name: str) -> tuple:
    """Natural sort key: Gi1/0/2 sorts before Gi1/0/10."""
    long = canonical_interface(name)
    parts = re.split(r"(\d+)", long)
    return tuple(int(p) if p.isdigit() else p for p in parts)


def normalize_mac(mac: str | None) -> str:
    """Normalise any MAC notation to Cisco dotted form (aaaa.bbbb.cccc)."""
    if not mac:
        return ""
    digits = re.sub(r"[^0-9a-fA-F]", "", mac).lower()
    if len(digits) != 12:
        return mac.strip().lower()
    return f"{digits[0:4]}.{digits[4:8]}.{digits[8:12]}"


def expand_vlans(spec: str | Iterable[int] | None) -> set[int]:
    """Expand an IOS VLAN list ("1-5,10,20-22") into a set of ints.

    Accepts "all" (1-4094), "none"/"" (empty) and iterables of ints.
    """
    if spec is None:
        return set()
    if not isinstance(spec, str):
        return {int(v) for v in spec}
    spec = spec.strip().lower()
    if spec in ("", "none"):
        return set()
    if spec == "all":
        return set(range(1, 4095))
    vlans: set[int] = set()
    for chunk in re.split(r"[,\s]+", spec):
        if not chunk:
            continue
        if "-" in chunk:
            start, _, end = chunk.partition("-")
            if start.isdigit() and end.isdigit():
                vlans.update(range(int(start), int(end) + 1))
        elif chunk.isdigit():
            vlans.add(int(chunk))
    return vlans


def compress_vlans(vlans: Iterable[int]) -> str:
    """Compress VLAN ids into IOS range notation ("1-3,5")."""
    ordered = sorted(set(int(v) for v in vlans))
    if not ordered:
        return ""
    ranges = []
    start = prev = ordered[0]
    for vlan in ordered[1:]:
        if vlan == prev + 1:
            prev = vlan
            continue
        ranges.append((start, prev))
        start = prev = vlan
    ranges.append((start, prev))
    return ",".join(f"{a}" if a == b else f"{a}-{b}" for a, b in ranges)


def vlan_from_instance(instance: str) -> int | None:
    """ "VLAN0010" -> 10; "MST1" -> None."""
    match = re.match(r"^VLAN0*(\d+)$", instance.strip(), re.I)
    return int(match.group(1)) if match else None


def instance_name(vlan: int) -> str:
    return f"VLAN{vlan:04d}"


_UNIT_SECONDS = {
    "y": 365 * 86400,
    "w": 7 * 86400,
    "d": 86400,
    "h": 3600,
    "m": 60,
    "s": 1,
}


def parse_ios_duration(text: str | None) -> int | None:
    """Parse IOS relative times: "00:01:23", "1d02h", "3w4d", "1y12w", "never".

    Returns seconds, or None when the value cannot be parsed (or is "never").
    """
    if not text:
        return None
    text = text.strip().lower()
    if text in ("never", "-", ""):
        return None
    match = re.fullmatch(r"(\d+):(\d{2}):(\d{2})", text)
    if match:
        hours, minutes, seconds = (int(x) for x in match.groups())
        return hours * 3600 + minutes * 60 + seconds
    parts = re.findall(r"(\d+)\s*([ywdhms])", text)
    if parts and "".join(f"{n}{u}" for n, u in parts) == re.sub(r"\s+", "", text):
        return sum(int(n) * _UNIT_SECONDS[u] for n, u in parts)
    return None


def format_duration(seconds: int | float | None) -> str:
    """Compact human duration: 42s, 5m, 3h12m, 4d6h, 2w3d."""
    if seconds is None:
        return "n/a"
    seconds = int(seconds)
    if seconds < 60:
        return f"{seconds}s"
    if seconds < 3600:
        return f"{seconds // 60}m"
    if seconds < 86400:
        hours, rem = divmod(seconds, 3600)
        return f"{hours}h{rem // 60:02d}m"
    if seconds < 14 * 86400:
        days, rem = divmod(seconds, 86400)
        return f"{days}d{rem // 3600}h"
    weeks, rem = divmod(seconds, 7 * 86400)
    return f"{weeks}w{rem // 86400}d"


_UPTIME_UNITS = {
    "year": 365 * 86400,
    "week": 7 * 86400,
    "day": 86400,
    "hour": 3600,
    "minute": 60,
    "second": 1,
}


def parse_uptime(text: str | None) -> int | None:
    """Parse "2 years, 3 weeks, 1 day, 4 hours, 12 minutes" into seconds."""
    if not text:
        return None
    total = 0
    found = False
    for number, unit in re.findall(r"(\d+)\s+(year|week|day|hour|minute|second)s?", text):
        total += int(number) * _UPTIME_UNITS[unit]
        found = True
    return total if found else None


def short_hostname(name: str | None) -> str:
    """Normalise a CDP/LLDP device id for matching against inventory names.

    Strips domain suffixes and NX-OS style serial numbers in brackets:
    "SW1.corp.example(FOC123)" -> "sw1".
    """
    if not name:
        return ""
    name = name.strip()
    name = re.sub(r"\(.*\)$", "", name)
    name = name.split(".")[0]
    return name.lower()


def slugify(text: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", text.strip()).strip("_")[:120] or "output"

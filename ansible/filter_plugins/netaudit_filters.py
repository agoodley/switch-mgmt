"""Jinja filters that reuse netaudit's IOS parsers inside playbooks."""

from netaudit.parsers.interfaces import parse_errdisabled, parse_interfaces_status
from netaudit.util import short_interface


def ios_interfaces_status(text):
    """`show interfaces status` -> {"Gi1/0/1": "connected", ...} (short names)."""
    return {short_interface(port): row.status for port, row in parse_interfaces_status(text or "").items()}


def ios_errdisabled(text):
    """`show interfaces status` (or `... err-disabled`) -> sorted list of err-disabled ports."""
    text = text or ""
    if any(line.startswith("Port") and "Reason" in line for line in text.splitlines()):
        ports = parse_errdisabled(text)
    else:
        ports = {p: "" for p, row in parse_interfaces_status(text).items() if row.status == "err-disabled"}
    return sorted(short_interface(p) for p in ports)


class FilterModule:
    def filters(self):
        return {
            "ios_interfaces_status": ios_interfaces_status,
            "ios_errdisabled": ios_errdisabled,
        }

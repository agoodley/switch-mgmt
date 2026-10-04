"""Remove passwords, keys and SNMP communities from IOS output before it is saved.

The rules follow Oxidized's IOS model (``remove_secret``), plus a few it does
not cover: plain-text RADIUS keys, NTP authentication keys, the VTP password
and credentials embedded in URLs (``archive`` paths, ``ip ftp``).
"""

from __future__ import annotations

import re

HIDDEN = "<secret hidden>"
REMOVED = "<configuration removed>"

_RULES: list[tuple[re.Pattern[str], str]] = [
    (re.compile(p, re.M), r)
    for p, r in [
        (r"^(snmp-server community).*", rf"\1 {REMOVED}"),
        # v1/v2c: the community follows the address; v3 lines name a user, not a secret
        (
            r"^(snmp-server host \S+(?: vrf \S+)?(?: informs?)?(?: version (?:1|2c))?) +(?!version\b|<)\S+((?: .*)?)$",
            rf"\1 {HIDDEN}\2",
        ),
        (r"^(username .+ (?:password|secret) \d) .+", rf"\1 {HIDDEN}"),
        (r"^(enable (?:password|secret)(?: level \d+)? \d) .+", rf"\1 {HIDDEN}"),
        (r"^(enable (?:password|secret)(?: level \d+)?) (?!\d )\S.*", rf"\1 {HIDDEN}"),
        (r"^( +(?:password|secret)) (?:\d )?(?!<)\S+", rf"\1 {HIDDEN}"),
        (r"^(.*wpa-psk ascii \d) (?!<)\S+", rf"\1 {HIDDEN}"),
        (r"^(.*key 7) \d.+", rf"\1 {HIDDEN}"),
        (r"^((?:tacacs|radius)-server (?:.+ )?key) .+", rf"\1 {HIDDEN}"),
        (r"^((?:tacacs|radius) server [^\n]+\n(?: +[^\n]+\n)* +key) [^\n]+$", rf"\1 {HIDDEN}"),
        (r"^(crypto isakmp key) (?!<)\S+ (.*)", rf"\1 {HIDDEN} \2"),
        (r"^( +ip ospf message-digest-key \d+ md5) .+", rf"\1 {HIDDEN}"),
        (r"^( +ip ospf authentication-key) .+", rf"\1 {HIDDEN}"),
        (r"^( +neighbor \S+ password) .+", rf"\1 {HIDDEN}"),
        (r"^( +vrrp \d+ authentication text) .+", rf"\1 {HIDDEN}"),
        (r"^( +standby \d+ authentication md5 key-string) .+?((?: timeout \d+)?)$", rf"\1 {HIDDEN}\2"),
        (r"^( +standby \d+ authentication) (?!md5 ).{1,8}$", rf"\1 {HIDDEN}"),
        (r"^( +key-string) .+", rf"\1 {HIDDEN}"),
        (r"^( +ppp (?:chap|pap) password \d) .+", rf"\1 {HIDDEN}"),
        (r"^( +dot1x username \S+ password \d) .*$", rf"\1 {HIDDEN}"),
        (r"^( +pre-shared-key).*", rf"\1 {REMOVED}"),
        (r"^(.*server-key(?: \d)?) (?!<)\S+", rf"\1 {HIDDEN}"),
        (r"^(ntp authentication-key \d+ md5) (?!<)\S+", rf"\1 {HIDDEN}"),
        (r"^(vtp password) .+", rf"\1 {HIDDEN}"),
        (r"^(ip (?:ftp|http client) password(?: \d)?) .+", rf"\1 {HIDDEN}"),
        (r"(\b[A-Za-z][A-Za-z0-9+.-]*://[^:/@\s]+):[^@\s]+@", rf"\1:{HIDDEN}@"),
    ]
]


def remove_secrets(text: str | None) -> str:
    """Return ``text`` with every password, key and SNMP community replaced.

    Safe to apply more than once: values already hidden are left alone.
    """
    if not text:
        return text or ""
    for pattern, replacement in _RULES:
        text = pattern.sub(replacement, text)
    return text

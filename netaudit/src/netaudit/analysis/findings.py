from __future__ import annotations

from dataclasses import dataclass, field

SEVERITIES = ["critical", "high", "medium", "low", "info"]
SEVERITY_RANK = {name: i for i, name in enumerate(SEVERITIES)}


@dataclass
class Finding:
    severity: str
    category: str
    title: str
    host: str | None = None  # None = site-wide
    site: str = ""
    detail: str = ""
    recommendation: str = ""
    ports: list[str] = field(default_factory=list)
    vlans: list[int] = field(default_factory=list)
    planned: bool = False  # the remediation plan fixes this

    @property
    def key(self) -> str:
        return f"{self.category}|{self.site}|{self.host or '*'}|{self.title}"

    @property
    def rank(self) -> int:
        return SEVERITY_RANK.get(self.severity, len(SEVERITIES))

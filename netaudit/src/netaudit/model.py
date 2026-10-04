"""Plain data structures produced by the parsers and consumed by the analysis."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class VersionInfo:
    hostname: str = ""
    os_version: str = ""
    model: str = ""
    serial: str = ""
    image: str = ""
    uptime_seconds: int | None = None
    is_iosxe: bool = False


@dataclass
class InterfaceConfig:
    """What the running-config says about one interface."""

    name: str
    lines: list[str] = field(default_factory=list)
    description: str = ""
    mode: str | None = None  # access | trunk | dynamic auto | dynamic desirable | routed | None
    access_vlan: int | None = None
    voice_vlan: int | None = None
    native_vlan: int | None = None
    allowed_vlans: str | None = None
    nonegotiate: bool = False
    shutdown: bool = False
    channel_group: int | None = None
    portfast: str | None = None  # edge | trunk | network | disable | None
    bpduguard: str | None = None  # enable | disable | None
    bpdufilter: str | None = None  # enable | disable | None
    guard: str | None = None  # root | loop | none | None
    link_type: str | None = None


@dataclass
class RunningConfig:
    hostname: str = ""
    global_lines: list[str] = field(default_factory=list)
    interfaces: dict[str, InterfaceConfig] = field(default_factory=dict)
    sections: dict[str, list[str]] = field(default_factory=dict)
    stp_mode: str | None = None
    stp_vlan_priority: dict[int, int] = field(default_factory=dict)
    stp_disabled_vlans: set[int] = field(default_factory=set)
    portfast_default: bool = False
    bpduguard_default: bool = False
    bpdufilter_default: bool = False
    loopguard_default: bool = False
    pathcost_method: str | None = None
    uplinkfast: bool = False
    backbonefast: bool = False
    extend_system_id: bool | None = None
    errdisable_recovery_causes: set[str] = field(default_factory=set)
    errdisable_recovery_interval: int | None = None
    mst_name: str | None = None
    mst_revision: int | None = None
    mst_instances: dict[int, str] = field(default_factory=dict)


@dataclass
class StpPort:
    """One row of the `show spanning-tree` interface table."""

    instance: str
    port: str  # canonical long name
    role: str
    state: str
    cost: int
    priority: int
    number: int
    type: str = ""
    edge: bool = False
    p2p: bool = True
    inconsistent: str | None = None  # ROOT_Inc, LOOP_Inc, TYPE_Inc, PVID_Inc, BKN ...
    peer: str | None = None  # e.g. "Peer(STP)", "Bound(PVST)"


@dataclass
class StpPortDetail:
    """Per-port facts only available in `show spanning-tree detail`."""

    instance: str
    port: str
    status: str = ""
    bpdu_sent: int | None = None
    bpdu_received: int | None = None
    transitions: int | None = None
    portfast: bool = False
    bpduguard: bool = False
    bpdufilter: bool = False
    root_guard: bool = False
    loop_guard: bool = False
    designated_bridge_mac: str = ""
    designated_bridge_priority: int | None = None


@dataclass
class StpInstance:
    name: str  # VLAN0010 / MST0
    vlan: int | None = None
    protocol: str = ""  # ieee | rstp | mstp
    root_priority: int | None = None
    root_mac: str = ""
    root_cost: int | None = None
    root_port: str | None = None
    is_root: bool = False
    bridge_priority: int | None = None  # full value incl. sys-id-ext
    bridge_priority_base: int | None = None  # configured value (multiple of 4096)
    bridge_sysid: int | None = None
    bridge_mac: str = ""
    hello: int | None = None
    max_age: int | None = None
    forward_delay: int | None = None
    ports: dict[str, StpPort] = field(default_factory=dict)
    port_details: dict[str, StpPortDetail] = field(default_factory=dict)
    tc_count: int | None = None
    tc_last_seconds: int | None = None
    tc_from: str | None = None
    tc_in_progress: bool = False


@dataclass
class StpSummary:
    mode: str | None = None  # pvst | rapid-pvst | mst
    root_for: list[str] = field(default_factory=list)
    portfast_default: str | None = None
    bpduguard_default: str | None = None
    bpdufilter_default: str | None = None
    loopguard_default: str | None = None
    pathcost_method: str | None = None
    uplinkfast: str | None = None
    backbonefast: str | None = None
    extended_system_id: str | None = None
    etherchannel_guard: str | None = None
    instance_counts: dict[str, dict[str, int]] = field(default_factory=dict)
    raw_flags: dict[str, str] = field(default_factory=dict)


@dataclass
class InterfaceStatus:
    port: str  # canonical long name
    name: str = ""
    status: str = ""
    vlan: str = ""
    duplex: str = ""
    speed: str = ""
    type: str = ""
    errdisable_reason: str = ""


@dataclass
class TrunkInfo:
    port: str
    mode: str = ""
    encapsulation: str = ""
    status: str = ""
    native_vlan: int | None = None
    allowed: str = ""
    active: str = ""
    forwarding: str = ""


@dataclass
class Neighbor:
    protocol: str  # cdp | lldp
    local_port: str  # canonical long name
    remote_name: str
    remote_port: str = ""
    platform: str = ""
    capabilities: list[str] = field(default_factory=list)
    mgmt_ip: str = ""
    native_vlan: int | None = None
    duplex: str = ""
    software: str = ""

    @property
    def is_switch(self) -> bool:
        """True when the neighbour advertises bridging/switching and is not a phone or AP."""
        caps = {c.lower() for c in self.capabilities}
        if self.protocol == "cdp":
            return "switch" in caps and "phone" not in caps
        # LLDP: B=bridge R=router T=telephone W=wlan-ap.  Phones and many APs
        # also advertise B because of their internal switch, so look at the
        # description too.
        if "t" in caps or "w" in caps:
            return False
        descr = f"{self.platform} {self.remote_name}".lower()
        if any(word in descr for word in ("ap software", "access point", "ip phone", "phone")):
            return False
        return "b" in caps


@dataclass
class EtherChannel:
    group: int
    port_channel: str  # canonical long name (Port-channel1)
    flags: str = ""
    protocol: str = ""
    members: dict[str, str] = field(default_factory=dict)  # member long name -> flags


@dataclass
class LogEvent:
    raw: str
    facility: str = ""
    severity: int | None = None
    mnemonic: str = ""
    message: str = ""

    @property
    def tag(self) -> str:
        return f"{self.facility}-{self.severity}-{self.mnemonic}"


@dataclass
class Device:
    """Everything known about one switch after parsing its collected outputs."""

    host: str
    intent: dict[str, Any] = field(default_factory=dict)
    collected_at: str = ""
    raw: dict[str, str] = field(default_factory=dict)
    errors: dict[str, str] = field(default_factory=dict)
    parse_errors: dict[str, str] = field(default_factory=dict)
    reachable: bool = True
    version: VersionInfo = field(default_factory=VersionInfo)
    config: RunningConfig = field(default_factory=RunningConfig)
    stp_summary: StpSummary = field(default_factory=StpSummary)
    stp: dict[str, StpInstance] = field(default_factory=dict)
    interfaces: dict[str, InterfaceStatus] = field(default_factory=dict)
    trunks: dict[str, TrunkInfo] = field(default_factory=dict)
    neighbors: list[Neighbor] = field(default_factory=list)
    vlans: dict[int, str] = field(default_factory=dict)
    etherchannels: dict[str, EtherChannel] = field(default_factory=dict)
    logs: list[LogEvent] = field(default_factory=list)

    @property
    def site(self) -> str:
        return str(self.intent.get("site") or "")

    @property
    def role(self) -> str:
        return str(self.intent.get("stp_role") or "access")

    @property
    def bridge_mac(self) -> str:
        for inst in self.stp.values():
            if inst.bridge_mac:
                return inst.bridge_mac
        return ""

    def neighbors_on(self, port: str) -> list[Neighbor]:
        """Neighbours seen on a port; for a port-channel, on any member link."""
        ports = {port}
        channel = self.etherchannels.get(port)
        if channel:
            ports.update(channel.members)
        return [n for n in self.neighbors if n.local_port in ports]

    def channel_of(self, port: str) -> str | None:
        for channel in self.etherchannels.values():
            if port in channel.members:
                return channel.port_channel
        return None

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data.pop("raw", None)
        return data

"""A small spanning-tree network simulator that renders realistic IOS show output.

The simulator holds one running-config per switch (editable through the fake
SSH server), derives STP parameters from it, runs the spanning-tree election
per VLAN and renders the show commands the audit collects.  It is not a full
STP implementation (no timers, no BPDU exchange) - it computes the converged
result, which is what the audit looks at.
"""

from __future__ import annotations

import hashlib
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from ..model import RunningConfig
from ..parsers.config import parse_running_config
from ..util import canonical_interface, expand_vlans, interface_sort_key, short_interface
from .configtree import ConfigTree

SHORT_COST = {"10": 100, "100": 19, "1000": 4, "10000": 2}
LONG_COST = {"10": 2000000, "100": 200000, "1000": 20000, "10000": 2000}


@dataclass
class LabLink:
    a: str
    a_port: str
    b: str
    b_port: str
    channel: str | None = None


@dataclass
class TcEvent:
    time: float
    origin: str
    port: str
    vlans: set[int]


@dataclass
class PortRole:
    port: str
    role: str  # Root | Desg | Altn
    state: str  # FWD | BLK | BKN
    cost: int
    number: int
    type: str
    neighbor: str | None = None
    inconsistent: str | None = None


@dataclass
class VlanState:
    vlan: int
    root: str
    root_bid: tuple[int, int]
    cost: dict[str, int] = field(default_factory=dict)
    root_port: dict[str, str | None] = field(default_factory=dict)
    roles: dict[str, dict[str, PortRole]] = field(default_factory=dict)
    parent: dict[str, tuple[str, str, str] | None] = field(
        default_factory=dict
    )  # host -> (parent, my port, parent port)


def mac_int(mac: str) -> int:
    return int(mac.replace(".", ""), 16)


class SimSwitch:
    def __init__(self, name: str, spec: dict[str, Any], lab: Lab):
        self.name = name
        self.spec = spec
        self.lab = lab
        self.mac = spec["mac"]
        self.model = spec.get("model", "WS-C2960X-48FPD-L")
        self.version = str(spec.get("version", "15.2(7)E8"))
        self.iosxe = bool(spec.get("iosxe", False))
        self.edge_syntax = bool(spec.get("portfast_edge_syntax", False))
        self.legacy_ssh = bool(spec.get("legacy_ssh", False))
        self.mgmt_ip = spec.get("mgmt_ip", "")
        self.boot_time = lab.t0 - float(spec.get("uptime_days", 30)) * 86400
        self.stp_restart = self.boot_time
        self.serial = "FOC" + hashlib.sha1(name.encode()).hexdigest()[:8].upper()
        self.ports: list[str] = []
        for prefix, count in spec.get("port_layout", {"GigabitEthernet1/0/": 52}).items():
            self.ports += [f"{prefix}{i}" for i in range(1, int(count) + 1)]
        self.port_number = {p: i for i, p in enumerate(self.ports, 1)}
        access = spec.get("access_ports") or {}
        self.access_range = (
            [f"{access['prefix']}{i}" for i in range(int(access.get("from", 1)), int(access.get("to", 0)) + 1)]
            if access
            else []
        )
        connected = int(access.get("connected", 0)) if access else 0
        self.hosts = set(self.access_range[:connected])
        self.phones = {f"{access['prefix']}{i}" for i in spec.get("phones", [])} if access else set()
        self.errdisabled: dict[str, str] = {}
        self.cfg = ConfigTree("")
        self._parsed: tuple[int, int, RunningConfig] | None = None
        self.startup = ""
        self.config_changed_at = lab.t0 - 86400 * 3
        self.logs: list[tuple[float, str]] = []

    # -- helpers -------------------------------------------------------------------
    @property
    def uptime(self) -> float:
        return self.lab.now() - self.boot_time

    def parsed(self) -> RunningConfig:
        key = (id(self.cfg), self.cfg.version)
        if self._parsed is None or self._parsed[:2] != key:
            self._parsed = (key[0], key[1], parse_running_config(self.cfg.text()))
        return self._parsed[2]

    def mode(self) -> str:
        return self.parsed().stp_mode or ("rapid-pvst" if self.iosxe else "pvst")

    def speed(self, port: str) -> str:
        port = canonical_interface(port)
        if port.startswith("TenGigabitEthernet"):
            return "10000"
        if port.startswith("FastEthernet"):
            return "100"
        if port.startswith("Port-channel"):
            members = [m for m, ch in self.channel_members().items() if ch == port]
            return str(sum(int(self.speed(m)) for m in members) or 1000)
        return "1000"

    def channel_members(self) -> dict[str, str]:
        cfg = self.parsed()
        return {
            name: f"Port-channel{iface.channel_group}"
            for name, iface in cfg.interfaces.items()
            if iface.channel_group is not None
        }

    def port_cost(self, port: str) -> int:
        method = self.parsed().pathcost_method or "short"
        speed = int(self.speed(port))
        table = LONG_COST if method == "long" else SHORT_COST
        if str(speed) in table:
            return table[str(speed)]
        if method == "long":
            return max(1, int(20_000_000_000 / (speed * 1_000_000) * 1)) if speed else 20000
        return 1 if speed > 10000 else 2

    def port_id(self, port: str) -> int:
        if port.startswith("Port-channel"):
            return 500 + int(port.replace("Port-channel", ""))
        return self.port_number.get(port, 0)

    def is_up(self, port: str) -> bool:
        cfg = self.parsed()
        iface = cfg.interfaces.get(port)
        if port.startswith("Port-channel"):
            return any(self.is_up(m) for m, ch in self.channel_members().items() if ch == port)
        if iface is not None and iface.shutdown:
            return False
        if port in self.errdisabled:
            return False
        return port in self.hosts or port in self.lab.switch_ports(self.name)

    def effective_portfast(self, port: str) -> bool:
        cfg = self.parsed()
        iface = cfg.interfaces.get(port)
        if iface is None:
            return False
        if iface.portfast in ("edge", "trunk"):
            return iface.mode != "trunk" or iface.portfast == "trunk"
        return cfg.portfast_default and iface.mode == "access" and iface.portfast not in ("disable", "network")

    def effective_bpduguard(self, port: str) -> bool:
        cfg = self.parsed()
        iface = cfg.interfaces.get(port)
        if iface is None:
            return False
        if iface.bpduguard == "enable":
            return True
        return cfg.bpduguard_default and self.effective_portfast(port) and iface.bpduguard != "disable"

    def log(self, message: str, at: float | None = None) -> None:
        self.logs.append((at if at is not None else self.lab.now(), message))


class Lab:
    def __init__(self, spec: dict[str, Any], clock: Callable[[], float] = time.time):
        self._clock = clock
        self.t0 = clock()
        self.spec = spec
        self.site = spec.get("site", "lab")
        self.vlans: dict[int, str] = {int(k): v for k, v in (spec.get("vlans") or {1: "default"}).items()}
        self.ssh = spec.get("ssh", {})
        self.problems = spec.get("problems", {}) or {}
        self.switches: dict[str, SimSwitch] = {}
        for name, sw_spec in spec["switches"].items():
            self.switches[name] = SimSwitch(name, sw_spec or {}, self)
        self.links: list[LabLink] = []
        for entry in spec.get("links", []):
            a, ap, b, bp = entry[:4]
            channel = entry[4] if len(entry) > 4 else None
            self.links.append(LabLink(a, canonical_interface(ap), b, canonical_interface(bp), channel))
        self.events: list[TcEvent] = []
        self._flap_active_since: float | None = None
        self._flap_deactivated_at: float | None = None
        self._flap_count_frozen = 0
        self._cache: dict[tuple, VlanState] = {}
        for sw in self.switches.values():
            sw.cfg = ConfigTree(self._initial_config(sw))
            sw.startup = sw.cfg.text()
        self._apply_static_problems()
        self._refresh_flap_state()

    # -- time ------------------------------------------------------------------------
    def now(self) -> float:
        return self._clock()

    # -- topology helpers --------------------------------------------------------------
    def switch_ports(self, name: str) -> set[str]:
        ports = set()
        for link in self.links:
            if link.a == name:
                ports.add(link.a_port)
            if link.b == name:
                ports.add(link.b_port)
        return ports

    def neighbors(self, name: str) -> list[tuple[str, str, str]]:
        """(local port, neighbour, neighbour port) for every physical link."""
        result = []
        for link in self.links:
            if link.a == name:
                result.append((link.a_port, link.b, link.b_port))
            elif link.b == name:
                result.append((link.b_port, link.a, link.a_port))
        return result

    # -- initial configuration -----------------------------------------------------------
    def _initial_config(self, sw: SimSwitch) -> str:
        spec = sw.spec
        version_short = "17.9" if sw.iosxe else ".".join(sw.version.split(".")[:2]).split("(")[0]
        lines = [
            f"version {version_short}",
            "no service pad",
            "service timestamps debug datetime msec",
            "service timestamps log datetime msec",
            "no service password-encryption",
            f"hostname {sw.name}",
            "boot-start-marker",
            "boot-end-marker",
            "enable secret 9 $9$labsecretlabsecretlabsecret",
            f"username {self.ssh.get('username', 'labadmin')} privilege 1 secret 9 $9$labuserlabuser",
            "no aaa new-model",
            "ip domain-name lab.local",
            "vtp mode transparent",
            f"spanning-tree mode {spec.get('mode', 'pvst')}",
            "spanning-tree extend system-id",
        ]
        text = "\n".join(lines) + "\n!\n"
        for vlan, name in sorted(self.vlans.items()):
            if vlan == 1:
                continue
            text += f"vlan {vlan}\n name {name}\n!\n"
        access = spec.get("access_ports") or {}
        pre = spec.get("preconfigured_edge") or {}
        pre_ports = (
            {f"{access.get('prefix')}{i}" for i in range(int(pre.get("from", 0)), int(pre.get("to", -1)) + 1)}
            if pre
            else set()
        )
        neighbors = {port: (n, np) for port, n, np in self.neighbors(sw.name)}
        channels = {}
        for link in self.links:
            if link.channel and link.a == sw.name:
                channels[link.a_port] = link.channel
            if link.channel and link.b == sw.name:
                channels[link.b_port] = link.channel
        for channel in sorted(set(channels.values())):
            text += f"interface {channel}\n switchport mode trunk\n!\n"
        for port in sw.ports:
            text += f"interface {port}\n"
            if port in neighbors:
                n, np = neighbors[port]
                text += f" description Uplink to {n} {short_interface(np)}\n switchport mode trunk\n"
                if port in channels:
                    group = channels[port].replace("Port-channel", "")
                    text += f" channel-group {group} mode active\n"
            elif port in sw.access_range:
                text += " description User port\n" if port not in sw.phones else " description Phone + PC\n"
                text += f" switchport access vlan {access.get('vlan', 10)}\n switchport mode access\n"
                if access.get("voice_vlan"):
                    text += f" switchport voice vlan {access['voice_vlan']}\n"
                if port in pre_ports:
                    text += " spanning-tree portfast\n spanning-tree bpduguard enable\n"
            text += "!\n"
        mgmt_vlan = 99 if 99 in self.vlans else 1
        text += f"interface Vlan{mgmt_vlan}\n ip address {sw.mgmt_ip or '10.99.0.250'} 255.255.255.0\n!\n"
        text += (
            "ip default-gateway 10.99.0.254\n!\nline con 0\nline vty 0 4\n login local\n transport input ssh\n!\nend\n"
        )
        cfg = ConfigTree(text)
        # ConfigTree applies portfast edge conversion only through set_child; do it for preconfigured ports.
        for port in pre_ports:
            cfg.set_child(f"interface {port}", "spanning-tree portfast", edge_portfast=sw.edge_syntax)
        return cfg.text()

    def _apply_static_problems(self) -> None:
        p = self.problems
        if nv := p.get("native_vlan_mismatch"):
            sw = self.switches[nv["switch"]]
            sw.cfg.set_child(
                f"interface {canonical_interface(nv['port'])}", f"switchport trunk native vlan {nv['native_vlan']}"
            )
            sw.startup = sw.cfg.text()
        if ed := p.get("errdisabled"):
            sw = self.switches[ed["switch"]]
            port = canonical_interface(ed["port"])
            sw.cfg.set_child(f"interface {port}", "spanning-tree bpduguard enable")
            sw.startup = sw.cfg.text()
            sw.errdisabled[port] = ed.get("reason", "bpduguard")
            at = self.now() - 3 * 3600
            sw.log(
                f"%SPANTREE-2-BLOCK_BPDUGUARD: Received BPDU on port {port} with BPDU Guard enabled. Disabling port.",
                at,
            )
            sw.log(
                f"%PM-4-ERR_DISABLE: bpduguard error detected on {short_interface(port)}, putting {short_interface(port)} in err-disable state",
                at,
            )
        if mf := p.get("macflap"):
            sw = self.switches[mf["switch"]]
            a, b = (short_interface(x) for x in mf["ports"])
            for minutes in (55, 41, 18, 6):
                sw.log(
                    f"%SW_MATM-4-MACFLAP_NOTIF: Host {mf['mac']} in vlan {mf['vlan']} is flapping between port {a} and port {b}",
                    self.now() - minutes * 60,
                )
        if nv := p.get("native_vlan_mismatch"):
            sw = self.switches[nv["switch"]]
            port = canonical_interface(nv["port"])
            peer = next((n, np) for lp, n, np in self.neighbors(sw.name) if lp == port)
            other = self.switches[peer[0]]
            for minutes in (50, 20):
                other.log(
                    f"%CDP-4-NATIVE_VLAN_MISMATCH: Native VLAN mismatch discovered on {peer[1]} (1), with {sw.name} {port} ({nv['native_vlan']}).",
                    self.now() - minutes * 60,
                )
                sw.log(
                    f"%CDP-4-NATIVE_VLAN_MISMATCH: Native VLAN mismatch discovered on {port} ({nv['native_vlan']}), with {other.name} {peer[1]} (1).",
                    self.now() - minutes * 60 - 3,
                )

    # -- flapping port / topology change events ---------------------------------------------
    def _flap(self) -> dict | None:
        return self.problems.get("flapping_port")

    def _flap_generates_tc(self) -> bool:
        flap = self._flap()
        if not flap:
            return False
        sw = self.switches[flap["switch"]]
        port = canonical_interface(flap["port"])
        iface = sw.parsed().interfaces.get(port)
        if iface is not None and iface.shutdown:
            return False
        return not sw.effective_portfast(port)

    def _refresh_flap_state(self) -> None:
        """Start/stop counting flaps when the flapping port gains or loses PortFast."""
        active = self._flap_generates_tc()
        now = self.now()
        if active and self._flap_active_since is None:
            self._flap_active_since = now
            self._flap_deactivated_at = None
        elif not active and self._flap_active_since is not None:
            self._flap_count_frozen = self._flap_events_until(now)
            self._flap_deactivated_at = now
            self._flap_active_since = None

    def _flap_events_until(self, until: float) -> int:
        flap = self._flap()
        if not flap or self._flap_active_since is None:
            return self._flap_count_frozen
        every = float(flap.get("every_seconds", 120))
        return self._flap_count_frozen + int(max(0.0, until - self._flap_active_since) // every)

    def _flap_vlans(self) -> set[int]:
        flap = self._flap()
        if not flap:
            return set()
        sw = self.switches[flap["switch"]]
        iface = sw.parsed().interfaces.get(canonical_interface(flap["port"]))
        vlans = set()
        if iface is not None:
            if iface.access_vlan:
                vlans.add(iface.access_vlan)
            if iface.voice_vlan:
                vlans.add(iface.voice_vlan)
        return vlans or {1}

    def tc_info(self, name: str, vlan: int, state: VlanState) -> tuple[int, float | None, str | None]:
        """(count, seconds since last change, from port) for switch ``name`` in ``vlan``."""
        sw = self.switches[name]
        now = self.now()
        flap = self._flap()
        events: list[tuple[float, str, str]] = []
        count = 0
        if sw.stp_restart <= sw.boot_time:
            count += 3  # changes while the network came up after this switch booted
            # Background: the most recently booted switch's uplink coming up.
            youngest = max(self.switches.values(), key=lambda s: s.boot_time)
            port = state.root_port.get(youngest.name) or next(iter(self.switch_ports(youngest.name)), "")
            events.append((youngest.boot_time + 95, youngest.name, port))
        if flap and vlan in self._flap_vlans() and flap["switch"] in state.cost:
            origin = flap["switch"]
            port = canonical_interface(flap["port"])
            every = float(flap.get("every_seconds", 120))
            new = self._flap_events_until(now)
            if sw.stp_restart <= sw.boot_time:
                count += int(flap.get("historic_changes", 0))
            else:
                # counters restarted: only flaps since then
                new = (
                    int(max(0.0, now - max(sw.stp_restart, self._flap_active_since or now)) // every)
                    if self._flap_active_since
                    else 0
                )
            count += new
            if self._flap_active_since is not None:
                last = now - ((now - self._flap_active_since) % every)
            elif self._flap_deactivated_at is not None:
                last = self._flap_deactivated_at - 1
            else:
                last = self.t0 - 600
            if last >= sw.stp_restart:
                events.append((last, origin, port))
        for event in self.events:
            if vlan in event.vlans and event.time >= sw.stp_restart:
                count += 1
                events.append((event.time, event.origin, event.port))
        if not events:
            return count, None, None
        when, origin, port = max(events, key=lambda e: e[0])
        if origin == name:
            from_port = port
        else:
            from_port = self._toward(state, name, origin)
        return count, max(0.0, now - when), from_port

    def _toward(self, state: VlanState, start: str, target: str) -> str | None:
        """First port on the tree path from ``start`` to ``target``."""

        def ancestors(node: str) -> list[str]:
            chain = [node]
            while state.parent.get(chain[-1]):
                chain.append(state.parent[chain[-1]][0])
                if len(chain) > 64:
                    break
            return chain

        up_target = ancestors(target)
        if start in up_target:
            # target is below start: go down towards the child on target's chain
            child = up_target[up_target.index(start) - 1]
            return state.parent[child][2]
        parent = state.parent.get(start)
        return parent[1] if parent else None

    # -- spanning tree -------------------------------------------------------------------------
    def _segments(self, vlan: int) -> tuple[list[tuple[str, str, str, str]], dict[tuple[str, str], str]]:
        """STP adjacencies carrying ``vlan`` and ports blocked as inconsistent."""
        segments = []
        inconsistent: dict[tuple[str, str], str] = {}
        seen = set()
        for link in self.links:
            a, b = self.switches[link.a], self.switches[link.b]
            ap = a.channel_members().get(link.a_port, link.a_port)
            bp = b.channel_members().get(link.b_port, link.b_port)
            key = (link.a, ap, link.b, bp)
            if key in seen:
                continue
            seen.add(key)
            if not (a.is_up(link.a_port) and b.is_up(link.b_port)):
                continue
            a_if, b_if = a.parsed().interfaces.get(ap), b.parsed().interfaces.get(bp)
            if not self._carries(a_if, vlan) or not self._carries(b_if, vlan):
                continue
            a_native = (a_if.native_vlan or 1) if a_if and a_if.mode == "trunk" else None
            b_native = (b_if.native_vlan or 1) if b_if and b_if.mode == "trunk" else None
            if a_native and b_native and a_native != b_native and vlan in (a_native, b_native):
                inconsistent[(link.a, ap)] = "PVID"
                inconsistent[(link.b, bp)] = "PVID"
                continue
            segments.append((link.a, ap, link.b, bp))
        return segments, inconsistent

    @staticmethod
    def _carries(iface, vlan: int) -> bool:
        if iface is None:
            return False
        if iface.mode == "trunk":
            return iface.allowed_vlans is None or vlan in expand_vlans(iface.allowed_vlans)
        if iface.mode == "access":
            return (iface.access_vlan or 1) == vlan
        return False

    def bridge_id(self, name: str, vlan: int) -> tuple[int, int]:
        sw = self.switches[name]
        priority = sw.cfg.stp_priorities().get(vlan, 32768)
        return priority + vlan, mac_int(sw.mac)

    def compute(self, vlan: int) -> VlanState:
        key = (vlan,) + tuple((sw.cfg.version, tuple(sorted(sw.errdisabled))) for sw in self.switches.values())
        if key not in self._cache:
            self._cache = {k: v for k, v in self._cache.items() if k[1:] == key[1:]}
            self._cache[key] = self._compute(vlan)
        return self._cache[key]

    def _compute(self, vlan: int) -> VlanState:
        segments, inconsistent = self._segments(vlan)
        adjacency: dict[str, list[tuple[str, str, str]]] = {n: [] for n in self.switches}
        for a, ap, b, bp in segments:
            adjacency[a].append((ap, b, bp))
            adjacency[b].append((bp, a, ap))
        bids = {n: self.bridge_id(n, vlan) for n in self.switches}
        # connected components each elect their own root
        component: dict[str, int] = {}
        for start in sorted(self.switches):
            if start in component:
                continue
            stack = [start]
            component[start] = len(set(component.values()))
            while stack:
                node = stack.pop()
                for _, other, _ in adjacency[node]:
                    if other not in component:
                        component[other] = component[start]
                        stack.append(other)
        roots = {}
        for node, comp in component.items():
            if comp not in roots or bids[node] < bids[roots[comp]]:
                roots[comp] = node
        main_root = roots[component[min(self.switches, key=lambda n: bids[n])]]
        state = VlanState(vlan=vlan, root=main_root, root_bid=bids[main_root])
        cost: dict[str, int] = {r: 0 for r in roots.values()}
        best: dict[str, tuple] = {}
        for _ in range(len(self.switches) + 1):
            changed = False
            for node in self.switches:
                if node in roots.values():
                    continue
                candidates = []
                for port, other, other_port in adjacency[node]:
                    if other not in cost:
                        continue
                    sw = self.switches[node]
                    vec = (
                        cost[other] + sw.port_cost(port),
                        bids[other],
                        (128, self.switches[other].port_id(other_port)),
                        (128, sw.port_id(port)),
                    )
                    candidates.append((vec, port, other, other_port))
                if not candidates:
                    continue
                choice = min(candidates, key=lambda c: c[0])
                if best.get(node) != choice:
                    best[node] = choice
                    cost[node] = choice[0][0]
                    changed = True
            if not changed:
                break
        state.cost = cost
        for node in self.switches:
            if node in best:
                vec, port, other, other_port = best[node]
                state.root_port[node] = port
                state.parent[node] = (other, port, other_port)
            else:
                state.root_port[node] = None
                state.parent[node] = None
            state.roles[node] = {}
        for a, ap, b, bp in segments:
            sa, sb = self.switches[a], self.switches[b]
            va = (cost.get(a, 1 << 30), bids[a], sa.port_id(ap))
            vb = (cost.get(b, 1 << 30), bids[b], sb.port_id(bp))
            designated, other = ((a, ap, b, bp), (b, bp, a, ap)) if va < vb else ((b, bp, a, ap), (a, ap, b, bp))
            d, dp, o, op = designated
            state.roles[d][dp] = PortRole(
                dp, "Desg", "FWD", self.switches[d].port_cost(dp), self.switches[d].port_id(dp), "", o
            )
            role = "Root" if state.root_port.get(o) == op else "Altn"
            st = "FWD" if role == "Root" else "BLK"
            state.roles[o][op] = PortRole(
                op, role, st, self.switches[o].port_cost(op), self.switches[o].port_id(op), "", d
            )
        for (node, port), kind in inconsistent.items():
            sw = self.switches[node]
            state.roles[node][port] = PortRole(
                port, "Desg", "BKN", sw.port_cost(port), sw.port_id(port), "", None, kind
            )
        # host ports
        for node, sw in self.switches.items():
            cfg = sw.parsed()
            for port in sorted(sw.hosts, key=interface_sort_key):
                iface = cfg.interfaces.get(port)
                if iface is None or not sw.is_up(port):
                    continue
                if vlan not in ((iface.access_vlan or 1), iface.voice_vlan):
                    continue
                state.roles[node][port] = PortRole(port, "Desg", "FWD", sw.port_cost(port), sw.port_id(port), "")
        # type column
        for node, ports in state.roles.items():
            sw = self.switches[node]
            mode = sw.mode()
            for port, role in ports.items():
                kind = "P2p"
                rogue = self._is_rogue(node, port)
                if role.neighbor is None and not rogue and sw.effective_portfast(port) and role.inconsistent is None:
                    kind += " Edge"
                if mode == "rapid-pvst" and role.neighbor and self.switches[role.neighbor].mode() == "pvst":
                    kind += " Peer(STP)"
                if role.inconsistent:
                    kind += f" *{role.inconsistent}_Inc"
                role.type = kind
        return state

    def _is_rogue(self, node: str, port: str) -> bool:
        rogue = self.problems.get("rogue_switch")
        return bool(rogue) and rogue["switch"] == node and canonical_interface(rogue["port"]) == port

    def check_bpduguard(self, sw: SimSwitch) -> None:
        """Ports that receive BPDUs while BPDU Guard is active go err-disabled."""
        rogue = self.problems.get("rogue_switch")
        if rogue and rogue["switch"] == sw.name:
            port = canonical_interface(rogue["port"])
            if sw.effective_bpduguard(port) and port not in sw.errdisabled and sw.is_up(port):
                sw.errdisabled[port] = "bpduguard"
                sw.log(
                    f"%SPANTREE-2-BLOCK_BPDUGUARD: Received BPDU on port {port} with BPDU Guard enabled. Disabling port."
                )
                sw.log(
                    f"%PM-4-ERR_DISABLE: bpduguard error detected on {short_interface(port)}, putting {short_interface(port)} in err-disable state"
                )

    def config_changed(self, sw: SimSwitch, before: dict[str, Any]) -> None:
        """Called by the SSH server after a configuration session ends."""
        after = self.snapshot(sw)
        now = self.now()
        if before["mode"] != after["mode"]:
            sw.stp_restart = now
            sw.log("%SPANTREE-5-EXTENDED_SYSID: Extended SysId enabled for type vlan")
            self.events.append(TcEvent(now, sw.name, self._any_uplink(sw), set(self.vlans)))
        if before["priorities"] != after["priorities"] or before["pathcost"] != after["pathcost"]:
            changed = {v for v in self.vlans if before["priorities"].get(v) != after["priorities"].get(v)}
            self.events.append(TcEvent(now + 0.5, sw.name, self._any_uplink(sw), changed or set(self.vlans)))
            for vlan in sorted(changed):
                state = self.compute(vlan)
                root = self.switches[state.root]
                for other in self.switches.values():
                    port = state.root_port.get(other.name)
                    other.log(
                        f"%SPANTREE-5-ROOTCHANGE: Root Changed for vlan {vlan}: New Root Port is "
                        f"{port or 'Unknown'}. New Root Mac Address is {root.mac}"
                    )
        self.check_bpduguard(sw)
        self._refresh_flap_state()
        sw.config_changed_at = now

    def snapshot(self, sw: SimSwitch) -> dict[str, Any]:
        cfg = sw.parsed()
        return {"mode": sw.mode(), "priorities": sw.cfg.stp_priorities(), "pathcost": cfg.pathcost_method}

    def _any_uplink(self, sw: SimSwitch) -> str:
        ports = sorted(self.switch_ports(sw.name), key=interface_sort_key)
        return ports[0] if ports else ""

    # -- rendering -------------------------------------------------------------------------------
    def fmt_time(self, ts: float) -> str:
        dt = datetime.fromtimestamp(ts, tz=UTC)
        return dt.strftime("%b %d %H:%M:%S.") + f"{dt.microsecond // 1000:03d}"

    def run(self, name: str, command: str) -> str | None:
        """Render one exec command.  Returns None for unknown commands."""
        from . import render

        return render.run(self, self.switches[name], command)


def ios_duration(seconds: float | None) -> str:
    if seconds is None:
        return "never"
    seconds = int(seconds)
    if seconds < 86400:
        h, rem = divmod(seconds, 3600)
        m, s = divmod(rem, 60)
        return f"{h:02d}:{m:02d}:{s:02d}"
    if seconds < 7 * 86400:
        d, rem = divmod(seconds, 86400)
        return f"{d}d{rem // 3600:02d}h"
    if seconds < 365 * 86400:
        w, rem = divmod(seconds, 7 * 86400)
        return f"{w}w{rem // 86400}d"
    y, rem = divmod(seconds, 365 * 86400)
    return f"{y}y{rem // (7 * 86400)}w"


def uptime_text(seconds: float) -> str:
    seconds = int(seconds)
    parts = []
    for unit, size in (("year", 365 * 86400), ("week", 7 * 86400), ("day", 86400), ("hour", 3600), ("minute", 60)):
        n, seconds = divmod(seconds, size)
        if n:
            parts.append(f"{n} {unit}{'s' if n != 1 else ''}")
    return ", ".join(parts) or "0 minutes"


def load_lab(path: str, clock: Callable[[], float] = time.time) -> Lab:
    import yaml

    with open(path, encoding="utf-8") as handle:
        return Lab(yaml.safe_load(handle), clock=clock)

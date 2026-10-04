"""Render simulated state as Cisco IOS / IOS-XE show command output."""

from __future__ import annotations

import re
from datetime import UTC
from typing import TYPE_CHECKING

from ..util import canonical_interface, compress_vlans, interface_sort_key, short_interface
from .sim import ios_duration, uptime_text

if TYPE_CHECKING:  # pragma: no cover
    from .sim import Lab, SimSwitch, VlanState


def run(lab: Lab, sw: SimSwitch, command: str) -> str | None:
    command = re.sub(r"\s+", " ", command.strip())
    base, pipe = command, None
    if " | " in command:
        base, pipe = command.split(" | ", 1)
    output = _dispatch(lab, sw, _expand(base))
    if output is None:
        return None
    if pipe:
        output = _apply_pipe(output, pipe)
    return output


_KEYWORDS = [
    "show",
    "running-config",
    "startup-config",
    "interfaces",
    "spanning-tree",
    "version",
    "cdp",
    "neighbors",
    "detail",
    "logging",
    "status",
    "err-disabled",
    "trunk",
    "etherchannel",
    "summary",
    "vlan",
    "brief",
    "lldp",
    "privilege",
    "inventory",
    "vtp",
    "mst",
    "configuration",
    "root",
    "clock",
    "users",
    "snmp",
    "user",
    "archive",
]


def _expand(command: str) -> str:
    """Expand unambiguous IOS keyword abbreviations ("sh int status" -> "show interfaces status")."""
    words = []
    for word in command.split():
        low = word.lower()
        if low in _KEYWORDS:
            words.append(low)
            continue
        matches = [k for k in _KEYWORDS if k.startswith(low)]
        words.append(matches[0] if len(matches) == 1 else word)
    return " ".join(words)


def _apply_pipe(output: str, pipe: str) -> str:
    match = re.match(
        r"^(i|in|inc|incl|inclu|includ|include|e|ex|exc|excl|exclu|exclud|exclude|b|be|beg|begi|begin|s|se|sec|sect|secti|sectio|section)\s+(.*)$",
        pipe.strip(),
    )
    if not match:
        return output
    verb, pattern = match.group(1), match.group(2)
    try:
        regex = re.compile(pattern)
    except re.error:
        regex = re.compile(re.escape(pattern))
    lines = output.splitlines()
    if verb.startswith("i"):
        return "\n".join(line for line in lines if regex.search(line))
    if verb.startswith("e"):
        return "\n".join(line for line in lines if not regex.search(line))
    if verb.startswith("b"):
        for i, line in enumerate(lines):
            if regex.search(line):
                return "\n".join(lines[i:])
        return ""
    # section
    out, keep = [], False
    for line in lines:
        if not line.startswith(" "):
            keep = bool(regex.search(line))
        if keep:
            out.append(line)
    return "\n".join(out)


def _dispatch(lab: Lab, sw: SimSwitch, command: str) -> str | None:
    table = {
        "show version": show_version,
        "show running-config": show_running_config,
        "show startup-config": show_startup_config,
        "show spanning-tree": show_spanning_tree,
        "show spanning-tree summary": show_spanning_tree_summary,
        "show spanning-tree detail": show_spanning_tree_detail,
        "show spanning-tree root": show_spanning_tree_root,
        "show spanning-tree mst configuration": show_mst_configuration,
        "show interfaces status": show_interfaces_status,
        "show interfaces status err-disabled": show_errdisabled,
        "show interfaces trunk": show_interfaces_trunk,
        "show etherchannel summary": show_etherchannel_summary,
        "show cdp neighbors detail": show_cdp_neighbors_detail,
        "show cdp neighbors": show_cdp_neighbors,
        "show lldp neighbors detail": lambda lab, sw: "% LLDP is not enabled",
        "show lldp neighbors": lambda lab, sw: "% LLDP is not enabled",
        "show vlan brief": show_vlan_brief,
        "show vlan": show_vlan_brief,
        "show logging": show_logging,
        "show privilege": lambda lab, sw: "Current privilege level is 15",
        "show inventory": show_inventory,
        "show vtp status": show_vtp_status,
        "show clock": lambda lab, sw: "*" + lab.fmt_time(lab.now()) + " UTC " + _weekday(lab),
        "show users": lambda lab, sw: (
            "    Line       User       Host(s)              Idle       Location\n*  1 vty 0     labadmin   idle                 00:00:00 10.99.0.250"
        ),
        "show snmp user": lambda lab, sw: "",
        "show archive": lambda lab, sw: "Archive feature not enabled",
        "show running-config | include hostname": None,
    }
    if command.startswith("show running-config "):
        command = "show running-config"
    func = table.get(command)
    if func is None:
        return None
    return func(lab, sw)


def _weekday(lab: Lab) -> str:
    from datetime import datetime

    return datetime.fromtimestamp(lab.now(), tz=UTC).strftime("%a %b %d %Y")


# ---------------------------------------------------------------------------
def show_version(lab: Lab, sw: SimSwitch) -> str:
    up = uptime_text(sw.uptime)
    if sw.iosxe:
        return f"""Cisco IOS XE Software, Version {sw.version}
Cisco IOS Software [Cupertino], Catalyst L3 Switch Software (CAT9K_IOSXE), Version {sw.version.lstrip("0").replace(".0", ".")}, RELEASE SOFTWARE (fc5)
Technical Support: http://www.cisco.com/techsupport
Copyright (c) 1986-2024 by Cisco Systems, Inc.
Compiled Fri 20-Oct-23 10:44 by mcpre

ROM: IOS-XE ROMMON
BOOTLDR: System Bootstrap, Version 17.6.1r[FC2], RELEASE SOFTWARE (P)

{sw.name} uptime is {up}
Uptime for this control processor is {up}
System returned to ROM by Reload Command
System image file is "flash:packages.conf"
Last reload reason: Reload Command

This product contains cryptographic features and is subject to United
States and local country laws governing import, export, transfer and
use.

cisco {sw.model} (X86) processor with 1419044K/6147K bytes of memory.
Processor board ID {sw.serial}
2048K bytes of non-volatile configuration memory.
8388608K bytes of physical memory.

Base Ethernet MAC Address          : {_colon_mac(sw.mac)}
Motherboard Assembly Number        : 73-17952-06
Model Number                       : {sw.model}
System Serial Number               : {sw.serial}

Configuration register is 0x102
"""
    if "2960X" in sw.model:
        family, train, cpu = "C2960X", "C2960X-UNIVERSALK9-M", "APM86XXX"
        image = "c2960x-universalk9-mz.152-7.E8.bin"
        loader = "C2960X Boot Loader (C2960X-HBOOT-M) Version 15.2(7r)E, RELEASE SOFTWARE (fc1)"
    else:
        family, train, cpu = "C2960", "C2960-LANBASEK9-M", "PowerPC405"
        image = "c2960-lanbasek9-mz.122-55.SE12.bin"
        loader = "C2960 Boot Loader (C2960-HBOOT-M) Version 12.2(53r)SEY3, RELEASE SOFTWARE (fc1)"
    counts = {}
    for port in sw.ports:
        kind = "FastEthernet" if port.startswith("FastEthernet") else "Gigabit Ethernet"
        counts[kind] = counts.get(kind, 0) + 1
    port_lines = "".join(f"{n} {kind} interfaces\n" for kind, n in counts.items())
    return f"""Cisco IOS Software, {family} Software ({train}), Version {sw.version}, RELEASE SOFTWARE (fc1)
Technical Support: http://www.cisco.com/techsupport
Copyright (c) 1986-2023 by Cisco Systems, Inc.
Compiled Tue 31-Oct-23 10:20 by mcpre

ROM: Bootstrap program is {family} boot loader
BOOTLDR: {loader}

{sw.name} uptime is {up}
System returned to ROM by power-on
System image file is "flash:/{image}"
Last reload reason: power-on

This product contains cryptographic features and is subject to United
States and local country laws governing import, export, transfer and
use.

cisco {sw.model} ({cpu}) processor (revision A0) with 524288K bytes of memory.
Processor board ID {sw.serial}
Last reset from power-on
1 Virtual Ethernet interface
{port_lines}The password-recovery mechanism is enabled.

512K bytes of flash-simulated non-volatile configuration memory.
Base ethernet MAC Address       : {_colon_mac(sw.mac).upper()}
Motherboard assembly number     : 73-15720-08
Model number                    : {sw.model}
System serial number            : {sw.serial}

Switch Ports Model                     SW Version            SW Image
------ ----- -----                     ----------            ----------
*    1 52    {sw.model:<25} {sw.version:<21} {train}


Configuration register is 0xF
"""


def _colon_mac(mac: str) -> str:
    digits = mac.replace(".", "")
    return ":".join(digits[i : i + 2] for i in range(0, 12, 2))


def show_running_config(lab: Lab, sw: SimSwitch) -> str:
    body = sw.cfg.text()
    changed = lab.fmt_time(sw.config_changed_at)
    return (
        f"Building configuration...\n\nCurrent configuration : {len(body)} bytes\n!\n"
        f"! Last configuration change at {changed} UTC by labadmin\n!\n{body}"
    )


def show_startup_config(lab: Lab, sw: SimSwitch) -> str:
    body = sw.startup
    return f"Using {len(body)} out of 524288 bytes\n!\n{body}"


def show_inventory(lab: Lab, sw: SimSwitch) -> str:
    return f'NAME: "1", DESCR: "{sw.model}"\nPID: {sw.model:<20}, VID: V02  , SN: {sw.serial}\n'


def show_vtp_status(lab: Lab, sw: SimSwitch) -> str:
    return (
        "VTP Version capable             : 1 to 3\n"
        "VTP version running             : 1\n"
        "VTP Domain Name                 : \n"
        "VTP Pruning Mode                : Disabled\n"
        "VTP Traps Generation            : Disabled\n"
        f"Device ID                       : {sw.mac}\n"
        "Configuration last modified by 0.0.0.0 at 0-0-00 00:00:00\n\n"
        "Feature VLAN:\n--------------\n"
        "VTP Operating Mode                : Transparent\n"
        f"Maximum VLANs supported locally   : 1005\n"
        f"Number of existing VLANs          : {len(lab.vlans) + 4}\n"
        "Configuration Revision            : 0\n"
    )


# ---------------------------------------------------------------------------
def _states(lab: Lab) -> list[VlanState]:
    return [lab.compute(vlan) for vlan in sorted(lab.vlans)]


def _protocol(sw: SimSwitch) -> str:
    return {"rapid-pvst": "rstp", "pvst": "ieee", "mst": "mstp"}.get(sw.mode(), "ieee")


def show_spanning_tree(lab: Lab, sw: SimSwitch) -> str:
    out = []
    for state in _states(lab):
        ports = state.roles.get(sw.name) or {}
        if not ports:
            continue
        vlan = state.vlan
        root_prio, root_mac = lab.bridge_id(state.root, vlan)[0], lab.switches[state.root].mac
        my_prio = lab.bridge_id(sw.name, vlan)[0]
        out.append(f"\nVLAN{vlan:04d}")
        out.append(f"  Spanning tree enabled protocol {_protocol(sw)}")
        out.append(f"  Root ID    Priority    {root_prio}")
        out.append(f"             Address     {root_mac}")
        if state.root == sw.name:
            out.append("             This bridge is the root")
        else:
            rp = state.root_port.get(sw.name)
            out.append(f"             Cost        {state.cost.get(sw.name, 0)}")
            out.append(f"             Port        {sw.port_id(rp) if rp else 0} ({rp})")
        out.append("             Hello Time   2 sec  Max Age 20 sec  Forward Delay 15 sec")
        out.append("")
        out.append(f"  Bridge ID  Priority    {my_prio}  (priority {my_prio - vlan} sys-id-ext {vlan})")
        out.append(f"             Address     {sw.mac}")
        out.append("             Hello Time   2 sec  Max Age 20 sec  Forward Delay 15 sec")
        out.append("             Aging Time  300 sec")
        out.append("")
        out.append("Interface           Role Sts Cost      Prio.Nbr Type")
        out.append("------------------- ---- --- --------- -------- --------------------------------")
        for port in sorted(ports, key=interface_sort_key):
            role = ports[port]
            sts = "BKN*" if role.state == "BKN" else f"{role.state} "
            prio = f"128.{role.number}"
            line = f"{short_interface(port):<19} {role.role:<4} {sts}{role.cost:<9} {prio:<8} {role.type}"
            out.append(line.rstrip())
        out.append("")
    return "\n".join(out) + "\n"


def show_spanning_tree_root(lab: Lab, sw: SimSwitch) -> str:
    out = [
        "                                        Root    Hello Max Fwd",
        "Vlan                   Root ID          Cost    Time  Age Dly  Root Port",
        "---------------- -------------------- --------- ----- --- ---  ------------",
    ]
    for state in _states(lab):
        if not state.roles.get(sw.name):
            continue
        prio = lab.bridge_id(state.root, state.vlan)[0]
        mac = lab.switches[state.root].mac
        rp = state.root_port.get(sw.name)
        cost = state.cost.get(sw.name, 0)
        out.append(
            f"VLAN{state.vlan:04d}         {prio:>5} {mac} {cost:>9} {2:>4} {20:>4} {15:>3}  {short_interface(rp) if rp else ''}"
        )
    return "\n".join(out) + "\n"


def show_spanning_tree_summary(lab: Lab, sw: SimSwitch) -> str:
    cfg = sw.parsed()
    mode = sw.mode()
    states = [s for s in _states(lab) if s.roles.get(sw.name)]
    root_for = [f"VLAN{s.vlan:04d}" for s in states if s.root == sw.name]
    edge = "Edge " if sw.edge_syntax or sw.iosxe else ""
    rapid = mode != "pvst"
    lines = [f"Switch is in {mode} mode", f"Root bridge for: {', '.join(root_for) if root_for else 'none'}"]
    flags = [
        ("Extended system ID", "enabled" if cfg.extend_system_id is not False else "disabled"),
        ("Portfast Default", "enabled" if cfg.portfast_default else "disabled"),
        (f"Portfast {edge}BPDU Guard Default", "enabled" if cfg.bpduguard_default else "disabled"),
        (f"Portfast {edge}BPDU Filter Default", "enabled" if cfg.bpdufilter_default else "disabled"),
        ("Loopguard Default", "enabled" if cfg.loopguard_default else "disabled"),
    ]
    if sw.edge_syntax or sw.iosxe:
        flags.append(("PVST Simulation Default", "enabled but inactive in rapid-pvst mode" if rapid else "enabled"))
        flags.append(("Bridge Assurance", "enabled but inactive in rapid-pvst mode" if rapid else "enabled"))
    flags.append(("EtherChannel misconfig guard", "enabled"))
    if sw.edge_syntax or sw.iosxe:
        flags.append(("Configured Pathcost method used", cfg.pathcost_method or "short"))
    flags.append(("UplinkFast", "enabled" if cfg.uplinkfast else "disabled"))
    flags.append(("BackboneFast", "enabled" if cfg.backbonefast else "disabled"))
    width = 40 if (sw.edge_syntax or sw.iosxe) else 29
    for key, value in flags:
        lines.append(f"{key:<{width}}is {value}")
    if not (sw.edge_syntax or sw.iosxe):
        lines.append(f"Configured Pathcost method used is {cfg.pathcost_method or 'short'}")
    lines.append("")
    lines.append("Name                   Blocking Listening Learning Forwarding STP Active")
    lines.append("---------------------- -------- --------- -------- ---------- ----------")
    totals = [0, 0, 0, 0, 0]
    for state in states:
        ports = state.roles[sw.name].values()
        blocking = sum(1 for p in ports if p.state in ("BLK", "BKN"))
        forwarding = sum(1 for p in ports if p.state == "FWD")
        row = [blocking, 0, 0, forwarding, blocking + forwarding]
        totals = [a + b for a, b in zip(totals, row)]
        lines.append(f"VLAN{state.vlan:04d}{'':<15}{row[0]:>8}{row[1]:>10}{row[2]:>9}{row[3]:>11}{row[4]:>11}")
    lines.append("---------------------- -------- --------- -------- ---------- ----------")
    lines.append(
        f"{str(len(states)) + ' vlans':<22}{totals[0]:>9}{totals[1]:>10}{totals[2]:>9}{totals[3]:>11}{totals[4]:>11}"
    )
    return "\n".join(lines) + "\n"


def show_spanning_tree_detail(lab: Lab, sw: SimSwitch) -> str:
    out = []
    rapid = sw.mode() == "rapid-pvst"
    uptime = int(sw.uptime)
    for state in _states(lab):
        ports = state.roles.get(sw.name) or {}
        if not ports:
            continue
        vlan = state.vlan
        my_prio = lab.bridge_id(sw.name, vlan)[0]
        root_prio = lab.bridge_id(state.root, vlan)[0]
        count, last, from_port = lab.tc_info(sw.name, vlan, state)
        out.append(f" VLAN{vlan:04d} is executing the {_protocol(sw)} compatible Spanning Tree protocol")
        out.append(f"  Bridge Identifier has priority {my_prio - vlan}, sysid {vlan}, address {sw.mac}")
        out.append(
            "  Configured hello time 2, max age 20, forward delay 15" + (", transmit hold-count 6" if rapid else "")
        )
        if state.root == sw.name:
            out.append("  We are the root of the spanning tree")
        else:
            rp = state.root_port.get(sw.name)
            out.append(f"  Current root has priority {root_prio}, address {lab.switches[state.root].mac}")
            out.append(f"  Root port is {sw.port_id(rp)} ({rp}), cost of root path is {state.cost.get(sw.name, 0)}")
        out.append("  Topology change flag not set, detected flag not set")
        out.append(f"  Number of topology changes {count} last change occurred {ios_duration(last)} ago")
        if from_port:
            out.append(f"          from {canonical_interface(from_port)}")
        out.append("  Times:  hold 1, topology change 35, notification 2")
        out.append("          hello 2, max age 20, forward delay 15 ")
        out.append("  Timers: hello 0, topology change 0, notification 0, aging 300")
        out.append("")
        for port in sorted(ports, key=interface_sort_key):
            role = ports[port]
            status = {
                ("Desg", "FWD"): "designated forwarding",
                ("Root", "FWD"): "root forwarding",
                ("Altn", "BLK"): "alternate blocking",
            }.get(
                (role.role, role.state),
                "broken  (Port VLAN ID Mismatch)" if role.inconsistent == "PVID" else "designated forwarding",
            )
            out.append(f" Port {role.number} ({port}) of VLAN{vlan:04d} is {status}")
            out.append(f"   Port path cost {role.cost}, Port priority 128, Port Identifier 128.{role.number}.")
            out.append(f"   Designated root has priority {root_prio}, address {lab.switches[state.root].mac}")
            if role.role == "Desg":
                d_name, d_cost, d_port = sw.name, state.cost.get(sw.name, 0), role.number
            else:
                d_name = role.neighbor or sw.name
                d_cost = state.cost.get(d_name, 0)
                d_port = lab.switches[d_name].port_id(_far_port(lab, sw.name, port, d_name))
            d_prio = lab.bridge_id(d_name, vlan)[0]
            out.append(f"   Designated bridge has priority {d_prio}, address {lab.switches[d_name].mac}")
            out.append(f"   Designated port id is 128.{d_port}, designated path cost {d_cost}")
            out.append("   Timers: message age 0, forward delay 0, hold 0")
            transitions = 1
            flap = lab.problems.get("flapping_port")
            if flap and flap["switch"] == sw.name and canonical_interface(flap["port"]) == port:
                transitions = int(flap.get("historic_changes", 0)) // 2 + lab._flap_events_until(lab.now())
            out.append(f"   Number of transitions to forwarding state: {transitions}")
            if role.neighbor is None and sw.effective_portfast(port) and not lab._is_rogue(sw.name, port):
                out.append(f"   The port is in the portfast {'edge ' if sw.edge_syntax else ''}mode")
            out.append("   Link type is point-to-point by default")
            if sw.effective_bpduguard(port):
                out.append("   Bpdu guard is enabled")
            iface = sw.parsed().interfaces.get(port)
            if iface is not None and iface.guard == "root":
                out.append("   Root guard is enabled on the port")
            sent, received = _bpdu_counters(lab, sw, port, role, uptime)
            out.append(f"   BPDU: sent {sent}, received {received}")
            out.append("")
    return "\n".join(out) + "\n"


def _far_port(lab: Lab, host: str, port: str, neighbor: str) -> str:
    for local, other, other_port in lab.neighbors(host):
        member_of = lab.switches[host].channel_members().get(local, local)
        if member_of == port and other == neighbor:
            return lab.switches[neighbor].channel_members().get(other_port, other_port)
    return port


def _bpdu_counters(lab: Lab, sw: SimSwitch, port: str, role, uptime: int) -> tuple[int, int]:
    if lab._is_rogue(sw.name, port):
        return uptime // 2, int(lab.problems["rogue_switch"].get("bpdus_received", 5))
    if role.neighbor is None:
        return uptime // 2, 0
    if role.role == "Desg":
        return uptime // 2, 4
    return 6, uptime // 2


def show_mst_configuration(lab: Lab, sw: SimSwitch) -> str:
    cfg = sw.parsed()
    name = cfg.mst_name or ""
    revision = cfg.mst_revision or 0
    instances = {0: "1-4094"}
    instances.update(cfg.mst_instances)
    lines = [
        f"Name      [{name}]",
        f"Revision  {revision}     Instances configured {len(instances)}",
        "",
        "Instance  Vlans mapped",
        "--------  ---------------------------------------------------------------------",
    ]
    for inst, vlans in sorted(instances.items()):
        lines.append(f"{inst:<9} {vlans}")
    lines.append("-------------------------------------------------------------------------------")
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
def _port_type(sw: SimSwitch, port: str) -> str:
    if port.startswith("TenGigabitEthernet"):
        return "SFP-10GBase-SR"
    if port.startswith("FastEthernet"):
        return "10/100BaseTX"
    if port.startswith("GigabitEthernet") and sw.port_number.get(port, 0) > 48:
        return "1000BaseSX SFP"
    return "10/100/1000BaseTX"


def show_interfaces_status(lab: Lab, sw: SimSwitch) -> str:
    cfg = sw.parsed()
    lines = ["", "Port      Name               Status       Vlan       Duplex  Speed Type"]
    ports = list(sw.ports) + sorted({ch for ch in sw.channel_members().values()})
    for port in sorted(ports, key=interface_sort_key):
        iface = cfg.interfaces.get(port)
        name = (iface.description if iface else "")[:18]
        if port in sw.errdisabled:
            status = "err-disabled"
        elif iface is not None and iface.shutdown:
            status = "disabled"
        elif sw.is_up(port):
            status = "connected"
        else:
            status = "notconnect"
        if iface is not None and iface.mode == "trunk":
            vlan = "trunk"
        elif iface is not None and iface.mode == "routed":
            vlan = "routed"
        else:
            vlan = str(iface.access_vlan or 1) if iface else "1"
        if port.startswith("Port-channel"):
            line = f"{short_interface(port):<10}{name:<19}{status:<13}{vlan:<11}{'a-full':>6} {'a-' + _speed_label(sw.speed(port)):>6} "
        else:
            up = status == "connected"
            speed = _speed_label(sw.speed(port))
            duplex = "a-full" if up else "auto"
            speed_text = f"a-{speed}" if up else "auto"
            if port.startswith("TenGigabitEthernet"):
                duplex, speed_text = ("full", "10G") if up else ("full", "10G")
            line = f"{short_interface(port):<10}{name:<19}{status:<13}{vlan:<11}{duplex:>6} {speed_text:>6} {_port_type(sw, port)}"
        lines.append(line.rstrip())
    return "\n".join(lines) + "\n"


def _speed_label(speed: str) -> str:
    return {"10000": "10G", "1000": "1000", "100": "100", "10": "10", "20000": "20G", "2000": "2000"}.get(speed, speed)


def show_errdisabled(lab: Lab, sw: SimSwitch) -> str:
    cfg = sw.parsed()
    lines = ["", "Port      Name               Status       Reason               Err-disabled Vlans"]
    for port in sorted(sw.errdisabled, key=interface_sort_key):
        iface = cfg.interfaces.get(port)
        name = (iface.description if iface else "")[:18]
        lines.append(f"{short_interface(port):<10}{name:<19}{'err-disabled':<13}{sw.errdisabled[port]}")
    return "\n".join(lines) + "\n"


def show_interfaces_trunk(lab: Lab, sw: SimSwitch) -> str:
    cfg = sw.parsed()
    members = sw.channel_members()
    trunks = []
    for name, iface in cfg.interfaces.items():
        if iface.mode != "trunk" or name in members:
            continue
        if not sw.is_up(name):
            continue
        trunks.append((name, iface))
    trunks.sort(key=lambda t: interface_sort_key(t[0]))
    if not trunks:
        return ""
    states = _states(lab)
    out = ["", "Port        Mode             Encapsulation  Status        Native vlan"]
    for name, iface in trunks:
        out.append(f"{short_interface(name):<12}{'on':<17}{'802.1q':<15}{'trunking':<14}{iface.native_vlan or 1}")
    out += ["", "Port        Vlans allowed on trunk"]
    for name, iface in trunks:
        out.append(f"{short_interface(name):<12}{iface.allowed_vlans or '1-4094'}")
    out += ["", "Port        Vlans allowed and active in management domain"]
    active = compress_vlans(lab.vlans)
    for name, _ in trunks:
        out.append(f"{short_interface(name):<12}{active}")
    out += ["", "Port        Vlans in spanning tree forwarding state and not pruned"]
    for name, _ in trunks:
        fwd = [s.vlan for s in states if (r := s.roles.get(sw.name, {}).get(name)) is not None and r.state == "FWD"]
        out.append(f"{short_interface(name):<12}{compress_vlans(fwd) or 'none'}")
    return "\n".join(out) + "\n"


def show_etherchannel_summary(lab: Lab, sw: SimSwitch) -> str:
    head = """Flags:  D - down        P - bundled in port-channel
        I - stand-alone s - suspended
        H - Hot-standby (LACP only)
        R - Layer3      S - Layer2
        U - in use      f - failed to allocate aggregator

        M - not in use, minimum links not met
        u - unsuitable for bundling
        w - waiting to be aggregated
        d - default port

        A - formed by Auto LAG

"""
    groups: dict[str, list[str]] = {}
    for member, channel in sw.channel_members().items():
        groups.setdefault(channel, []).append(member)
    out = [
        head,
        f"Number of channel-groups in use: {len(groups)}",
        f"Number of aggregators:           {len(groups)}",
        "",
    ]
    out.append("Group  Port-channel  Protocol    Ports")
    out.append("------+-------------+-----------+-----------------------------------------------")
    for channel in sorted(groups, key=interface_sort_key):
        num = channel.replace("Port-channel", "")
        members = "  ".join(
            f"{short_interface(m)}({'P' if sw.is_up(m) else 'D'})"
            for m in sorted(groups[channel], key=interface_sort_key)
        )
        flag = "SU" if any(sw.is_up(m) for m in groups[channel]) else "SD"
        out.append(f"{num:<7}{short_interface(channel) + '(' + flag + ')':<16}{'LACP':<10}{members}")
    return "\n".join(out) + "\n"


def _cdp_entry(lab: Lab, local_sw: SimSwitch, local_port: str, remote: SimSwitch, remote_port: str) -> str:
    platform = f"cisco {remote.model}"
    caps = "Router Switch IGMP" if remote.iosxe else "Switch IGMP"
    software = (
        f"Cisco IOS Software [Cupertino], Catalyst L3 Switch Software (CAT9K_IOSXE), Version {remote.version}, RELEASE SOFTWARE (fc5)"
        if remote.iosxe
        else f"Cisco IOS Software, C2960X Software (C2960X-UNIVERSALK9-M), Version {remote.version}, RELEASE SOFTWARE (fc1)"
    )
    iface = remote.parsed().interfaces.get(remote_port)
    native = (iface.native_vlan or 1) if iface else 1
    return f"""-------------------------
Device ID: {remote.name}.lab.local
Entry address(es):
  IP address: {remote.mgmt_ip}
Platform: {platform},  Capabilities: {caps}
Interface: {local_port},  Port ID (outgoing port): {remote_port}
Holdtime : 152 sec

Version :
{software}
Technical Support: http://www.cisco.com/techsupport
Copyright (c) 1986-2023 by Cisco Systems, Inc.
Compiled Tue 31-Oct-23 10:20 by mcpre

advertisement version: 2
Protocol Hello:  OUI=0x00000C, Protocol ID=0x0112; payload len=27, value=00000000FFFFFFFF010221FF000000000000{remote.mac.replace(".", "").upper()}FF0000
VTP Management Domain: ''
Native VLAN: {native}
Duplex: full
Management address(es):
  IP address: {remote.mgmt_ip}
"""


def _phone_entry(sw: SimSwitch, port: str, index: int) -> str:
    mac = f"0041d2{index:06x}".upper()
    return f"""-------------------------
Device ID: SEP{mac}
Entry address(es):
  IP address: 10.20.0.{index + 10}
Platform: Cisco IP Phone 8845,  Capabilities: Host Phone Two-port Mac Relay
Interface: {port},  Port ID (outgoing port): Port 1
Holdtime : 163 sec
Second Port Status: Up

Version :
sip8845_65.14-1-1MN-18

advertisement version: 2
Duplex: full
Power drawn: 6.300 Watts
Power request id: 51402, Power management id: 3
Power request levels are:6300 0 0 0 0
Management address(es):
"""


def show_cdp_neighbors_detail(lab: Lab, sw: SimSwitch) -> str:
    entries = []
    for local, other, other_port in sorted(lab.neighbors(sw.name), key=lambda n: interface_sort_key(n[0])):
        if not (sw.is_up(local) and lab.switches[other].is_up(other_port)):
            continue
        entries.append(_cdp_entry(lab, sw, local, lab.switches[other], other_port))
    for i, port in enumerate(sorted(sw.phones, key=interface_sort_key)):
        if sw.is_up(port):
            entries.append(_phone_entry(sw, port, i + 1))
    return "\n".join(entries) + f"\n\nTotal cdp entries displayed : {len(entries)}\n"


def show_cdp_neighbors(lab: Lab, sw: SimSwitch) -> str:
    out = [
        "Capability Codes: R - Router, T - Trans Bridge, B - Source Route Bridge",
        "                  S - Switch, H - Host, I - IGMP, r - Repeater, P - Phone,",
        "                  D - Remote, C - CVTA, M - Two-port Mac Relay ",
        "",
        "Device ID        Local Intrfce     Holdtme    Capability  Platform  Port ID",
    ]
    for local, other, other_port in sorted(lab.neighbors(sw.name), key=lambda n: interface_sort_key(n[0])):
        remote = lab.switches[other]
        out.append(
            f"{other + '.lab.local':<17}{short_interface(local):<18}{152:<11}{'S I':<12}{remote.model[:9]:<10}{short_interface(other_port)}"
        )
    return "\n".join(out) + "\n"


def show_vlan_brief(lab: Lab, sw: SimSwitch) -> str:
    out = [
        "",
        "VLAN Name                             Status    Ports",
        "---- -------------------------------- --------- -------------------------------",
    ]
    cfg = sw.parsed()
    for vlan, name in sorted(lab.vlans.items()):
        ports = [
            short_interface(p)
            for p, iface in sorted(cfg.interfaces.items(), key=lambda kv: interface_sort_key(kv[0]))
            if iface.mode == "access" and (iface.access_vlan or 1) == vlan
        ]
        first = ", ".join(ports[:4])
        out.append(f"{vlan:<4} {name:<32} {'active':<9} {first}")
        for i in range(4, len(ports), 4):
            out.append(f"{'':<47}{', '.join(ports[i : i + 4])}")
    for vlan, name in (
        (1002, "fddi-default"),
        (1003, "token-ring-default"),
        (1004, "fddinet-default"),
        (1005, "trnet-default"),
    ):
        out.append(f"{vlan:<4} {name:<32} act/unsup ")
    return "\n".join(out) + "\n"


def show_logging(lab: Lab, sw: SimSwitch) -> str:
    events = list(sw.logs)
    flap = lab.problems.get("flapping_port")
    if flap and flap["switch"] == sw.name:
        port = canonical_interface(flap["port"])
        every = float(flap.get("every_seconds", 120))
        now = lab.now()
        if lab._flap_active_since is not None:
            last = now - ((now - lab._flap_active_since) % every)
        else:
            last = (lab._flap_deactivated_at or now) - 1
        for i in range(12):
            t = last - i * every
            events.append((t, f"%LINK-3-UPDOWN: Interface {port}, changed state to up"))
            events.append((t - 4, f"%LINK-3-UPDOWN: Interface {port}, changed state to down"))
    events.sort()
    header = (
        "Syslog logging: enabled (0 messages dropped, 2 messages rate-limited, 0 flushes, 0 overruns, xml disabled, filtering disabled)\n\n"
        "Log Buffer (16384 bytes):\n"
    )
    return header + "\n".join(f"*{lab.fmt_time(t)}: {msg}" for t, msg in events[-200:]) + "\n"

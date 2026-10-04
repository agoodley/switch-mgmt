import json

from conftest import fixture_text

from netaudit.parsers import AUDIT_COMMANDS, build_device, load_devices
from netaudit.parsers.config import parse_running_config, split_sections
from netaudit.parsers.interfaces import parse_errdisabled, parse_interfaces_status, parse_interfaces_trunk
from netaudit.parsers.neighbors import parse_cdp_neighbors_detail, parse_lldp_neighbors_detail
from netaudit.parsers.platform import parse_etherchannel_summary, parse_logging, parse_version, parse_vlan_brief
from netaudit.parsers.stp import (
    parse_mst_configuration,
    parse_spanning_tree,
    parse_spanning_tree_detail,
    parse_spanning_tree_summary,
)

# -- spanning tree -------------------------------------------------------------------


def test_spanning_tree_non_root_instance():
    stp = parse_spanning_tree(fixture_text("show_spanning_tree.txt"))
    assert set(stp) == {"VLAN0001", "VLAN0010"}
    vlan1 = stp["VLAN0001"]
    assert vlan1.vlan == 1
    assert vlan1.protocol == "ieee"
    assert (vlan1.root_priority, vlan1.root_mac, vlan1.root_cost) == (32769, "0019.e8a4.0100", 4)
    assert vlan1.root_port == "GigabitEthernet1/0/49"
    assert not vlan1.is_root
    assert (vlan1.bridge_priority, vlan1.bridge_priority_base, vlan1.bridge_sysid) == (32769, 32768, 1)
    assert vlan1.bridge_mac == "0021.a0b1.0200"
    assert (vlan1.hello, vlan1.max_age, vlan1.forward_delay) == (2, 20, 15)

    ports = vlan1.ports
    assert list(ports) == [
        "GigabitEthernet1/0/11",
        "GigabitEthernet1/0/12",
        "GigabitEthernet1/0/48",
        "GigabitEthernet1/0/49",
        "GigabitEthernet1/0/50",
    ]
    assert (ports["GigabitEthernet1/0/49"].role, ports["GigabitEthernet1/0/49"].state) == ("Root", "FWD")
    assert (ports["GigabitEthernet1/0/50"].role, ports["GigabitEthernet1/0/50"].state) == ("Altn", "BLK")
    assert ports["GigabitEthernet1/0/50"].number == 50
    assert not ports["GigabitEthernet1/0/12"].p2p  # "Shr" = half duplex
    pvid = ports["GigabitEthernet1/0/48"]
    assert (pvid.state, pvid.cost, pvid.inconsistent) == ("BKN", 4, "PVID")


def test_spanning_tree_root_instance_flags():
    vlan10 = parse_spanning_tree(fixture_text("show_spanning_tree.txt"))["VLAN0010"]
    assert vlan10.protocol == "rstp"
    assert vlan10.is_root
    assert vlan10.root_cost == 0
    assert vlan10.root_port is None
    assert vlan10.bridge_priority_base == 4096
    ports = vlan10.ports
    assert ports["GigabitEthernet1/0/1"].peer == "Peer(STP)"
    assert ports["GigabitEthernet1/0/2"].inconsistent == "ROOT"
    assert ports["GigabitEthernet1/0/10"].edge
    assert not ports["GigabitEthernet1/0/1"].edge
    assert ports["Port-channel1"].number == 2081


def test_spanning_tree_12_2_without_sys_id_ext():
    vlan1 = parse_spanning_tree(fixture_text("show_spanning_tree_12_2.txt"))["VLAN0001"]
    assert vlan1.root_port == "GigabitEthernet0/2"
    assert vlan1.bridge_priority == 32769
    # derived from the VLAN number when "(priority X sys-id-ext Y)" is missing
    assert (vlan1.bridge_priority_base, vlan1.bridge_sysid) == (32768, 1)
    assert set(vlan1.ports) == {"FastEthernet0/1", "GigabitEthernet0/1", "GigabitEthernet0/2"}


def test_spanning_tree_detail_counters():
    stp = parse_spanning_tree_detail(fixture_text("show_spanning_tree_detail.txt"))
    vlan1 = stp["VLAN0001"]
    assert vlan1.is_root
    assert vlan1.tc_count == 3
    assert vlan1.tc_last_seconds == 15 * 86400
    assert vlan1.tc_from == "GigabitEthernet1/0/50"
    assert not vlan1.tc_in_progress

    vlan10 = stp["VLAN0010"]
    assert vlan10.protocol == "rstp"
    assert (vlan10.bridge_priority_base, vlan10.bridge_sysid, vlan10.bridge_priority) == (32768, 10, 32778)
    assert (vlan10.root_priority, vlan10.root_mac) == (32778, "0019.e8a4.0100")
    assert (vlan10.root_port, vlan10.root_cost) == ("GigabitEthernet1/0/49", 8)
    assert (vlan10.tc_count, vlan10.tc_last_seconds, vlan10.tc_from) == (21436, 41, "GigabitEthernet1/0/7")
    assert vlan10.tc_in_progress

    flapping = vlan10.port_details["GigabitEthernet1/0/7"]
    assert flapping.status == "designated forwarding"
    assert (flapping.transitions, flapping.bpdu_sent, flapping.bpdu_received) == (1203, 1350, 0)
    assert not flapping.portfast

    edge = vlan10.port_details["GigabitEthernet1/0/30"]
    assert edge.portfast and edge.bpduguard and not edge.bpdufilter

    uplink = vlan10.port_details["GigabitEthernet1/0/49"]
    assert uplink.loop_guard
    assert uplink.bpdu_received == 1784021
    assert (uplink.designated_bridge_priority, uplink.designated_bridge_mac) == (32778, "00a3.d1f4.1180")

    alternate = vlan10.port_details["GigabitEthernet1/0/50"]
    assert alternate.status == "alternate blocking"
    assert not alternate.portfast  # "portfast network" is not an edge port
    assert alternate.root_guard and alternate.bpdufilter


def test_spanning_tree_detail_merges_into_brief_output():
    stp = parse_spanning_tree(fixture_text("show_spanning_tree.txt"))
    parse_spanning_tree_detail(fixture_text("show_spanning_tree_detail.txt"), stp)
    vlan1 = stp["VLAN0001"]
    # values from the brief output win; counters come from the detail
    assert vlan1.bridge_mac == "0021.a0b1.0200"
    assert vlan1.tc_count == 3
    assert "GigabitEthernet1/0/49" in vlan1.ports


def test_spanning_tree_summary():
    summary = parse_spanning_tree_summary(fixture_text("show_spanning_tree_summary.txt"))
    assert summary.mode == "rapid-pvst"
    assert summary.root_for == [
        "VLAN0010",
        "VLAN0020",
        "VLAN0030",
        "VLAN0040",
        "VLAN0050",
        "VLAN0060",
        "VLAN0099",
    ]
    assert summary.extended_system_id == "enabled"
    assert summary.portfast_default == "disabled"
    assert summary.bpduguard_default == "enabled"
    assert summary.bpdufilter_default == "disabled"
    assert summary.loopguard_default == "disabled"
    assert summary.pathcost_method == "long"
    assert summary.etherchannel_guard == "enabled"
    assert summary.instance_counts["VLAN0001"] == {
        "blocking": 1,
        "listening": 0,
        "learning": 0,
        "forwarding": 3,
        "active": 4,
    }


def test_spanning_tree_summary_12_2():
    summary = parse_spanning_tree_summary(fixture_text("show_spanning_tree_summary_12_2.txt"))
    assert summary.mode == "pvst"
    assert summary.root_for == []
    assert summary.bpduguard_default == "disabled"
    assert summary.uplinkfast == "enabled"
    assert summary.pathcost_method == "short"


def test_mst_configuration():
    mst = parse_mst_configuration(fixture_text("show_mst_configuration.txt"))
    assert mst == {"name": "CAMPUS", "revision": 3, "instances": {0: "1-9,11-19,21-98,100-4094", 1: "10,20", 2: "99"}}


# -- interfaces ------------------------------------------------------------------------


def test_interfaces_status():
    status = parse_interfaces_status(fixture_text("show_interfaces_status.txt"))
    gi1 = status["GigabitEthernet1/0/1"]
    assert (gi1.name, gi1.status, gi1.vlan, gi1.duplex, gi1.speed, gi1.type) == (
        "User port",
        "connected",
        "10",
        "a-full",
        "a-1000",
        "10/100/1000BaseTX",
    )
    assert status["GigabitEthernet1/0/2"].status == "notconnect"
    assert status["GigabitEthernet1/0/15"].name == ""
    assert status["GigabitEthernet1/0/15"].status == "err-disabled"
    assert status["GigabitEthernet1/0/16"].status == "disabled"
    # a description longer than the column pushes everything right
    drifted = status["GigabitEthernet1/0/11"]
    assert (drifted.name, drifted.status, drifted.vlan) == ("Desk switch - do not touch", "connected", "10")
    tdr = status["GigabitEthernet1/0/17"]
    assert (tdr.status, tdr.vlan, tdr.duplex) == ("notconnect", "10", "auto")
    assert status["GigabitEthernet1/0/18"].vlan == "pvlan prom"
    assert status["GigabitEthernet1/0/20"].vlan == "routed"
    assert status["GigabitEthernet1/0/49"].type == "1000BaseSX SFP"
    assert status["GigabitEthernet1/0/52"].type == "Not Present"
    assert status["Port-channel1"].vlan == "trunk"


def test_errdisabled():
    assert parse_errdisabled(fixture_text("show_interfaces_status_errdisabled.txt")) == {
        "GigabitEthernet1/0/15": "bpduguard",
        "FastEthernet0/15": "bpduguard",
        "GigabitEthernet1/0/21": "loopback",
    }


def test_interfaces_trunk():
    trunks = parse_interfaces_trunk(fixture_text("show_interfaces_trunk.txt"))
    assert set(trunks) == {"GigabitEthernet1/0/48", "GigabitEthernet1/0/49", "Port-channel1"}
    po = trunks["Port-channel1"]
    assert (po.mode, po.encapsulation, po.status, po.native_vlan) == ("on", "802.1q", "trunking", 99)
    assert (po.allowed, po.active, po.forwarding) == ("10,20,99", "10,20,99", "10,20,99")
    assert trunks["GigabitEthernet1/0/48"].forwarding == "10,20"


def test_etherchannel_summary():
    channels = parse_etherchannel_summary(fixture_text("show_etherchannel_summary.txt"))
    assert set(channels) == {"Port-channel1", "Port-channel2"}
    po1 = channels["Port-channel1"]
    assert (po1.group, po1.flags, po1.protocol) == (1, "SU", "LACP")
    assert po1.members == {"TenGigabitEthernet1/1/1": "P", "TenGigabitEthernet1/1/2": "P"}
    # members wrapped onto a second line
    assert channels["Port-channel2"].members == {
        "GigabitEthernet1/0/20": "D",
        "GigabitEthernet1/0/21": "s",
        "GigabitEthernet1/0/22": "I",
        "GigabitEthernet1/0/23": "w",
    }


# -- neighbours ------------------------------------------------------------------------


def test_cdp_neighbors_detail():
    neighbors = parse_cdp_neighbors_detail(fixture_text("show_cdp_neighbors_detail.txt"))
    by_name = {n.remote_name: n for n in neighbors}
    assert set(by_name) == {"core-01.lab.local", "SEP001122334455", "AP-FLOOR1", "acc-04"}

    core = by_name["core-01.lab.local"]
    assert core.local_port == "GigabitEthernet1/0/49"
    assert core.remote_port == "GigabitEthernet1/0/3"
    assert core.platform == "cisco C9300-48P"
    assert core.capabilities == ["Router", "Switch", "IGMP"]
    assert core.mgmt_ip == "10.99.0.1"
    assert core.native_vlan == 1
    assert core.software.startswith("Cisco IOS Software [Cupertino]")
    assert core.is_switch

    phone = by_name["SEP001122334455"]
    assert phone.remote_port == "Port 1"
    assert phone.mgmt_ip == "10.20.0.15"  # from "Entry address(es)" when no management address
    assert not phone.is_switch
    assert not by_name["AP-FLOOR1"].is_switch

    old = by_name["acc-04"]
    assert (old.native_vlan, old.duplex, old.mgmt_ip) == (99, "full", "10.99.0.14")
    assert old.is_switch


def test_lldp_neighbors_detail():
    neighbors = parse_lldp_neighbors_detail(fixture_text("show_lldp_neighbors_detail.txt"))
    by_port = {n.local_port: n for n in neighbors}
    assert set(by_port) == {
        "GigabitEthernet1/0/50",
        "GigabitEthernet1/0/12",
        "GigabitEthernet1/0/13",
        "GigabitEthernet1/0/14",
        "GigabitEthernet1/0/49",
    }
    core = by_port["GigabitEthernet1/0/50"]
    assert (core.remote_name, core.remote_port, core.mgmt_ip, core.native_vlan) == (
        "core-02.lab.local",
        "Gi1/0/3",
        "10.99.0.2",
        1,
    )
    assert core.capabilities == ["b", "r"]
    assert core.is_switch

    ap = by_port["GigabitEthernet1/0/12"]
    assert ap.remote_port == "eth0"  # port id was a MAC address
    assert ap.native_vlan is None
    assert not ap.is_switch  # advertises B, but it is an access point

    assert not by_port["GigabitEthernet1/0/13"].is_switch  # phone: B,T

    unmanaged = by_port["GigabitEthernet1/0/14"]
    assert unmanaged.remote_name == "aabb.cc00.0100"  # no system name: use the chassis id
    assert unmanaged.mgmt_ip == ""
    assert unmanaged.is_switch


def test_build_device_prefers_cdp_over_lldp_on_the_same_port():
    device = build_device(
        "acc-03",
        {
            "show cdp neighbors detail": fixture_text("show_cdp_neighbors_detail.txt"),
            "show lldp neighbors detail": fixture_text("show_lldp_neighbors_detail.txt"),
        },
    )
    on_49 = device.neighbors_on("GigabitEthernet1/0/49")
    assert [(n.protocol, n.remote_name) for n in on_49] == [("cdp", "core-01.lab.local")]
    assert [n.protocol for n in device.neighbors_on("GigabitEthernet1/0/50")] == ["lldp"]


# -- platform ----------------------------------------------------------------------------


def test_version_iosxe():
    info = parse_version(fixture_text("show_version_iosxe.txt"))
    assert info.hostname == "core-01"
    assert info.is_iosxe
    assert info.os_version == "17.09.04a"
    assert info.model == "C9300-48P"
    assert info.serial == "FOC2318X0AB"
    assert info.image == "flash:packages.conf"
    assert info.uptime_seconds == 30 * 7 * 86400 + 2 * 86400 + 4 * 3600 + 11 * 60


def test_version_ios15():
    info = parse_version(fixture_text("show_version_ios15.txt"))
    assert info.hostname == "acc-03"
    assert not info.is_iosxe
    assert info.os_version == "15.2(7)E8"
    assert info.model == "WS-C2960X-48FPD-L"
    assert info.serial == "FOC1234X5YZ"


def test_vlan_brief():
    text = """
VLAN Name                             Status    Ports
---- -------------------------------- --------- -------------------------------
1    default                          active    Gi1/0/51, Gi1/0/52
10   USERS                            active    Gi1/0/1, Gi1/0/2
20   VOICE                            active
99   MGMT                             act/lshut
1002 fddi-default                     act/unsup
"""
    assert parse_vlan_brief(text) == {1: "default", 10: "USERS", 20: "VOICE", 99: "MGMT", 1002: "fddi-default"}


def test_logging():
    events = parse_logging(fixture_text("show_logging.txt"))
    assert [e.tag for e in events] == [
        "SPANTREE-2-BLOCK_BPDUGUARD",
        "PM-4-ERR_DISABLE",
        "SW_MATM-4-MACFLAP_NOTIF",
        "SPANTREE-5-ROOTCHANGE",
        "LINK-3-UPDOWN",
    ]
    assert events[2].message.startswith("Host 0050.56a1.2b3c in vlan 10")
    assert events[0].severity == 2


# -- running-config ------------------------------------------------------------------------


def test_split_sections_skips_banners():
    sections = dict(split_sections(fixture_text("running_config.txt")))
    assert "interface GigabitEthernet9/9/9" not in sections
    assert "spanning-tree mode mst" not in sections
    assert sections["interface GigabitEthernet1/0/2"][-1] == "shutdown"


def test_running_config_globals():
    cfg = parse_running_config(fixture_text("running_config.txt"))
    assert cfg.hostname == "acc-02"
    assert cfg.stp_mode == "rapid-pvst"  # not "mst" from the banner text
    assert cfg.portfast_default and cfg.bpduguard_default and cfg.loopguard_default
    assert not cfg.bpdufilter_default
    assert cfg.extend_system_id is True
    assert cfg.pathcost_method == "long"
    assert cfg.uplinkfast and not cfg.backbonefast
    assert cfg.stp_disabled_vlans == {999}
    assert cfg.stp_vlan_priority == {1: 8192, 10: 8192, 20: 8192, 99: 12288}
    assert cfg.errdisable_recovery_causes == {"bpduguard", "psecure-violation"}
    assert cfg.errdisable_recovery_interval == 600
    assert (cfg.mst_name, cfg.mst_revision) == ("CAMPUS", 3)
    assert cfg.mst_instances == {1: "10,20"}


def test_running_config_interfaces():
    interfaces = parse_running_config(fixture_text("running_config.txt")).interfaces
    po = interfaces["Port-channel1"]
    assert (po.mode, po.native_vlan, po.allowed_vlans, po.description) == ("trunk", 99, "10,20,99", "Core bundle")

    user = interfaces["GigabitEthernet1/0/1"]
    assert (user.mode, user.access_vlan, user.voice_vlan) == ("access", 10, 20)
    assert (user.portfast, user.bpduguard) == ("edge", "enable")

    off = interfaces["GigabitEthernet1/0/2"]
    assert (off.portfast, off.bpduguard, off.shutdown) == ("disable", "disable", True)

    trunk = interfaces["GigabitEthernet1/0/3"]
    assert trunk.allowed_vlans == "1-10,20,30-40"
    assert (trunk.portfast, trunk.guard, trunk.nonegotiate) == ("trunk", "root", True)

    assert interfaces["GigabitEthernet1/0/4"].mode == "routed"
    other = interfaces["GigabitEthernet1/0/5"]
    assert (other.mode, other.bpdufilter, other.guard, other.link_type) == (None, "enable", "loop", "point-to-point")
    assert interfaces["TenGigabitEthernet1/1/1"].channel_group == 1


# -- whole devices ---------------------------------------------------------------------------


def test_simulated_switches_parse_cleanly(lab):
    for name in lab.switches:
        outputs = {cmd: out for cmd in AUDIT_COMMANDS if (out := lab.run(name, cmd)) is not None}
        assert set(outputs) == set(AUDIT_COMMANDS), name
        device = build_device(name, outputs, {"site": "lab"})
        assert device.parse_errors == {}, name
        assert device.version.hostname == name
        assert device.config.hostname == name
        assert device.stp and device.interfaces and device.neighbors and device.vlans
        assert device.stp_summary.mode in ("pvst", "rapid-pvst")
        for inst in device.stp.values():
            assert inst.bridge_mac == lab.switches[name].mac
            assert inst.tc_count is not None


def test_build_device_accepts_abbreviated_commands():
    outputs = {
        "sh ver": fixture_text("show_version_ios15.txt"),
        "sh run": fixture_text("running_config.txt"),
        "show int status": fixture_text("show_interfaces_status.txt"),
    }
    device = build_device("acc-03", outputs)
    assert device.version.model == "WS-C2960X-48FPD-L"
    assert device.config.stp_mode == "rapid-pvst"
    assert "GigabitEthernet1/0/1" in device.interfaces


def test_build_device_errdisabled_merge():
    device = build_device(
        "sw",
        {
            "show interfaces status": fixture_text("show_interfaces_status.txt"),
            "show interfaces status err-disabled": fixture_text("show_interfaces_status_errdisabled.txt"),
        },
    )
    assert device.interfaces["GigabitEthernet1/0/15"].errdisable_reason == "bpduguard"
    # ports only listed as err-disabled are added
    assert device.interfaces["FastEthernet0/15"].status == "err-disabled"


def test_load_devices(tmp_path):
    raw = tmp_path / "raw"
    raw.mkdir()
    (raw / "acc-03.json").write_text(
        json.dumps(
            {
                "host": "acc-03",
                "collected_at": "2026-10-04T04:00:00+00:00",
                "intent": {"site": "hq", "stp_role": "access"},
                "outputs": {"show version": fixture_text("show_version_ios15.txt")},
                "errors": {"show lldp neighbors detail": "% LLDP is not enabled"},
            }
        )
    )
    (raw / "dead-sw.json").write_text(json.dumps({"host": "dead-sw", "outputs": {}, "unreachable": True}))
    devices = {d.host: d for d in load_devices(raw)}
    assert devices["acc-03"].reachable
    assert devices["acc-03"].site == "hq"
    assert devices["acc-03"].errors == {"show lldp neighbors detail": "% LLDP is not enabled"}
    assert not devices["dead-sw"].reachable

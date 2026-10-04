"""The lab simulator and its IOS-like CLI (driven without SSH)."""

import pytest
from conftest import cli, configure

from netaudit.parsers.config import parse_running_config
from netaudit.parsers.interfaces import parse_errdisabled
from netaudit.parsers.platform import parse_version
from netaudit.parsers.stp import parse_spanning_tree, parse_spanning_tree_detail

pytest.importorskip("paramiko")

ALL_VLANS = (1, 10, 20, 99)


def tc_count(lab, host, vlan=10):
    stp = parse_spanning_tree_detail(lab.run(host, "show spanning-tree detail"))
    return stp[f"VLAN{vlan:04d}"].tc_count


# -- the simulated network -------------------------------------------------------------


def test_lowest_mac_wins_the_election_by_default(lab):
    for vlan in ALL_VLANS:
        assert lab.compute(vlan).root == "acc-01"


def test_native_vlan_mismatch_blocks_the_link_as_pvid_inconsistent(lab):
    stp = parse_spanning_tree(lab.run("acc-04", "show spanning-tree"))
    port = stp["VLAN0001"].ports["GigabitEthernet0/2"]
    assert (port.state, port.inconsistent) == ("BKN", "PVID")
    # VLAN 10 is not the native VLAN on either side and is forwarded normally
    assert stp["VLAN0010"].ports["GigabitEthernet0/2"].inconsistent is None


def test_show_version_matches_each_platform(lab):
    expected = {
        "core-01": ("C9300-48P", True),
        "acc-01": ("WS-C2960X-48FPD-L", False),
        "acc-04": ("WS-C2960-48TT-L", False),
    }
    for host, (model, iosxe) in expected.items():
        output = lab.run(host, "show version")
        info = parse_version(output)
        assert (info.hostname, info.model, info.is_iosxe) == (host, model, iosxe)
    assert "C2960 Software (C2960-LANBASEK9-M)" in lab.run("acc-04", "show version")


def test_unknown_commands_return_none(lab):
    assert lab.run("acc-01", "show ip bgp summary") is None


def test_lldp_is_disabled_like_on_many_real_switches(lab):
    assert lab.run("acc-01", "show lldp neighbors detail").startswith("% LLDP is not enabled")


# -- the CLI ---------------------------------------------------------------------------------


def test_enable_password(lab):
    session, output = cli(lab, "acc-01", "show running-config", privileged=False)
    assert "% Invalid input" in output
    session.handle_line("enable")
    assert session.awaiting == "enable-password"
    session.handle_line("labenable")
    assert session.mode == "priv"


def test_enable_password_gives_up_after_three_tries(lab):
    session, output = cli(lab, "acc-01", "enable", "x", "y", "z", privileged=False)
    assert session.mode == "user"
    assert "% Bad passwords" in output


def test_show_commands_with_abbreviations_and_pipes(lab):
    _, output = cli(lab, "acc-01", "sh run | inc ^hostname")
    assert output.strip() == "hostname acc-01"
    _, output = cli(lab, "acc-01", "show running-config | section interface GigabitEthernet1/0/49")
    assert output.splitlines()[0] == "interface GigabitEthernet1/0/49"
    assert all(line.startswith(" ") for line in output.strip().splitlines()[1:])
    _, output = cli(lab, "acc-01", "show spanning-tree | begin VLAN0010")
    assert output.startswith("VLAN0010")
    _, output = cli(lab, "acc-01", "show running-config | exclude ^ |^!")
    assert "interface GigabitEthernet1/0/1" in output
    assert " switchport mode access" not in output


def test_configuration_changes_the_running_config_only(lab):
    configure(lab, "acc-01", "interface GigabitEthernet1/0/5\n description Printer\n shutdown")
    cfg = parse_running_config(lab.run("acc-01", "show running-config"))
    assert cfg.interfaces["GigabitEthernet1/0/5"].description == "Printer"
    assert cfg.interfaces["GigabitEthernet1/0/5"].shutdown
    startup = parse_running_config(lab.run("acc-01", "show startup-config"))
    assert not startup.interfaces["GigabitEthernet1/0/5"].shutdown
    assert "%SYS-5-CONFIG_I" in lab.run("acc-01", "show logging")


def test_copy_running_config_to_startup(lab):
    configure(lab, "acc-01", "snmp-server location Lab rack 1")
    session, output = cli(lab, "acc-01", "copy running-config startup-config")
    assert session.awaiting == "copy-destination"
    session.handle_line("")
    assert "snmp-server location Lab rack 1" in lab.run("acc-01", "show startup-config")


def test_global_command_inside_interface_mode_falls_back_to_global(lab):
    session, _ = cli(lab, "acc-01", "configure terminal", "interface GigabitEthernet1/0/5")
    assert session.mode == "config-if"
    session.handle_line("errdisable recovery cause bpduguard")
    assert session.mode == "config"  # IOS leaves the interface, like here
    session.handle_line("end")
    cfg = parse_running_config(lab.run("acc-01", "show running-config"))
    assert cfg.errdisable_recovery_causes == {"bpduguard"}
    assert "errdisable recovery cause bpduguard" not in cfg.interfaces["GigabitEthernet1/0/5"].lines


def test_invalid_input_is_rejected(lab):
    _, output = cli(
        lab,
        "acc-01",
        "configure terminal",
        "frobnicate the network",
        "interface GigabitEthernet9/9/9",
        "spanning-tree vlan 10 priority 1000",
        "spanning-tree mode turbo",
        "end",
    )
    assert output.count("% Invalid input") == 3
    assert "% Bridge Priority must be in increments of 4096." in output
    cfg = parse_running_config(lab.run("acc-01", "show running-config"))
    assert cfg.stp_mode == "pvst"
    assert cfg.stp_vlan_priority == {}


def test_do_runs_exec_commands_in_config_mode(lab):
    _, output = cli(lab, "acc-01", "configure terminal", "do show running-config | include ^hostname", "end")
    assert "hostname acc-01" in output


# -- behaviour that the audit relies on --------------------------------------------------------


def test_priority_change_moves_the_root_and_logs_rootchange(lab, clock):
    clock.advance(60)
    configure(lab, "core-01", "spanning-tree vlan 1,10,20,99 priority 4096")
    for vlan in ALL_VLANS:
        assert lab.compute(vlan).root == "core-01"
    stp = parse_spanning_tree(lab.run("acc-02", "show spanning-tree"))
    assert stp["VLAN0010"].root_mac == lab.switches["core-01"].mac
    assert "%SPANTREE-5-ROOTCHANGE: Root Changed for vlan 10" in lab.run("acc-02", "show logging")


def test_flapping_port_stops_causing_topology_changes_with_portfast(lab, clock):
    before = tc_count(lab, "acc-03")
    clock.advance(900)  # the PC flaps every 90 seconds
    during = tc_count(lab, "acc-03")
    assert during - before == 10
    configure(lab, "acc-03", "interface GigabitEthernet1/0/7\n spanning-tree portfast edge")
    after_fix = tc_count(lab, "acc-03")
    clock.advance(900)
    assert tc_count(lab, "acc-03") == after_fix


def test_tc_source_is_reported_towards_the_flapping_port(lab):
    acc03 = parse_spanning_tree_detail(lab.run("acc-03", "show spanning-tree detail"))["VLAN0010"]
    assert acc03.tc_from == "GigabitEthernet1/0/7"
    root = parse_spanning_tree_detail(lab.run("acc-01", "show spanning-tree detail"))["VLAN0010"]
    assert root.tc_from is not None and root.tc_from != "GigabitEthernet1/0/7"


def test_bpdu_guard_on_the_rogue_switch_port_err_disables_it(lab):
    assert parse_errdisabled(lab.run("acc-02", "show interfaces status err-disabled")) == {}
    configure(lab, "acc-02", "interface GigabitEthernet1/0/11\n spanning-tree bpduguard enable")
    assert parse_errdisabled(lab.run("acc-02", "show interfaces status err-disabled")) == {
        "GigabitEthernet1/0/11": "bpduguard"
    }
    assert "%SPANTREE-2-BLOCK_BPDUGUARD" in lab.run("acc-02", "show logging")


def test_mode_change_restarts_the_counters(lab, clock):
    assert tc_count(lab, "acc-01") > 0
    clock.advance(60)
    configure(lab, "acc-01", "spanning-tree mode rapid-pvst")
    summary = lab.run("acc-01", "show spanning-tree summary")
    assert "Switch is in rapid-pvst mode" in summary
    assert tc_count(lab, "acc-01") < 5


def test_shutdown_no_shutdown_recovers_an_err_disabled_port(lab):
    configure(lab, "acc-02", "interface GigabitEthernet1/0/11\n spanning-tree bpduguard enable")
    # still guarded, and the switch behind it still sends BPDUs: err-disabled again
    configure(lab, "acc-02", "interface GigabitEthernet1/0/11\n shutdown\n no shutdown")
    assert "GigabitEthernet1/0/11" in lab.switches["acc-02"].errdisabled
    configure(lab, "acc-02", "interface GigabitEthernet1/0/11\n no spanning-tree bpduguard\n shutdown\n no shutdown")
    assert lab.switches["acc-02"].errdisabled == {}
    stp = parse_spanning_tree(lab.run("acc-02", "show spanning-tree"))
    assert stp["VLAN0010"].ports["GigabitEthernet1/0/11"].state == "FWD"

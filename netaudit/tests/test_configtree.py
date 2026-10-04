from netaudit.lab.configtree import ConfigTree
from netaudit.parsers.config import parse_running_config

BASE = """\
hostname sw1
spanning-tree mode pvst
spanning-tree extend system-id
!
interface GigabitEthernet1/0/2
 switchport mode access
!
interface GigabitEthernet1/0/10
 switchport mode access
!
interface GigabitEthernet1/0/1
 description uplink
 switchport mode trunk
!
line vty 0 4
 login local
!
end
"""


def test_text_round_trip_orders_interfaces_naturally():
    text = ConfigTree(BASE).text()
    positions = [text.index(f"interface GigabitEthernet1/0/{n}\n") for n in (1, 2, 10)]
    assert positions == sorted(positions)
    assert text.index("line vty 0 4") > positions[-1]
    assert text.endswith("end\n")
    assert ConfigTree(text).text() == text


def test_set_global_replaces_single_value_commands():
    tree = ConfigTree(BASE)
    tree.set_global("spanning-tree mode rapid-pvst")
    tree.set_global("hostname sw1-new")
    cfg = parse_running_config(tree.text())
    assert cfg.stp_mode == "rapid-pvst"
    assert cfg.hostname == "sw1-new"
    assert tree.text().count("spanning-tree mode") == 1


def test_set_global_adds_multi_value_commands_once():
    tree = ConfigTree(BASE)
    tree.set_global("errdisable recovery cause bpduguard")
    tree.set_global("errdisable recovery cause psecure-violation")
    tree.set_global("errdisable recovery cause bpduguard")
    assert tree.text().count("errdisable recovery cause bpduguard") == 1
    assert parse_running_config(tree.text()).errdisable_recovery_causes == {"bpduguard", "psecure-violation"}
    tree.remove_global("errdisable recovery cause bpduguard")
    assert parse_running_config(tree.text()).errdisable_recovery_causes == {"psecure-violation"}


def test_stp_priorities_are_grouped_like_ios():
    tree = ConfigTree(BASE)
    tree.set_global("spanning-tree vlan 1-10 priority 4096")
    tree.set_global("spanning-tree vlan 5 priority 8192")
    assert tree.stp_priorities() == {**{v: 4096 for v in range(1, 11) if v != 5}, 5: 8192}
    lines = [line for line in tree.text().splitlines() if " priority " in line]
    assert lines == ["spanning-tree vlan 1-4,6-10 priority 4096", "spanning-tree vlan 5 priority 8192"]
    tree.remove_global("spanning-tree vlan 6-10 priority")
    assert [line for line in tree.text().splitlines() if " priority " in line] == [
        "spanning-tree vlan 1-4 priority 4096",
        "spanning-tree vlan 5 priority 8192",
    ]
    # STP lines stay together, after the existing spanning-tree commands
    text = tree.text()
    assert text.index("spanning-tree vlan 1-4") > text.index("spanning-tree mode")


def test_interface_children_replace_and_remove():
    tree = ConfigTree(BASE)
    parent = "interface GigabitEthernet1/0/2"
    tree.set_child(parent, "switchport access vlan 10")
    tree.set_child(parent, "switchport access vlan 20")
    tree.set_child(parent, "spanning-tree portfast", edge_portfast=True)
    tree.set_child(parent, "spanning-tree bpduguard enable")
    assert tree.interface("Gi1/0/2") == [
        "switchport mode access",
        "switchport access vlan 20",
        "spanning-tree portfast edge",
        "spanning-tree bpduguard enable",
    ]
    tree.remove_child(parent, "spanning-tree portfast")
    tree.remove_child(parent, "spanning-tree bpduguard")
    assert tree.interface("Gi1/0/2") == ["switchport mode access", "switchport access vlan 20"]


def test_portfast_trunk_does_not_replace_portfast():
    tree = ConfigTree(BASE)
    parent = "interface GigabitEthernet1/0/1"
    tree.set_child(parent, "spanning-tree portfast trunk")
    tree.set_child(parent, "spanning-tree portfast")
    assert "spanning-tree portfast trunk" in tree.interface("Gi1/0/1")
    assert "spanning-tree portfast" in tree.interface("Gi1/0/1")


def test_version_changes_on_every_edit():
    tree = ConfigTree(BASE)
    before = tree.version
    tree.set_global("logging buffered 64000")
    tree.set_child("interface GigabitEthernet1/0/1", "shutdown")
    tree.remove_child("interface GigabitEthernet1/0/1", "shutdown")
    assert tree.version == before + 3
    assert tree.section("interface GigabitEthernet9/0/1") is None
    assert tree.section("interface Vlan99", create=True) == []

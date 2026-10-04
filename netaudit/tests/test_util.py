import pytest

from netaudit.util import (
    canonical_interface,
    compress_vlans,
    expand_vlans,
    format_duration,
    instance_name,
    interface_sort_key,
    is_physical_ethernet,
    normalize_mac,
    parse_ios_duration,
    parse_uptime,
    short_hostname,
    short_interface,
    slugify,
    vlan_from_instance,
)


@pytest.mark.parametrize(
    ("name", "long", "short"),
    [
        ("Gi1/0/1", "GigabitEthernet1/0/1", "Gi1/0/1"),
        ("gi1/0/1", "GigabitEthernet1/0/1", "Gi1/0/1"),
        ("GigabitEthernet1/0/1", "GigabitEthernet1/0/1", "Gi1/0/1"),
        ("Gig1/0/1", "GigabitEthernet1/0/1", "Gi1/0/1"),
        ("Fa0/15", "FastEthernet0/15", "Fa0/15"),
        ("Te1/1/1", "TenGigabitEthernet1/1/1", "Te1/1/1"),
        ("TenGig1/1/1", "TenGigabitEthernet1/1/1", "Te1/1/1"),
        ("Tw1/0/1", "TwoGigabitEthernet1/0/1", "Tw1/0/1"),
        ("Twe1/1/1", "TwentyFiveGigE1/1/1", "Twe1/1/1"),
        ("Po1", "Port-channel1", "Po1"),
        ("Port-channel12", "Port-channel12", "Po12"),
        ("Vl99", "Vlan99", "Vl99"),
        ("  Gi1/0/2 ", "GigabitEthernet1/0/2", "Gi1/0/2"),
    ],
)
def test_interface_names(name, long, short):
    assert canonical_interface(name) == long
    assert short_interface(name) == short


def test_interface_names_unknown_and_empty():
    assert canonical_interface("Null0") == "Null0"
    assert canonical_interface("mgmt") == "mgmt"
    assert canonical_interface(None) == ""
    assert short_interface("") == ""


def test_physical_ethernet():
    assert is_physical_ethernet("Gi1/0/1")
    assert is_physical_ethernet("Fa0/1")
    assert not is_physical_ethernet("Po1")
    assert not is_physical_ethernet("Vlan99")


def test_natural_interface_sort():
    ports = ["Gi1/0/10", "Gi1/0/2", "Gi1/0/1", "Gi2/0/1", "Gi1/1/1"]
    assert sorted(ports, key=interface_sort_key) == ["Gi1/0/1", "Gi1/0/2", "Gi1/0/10", "Gi1/1/1", "Gi2/0/1"]


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("00a3.d1f4.1180", "00a3.d1f4.1180"),
        ("00:A3:D1:F4:11:80", "00a3.d1f4.1180"),
        ("00-a3-d1-f4-11-80", "00a3.d1f4.1180"),
        ("00a3d1f41180", "00a3.d1f4.1180"),
        ("", ""),
        (None, ""),
        ("not-a-mac", "not-a-mac"),
    ],
)
def test_normalize_mac(raw, expected):
    assert normalize_mac(raw) == expected


def test_expand_and_compress_vlans():
    assert expand_vlans("1-3,10,20-21") == {1, 2, 3, 10, 20, 21}
    assert expand_vlans("1-3, 5") == {1, 2, 3, 5}
    assert expand_vlans("none") == set()
    assert expand_vlans("") == set()
    assert expand_vlans(None) == set()
    assert len(expand_vlans("all")) == 4094
    assert expand_vlans([10, "20"]) == {10, 20}
    assert compress_vlans([1, 2, 3, 5, 10, 11]) == "1-3,5,10-11"
    assert compress_vlans([]) == ""
    for spec in ("1", "1-4094", "1,3,5-9,100-200,4094"):
        assert compress_vlans(expand_vlans(spec)) == spec


def test_vlan_instance_names():
    assert vlan_from_instance("VLAN0010") == 10
    assert vlan_from_instance("VLAN4094") == 4094
    assert vlan_from_instance("MST1") is None
    assert instance_name(10) == "VLAN0010"


@pytest.mark.parametrize(
    ("text", "seconds"),
    [
        ("00:01:23", 83),
        ("12:00:00", 43200),
        ("1d02h", 93600),
        ("3w4d", 3 * 7 * 86400 + 4 * 86400),
        ("1y12w", 365 * 86400 + 12 * 7 * 86400),
        ("never", None),
        ("", None),
        (None, None),
        ("garbage", None),
    ],
)
def test_parse_ios_duration(text, seconds):
    assert parse_ios_duration(text) == seconds


def test_format_duration():
    assert format_duration(None) == "n/a"
    assert format_duration(42) == "42s"
    assert format_duration(300) == "5m"
    assert format_duration(3 * 3600 + 12 * 60) == "3h12m"
    assert format_duration(4 * 86400 + 6 * 3600) == "4d6h"
    assert format_duration(17 * 86400) == "2w3d"


def test_parse_uptime():
    text = "core-01 uptime is 2 years, 3 weeks, 1 day, 4 hours, 12 minutes"
    assert parse_uptime(text) == 2 * 365 * 86400 + 3 * 7 * 86400 + 86400 + 4 * 3600 + 12 * 60
    assert parse_uptime("1 minute") == 60
    assert parse_uptime("") is None
    assert parse_uptime("soon") is None


def test_short_hostname():
    assert short_hostname("SW1.corp.example.com") == "sw1"
    assert short_hostname("N9K-1(FOC1234ABCD)") == "n9k-1"
    assert short_hostname(None) == ""


def test_slugify():
    assert slugify("show spanning-tree detail") == "show_spanning-tree_detail"
    assert slugify("show logging | include SPANTREE") == "show_logging_include_SPANTREE"
    assert slugify("///") == "output"
    assert len(slugify("x" * 500)) == 120

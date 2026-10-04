from netaudit.parsers.config import parse_running_config
from netaudit.sanitize import remove_secrets

SECRETS = [
    "Pr1vateComm",
    "TrapComm42",
    "$9$labuserhash",
    "0822455D0A16",
    "$8$enablehash",
    "plainEnable",
    "vtyPass",
    "TacKey99",
    "radKeyPlain",
    "newRadKey",
    "ntpKey123",
    "vtpSecret",
    "ftpPass",
    "urlPass",
    "isakmpKey",
    "ospfKey",
    "bgpPass",
    "keyStr1ng",
    "hsrpPw",
    "dot1xPw",
]

CONFIG = """\
hostname acc-01
enable secret 8 $8$enablehash
enable password plainEnable
username admin privilege 15 secret 9 $9$labuserhash
username backup password 7 0822455D0A16
snmp-server community Pr1vateComm RO 10
snmp-server host 10.0.0.5 version 2c TrapComm42 config snmp
snmp-server host 10.0.0.6 version 3 priv LIBRENMS
snmp-server location Rack 1
tacacs-server host 10.0.0.9 key TacKey99
radius-server key radKeyPlain
radius server ISE-1
 address ipv4 10.0.0.10 auth-port 1812 acct-port 1813
 key newRadKey
ntp authentication-key 1 md5 ntpKey123 7
vtp password vtpSecret
ip ftp password ftpPass
archive
 path ftp://backup:urlPass@10.0.0.20/$h
crypto isakmp key isakmpKey address 0.0.0.0
spanning-tree mode rapid-pvst
spanning-tree vlan 1-4094 priority 4096
key chain KC
 key 1
  key-string keyStr1ng
interface Vlan10
 ip ospf message-digest-key 1 md5 ospfKey
 standby 1 authentication hsrpPw
interface GigabitEthernet1/0/1
 description Uplink to core
 switchport mode trunk
 dot1x username sup password 0 dot1xPw
router bgp 65000
 neighbor 10.0.0.1 password bgpPass
line vty 0 4
 password 7 vtyPass
 login local
"""


def test_every_secret_is_removed():
    cleaned = remove_secrets(CONFIG)
    for secret in SECRETS:
        assert secret not in cleaned, secret


def test_everything_else_is_untouched():
    cleaned = remove_secrets(CONFIG)
    for line in (
        "hostname acc-01",
        "snmp-server host 10.0.0.6 version 3 priv LIBRENMS",
        "snmp-server location Rack 1",
        "spanning-tree vlan 1-4094 priority 4096",
        " description Uplink to core",
        " login local",
        " address ipv4 10.0.0.10 auth-port 1812 acct-port 1813",
    ):
        assert line in cleaned.splitlines(), line
    assert "snmp-server host 10.0.0.5 version 2c <secret hidden> config snmp" in cleaned
    assert "username admin privilege 15 secret 9 <secret hidden>" in cleaned
    assert " path ftp://backup:<secret hidden>@10.0.0.20/$h" in cleaned
    assert len(cleaned.splitlines()) == len(CONFIG.splitlines())


def test_analysis_still_sees_the_spanning_tree_settings():
    cfg = parse_running_config(remove_secrets(CONFIG))
    assert cfg.stp_mode == "rapid-pvst"
    assert cfg.stp_vlan_priority[10] == 4096
    assert cfg.interfaces["GigabitEthernet1/0/1"].mode == "trunk"


def test_idempotent_and_empty_input():
    once = remove_secrets(CONFIG)
    assert remove_secrets(once) == once
    assert remove_secrets("") == ""
    assert remove_secrets(None) == ""

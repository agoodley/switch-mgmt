import yaml

from netaudit.credentials import Login
from netaudit.discover import crawl, write_inventory

LOGIN = Login("netops", "secret")


class LabSession:
    def __init__(self, lab, name):
        self.lab, self.name = lab, name

    def send_command(self, command):
        return self.lab.run(self.name, command)

    def disconnect(self):
        pass


class AuthenticationException(Exception):
    """Named like paramiko's / Netmiko's authentication errors."""


def lab_connect(lab, down=(), logins=None):
    """Fake Netmiko: each switch accepts the login given in ``logins`` (default: netops/secret)."""
    by_ip = {sw.mgmt_ip: name for name, sw in lab.switches.items()}
    logins = logins or {}

    def connect(host, username, password, secret, port=22):
        if host in down or host not in by_ip:
            raise TimeoutError(f"TCP connection to device failed.\nCommon causes: {host}")
        name = by_ip[host]
        expected = logins.get(name, ("netops", "secret", "secret"))
        if (username, password, secret) != expected:
            raise AuthenticationException(f"Authentication to device failed ({username})")
        return LabSession(lab, name)

    return connect


def test_crawl_finds_every_switch_from_one_seed(lab):
    result = crawl(["10.99.0.11"], LOGIN, connect=lab_connect(lab), workers=3)
    assert sorted(result.switches) == sorted(lab.switches)
    assert result.failures == {}
    assert result.switches["acc-01"].via == "seed"
    assert result.switches["core-01"].via == "acc-01 Gi1/0/49"
    assert result.switches["acc-04"].model == "WS-C2960-48TT-L"
    assert result.switches["core-01"].version == "17.09.04a"
    # IP phones on acc-01 are not followed
    assert all("SEP" not in name for name, _ in result.skipped)


def test_crawl_reports_switches_it_cannot_log_into(lab):
    result = crawl(["10.99.0.1"], LOGIN, connect=lab_connect(lab, down={"10.99.0.14"}))
    assert "acc-04" not in result.switches
    assert len(result.switches) == 5
    assert result.failures["10.99.0.14"].startswith("TimeoutError: TCP connection to device failed.")
    assert "(via acc-0" in result.failures["10.99.0.14"]


def test_crawl_respects_max_hosts(lab):
    result = crawl(["10.99.0.1"], LOGIN, connect=lab_connect(lab), max_hosts=2, workers=1)
    assert len(result.switches) == 2
    assert any("max_hosts (2) reached" in reason for _, reason in result.skipped)


def test_crawl_platform_exclusion(lab):
    result = crawl(["10.99.0.1"], LOGIN, connect=lab_connect(lab), exclude_platforms=["2960-48TT"])
    assert "acc-04" not in result.switches
    assert ("acc-04.lab.local (cisco WS-C2960-48TT-L)", "platform excluded") in result.skipped


def test_write_inventory(lab):
    result = crawl(["10.99.0.11"], LOGIN, connect=lab_connect(lab, down={"10.99.0.14"}))
    text = write_inventory(result, site="HQ-1")
    data = yaml.safe_load(text)
    group = data["switches"]["children"]["HQ_1"]
    assert group["vars"] == {"site": "HQ-1"}
    assert group["hosts"]["core-01"] == {"ansible_host": "10.99.0.1"}
    assert set(group["hosts"]) == {"core-01", "core-02", "acc-01", "acc-02", "acc-03"}
    # the two best-connected switches are suggested as roots, commented out
    lines = text.splitlines()
    core01 = lines.index("        core-01:")
    assert "# stp_role: root_primary" in lines[core01 + 2]
    assert "# stp_role: root_secondary" in text
    assert "#   10.99.0.14: TimeoutError" in text


ACC04 = ("oldadmin", "0ld#p@ss", "3n%ble")


def test_switches_with_their_own_login(lab):
    connect = lab_connect(lab, logins={"acc-04": ACC04})
    # without an entry the old switch refuses the default login
    result = crawl(["10.99.0.1"], LOGIN, connect=connect)
    assert "acc-04" not in result.switches
    assert result.failures["10.99.0.14"].startswith("AuthenticationException")
    # an entry under the CDP name (acc-04.lab.local -> acc-04) or the address both work
    for key in ("acc-04", "10.99.0.14"):
        credentials = {key: {"username": "oldadmin", "password": "0ld#p@ss", "enable": "3n%ble"}}
        result = crawl(["10.99.0.1"], LOGIN, credentials=credentials, connect=connect)
        assert sorted(result.switches) == sorted(lab.switches), key


def test_site_login_and_switch_override(lab):
    site_login = ("site-user", "site-pass", "site-pass")
    logins = {name: site_login for name in lab.switches} | {"acc-04": ("site-user", "own-pass", "own-pass")}
    credentials = {
        "lab": {"username": "site-user", "password": "site-pass"},
        "acc-04": {"password": "own-pass"},
    }
    result = crawl(["10.99.0.11"], LOGIN, credentials=credentials, site="lab", connect=lab_connect(lab, logins=logins))
    assert sorted(result.switches) == sorted(lab.switches)

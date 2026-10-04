"""netaudit known-hosts against the lab's SSH server (over socket pairs, no ports)."""

import socket
import stat
import threading

import pytest

paramiko = pytest.importorskip("paramiko")

from netaudit import hostkeys  # noqa: E402
from netaudit.cli import main  # noqa: E402
from netaudit.lab.server import _handle  # noqa: E402


@pytest.fixture
def serve(lab, monkeypatch):
    """Route connections to <switch name>:<port> to the simulated switch, with a given host key."""
    keys = {"key": paramiko.RSAKey.generate(1024)}

    def create_connection(address, timeout=None):
        host, _port = address
        if host not in lab.switches:
            raise ConnectionRefusedError(111, "Connection refused")
        server_side, client_side = socket.socketpair()
        threading.Thread(target=_handle, args=(lab, lab.switches[host], server_side, keys["key"]), daemon=True).start()
        return client_side

    monkeypatch.setattr(hostkeys.socket, "create_connection", create_connection)
    return keys


def test_targets_and_labels():
    assert hostkeys.parse_target("10.0.0.1") == ("10.0.0.1", 22)
    assert hostkeys.parse_target("lab:2201") == ("lab", 2201)
    assert hostkeys.parse_target("[2001:db8::1]:2222") == ("2001:db8::1", 2222)
    assert hostkeys.parse_target("2001:db8::1") == ("2001:db8::1", 22)
    assert hostkeys.host_label("10.0.0.1", 22) == "10.0.0.1"
    assert hostkeys.host_label("lab", 2201) == "[lab]:2201"


def test_trust_on_first_use_then_detect_a_changed_key(serve, tmp_path):
    known_hosts = tmp_path / "ssh" / "known_hosts"
    targets = [("core-01", 2201), ("acc-04", 22)]  # acc-04 only speaks legacy algorithms

    first = hostkeys.update_known_hosts(known_hosts, targets)
    assert [(r.target, r.status, r.key_type) for r in first] == [
        ("[core-01]:2201", "added", "ssh-rsa"),
        ("acc-04", "added", "ssh-rsa"),
    ]
    assert stat.S_IMODE(known_hosts.stat().st_mode) == 0o600
    assert first[0].fingerprint == hostkeys.fingerprint(serve["key"])

    assert [r.status for r in hostkeys.update_known_hosts(known_hosts, targets)] == ["known", "known"]

    before = known_hosts.read_text()
    serve["key"] = paramiko.RSAKey.generate(1024)  # switch replaced, or someone in the middle
    changed = hostkeys.update_known_hosts(known_hosts, targets)
    assert [r.status for r in changed] == ["changed", "changed"]
    assert "forget-host" in changed[0].detail
    assert known_hosts.read_text() == before  # never overwritten


def test_unreachable_switch_is_reported_not_recorded(serve, tmp_path):
    known_hosts = tmp_path / "known_hosts"
    (result,) = hostkeys.update_known_hosts(known_hosts, [("no-such-switch", 22)])
    assert result.status == "error"
    assert "ConnectionRefusedError" in result.detail
    assert not known_hosts.exists()


def test_keys_are_readable_by_paramiko_clients(serve, tmp_path):
    known_hosts = tmp_path / "known_hosts"
    hostkeys.update_known_hosts(known_hosts, [("core-01", 2201)])
    loaded = paramiko.HostKeys(str(known_hosts))
    assert loaded.lookup("[core-01]:2201")["ssh-rsa"].asbytes() == serve["key"].asbytes()


def test_cli_exit_code_flags_changed_keys(serve, tmp_path, capsys):
    known_hosts = str(tmp_path / "known_hosts")
    assert main(["known-hosts", "--file", known_hosts, "core-01:2201", "nowhere:22"]) == 0
    out = capsys.readouterr().out
    assert "added    [core-01]:2201" in out
    assert "error    [nowhere]" not in out and "error    nowhere" in out
    serve["key"] = paramiko.RSAKey.generate(1024)
    assert main(["known-hosts", "--file", known_hosts, "core-01:2201"]) == 3
    assert "changed  [core-01]:2201" in capsys.readouterr().out

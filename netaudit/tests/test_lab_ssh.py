"""The lab's SSH front-end, over a socket pair (no TCP ports needed)."""

import socket
import threading
import time

import pytest

paramiko = pytest.importorskip("paramiko")

from netaudit.lab.server import _handle, _host_key  # noqa: E402


@pytest.fixture(scope="module")
def host_key(tmp_path_factory):
    return _host_key(str(tmp_path_factory.mktemp("keys") / "lab_host_key"))


def connect(lab, name, host_key, login=None):
    server_side, client_side = socket.socketpair()
    threading.Thread(target=_handle, args=(lab, lab.switches[name], server_side, host_key), daemon=True).start()
    transport = paramiko.Transport(client_side)
    login = login or lab.switches[name].login
    transport.connect(username=login["username"], password=login["password"])
    return transport


def read_until(channel, marker, timeout=10.0):
    data = ""
    deadline = time.time() + timeout
    while marker not in data and time.time() < deadline:
        if channel.recv_ready():
            data += channel.recv(65535).decode()
        else:
            time.sleep(0.02)
    assert marker in data, data
    return data


def test_exec_command(lab, host_key):
    transport = connect(lab, "core-01", host_key)
    try:
        assert transport.remote_version == "SSH-2.0-Cisco-1.25"
        channel = transport.open_session()
        channel.exec_command("show version")
        output = read_until(channel, "Configuration register")
        assert "core-01 uptime is" in output
    finally:
        transport.close()


def test_interactive_shell_with_enable(lab, host_key):
    transport = connect(lab, "core-01", host_key)
    try:
        channel = transport.open_session()
        channel.get_pty()
        channel.invoke_shell()
        read_until(channel, "core-01>")
        channel.send("enable\n")
        read_until(channel, "Password: ")
        channel.send("labenable\n")
        read_until(channel, "core-01#")
        channel.send("show privilege\n")
        assert "Current privilege level is 15" in read_until(channel, "core-01#")
    finally:
        transport.close()


def test_legacy_switch_only_offers_old_algorithms(lab, host_key):
    transport = connect(lab, "acc-04", host_key)
    try:
        assert transport.host_key_type == "ssh-rsa"
        assert transport.local_cipher.endswith("-cbc")
        channel = transport.open_session()
        channel.exec_command("show version")
        assert "acc-04 uptime is" in read_until(channel, "Configuration register")
    finally:
        transport.close()


def test_a_switch_with_its_own_login_refuses_the_shared_one(lab, host_key):
    assert lab.switches["acc-04"].login["username"] == "oldadmin"
    with pytest.raises(paramiko.AuthenticationException):
        connect(lab, "acc-04", host_key, login=lab.ssh)
    transport = connect(lab, "acc-04", host_key)
    try:
        channel = transport.open_session()
        channel.get_pty()
        channel.invoke_shell()
        read_until(channel, "acc-04>")
        channel.send("enable\n")
        read_until(channel, "Password: ")
        channel.send(lab.switches["acc-04"].login["enable"] + "\n")
        read_until(channel, "acc-04#")
    finally:
        transport.close()


def test_host_key_is_kept_across_restarts(tmp_path):
    path = str(tmp_path / "key")
    first = _host_key(path)
    assert _host_key(path).get_fingerprint() == first.get_fingerprint()

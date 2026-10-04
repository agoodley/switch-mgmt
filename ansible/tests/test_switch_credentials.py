"""The switch_credentials vars plugin, run through real ansible commands."""

import json
import os
import re
import shutil
import subprocess
import textwrap
from pathlib import Path

import pytest

ANSIBLE_DIR = Path(__file__).resolve().parents[1]

pytestmark = pytest.mark.skipif(shutil.which("ansible") is None, reason="ansible is not installed")

SITE = """\
switches:
  children:
    hq:
      vars:
        site: hq
      hosts:
        sw1: {ansible_host: 10.0.0.1}
        sw2: {ansible_host: 10.0.0.2}
        sw3: {ansible_host: 10.0.0.3}
    branch:
      hosts:
        br1: {ansible_host: 10.1.0.1}
"""

DEFAULTS = """\
ansible_user: default-user
ansible_password: default-pass
switch_enable_secret: ""
ansible_become_password: "{{ switch_enable_secret | default(ansible_password, true) }}"
"""

CREDENTIALS = """\
hq:
  username: 'site-user'
  password: 'site-pass'
10.0.0.2:
  password: 'ip-pass'
sw2:
  enable: 'sw2-enable'
10.0.0.3:
  password: 'ip3-pass'
sw3:
  password: 'name-beats-ip {{ not_a_template }}'
"""


def make_inventory(tmp_path: Path, credentials: str | None, mode: int = 0o600) -> Path:
    inventory = tmp_path / "inventory"
    (inventory / "sites").mkdir(parents=True)
    (inventory / "group_vars").mkdir()
    (inventory / "sites" / "hq.yml").write_text(SITE)
    (inventory / "group_vars" / "switches.yml").write_text(DEFAULTS)
    if credentials is not None:
        path = inventory / "credentials.yml"
        path.write_text(credentials)
        path.chmod(mode)
    return inventory


def run_ansible(inventory: Path) -> subprocess.CompletedProcess:
    env = {
        **os.environ,
        "ANSIBLE_CONFIG": str(ANSIBLE_DIR / "ansible.cfg"),
        "ANSIBLE_CALLBACK_RESULT_FORMAT": "json",
        "ANSIBLE_NOCOLOR": "1",
        "ANSIBLE_FORCE_COLOR": "0",  # the toolbox image forces colour on
    }
    return subprocess.run(
        [
            "ansible",
            "-i",
            str(inventory),
            "switches",
            "-m",
            "ansible.builtin.debug",
            "-a",
            "msg={{ ansible_user }}|{{ ansible_password }}|{{ ansible_become_password }}",
        ],
        cwd=ANSIBLE_DIR,
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
    )


def logins(inventory: Path) -> dict[str, list[str]]:
    result = run_ansible(inventory)
    assert result.returncode == 0, result.stdout + result.stderr
    # "sw1 | SUCCESS => {...json...}" per host
    stdout = re.sub(r"\x1b\[[0-9;]*m", "", result.stdout)
    blocks = re.findall(r"^(\S+) \| SUCCESS => (\{.*?^\})", stdout, re.M | re.S)
    return {host: json.loads(body)["msg"].split("|") for host, body in blocks}


def test_switch_beats_address_beats_site_beats_default(tmp_path):
    found = logins(make_inventory(tmp_path, CREDENTIALS))
    assert found["sw1"] == ["site-user", "site-pass", "site-pass"]
    assert found["sw2"] == ["site-user", "ip-pass", "sw2-enable"]
    # a value is never treated as a template, whatever characters it contains
    assert found["sw3"] == ["site-user", "name-beats-ip {{ not_a_template }}", "name-beats-ip {{ not_a_template }}"]
    assert found["br1"] == ["default-user", "default-pass", "default-pass"]


def test_without_a_credentials_file_the_defaults_apply(tmp_path):
    found = logins(make_inventory(tmp_path, None))
    assert set(map(tuple, found.values())) == {("default-user", "default-pass", "default-pass")}


@pytest.mark.parametrize(
    ("content", "message"),
    [
        ("sw1:\n  password: 0123\n", "put the password of 'sw1' in quotes"),
        ("sw1:\n  password: yes\n", "put the password of 'sw1' in quotes"),
        ("sw1:\n  pasword: 'x'\n", "unknown setting pasword for 'sw1'"),
        ("sw1: 'just-a-password'\n", "'sw1' must contain username, password and/or enable"),
    ],
)
def test_mistakes_are_explained(tmp_path, content, message):
    result = run_ansible(make_inventory(tmp_path, content))
    assert result.returncode != 0
    assert message in " ".join((result.stdout + result.stderr).split())


def test_world_readable_file_is_reported(tmp_path):
    result = run_ansible(make_inventory(tmp_path, CREDENTIALS, mode=0o644))
    assert result.returncode == 0
    assert "can be read by other users" in result.stderr


def test_lab_inventory_gives_acc_04_its_own_login():
    found = logins(ANSIBLE_DIR / "inventory-lab")
    assert found["acc-01"] == ["labadmin", "labpass", "labenable"]
    assert found["acc-04"] == ["oldadmin", "0ld#p@ss:1'x", "3n%ble {{x}}"]


def test_sample_file_is_valid(tmp_path):
    sample = (ANSIBLE_DIR / "inventory" / "credentials.yml.sample").read_text()
    found = logins(make_inventory(tmp_path, textwrap.dedent(sample)))
    assert found["sw1"] == ["default-user", "default-pass", "default-pass"]


def test_file_written_by_credentials_import_reads_the_same(tmp_path):
    netaudit_credentials = pytest.importorskip("netaudit.credentials")
    entries = {
        "sw1": {"password": "0123"},
        "sw2": {"password": "it's {{ x }}"},
        "sw3": {"username": "yes", "password": "p@ss:#1", "enable": " spaced "},
    }
    found = logins(make_inventory(tmp_path, netaudit_credentials.dump(entries)))
    assert found["sw1"] == ["default-user", "0123", "0123"]
    assert found["sw2"] == ["default-user", "it's {{ x }}", "it's {{ x }}"]
    assert found["sw3"] == ["yes", "p@ss:#1", " spaced "]

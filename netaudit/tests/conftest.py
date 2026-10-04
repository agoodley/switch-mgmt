"""Shared fixtures: the lab network from lab/topology.yml driven by a fake clock."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
import yaml

from netaudit.lab.sim import Lab
from netaudit.parsers import AUDIT_COMMANDS, build_device

REPO = Path(__file__).resolve().parents[2]
TOPOLOGY = REPO / "lab" / "topology.yml"
FIXTURES = Path(__file__).parent / "fixtures"
ROLES = {"core-01": "root_primary", "core-02": "root_secondary"}


class Clock:
    """Deterministic time source for the simulator."""

    def __init__(self, start: float = 1_790_000_000.0):
        self.now = start

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


@pytest.fixture
def clock() -> Clock:
    return Clock()


@pytest.fixture
def lab(clock: Clock) -> Lab:
    return Lab(yaml.safe_load(TOPOLOGY.read_text(encoding="utf-8")), clock=clock)


def fixture_text(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


def collect_payloads(lab: Lab, roles: dict[str, str] | None = None, intent: dict | None = None) -> list[dict]:
    """What the audit playbook would collect from every lab switch right now."""
    roles = ROLES if roles is None else roles
    stamp = datetime.fromtimestamp(lab.now(), tz=UTC).isoformat(timespec="seconds")
    payloads = []
    for name, sw in lab.switches.items():
        outputs, errors = {}, {}
        for command in AUDIT_COMMANDS:
            output = lab.run(name, command)
            if output is None:
                errors[command] = "% Invalid input detected at '^' marker."
            else:
                outputs[command] = output
        payloads.append(
            {
                "host": name,
                "collected_at": stamp,
                "intent": {"site": lab.site, "stp_role": roles.get(name, "access"), "ansible_host": sw.mgmt_ip}
                | (intent or {}),
                "outputs": outputs,
                "errors": errors,
            }
        )
    return payloads


def collect(lab: Lab, roles: dict[str, str] | None = None, intent: dict | None = None):
    """Parsed devices, as `netaudit analyze` would load them."""
    devices = []
    for payload in collect_payloads(lab, roles, intent):
        device = build_device(payload["host"], payload["outputs"], payload["intent"])
        device.collected_at = payload["collected_at"]
        device.errors = payload["errors"]
        devices.append(device)
    return devices


def write_run(lab: Lab, run_dir: Path, roles: dict[str, str] | None = None) -> Path:
    """Write a run directory (raw/<host>.json) like the audit playbook does."""
    raw = run_dir / "raw"
    raw.mkdir(parents=True, exist_ok=True)
    for payload in collect_payloads(lab, roles):
        (raw / f"{payload['host']}.json").write_text(json.dumps(payload), encoding="utf-8")
    return run_dir


class FakeChannel:
    """Stands in for a paramiko channel when driving the lab CLI directly."""

    def __init__(self):
        self.output: list[str] = []
        self.closed = False

    def sendall(self, data: bytes) -> None:
        self.output.append(data.decode())

    def close(self) -> None:
        self.closed = True

    def text(self) -> str:
        return "".join(self.output).replace("\r\n", "\n")


def cli(lab: Lab, host: str, *lines: str, privileged: bool = True):
    """Type lines into a lab switch's CLI; returns (session, output)."""
    from netaudit.lab.server import CliSession

    channel = FakeChannel()
    session = CliSession(lab, lab.switches[host], channel, str(lab.ssh.get("enable", "labenable")))
    if privileged:
        session.mode = "priv"
    for line in lines:
        session.handle_line(line)
    return session, channel.text()


def configure(lab: Lab, host: str, config: str) -> str:
    """Apply a block of IOS configuration the way Ansible's ios_config sends it."""
    lines = [line for line in config.splitlines() if line.strip() and not line.startswith("!")]
    _, output = cli(lab, host, "configure terminal", *lines, "end")
    return output

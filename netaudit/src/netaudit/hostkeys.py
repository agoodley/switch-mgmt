"""Record and check switches' SSH host keys in a known_hosts file.

Trust on first use: a key never seen before is added; a key that differs from
the recorded one is reported and left alone, so the tools that check it
(Ansible, Oxidized) refuse to log in until someone confirms the change.

    netaudit known-hosts 10.10.0.1 10.10.0.2:2222 ...

No login is needed: only the SSH handshake is done.
"""

from __future__ import annotations

import base64
import fcntl
import hashlib
import os
import socket
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path

DEFAULT_FILE = "~/.ssh/known_hosts"
# Host key algorithms that prove possession of a recorded key of this type.
_ALGORITHMS = {"ssh-rsa": ["rsa-sha2-512", "rsa-sha2-256", "ssh-rsa"]}


@dataclass
class KeyResult:
    target: str  # as written in known_hosts: host, or [host]:port
    status: str  # known | added | changed | error
    key_type: str = ""
    fingerprint: str = ""
    detail: str = ""


def host_label(host: str, port: int) -> str:
    return host if port == 22 else f"[{host}]:{port}"


def parse_target(text: str) -> tuple[str, int]:
    """'10.0.0.1', '10.0.0.1:2201', '[2001:db8::1]:22' or '2001:db8::1'."""
    text = text.strip()
    if text.startswith("["):
        host, _, rest = text[1:].partition("]")
        return host, int(rest[1:]) if rest.startswith(":") else 22
    if text.count(":") == 1:
        host, port = text.split(":")
        return host, int(port)
    return text, 22


def fingerprint(key) -> str:
    digest = hashlib.sha256(key.asbytes()).digest()
    return "SHA256:" + base64.b64encode(digest).decode().rstrip("=")


def fetch_key(host: str, port: int, timeout: float = 10.0, prefer: list[str] | None = None):
    """The server's host key, from the SSH handshake (no authentication).

    ``prefer`` lists key types already recorded for the host, so a switch with
    several host keys presents the one that can be compared.
    """
    import paramiko

    sock = socket.create_connection((host, port), timeout=timeout)
    transport = paramiko.Transport(sock)
    try:
        if prefer:
            options = transport.get_security_options()
            supported = list(options.key_types)
            wanted = [a for name in prefer for a in _ALGORITHMS.get(name, [name]) if a in supported]
            if wanted:
                options.key_types = wanted + [a for a in supported if a not in wanted]
        transport.start_client(timeout=timeout)
        return transport.get_remote_server_key()
    finally:
        transport.close()


def update_known_hosts(
    path: str | os.PathLike,
    targets: list[tuple[str, int]],
    timeout: float = 10.0,
    workers: int = 16,
) -> list[KeyResult]:
    """Add unknown host keys to ``path``; report known, changed and unreachable ones."""
    import paramiko

    path = Path(os.path.expanduser(str(path)))
    path.parent.mkdir(parents=True, exist_ok=True)
    # The same lock Ansible's network_cli takes when it records keys.
    lock_path = str(path).replace("known_hosts", ".known_hosts.lock")
    with open(lock_path, "w") as lock:
        fcntl.lockf(lock, fcntl.LOCK_EX)
        try:
            known = paramiko.HostKeys(str(path)) if path.exists() else paramiko.HostKeys()

            def check(target: tuple[str, int]):
                host, port = target
                label = host_label(host, port)
                recorded = known.lookup(label) or {}
                try:
                    key = fetch_key(host, port, timeout, prefer=list(recorded))
                except Exception as exc:  # noqa: BLE001 - report every connection problem
                    detail = f"{type(exc).__name__}: {exc}".splitlines()[0][:160]
                    return KeyResult(label, "error", detail=detail), None
                result = KeyResult(label, "added", key.get_name(), fingerprint(key))
                if recorded:
                    same = key.get_name() in recorded and recorded[key.get_name()].asbytes() == key.asbytes()
                    result.status = "known" if same else "changed"
                    if not same:
                        result.detail = "differs from the recorded key (switch replaced? make forget-host)"
                return result, key

            with ThreadPoolExecutor(max_workers=max(1, min(workers, len(targets)))) as pool:
                checked = list(pool.map(check, targets)) if targets else []
            for result, key in checked:
                if result.status == "added":
                    known.add(result.target, key.get_name(), key)
            if any(result.status == "added" for result, _ in checked):
                _save(known, path)
            return [result for result, _ in checked]
        finally:
            fcntl.lockf(lock, fcntl.LOCK_UN)


def _save(known, path: Path) -> None:
    """Write the file atomically, readable by its owner only."""
    tmp = path.with_name(path.name + ".tmp")
    os.close(os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600))
    known.save(str(tmp))
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)

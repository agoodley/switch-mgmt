"""Find every switch of a site by crawling CDP from one or more seed switches.

    netaudit discover --seed 10.10.0.1 --site hq --out ansible/inventory/sites/hq.yml

Logs in with Netmiko (the login from NET_USERNAME / NET_PASSWORD /
NET_ENABLE_SECRET, or the switch's entry in credentials.yml), reads `show
version` and `show cdp neighbors detail`, follows every neighbour that
advertises the Switch capability, and writes an Ansible inventory file for the
site.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Protocol

from .credentials import Login, resolve
from .model import Neighbor
from .parsers.neighbors import parse_cdp_neighbors_detail
from .parsers.platform import parse_version
from .util import short_hostname, short_interface

DEFAULT_EXCLUDE = r"(?i)ip phone|^cisco air-|^air-|c91\d\dax|c92\d\dax|meraki|^n\dk-|nexus"


class Session(Protocol):
    def send_command(self, command: str) -> str: ...

    def disconnect(self) -> None: ...


@dataclass
class FoundSwitch:
    name: str
    ip: str
    model: str = ""
    version: str = ""
    via: str = ""
    switch_neighbors: list[str] = field(default_factory=list)


@dataclass
class CrawlResult:
    seeds: list[str]
    switches: dict[str, FoundSwitch] = field(default_factory=dict)
    failures: dict[str, str] = field(default_factory=dict)
    skipped: list[tuple[str, str]] = field(default_factory=list)  # (neighbour, reason)


def netmiko_connect(host: str, username: str, password: str, secret: str, port: int = 22) -> Session:
    from netmiko import ConnectHandler

    connection = ConnectHandler(
        device_type="cisco_ios",
        host=host,
        port=port,
        username=username,
        password=password,
        secret=secret,
        conn_timeout=15,
        auth_timeout=20,
        banner_timeout=20,
        fast_cli=False,
        # Check switches already in ~/.ssh/known_hosts; new ones are accepted.
        system_host_keys=True,
    )
    if not connection.check_enable_mode():
        connection.enable()
    return connection


def crawl(
    seeds: list[str],
    login: Login,
    credentials: dict[str, dict[str, str]] | None = None,
    site: str = "",
    max_hosts: int = 500,
    workers: int = 8,
    exclude_platforms: list[str] | None = None,
    port: int = 22,
    connect: Callable[..., Session] | None = None,
) -> CrawlResult:
    """Crawl CDP from ``seeds``.  Each switch is logged into with ``login``,
    unless ``credentials`` has an entry for its site, address or CDP name."""
    connect = connect or netmiko_connect
    credentials = credentials or {}
    site_keys = [site, _group_name(site)] if site else []
    patterns = [re.compile(DEFAULT_EXCLUDE)] + [re.compile(p, re.I) for p in (exclude_platforms or [])]
    result = CrawlResult(seeds=list(seeds))
    queued: set[str] = set()
    names_seen: set[str] = set()

    def visit(ip: str, via: str, name: str = "") -> tuple[str, str, FoundSwitch | None, list[Neighbor], str | None]:
        switch_login = resolve(credentials, login, *site_keys, ip, name)
        try:
            session = connect(ip, switch_login.username, switch_login.password, switch_login.secret, port=port)
        except Exception as exc:  # noqa: BLE001 - report every connection problem
            return ip, via, None, [], f"{type(exc).__name__}: {exc}".splitlines()[0][:200]
        try:
            version = parse_version(session.send_command("show version"))
            neighbors = parse_cdp_neighbors_detail(session.send_command("show cdp neighbors detail"))
        except Exception as exc:  # noqa: BLE001
            return ip, via, None, [], f"{type(exc).__name__}: {exc}".splitlines()[0][:200]
        finally:
            try:
                session.disconnect()
            except Exception:  # noqa: BLE001
                pass
        name = version.hostname or ip
        found = FoundSwitch(name=name, ip=ip, model=version.model, version=version.os_version, via=via)
        return ip, via, found, neighbors, None

    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        pending: set[Future] = set()
        for seed in seeds:
            queued.add(seed)
            pending.add(pool.submit(visit, seed, "seed"))
        while pending:
            done, pending = wait(pending, return_when=FIRST_COMPLETED)
            for future in done:
                ip, via, found, neighbors, error = future.result()
                if error or found is None:
                    result.failures[ip] = f"{error} (via {via})"
                    continue
                key = short_hostname(found.name)
                if key in names_seen:
                    continue  # second management address of a switch we already have
                names_seen.add(key)
                result.switches[found.name] = found
                for neighbor in neighbors:
                    label = f"{neighbor.remote_name} ({neighbor.platform or '?'})"
                    if not neighbor.is_switch:
                        continue
                    if any(p.search(neighbor.platform) for p in patterns):
                        result.skipped.append((label, "platform excluded"))
                        continue
                    found.switch_neighbors.append(short_hostname(neighbor.remote_name))
                    if not neighbor.mgmt_ip:
                        result.skipped.append((label, "no management address in CDP"))
                        continue
                    if neighbor.mgmt_ip in queued or short_hostname(neighbor.remote_name) in names_seen:
                        continue
                    if len(queued) >= max_hosts:
                        result.skipped.append((label, f"max_hosts ({max_hosts}) reached"))
                        continue
                    queued.add(neighbor.mgmt_ip)
                    pending.add(
                        pool.submit(
                            visit,
                            neighbor.mgmt_ip,
                            f"{found.name} {short_interface(neighbor.local_port)}",
                            short_hostname(neighbor.remote_name),
                        )
                    )
    return result


def _group_name(site: str) -> str:
    return re.sub(r"[^A-Za-z0-9_]", "_", site)


def write_inventory(result: CrawlResult, site: str) -> str:
    """Render the crawl result as an Ansible inventory file for one site."""
    group = _group_name(site)
    degree = {name: len(set(sw.switch_neighbors)) for name, sw in result.switches.items()}
    likely_core = sorted(degree, key=lambda n: (-degree[n], n))[:2] if degree else []
    stamp = datetime.now(UTC).isoformat(timespec="seconds")
    lines = [
        "---",
        f"# Generated by `netaudit discover` at {stamp} from seed(s) {', '.join(result.seeds)}.",
        f"# {len(result.switches)} switch(es) found, {len(result.failures)} could not be logged into.",
        "# Before `make plan`: set stp_role on the core pair (root_primary / root_secondary).",
        "switches:",
        "  children:",
        f"    {group}:",
        "      vars:",
        f"        site: {site}",
        "      hosts:",
    ]
    suggested = dict(zip(likely_core, ("root_primary", "root_secondary")))
    for name in sorted(result.switches, key=str.lower):
        sw = result.switches[name]
        lines.append(f"        {_yaml_key(name)}:")
        lines.append(f"          ansible_host: {sw.ip}")
        if name in suggested and degree.get(name, 0) > 1:
            lines.append(
                f"          # stp_role: {suggested[name]}   # {degree[name]} switch neighbours - core? uncomment to confirm"
            )
        description = " ".join(part for part in (sw.model or "?", sw.version) if part)
        lines.append(f"          # {description}, found via {sw.via}")
    if result.failures:
        lines.append("# Could not log in / read (fix and re-run, or add by hand):")
        for ip, error in sorted(result.failures.items()):
            lines.append(f"#   {ip}: {error}")
    if result.skipped:
        lines.append("# Neighbours not followed:")
        for label, reason in sorted(set(result.skipped)):
            lines.append(f"#   {label}: {reason}")
    return "\n".join(lines) + "\n"


def _yaml_key(name: str) -> str:
    return name if re.fullmatch(r"[A-Za-z0-9_.\-]+", name) else f'"{name}"'

"""Per-switch and per-site logins from ansible/inventory/credentials.yml.

The same file and rules as the Ansible vars plugin
(ansible/vars_plugins/switch_credentials.py): keys are switch names, management
addresses or site names; a switch entry beats its site's entry, which beats
the defaults from .env.
"""

from __future__ import annotations

import csv
import os
import re
from dataclasses import dataclass, replace
from pathlib import Path

import yaml

FIELDS = ("username", "password", "enable")
_CSV_KEY_COLUMNS = ("switch", "name", "host", "hostname", "ip", "address", "site")


class CredentialsError(ValueError):
    pass


@dataclass(frozen=True)
class Login:
    username: str
    password: str
    enable: str = ""

    @property
    def secret(self) -> str:
        """What to answer at the enable prompt."""
        return self.enable or self.password


def validate(data, source: str) -> dict[str, dict[str, str]]:
    if data is None:
        return {}
    if not isinstance(data, dict):
        raise CredentialsError(f"{source}: expected entries like 'hq-acc-01: {{password: ...}}'")
    result: dict[str, dict[str, str]] = {}
    for key, entry in data.items():
        if entry is None:
            continue
        if not isinstance(entry, dict):
            raise CredentialsError(f"{source}: '{key}' must contain username, password and/or enable")
        unknown = sorted(str(k) for k in entry if k not in FIELDS)
        if unknown:
            raise CredentialsError(
                f"{source}: unknown setting {', '.join(unknown)} for '{key}' (allowed: username, password, enable)"
            )
        values = {}
        for field, value in entry.items():
            if value is None:
                continue
            if not isinstance(value, str):
                raise CredentialsError(
                    f"{source}: put the {field} of '{key}' in quotes (YAML reads it as {type(value).__name__})"
                )
            values[field] = value
        result[str(key)] = values
    return result


def load_credentials(path: str | os.PathLike | None) -> dict[str, dict[str, str]]:
    """Read credentials.yml; a missing file means no exceptions to the defaults."""
    if not path:
        return {}
    path = Path(path)
    if not path.is_file():
        return {}
    text = path.read_text(encoding="utf-8")
    if text.lstrip().startswith("$ANSIBLE_VAULT"):
        raise CredentialsError(
            f"{path} is encrypted with ansible-vault; netaudit cannot read it. "
            "Decrypt it for the run (ansible-vault decrypt) or rely on the .env login."
        )
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise CredentialsError(f"{path}: {exc}") from exc
    return validate(data, str(path))


def resolve(credentials: dict[str, dict[str, str]], default: Login, *keys: str | None) -> Login:
    """The login for a switch.  ``keys`` go from least to most specific
    (site name(s), address, switch name); later entries override earlier ones."""
    login = default
    for key in keys:
        entry = credentials.get(key) if key else None
        if entry:
            login = replace(login, **entry)
    return login


def default_login() -> Login:
    return Login(
        username=os.environ.get("NET_USERNAME", ""),
        password=os.environ.get("NET_PASSWORD", ""),
        enable=os.environ.get("NET_ENABLE_SECRET", ""),
    )


# -- import from a spreadsheet --------------------------------------------------------


def read_csv(path: str | os.PathLike) -> dict[str, dict[str, str]]:
    """Read a CSV export (header row required) into credentials entries.

    The first matching column of switch/name/host/hostname/ip/address/site is
    the key; username, password and enable columns are optional; empty cells
    are skipped.
    """
    with open(path, newline="", encoding="utf-8-sig") as handle:
        # The header has no passwords in it, so its separator is reliable.
        header = handle.readline()
        handle.seek(0)
        delimiter = max(",;\t", key=header.count)
        reader = csv.DictReader(handle, delimiter=delimiter)
        columns = {name.strip().lower(): name for name in reader.fieldnames or []}
        key_column = next((columns[c] for c in _CSV_KEY_COLUMNS if c in columns), None)
        if key_column is None:
            raise CredentialsError(f"{path}: no switch column (one of: {', '.join(_CSV_KEY_COLUMNS)})")
        fields = {field: columns[field] for field in FIELDS if field in columns}
        if not fields:
            raise CredentialsError(f"{path}: no username, password or enable column")
        entries: dict[str, dict[str, str]] = {}
        for row in reader:
            key = (row.get(key_column) or "").strip()
            if not key:
                continue
            values = {field: row[column] for field, column in fields.items() if row.get(column)}
            if values:
                entries[key] = values
        return entries


def _quote(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def _key(key: str) -> str:
    plain = re.fullmatch(r"[A-Za-z0-9_.\-]+", key) and yaml.safe_load(key) == key
    return key if plain else _quote(key)


def dump(credentials: dict[str, dict[str, str]]) -> str:
    """credentials.yml text with every value single-quoted (safe for any password)."""
    lines = ["---", "# Switch, address or site -> login; see credentials.yml.sample.", ""]
    for key, entry in credentials.items():
        lines.append(f"{_key(key)}:")
        lines.extend(f"  {field}: {_quote(entry[field])}" for field in FIELDS if field in entry)
    return "\n".join(lines) + "\n"


def merge_into(path: str | os.PathLike, new: dict[str, dict[str, str]]) -> tuple[int, int]:
    """Add/update entries in credentials.yml (mode 600).  Returns (added, updated)."""
    path = Path(path)
    current = load_credentials(path)
    added = sum(1 for key in new if key not in current)
    updated = sum(1 for key in new if key in current and {**current[key], **new[key]} != current[key])
    for key, entry in new.items():
        current[key] = {**current.get(key, {}), **entry}
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(dump(current))
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)
    return added, updated

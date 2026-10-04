"""Per-switch and per-site logins from credentials.yml next to the inventory."""

from __future__ import annotations

import os
import stat

from ansible.errors import AnsibleError, AnsibleParserError
from ansible.inventory.group import InventoryObjectType
from ansible.plugins.vars import BaseVarsPlugin

DOCUMENTATION = """
    name: switch_credentials
    short_description: Per-switch and per-site logins from credentials.yml
    requirements:
        - Enabled in ansible.cfg (vars_plugins_enabled)
    description:
        - Reads C(credentials.yml) from the inventory directory (or its parent).
        - Each key is a switch (inventory name or C(ansible_host) address) or a
          site (inventory group); each value sets C(username), C(password)
          and/or C(enable).
        - Sets C(ansible_user), C(ansible_password) and C(switch_enable_secret)
          for those hosts and groups. A switch entry beats its site's entry,
          which beats the defaults in group_vars (from .env).
        - The file may be encrypted with ansible-vault.
    options:
      stage:
        ini:
          - key: stage
            section: vars_switch_credentials
        env:
          - name: ANSIBLE_VARS_PLUGIN_STAGE
    extends_documentation_fragment:
      - vars_plugin_staging
"""

FILENAME = "credentials.yml"
FIELDS = {"username": "ansible_user", "password": "ansible_password", "enable": "switch_enable_secret"}

_CACHE: dict[str, tuple[float, dict[str, dict[str, str]]]] = {}
_WARNED: set[str] = set()


def _find(path: str) -> str | None:
    for directory in (path, os.path.dirname(path)):
        candidate = os.path.join(directory, FILENAME)
        if os.path.isfile(candidate):
            return candidate
    return None


def _validate(data, source: str) -> dict[str, dict[str, str]]:
    if data is None:
        return {}
    if not isinstance(data, dict):
        raise AnsibleParserError(f"{source}: expected entries like 'hq-acc-01: {{password: ...}}'")
    result = {}
    for key, entry in data.items():
        if entry is None:
            continue
        if not isinstance(entry, dict):
            raise AnsibleParserError(f"{source}: '{key}' must contain username, password and/or enable")
        unknown = sorted(str(k) for k in entry if k not in FIELDS)
        if unknown:
            raise AnsibleParserError(
                f"{source}: unknown setting {', '.join(unknown)} for '{key}' (allowed: username, password, enable)"
            )
        values = {}
        for field, value in entry.items():
            if value is None:
                continue
            if not isinstance(value, str):
                # YAML turns 0123 into 83 and yes into True: refuse rather than guess
                raise AnsibleParserError(
                    f"{source}: put the {field} of '{key}' in quotes (YAML reads it as {type(value).__name__})"
                )
            values[field] = str(value)
        result[str(key)] = values
    return result


class VarsModule(BaseVarsPlugin):
    REQUIRES_ENABLED = True
    is_stateless = True

    def _load(self, loader, path: str) -> dict[str, dict[str, str]]:
        source = _find(path)
        if source is None:
            return {}
        mtime = os.stat(source).st_mtime
        cached = _CACHE.get(source)
        if cached and cached[0] == mtime:
            return cached[1]
        info = os.stat(source)
        # Only for a file of ours: one provided read-only by the toolbox image
        # (the lab's, root-owned) is not something the user could chmod.
        if info.st_mode & (stat.S_IRWXG | stat.S_IRWXO) and info.st_uid == os.getuid() and source not in _WARNED:
            _WARNED.add(source)
            self._display.warning(f"{source} can be read by other users; run: chmod 600 {source}")
        try:
            data = loader.load_from_file(source, cache="none")
        except AnsibleError as exc:
            raise AnsibleError(
                f"Could not read {source}: {exc}. If it is encrypted with ansible-vault, "
                "add --ask-vault-pass (make ... ARGS=--ask-vault-pass)."
            ) from exc
        credentials = _validate(data, source)
        _CACHE[source] = (mtime, credentials)
        return credentials

    def get_vars(self, loader, path, entities, cache=True):
        super().get_vars(loader, path, entities)
        credentials = self._load(loader, path)
        if not credentials:
            return {}
        if not isinstance(entities, list):
            entities = [entities]
        data = {}
        for entity in entities:
            if entity.base_type is InventoryObjectType.HOST:
                # the address first, so an entry under the switch's name wins
                keys = [str(entity.vars.get("ansible_host", "")), entity.name]
            else:
                keys = [entity.name]
            for key in keys:
                for field, value in credentials.get(key, {}).items():
                    data[FIELDS[field]] = value
        return data

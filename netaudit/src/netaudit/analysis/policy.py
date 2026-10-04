"""Desired-state policy, read from Ansible inventory variables ("intent")."""

from __future__ import annotations

from typing import Any

from ..model import Device
from ..util import canonical_interface

# Mirrors ansible/inventory/group_vars/switches.yml.  Anything set in the
# inventory (group_vars / host_vars) overrides these defaults.
DEFAULT_POLICY: dict[str, Any] = {
    "stp_mode": "rapid-pvst",
    "stp_role": "access",
    "stp_vlans": "1-4094",
    "stp_priority": None,
    "stp_priority_root_primary": 4096,
    "stp_priority_root_secondary": 8192,
    "stp_priority_other": None,
    "stp_edge_portfast": True,
    "stp_edge_bpduguard": True,
    "stp_portfast_command": "spanning-tree portfast",
    "stp_portfast_trunk_command": "spanning-tree portfast trunk",
    "stp_edge_skip_bpdu_seen": True,
    "stp_edge_exclude": [],
    "stp_edge_trunks": [],
    "stp_errdisable_recovery": True,
    "stp_errdisable_recovery_interval": 300,
    "stp_loopguard_default": False,
    "stp_rootguard_downlinks": False,
    "stp_pathcost_method": None,
    "audit_tc_warn_per_day": 24,
    "audit_tc_high_per_day": 240,
    "audit_tc_recent_seconds": 600,
    "audit_flap_transitions": 100,
    "audit_max_pvst_instances": 128,
}

_BOOL_TRUE = {"true", "yes", "on", "1"}
_BOOL_FALSE = {"false", "no", "off", "0", ""}


def _coerce(key: str, value: Any) -> Any:
    default = DEFAULT_POLICY.get(key)
    if value is None:
        return None
    if isinstance(default, bool):
        if isinstance(value, str):
            low = value.strip().lower()
            if low in _BOOL_TRUE:
                return True
            if low in _BOOL_FALSE:
                return False
        return bool(value)
    if isinstance(default, list):
        if isinstance(value, str):
            return [v.strip() for v in value.split(",") if v.strip()]
        return list(value)
    if key.startswith(("stp_priority", "audit_", "stp_errdisable_recovery_interval")):
        if isinstance(value, str):
            value = value.strip()
            if value in ("", "none", "null"):
                return None
        try:
            return int(value)
        except (TypeError, ValueError):
            return value
    if isinstance(value, str) and value.strip().lower() in ("", "none", "null"):
        return None
    return value


def policy_for(device: Device) -> dict[str, Any]:
    policy = dict(DEFAULT_POLICY)
    for key, value in device.intent.items():
        if key in DEFAULT_POLICY:
            policy[key] = _coerce(key, value)
    policy["stp_edge_exclude"] = {canonical_interface(p) for p in policy.get("stp_edge_exclude") or []}
    policy["stp_edge_trunks"] = [canonical_interface(p) for p in policy.get("stp_edge_trunks") or []]
    if policy.get("stp_mode"):
        policy["stp_mode"] = str(policy["stp_mode"]).strip().lower()
    return policy


def target_priority(policy: dict[str, Any]) -> int | None:
    """The bridge priority this switch should have, or None to leave it alone."""
    if policy.get("stp_priority") is not None:
        return policy["stp_priority"]
    role = policy.get("stp_role") or "access"
    if role == "root_primary":
        return policy.get("stp_priority_root_primary")
    if role == "root_secondary":
        return policy.get("stp_priority_root_secondary")
    return policy.get("stp_priority_other")


def valid_priority(value: Any) -> bool:
    return isinstance(value, int) and 0 <= value <= 61440 and value % 4096 == 0

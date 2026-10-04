"""End-to-end analysis of the simulated lab: findings, topology-change tracing and the plan."""

import pytest
from conftest import collect, configure

from netaudit.analysis import analyze
from netaudit.analysis.policy import policy_for, target_priority, valid_priority
from netaudit.model import Device

pytest.importorskip("paramiko")  # the CLI used to apply plans lives in netaudit.lab.server


def find(result, category, host=None, contains=""):
    return [
        f
        for f in result.findings
        if f.category == category and (host is None or f.host == host) and contains in f.title
    ]


def apply_plan(lab, plan):
    """What the stp_remediate playbook does: every switch in order, safe changes first."""
    for host in plan.apply_order:
        host_plan = plan.hosts[host]
        for disruptive in (False, True):
            text = host_plan.config_text(disruptive=disruptive)
            if text:
                output = configure(lab, host, text)
                assert "% Invalid" not in output, (host, output)


@pytest.fixture
def result(lab):
    return analyze(collect(lab))


# -- findings -----------------------------------------------------------------------------


def test_wrong_root_bridge(result):
    view = result.views[("lab", "VLAN0010")]
    assert view.root_host == "acc-01"
    assert view.expected_root == "core-01"
    (finding,) = find(result, "root-bridge", "core-01")
    assert finding.severity == "high"
    assert finding.planned
    assert "acc-01" in finding.title


def test_mixed_modes(result):
    (finding,) = find(result, "stp-mode", contains="Mixed")
    assert finding.host is None and finding.site == "lab"
    assert finding.planned


def test_topology_changes_traced_to_the_flapping_port(result):
    trace = next(t for t in result.traces if t.instance == "VLAN0010")
    assert (trace.origin_host, trace.origin_port, trace.origin_kind) == (
        "acc-03",
        "GigabitEthernet1/0/7",
        "access-port",
    )
    assert [hop.host for hop in trace.hops] == ["acc-01", "core-01", "acc-03"]
    (finding,) = find(result, "topology-change", "acc-03", "originate")
    assert finding.severity == "high"
    assert finding.planned  # PortFast on Gi1/0/7 is in the plan


def test_rogue_switch_behind_an_access_port(result):
    (finding,) = find(result, "edge-ports", "acc-02", "switch or bridge")
    assert finding.ports == ["GigabitEthernet1/0/11"]
    assert not finding.planned


def test_other_lab_problems_are_reported(result):
    assert find(result, "errdisable", "acc-04")
    assert find(result, "inconsistent-ports", "acc-04", "PVID")
    assert find(result, "inconsistent-ports", "acc-02", "PVID")
    assert find(result, "logs", "acc-02", "MAC address flapping")
    (mismatch,) = find(result, "trunks", contains="Native VLAN mismatch")
    assert "acc-04 Gi0/2" in mismatch.title


def test_findings_are_sorted_by_severity(result):
    ranks = [f.rank for f in result.findings]
    assert ranks == sorted(ranks)
    assert result.counts()["critical"] == 0


# -- plan -------------------------------------------------------------------------------------


def test_apply_order_canary_then_roots(result):
    plan = result.plan
    assert plan.warnings == []
    assert plan.apply_order[:3] == ["acc-03", "core-01", "core-02"]
    assert sorted(plan.apply_order) == sorted(result.devices)
    canary = plan.hosts["acc-03"]
    assert canary.role == "access" and not canary.disruptive
    assert [plan.hosts[h].order for h in plan.apply_order] == list(range(1, 7))


def test_root_priorities_and_modes(result):
    hosts = result.plan.hosts
    assert "spanning-tree vlan 1-4094 priority 4096" in hosts["core-01"].config_text(disruptive=True)
    assert "spanning-tree vlan 1-4094 priority 8192" in hosts["core-02"].config_text(disruptive=True)
    for host in ("acc-01", "acc-02", "acc-04"):  # the PVST+ switches
        assert "spanning-tree mode rapid-pvst" in hosts[host].config_text(disruptive=True)
    assert "spanning-tree mode" not in hosts["core-01"].config_text()
    assert "priority" not in hosts["acc-01"].config_text()


def test_edge_ports_are_hardened_but_not_the_rogue_switch_port(result):
    acc02 = result.plan.hosts["acc-02"]
    text = acc02.config_text(disruptive=False)
    assert "interface GigabitEthernet1/0/1\n spanning-tree portfast\n spanning-tree bpduguard enable" in text
    assert "interface GigabitEthernet1/0/11\n" not in text
    assert acc02.skipped == [{"port": "Gi1/0/11", "reason": "has received 7 BPDUs - something running STP is attached"}]
    # uplinks are never touched
    assert "interface GigabitEthernet1/0/49\n" not in text
    # acc-03 Gi1/0/25-44 were hardened by hand already
    acc03 = result.plan.hosts["acc-03"].config_text()
    assert "interface GigabitEthernet1/0/7\n spanning-tree portfast" in acc03
    assert "interface GigabitEthernet1/0/30\n" not in acc03


def test_portfast_command_works_on_old_and_new_ios(lab, result):
    # "spanning-tree portfast" is accepted everywhere; 15.2(2)E+ stores it as "portfast edge"
    for host in ("acc-01", "acc-04"):
        text = result.plan.hosts[host].config_text()
        assert "portfast edge" not in text
        configure(lab, host, text)
    assert " spanning-tree portfast edge\n" in lab.run("acc-01", "show running-config | section GigabitEthernet1/0/1$")
    assert " spanning-tree portfast\n" in lab.run("acc-04", "show running-config | section FastEthernet0/1$") + "\n"


def test_rollback_undoes_every_change(result):
    plan = result.plan.hosts["core-01"]
    rollback = plan.rollback_text()
    assert "no spanning-tree vlan 1-4094 priority" in rollback
    assert "no errdisable recovery cause bpduguard" in rollback
    assert rollback.count("interface ") == plan.config_text().count("interface ")


def test_plan_to_dict_is_what_the_playbook_reads(result):
    data = result.plan.to_dict()
    assert data["apply_order"] == result.plan.apply_order
    host = data["hosts"]["core-01"]
    for key in ("config_safe", "config_disruptive", "rollback", "summary", "has_changes", "blockers", "verify_ports"):
        assert key in host
    assert host["config_disruptive"].strip() == "spanning-tree vlan 1-4094 priority 4096"
    assert host["verify_ports"] == ["Gi1/0/1", "Gi1/0/2", "Gi1/0/3", "Po1"]


# -- the whole loop ------------------------------------------------------------------------------


def test_remediation_fixes_what_it_planned(lab, clock):
    before = analyze(collect(lab))
    clock.advance(300)
    apply_plan(lab, before.plan)
    clock.advance(4 * 3600)
    after = analyze(collect(lab), previous=collect_previous(before))

    for (_, instance), view in after.views.items():
        assert view.root_host == "core-01", instance
    assert {d.stp_summary.mode for d in after.devices.values()} == {"rapid-pvst"}
    assert after.plan.apply_order == []
    assert not [f for f in after.findings if f.planned]
    assert not find(after, "root-bridge")
    assert not find(after, "stp-mode")
    # the flapping PC no longer causes topology changes
    assert all(f.severity not in ("critical", "high") for f in find(after, "topology-change"))
    # things the plan deliberately does not touch are still reported
    assert find(after, "edge-ports", "acc-02", "switch or bridge")
    assert find(after, "inconsistent-ports", "acc-04", "PVID")


def collect_previous(result):
    return list(result.devices.values())


def test_tc_deltas_against_the_previous_run(lab, clock):
    first = collect(lab)
    clock.advance(3600)
    result = analyze(collect(lab), previous=first)
    state = result.views[("lab", "VLAN0010")].switches["acc-03"]
    assert state.tc_delta == 40  # one change every 90 seconds
    assert state.tc_delta_seconds == 3600
    (finding,) = find(result, "topology-change", "acc-03", "originate")
    assert finding.severity == "high"


# -- policy edge cases ---------------------------------------------------------------------------------


def test_mst_switch_is_a_blocker(lab):
    configure(lab, "acc-01", "spanning-tree mode mst")
    result = analyze(collect(lab))
    plan = result.plan.hosts["acc-01"]
    assert plan.blockers
    assert "acc-01" not in result.plan.apply_order


def test_priority_conflict_blocks_the_primary_root(lab):
    devices = [_with_intent(d, stp_priority=4096) if d.host == "acc-01" else d for d in collect(lab)]
    result = analyze(devices)
    assert any("acc-01 has priority <= 4096" in w for w in result.plan.warnings)
    assert result.plan.hosts["core-01"].blockers
    assert "core-01" not in result.plan.apply_order


def test_edge_exclude_and_disabled_edge_hardening(lab):
    devices = [
        _with_intent(d, stp_edge_exclude=["Gi1/0/1", "GigabitEthernet1/0/2"])
        if d.host == "acc-01"
        else _with_intent(d, stp_edge_portfast=False, stp_edge_bpduguard="no")
        if d.host == "acc-02"
        else d
        for d in collect(lab)
    ]
    plan = analyze(devices).plan
    acc01 = plan.hosts["acc-01"].config_text()
    assert "interface GigabitEthernet1/0/1\n" not in acc01
    assert "interface GigabitEthernet1/0/2\n" not in acc01
    assert "interface GigabitEthernet1/0/3\n" in acc01
    assert "portfast" not in plan.hosts["acc-02"].config_text()


def test_no_root_roles_means_no_priority_changes(lab):
    result = analyze(collect(lab, roles={}))
    for host_plan in result.plan.hosts.values():
        assert "priority" not in host_plan.config_text()
    assert not find(result, "root-bridge", contains="expected")


def test_policy_coercion():
    device = Device(
        host="sw",
        intent={
            "site": "hq",
            "stp_role": "root_secondary",
            "stp_priority": "",
            "stp_edge_bpduguard": "false",
            "stp_edge_exclude": "Gi1/0/1, Gi1/0/2",
            "stp_mode": " Rapid-PVST ",
            "audit_tc_warn_per_day": "50",
            "unrelated": "ignored",
        },
    )
    policy = policy_for(device)
    assert policy["stp_priority"] is None
    assert policy["stp_edge_bpduguard"] is False
    assert policy["stp_edge_exclude"] == {"GigabitEthernet1/0/1", "GigabitEthernet1/0/2"}
    assert policy["stp_mode"] == "rapid-pvst"
    assert policy["audit_tc_warn_per_day"] == 50
    assert "unrelated" not in policy
    assert target_priority(policy) == 8192
    assert valid_priority(8192) and not valid_priority(1000) and not valid_priority("4096")


def test_unreachable_switch_is_reported(lab):
    devices = collect(lab)
    dead = Device(host="acc-99", intent={"site": "lab"}, reachable=False, errors={"connection": "timed out"})
    result = analyze(devices + [dead])
    assert [f for f in result.findings if f.host == "acc-99" and f.category == "collection"]
    assert "acc-99" not in result.plan.apply_order


def _with_intent(device, **values):
    device.intent = {**device.intent, **values}
    return device

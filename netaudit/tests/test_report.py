import json

from conftest import collect, configure, write_run

from netaudit.analysis import analyze
from netaudit.report import split_raw, write_reports
from netaudit.report.diagram import mermaid, svg


def test_write_reports(lab, tmp_path):
    result = analyze(collect(lab))
    paths = write_reports(result, tmp_path, title="Lab audit")

    html = paths["html"].read_text(encoding="utf-8")
    assert "<title>Lab audit" in html
    assert "<svg" in html
    assert "Root bridge is acc-01, expected core-01" in html
    assert "Gi1/0/7" in html

    markdown = paths["markdown"].read_text(encoding="utf-8")
    assert markdown.startswith("# Lab audit")
    assert "Root bridge is acc-01, expected core-01" in markdown

    findings = json.loads(paths["findings"].read_text())
    assert len(findings) == len(result.findings)
    assert {"severity", "category", "title", "host"} <= set(findings[0])

    plan = json.loads(paths["plan"].read_text())
    assert plan == json.loads(json.dumps(result.plan.to_dict()))

    summary = json.loads(paths["summary"].read_text())
    assert summary["counts"]["high"] == result.counts()["high"]

    cfg = (tmp_path / "plan" / "core-01.cfg").read_text()
    assert cfg.startswith("! Planned changes for core-01 (apply order 2)")
    assert "!   no spanning-tree vlan 1-4094 priority" in cfg
    assert "spanning-tree vlan 1-4094 priority 4096" in cfg
    assert json.loads((tmp_path / "plan" / "core-01.json").read_text())["order"] == 2


def test_stale_plan_files_are_removed(lab, tmp_path):
    first = analyze(collect(lab))
    write_reports(first, tmp_path)
    assert (tmp_path / "plan" / "acc-03.cfg").exists()
    configure(lab, "acc-03", first.plan.hosts["acc-03"].config_text())
    write_reports(analyze(collect(lab)), tmp_path)
    assert not (tmp_path / "plan" / "acc-03.cfg").exists()
    assert (tmp_path / "plan" / "acc-03.json").exists()


def test_split_raw(lab, tmp_path):
    run = write_run(lab, tmp_path / "run")
    split_raw(run / "raw")
    text = (run / "raw" / "acc-01" / "show_spanning-tree_detail.txt").read_text()
    assert "VLAN0010 is executing the" in text


def test_diagrams(lab):
    result = analyze(collect(lab))
    view = result.views[("lab", "VLAN0010")]
    picture = svg(result.topology, view)
    assert picture.startswith("<svg") and picture.rstrip().endswith("</svg>")
    for host in result.devices:
        assert host in picture
    graph = mermaid(view)
    assert graph.startswith("graph")
    assert "acc-01" in graph and "acc-03" in graph

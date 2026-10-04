import json

from conftest import TOPOLOGY, write_run

from netaudit.cli import main


def test_lab_generate_and_analyze(tmp_path, capsys):
    run = tmp_path / "20261004T0400"
    assert main(["lab", "generate", "--topology", str(TOPOLOGY), "--out", str(run)]) == 0
    payload = json.loads((run / "raw" / "core-01.json").read_text())
    assert payload["intent"] == {"site": "lab", "stp_role": "root_primary", "ansible_host": "10.99.0.1"}
    assert payload["errors"] == {}

    assert main(["analyze", str(run), "--title", "Lab"]) == 0
    out = capsys.readouterr().out
    assert "Audited 6 switch(es)" in out
    assert "Plan: 6 switch(es)" in out
    assert (run / "report.html").is_file()
    assert (run / "raw" / "core-01" / "show_version.txt").is_file()

    assert main(["analyze", str(run), "--fail-on", "high", "--no-split"]) == 3
    assert main(["analyze", str(run), "--fail-on", "critical"]) == 0


def test_analyze_compares_with_the_previous_run(lab, clock, tmp_path, capsys):
    write_run(lab, tmp_path / "20261004T0400")
    clock.advance(3600)
    newer = write_run(lab, tmp_path / "20261004T0500")
    (tmp_path / "latest").symlink_to(newer)
    assert main(["analyze", str(newer)]) == 0
    assert "Compared topology-change counters with 20261004T0400" in capsys.readouterr().out
    assert main(["analyze", str(newer), "--previous", "none"]) == 0
    assert "Compared" not in capsys.readouterr().out


def test_analyze_errors(tmp_path, capsys):
    assert main(["analyze", str(tmp_path / "missing")]) == 2
    (tmp_path / "empty" / "raw").mkdir(parents=True)
    assert main(["analyze", str(tmp_path / "empty")]) == 2
    assert "no collected data" in capsys.readouterr().err


def test_discover_needs_credentials(monkeypatch, capsys):
    monkeypatch.delenv("NET_USERNAME", raising=False)
    monkeypatch.delenv("NET_PASSWORD", raising=False)
    assert main(["discover", "--seed", "192.0.2.1", "--site", "hq"]) == 2
    assert "NET_USERNAME" in capsys.readouterr().err

import json
from pathlib import Path

import pytest

from alertsift.cli import main

SAMPLES = Path(__file__).resolve().parents[1] / "sample_logs"


def everything():
    return [
        "--auth", str(SAMPLES / "auth.log"), str(SAMPLES / "windows_security.csv"),
        "--portscan", str(SAMPLES / "firewall.log"), str(SAMPLES / "pfirewall.log"),
        "--web", str(SAMPLES / "access.log"),
        "--phishing", str(SAMPLES / "emails"),
        "--c2", str(SAMPLES / "dns.csv"),
        "--year", "2026",
    ]


def run_json(capsys, args):
    code = main(args + ["--format", "json"])
    return code, json.loads(capsys.readouterr().out)


def test_no_inputs_is_a_usage_error():
    with pytest.raises(SystemExit) as exc:
        main([])
    assert exc.value.code == 2


def test_version_flag(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    assert "alertsift" in capsys.readouterr().out


def test_text_report_ranks_the_compromised_attacker_first(capsys):
    assert main(everything()) == 0
    out = capsys.readouterr().out
    assert "ALERTSIFT TRIAGE REPORT" in out
    first_row = next(l for l in out.splitlines() if l.startswith('1 '))
    assert "CRITICAL" in first_row and "45.33.32.156" in first_row


def test_all_five_attack_types_are_reported_with_big_workload_reduction(capsys):
    code, data = run_json(capsys, everything())
    assert code == 0
    assert {i["type"] for i in data["incidents"]} == {
        "auth_attack", "port_scan", "web_attack", "phishing", "c2_beaconing"}
    assert data["stats"]["reduction_pct"] >= 90
    assert data["stats"]["raw_alerts"] > 200


def test_benign_sample_traffic_produces_no_incidents(capsys):
    # 2 legitimate emails + the periodic NTP-style traffic must stay silent
    code, data = run_json(capsys, ["--phishing", str(SAMPLES / "emails" / "legit_1.eml"),
                                   str(SAMPLES / "emails" / "legit_2.eml")])
    assert code == 0 and data["incidents"] == []


def test_phishing_campaign_groups_into_one_incident(capsys):
    _, data = run_json(capsys, ["--phishing", str(SAMPLES / "emails")])
    assert len(data["incidents"]) == 1
    assert data["incidents"][0]["alert_count"] == 5


def test_markdown_output_to_a_file(tmp_path, capsys):
    target = tmp_path / "out" / "report.md"
    assert main(everything() + ["--format", "markdown", "-o", str(target)]) == 0
    assert "Wrote" in capsys.readouterr().out
    assert target.read_text(encoding="utf-8").startswith("# AlertSift Triage Report")


def test_fail_on_threshold_sets_the_exit_code(capsys):
    args = ["--phishing", str(SAMPLES / "emails")]             # one MEDIUM incident
    assert main(args + ["--fail-on", "high"]) == 0
    assert main(args + ["--fail-on", "medium"]) == 1


def test_missing_input_file_exits_with_code_2(capsys):
    assert main(["--auth", "no_such_file.log"]) == 2
    assert "error:" in capsys.readouterr().err


def test_bad_csv_columns_exit_with_code_2(tmp_path, capsys):
    bad = tmp_path / "bad.csv"
    bad.write_text("foo,bar\n1,2\n")
    assert main(["--c2", str(bad)]) == 2
    assert "error:" in capsys.readouterr().err


def test_allowlist_lowers_the_score_of_a_known_scanner(tmp_path, capsys):
    base = ["--auth", str(SAMPLES / "windows_security.csv")]
    _, before = run_json(capsys, base)
    allow = tmp_path / "allow.txt"
    allow.write_text("# our scanner\n10.0.2.15\n")
    _, after = run_json(capsys, base + ["--allowlist", str(allow)])
    assert after["incidents"][0]["score"] == before["incidents"][0]["score"] - 30
    assert any("allowlist" in r for r in after["incidents"][0]["reasons"])


def test_blocklist_raises_the_score(tmp_path, capsys):
    base = ["--auth", str(SAMPLES / "windows_security.csv")]
    _, before = run_json(capsys, base)
    block = tmp_path / "block.txt"
    block.write_text("10.0.2.15\n")
    _, after = run_json(capsys, base + ["--blocklist", str(block)])
    assert after["incidents"][0]["score"] > before["incidents"][0]["score"]


def test_output_is_deterministic(capsys):
    main(everything())
    first = capsys.readouterr().out
    main(everything())
    assert capsys.readouterr().out == first

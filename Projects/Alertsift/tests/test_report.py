import json
from datetime import datetime, timedelta, timezone

from alertsift.report import to_json, to_markdown, to_text
from alertsift.schema import Alert, AlertType, Incident
from alertsift.scoring import score_incidents

T0 = datetime(2026, 10, 9, 10, 0, tzinfo=timezone.utc)
STATS = {"raw_alerts": 50, "duplicates_removed": 0, "incidents": 2, "reduction_pct": 96}


def make_incident(entity, n=3, compromise=False):
    alerts = [
        Alert(AlertType.AUTH_ATTACK, T0 + timedelta(seconds=30 * i), "test", entity, "root",
              raw=f"{entity}-{i}", evidence={"compromise": compromise})
        for i in range(n)
    ]
    return Incident(AlertType.AUTH_ATTACK, entity, alerts)


def ranked():
    return score_incidents([make_incident("10.0.0.1"), make_incident("8.8.8.8", compromise=True)])


def test_text_report_lists_every_incident_and_the_stats_line():
    incidents = ranked()
    text = to_text(incidents, STATS)
    for inc in incidents:
        assert inc.id in text
    assert "50 raw alerts -> 2 incidents (96% less to review)" in text
    assert text.index("8.8.8.8") < text.index("10.0.0.1")


def test_text_report_limits_the_detail_sections():
    assert to_text(ranked(), STATS, max_details=1).count("Why this score:") == 1


def test_markdown_report_has_table_and_details():
    incidents = ranked()
    md = to_markdown(incidents, STATS)
    assert "| Rank | ID | Severity | Score | Type | Source | Alerts |" in md
    assert f"### {incidents[0].id}" in md
    assert md.endswith("\n")


def test_json_report_is_valid_and_complete():
    incidents = ranked()
    data = json.loads(to_json(incidents, STATS))
    assert data["stats"]["incidents"] == 2
    first = data["incidents"][0]
    assert first["id"] == incidents[0].id
    assert first["severity"] == incidents[0].severity.value
    assert isinstance(first["reasons"], list) and first["reasons"]
    datetime.fromisoformat(first["first_seen"])


def test_reports_handle_no_incidents():
    assert "ALERTSIFT TRIAGE REPORT" in to_text([])
    assert "| Rank |" in to_markdown([])
    assert json.loads(to_json([]))["incidents"] == []

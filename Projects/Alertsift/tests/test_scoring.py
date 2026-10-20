import re
from datetime import datetime, timedelta, timezone

from alertsift.schema import Alert, AlertType, Incident, Severity
from alertsift.scoring import (
    allowlist_enricher,
    blocklist_enricher,
    score_incidents,
    severity_for,
)

T0 = datetime(2026, 10, 9, 10, 0, tzinfo=timezone.utc)


def make_incident(n=3, atype=AlertType.AUTH_ATTACK, entity="10.0.0.5",
                  targets=("kali",), span_seconds=120, evidence=None):
    alerts = []
    for i in range(n):
        offset = span_seconds * i / max(n - 1, 1)
        alerts.append(Alert(
            atype, T0 + timedelta(seconds=offset), "test", entity,
            targets[i % len(targets)], raw=f"r{i}", evidence=dict(evidence or {}),
        ))
    return Incident(atype, entity, alerts)


def points(inc):
    return [int(re.match(r"^([+-]\d+)\s", r).group(1)) for r in inc.reasons]


def test_severity_thresholds():
    expected = {0: "low", 29: "low", 30: "medium", 59: "medium",
                60: "high", 89: "high", 90: "critical", 100: "critical"}
    for score, sev in expected.items():
        assert severity_for(score).value == sev


def test_small_internal_incident_gets_only_the_baseline():
    inc = make_incident(n=3)
    score_incidents([inc])
    assert inc.score == 10
    assert inc.severity == Severity.LOW
    assert inc.reasons == ["+10 baseline for auth_attack"]


def test_volume_tiers():
    for n, span, expected in [(5, 3600, 20), (20, 3600, 30), (100, 36000, 40)]:
        inc = make_incident(n=n, span_seconds=span)
        score_incidents([inc])
        assert inc.score == expected, f"n={n}"


def test_burst_rate_needs_enough_alerts_and_speed():
    fast = make_incident(n=10, span_seconds=30)
    slow = make_incident(n=9, span_seconds=30)
    score_incidents([fast, slow])
    assert any("burst" in r for r in fast.reasons)
    assert not any("burst" in r for r in slow.reasons)


def test_target_spread():
    three = make_incident(n=3, targets=("a", "b", "c"))
    ten = make_incident(n=10, targets=tuple(f"h{i}" for i in range(10)), span_seconds=3600)
    score_incidents([three, ten])
    assert three.score == 10 + 10
    assert ten.score == 10 + 10 + 20


def test_external_ip_scores_higher_than_private_or_non_ip():
    ext = make_incident(entity="8.8.8.8")
    private = make_incident(entity="10.0.0.5")
    email = make_incident(entity="a@b.example")
    score_incidents([ext, private, email])
    assert ext.score == private.score + 10
    assert email.score == private.score


def test_privileged_target_is_case_insensitive():
    inc = make_incident(targets=("Administrator",))
    score_incidents([inc])
    assert inc.score == 20


def test_compromise_flag_adds_40():
    inc = make_incident(evidence={"compromise": True})
    score_incidents([inc])
    assert inc.score == 50
    assert any("compromise" in r for r in inc.reasons)


def test_multi_stage_bonus_for_same_source_across_types():
    auth = make_incident(entity="45.33.32.156", targets=("web",))
    scan = make_incident(entity="45.33.32.156", atype=AlertType.PORT_SCAN, targets=("web",))
    other = make_incident(entity="10.0.0.9", targets=("web",))
    score_incidents([auth, scan, other])
    assert auth.score == 10 + 10 + 20
    assert scan.score == 5 + 10 + 20
    assert other.score == 10


def test_multi_stage_matching_ignores_case():
    a = make_incident(entity="Evil@Example.com", atype=AlertType.PHISHING, targets=("x",))
    b = make_incident(entity="evil@example.com", atype=AlertType.WEB_ATTACK, targets=("x",))
    score_incidents([a, b])
    assert any("multi-stage" in r for r in a.reasons)


def test_score_is_capped_at_100_but_reasons_still_show_everything():
    big = make_incident(n=100, entity="8.8.8.8", targets=("root",), span_seconds=36000,
                        evidence={"compromise": True})
    scan = make_incident(entity="8.8.8.8", atype=AlertType.PORT_SCAN, targets=("web",))
    score_incidents([big, scan])
    assert big.score == 100
    assert sum(points(big)) == 120


def test_reasons_add_up_to_the_score():
    inc = make_incident(n=20, entity="8.8.8.8", targets=("root",), span_seconds=3600)
    score_incidents([inc])
    assert sum(points(inc)) == inc.score


def test_custom_enricher_and_none_results():
    inc = make_incident()
    score_incidents([inc], enrichers=[lambda i: (15, "custom signal"), lambda i: None,
                                      lambda i: (0, "ignored")])
    assert inc.score == 25
    assert "+15 custom signal" in inc.reasons
    assert len(inc.reasons) == 2


def test_blocklist_adds_points_case_insensitively():
    inc = make_incident(entity="Evil.Example")
    score_incidents([inc], enrichers=[blocklist_enricher(["evil.example"])])
    assert inc.score == 40


def test_allowlist_reduces_but_never_below_zero():
    inc = make_incident(entity="10.0.0.99")
    score_incidents([inc], enrichers=[allowlist_enricher(["10.0.0.99"])])
    assert inc.score == 0
    assert inc.severity == Severity.LOW


def test_incidents_are_returned_ranked():
    low = make_incident(entity="10.0.0.1")
    high = make_incident(entity="10.0.0.2", evidence={"compromise": True})
    ranked = score_incidents([low, high])
    assert ranked[0] is high and ranked[1] is low


def test_ties_are_broken_by_alert_count():
    few = make_incident(n=3, entity="10.0.0.1")
    many = make_incident(n=4, entity="10.0.0.2")
    ranked = score_incidents([few, many])
    assert ranked[0].score == ranked[1].score
    assert ranked[0] is many


def test_summary_mentions_source_severity_and_next_step():
    inc = make_incident(entity="8.8.8.8", targets=("root",))
    score_incidents([inc])
    assert "8.8.8.8" in inc.summary
    assert inc.severity.value.upper() in inc.summary
    assert "Suggested next step" in inc.summary

from datetime import datetime, timedelta, timezone

from alertsift.grouping import deduplicate, group_alerts, reduction_stats
from alertsift.schema import Alert, AlertType

T0 = datetime(2026, 10, 9, 10, 0, tzinfo=timezone.utc)


def alert(minutes=0, entity="10.0.0.5", target="root", atype=AlertType.AUTH_ATTACK,
          raw=None, seconds=0):
    return Alert(
        alert_type=atype,
        timestamp=T0 + timedelta(minutes=minutes, seconds=seconds),
        source="test",
        entity=entity,
        target=target,
        raw=raw if raw is not None else f"line-{minutes}-{seconds}-{entity}-{target}",
    )


def test_exact_duplicates_are_removed():
    a = alert(0)
    assert len(deduplicate([a, alert(0), a])) == 1


def test_distinct_events_in_same_second_are_both_kept():
    # Different raw lines -> two real failed logins, both must count.
    a = alert(0, raw="failed login attempt #1")
    b = alert(0, raw="failed login attempt #2")
    assert len(deduplicate([a, b])) == 2


def test_many_alerts_from_one_entity_become_one_incident():
    alerts = [alert(minutes=m // 4, seconds=(m % 4) * 15) for m in range(40)]
    incidents = group_alerts(alerts)
    assert len(incidents) == 1
    assert incidents[0].count == 40


def test_different_entities_make_separate_incidents():
    incidents = group_alerts([alert(0, entity="10.0.0.5"), alert(1, entity="10.0.0.9")])
    assert len(incidents) == 2


def test_entity_matching_ignores_case_and_whitespace():
    incidents = group_alerts([
        alert(0, entity="Evil@Example.com", atype=AlertType.PHISHING),
        alert(5, entity=" evil@example.com ", atype=AlertType.PHISHING),
    ])
    assert len(incidents) == 1


def test_quiet_gap_longer_than_window_splits_the_incident():
    incidents = group_alerts([alert(0), alert(5), alert(120)])
    assert [i.count for i in incidents] == [2, 1]


def test_long_continuous_attack_stays_one_incident():
    # 2 hours of alerts every 10 minutes: each gap < 15 min window.
    incidents = group_alerts([alert(m) for m in range(0, 121, 10)])
    assert len(incidents) == 1


def test_window_is_configurable_per_type():
    alerts = [alert(0), alert(30)]
    assert len(group_alerts(alerts)) == 2
    wide = {AlertType.AUTH_ATTACK: timedelta(hours=1)}
    assert len(group_alerts(alerts, windows=wide)) == 1


def test_same_entity_different_attack_types_stay_separate():
    incidents = group_alerts([
        alert(0, atype=AlertType.AUTH_ATTACK),
        alert(1, atype=AlertType.PORT_SCAN),
    ])
    assert {i.alert_type for i in incidents} == {AlertType.AUTH_ATTACK, AlertType.PORT_SCAN}


def test_unsorted_input_is_handled():
    incidents = group_alerts([alert(10), alert(0), alert(5)])
    assert len(incidents) == 1
    assert incidents[0].first_seen == T0


def test_empty_input():
    assert group_alerts([]) == []
    assert reduction_stats(0, [])["reduction_pct"] == 0


def test_reduction_stats():
    alerts = [alert(m % 5, raw=f"r{m}") for m in range(50)] + [alert(0, raw="r0")]
    incidents = group_alerts(alerts)
    stats = reduction_stats(len(alerts), incidents)
    assert stats["raw_alerts"] == 51
    assert stats["duplicates_removed"] == 1
    assert stats["incidents"] == 1
    assert stats["reduction_pct"] == 98

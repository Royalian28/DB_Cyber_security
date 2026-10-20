"""Grouping and de-duplication: many raw alerts -> few incidents.

Two steps:
1. De-duplicate: drop alerts that are exact repeats (same log line ingested
   twice, or reported by two sources).
2. Group: alerts of the same type from the same entity belong to one incident
   as long as there is no quiet gap longer than the type's time window.
   A long, continuous attack stays one incident; the same attacker coming
   back hours later starts a new one.
"""
from __future__ import annotations

from collections import defaultdict
from datetime import timedelta
from typing import Dict, Iterable, List, Optional, Tuple

from .schema import Alert, AlertType, Incident

# Quiet gap that ends an incident. Tunable per attack type.
DEFAULT_WINDOWS: Dict[AlertType, timedelta] = {
    AlertType.AUTH_ATTACK: timedelta(minutes=15),
    AlertType.PORT_SCAN: timedelta(minutes=15),
    AlertType.WEB_ATTACK: timedelta(minutes=15),
    AlertType.PHISHING: timedelta(hours=24),
    AlertType.C2_BEACONING: timedelta(hours=6),
}


def _entity_key(alert: Alert) -> str:
    return alert.entity.strip().lower()


def _dedup_key(alert: Alert) -> Tuple:
    # The raw log line is part of the key on purpose: two different failed
    # logins in the same second are two real events and must both be counted.
    return (
        alert.alert_type,
        _entity_key(alert),
        alert.target,
        alert.timestamp,
        alert.raw or alert.description,
    )


def deduplicate(alerts: Iterable[Alert]) -> List[Alert]:
    """Remove exact duplicate alerts, keeping the first occurrence."""
    seen = set()
    unique: List[Alert] = []
    for alert in alerts:
        key = _dedup_key(alert)
        if key in seen:
            continue
        seen.add(key)
        unique.append(alert)
    return unique


def _make_incident(alert_type: AlertType, alerts: List[Alert]) -> Incident:
    return Incident(
        alert_type=alert_type,
        entity=alerts[0].entity.strip(),
        alerts=list(alerts),
    )


def group_alerts(
    alerts: Iterable[Alert],
    windows: Optional[Dict[AlertType, timedelta]] = None,
) -> List[Incident]:
    """Turn raw alerts into incidents, oldest first."""
    window_for = {**DEFAULT_WINDOWS, **(windows or {})}

    buckets: Dict[Tuple[AlertType, str], List[Alert]] = defaultdict(list)
    for alert in deduplicate(alerts):
        buckets[(alert.alert_type, _entity_key(alert))].append(alert)

    incidents: List[Incident] = []
    for (alert_type, _), items in buckets.items():
        items.sort(key=lambda a: a.timestamp)
        window = window_for[alert_type]

        current = [items[0]]
        for previous, alert in zip(items, items[1:]):
            if alert.timestamp - previous.timestamp > window:
                incidents.append(_make_incident(alert_type, current))
                current = [alert]
            else:
                current.append(alert)
        incidents.append(_make_incident(alert_type, current))

    incidents.sort(key=lambda i: (i.first_seen, i.alert_type.value, i.entity))
    return incidents


def reduction_stats(raw_count: int, incidents: List[Incident]) -> Dict[str, float]:
    """How much analyst workload the grouping removed."""
    unique = sum(i.count for i in incidents)
    pct = round(100 * (1 - len(incidents) / raw_count)) if raw_count else 0
    return {
        "raw_alerts": raw_count,
        "duplicates_removed": raw_count - unique,
        "incidents": len(incidents),
        "reduction_pct": pct,
    }

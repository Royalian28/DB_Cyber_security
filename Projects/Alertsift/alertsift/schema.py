"""Common data model.

Every detector converts its own log format into `Alert` objects. Everything
after that (grouping, scoring, reporting) only ever sees `Alert` and
`Incident`, so adding a new attack type never touches the core engine.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Set


class AlertType(str, Enum):
    AUTH_ATTACK = "auth_attack"
    PORT_SCAN = "port_scan"
    WEB_ATTACK = "web_attack"
    PHISHING = "phishing"
    C2_BEACONING = "c2_beaconing"


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


def to_utc(dt: datetime) -> datetime:
    """Normalise any datetime to timezone-aware UTC.

    Naive datetimes are assumed to already be UTC. Logs from different
    sources use different timezones, so everything is compared in UTC.
    """
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


@dataclass
class Alert:
    """One suspicious event or pattern found by a detector."""

    alert_type: AlertType
    timestamp: datetime
    source: str                 # which log/detector produced it, e.g. "linux_auth"
    entity: str                 # the actor: attacker IP, sender address, client IP...
    target: str = ""            # the victim: user, host, URL...
    description: str = ""
    evidence: Dict[str, Any] = field(default_factory=dict)
    mitre: str = ""             # MITRE ATT&CK technique id, e.g. "T1110"
    raw: str = ""               # original log line, kept for the analyst

    def __post_init__(self) -> None:
        self.timestamp = to_utc(self.timestamp)


@dataclass
class Incident:
    """A group of related alerts, scored and ready for an analyst."""

    alert_type: AlertType
    entity: str
    alerts: List[Alert] = field(default_factory=list)
    score: int = 0
    reasons: List[str] = field(default_factory=list)   # why the score is what it is
    severity: Severity = Severity.LOW
    summary: str = ""

    @property
    def first_seen(self) -> datetime:
        return min(a.timestamp for a in self.alerts)

    @property
    def last_seen(self) -> datetime:
        return max(a.timestamp for a in self.alerts)

    @property
    def count(self) -> int:
        return len(self.alerts)

    @property
    def targets(self) -> Set[str]:
        return {a.target for a in self.alerts if a.target}

    @property
    def id(self) -> str:
        """Stable short id, so the same incident gets the same id every run."""
        key = f"{self.alert_type.value}|{self.entity}|{self.first_seen.isoformat()}"
        return "INC-" + hashlib.sha1(key.encode()).hexdigest()[:8].upper()

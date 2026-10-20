"""Explainable risk scoring.

Every point in an incident's score comes with a plain-English reason, so an
analyst can see *why* something ranked high and overrule it. The weights are
heuristic starting points, meant to be tuned against real data.

Evidence contract: detectors may set these keys in `Alert.evidence`:
    compromise (bool)  the alert indicates the attacker may have succeeded
                       (e.g. a successful login after many failures, or an
                       active C2 beacon).
"""
from __future__ import annotations

import ipaddress
from collections import defaultdict
from typing import Callable, Dict, Iterable, List, Optional, Sequence, Set, Tuple

from .schema import AlertType, Incident, Severity

Part = Tuple[int, str]                       # (points, reason)
Enricher = Callable[[Incident], Optional[Part]]

BASELINE: Dict[AlertType, int] = {
    AlertType.AUTH_ATTACK: 10,
    AlertType.PORT_SCAN: 5,
    AlertType.WEB_ATTACK: 10,
    AlertType.PHISHING: 15,
    AlertType.C2_BEACONING: 25,
}

LABELS: Dict[AlertType, str] = {
    AlertType.AUTH_ATTACK: "Authentication attack",
    AlertType.PORT_SCAN: "Port scan / reconnaissance",
    AlertType.WEB_ATTACK: "Web application attack",
    AlertType.PHISHING: "Phishing email campaign",
    AlertType.C2_BEACONING: "Possible C2 beaconing",
}

NEXT_STEPS: Dict[AlertType, str] = {
    AlertType.AUTH_ATTACK: (
        "Check whether any login from this source succeeded; if so, treat the account as "
        "compromised and reset credentials. Block the source if it is external."
    ),
    AlertType.PORT_SCAN: (
        "Confirm the source is not an authorized scanner. If it is unknown, block it and "
        "review which scanned services are exposed."
    ),
    AlertType.WEB_ATTACK: (
        "Review web server logs for this source, consider blocking it at the WAF/firewall, "
        "and check whether the targeted endpoints are vulnerable to the attempted attack."
    ),
    AlertType.PHISHING: (
        "Quarantine the messages, search all mailboxes for the same sender/URL, and check "
        "whether any recipient clicked or entered credentials."
    ),
    AlertType.C2_BEACONING: (
        "Isolate the host, preserve network/memory evidence, block the destination, and "
        "hunt for the same indicator on other hosts."
    ),
}

PRIVILEGED_ACCOUNTS: Set[str] = {"root", "administrator", "admin", "system"}


def severity_for(score: int) -> Severity:
    if score >= 90:
        return Severity.CRITICAL
    if score >= 60:
        return Severity.HIGH
    if score >= 30:
        return Severity.MEDIUM
    return Severity.LOW


def _is_external_ip(value: str) -> bool:
    try:
        return ipaddress.ip_address(value.strip()).is_global
    except ValueError:
        return False


def _fmt_duration(seconds: float) -> str:
    if seconds < 60:
        return f"{int(seconds)}s"
    if seconds < 3600:
        return f"{seconds / 60:.0f} min"
    return f"{seconds / 3600:.1f} h"


def _builtin_rules(inc: Incident, types_by_entity: Dict[str, Set[AlertType]]) -> List[Part]:
    parts: List[Part] = [(BASELINE[inc.alert_type], f"baseline for {inc.alert_type.value}")]
    duration = (inc.last_seen - inc.first_seen).total_seconds()
    n = inc.count

    # Volume
    if n >= 100:
        parts.append((30, f"{n} alerts in {_fmt_duration(duration)} (very high volume)"))
    elif n >= 20:
        parts.append((20, f"{n} alerts in {_fmt_duration(duration)} (high volume)"))
    elif n >= 5:
        parts.append((10, f"{n} alerts in {_fmt_duration(duration)} (repeated activity)"))

    # Burst rate
    rate = n / max(duration / 60, 1.0)
    if n >= 10 and rate >= 10:
        parts.append((15, f"burst of about {rate:.0f} alerts per minute (likely automated)"))

    # Spread across targets
    targets = len(inc.targets)
    if targets >= 10:
        parts.append((20, f"touched {targets} different targets (wide spread)"))
    elif targets >= 3:
        parts.append((10, f"touched {targets} different targets"))

    # Who is it coming from / going to
    if _is_external_ip(inc.entity):
        parts.append((10, "source is an external (public) IP address"))
    if {t.strip().lower() for t in inc.targets} & PRIVILEGED_ACCOUNTS:
        parts.append((10, "a privileged account was targeted"))

    # Detector says the attacker may have won
    if any(a.evidence.get("compromise") for a in inc.alerts):
        parts.append((40, "indicator of successful compromise (e.g. login success after failures, active beacon)"))

    # Same source involved in other attack types = multi-stage activity
    others = types_by_entity[inc.entity.strip().lower()] - {inc.alert_type}
    if others:
        names = ", ".join(sorted(t.value for t in others))
        parts.append((20, f"same source also seen in: {names} (possible multi-stage attack)"))

    return parts


def _targets_text(inc: Incident) -> str:
    targets = sorted(inc.targets)
    if not targets:
        return "unspecified targets"
    if len(targets) <= 3:
        return ", ".join(targets)
    return f"{len(targets)} targets (e.g. {', '.join(targets[:3])})"


def _summary(inc: Incident, parts: Sequence[Part]) -> str:
    why = [text for pts, text in sorted(parts[1:], key=lambda p: -p[0]) if pts > 0][:3]
    why_text = "; ".join(why) if why else "low-volume activity"
    return (
        f"{LABELS[inc.alert_type]} from {inc.entity}: {inc.count} alert(s) against "
        f"{_targets_text(inc)} between {inc.first_seen:%Y-%m-%d %H:%M} and "
        f"{inc.last_seen:%Y-%m-%d %H:%M} UTC. Severity {inc.severity.value.upper()} "
        f"(score {inc.score}). Main factors: {why_text}. "
        f"Suggested next step: {NEXT_STEPS[inc.alert_type]}"
    )


def score_incidents(
    incidents: Iterable[Incident],
    enrichers: Sequence[Enricher] = (),
) -> List[Incident]:
    """Score every incident in place and return them ranked, highest risk first.

    Pass one batch (for example one day of alerts): the multi-stage check
    compares incidents within the batch you give it.
    """
    incidents = list(incidents)
    types_by_entity: Dict[str, Set[AlertType]] = defaultdict(set)
    for inc in incidents:
        types_by_entity[inc.entity.strip().lower()].add(inc.alert_type)

    for inc in incidents:
        parts = _builtin_rules(inc, types_by_entity)
        for enrich in enrichers:
            result = enrich(inc)
            if result and result[0]:
                parts.append(result)

        total = sum(points for points, _ in parts)
        inc.score = max(0, min(total, 100))
        inc.reasons = [f"{points:+d} {text}" for points, text in parts]
        inc.severity = severity_for(inc.score)
        inc.summary = _summary(inc, parts)

    return sorted(incidents, key=lambda i: (-i.score, -i.count, i.first_seen))


# ---- ready-made enrichers (offline, free) -------------------------------

def blocklist_enricher(entries: Iterable[str]) -> Enricher:
    """+30 when the source is on your own list of known-bad IPs/domains/senders."""
    bad = {e.strip().lower() for e in entries if e.strip()}

    def enrich(inc: Incident) -> Optional[Part]:
        if inc.entity.strip().lower() in bad:
            return 30, "source is on the local blocklist"
        return None

    return enrich


def allowlist_enricher(entries: Iterable[str]) -> Enricher:
    """-30 for known-good sources such as your authorized vulnerability scanner."""
    good = {e.strip().lower() for e in entries if e.strip()}

    def enrich(inc: Incident) -> Optional[Part]:
        if inc.entity.strip().lower() in good:
            return -30, "source is on the local allowlist (known scanner / admin host)"
        return None

    return enrich

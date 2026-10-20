"""Turn scored incidents into reports an analyst can read or paste into a ticket."""
from __future__ import annotations

import json
from typing import Dict, Optional, Sequence

from .schema import Incident


def _stats_line(stats: Optional[Dict]) -> str:
    if not stats:
        return ""
    alerts, incidents = stats["raw_alerts"], stats["incidents"]
    return (
        f"{alerts} raw alert{'' if alerts == 1 else 's'} -> {incidents} "
        f"incident{'' if incidents == 1 else 's'} ({stats['reduction_pct']}% less to review)"
    )


def to_text(incidents: Sequence[Incident], stats: Optional[Dict] = None, max_details: int = 5) -> str:
    lines = ["ALERTSIFT TRIAGE REPORT", "=" * 23]
    if stats:
        lines.append(_stats_line(stats))
    lines.append("")
    lines.append(f"{'#':<3} {'ID':<13} {'SEVERITY':<9} {'SCORE':>5}  {'TYPE':<13} {'SOURCE':<30} {'ALERTS':>6}")
    for rank, inc in enumerate(incidents, 1):
        lines.append(
            f"{rank:<3} {inc.id:<13} {inc.severity.value.upper():<9} {inc.score:>5}  "
            f"{inc.alert_type.value:<13} {inc.entity[:30]:<30} {inc.count:>6}"
        )
    for rank, inc in enumerate(incidents[:max_details], 1):
        lines += ["", f"[{rank}] {inc.id} - {inc.severity.value.upper()} (score {inc.score})",
                  f"    {inc.summary}", "    Why this score:"]
        lines += [f"      {reason}" for reason in inc.reasons]
    return "\n".join(lines)


def to_markdown(incidents: Sequence[Incident], stats: Optional[Dict] = None) -> str:
    lines = ["# AlertSift Triage Report", ""]
    if stats:
        lines += [f"**{_stats_line(stats)}**", ""]
    lines += [
        "| Rank | ID | Severity | Score | Type | Source | Alerts |",
        "|---|---|---|---|---|---|---|",
    ]
    for rank, inc in enumerate(incidents, 1):
        lines.append(
            f"| {rank} | {inc.id} | {inc.severity.value.upper()} | {inc.score} | "
            f"{inc.alert_type.value} | {inc.entity} | {inc.count} |"
        )
    for inc in incidents:
        lines += ["", f"### {inc.id} - {inc.severity.value.upper()} (score {inc.score})", "",
                  inc.summary, "", "Why this score:"]
        lines += [f"- {reason}" for reason in inc.reasons]
    return "\n".join(lines) + "\n"


def to_json(incidents: Sequence[Incident], stats: Optional[Dict] = None) -> str:
    payload = {
        "stats": stats or {},
        "incidents": [
            {
                "id": inc.id,
                "type": inc.alert_type.value,
                "source": inc.entity,
                "severity": inc.severity.value,
                "score": inc.score,
                "alert_count": inc.count,
                "first_seen": inc.first_seen.isoformat(),
                "last_seen": inc.last_seen.isoformat(),
                "targets": sorted(inc.targets),
                "reasons": inc.reasons,
                "summary": inc.summary,
            }
            for inc in incidents
        ],
    }
    return json.dumps(payload, indent=2)

"""Use AlertSift as a Python library: python examples/library_usage.py"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from alertsift.detectors import get_detector                      # noqa: E402
from alertsift.grouping import group_alerts, reduction_stats      # noqa: E402
from alertsift.report import to_text                              # noqa: E402
from alertsift.scoring import allowlist_enricher, score_incidents  # noqa: E402

logs = ROOT / "sample_logs"

alerts = []
alerts += get_detector("auth", year=2026).detect(str(logs / "auth.log"))
alerts += get_detector("web").detect(str(logs / "access.log"))
alerts = list(alerts)

incidents = group_alerts(alerts)
stats = reduction_stats(len(alerts), incidents)
ranked = score_incidents(incidents, enrichers=[allowlist_enricher(["10.0.0.9"])])

print(to_text(ranked, stats, max_details=1))

"""Command-line interface: `alertsift --auth auth.log --web access.log ...`"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
from typing import List, Optional, Sequence

from . import __version__
from .detectors import available, describe, get_detector
from .grouping import group_alerts, reduction_stats
from .report import to_json, to_markdown, to_text
from .schema import Alert, Severity
from .scoring import allowlist_enricher, blocklist_enricher, score_incidents

_SEVERITY_ORDER = [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]

EXAMPLES = """\
examples:
  alertsift --auth sample_logs/auth.log --web sample_logs/access.log
  alertsift --auth sample_logs/auth.log --portscan sample_logs/firewall.log --format markdown -o report.md
  alertsift --phishing sample_logs/emails --c2 sample_logs/dns.csv --format json
  alertsift --auth /var/log/auth.log --allowlist my_scanners.txt --fail-on high
"""


def _read_list(path: str) -> List[str]:
    entries = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            entries.append(line)
    return entries


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="alertsift",
        description="Explainable security alert triage: de-duplicate, group, score and rank alerts "
                    "from authentication, firewall, web, email and DNS logs.",
        epilog=EXAMPLES,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    inputs = parser.add_argument_group("inputs (give at least one; each takes one or more files/folders)")
    for name, text in describe().items():
        inputs.add_argument(f"--{name}", nargs="+", metavar="PATH", help=text)

    output = parser.add_argument_group("output")
    output.add_argument("--format", choices=["text", "markdown", "json"], default="text")
    output.add_argument("-o", "--output", metavar="FILE", help="write the report to a file instead of printing it")
    output.add_argument("--max-details", type=int, default=5, metavar="N",
                        help="incidents to explain in detail in the text report (default 5)")

    tuning = parser.add_argument_group("tuning")
    tuning.add_argument("--allowlist", metavar="FILE",
                        help="known-good sources (one per line, # comments allowed); lowers their score")
    tuning.add_argument("--blocklist", metavar="FILE",
                        help="known-bad sources (one per line); raises their score")
    tuning.add_argument("--year", type=int, help="year for syslog lines that have no year (default: current)")
    tuning.add_argument("--fail-on", choices=[s.value for s in _SEVERITY_ORDER], metavar="SEVERITY",
                        help="exit with code 1 if any incident is at least this severe (low|medium|high|critical)")
    parser.add_argument("--version", action="version", version=f"alertsift {__version__}")
    return parser


def _use_utf8() -> None:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")   # type: ignore[attr-defined]
        except (AttributeError, ValueError, OSError):
            pass


def main(argv: Optional[Sequence[str]] = None) -> int:
    _use_utf8()
    parser = build_parser()
    args = parser.parse_args(argv)

    chosen = {name: getattr(args, name) for name in available() if getattr(args, name)}
    if not chosen:
        parser.error("give at least one input, e.g. --auth /var/log/auth.log")

    alerts: List[Alert] = []
    try:
        for name, paths in chosen.items():
            detector = get_detector(name, year=args.year)
            for path in paths:
                alerts.extend(detector.detect(path))

        enrichers = []
        if args.allowlist:
            enrichers.append(allowlist_enricher(_read_list(args.allowlist)))
        if args.blocklist:
            enrichers.append(blocklist_enricher(_read_list(args.blocklist)))
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    incidents = group_alerts(alerts)
    stats = reduction_stats(len(alerts), incidents)
    ranked = score_incidents(incidents, enrichers)

    if args.format == "json":
        report = to_json(ranked, stats)
    elif args.format == "markdown":
        report = to_markdown(ranked, stats)
    else:
        report = to_text(ranked, stats, max_details=args.max_details)

    if args.output:
        out = Path(args.output)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(report, encoding="utf-8")
        print(f"Wrote {out} ({len(ranked)} incidents from {len(alerts)} alerts)")
    else:
        try:
            print(report)
            sys.stdout.flush()
        except BrokenPipeError:            # e.g. `alertsift ... | head`: stop quietly
            os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
            return 0

    if args.fail_on:
        threshold = _SEVERITY_ORDER.index(Severity(args.fail_on))
        if any(_SEVERITY_ORDER.index(i.severity) >= threshold for i in ranked):
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""C2 beaconing: hosts that contact the same destination at regular intervals.

Input: a CSV of DNS queries / proxy / flow records with a time, a source and a
destination column. Export from Splunk with:  ... | table _time src dest
Recognised column names are listed below.

A (source, destination) pair is flagged when it has at least `min_events`
contacts and at least `min_regular` of the gaps between them are within
`tolerance` of the median gap (so jitter is allowed). Software that
legitimately phones home on a timer (update checks, agents, NTP) looks the same,
so common benign domains are ignored by default and you can pass your own.
"""
from __future__ import annotations

import csv
import statistics
from collections import defaultdict
from datetime import datetime, timezone
from typing import Dict, Iterator, List, Optional, Sequence, Tuple

from ..schema import Alert, AlertType
from .base import Detector, register
from .util import iter_paths, parse_timestamp

DEFAULT_IGNORE = ("ntp.org", "windowsupdate.com", "msftconnecttest.com", "windows.com",
                  "microsoft.com", "apple.com", "google.com", "googleapis.com", "gstatic.com",
                  "arpa", "local", "localhost")

_TIME = ("timestamp", "_time", "time", "ts")
_SRC = ("src", "src_ip", "source", "client", "client_ip", "host")
_DST = ("dst", "dest", "dest_ip", "dst_ip", "destination", "query", "domain", "dst_domain")


def _find(fieldnames: Sequence[str], aliases: Sequence[str]) -> Optional[str]:
    for alias in aliases:
        if alias in fieldnames:
            return alias
    return None


@register
class BeaconDetector(Detector):
    name = "c2"
    alert_type = AlertType.C2_BEACONING
    description = "Regular-interval beaconing in a DNS/proxy/flow CSV (columns: time, src, dst)"

    def __init__(self, min_events: int = 10, tolerance: float = 0.25, min_regular: float = 0.8,
                 min_interval: float = 2.0, ignore_suffixes: Sequence[str] = DEFAULT_IGNORE):
        self.min_events = min_events
        self.tolerance = tolerance
        self.min_regular = min_regular
        self.min_interval = min_interval
        self.ignore_suffixes = tuple(s.lower().lstrip(".") for s in ignore_suffixes)

    def _ignored(self, destination: str) -> bool:
        dest = destination.lower().rstrip(".")
        return any(dest == s or dest.endswith("." + s) for s in self.ignore_suffixes)

    def _read(self, path) -> Iterator[Tuple[str, str, datetime]]:
        with open(path, "r", encoding="utf-8", errors="replace", newline="") as handle:
            reader = csv.DictReader(handle)
            if not reader.fieldnames:
                return
            reader.fieldnames = [name.strip().lower() for name in reader.fieldnames]
            t_col, s_col, d_col = (_find(reader.fieldnames, a) for a in (_TIME, _SRC, _DST))
            if not (t_col and s_col and d_col):
                raise ValueError(
                    f"{path}: need a time, source and destination column "
                    f"(found: {', '.join(reader.fieldnames)})")
            for row in reader:
                ts = parse_timestamp(row.get(t_col, ""))
                src, dst = (row.get(s_col) or "").strip(), (row.get(d_col) or "").strip()
                if ts and src and dst:
                    yield src, dst, ts

    def detect(self, path: str) -> Iterator[Alert]:
        series: Dict[Tuple[str, str], List[datetime]] = defaultdict(list)
        for file in iter_paths(path):
            for src, dst, ts in self._read(file):
                if not self._ignored(dst):
                    series[(src, dst)].append(ts)

        for (src, dst), stamps in sorted(series.items()):
            times = sorted({int(t.timestamp()) for t in stamps})   # collapse A/AAAA duplicates
            if len(times) < self.min_events:
                continue
            gaps = [b - a for a, b in zip(times, times[1:])]
            median = statistics.median(gaps)
            if median < self.min_interval:
                continue
            regular = sum(1 for g in gaps if abs(g - median) <= self.tolerance * median) / len(gaps)
            if regular < self.min_regular:
                continue
            for epoch in times:
                when = datetime.fromtimestamp(epoch, tz=timezone.utc)
                yield Alert(
                    AlertType.C2_BEACONING, when, "network", src, dst,
                    description=f"Possible beacon: {src} contacts {dst} every ~{median:.0f}s ({regular:.0%} regular)",
                    evidence={"compromise": True, "median_interval_s": median,
                              "regularity": round(regular, 2), "events": len(times)},
                    mitre="T1071", raw=f"{src} -> {dst} at {when.isoformat()}",
                )

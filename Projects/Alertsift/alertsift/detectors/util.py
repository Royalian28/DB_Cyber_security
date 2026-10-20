"""Helpers shared by detectors: file walking, timestamps, syslog lines."""
from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator, Optional, Sequence, Tuple

from ..schema import to_utc


def iter_paths(path: str, suffixes: Optional[Sequence[str]] = None) -> Iterator[Path]:
    """Yield the file itself, or every file under a folder (sorted)."""
    root = Path(path)
    if not root.exists():
        raise FileNotFoundError(f"No such file or folder: {path}")
    if root.is_file():
        yield root
        return
    for item in sorted(root.rglob("*")):
        if item.is_file() and (not suffixes or item.suffix.lower() in suffixes):
            yield item


def read_lines(path: Path) -> Iterator[str]:
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            line = line.rstrip("\r\n")
            if line.strip():
                yield line


_TIME_FORMATS = (
    "%Y-%m-%d %H:%M:%S.%f",
    "%Y-%m-%d %H:%M:%S",
    "%m/%d/%Y %H:%M:%S",
    "%m/%d/%y %I:%M:%S %p",
    "%d/%b/%Y:%H:%M:%S %z",
)


def parse_timestamp(value: str) -> Optional[datetime]:
    """Best-effort parse of the timestamp styles found in common exports."""
    value = (value or "").strip()
    if not value:
        return None
    iso = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        return to_utc(datetime.fromisoformat(iso))
    except ValueError:
        pass
    for fmt in _TIME_FORMATS:
        try:
            return to_utc(datetime.strptime(value, fmt))
        except ValueError:
            continue
    try:
        return datetime.fromtimestamp(float(value), tz=timezone.utc)
    except (ValueError, OverflowError, OSError):
        return None


# Two syslog timestamp styles: ISO 8601 (modern rsyslog) and "Oct  9 10:00:01".
_ISO_LINE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}T[\d:.]+(?:[+-]\d{2}:\d{2}|Z)?)\s+(?P<host>\S+)\s+"
    r"(?P<proc>[^\s:\[]+)(?:\[\d+\])?:\s*(?P<msg>.*)$"
)
_CLASSIC_LINE = re.compile(
    r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+"
    r"(?P<proc>[^\s:\[]+)(?:\[\d+\])?:\s*(?P<msg>.*)$"
)


def split_syslog(line: str, year: int) -> Optional[Tuple[datetime, str, str, str]]:
    """Split a syslog line into (timestamp, host, process, message)."""
    match = _ISO_LINE.match(line)
    if match:
        ts = parse_timestamp(match.group("ts"))
    else:
        match = _CLASSIC_LINE.match(line)
        if not match:
            return None
        try:
            ts = to_utc(datetime.strptime(f"{year} {' '.join(match.group('ts').split())}",
                                          "%Y %b %d %H:%M:%S"))
        except ValueError:
            return None
    if ts is None:
        return None
    return ts, match.group("host"), match.group("proc"), match.group("msg")

"""Port scans / reconnaissance from firewall logs.

Inputs
    iptables / UFW kernel log lines  (SRC= DST= PROTO= DPT=)
    Windows Firewall log (pfirewall.log) DROP lines

A source is scanning when it touches at least `min_ports` distinct
destination ip:port pairs within `window_seconds`. Every blocked connection
inside such a burst becomes an alert. Only blocked traffic is read, so scans
against closed or filtered ports are what get caught.
"""
from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, Iterator, List, Optional, Tuple

from ..schema import Alert, AlertType
from .base import Detector, register
from .util import iter_paths, parse_timestamp, read_lines, split_syslog

_KV = re.compile(r"\b(SRC|DST|PROTO|DPT)=(\S+)")
_WIN_FW = re.compile(
    r"^(?P<d>\d{4}-\d{2}-\d{2})\s+(?P<t>\d{2}:\d{2}:\d{2})\s+(?P<action>DROP|ALLOW)\s+"
    r"(?P<proto>\S+)\s+(?P<src>\S+)\s+(?P<dst>\S+)\s+(?P<sport>\S+)\s+(?P<dport>\S+)"
)


@dataclass
class _Conn:
    ts: datetime
    src: str
    dst: str
    dport: str
    proto: str
    raw: str


@register
class PortScanDetector(Detector):
    name = "portscan"
    alert_type = AlertType.PORT_SCAN
    description = "Port scans in UFW/iptables or Windows Firewall logs (many distinct ports in a short time)"

    def __init__(self, min_ports: int = 10, window_seconds: int = 60, year: Optional[int] = None):
        self.min_ports = min_ports
        self.window = timedelta(seconds=window_seconds)
        self.year = year or datetime.now(timezone.utc).year

    def _parse(self, path: Path) -> Iterator[_Conn]:
        for line in read_lines(path):
            win = _WIN_FW.match(line)
            if win:
                if win.group("action") != "DROP" or not win.group("dport").isdigit():
                    continue
                ts = parse_timestamp(f"{win.group('d')} {win.group('t')}")
                if ts:
                    yield _Conn(ts, win.group("src"), win.group("dst"), win.group("dport"),
                                win.group("proto").upper(), line)
                continue

            if "SRC=" not in line or "DPT=" not in line or "ALLOW" in line:
                continue
            fields = dict(_KV.findall(line))
            parts = split_syslog(line, self.year)
            if parts and {"SRC", "DST", "DPT"} <= fields.keys():
                yield _Conn(parts[0], fields["SRC"], fields["DST"], fields["DPT"],
                            fields.get("PROTO", "?").upper(), line)

    def detect(self, path: str) -> Iterator[Alert]:
        by_source: Dict[str, List[_Conn]] = defaultdict(list)
        for file in iter_paths(path):
            for conn in self._parse(file):
                by_source[conn.src].append(conn)

        for src in sorted(by_source):
            conns = sorted(by_source[src], key=lambda c: c.ts)
            in_window: Dict[Tuple[str, str], int] = {}
            left, marked = 0, -1
            flagged: List[_Conn] = []

            for right, conn in enumerate(conns):
                key = (conn.dst, conn.dport)
                in_window[key] = in_window.get(key, 0) + 1
                while conn.ts - conns[left].ts > self.window:
                    old = (conns[left].dst, conns[left].dport)
                    in_window[old] -= 1
                    if in_window[old] == 0:
                        del in_window[old]
                    left += 1
                if len(in_window) >= self.min_ports:
                    flagged.extend(conns[max(left, marked + 1): right + 1])
                    marked = right

            for conn in flagged:
                yield Alert(
                    AlertType.PORT_SCAN, conn.ts, "firewall", src, conn.dst,
                    description=f"Blocked {conn.proto} connection to {conn.dst}:{conn.dport}, part of a scan",
                    evidence={"dst_port": conn.dport, "protocol": conn.proto},
                    mitre="T1046", raw=conn.raw,
                )

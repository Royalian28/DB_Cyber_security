"""Authentication attacks: brute force, password spraying, and a login that
succeeds after a run of failures.

Inputs
    Linux auth.log / secure (classic or ISO-8601 syslog timestamps)
    Windows Security events exported from Splunk as CSV (4624 / 4625)

Each failed login becomes one alert; the grouping step turns them into
incidents. A successful login that follows at least three recent failures from
the same source becomes a `compromise` alert.

Duplicate-avoidance: sshd writes both its own "Failed password" line and a PAM
"authentication failure" line for the same attempt, so PAM lines are only used
for services other than sshd.
"""
from __future__ import annotations

import csv
import re
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, Iterator, List, Optional

from ..schema import Alert, AlertType
from .base import Detector, register
from .util import iter_paths, parse_timestamp, read_lines, split_syslog

PRIOR_FAILURES_FOR_COMPROMISE = 3
FAILURE_WINDOW = timedelta(minutes=15)

_SSH_FAIL = re.compile(r"Failed [\w/-]+ for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+)")
_SSH_OK = re.compile(r"Accepted [\w/-]+ for (?P<user>\S+) from (?P<ip>\S+)")
_RHOST = re.compile(r"\brhost=(\S*)")
_USER = re.compile(r"\buser=(\S+)")
_SESSION_OPEN = re.compile(r"session opened for user (?P<user>[^\s(]+)(?:\(uid=\d+\))? by (?P<by>[^\s(]*)")
_LOCAL_LOGIN_PROCS = {"lightdm", "login", "su", "sudo", "gdm-password", "gdm", "sddm", "xdm"}

_WIN_TIME = ("_time", "time", "timestamp", "timecreated")
_WIN_CODE = ("eventcode", "event_id", "eventid", "id")
_WIN_USER = ("account_name", "targetusername", "user", "username")
_WIN_IP = ("source_network_address", "ipaddress", "src_ip", "src", "source_ip")
_WIN_HOST = ("host", "computername", "computer", "dest")
_WIN_LOGON_TYPE = ("logon_type", "logontype")
_WIN_IGNORED_ACCOUNTS = {"system", "local service", "network service", "anonymous logon"}
_NO_REMOTE = {"", "-", "::1", "127.0.0.1", "localhost"}


@dataclass
class _Event:
    ts: datetime
    kind: str          # "fail" or "ok"
    entity: str
    user: str
    service: str
    source: str
    raw: str


def _pick(row: Dict[str, str], keys) -> str:
    for key in keys:
        value = (row.get(key) or "").strip()
        if value:
            return value
    return ""


def _clean_account(value: str) -> str:
    tokens = [t for t in value.replace("\r", "\n").split() if t != "-"]
    return tokens[-1] if tokens else ""


def _ignored_account(name: str) -> bool:
    low = name.lower()
    return (not name or low.endswith("$") or low in _WIN_IGNORED_ACCOUNTS
            or low.startswith(("umfd-", "dwm-")))


@register
class AuthDetector(Detector):
    name = "auth"
    alert_type = AlertType.AUTH_ATTACK
    description = "Brute force / password spraying in Linux auth.log or Windows Security CSV (4624/4625)"

    def __init__(self, year: Optional[int] = None):
        # Classic syslog timestamps carry no year; ISO ones do.
        self.year = year or datetime.now(timezone.utc).year

    # ---- parsing -------------------------------------------------------
    def _parse_linux(self, path: Path) -> Iterator[_Event]:
        for line in read_lines(path):
            parts = split_syslog(line, self.year)
            if not parts:
                continue
            ts, host, proc, msg = parts

            if proc.startswith("sshd"):
                match = _SSH_FAIL.search(msg)
                if match:
                    yield _Event(ts, "fail", match.group("ip"), match.group("user"), "ssh", "linux_auth", line)
                    continue
                match = _SSH_OK.search(msg)
                if match:
                    yield _Event(ts, "ok", match.group("ip"), match.group("user"), "ssh", "linux_auth", line)
                    continue

            if "authentication failure" in msg and "pam_unix(sshd" not in msg:
                rhost = _RHOST.search(msg)
                user = _USER.search(msg)
                entity = (rhost.group(1).strip() if rhost else "") or host
                yield _Event(ts, "fail", entity, user.group(1) if user else "unknown", proc,
                             "linux_auth", line)
                continue

            session = _SESSION_OPEN.search(msg)
            if session and proc in _LOCAL_LOGIN_PROCS:
                who = session.group("by") if proc in ("sudo", "su") and session.group("by") \
                    else session.group("user")
                yield _Event(ts, "ok", host, who, proc, "linux_auth", line)

    def _parse_windows(self, path: Path) -> Iterator[_Event]:
        with open(path, "r", encoding="utf-8", errors="replace", newline="") as handle:
            reader = csv.DictReader(handle)
            if not reader.fieldnames:
                return
            reader.fieldnames = [name.strip().lower() for name in reader.fieldnames]
            for row in reader:
                code = _pick(row, _WIN_CODE)
                if code not in ("4624", "4625"):
                    continue
                ts = parse_timestamp(_pick(row, _WIN_TIME))
                user = _clean_account(_pick(row, _WIN_USER))
                if ts is None or _ignored_account(user):
                    continue
                if code == "4624" and _pick(row, _WIN_LOGON_TYPE) in ("0", "4", "5"):
                    continue          # system / batch / service logons are noise
                address = _clean_account(_pick(row, _WIN_IP))
                entity = address if address not in _NO_REMOTE else (_pick(row, _WIN_HOST) or "windows-host")
                yield _Event(ts, "fail" if code == "4625" else "ok", entity, user, "windows-logon",
                             "windows_security", ",".join(row.values() if row else ()))

    # ---- detection -----------------------------------------------------
    def detect(self, path: str) -> Iterator[Alert]:
        events: List[_Event] = []
        for file in iter_paths(path):
            if file.suffix.lower() == ".csv":
                events.extend(self._parse_windows(file))
            else:
                events.extend(self._parse_linux(file))
        events.sort(key=lambda e: e.ts)

        recent_failures: Dict[str, List[datetime]] = defaultdict(list)
        for ev in events:
            if ev.kind == "fail":
                recent_failures[ev.entity].append(ev.ts)
                yield Alert(
                    AlertType.AUTH_ATTACK, ev.ts, ev.source, ev.entity, ev.user,
                    description=f"Failed login for {ev.user} from {ev.entity} ({ev.service})",
                    evidence={"service": ev.service}, mitre="T1110", raw=ev.raw,
                )
                continue

            window = [t for t in recent_failures[ev.entity] if timedelta(0) <= ev.ts - t <= FAILURE_WINDOW]
            if len(window) >= PRIOR_FAILURES_FOR_COMPROMISE:
                yield Alert(
                    AlertType.AUTH_ATTACK, ev.ts, ev.source, ev.entity, ev.user,
                    description=(f"Successful login for {ev.user} from {ev.entity} after "
                                 f"{len(window)} recent failures ({ev.service})"),
                    evidence={"compromise": True, "prior_failures": len(window), "service": ev.service},
                    mitre="T1110", raw=ev.raw,
                )
                recent_failures[ev.entity] = []

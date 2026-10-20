"""Web application attacks in Apache / nginx access logs (combined format).

Signature-based: each request is URL-decoded (twice, to catch double
encoding) and checked for injection, XSS, path traversal and command
injection patterns, plus well-known scanner User-Agents. Categories are mapped
to the OWASP Top 10 (2021).

These are *indicators*, not proof: a matching request may have been blocked,
or may come from your own authorized scanner (use the allowlist for those).
"""
from __future__ import annotations

import re
from datetime import datetime
from typing import Iterator, List, Tuple
from urllib.parse import unquote_plus

from ..schema import Alert, AlertType, to_utc
from .base import Detector, register
from .util import iter_paths, read_lines

_ACCESS = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<ts>[^\]]+)\] "(?P<method>[A-Z]+) (?P<url>\S+)(?: HTTP/[\d.]+)?" '
    r'(?P<status>\d{3}) (?P<size>\S+)(?: "(?P<ref>[^"]*)" "(?P<ua>[^"]*)")?'
)

_SIGNATURES: List[Tuple[str, str, "re.Pattern[str]"]] = [
    ("sqli", "A03:2021 Injection", re.compile(
        r"\bunion\b\s+(?:all\s+)?select\b|\b(?:and|or)\b\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+"
        r"|'\s*or\s*'|\bsleep\s*\(\s*\d+|\bbenchmark\s*\(|\binformation_schema\b"
        r"|;\s*drop\s+table\b|\bxp_cmdshell\b|'\s*--", re.I)),
    ("xss", "A03:2021 Injection", re.compile(
        r"<\s*script\b|javascript\s*:|\bon(?:error|load|mouseover|focus|click)\s*="
        r"|<\s*svg\b[^>]*\bon\w+\s*=|document\.cookie|\balert\s*\(", re.I)),
    ("path_traversal", "A01:2021 Broken Access Control", re.compile(
        r"\.\./|\.\.\\|/etc/(?:passwd|shadow)|\bboot\.ini\b|windows/win\.ini|/proc/self/environ", re.I)),
    ("command_injection", "A03:2021 Injection", re.compile(
        r"(?:;|\|\||\||&&|`|\$\()\s*(?:cat|ls|id|whoami|uname|wget|curl|nc|bash|sh|powershell|cmd)\b"
        r"|/bin/(?:ba)?sh\b|cmd\.exe", re.I)),
]
_SCANNER_UA = re.compile(
    r"sqlmap|nikto|nmap scripting engine|dirbuster|gobuster|wfuzz|acunetix|nessus|havij|masscan|zgrab", re.I)


def _decode(text: str) -> str:
    for _ in range(2):
        decoded = unquote_plus(text)
        if decoded == text:
            break
        text = decoded
    return text


def classify(url: str, user_agent: str = "") -> Tuple[List[str], str]:
    """Return (categories, primary OWASP category) for a request."""
    decoded = _decode(url)
    categories, owasp = [], ""
    for category, mapping, pattern in _SIGNATURES:
        if pattern.search(decoded):
            categories.append(category)
            owasp = owasp or mapping
    if _SCANNER_UA.search(user_agent or ""):
        categories.append("automated_scanner")
    return categories, owasp


@register
class WebAttackDetector(Detector):
    name = "web"
    alert_type = AlertType.WEB_ATTACK
    description = "SQLi / XSS / path traversal / command injection / scanners in Apache or nginx access logs"

    def detect(self, path: str) -> Iterator[Alert]:
        for file in iter_paths(path):
            for line in read_lines(file):
                match = _ACCESS.match(line)
                if not match:
                    continue
                try:
                    ts = to_utc(datetime.strptime(match.group("ts"), "%d/%b/%Y:%H:%M:%S %z"))
                except ValueError:
                    continue
                categories, owasp = classify(match.group("url"), match.group("ua") or "")
                if not categories:
                    continue
                url_path = match.group("url").split("?", 1)[0]
                yield Alert(
                    AlertType.WEB_ATTACK, ts, "web_access", match.group("ip"), url_path,
                    description=f"{', '.join(categories)} attempt: {match.group('method')} {url_path}",
                    evidence={
                        "categories": categories,
                        "owasp": owasp,
                        "status": int(match.group("status")),
                        "method": match.group("method"),
                        "user_agent": match.group("ua") or "",
                    },
                    mitre="T1190", raw=line,
                )

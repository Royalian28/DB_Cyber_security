"""Phishing emails in .eml files.

Each message is scored on independent indicators (failed SPF/DKIM/DMARC,
mismatched Reply-To, brand impersonation, look-alike domains, deceptive
links, urgency language, risky attachments). Messages that reach `min_score`
become alerts; the sender is the entity, so a campaign from one sender groups
into a single incident.

Heuristics only: nothing here fetches URLs or opens attachments.
"""
from __future__ import annotations

import ipaddress
import re
from datetime import datetime, timezone
from email import message_from_binary_file, policy
from email.utils import parseaddr, parsedate_to_datetime
from pathlib import Path
from typing import Iterator, List, Optional, Set, Tuple
from urllib.parse import urlsplit

from ..schema import Alert, AlertType, to_utc
from .base import Detector, register
from .util import iter_paths

BRANDS = ("paypal", "microsoft", "office365", "amazon", "apple", "google", "netflix", "dhl", "fedex",
          "hdfc", "icici", "sbi", "paytm", "whatsapp", "facebook", "instagram", "linkedin",
          "dropbox", "docusign", "adobe")
URGENCY = ("urgent", "immediately", "verify your account", "account suspended", "suspended",
           "unusual sign-in", "unusual activity", "confirm your identity", "password expires",
           "within 24 hours", "action required", "click here", "final notice", "will be closed")
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly", "ow.ly", "rebrand.ly",
              "shorturl.at", "tiny.cc"}
RISKY_TLDS = {"zip", "top", "xyz", "click", "gq", "tk", "ml", "cf", "ga", "work", "loan"}
DOMAIN_KEYWORDS = {"secure", "login", "verify", "account", "support", "update", "billing", "service"}
DANGEROUS_EXT = {".exe", ".scr", ".js", ".jse", ".vbs", ".vbe", ".bat", ".cmd", ".ps1", ".hta", ".jar",
                 ".lnk", ".iso", ".msi", ".com", ".pif", ".wsf"}
MACRO_EXT = {".docm", ".xlsm", ".pptm"}
HTML_EXT = {".html", ".htm", ".shtml"}

_URL = re.compile(r"https?://[^\s<>\"')\]]+", re.I)
_ANCHOR = re.compile(r"<a\s[^>]*href=[\"']([^\"']+)[\"'][^>]*>(.*?)</a>", re.I | re.S)
_LEET = str.maketrans("013@5$", "oleass")


def _host(url: str) -> str:
    if "://" not in url:
        url = "http://" + url
    try:
        return (urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""


def _root(host: str) -> str:
    return ".".join(host.split(".")[-2:])


def _domain_of(address: str) -> str:
    return address.rsplit("@", 1)[-1].lower() if "@" in address else ""


def _body_parts(msg) -> Tuple[str, str]:
    plain, html = [], []
    for part in msg.walk():
        if part.get_content_maintype() != "text" or part.get_filename():
            continue
        try:
            content = part.get_content()
        except (LookupError, UnicodeDecodeError, KeyError):
            payload = part.get_payload(decode=True) or b""
            content = payload.decode("utf-8", errors="replace")
        (html if part.get_content_subtype() == "html" else plain).append(str(content))
    return "\n".join(plain), "\n".join(html)


def analyse_message(msg) -> Tuple[int, List[str]]:
    """Return (score, indicators) for one parsed email message."""
    score, found = 0, []

    def add(points: int, text: str) -> None:
        nonlocal score
        score += points
        found.append(f"+{points} {text}")

    display, address = parseaddr(str(msg.get("From", "")))
    sender_domain = _domain_of(address)

    # -- authentication results
    auth = " ".join(msg.get_all("Authentication-Results", []) or []).lower()
    spf_header = " ".join(msg.get_all("Received-SPF", []) or []).strip().lower()
    spf = re.search(r"\bspf=(\w+)", auth)
    spf_result = spf.group(1) if spf else (spf_header.split(" ")[0] if spf_header else "")
    if spf_result in ("fail", "softfail"):
        add(2, f"SPF {spf_result}")
    dkim = re.search(r"\bdkim=(\w+)", auth)
    if dkim and dkim.group(1) == "fail":
        add(2, "DKIM fail")
    dmarc = re.search(r"\bdmarc=(\w+)", auth)
    if dmarc and dmarc.group(1) == "fail":
        add(2, "DMARC fail")

    # -- header mismatches
    _, reply_to = parseaddr(str(msg.get("Reply-To", "")))
    if reply_to and _domain_of(reply_to) != sender_domain:
        add(2, f"Reply-To domain ({_domain_of(reply_to)}) differs from sender domain")
    _, return_path = parseaddr(str(msg.get("Return-Path", "")))
    if return_path and _domain_of(return_path) != sender_domain:
        add(1, "Return-Path domain differs from sender domain")

    # -- impersonation
    display_low = display.lower()
    for brand in BRANDS:
        if re.search(rf"\b{brand}\b", display_low) and brand not in sender_domain.replace("-", ""):
            add(2, f"display name claims '{brand}' but sender domain is {sender_domain}")
            break
    tokens = re.split(r"[.-]", sender_domain)
    for token in tokens:
        normalised = token.translate(_LEET)
        if normalised != token and normalised in BRANDS:
            add(3, f"look-alike domain: '{token}' imitates '{normalised}'")
            break
    if sender_domain.startswith("xn--") or ".xn--" in sender_domain:
        add(2, "punycode (internationalised) sender domain")
    if "-" in sender_domain and DOMAIN_KEYWORDS & set(tokens):
        add(1, "sender domain contains lure keywords (secure/login/verify...)")

    # -- content
    plain, html = _body_parts(msg)
    text = f"{msg.get('Subject', '')}\n{plain}\n{re.sub(r'<[^>]+>', ' ', html)}".lower()
    hits = sum(1 for phrase in URGENCY if phrase in text)
    if hits >= 3:
        add(2, f"{hits} urgency/pressure phrases")
    elif hits >= 1:
        add(1, f"{hits} urgency/pressure phrase(s)")

    urls: Set[str] = set(_URL.findall(plain + "\n" + html))
    hosts = {_host(u) for u in urls}
    if any(_is_ip(h) for h in hosts):
        add(2, "link points to a raw IP address")
    if hosts & SHORTENERS:
        add(1, "link uses a URL shortener")
    if any(h.split(".")[-1] in RISKY_TLDS for h in hosts if h):
        add(1, "link uses a high-abuse top-level domain")
    if any("@" in urlsplit(u).netloc for u in urls if "://" in u):
        add(2, "link contains '@' to disguise its real destination")
    if any(h.startswith("xn--") or ".xn--" in h for h in hosts):
        add(2, "link uses a punycode domain")
    for href, label in _ANCHOR.findall(html):
        shown = re.sub(r"<[^>]+>", "", label).strip()
        if re.fullmatch(r"(?:https?://)?[\w.-]+\.[a-z]{2,}(?:/\S*)?", shown, re.I):
            shown_host, real_host = _host(shown), _host(href)
            if shown_host and real_host and _root(shown_host) != _root(real_host):
                add(3, f"link text shows {shown_host} but goes to {real_host}")
                break

    # -- attachments
    for part in msg.walk():
        filename = (part.get_filename() or "").lower()
        if not filename:
            continue
        suffixes = Path(filename).suffixes
        ext = suffixes[-1] if suffixes else ""
        if len(suffixes) >= 2 and ext in DANGEROUS_EXT:
            add(3, f"double-extension executable attachment '{filename}'")
        elif ext in DANGEROUS_EXT:
            add(3, f"executable/script attachment '{filename}'")
        elif ext in MACRO_EXT:
            add(2, f"macro-enabled document '{filename}'")
        elif ext in HTML_EXT:
            add(2, f"HTML attachment '{filename}' (common credential-phish vehicle)")

    return score, found


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


@register
class PhishingDetector(Detector):
    name = "phishing"
    alert_type = AlertType.PHISHING
    description = "Suspicious emails in .eml files (auth failures, spoofing, deceptive links, risky attachments)"

    def __init__(self, min_score: int = 3):
        self.min_score = min_score

    def detect(self, path: str) -> Iterator[Alert]:
        for file in iter_paths(path, suffixes=(".eml",)):
            if file.suffix.lower() != ".eml":
                continue
            with open(file, "rb") as handle:
                msg = message_from_binary_file(handle, policy=policy.default)
            score, indicators = analyse_message(msg)
            if score < self.min_score:
                continue

            _, sender = parseaddr(str(msg.get("From", "")))
            _, recipient = parseaddr(str(msg.get("To", "")))
            try:
                sent: Optional[datetime] = to_utc(parsedate_to_datetime(str(msg["Date"])))
            except (TypeError, ValueError):
                sent = datetime.fromtimestamp(file.stat().st_mtime, tz=timezone.utc)
            subject = str(msg.get("Subject", ""))
            yield Alert(
                AlertType.PHISHING, sent, "email", sender.lower() or "unknown-sender",
                recipient.lower() or "unknown-recipient",
                description=f"Suspicious email '{subject}' (indicator score {score}): " + "; ".join(indicators),
                evidence={"phish_score": score, "indicators": indicators, "subject": subject},
                mitre="T1566", raw=f"{file.name}: {subject}",
            )

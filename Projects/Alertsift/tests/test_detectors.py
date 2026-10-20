import textwrap
from email.message import EmailMessage
from email.utils import format_datetime
from datetime import datetime, timedelta, timezone

import pytest

from alertsift.detectors import available, get_detector
from alertsift.detectors.phishing import PhishingDetector
from alertsift.detectors.web import classify

T0 = datetime(2026, 10, 9, 10, 0, tzinfo=timezone.utc)


def write(tmp_path, name, text):
    path = tmp_path / name
    path.write_text(textwrap.dedent(text).lstrip("\n"), encoding="utf-8")
    return str(path)


def run(name, path, **options):
    return list(get_detector(name, **options).detect(path))


def test_all_five_detectors_are_registered():
    assert {"auth", "c2", "phishing", "portscan", "web"} <= set(available())


# ------------------------------------------------------------------ auth
def test_ssh_bruteforce_then_success_is_one_failure_per_attempt_plus_compromise(tmp_path):
    lines = []
    for i in range(5):
        lines.append(f"Oct  9 10:00:0{i} web01 sshd[10{i}]: Failed password for root from 1.2.3.4 port 22 ssh2")
        lines.append(f"Oct  9 10:00:0{i} web01 sshd[10{i}]: pam_unix(sshd:auth): authentication failure; "
                     f"logname= uid=0 euid=0 tty=ssh ruser= rhost=1.2.3.4  user=root")
    lines.append("Oct  9 10:00:30 web01 sshd[200]: Accepted password for root from 1.2.3.4 port 22 ssh2")
    path = write(tmp_path, "auth.log", "\n".join(lines))
    alerts = run("auth", path, year=2026)
    assert len(alerts) == 6                      # PAM duplicates are not double counted
    assert alerts[0].entity == "1.2.3.4" and alerts[0].target == "root"
    assert alerts[0].timestamp.year == 2026
    compromise = [a for a in alerts if a.evidence.get("compromise")]
    assert len(compromise) == 1 and compromise[0].evidence["prior_failures"] == 5


def test_invalid_user_attempts_are_counted_once(tmp_path):
    path = write(tmp_path, "auth.log", """
        Oct  9 10:00:00 h sshd[1]: Invalid user admin from 5.6.7.8 port 1
        Oct  9 10:00:00 h sshd[1]: Failed password for invalid user admin from 5.6.7.8 port 1 ssh2
    """)
    alerts = run("auth", path, year=2026)
    assert len(alerts) == 1 and alerts[0].target == "admin"


def test_iso_timestamps_with_offsets_are_converted_to_utc(tmp_path):
    path = write(tmp_path, "auth.log", """
        2026-09-19T01:59:06.951294-04:00 kali lightdm: pam_unix(lightdm:auth): authentication failure; logname= uid=0 euid=0 tty=:0 ruser= rhost=  user=kali
        2026-09-19T01:59:06.949228-04:00 kali unix_chkpwd[29364]: password check failed for user (kali)
    """)
    alerts = run("auth", path)
    assert len(alerts) == 1                       # the chkpwd helper line is not a second attempt
    assert alerts[0].entity == "kali" and alerts[0].target == "kali"
    assert alerts[0].timestamp.hour == 5          # 01:59 at UTC-4


def test_success_after_fewer_than_three_failures_is_not_flagged(tmp_path):
    path = write(tmp_path, "auth.log", """
        Oct  9 10:00:00 h sshd[1]: Failed password for bob from 1.1.1.1 port 1 ssh2
        Oct  9 10:00:05 h sshd[1]: Failed password for bob from 1.1.1.1 port 1 ssh2
        Oct  9 10:00:10 h sshd[2]: Accepted password for bob from 1.1.1.1 port 1 ssh2
    """)
    alerts = run("auth", path, year=2026)
    assert len(alerts) == 2 and not any(a.evidence.get("compromise") for a in alerts)


def test_old_failures_outside_the_window_do_not_count(tmp_path):
    path = write(tmp_path, "auth.log", """
        Oct  9 10:00:00 h sshd[1]: Failed password for bob from 1.1.1.1 port 1 ssh2
        Oct  9 10:00:05 h sshd[1]: Failed password for bob from 1.1.1.1 port 1 ssh2
        Oct  9 10:00:10 h sshd[1]: Failed password for bob from 1.1.1.1 port 1 ssh2
        Oct  9 11:30:00 h sshd[2]: Accepted password for bob from 1.1.1.1 port 1 ssh2
    """)
    assert not any(a.evidence.get("compromise") for a in run("auth", path, year=2026))


def test_sudo_success_is_attributed_to_the_invoking_user(tmp_path):
    lines = [f"Oct  9 10:00:0{i} kali sudo: pam_unix(sudo:auth): authentication failure; logname=kali uid=1000 "
             f"euid=0 tty=/dev/pts/1 ruser=kali rhost=  user=kali" for i in range(3)]
    lines.append("Oct  9 10:00:20 kali sudo: pam_unix(sudo:session): session opened for user root(uid=0) by kali(uid=1000)")
    alerts = run("auth", write(tmp_path, "auth.log", "\n".join(lines)), year=2026)
    compromise = [a for a in alerts if a.evidence.get("compromise")]
    assert len(compromise) == 1 and compromise[0].target == "kali"


def test_cron_sessions_are_ignored(tmp_path):
    path = write(tmp_path, "auth.log", """
        Oct  9 10:00:00 h CRON[1]: pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)
    """)
    assert run("auth", path, year=2026) == []


def test_windows_csv_detects_failures_and_compromise_and_ignores_noise(tmp_path):
    rows = ["_time,host,EventCode,Account_Name,Source_Network_Address,Logon_Type"]
    for i in range(4):
        rows.append(f"2026-10-09T12:00:0{i}+00:00,PC1,4625,Administrator,10.0.2.15,3")
    rows.append("2026-10-09T12:00:20+00:00,PC1,4624,Administrator,10.0.2.15,3")
    rows.append("2026-10-09T12:00:21+00:00,PC1,4624,SYSTEM,-,5")
    rows.append("2026-10-09T12:00:22+00:00,PC1,4624,PC1$,-,5")
    rows.append("2026-10-09T12:00:23+00:00,PC1,4688,Administrator,-,2")
    path = write(tmp_path, "win.csv", "\n".join(rows))
    alerts = run("auth", path)
    assert len(alerts) == 5
    assert alerts[0].entity == "10.0.2.15" and alerts[0].source == "windows_security"
    assert sum(1 for a in alerts if a.evidence.get("compromise")) == 1


# -------------------------------------------------------------- portscan
def ufw(second, port, src="9.9.9.9", dst="10.0.0.5"):
    return (f"Oct  9 10:00:{second:02d} fw kernel: [UFW BLOCK] IN=eth0 OUT= SRC={src} DST={dst} "
            f"LEN=44 PROTO=TCP SPT=4000 DPT={port} SYN")


def test_fast_scan_of_many_ports_is_flagged(tmp_path):
    path = write(tmp_path, "fw.log", "\n".join(ufw(i, 20 + i) for i in range(12)))
    alerts = run("portscan", path, year=2026)
    assert len(alerts) == 12
    assert {a.entity for a in alerts} == {"9.9.9.9"} and alerts[0].mitre == "T1046"


def test_few_ports_is_not_a_scan(tmp_path):
    path = write(tmp_path, "fw.log", "\n".join(ufw(i, 20 + i) for i in range(5)))
    assert run("portscan", path, year=2026) == []


def test_slow_scan_below_the_window_rate_is_not_flagged(tmp_path):
    lines = [f"Oct  9 10:{i // 6:02d}:{(i % 6) * 10:02d} fw kernel: [UFW BLOCK] SRC=9.9.9.9 DST=10.0.0.5 PROTO=TCP DPT={20 + i}"
             for i in range(12)]
    assert run("portscan", write(tmp_path, "fw.log", "\n".join(lines)), year=2026) == []


def test_hammering_one_port_is_not_a_port_scan(tmp_path):
    path = write(tmp_path, "fw.log", "\n".join(ufw(i, 22) for i in range(40)))
    assert run("portscan", path, year=2026) == []


def test_sources_are_evaluated_independently(tmp_path):
    lines = [ufw(i, 20 + i, src="1.1.1.1") for i in range(12)] + [ufw(i, 20 + i, src="2.2.2.2") for i in range(4)]
    alerts = run("portscan", write(tmp_path, "fw.log", "\n".join(lines)), year=2026)
    assert {a.entity for a in alerts} == {"1.1.1.1"}


def test_windows_firewall_drops_are_parsed(tmp_path):
    lines = ["#Version: 1.5"]
    lines += [f"2026-10-09 10:00:{i:02d} DROP TCP 10.0.2.15 10.0.2.4 4400{i} {i + 1} 44 S 1 0 1024 - - - RECEIVE"
              for i in range(15)]
    lines.append("2026-10-09 10:00:30 ALLOW TCP 10.0.2.15 10.0.2.4 44100 445 52 S 1 0 8192 - - - RECEIVE")
    lines.append("2026-10-09 10:00:31 DROP ICMP 10.0.2.15 10.0.2.4 - - 60 - - - - 8 0 - RECEIVE")
    alerts = run("portscan", write(tmp_path, "pfirewall.log", "\n".join(lines)))
    assert len(alerts) == 15 and alerts[0].entity == "10.0.2.15"


# ------------------------------------------------------------------- web
@pytest.mark.parametrize("url,category", [
    ("/search?q=%27+OR+1%3D1--", "sqli"),
    ("/item?id=1+UNION+SELECT+user,pass+FROM+users", "sqli"),
    ("/p?id=1;SELECT+SLEEP(5)", "sqli"),
    ("/s?q=<script>alert(1)</script>", "xss"),
    ("/s?q=%3Cimg+src%3Dx+onerror%3Dalert(1)%3E", "xss"),
    ("/dl?f=../../../../etc/passwd", "path_traversal"),
    ("/dl?f=..%252f..%252fetc%252fshadow", "path_traversal"),
    ("/ping?h=8.8.8.8;cat+/etc/passwd", "command_injection"),
])
def test_web_signatures(url, category):
    categories, _ = classify(url)
    assert category in categories


@pytest.mark.parametrize("url", [
    "/", "/products?cat=shoes&sort=asc", "/search?q=orange+juice", "/blog/how-to-sort-lists",
    "/profile?name=oreo&tag=organic",
])
def test_normal_requests_are_not_flagged(url):
    assert classify(url) == ([], "")


def test_scanner_user_agent_is_flagged_even_for_a_normal_url():
    categories, _ = classify("/products?id=1", "sqlmap/1.7.2#stable")
    assert categories == ["automated_scanner"]


def test_web_detector_reads_combined_log_and_maps_owasp(tmp_path):
    path = write(tmp_path, "access.log", """
        10.0.0.4 - - [09/Oct/2026:10:00:00 +0000] "GET /products HTTP/1.1" 200 500 "-" "Mozilla/5.0"
        6.6.6.6 - - [09/Oct/2026:10:00:05 +0000] "GET /s?q=%27+OR+1%3D1-- HTTP/1.1" 500 300 "-" "Mozilla/5.0"
        6.6.6.6 - - [09/Oct/2026:10:00:06 +0000] "GET /dl?f=../../etc/passwd HTTP/1.1" 200 300 "-" "Mozilla/5.0"
        this line is not a log line
    """)
    alerts = run("web", path)
    assert len(alerts) == 2
    assert alerts[0].entity == "6.6.6.6" and alerts[0].target == "/s"
    assert alerts[0].evidence["owasp"].startswith("A03:2021")
    assert alerts[1].evidence["owasp"].startswith("A01:2021")
    assert alerts[0].evidence["status"] == 500


# -------------------------------------------------------------- phishing
def make_eml(tmp_path, name, sender, subject, text, html=None, headers=None, attach=None):
    msg = EmailMessage()
    msg["From"], msg["To"], msg["Subject"] = sender, "victim@company.example", subject
    msg["Date"] = format_datetime(T0)
    for key, value in (headers or {}).items():
        msg[key] = value
    msg.set_content(text)
    if html:
        msg.add_alternative(html, subtype="html")
    if attach:
        msg.add_attachment(b"x", maintype="application", subtype="octet-stream", filename=attach)
    (tmp_path / name).write_bytes(bytes(msg))


def phish_headers():
    return {"Authentication-Results": "mx; spf=fail; dkim=none; dmarc=fail",
            "Reply-To": "help@other-domain.example"}


def test_obvious_phish_is_flagged_with_reasons(tmp_path):
    make_eml(tmp_path, "p.eml", '"PayPal Support" <billing@paypa1-secure.example>',
             "URGENT: account suspended, verify immediately",
             "Action required within 24 hours: http://45.9.148.20/login",
             html='<a href="http://45.9.148.20/login">www.paypal.com/verify</a>',
             headers=phish_headers(), attach="invoice.pdf.exe")
    alerts = run("phishing", str(tmp_path))
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.entity == "billing@paypa1-secure.example"
    joined = " | ".join(alert.evidence["indicators"])
    for expected in ("SPF fail", "DMARC fail", "Reply-To", "look-alike", "raw IP", "link text shows",
                     "double-extension", "urgency"):
        assert expected in joined, expected


def test_legitimate_email_is_not_flagged(tmp_path):
    make_eml(tmp_path, "ok.eml", "Priya <priya@company.example>", "Notes",
             "Notes are at https://github.com/org/repo",
             headers={"Authentication-Results": "mx; spf=pass; dkim=pass; dmarc=pass"})
    assert run("phishing", str(tmp_path)) == []


def test_html_attachment_and_macro_documents_score(tmp_path):
    make_eml(tmp_path, "h.eml", "Docs <docs@sharepoint-files.example>", "Shared document",
             "Please open the attached file.", attach="statement.html")
    make_eml(tmp_path, "m.eml", "Fin <fin@example.org>", "Invoice", "See attached.", attach="invoice.xlsm")
    alerts = PhishingDetector(min_score=2).detect(str(tmp_path))
    assert len(list(alerts)) == 2


def test_min_score_controls_sensitivity(tmp_path):
    make_eml(tmp_path, "w.eml", "A <a@example.org>", "Hello", "Please click here", headers=phish_headers())
    assert len(list(PhishingDetector(min_score=3).detect(str(tmp_path)))) == 1
    assert len(list(PhishingDetector(min_score=9).detect(str(tmp_path)))) == 0


def test_non_eml_files_are_skipped(tmp_path):
    (tmp_path / "notes.txt").write_text("hello")
    assert run("phishing", str(tmp_path)) == []


# -------------------------------------------------------------------- c2
def write_csv(tmp_path, rows, header="timestamp,src,dst"):
    path = tmp_path / "dns.csv"
    path.write_text(header + "\n" + "\n".join(rows) + "\n", encoding="utf-8")
    return str(path)


def beacon_rows(gaps, dst="update-check.example", src="10.0.0.23"):
    rows, t = [], T0
    for gap in gaps:
        rows.append(f"{t.isoformat()},{src},{dst}")
        t += timedelta(seconds=gap)
    return rows


def test_regular_beacon_is_flagged(tmp_path):
    alerts = run("c2", write_csv(tmp_path, beacon_rows([60] * 14)))
    assert len(alerts) == 14
    assert alerts[0].entity == "10.0.0.23" and alerts[0].target == "update-check.example"
    assert alerts[0].evidence["compromise"] is True
    assert alerts[0].evidence["median_interval_s"] == 60


def test_jitter_within_tolerance_is_still_flagged(tmp_path):
    gaps = [60, 63, 57, 61, 59, 64, 56, 60, 62, 58, 60, 61]
    assert run("c2", write_csv(tmp_path, beacon_rows(gaps)))


def test_irregular_traffic_is_not_flagged(tmp_path):
    gaps = [3, 140, 12, 300, 45, 7, 220, 90, 5, 180, 33, 400]
    assert run("c2", write_csv(tmp_path, beacon_rows(gaps))) == []


def test_too_few_events_are_not_flagged(tmp_path):
    assert run("c2", write_csv(tmp_path, beacon_rows([60] * 5))) == []


def test_default_ignore_list_skips_known_periodic_services(tmp_path):
    path = write_csv(tmp_path, beacon_rows([300] * 14, dst="time.windows.com"))
    assert run("c2", path) == []
    assert run("c2", path, ignore_suffixes=()) != []


def test_column_aliases_are_recognised(tmp_path):
    rows = [f"{t.isoformat()},10.0.0.9,evil.example" for t in
            [T0 + timedelta(seconds=30 * i) for i in range(12)]]
    path = write_csv(tmp_path, rows, header="_time,src_ip,query")
    assert len(run("c2", path)) == 12


def test_missing_columns_raise_a_helpful_error(tmp_path):
    path = write_csv(tmp_path, ["1,2"], header="foo,bar")
    with pytest.raises(ValueError, match="time, source and destination"):
        run("c2", path)


def test_missing_path_raises_file_not_found():
    with pytest.raises(FileNotFoundError):
        run("auth", "does/not/exist.log")

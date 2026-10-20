"""Generate the synthetic sample logs in ./sample_logs (no real data).

Run from the project root:  python tools/generate_sample_logs.py

Everything is invented. The two public IPs are only labels so the 'external
source' scoring rule fires; no traffic involves them.
"""
import random
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from email.utils import format_datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1] / "sample_logs"
ATTACKER = "45.33.32.156"        # public IP used as a label
WEB_ATTACKER = "93.184.216.34"   # public IP used as a label
T0 = datetime(2026, 10, 9, 10, 0, 0, tzinfo=timezone.utc)
random.seed(7)


def syslog(ts):
    return f"{ts:%b} {ts.day:>2} {ts:%H:%M:%S}"   # %e is not available on Windows


def write(name, text):
    ROOT.mkdir(exist_ok=True)
    (ROOT / name).write_text(text, encoding="utf-8", newline="\n")


def auth_log():
    lines = []
    host = "web01"
    # quiet background noise
    for i in range(6):
        t = T0 - timedelta(hours=2) + timedelta(minutes=17 * i)
        lines.append(f"{syslog(t)} {host} CRON[{2000 + i}]: pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)")
        lines.append(f"{syslog(t + timedelta(seconds=1))} {host} CRON[{2000 + i}]: pam_unix(cron:session): session closed for user root")
    # the attacker scans, then brute-forces root over SSH, then gets in
    users = ["root"] * 40 + ["admin", "ubuntu", "test", "oracle"] * 5
    random.shuffle(users)
    for i, user in enumerate(users):
        t = T0 + timedelta(seconds=5 * i)
        invalid = "" if user == "root" else "invalid user "
        lines.append(f"{syslog(t)} {host} sshd[{4000 + i}]: Failed password for {invalid}{user} from {ATTACKER} port {40000 + i} ssh2")
        lines.append(f"{syslog(t)} {host} sshd[{4000 + i}]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost={ATTACKER}  user={user}")
    t = T0 + timedelta(seconds=5 * len(users) + 3)
    lines.append(f"{syslog(t)} {host} sshd[5000]: Accepted password for root from {ATTACKER} port 51000 ssh2")
    # an admin fat-fingers a password locally, in the modern ISO timestamp style
    for i in range(3):
        t = T0 + timedelta(hours=1, seconds=20 * i)
        iso = t.strftime("%Y-%m-%dT%H:%M:%S.%f") + "+00:00"
        lines.append(f"{iso} kali unix_chkpwd[{6000 + i}]: password check failed for user (kali)")
        lines.append(f"{iso} kali lightdm: pam_unix(lightdm:auth): authentication failure; logname= uid=0 euid=0 tty=:0 ruser= rhost=  user=kali")
    t = T0 + timedelta(hours=1, seconds=75)
    iso = t.strftime("%Y-%m-%dT%H:%M:%S.%f") + "+00:00"
    lines.append(f"{iso} kali lightdm: pam_unix(lightdm:session): session opened for user kali(uid=1000) by kali(uid=0)")
    write("auth.log", "\n".join(lines) + "\n")


def firewall_logs():
    lines = []
    scan_start = T0 - timedelta(minutes=6)
    for i, port in enumerate(list(range(20, 70)) + [80, 443, 3306, 8080]):
        t = scan_start + timedelta(milliseconds=400 * i)
        lines.append(
            f"{syslog(t)} fw01 kernel: [UFW BLOCK] IN=eth0 OUT= MAC=00:00:00:00:00:00 SRC={ATTACKER} DST=10.0.0.5 "
            f"LEN=44 TOS=0x00 PREC=0x00 TTL=52 ID={1000 + i} PROTO=TCP SPT={50000 + i} DPT={port} WINDOW=1024 RES=0x00 SYN URGP=0")
    # normal blocked noise: one stray connection
    lines.append(f"{syslog(T0 - timedelta(hours=1))} fw01 kernel: [UFW BLOCK] IN=eth0 OUT= SRC=10.0.0.77 DST=10.0.0.5 PROTO=UDP SPT=5353 DPT=5353")
    write("firewall.log", "\n".join(lines) + "\n")

    # Windows Firewall (pfirewall.log) from a home-lab nmap run: Kali -> Windows
    win = ["#Version: 1.5", "#Software: Microsoft Windows Firewall", "#Fields: date time action protocol src-ip dst-ip src-port dst-port size tcpflags tcpsyn tcpack tcpwin icmptype icmpcode info path"]
    for i, port in enumerate(range(1, 41)):
        t = T0 + timedelta(hours=3) + timedelta(milliseconds=250 * i)
        win.append(f"{t:%Y-%m-%d %H:%M:%S} DROP TCP 10.0.2.15 10.0.2.4 {44000 + i} {port} 44 S 123 0 1024 - - - RECEIVE")
    win.append(f"{T0 + timedelta(hours=3):%Y-%m-%d %H:%M:%S} ALLOW TCP 10.0.2.15 10.0.2.4 44100 445 52 S 1 0 8192 - - - RECEIVE")
    write("pfirewall.log", "\n".join(win) + "\n")


def access_log():
    lines = []
    normal_urls = ["/", "/products", "/products?cat=shoes&sort=asc", "/about", "/contact", "/blog/hello-world", "/cart"]
    for i in range(40):
        t = T0 + timedelta(minutes=45) - timedelta(seconds=37 * (40 - i))
        ip = f"10.0.0.{10 + i % 9}"
        url = random.choice(normal_urls)
        lines.append(f'{ip} - - [{t:%d/%b/%Y:%H:%M:%S +0000}] "GET {url} HTTP/1.1" 200 {random.randint(500, 9000)} "-" "Mozilla/5.0"')
    attacks = [
        "/search?q=%27+OR+1%3D1--", "/item?id=1+UNION+SELECT+username,password+FROM+users",
        "/profile?id=1;SELECT+SLEEP(5)--", "/search?q=<script>alert(document.cookie)</script>",
        "/page?name=%3Cimg+src%3Dx+onerror%3Dalert(1)%3E", "/download?file=../../../../etc/passwd",
        "/download?file=..%252f..%252fetc%252fshadow", "/ping?host=8.8.8.8;cat+/etc/passwd",
        "/login?user=admin%27+--", "/admin", "/phpmyadmin/", "/wp-login.php",
    ]
    for i, url in enumerate(attacks):
        t = T0 + timedelta(minutes=45, seconds=4 * i)
        status = 500 if "SLEEP" in url or "UNION" in url else 404 if url in ("/admin", "/phpmyadmin/", "/wp-login.php") else 200
        lines.append(f'{WEB_ATTACKER} - - [{t:%d/%b/%Y:%H:%M:%S +0000}] "GET {url} HTTP/1.1" {status} 312 "-" "Mozilla/5.0"')
    for i in range(6):
        t = T0 + timedelta(minutes=46, seconds=2 * i)
        lines.append(f'{WEB_ATTACKER} - - [{t:%d/%b/%Y:%H:%M:%S +0000}] "GET /products?id={i} HTTP/1.1" 200 800 "-" "sqlmap/1.7.2#stable (https://sqlmap.org)"')
    lines.sort(key=lambda l: l.split("[", 1)[1])
    write("access.log", "\n".join(lines) + "\n")


def emails():
    folder = ROOT / "emails"
    folder.mkdir(parents=True, exist_ok=True)

    def build(name, sender, rcpt, subject, text, html=None, headers=None, attach=None, when=None):
        msg = EmailMessage()
        msg["From"], msg["To"], msg["Subject"] = sender, rcpt, subject
        msg["Date"] = format_datetime(when or (T0 + timedelta(hours=1)))
        for key, value in (headers or {}).items():
            msg[key] = value
        msg.set_content(text)
        if html:
            msg.add_alternative(html, subtype="html")
        if attach:
            msg.add_attachment(b"placeholder - not a real file", maintype="application",
                               subtype="octet-stream", filename=attach)
        (folder / name).write_bytes(bytes(msg))

    bad_headers = {
        "Authentication-Results": "mx.company.example; spf=fail smtp.mailfrom=paypa1-secure.example; dkim=none; dmarc=fail",
        "Reply-To": "recover-account@mail-helpdesk.example",
    }
    for i in range(5):
        build(
            f"phish_{i + 1}.eml", '"PayPal Support" <billing@paypa1-secure.example>', f"user{i}@company.example",
            "URGENT: Your account has been suspended - verify immediately",
            "Your account will be closed within 24 hours. Action required: confirm your identity at "
            "http://45.9.148.20/paypal/login",
            html='<p>Your account is suspended. <a href="http://45.9.148.20/paypal/login">www.paypal.com/verify</a></p>',
            headers=bad_headers, attach="invoice.pdf.exe" if i == 0 else None,
            when=T0 + timedelta(hours=1, minutes=i),
        )
    build("legit_1.eml", "Priya Nair <priya.nair@company.example>", "user0@company.example",
          "Weekly sync notes", "Hi all, notes from today's sync are in the shared folder. Thanks, Priya",
          headers={"Authentication-Results": "mx.company.example; spf=pass; dkim=pass; dmarc=pass"})
    build("legit_2.eml", "GitHub <noreply@github.com>", "user1@company.example",
          "Your pull request was merged", "Your pull request #42 was merged. View it at https://github.com/org/repo/pull/42",
          headers={"Authentication-Results": "mx.company.example; spf=pass; dkim=pass; dmarc=pass"})


def dns_csv():
    rows = ["timestamp,src,dst"]
    # normal, irregular browsing from the same host
    domains = ["github.com", "stackoverflow.com", "news.example", "cdn.example", "mail.company.example"]
    t = T0
    for _ in range(120):
        t += timedelta(seconds=random.randint(3, 240))
        rows.append(f"{t.isoformat()},10.0.0.23,{random.choice(domains)}")
    # beacon: every 60s with a little jitter
    t = T0 + timedelta(minutes=2)
    for _ in range(45):
        rows.append(f"{t.isoformat()},10.0.0.23,update-check.example")
        t += timedelta(seconds=60 + random.randint(-4, 4))
    # a legitimately periodic service (ignored by default)
    t = T0
    for _ in range(30):
        rows.append(f"{t.isoformat()},10.0.0.23,time.windows.com")
        t += timedelta(seconds=300)
    rows.sort(key=lambda r: r.split(",")[0] if not r.startswith("timestamp") else "")
    write("dns.csv", "\n".join(rows) + "\n")


def windows_csv():
    rows = ["_time,host,EventCode,Account_Name,Source_Network_Address,Logon_Type"]
    for i in range(8):
        t = T0 + timedelta(hours=2, seconds=10 * i)
        rows.append(f"{t.isoformat()},DBs_Asus,4625,Administrator,10.0.2.15,3")
    t = T0 + timedelta(hours=2, seconds=100)
    rows.append(f"{t.isoformat()},DBs_Asus,4624,Administrator,10.0.2.15,3")
    for i in range(10):      # noise the detector must ignore
        t = T0 + timedelta(hours=2, minutes=i)
        rows.append(f"{t.isoformat()},DBs_Asus,4624,SYSTEM,-,5")
        rows.append(f"{t.isoformat()},DBs_Asus,4624,DBS_ASUS$,-,5")
    write("windows_security.csv", "\n".join(rows) + "\n")


if __name__ == "__main__":
    auth_log()
    firewall_logs()
    access_log()
    emails()
    dns_csv()
    windows_csv()
    allow = ROOT / "allowlist.txt"
    allow.write_text("# authorized scanners / admin hosts, one per line\n10.0.2.15\n", encoding="utf-8")
    print(f"Sample logs written to {ROOT}")

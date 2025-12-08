#!/usr/bin/env python3
import requests
import argparse
from urllib.parse import urljoin
from colorama import Fore, Style
from datetime import datetime
import json
from concurrent.futures import ThreadPoolExecutor, as_completed


# --- Helper: Smart Response Check with Severity ---
def check_response(response, baseline_length=None):
    text = response.text.lower()
    length = len(response.text)

    block_keywords = ["access denied", "unauthorized", "login", "sign in", "forbidden", "error"]

    if any(keyword in text for keyword in block_keywords):
        return f"{Fore.RED}{response.status_code} (Blocked){Style.RESET_ALL}", "Low"

    if baseline_length and abs(length - baseline_length) < 50:
        return f"{Fore.YELLOW}{response.status_code} (Login Page){Style.RESET_ALL}", "Medium"

    return f"{Fore.GREEN}{response.status_code} (Possible Bypass){Style.RESET_ALL}", "High"


# --- Reporter ---
class Reporter:
    def __init__(self, target, json_mode=False):
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.json_mode = json_mode
        self.target = target
        self.ts = ts
        self.results = []  # store results in memory

        if json_mode:
            self.filename = f"scan_report_{ts}.json"
        else:
            self.filename = f"scan_report_{ts}.txt"

    def log(self, test_type, item, result, severity):
        self.results.append({
            "type": test_type,
            "item": item,
            "result": result,
            "severity": severity
        })

    def save(self):
        # sort results: High → Medium → Low
        severity_order = {"High": 0, "Medium": 1, "Low": 2}
        sorted_results = sorted(self.results, key=lambda x: severity_order.get(x["severity"], 3))

        if self.json_mode:
            data = {
                "target": self.target,
                "date": str(datetime.now()),
                "results": sorted_results
            }
            with open(self.filename, "w") as f:
                json.dump(data, f, indent=4)
        else:
            with open(self.filename, "w") as f:
                f.write(f"[*] Broken Access Control Scan Report\nTarget: {self.target}\nDate: {datetime.now()}\n\n")
                for r in sorted_results:
                    f.write(f"[{r['type']}] {r['item']:30} -> {r['result']} | Severity: {r['severity']}\n")


# --- HTTP Method Tests ---
def test_methods(url, reporter, baseline_length=None):
    methods = ["GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD", "PATCH"]
    print("\n[+] Testing HTTP Methods:")
    for method in methods:
        try:
            response = requests.request(method, url, timeout=5)
            res, sev = check_response(response, baseline_length)
            print(f"{method:7} -> {res}")
            reporter.log("Method", method, response.status_code, sev)
        except Exception as e:
            print(f"{method:7} -> Error: {e}")
            reporter.log("Method", method, "Error", "N/A")


# --- Header Manipulation ---
def test_headers(url, reporter, baseline_length=None, headers_file=None, limit=None, threads=5):
    headers_list = []
    if headers_file:
        with open(headers_file, "r") as f:
            for line in f:
                if ":" in line:
                    k, v = line.strip().split(":", 1)
                    headers_list.append({k.strip(): v.strip()})
        if limit:
            headers_list = headers_list[:limit]
    else:
        headers_list = [
            {"X-Forwarded-For": "127.0.0.1"},
            {"X-Original-URL": "/admin"},
            {"X-Rewrite-URL": "/admin"},
            {"X-Custom-IP-Authorization": "127.0.0.1"},
            {"X-Forwarded-Host": "localhost"},
            {"Referer": "http://localhost/"},
            {"User-Agent": "AdminBrowser/1.0"}
        ]

    print("\n[+] Testing Header Manipulations:")

    def worker(custom_header):
        try:
            response = requests.get(url, headers=custom_header, timeout=5)
            hdr = list(custom_header.keys())[0]
            res, sev = check_response(response, baseline_length)
            return f"Header {hdr:25} -> {res}", ("Header", hdr, response.status_code, sev)
        except Exception as e:
            return f"Header {custom_header} -> Error: {e}", ("Header", str(custom_header), "Error", "N/A")

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = [executor.submit(worker, h) for h in headers_list]
        for future in as_completed(futures):
            out, log_entry = future.result()
            print(out)
            reporter.log(*log_entry)


# --- Path Manipulation ---
def test_paths(base_url, reporter, baseline_length=None, paths_file=None, limit=None, threads=5):
    path_variants = []
    if paths_file:
        with open(paths_file, "r") as f:
            path_variants = [line.strip() for line in f if line.strip()]
        if limit:
            path_variants = path_variants[:limit]
    else:
        path_variants = [
            "/..;/administration",
            "/%2e%2e/administration",
            "//administration",
            "/administration/../admin",
            "/..%2fadministration",
            "/admin%20",
            "/admin/",
            "/./admin",
        ]

    print("\n[+] Testing Path Manipulations:")

    def worker(variant):
        if variant.startswith("//"):
            test_url = base_url.rstrip("/") + variant
        else:
            test_url = urljoin(base_url, variant)

        try:
            response = requests.get(test_url, timeout=5)
            res, sev = check_response(response, baseline_length)
            return f"Path {variant:30} -> {res}", ("Path", variant, response.status_code, sev)
        except Exception as e:
            return f"Path {variant:30} -> Error: {e}", ("Path", variant, "Error", "N/A")

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = [executor.submit(worker, v) for v in path_variants]
        for future in as_completed(futures):
            out, log_entry = future.result()
            print(out)
            reporter.log(*log_entry)


# --- Main Function ---
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Broken Access Control Scanner")
    parser.add_argument("url", nargs="?", help="Target URL (e.g., https://target.com/admin)")
    parser.add_argument("-l", "--list", help="File with list of URLs to scan", required=False)
    parser.add_argument("-js", "--json", action="store_true", help="Save report in JSON format")
    parser.add_argument("-hf", "--headers-file", dest="headers_file", help="Custom headers file", required=False)
    parser.add_argument("-pf", "--paths-file", dest="paths_file", help="Custom paths file", required=False)
    parser.add_argument("--limit", type=int, help="Limit number of headers/paths tested", required=False)
    parser.add_argument("--threads", type=int, default=5, help="Number of threads to use for header/path tests")
    args = parser.parse_args()

    if not args.url and not args.list:
        parser.error("You must provide either a single URL or a list of URLs (-l).")

    targets = []
    if args.list:
        with open(args.list, "r") as f:
            targets = [line.strip() for line in f if line.strip()]
    else:
        targets = [args.url]

    for target in targets:
        try:
            baseline_resp = requests.get("http://127.0.0.1:3000/#/login", timeout=5)
            baseline_length = len(baseline_resp.text)
            print("[*] Baseline login page captured for comparison.")
        except Exception:
            baseline_length = None
            print("[!] Could not fetch baseline login page, proceeding without it.")

        print(f"\n[*] Scanning Target: {target}")
        reporter = Reporter(target, json_mode=args.json)

        test_methods(target, reporter, baseline_length)
        test_headers(target, reporter, baseline_length, args.headers_file, args.limit, args.threads)
        test_paths(target, reporter, baseline_length, args.paths_file, args.limit, args.threads)

        reporter.save()
        print(f"\n[+] Report saved as {reporter.filename}")

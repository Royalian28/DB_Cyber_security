Here’s a polished README.md draft for your Broken Access Control Scanner:

#Broken Access Control (BAC) Bypass Scanner

A Python-based scanner to identify **Broken Access Control vulnerabilities** by testing HTTP methods, header manipulations, and path traversal bypasses.

Supports multi-threading, custom wordlists, and can save results in **TXT** or JSON formats.

#Features

* 🚀 HTTP Method Tests (GET, POST, PUT, DELETE, etc.)
* 🕵️ Header Manipulation (built-in + custom header wordlist support)
* 📂 Path Traversal / Manipulation (built-in + custom path wordlist support)
* ⚡ Multithreading for faster scanning
* 📊 Reports in TXT or JSON

  * TXT: Groups results by severity (Bypasses first, Blocked last)
  * JSON: Structured for automation pipelines
  
#Customizable:

  * Header file (`--headers-file`)
  * Path file (`--paths-file`)
  * Thread count (`--threads`)
  * Limit number of tests (`--limit`)

#Installation

Clone the repo and install dependencies:

git clone https://github.com/yourusername/bac-bypass-scanner.git
cd bac-bypass-scanner
pip install -r requirements.txt

Requirements:

* Python 3.8+
* requests
* colorama

#Usage

Single URL: python3 bac_bypass.py http://target.com/admin

URL List: python3 bac_bypass.py -l urls.txt

With Custom Wordlists: python3 bac_bypass.py -hf extra_headers.txt -pf raft_path_traversal.txt http://target.com/admin

Multithreading + Limit: python3 bac_bypass.py --threads 10 --limit 500 http://target.com/admin

Save JSON Report: python3 bac_bypass.py -js http://target.com/admin


# Broken Access Control Scanner

positional arguments:
  url                   Target URL (e.g., https://target.com/admin)

options:
  -h, --help            show this help message and exit
  -l, --list LIST       File with list of URLs to scan
  -js, --json           Save report in JSON format
  --hf, --headers-file HEADERS_FILE
                        Custom headers file
  --pf, --paths-file PATHS_FILE
                        Custom paths file
  --limit LIMIT         Limit number of headers/paths tested
  --threads THREADS     Number of threads to use for header/path tests



#Example Reports

TXT Report

[*] Broken Access Control Scan Report
Target: http://target.com/admin
Date: 2025-08-22 11:28:26

[+] Possible Bypass Results:
[Path] /admin%20                    -> 200 | Severity: High
[Header] X-Forwarded-For            -> 200 | Severity: High

[+] Blocked Results:
[Method] GET                         -> 200 | Severity: Low
[Header] Referer                     -> 200 | Severity: Low


JSON Report

json
{
  "target": "http://target.com/admin",
  "date": "2025-08-22 11:28:26",
  "results": [
    {
      "type": "Path",
      "item": "/admin%20",
      "result": 200,
      "severity": "High"
    },
    {
      "type": "Header",
      "item": "X-Forwarded-For",
      "result": 200,
      "severity": "High"
    }
  ]
}


#Disclaimer

This tool is for educational and authorized penetration testing purposes only.
Unauthorized use against systems without explicit permission is illegal.

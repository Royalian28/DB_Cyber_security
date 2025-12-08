# IOC Extractor + VirusTotal Enrichment

A Python-based Indicator of Compromise (IOC) extractor that parses log files to detect suspicious artifacts such as domains, IPs, URLs, and file hashes.
Optionally, it enriches IOCs using the VirusTotal API for quick threat intelligence lookup.



# Features

* 📂 Parse log files to extract:

  * Domains
  * URLs
  * IPv4 / IPv6 addresses
  * File Hashes (MD5, SHA1, SHA256)
* 🦠 Optional **VirusTotal API integration** for enrichment.
* ⚡ **Threaded API requests** for faster lookups.
* 📊 Export results to:

  * JSON (structured with enrichment data)
  * CSV (flat format for Excel/SIEM ingestion)
* 🖥 Console summary with IOC counts + malicious detections.



# Installation

1. Clone the repository:

   bash
   git clone https://github.com/yourname/ioc-extractor.git
   cd ioc-extractor


2. Create a virtual environment & install requirements:

   bash
   python3 -m venv env
   source env/bin/activate   # Linux/Mac
   env\Scripts\activate      # Windows

   pip install -r requirements.txt


3. (Optional) Get a free VirusTotal API key:

   * Sign up at [https://www.virustotal.com](https://www.virustotal.com/)
   * Copy your API key


# Usage

# Extract IOCs only

bash
python3 ioc_extractor.py -i sample.log -j iocs.json -c iocs.csv


### Extract IOCs + Enrich with VirusTotal

bash
python3 ioc_extractor.py -i sample.log -j iocs.json -c iocs.csv --vt


# Output Examples

# Console


[ALERT] Malicious urls detected: http://malicious.com/login
[ALERT] Malicious domains detected: malicious.com

IOC Summary 
urls: 10 found
domains: 9 found
ipv4: 13 found
ipv6: 16 found
md5: 9 found
sha1: 14 found
sha256: 12 found


# JSON (`iocs.json`)

json
{
  "domains": {
    "values": [
      "safe-site.org",
      "malicious.com"
    ],
    "virustotal": {
      "safe-site.org": { "malicious": 0, "suspicious": 0 },
      "malicious.com": { "malicious": 13, "suspicious": 0 }
    }
  },
  "urls": {
    "values": [
      "http://test.org",
      "http://malicious.com/login"
    ]
  }
}


# CSV (`iocs.csv`)

| Type   | Value                                                    | Malicious | Suspicious | Harmless | Undetected |
| ------ | -------------------------------------------------------- | --------- | ---------- | -------- | ---------- |
| domain | malicious.com                                            | 13        | 0          | 0        | 1          |
| url    | [http://malicious.com/login](http://malicious.com/login) | 12        | 1          | 3        | 2          |
| ipv4   | 8.8.8.8                                                  | 0         | 0          | 50       | 1          |


# Command Line Options

usage: ioc_extractor.py [-h] -i INPUT [-j JSON] [-c CSV] [--vt]

optional arguments:
  -h, --help     show this help message
  -i INPUT       Input log file
  -j JSON        Output JSON file
  -c CSV         Output CSV file
  --vt           Enable VirusTotal enrichment (requires API key)


# Future Improvements

* Support for more log formats (Apache, Syslog, Windows Event Logs).
* YARA rules integration.
* Threat intelligence feeds beyond VirusTotal (AlienVault OTX, AbuseIPDB).


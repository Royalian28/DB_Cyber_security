import re
import argparse
import json
import csv
import requests
import concurrent.futures

# ======================
# Regex patterns for IOCs
# ======================
RE_URL = re.compile(r'\bhttps?://[^\s\'"<>]+', re.IGNORECASE)
RE_IPV4 = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
RE_IPV6 = re.compile(r'\b(?:[0-9A-Fa-f]{1,4}:){2,7}[0-9A-Fa-f]{1,4}\b')
RE_DOMAIN = re.compile(r'\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b', re.IGNORECASE)
RE_MD5 = re.compile(r'\b[a-fA-F0-9]{32}\b')
RE_SHA1 = re.compile(r'\b[a-fA-F0-9]{40}\b')
RE_SHA256 = re.compile(r'\b[a-fA-F0-9]{64}\b')

# ======================
# VirusTotal API settings
# ======================
API_KEY = "Your_API_Key"
VT_URL = "https://www.virustotal.com/api/v3"

# ======================
# Extract IOCs from logs
# ======================
def extract_iocs(logfile):
    iocs = {
        "urls": [],
        "domains": [],
        "ipv4": [],
        "ipv6": [],
        "md5": [],
        "sha1": [],
        "sha256": []
    }

    with open(logfile, "r", encoding="utf-8") as f:
        for line in f:
            iocs["urls"].extend(RE_URL.findall(line))
            iocs["ipv4"].extend(RE_IPV4.findall(line))
            iocs["ipv6"].extend(RE_IPV6.findall(line))
            iocs["domains"].extend(RE_DOMAIN.findall(line))
            iocs["md5"].extend(RE_MD5.findall(line))
            iocs["sha1"].extend(RE_SHA1.findall(line))
            iocs["sha256"].extend(RE_SHA256.findall(line))

    for key in iocs:
        iocs[key] = list(set(iocs[key]))

    return iocs

# ======================
# VirusTotal API Queries
# ======================
def vt_request(endpoint):
    headers = {"x-apikey": API_KEY}
    try:
        r = requests.get(endpoint, headers=headers, timeout=15)
        if r.status_code == 200:
            return r.json()
    except Exception as e:
        print(f"[!] VT error: {e}")
    return {}

def check_url(url):
    return vt_request(f"{VT_URL}/urls/{requests.utils.quote(url)}")

def check_domain(domain):
    return vt_request(f"{VT_URL}/domains/{domain}")

def check_ip(ip):
    return vt_request(f"{VT_URL}/ip_addresses/{ip}")

def check_hash(filehash):
    return vt_request(f"{VT_URL}/files/{filehash}")

# ======================
# Enrich IOCs with VT
# ======================
def enrich_iocs(iocs):
    enriched = {k: {"values": v, "virustotal": {}} for k, v in iocs.items()}

    def process(ioc_type, value):
        if ioc_type == "urls":
            data = check_url(value)
        elif ioc_type == "domains":
            data = check_domain(value)
        elif ioc_type in ["ipv4", "ipv6"]:
            data = check_ip(value)
        else:  # hashes
            data = check_hash(value)

        stats = {}
        if "data" in data and "attributes" in data["data"]:
            stats = data["data"]["attributes"].get("last_analysis_stats", {})

        return ioc_type, value, stats

    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        future_to_ioc = {
            executor.submit(process, ioc_type, v): (ioc_type, v)
            for ioc_type, values in iocs.items()
            for v in values
        }

        for future in concurrent.futures.as_completed(future_to_ioc):
            ioc_type, val = future_to_ioc[future]
            try:
                _, value, stats = future.result()
                enriched[ioc_type]["virustotal"][value] = stats
            except Exception as e:
                print(f"[!] Thread error: {e}")

    return enriched

# ======================
# Save as CSV
# ======================
def save_csv(iocs, filename, enriched=None):
    with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
        writer = csv.writer(csvfile)

        if enriched:
            writer.writerow(["Type", "Value", "Malicious", "Suspicious", "Harmless", "Undetected"])
            for ioc_type, content in enriched.items():
                for val in content["values"]:
                    stats = content["virustotal"].get(val, {})
                    writer.writerow([
                        ioc_type,
                        val,
                        stats.get("malicious", 0),
                        stats.get("suspicious", 0),
                        stats.get("harmless", 0),
                        stats.get("undetected", 0),
                    ])
        else:
            writer.writerow(["Type", "Value"])
            for ioc_type, values in iocs.items():
                for val in values:
                    writer.writerow([ioc_type, val])

    print(f"Saved IOCs to {filename}")

# ======================
# Main Function
# ======================
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="IOC Extractor with VirusTotal enrichment")
    parser.add_argument("-i", "--input", required=True, help="Input log file")
    parser.add_argument("-j", "--json", help="Output JSON file")
    parser.add_argument("-c", "--csv", help="Output CSV file")
    parser.add_argument("--vt", action="store_true", help="Enable VirusTotal enrichment")
    args = parser.parse_args()

    # Step 1: Extract IOCs
    iocs = extract_iocs(args.input)

    # Step 2: Enrich if enabled
    enriched = None
    if args.vt:
        enriched = enrich_iocs(iocs)

    # Step 3: Save JSON
    if args.json:
        with open(args.json, 'w', encoding='utf-8') as f:
            json.dump(enriched if args.vt else {k: {"values": v} for k, v in iocs.items()}, f, indent=2)
        print(f"Saved JSON to {args.json}")

    # Step 4: Save CSV
    if args.csv:
        save_csv(iocs, args.csv, enriched if args.vt else None)

    # Step 5: Print Summary
    print("\n--- IOC Summary ---")
    for k, v in iocs.items():
        print(f"{k}: {len(v)} found")

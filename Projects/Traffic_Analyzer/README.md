---

✅ `README.md` — Complete

🕵️ TCP Traffic Analyzer

A Python-based network traffic analyzer that reads TCP connection logs (exported from Wireshark) and identifies the most contacted destination IP addresses. It performs basic threat intelligence by using WHOIS lookups to flag frequently contacted external systems.

---

🚀 Features

- Parses real `.pcapng` files (via `tshark`) or cleaned `.txt` exports from Wireshark
- Extracts and counts destination IPs
- Flags IPs contacted more than 5 times
- Performs WHOIS lookup to identify IP owner/organization
- Generates a simple text-based report (`flagged_ips.txt`)

---

📂 Project Structure

```
tcp-traffic-analyzer/
├── raw_tcp_connections.pcapng    # Raw packet capture (from Wireshark)
├── raw_tcp_connections.txt       # Cleaned connection flows (IP src → dst)
├── tcp_traffic_analyzer.py       # Main analysis script
├── flagged\_ips.txt               # Output: flagged IPs with owner info
└── README.md                     # This documentation

````

---

🛠 Requirements

- Python 3.13
- `whois` module:
  pip install python-whois


Optional:

* `tshark` (comes with Wireshark) to convert `.pcapng` to `.txt`

---

🧪 How to Use

1. Capture Packets

* Launch Wireshark in Kali Linux
* Capture TCP traffic
* Save the file as `raw_tcp_connections.pcapng`

2. Extract Clean IP Log

Run this command in the terminal to extract just IPs:

tshark -r raw_tcp_connections.pcapng -Y "tcp" -T fields -e ip.src -e ip.dst > raw_tcp_connections.txt


### 3. Run the Analyzer

python3 tcp_traffic_analyzer.py


The script will:

* Print the top 10 most contacted IPs
* Flag those with >5 connections
* Perform WHOIS lookup
* Save results to `flagged_ips.txt`

---

📌 Sample Output

Console Output:

```
🔍 Top Contacted IPs:
142.250.77.142 → 130 times
34.149.100.209 → 56 times
...
```

flagged_ips.txt:

```
142.250.77.142 - 130 connections
   → Owner: Google LLC
34.149.100.209 - 56 connections
   → Owner: Google Cloud
```

---

🧠 Why This Project Matters

In cybersecurity, identifying who your system is talking to can reveal:

* Suspicious behavior
* Malware callbacks
* Data exfiltration attempts
* Legitimate vs risky IPs

This tool simulates an essential part of SOC analysis, packet forensics, and threat hunting — using Python.

---

📜 License

MIT License — use freely with attribution.

---

🙌 Credits

Built by DB using Kali Linux, Wireshark, Python 3, and WHOIS and with the great help of ChatGPT.


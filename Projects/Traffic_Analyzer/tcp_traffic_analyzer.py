from collections import Counter
import whois
import time

# Load cleaned packet data
with open("raw_tcp_connections.txt", "r") as file:
    lines = file.readlines()

# Extract only destination IPs
dest_ips = []
for line in lines:
    parts = line.strip().split()
    if len(parts) == 2:
        src, dst = parts
        dest_ips.append(dst)

# Count top destination IPs
counts = Counter(dest_ips)

print("\n🔍 Top Contacted IPs:")
for ip, count in counts.most_common(10):
    print(f"{ip} → {count} times")

# Save flagged IPs with WHOIS lookup
with open("flagged_ips.txt", "w") as f:
    for ip, count in counts.most_common(5):
        if count > 5:
            f.write(f"{ip} - {count} connections\n")
            try:
                info = whois.whois(ip)
                owner = info.org if info.org else info.name
                f.write(f"   → Owner: {owner}\n")
            except Exception as e:
                f.write(f"   → WHOIS lookup failed: {e}\n")
            time.sleep(0.3)  # polite delay to avoid abuse

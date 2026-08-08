import json
import os
import ipaddress
import requests

from pathlib import Path
from dotenv import load_dotenv


# --------------------------------------------------
# Load environment
# --------------------------------------------------

env_path = Path(__file__).resolve().parent.parent / ".env"
load_dotenv(env_path)

VT_API_KEY = os.getenv("VT_API_KEY")


# --------------------------------------------------
# Load latest Splunk alert
# --------------------------------------------------

with open("latest_alert.json", "r") as f:
    alert = json.load(f)


source_ip = alert.get("Message", "")

# Extract source IP from Windows event
import re

match = re.search(
    r"Source Network Address:\s*([^\r\n]+)",
    source_ip
)

if match:
    source_ip = match.group(1).strip()
else:
    source_ip = None


print("\n========================================")
print("       THREAT INTELLIGENCE")
print("========================================\n")

print(f"Source IP: {source_ip}")


# --------------------------------------------------
# Validate IP
# --------------------------------------------------

if not source_ip:

    print("No source IP found.")
    exit()

try:

    ip = ipaddress.ip_address(source_ip)

except ValueError:

    print("Invalid IP address.")
    exit()


# --------------------------------------------------
# Ignore private / loopback addresses
# --------------------------------------------------

if ip.is_private or ip.is_loopback:

    print("\nThis is a private/loopback IP.")
    print("External threat-intelligence lookup skipped.")

    result = {
        "ip": source_ip,
        "lookup": "skipped",
        "reason": "Private or loopback address"
    }

    with open("../reports/threat_intel.json", "w") as f:
        json.dump(result, f, indent=4)

    exit()


# --------------------------------------------------
# Check API key
# --------------------------------------------------

if not VT_API_KEY:

    print("\nERROR: VT_API_KEY not found.")
    exit(1)


# --------------------------------------------------
# VirusTotal IP lookup
# --------------------------------------------------

url = f"https://www.virustotal.com/api/v3/ip_addresses/{source_ip}"

headers = {
    "x-apikey": VT_API_KEY
}


try:

    response = requests.get(
        url,
        headers=headers,
        timeout=20
    )

except requests.RequestException as e:

    print(f"\nVirusTotal connection error: {e}")
    exit(1)


if response.status_code != 200:

    print("\nVirusTotal API error:")
    print(response.text)
    exit(1)


data = response.json()


# --------------------------------------------------
# Extract reputation
# --------------------------------------------------

attributes = data.get("data", {}).get("attributes", {})

reputation = attributes.get("reputation", 0)

stats = attributes.get(
    "last_analysis_stats",
    {}
)


print("\nVirusTotal Result")
print("----------------------------")

print(f"Reputation : {reputation}")

print(
    f"Malicious  : {stats.get('malicious', 0)}"
)

print(
    f"Suspicious : {stats.get('suspicious', 0)}"
)

print(
    f"Harmless   : {stats.get('harmless', 0)}"
)

print(
    f"Undetected : {stats.get('undetected', 0)}"
)


# --------------------------------------------------
# Save result
# --------------------------------------------------

result = {

    "ip": source_ip,

    "virus_total": {

        "reputation": reputation,

        "malicious": stats.get(
            "malicious", 0
        ),

        "suspicious": stats.get(
            "suspicious", 0
        ),

        "harmless": stats.get(
            "harmless", 0
        ),

        "undetected": stats.get(
            "undetected", 0
        )
    }
}


with open(
    "../reports/threat_intel.json",
    "w"
) as f:

    json.dump(
        result,
        f,
        indent=4
    )


print("\nThreat intelligence saved:")
print("../reports/threat_intel.json")

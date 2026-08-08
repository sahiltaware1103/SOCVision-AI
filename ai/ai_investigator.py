import json
import os
from pathlib import Path

from dotenv import load_dotenv
from google import genai

from soc_logic import investigate_alert


# ============================================================
# 1. LOAD GEMINI API KEY
# ============================================================

env_path = Path(__file__).resolve().parent.parent / ".env"
load_dotenv(env_path)

api_key = os.getenv("GEMINI_API_KEY")

if not api_key:
    print("ERROR: GEMINI_API_KEY not found")
    exit(1)


# ============================================================
# 2. LOAD LATEST SPLUNK ALERT
# ============================================================

with open("latest_alert.json", "r") as f:
    alert = json.load(f)


# ============================================================
# 3. RUN SOC DETECTION LOGIC
# ============================================================

analysis = investigate_alert(alert)


# ============================================================
# 4. LOAD THREAT INTELLIGENCE
# ============================================================

threat_intel_path = Path("../reports/threat_intel.json")

if threat_intel_path.exists():

    with open(threat_intel_path, "r") as f:
        threat_intel = json.load(f)

else:

    threat_intel = {
        "lookup": "not_available",
        "reason": "Threat intelligence result was not found."
    }


# ============================================================
# 5. DISPLAY ALERT INFORMATION
# ============================================================

print("\n========================================")
print("       SOCVISION AI INVESTIGATION")
print("========================================\n")

print("SOC Detection Result:")
print(f"Event ID   : {analysis['event_id']}")
print(f"Event      : {analysis['event_name']}")
print(f"Severity   : {analysis['severity']}")
print(f"Host       : {analysis['host']}")
print(f"Time       : {analysis['time']}")
print(f"Source IP  : {analysis['source_ip']}")
print(f"Process    : {analysis['process']}")
print(f"Logon Type : {analysis['logon_type']}")
print(f"Status     : {analysis['status']}")
print(f"Substatus  : {analysis['substatus']}")
print(f"SOC Class  : {analysis['mitre']}")


print("\nThreat Intelligence:")

if threat_intel.get("lookup") == "skipped":

    print("Lookup     : Skipped")
    print(
        f"Reason     : "
        f"{threat_intel.get('reason', 'Private/loopback IP')}"
    )

elif "virus_total" in threat_intel:

    vt = threat_intel["virus_total"]

    print("Provider   : VirusTotal")
    print(f"Reputation : {vt.get('reputation', 0)}")
    print(f"Malicious  : {vt.get('malicious', 0)}")
    print(f"Suspicious : {vt.get('suspicious', 0)}")
    print(f"Harmless   : {vt.get('harmless', 0)}")
    print(f"Undetected : {vt.get('undetected', 0)}")

else:

    print("Status     : Not available")


print("\nSending enriched investigation to Gemini...\n")


# ============================================================
# 6. BUILD ENRICHED GEMINI PROMPT
# ============================================================

prompt = f"""
You are an AI assistant supporting a Tier-1 Security Operations
Center (SOC) analyst.

You are analyzing one Windows security alert.

The SOC detection engine and threat-intelligence module have
already processed the evidence below.

Treat the supplied values as facts.

================ SOC DETECTION ================

Event ID:
{analysis['event_id']}

Event Name:
{analysis['event_name']}

Severity:
{analysis['severity']}

Host:
{analysis['host']}

Timestamp:
{analysis['time']}

Source IP:
{analysis['source_ip']}

Process:
{analysis['process']}

Logon Type:
{analysis['logon_type']}

Status:
{analysis['status']}

Substatus:
{analysis['substatus']}

SOC Classification:
{analysis['mitre']}

================ THREAT INTELLIGENCE ================

{json.dumps(threat_intel, indent=2)}

=======================================================

TASK

Perform a concise professional SOC L1 investigation using both
the security alert and the available threat-intelligence result.

Use EXACTLY these sections:

1. Executive Summary

2. Alert Analysis

3. Threat Intelligence Assessment

4. Investigation Steps

5. Recommended Containment

6. Recommended Remediation

7. Escalation Decision

IMPORTANT RULES

- Treat the supplied SOC detection values as authoritative.
- Do not change the Event ID.
- Do not change the Event Name.
- Do not change the Severity.
- Do not invent usernames, attackers, services, credentials,
  or additional events.
- Do not automatically classify one Event ID 4625 as brute force.
- Do not automatically classify the event as malicious.
- Do not treat a private or loopback IP as an external malicious IP.
- If threat intelligence was skipped, explicitly state that
  external reputation could not be assessed.
- Clearly distinguish observed facts from possible explanations.
- If additional evidence is required, identify exactly what
  a SOC L1 analyst should collect.
- Keep recommendations practical.
- Do not ask the user to provide the alert data.
- Return only the seven requested sections.
- Do not interpret Windows status or substatus codes unless the
  exact meaning has been explicitly provided as verified evidence.
- Treat status and substatus values as raw indicators that require
  verification.
- Do not state that a password expired, account was restricted,
  account was locked, or domain authentication failed unless that
  fact is explicitly present in the supplied evidence.
- Do not describe svchost.exe as malicious merely because it appears
  in the event.
- If a process/event combination appears unusual, describe it as
  "requires investigation" rather than "malicious" or "anomalous".
- Do not recommend a password reset unless an affected account has
  actually been identified and evidence supports it.
- Clearly distinguish observed facts from possible explanations.
- If additional evidence is required, identify exactly what
  a SOC L1 analyst should collect.
- Keep recommendations practical.
- Do not ask the user to provide the alert data.
- Return only the seven requested sections.
"""


# ============================================================
# 7. SEND TO GEMINI
# ============================================================

try:

    client = genai.Client(api_key=api_key)

    response = client.models.generate_content(
        model="gemini-3.1-flash-lite",
        contents=prompt
    )

    report = response.text

except Exception as e:

    print("\nERROR: Gemini request failed")
    print(e)
    exit(1)


# ============================================================
# 8. DISPLAY AI INVESTIGATION
# ============================================================

print("========================================")
print("          AI INVESTIGATION")
print("========================================\n")

print(report)


# ============================================================
# 9. SAVE FINAL REPORT
# ============================================================

reports_dir = Path("../reports")
reports_dir.mkdir(exist_ok=True)

report_path = reports_dir / "incident_report.txt"

with open(report_path, "w") as f:

    f.write("SOCVISION AI INVESTIGATION REPORT\n")
    f.write("=" * 50 + "\n\n")

    f.write("SOC DETECTION\n")
    f.write("-" * 50 + "\n")

    f.write(f"Event ID: {analysis['event_id']}\n")
    f.write(f"Event: {analysis['event_name']}\n")
    f.write(f"Severity: {analysis['severity']}\n")
    f.write(f"Host: {analysis['host']}\n")
    f.write(f"Time: {analysis['time']}\n")
    f.write(f"Source IP: {analysis['source_ip']}\n")
    f.write(f"Process: {analysis['process']}\n")
    f.write(f"Logon Type: {analysis['logon_type']}\n")
    f.write(f"Status: {analysis['status']}\n")
    f.write(f"Substatus: {analysis['substatus']}\n")
    f.write(f"SOC Classification: {analysis['mitre']}\n\n")

    f.write("THREAT INTELLIGENCE\n")
    f.write("-" * 50 + "\n")

    f.write(
        json.dumps(
            threat_intel,
            indent=2
        )
    )

    f.write("\n\nAI INVESTIGATION\n")
    f.write("-" * 50 + "\n\n")

    f.write(report)


print("\n========================================")
print(f"Report saved: {report_path}")
print("========================================")

import json
import re


def extract_event_details(alert):
    """
    Extract important information from a Windows security event.
    """

    message = alert.get("Message", "")

    details = {
        "event_id": alert.get("EventCode", "Unknown"),
        "host": alert.get("host", "Unknown"),
        "time": alert.get("_time", "Unknown"),
        "source_ip": "Unknown",
        "process": "Unknown",
        "logon_type": "Unknown",
        "status": "Unknown",
        "substatus": "Unknown"
    }

    patterns = {
        "source_ip": r"Source Network Address:\s*([^\r\n]+)",
        "process": r"Caller Process Name:\s*([^\r\n]+)",
        "logon_type": r"Logon Type:\s*([^\r\n]+)",
        "status": r"Status:\s*([^\r\n]+)",
        "substatus": r"Sub Status:\s*([^\r\n]+)"
    }

    for field, pattern in patterns.items():

        match = re.search(pattern, message)

        if match:
            details[field] = match.group(1).strip()

    return details


def classify_event(event_id):
    """
    Deterministic SOC classification.
    """

    classifications = {

        "4624": {
            "event": "Successful Logon",
            "severity": "Low",
            "mitre": "T1078 - Valid Accounts"
        },

        "4625": {
            "event": "Failed Logon",
            "severity": "Medium",
            "mitre": "Authentication Failure"
        },

        "4672": {
            "event": "Special Privileges Assigned",
            "severity": "Medium",
            "mitre": "T1078 - Valid Accounts"
        },

        "4688": {
            "event": "Process Creation",
            "severity": "Medium",
            "mitre": "T1059 - Command and Scripting Interpreter"
        },

        "4104": {
            "event": "PowerShell Script Block",
            "severity": "Medium",
            "mitre": "T1059.001 - PowerShell"
        }

    }

    return classifications.get(
        str(event_id),
        {
            "event": "Unknown Event",
            "severity": "Low",
            "mitre": "Unknown"
        }
    )


def investigate_alert(alert):

    details = extract_event_details(alert)

    classification = classify_event(
        details["event_id"]
    )

    investigation = {

        **details,

        "event_name": classification["event"],

        "severity": classification["severity"],

        "mitre": classification["mitre"]

    }

    return investigation


if __name__ == "__main__":

    with open("latest_alert.json", "r") as f:
        alert = json.load(f)

    result = investigate_alert(alert)

    print("\n========== SOC ANALYSIS ==========\n")

    for key, value in result.items():

        print(f"{key}: {value}")

    print("\n==================================")

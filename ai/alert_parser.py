import requests
import urllib3
import json
from config import *

urllib3.disable_warnings()

url = f"https://{SPLUNK_HOST}:{SPLUNK_PORT}/services/search/jobs/export"

query = """
search index=* EventCode=4625
| head 1
"""

data = {
    "search": query,
    "output_mode": "json"
}

response = requests.post(
    url,
    auth=(USERNAME, PASSWORD),
    data=data,
    verify=False
)

if response.status_code == 200:

    lines = response.text.strip().split("\n")

    for line in lines:
        record = json.loads(line)

        if "result" in record:
            alert = record["result"]

            with open("latest_alert.json", "w") as f:
                json.dump(alert, f, indent=4)

            print("✅ Latest alert saved as latest_alert.json")
            break

else:
    print("Error:", response.status_code)

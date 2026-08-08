# 🛡️ SOCVision-AI

An AI-assisted Security Operations Center (SOC) investigation platform that collects security alerts, performs rule-based analysis, enriches alerts with threat intelligence, and uses Google Gemini to generate investigation reports.

## 🚀 Overview

SOCVision-AI is a cybersecurity project designed to simulate a SOC Analyst L1 workflow.

### Current Features

- Splunk security alert collection
- Windows Event Log analysis
- SOC detection and severity classification
- Threat intelligence enrichment
- AI-assisted investigation using Google Gemini
- MITRE ATT&CK data integration
- Automated incident report generation

## 🔄 SOC Investigation Workflow

Windows Security Events  
↓  
Splunk  
↓  
Alert Parser  
↓  
SOC Detection  
↓  
Threat Intelligence  
↓  
Google Gemini AI  
↓  
Investigation Report

## 🔍 Detection Example

The project can analyze Windows Security Event ID 4625, which represents a failed logon attempt.

Example:

Event ID: 4625  
Event: Failed Logon  
Severity: Medium  
Host: LAPTOP-A3LO51JL  
Source IP: 127.0.0.1  
Logon Type: 2  
Process: C:\Windows\System32\svchost.exe

The alert is then analyzed and sent to Gemini for additional investigation.

## 🤖 AI Investigation

SOCVision-AI uses the Google Gemini API to assist with security alert investigation.

The investigation report provides:

1. Executive Summary
2. Alert Analysis
3. Threat Intelligence Assessment
4. Investigation Steps
5. Recommended Containment
6. Recommended Remediation
7. Escalation Decision

AI-generated results should be validated against the original security evidence by a SOC analyst.

## 🌐 Threat Intelligence

The project includes a threat intelligence module that evaluates source IP addresses.

Private and loopback addresses such as:

127.0.0.1

are identified locally and external reputation lookups are skipped.

External IP addresses can be enriched using threat intelligence services.

## 🧠 MITRE ATT&CK

MITRE ATT&CK data is included in:

data/mitre_attack.json

This data provides additional security context during alert analysis.

## 📁 Project Structure

SOCVision-AI/
│
├── ai/
│   ├── ai_investigator.py
│   ├── alert_parser.py
│   ├── config.py
│   ├── gemini_test.py
│   ├── main.py
│   ├── report_generator.py
│   ├── soc_logic.py
│   └── threat_intel.py
│
├── data/
│   └── mitre_attack.json
│
├── logs/
├── reports/
├── dashboards/
├── detections/
├── screenshots/
│
└── .gitignore

## 🛠️ Technologies Used

- Python
- Splunk
- Windows Event Logs
- Google Gemini API
- MITRE ATT&CK
- Threat Intelligence
- REST APIs
- JSON
- Linux
- VirtualBox

## ⚙️ Installation

Clone the repository:

git clone https://github.com/sahiltaware1103/SOCVision-AI.git

cd SOCVision-AI

Create a virtual environment:

python3 -m venv venv

Activate it:

source venv/bin/activate

Install the required packages:

pip install requests python-dotenv google-genai

## 🔑 API Configuration

Create a .env file in the project root:

GEMINI_API_KEY=your_api_key_here

Never upload the .env file to GitHub.

## ▶️ Running the Project

Activate the virtual environment:

source venv/bin/activate

Go to the AI directory:

cd ai

Run SOC detection:

python soc_logic.py

Run AI investigation:

python ai_investigator.py

## 🔐 Security

API keys and sensitive security data are excluded from this repository.

The .env file should remain local and must never be uploaded to GitHub.

## 🎯 Project Goals

SOCVision-AI aims to demonstrate a practical SOC Analyst workflow combining:

- SIEM monitoring
- Alert triage
- Log analysis
- Threat intelligence
- Security investigation
- AI-assisted analysis
- Incident reporting

## 🚧 Future Improvements

- Additional Windows event detections
- Improved alert correlation
- More threat intelligence sources
- Automated SOC dashboards
- Additional MITRE ATT&CK mappings
- Improved incident severity scoring
- More automated SOC workflows

## 👨‍💻 Author

Sahil Taware

Cybersecurity / SOC Analyst Enthusiast

GitHub: https://github.com/sahiltaware1103

 🛡️ SOC Analyst Portfolio

 👤 About Me

SOC Analyst with hands-on experience building a home SIEM lab, writing custom detection rules, triaging security alerts, and documenting full incident response workflows. Every project in this portfolio was built from real lab work — simulated attacks, Splunk detections, and professional incident documentation.

📍 Pakistan | 💼 Seeking Remote / On-site | 🕐 Available Immediately**


 🧠 Skills Demonstrated

| Category | Tools & Techniques |
|----------|-------------------|
| **SIEM** | Splunk (Dev License), SPL, Dashboards, Alert Creation, Log Ingestion |
| **Log Analysis** | Windows Event Logs (Security, System, Application), Linux syslog |
| **Detection Engineering** | Custom Correlation Rules, MITRE ATT&CK Mapping, 6 Active Rules |
| **Incident Response** | PICERL Framework, Containment Actions, Professional Documentation |
| **Phishing Analysis** | Email Header Analysis, URL Detonation, SPF/DKIM/DMARC Verification |
| **Threat Intelligence** | IOC Extraction, VirusTotal, AbuseIPDB, MalwareBazaar |
| **Automation** | Python (Log Triage Script, IOC Enrichment) |
| **Communication** | Ticket Writing, Shift Handovers, Executive Brief Templates |

---

 🏗️ Live Lab Architecture

 ┌──────────────────────┐ ┌──────────────────────────┐
│ Kali Linux VM │──────▶│ Windows 10 (Splunk) │
│ (Attack Simulator) │ │ (SIEM + Victim Host) │
└──────────────────────┘ └──────────────────────────┘
│
│ Log Sources:
│ • Windows Event Logs
│ • Sample Security Data
│
▼
┌────────────────────┐
│ Splunk SIEM │
│ (Dev License) │
│ │
│ 📊 Dashboard │
│ 🚨 6 Alert Rules │
│ 🔍 SPL Queries │
└────────────────────┘


 Live Dashboard Evidence
![Splunk Dashboard](screenshots/dashboard-overview.png)
*Real-time SOC monitoring dashboard with live Windows Event Logs*

---

## 📂 Portfolio Projects

### 🔍 1. Detection Rules Library
6 custom SPL detection rules mapped to the MITRE ATT&CK framework.
Covers brute force, encoded PowerShell, persistence, privilege escalation, and defense evasion.
→ [View Detection Rules](./Detection-Rules.md)

### 📋 2. Triage Workbook
Real-world alert scenarios analyzed using the 5-step triage framework.
Includes brute force with credential compromise, malware persistence, and false positive handling.
→ [View Triage Workbook](./Triage-Workbook.md)

### 🚨 3. Incident Response Drill
Complete PICERL incident response simulation — from initial detection through containment, eradication, recovery, and lessons learned.
→ [View IR Drill Report](./IR-Drill-Report.md)

### 🤖 4. Log Triage Automation
Python script that reads Windows Event Logs (CSV), assigns risk scores based on MITRE ATT&CK, and outputs prioritized alerts for SOC analyst review.
→ [View Automation Script](./automation/log_triage.py)

### 📊 5. Splunk SPL Quick Reference
Cheat sheet of essential Splunk commands for SOC operations — data discovery, investigation, aggregation, and field extraction.
→ [View SPL Cheat Sheet](./Splunk-Cheat-Sheet.md)

---

 🔬 Lab Details

| Component | Detail |
|-----------|--------|
| **SIEM** | Splunk Enterprise (Developer License) |
| **Log Sources** | Windows Event Logs (Security, System, Application) |
| **Custom Indexes** | `win_logs` (Event Logs), `soc_lab` (Sample Data) |
| **Detection Rules** | 6 active rules with MITRE ATT&CK mapping |
| **Dashboard** | 7-panel real-time monitoring view |
| **Attack Simulation** | Kali Linux VM + PowerShell attack scripts |
| **Automation** | Python-based log triage and alert prioritization |

---

 🎯 Currently Seeking

Tier 1 SOC Analyst | Security Analyst | Cyber Defense Analyst**
📍 Remote Preferred | Full-time or Contract | Available Immediately

---

"I don't just claim to know security — I built a lab, simulated attacks, detected them, and documented my response."

# Log Triage Automation Script

## Purpose
Automatically triages Windows Event Logs and prioritizes alerts for SOC analysts. Maps events to MITRE ATT&CK framework and assigns risk scores.

## How It Works
1. Reads CSV export of Windows Event Logs
2. Maps each Event ID to MITRE ATT&CK technique
3. Assigns severity: CRITICAL, HIGH, MEDIUM, LOW
4. Automatically escalates encoded PowerShell commands to HIGH
5. Outputs prioritized alert queue with technique mapping

## Usage
```bash
python log_triage.py sample_events.csv
python log_triage.py sample_events.csv --output results.csv

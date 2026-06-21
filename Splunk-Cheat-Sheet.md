# 📊 Splunk SPL Quick Reference

**Purpose:** Operational cheat sheet for SOC analysts performing log investigations.
**Environment:** Splunk Enterprise (Dev License) | Windows Event Logs

---

## Data Discovery

| Task | SPL Command |
|------|-------------|
| List all indexes | `\| eventcount summarize=false index=* \| dedup index \| table index` |
| List sourcetypes in index | `index=win_logs \| stats count by sourcetype` |
| List all hosts sending data | `index=* \| stats count by host` |
| Field summary for sourcetype | `index=win_logs sourcetype="WinEventLog:Security" \| head 10 \| fieldsummary` |
| Count total events | `index=win_logs \| stats count` |
| Events over time | `index=win_logs \| timechart count span=1h` |

---

## Essential Investigation Searches

### Authentication & Logons
| Investigation | SPL |
|---------------|-----|
| Successful logons | `index=win_logs sourcetype="WinEventLog:Security" EventCode=4624 \| table _time Account_Name Logon_Type IpAddress` |
| Failed logons | `index=win_logs sourcetype="WinEventLog:Security" EventCode=4625 \| table _time Account_Name Failure_Reason IpAddress` |
| RDP logons only (Type 10) | `index=win_logs EventCode=4624 Logon_Type=10 \| table _time Account_Name IpAddress` |
| Top failed logon users | `index=win_logs EventCode=4625 \| top limit=10 Account_Name` |
| Top failed logon source IPs | `index=win_logs EventCode=4625 \| top limit=10 IpAddress` |
| Logoffs | `index=win_logs EventCode=4634 OR EventCode=4647 \| table _time Account_Name` |

### Process Execution
| Investigation | SPL |
|---------------|-----|
| All process creation | `index=win_logs EventCode=4688 \| table _time Account_Name Process_Name Command_Line` |
| PowerShell executions | `index=win_logs EventCode=4688 Process_Name="*powershell*" \| table _time Account_Name Command_Line` |
| Encoded PowerShell | `index=win_logs EventCode=4688 Command_Line="*enc*" OR Command_Line="*iex*" \| table _time Account_Name Command_Line` |
| LOLBin detection | `index=win_logs EventCode=4688 (Process_Name="*certutil*" OR Process_Name="*mshta*" OR Process_Name="*bitsadmin*") \| table _time Account_Name Command_Line` |
| Top processes | `index=win_logs EventCode=4688 \| top limit=10 Process_Name` |

### Account Management
| Investigation | SPL |
|---------------|-----|
| New users created | `index=win_logs EventCode=4720 \| table _time Account_Name SubjectUserName` |
| Users added to groups | `index=win_logs EventCode=4732 \| table _time Member_Name Group_Name` |
| Password resets | `index=win_logs EventCode=4724 \| table _time Account_Name SubjectUserName` |
| Accounts enabled | `index=win_logs EventCode=4722 \| table _time Account_Name SubjectUserName` |

### System Events
| Investigation | SPL |
|---------------|-----|
| New services installed | `index=win_logs sourcetype="WinEventLog:System" EventCode=7045 \| table _time Service_Name Service_File_Name` |
| Service status changes | `index=win_logs sourcetype="WinEventLog:System" EventCode=7036 \| table _time Service_Name Message` |
| Audit log cleared (Critical) | `index=win_logs EventCode=1102 \| table _time Account_Name` |

### Privilege Escalation
| Investigation | SPL |
|---------------|-----|
| Special privileges assigned | `index=win_logs EventCode=4672 \| table _time Account_Name Privileges` |
| Admin group changes | `index=win_logs EventCode=4732 Group_Name="*Administrators*" \| table _time Member_Name SubjectUserName` |

---

## Aggregation & Analysis

| Task | SPL |
|------|-----|
| Count by field | `\| stats count by FieldName` |
| Distinct count | `\| stats dc(FieldName)` |
| Top 10 values | `\| top limit=10 FieldName` |
| Rare values (anomalies) | `\| rare FieldName` |
| Sort descending | `\| sort -count` |
| Sort ascending | `\| sort count` |
| Limit results | `\| head 20` |
| Filter aggregated results | `\| search count > 5` |
| Multiple aggregations | `\| stats count as Total, dc(Account_Name) as UniqueUsers by host` |

---

## Time-Based Analysis

| Task | SPL |
|------|-----|
| Timechart (line/bar) | `\| timechart count span=1h` |
| Timechart by field | `\| timechart count by EventCode span=10m` |
| Time bucket + stats | `\| bucket _time span=5m \| stats count by _time Account_Name` |
| Last 1 hour | `earliest=-1h` |
| Last 24 hours | `earliest=-24h` |
| Last 7 days | `earliest=-7d` |
| Specific date range | `earliest=06/01/2026:00:00:00 latest=06/07/2026:23:59:59` |
| Business hours only | `date_hour>=9 date_hour<=17` |

---

## Field Extraction & Transformation

| Task | SPL |
|------|-----|
| Extract with regex | `\| rex "from (?<AttackerIP>\d+\.\d+\.\d+\.\d+)"` |
| Extract username | `\| rex "for (?<TargetUser>\S+) from"` |
| Create calculated field | `\| eval Severity=if(count>10, "HIGH", "LOW")` |
| Rename field | `\| rename Account_Name as User` |
| Convert to lowercase | `\| eval Domain=lower(Domain)` |
| String matching | `\| eval IsSuspicious=if(match(Command_Line, "-enc"), "Yes", "No")` |

---

## Lookups & Correlation

| Task | SPL |
|------|-----|
| Join two searches | `index=win_logs EventCode=4688 \| join ProcessID [search index=win_logs EventCode=5156]` |
| Transaction (group events) | `\| transaction Account_Name startswith=(EventCode=4625) endswith=(EventCode=4624)` |
| Subsearch | `index=win_logs [search index=win_logs EventCode=4720 \| fields Account_Name]` |

---

## Brute Force Detection Pattern

```spl
index=win_logs sourcetype="WinEventLog:Security" EventCode=4625
| bucket _time span=5m
| stats count by _time Account_Name IpAddress
| where count > 5
| sort -count

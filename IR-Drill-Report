# 🚨 Incident Response Drill Report

**Analyst:** Ahmed
**Environment:** Home SOC Lab
**Framework:** PICERL (Preparation, Identification, Containment, Eradication, Recovery, Lessons Learned)


---

## Executive Summary

A simulated multi-stage attack was executed against a Windows host monitored by Splunk SIEM. The attack chain consisted of encoded command execution, unauthorized user account creation, and malicious service installation. All three stages were detected by custom correlation rules, triaged using the 5-step framework, contained within 15 minutes, and fully eradicated. This drill demonstrates complete Tier 1 SOC incident response capability.

---

## Attack Timeline

| Time (UTC) | Event | Event ID | Severity |
|------------|-------|----------|----------|
| 14:05 | Encoded command executed via PowerShell | 4688 | HIGH |
| 14:07 | Unauthorized user "ir_attacker" created | 4720 | HIGH |
| 14:09 | Malicious service "IRTestService" installed | 7045 | HIGH |
| 14:12 | All three alerts correlated — incident declared | N/A | HIGH |
| 14:15 | Containment initiated | N/A | N/A |
| 14:20 | User account deleted | 4726 | N/A |
| 14:22 | Service stopped and removed | 7036 | N/A |
| 14:25 | Eradication verified | N/A | N/A |

---

## Phase 1: Preparation

### Pre-Incident Readiness

| Component | Status Before Drill |
|-----------|---------------------|
| Splunk SIEM operational | ✅ Running with Dev License |
| Windows Event Logs flowing | ✅ Security, System, Application to `win_logs` index |
| Detection rules active | ✅ 6 rules deployed and tested |
| Dashboard monitoring | ✅ 7-panel SOC dashboard live |
| Runbook templates ready | ✅ Brute force and malware runbooks prepared |
| Escalation contacts documented | ✅ Mock contact list created |

### Tools Used
- **SIEM:** Splunk Enterprise (Developer License)
- **Log Sources:** Windows Event Logs (Security, System)
- **Investigation:** SPL searches, field extraction, time correlation
- **Documentation:** Markdown-based incident ticket templates

---

## Phase 2: Identification

### Alert 1: Encoded PowerShell Detected
![Encoded PowerShell](screenshots/ir-1-detection-ps.png)

**Investigation:**
- Verified Event ID 4688 in raw Security log
- Confirmed command line contains obfuscated content
- Identified executing user: Administrator
- Technique mapped: MITRE T1059.001 (PowerShell)

### Alert 2: New User Account Created
![New User](screenshots/ir-2-detection-user.png)

**Investigation:**
- Verified Event ID 4720 — account "ir_attacker" created
- Creator: Administrator account
- Account added to Administrators group (Event ID 4732 confirmed)
- Technique mapped: MITRE T1136.001 (Create Account)

### Alert 3: New Service Installed
![New Service](screenshots/ir-3-detection-service.png)

**Investigation:**
- Verified Event ID 7045 in System log
- Service name: IRTestService (non-standard naming)
- Binary path: cmd.exe (legitimate binary used maliciously)
- Technique mapped: MITRE T1543.003 (Windows Service)

### Correlation Analysis
![Correlation](screenshots/ir-4-correlation.png)

All three alerts occurred within a 4-minute window on the same host with the same user context. This pattern confirms a multi-stage attack rather than three isolated events.

**Incident Declared: HIGH severity**
- Attack chain: Execution → Persistence → Privilege Escalation
- Attacker achieved persistent access with administrator privileges
- Immediate containment required

---

## Phase 3: Containment

### Actions Taken

| Time (UTC) | Action | Method | Result |
|------------|--------|--------|--------|
| 14:15 | Identified compromised host | Splunk correlation | Single host confirmed |
| 14:16 | Documented all IOCs | Extracted from event logs | IOC list compiled |
| 14:17 | Disabled unauthorized user | `net user ir_attacker /active:no` | Account deactivated |
| 14:18 | Stopped malicious service | `Stop-Service IRTestService` | Service halted |
| 14:20 | Deleted user account | `net user ir_attacker /delete` | Account removed |

### Containment Verification
- Attacker can no longer authenticate (account deleted)
- Malicious service no longer running
- No lateral movement detected (no Type 3 logons from host)
- No other hosts affected

---

## Phase 4: Eradication

### Actions Taken

| Action | Method | Status |
|--------|--------|--------|
| Remove user account | `net user ir_attacker /delete` | ✅ Complete |
| Remove malicious service | `sc delete IRTestService` | ✅ Complete |
| Verify no other accounts created | Splunk search: Event ID 4720 | ✅ No others found |
| Verify no other services installed | Splunk search: Event ID 7045 | ✅ No others found |
| Verify no scheduled tasks created | Checked Event ID 4698 | ✅ None detected |

### Eradication Evidence
![User Deleted](screenshots/ir-5-cleanup-user.png)
*User account deletion confirmed (Event ID 4726)*

![Service Removed](screenshots/ir-6-cleanup-service.png)
*Service status change confirmed (Event ID 7036)*

---

## Phase 5: Recovery

### Recovery Verification

| Check | Method | Result |
|-------|--------|--------|
| No recurrence of encoded PowerShell | Monitored Event ID 4688 for 30 min | ✅ Clean |
| No new unauthorized accounts | Monitored Event ID 4720 | ✅ Clean |
| No new services installed | Monitored Event ID 7045 | ✅ Clean |
| System stability confirmed | All critical services running | ✅ Normal |

### Monitoring Period
- Duration: 30 minutes post-eradication
- No alerts fired during monitoring period
- Host returned to normal operational state

---

## Phase 6: Lessons Learned

### What Went Well
1. ✅ Detection rules fired within seconds of each attack action
2. ✅ Triage correctly identified three alerts as single incident
3. ✅ Containment completed within 5 minutes of incident declaration
4. ✅ Full eradication verified with Splunk searches
5. ✅ MITRE ATT&CK mapping performed for all techniques

### What Could Be Improved
1. ⚠️ Initial alert triage took 3 minutes — aim for 2 minutes with practice
2. ⚠️ No automated containment — all actions were manual
3. ⚠️ Would benefit from Sysmon for richer process telemetry

### Action Items

| # | Action | Priority | Status |
|---|--------|----------|--------|
| 1 | Create combined attack chain detection rule | High | Planned |
| 2 | Develop automated containment scripts | Medium | Planned |
| 3 | Integrate Sysmon for process-level visibility | Medium | Pending |
| 4 | Update IR runbook with this scenario | High | ✅ Done |

---

## MITRE ATT&CK Mapping

| Tactic | Technique | ID | Evidence |
|--------|-----------|-----|----------|
| Execution | PowerShell | T1059.001 | Encoded command in Event ID 4688 |
| Persistence | Create Account | T1136.001 | User "ir_attacker" in Event ID 4720 |
| Persistence | Windows Service | T1543.003 | Service "IRTestService" in Event ID 7045 |
| Privilege Escalation | Added to Admin Group | T1098 | Account added to Administrators |

---

## Indicators of Compromise (IOCs)

| Type | Value | Source |
|------|-------|--------|
| Username | ir_attacker | Event ID 4720 |
| Service Name | IRTestService | Event ID 7045 |
| Command Pattern | powershell -enc [base64] | Event ID 4688 |
| Host | [Your Hostname] | All events |

---

## Skills Demonstrated

- ✅ PICERL incident response framework
- ✅ Multi-stage attack detection and correlation
- ✅ Splunk SPL investigation and scoping
- ✅ Containment actions (account disable, service stop, account deletion)
- ✅ Eradication verification through log analysis
- ✅ MITRE ATT&CK technique mapping
- ✅ Professional incident documentation
- ✅ IOC extraction and compilation
- ✅ Lessons learned and improvement planning

---

*This drill was conducted in a home SOC lab environment.*
*All attacks were simulated. All detections were real. All response actions were performed and verified.*
*This report demonstrates readiness for Tier 1 SOC incident response duties.*

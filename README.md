# Threat Hunt: Sudden Network Slowdown

### Executive Summary
In this project, we investigated a significant network slowdown affecting older devices on the corporate network. After ruling out a DDoS attack, the hunt focused internally and traced the source to a single host (`nemwindows10`) running an unauthorized port scan via a PowerShell script. The device was immediately contained, and we developed new security recommendations to prevent similar incidents in the future.

---

### Phase 1: Preparation & Hypothesis

* **Goal:** Investigate the root cause of a significant network performance degradation affecting the (`10.0.0.0/16`) network. After ruling out external DDoS attacks, the security team suspected an internal issue.
* **Hypothesis:** Based on threat intelligence, a likely cause was an internal host either being used for lateral reconnaissance (port scanning) or consuming excessive bandwidth through unauthorized software.

---

### Phase 2: Investigation & Analysis

The investigation began by querying Microsoft Defender XDR logs to test the hypothesis. The full set of queries used in this hunt can be viewed in the [`KQL-Queries.md`](https://github.com/jorjuarez/Cybersecurity-Portfolio-Public/tree/main/project-sudden-network-slowdown#related-kql-queries) file and are also detailed below for context.

#### 1. Initial Data Analysis: Failed Connections
The first step was to look for unusual network traffic patterns. A KQL query was used to find hosts with an excessive number of failed connections, which could indicate a port scan.

```kql
let target_machine = "nemwindows10";
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where DeviceName == target_machine
| where ActionType == "ConnectionFailed"
| summarize ConnectionCount = count() by DeviceName, ActionType, LocalIP
| order by ConnectionCount
```
**Finding:** The output clearly shows that the host `nemwindows10` is the source of the anomalous activity. The high number of failed connections associated with its primary IP (`10.0.0.108`) strongly supports the hypothesis that a port scan is being conducted.

| DeviceName  | ActionType        | LocalIP      | ConnectionCount |
|-------------|-------------------|--------------|-----------------|
| nemwindows10| ConnectionFailed  | 10.0.0.108   | 24              |
| nemwindows10| ConnectionFailed  | 127.0.0.1    | 3               |
| nemwindows10| ConnectionFailed  | ::1          | 3               |

#### 2. Confirming the Port Scan & Pivoting to the Process
With the initial anomaly identified, the investigation moved to confirm that the activity was indeed a port scan by examining the specific network traffic details.

```kql
let target_machine = "nemwindows10";
let problematic_LocalIP = "10.0.0.108";
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where DeviceName == target_machine
| where ActionType == "ConnectionFailed"
| where LocalIP == problematic_LocalIP
| project Timestamp, InitiatingProcessFileName, RemoteIP, RemotePort, Protocol
| sort by Timestamp asc
```
The results confirmed a sequential port scan. The hunt then pivoted from network events to process events to answer the most critical question: **"What process on `nemwindows10` is responsible for this activity?"**

This query was crafted to search for any processes created around the exact time of the port scan.

```kql
let target_machine = "nemwindows10";
let Specific_StartDate_UTC = datetime(2025-05-02T05:35:00Z); //May 2nd 5:35 AM UTC time.
let Specific_EndDate_UTC = datetime(2025-05-02T05:40:00Z); //May2nd 5:40 AM UTC time.
DeviceProcessEvents
| where DeviceName == target_machine
| where Timestamp between (Specific_StartDate_UTC .. Specific_EndDate_UTC )
| project Timestamp, ActionType, FileName, ProcessCommandline, AccountName, InitiatingProcessAccountName, InitiatingProcessParentFileName
| sort by Timestamp asc
```
**Finding:** This query provided the breakthrough. It revealed that a PowerShell script named [`portscan.ps1`](https://github.com/jorjuarez/Cybersecurity-Portfolio-Public/blob/main/project-sudden-network-slowdown/README.md#4portscanps1-found-in-device-newwindows10) was executed by the user account `analyst1`, perfectly matching the timeline of the network scan.

---

### Phase 3: Incident Response & Remediation
Upon identifying the unauthorized script execution as the root cause, immediate response actions were taken to contain the threat and plan for full recovery.

### Containment
The affected host, `nemwindows10`, was immediately isolated from the network using Microsoft Defender for Endpoint. This crucial first step prevented any potential lateral movement or further reconnaissance from the machine.

### Eradication & Recovery
An initial malware scan was performed on the isolated host, which yielded no results. However, due to the suspicious nature of the unauthorized script and to ensure no persistence mechanisms were left behind, a ticket was submitted to reimage and rebuild the host to a known-good, trusted state.

### Strategic Recommendations
This incident highlighted several opportunities to harden the environment against similar threats. The following strategic recommendations were developed and presented to the relevant teams:

* **Account Security:**
    * Investigate the `analyst1` account for any signs of compromise.
    * Enforce an immediate password reset and ensure multi-factor authentication (MFA) is active.
    * Interview the user to understand the circumstances of the script execution.
* **PowerShell Hardening:**
    * Configure the PowerShell Execution Policy to only allow signed or approved scripts.
    * Use AppLocker or WDAC (Windows Defender Application Control) to whitelist authorized scripts.
    * Implement Constrained Language Mode for standard users to limit access to sensitive commands.
* **Enhanced Monitoring:**
    * Improve logging and create new SIEM/EDR detection rules based on the specific behaviors observed in this incident.
    * Closely monitor the rebuilt `nemwindows10` host for any anomalous activity after it rejoins the network.
    * 
    ---

**Conclusion:**  
This project shows the value of using a structured framework like NIST 800-61 to investigate even minor anomalies with a security lens. This approach allowed us to move with speed, identify a policy violation, and uncover a threat vector before it could escalate into a more serious incident.

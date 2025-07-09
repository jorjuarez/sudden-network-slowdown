# Threat Hunt: Sudden Network Slowdown

### Executive Summary
A proactive threat hunt was initiated in response to network slowdown reports. The investigation traced the source to a host (`nemwindows10`) executing an unauthorized port scan via a PowerShell script. The host was immediately contained using Microsoft Defender for Endpoint, and strategic recommendations were developed to harden PowerShell security and improve detection capabilities across the enterprise.

---

### Phase 1: Preparation & Hypothesis

* **Goal:** Investigate the root cause of a significant network performance degradation affecting the `10.0.0.0/16` network. After ruling out external DDoS attacks, the security team suspected an internal issue.
* **Hypothesis:** Based on threat intelligence, a likely cause was an internal host either being used for lateral reconnaissance (port scanning) or consuming excessive bandwidth through unauthorized software.

---

### Phase 2: Investigation & Analysis

The investigation began by querying Microsoft Defender XDR logs to test the hypothesis.

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

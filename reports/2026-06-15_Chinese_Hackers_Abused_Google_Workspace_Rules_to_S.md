# CTI Report: Chinese Hackers Abused Google Workspace Rules to Steal Research and Defense Emails

| Field | Value |
| --- | --- |
| Source | The Hacker News |
| Published | 2026-06-15 19:44 UTC |
| URL | [https://thehackernews.com/2026/06/chinese-hackers-abused-google-workspace.html](https://thehackernews.com/2026/06/chinese-hackers-abused-google-workspace.html) |
| Report Generated | 2026-06-16 12:37 UTC |
| Model | qwen3:8b |
| LLM Processing Time | 292.03s |

---

## Executive Summary

A China-linked espionage group, UNC6508, used a backdoor in REDCap research servers to steal sensitive research and defense emails by abusing Google Workspace content compliance rules to exfiltrate data.

## Threat Actors

### UNC6508
- **Aliases:** —
- **Attribution:** China-linked
- **Motivation:** Steal sensitive research and defense emails
- **Confidence:** High
- **Evidence:** Google's Threat Intelligence Group attributes the campaign to UNC6508 with high confidence.

## Campaigns

### UNC6508 Campaign
- **Aliases:** —
- **Confidence:** High
- **Description:** A long-term espionage campaign involving the use of a REDCap backdoor and Google Workspace rules to exfiltrate sensitive data.
- **Evidence:** Google's Threat Intelligence Group laid out the campaign in a report and attributes it to UNC6508.

## Malware

### INFINITERED (Backdoor)
- **Aliases:** —
- **Confidence:** High
- **Description:** Custom malware that trojanizes REDCap's system files, hijacks the upgrade process, harvests credentials, and acts as a backdoor.

## Indicators of Compromise

| IOC Value | Type | Confidence | Context |
| --- | --- | --- | --- |
| REDCap | Filename | High | The compromised platform used by the attackers to gain initial access. |
| INFINITERED | Filename | High | The custom malware deployed by UNC6508. |
| Patroit | Email | High | The misspelled rule name used in Google Workspace to exfiltrate data. |
| chikungunya | URL | High | A specific keyword used in the exfiltration rule. |

## Observed Behaviors

**1. The attackers compromised externally facing REDCap servers to gain initial access.**
- Category: Initial Access  |  Confidence: High
- Evidence: _UNC6508 compromised externally facing REDCap servers._
- Artifacts: `REDCap`

**2. The attackers deployed custom malware to hijack the REDCap upgrade process and harvest credentials.**
- Category: Persistence  |  Confidence: High
- Evidence: _The malware hijacks the upgrade process so each new REDCap version reinjects the code instead of clearing it._
- Artifacts: `INFINITERED`

**3. The attackers used Google Workspace content compliance rules to exfiltrate data by copying messages matching specific keywords to an attacker-controlled Gmail address.**
- Category: Exfiltration  |  Confidence: High
- Evidence: _UNC6508 abused content compliance rules to copy any message matching their keywords to an inbox they controlled._
- Artifacts: `Patroit, chikungunya`

**4. The attackers harvested usernames and passwords from the REDCap login page and stored them in local database tables.**
- Category: Credential Access  |  Confidence: High
- Evidence: _The malware harvests usernames and passwords from the login page and stores them, encrypted, in local database tables._
- Artifacts: `—`

**5. The attackers used stolen credentials to move into the internal network and access a domain administrator account.**
- Category: Lateral Movement  |  Confidence: High
- Evidence: _Once on the server, UNC6508 ran internal reconnaissance and credential discovery, pulling database and service account credentials, then used those logins to move into the internal network and on to a domain administrator account._
- Artifacts: `—`

## MITRE ATT&CK Mapping

| Tactic | Technique ID | Technique Name | Observed Behavior | Confidence | Similarity |
| --- | --- | --- | --- | --- | --- |
| Unknown | `T1110.004` | Credential Stuffing | The attackers harvested usernames and passwords from the REDCap login  | High | 0.81 |
| Unknown | `T1078.003` | Local Accounts | The attackers harvested usernames and passwords from the REDCap login  | Medium | 0.80 |
| Unknown | `T1212` | Exploitation for Credential Access | The attackers harvested usernames and passwords from the REDCap login  | Medium | 0.80 |
| Unknown | `T1078` | Valid Accounts | The attackers used stolen credentials to move into the internal networ | Medium | 0.78 |
| Unknown | `T1078.002` | Domain Accounts | The attackers used stolen credentials to move into the internal networ | Medium | 0.78 |
| Unknown | `T1556.001` | Domain Controller Authentication | The attackers used stolen credentials to move into the internal networ | Medium | 0.77 |
| Unknown | `T1070.009` | Clear Persistence | The attackers deployed custom malware to hijack the REDCap upgrade pro | Medium | 0.77 |
| Unknown | `T1037.004` | RC Scripts | The attackers deployed custom malware to hijack the REDCap upgrade pro | Medium | 0.75 |
| Unknown | `T1584.006` | Web Services | The attackers used Google Workspace content compliance rules to exfilt | Medium | 0.74 |
| Unknown | `T1546` | Event Triggered Execution | The attackers deployed custom malware to hijack the REDCap upgrade pro | Medium | 0.74 |
| Unknown | `T1020` | Automated Exfiltration | The attackers used Google Workspace content compliance rules to exfilt | Medium | 0.74 |
| Unknown | `T1114.002` | Remote Email Collection | The attackers used Google Workspace content compliance rules to exfilt | Medium | 0.74 |
| Unknown | `T1108` | Redundant Access | The attackers compromised externally facing REDCap servers to gain ini | Medium | 0.72 |
| Unknown | `T1650` | Acquire Access | The attackers compromised externally facing REDCap servers to gain ini | Medium | 0.72 |
| Unknown | `T1584.004` | Server | The attackers compromised externally facing REDCap servers to gain ini | Medium | 0.71 |

## Threat Hunt Hypotheses

### Hypothesis 1 — ✅ Huntable
> Adversary activity consistent with the Unknown tactic may be present. Observed techniques: T1110.004 (Credential Stuffing), T1078.003 (Local Accounts), T1212 (Exploitation for Credential Access) and 12 more. Look for artifacts: REDCap, INFINITERED, Patroit, chikungunya.

**Evidence:** UNC6508 compromised externally facing REDCap servers. | The malware hijacks the upgrade process so each new REDCap version reinjects the code instead of clearing it. | UNC6508 abused content compliance rules to copy any message matching their keywords to an inbox they controlled.
**Techniques:** `T1110.004`, `T1078.003`, `T1212`, `T1078`, `T1078.002`, `T1556.001`, `T1070.009`, `T1037.004`, `T1584.006`, `T1546`, `T1020`, `T1114.002`, `T1108`, `T1650`, `T1584.004`
**Reason:** 15 technique(s) mapped under Unknown with High confidence; 4 observable artifact(s) identified.

**Data Sources:**
  - EDR
  - Sysmon

**Required Telemetry:**
  - Search for artifact: REDCap
  - Search for artifact: INFINITERED
  - Search for artifact: Patroit
  - EDR process events
  - System logs

**Sigma Detection Stub:**
```yaml
title: Valid Account Used from Unusual Location
logsource:
  category: authentication
  product: windows
detection:
  selection:
    EventID: 4624
    LogonType: 10
  condition: selection
```

## Huntability Assessment

| Hypothesis (truncated) | Huntable | Technique(s) | Reason |
| --- | --- | --- | --- |
| Adversary activity consistent with the Unknown tactic may be… | ✅ | T1110.004, T1078.003, T1212, T1078, T1078.002, T1556.001, T1070.009, T1037.004, T1584.006, T1546, T1020, T1114.002, T110 | 15 technique(s) mapped under Unknown with High confidence; 4 observable artifact |

---
*Generated by CTI Pipeline | 2026-06-16 12:37 UTC*
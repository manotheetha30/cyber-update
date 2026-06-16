# CTI Report: Google exposes China espionage group that’s been lurking in networks undetected since 2023

| Field | Value |
| --- | --- |
| Source | CyberScoop |
| Published | 2026-06-15 20:11 UTC |
| URL | [https://cyberscoop.com/google-unc6508-china-espionage-threat/](https://cyberscoop.com/google-unc6508-china-espionage-threat/) |
| Report Generated | 2026-06-16 12:37 UTC |
| Model | qwen3:8b |
| LLM Processing Time | 249.44s |

---

## Executive Summary

Google uncovered a Chinese state-sponsored espionage group, UNC6508, that has been operating stealthily since 2023, targeting organizations in the U.S. and Canada. The group used a custom backdoor called INFINITERED to steal credentials and data from medical research institutions and other critical sectors.

## Threat Actors

### UNC6508
- **Aliases:** —
- **Attribution:** Chinese state-sponsored
- **Motivation:** Steal data with national security implications
- **Confidence:** High
- **Evidence:** Google Threat Intelligence Group confirmed the group's activities and attributed them to China's government.

## Campaigns

### UNC6508 campaign
- **Aliases:** —
- **Confidence:** High
- **Description:** A long-term espionage campaign targeting medical research, government, and private organizations, with stealthy operations and data exfiltration.
- **Evidence:** Google confirmed multiple victims compromised with INFINITERED, and the group remained active for over a year.

## Malware

### INFINITERED (Backdoor)
- **Aliases:** —
- **Confidence:** High
- **Description:** A custom backdoor deployed by UNC6508 to steal administrative credentials after exploiting REDCap servers.

## Indicators of Compromise

| IOC Value | Type | Confidence | Context |
| --- | --- | --- | --- |
| REDCap | Domain | High | The threat group exploited externally facing REDCap servers. |
| INFINITERED | URL | High | Custom backdoor deployed by UNC6508. |

## Observed Behaviors

**1. Exploited externally facing REDCap servers to deploy the INFINITERED backdoor.**
- Category: Initial Access  |  Confidence: High
- Evidence: _Google said it confirmed multiple victims compromised with INFINITERED, a custom backdoor the threat group deployed on targeted networks to steal administrative credentials after it exploited externally facing REDCap servers._
- Artifacts: `REDCap`

**2. Used a custom backdoor to steal administrative credentials.**
- Category: Credential Access  |  Confidence: High
- Evidence: _Google said it confirmed multiple victims compromised with INFINITERED, a custom backdoor the threat group deployed on targeted networks to steal administrative credentials after it exploited externally facing REDCap servers._
- Artifacts: `INFINITERED`

**3. Abused domain compliance rules to steal data without relying on malware or living-off-the-land tools.**
- Category: Collection  |  Confidence: High
- Evidence: _Researchers said the threat group abused domain compliance rules to steal data, a technique that doesn’t rely on malware or living-off-the-land tools._
- Artifacts: `—`

**4. Routed traffic through U.S.-based IPs to blend in with legitimate traffic.**
- Category: Exfiltration  |  Confidence: High
- Evidence: _Researchers said the threat group routed traffic through U.S.-based IPs to blend in with legitimate traffic._
- Artifacts: `—`

**5. Used a Gmail account to exfiltrate data.**
- Category: Exfiltration  |  Confidence: High
- Evidence: _Google said it disrupted some of UNC6508’s known infrastructure by disabling a Gmail account it used to exfiltrate data._
- Artifacts: `Gmail account`

## MITRE ATT&CK Mapping

| Tactic | Technique ID | Technique Name | Observed Behavior | Confidence | Similarity |
| --- | --- | --- | --- | --- | --- |
| Unknown | `T1212` | Exploitation for Credential Access | Used a custom backdoor to steal administrative credentials. | High | 0.80 |
| Unknown | `T1011` | Exfiltration Over Other Network Medium | Routed traffic through U.S.-based IPs to blend in with legitimate traf | Medium | 0.79 |
| Unknown | `T1110.004` | Credential Stuffing | Used a custom backdoor to steal administrative credentials. | Medium | 0.78 |
| Unknown | `T1003` | OS Credential Dumping | Used a custom backdoor to steal administrative credentials. | Medium | 0.78 |
| Unknown | `T1567` | Exfiltration Over Web Service | Routed traffic through U.S.-based IPs to blend in with legitimate traf | Medium | 0.78 |
| Unknown | `T1586.002` | Email Accounts | Used a Gmail account to exfiltrate data. | Medium | 0.78 |
| Unknown | `T1048` | Exfiltration Over Alternative Protocol | Routed traffic through U.S.-based IPs to blend in with legitimate traf | Medium | 0.77 |
| Unknown | `T1583.001` | Domains | Abused domain compliance rules to steal data without relying on malwar | Medium | 0.77 |
| Unknown | `T1590.001` | Domain Properties | Abused domain compliance rules to steal data without relying on malwar | Medium | 0.77 |
| Unknown | `T1585.002` | Email Accounts | Used a Gmail account to exfiltrate data. | Medium | 0.76 |
| Unknown | `T1119` | Automated Collection | Abused domain compliance rules to steal data without relying on malwar | Medium | 0.76 |
| Unknown | `T1087` | Account Discovery | Used a Gmail account to exfiltrate data. | Medium | 0.75 |
| Unknown | `T1525` | Implant Internal Image | Exploited externally facing REDCap servers to deploy the INFINITERED b | Medium | 0.70 |
| Unknown | `T1108` | Redundant Access | Exploited externally facing REDCap servers to deploy the INFINITERED b | Medium | 0.70 |
| Unknown | `T1190` | Exploit Public-Facing Application | Exploited externally facing REDCap servers to deploy the INFINITERED b | Medium | 0.70 |

## Threat Hunt Hypotheses

### Hypothesis 1 — ✅ Huntable
> Adversary activity consistent with the Unknown tactic may be present. Observed techniques: T1212 (Exploitation for Credential Access), T1011 (Exfiltration Over Other Network Medium), T1110.004 (Credential Stuffing) and 12 more. Look for artifacts: REDCap, INFINITERED, Gmail account.

**Evidence:** Google said it confirmed multiple victims compromised with INFINITERED, a custom backdoor the threat group deployed on targeted networks to steal administrative credentials after it exploited externally facing REDCap servers. | Google said it confirmed multiple victims compromised with INFINITERED, a custom backdoor the threat group deployed on targeted networks to steal administrative credentials after it exploited externally facing REDCap servers. | Researchers said the threat group abused domain compliance rules to steal data, a technique that doesn’t rely on malware or living-off-the-land tools.
**Techniques:** `T1212`, `T1011`, `T1110.004`, `T1003`, `T1567`, `T1586.002`, `T1048`, `T1583.001`, `T1590.001`, `T1585.002`, `T1119`, `T1087`, `T1525`, `T1108`, `T1190`
**Reason:** 15 technique(s) mapped under Unknown with High confidence; 3 observable artifact(s) identified.

**Data Sources:**
  - EDR
  - Sysmon

**Required Telemetry:**
  - Search for artifact: REDCap
  - Search for artifact: INFINITERED
  - Search for artifact: Gmail account
  - EDR process events
  - System logs

**Sigma Detection Stub:**
```yaml
title: Exploit Public-Facing Application
logsource:
  category: webserver
detection:
  selection:
    sc-status:
      - 500
      - 400
    cs-uri-query|contains:
      - '../'
      - 'cmd='
      - 'exec('
  condition: selection
```

## Huntability Assessment

| Hypothesis (truncated) | Huntable | Technique(s) | Reason |
| --- | --- | --- | --- |
| Adversary activity consistent with the Unknown tactic may be… | ✅ | T1212, T1011, T1110.004, T1003, T1567, T1586.002, T1048, T1583.001, T1590.001, T1585.002, T1119, T1087, T1525, T1108, T1 | 15 technique(s) mapped under Unknown with High confidence; 3 observable artifact |

---
*Generated by CTI Pipeline | 2026-06-16 12:37 UTC*
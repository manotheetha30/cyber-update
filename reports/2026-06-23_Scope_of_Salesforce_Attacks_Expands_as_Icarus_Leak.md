# Threat Hunt Generation Report: Scope of Salesforce Attacks Expands as Icarus Leaks Data

| Field               | Value                                                                                                                                                                                                                  |
| ------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Source              | Dark Reading                                                                                                                                                                                                           |
| Published           | 2026-06-23 20:44 UTC                                                                                                                                                                                                   |
| URL                 | [https://www.darkreading.com/cyberattacks-data-breaches/scope-salesforce-attacks-expands-icarus-leaks-data](https://www.darkreading.com/cyberattacks-data-breaches/scope-salesforce-attacks-expands-icarus-leaks-data) |
| Classification      | Security Incident                                                                                                                                                                                                      |
| Report Generated    | 2026-06-24 23:50 UTC                                                                                                                                                                                                   |
| Model               | cth-qwen:latest                                                                                                                                                                                                        |
| LLM Processing Time | 1088.6s                                                                                                                                                                                                                |

---

## Executive Summary

The Icarus extortion group exploited Klue's OAuth tokens to steal Salesforce data from multiple technology and cybersecurity companies, including LastPass, HackerOne, and Gong. The attackers exfiltrated customer data to a Dark Web site and warned of more victims, prompting affected organizations to suspend access to Klue and rotate API tokens.

## Threat Actors

### Icarus

- **Aliases:** —
- **Motivation:** —
- **Evidence:** Claimed responsibility for attacks, posted stolen data on Dark Web site, and issued a deadline for Klue customers to contact the group.

## Campaigns

### Icarus Campaign

- **Aliases:** —
- **Description:** Exploitation of Klue's OAuth tokens to access Salesforce instances, exfiltration of customer data to Dark Web, and extortion of affected organizations.
- **Evidence:** Icarus took credit for attacks, posted victim data, and warned of more victims.

## Malware

_None identified._

## Indicators of Compromise

| IOC Value                                     | Type       | Context                                                           |
| --------------------------------------------- | ---------- | ----------------------------------------------------------------- |
| klue.com                                      | Domain     | Klue's OAuth tokens were used to access Salesforce data.          |
| salesforce.com                                | Domain     | Attackers accessed Salesforce instances of multiple companies.    |
| four suspicious IP addresses provided by Klue | IP Address | Gong blocked these IPs after detecting compromised customer data. |

## Observed Behaviors

**1. OAuth tokens from Klue used to access Salesforce customer data**

- **Evidence:** Attackers breached Klue and used its OAuth tokens to steal customers' Salesforce data.
- **Artifacts:** `OAuth tokens`, `Salesforce data`
- **Context:** Initial breach of Klue's integration with Salesforce instances.

**2. Suspension of company access to Klue**

- **Evidence:** LastPass and other companies suspended all company access to Klue following the breach.
- **Artifacts:** `Klue integration`
- **Context:** Mitigation steps taken by affected organizations.

**3. Rotation of exposed API access tokens**

- **Evidence:** LastPass rotated exposed API access tokens after detecting the breach.
- **Context:** Post-breach mitigation actions.

**4. Data exfiltrated to Dark Web site by Icarus group**

- **Evidence:** Icarus posted victims' data on its Dark Web leak site, with company names partially redacted.
- **Artifacts:** `Dark Web site`
- **Context:** Extortion group's data exfiltration method.

**5. Klue integration with Gong accessed internal user data**

- **Evidence:** Gong stated attackers may have accessed internal licensed user data for customers using Klue integration.
- **Artifacts:** `Klue integration`, `Gong user data`
- **Context:** Secondary impact of Klue breach on Gong's customers.

## MITRE ATT&CK Mapping

| Tactic               | Technique ID | Technique Name                                        | Observed Behavior                                              |
| -------------------- | ------------ | ----------------------------------------------------- | -------------------------------------------------------------- |
| Credential Access    | `T1528`      | Steal Application Access Token                        | OAuth tokens from Klue used to access Salesforce customer data |
| Impact               | `T1531`      | Account Access Removal                                | Suspension of company access to Klue                           |
| Privilege Escalation | `T1134.003`  | Access Token Manipulation: Make and Impersonate Token | Rotation of exposed API access tokens                          |
| Exfiltration         | `T1567`      | Exfiltration Over Web Service                         | Data exfiltrated to Dark Web site by Icarus group              |
| Initial Access       | `T1199`      | Trusted Relationship                                  | Klue integration with Gong accessed internal user data         |

## PEAK Hunt Hypotheses

### Hunt 1

#### Prepare

- **Hypothesis:** Adversaries may be using stolen OAuth tokens to access Salesforce customer data.
- **Behavior Basis:** OAuth tokens from Klue used to access Salesforce customer data
- **Objective:** Validate if stolen OAuth tokens are being used to access Salesforce instances.
- **Required Data Sources:** OAuth token usage logs, Network traffic to Salesforce endpoints

#### Execute

**Gather Data**

- Collect logs showing OAuth token usage and network connections to Salesforce instances

**Analysis Steps**

- Correlate OAuth token usage with network connections to Salesforce endpoints
- Check for unusual authentication patterns or data transfer volumes

**Supporting Evidence**

- Presence of OAuth tokens in network requests to Salesforce
- Unusual data transfer volumes to Salesforce endpoints

#### Act

- **Documentation Requirements:** Document validated OAuth token usage and network connections to Salesforce.

**Findings to Preserve**

- Validated OAuth token usage
- Network connections to Salesforce endpoints

**Future Hunt Recommendations**

- Monitor for unusual OAuth token usage patterns
- Track data transfer volumes to external services

### Hunt 2

#### Prepare

- **Hypothesis:** Adversaries may be exfiltrating data to a Dark Web site.
- **Behavior Basis:** Data exfiltrated to Dark Web site by Icarus group
- **Objective:** Validate if data is being exfiltrated to the Dark Web site.
- **Required Data Sources:** Network logs for outbound connections to the Dark Web site

#### Execute

**Gather Data**

- Collect network logs for outbound connections to the Dark Web site

**Analysis Steps**

- Identify outbound connections to the Dark Web site
- Analyze data transfer patterns and file sizes

**Supporting Evidence**

- Outbound connections to the Dark Web site
- Large data transfers to the site

#### Act

- **Documentation Requirements:** Document exfiltration attempts and data transfer patterns.

**Findings to Preserve**

- Outbound connections to the Dark Web site
- Data transfer patterns

**Future Hunt Recommendations**

- Monitor for connections to known malicious domains
- Track data exfiltration patterns to external sites

---

_Generated by Threat Hunt Generation Pipeline | 2026-06-24 23:50 UTC_

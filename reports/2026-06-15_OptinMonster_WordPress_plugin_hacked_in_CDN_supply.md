# CTI Report: OptinMonster WordPress plugin hacked in CDN supply-chain attack

| Field | Value |
| --- | --- |
| Source | BleepingComputer |
| Published | 2026-06-15 17:37 UTC |
| URL | [https://www.bleepingcomputer.com/news/security/optinmonster-wordpress-plugin-hacked-in-cdn-supply-chain-attack/](https://www.bleepingcomputer.com/news/security/optinmonster-wordpress-plugin-hacked-in-cdn-supply-chain-attack/) |
| Report Generated | 2026-06-16 12:37 UTC |
| Model | qwen3:8b |
| LLM Processing Time | 4029.77s |

---

## Executive Summary

A supply-chain attack compromised the OptinMonster, TrustPulse, and PushEngage WordPress plugins via Awesome Motive's CDN, allowing attackers to inject malicious scripts and gain full control of affected websites. The attack exploited a known flaw in UpdraftPlus and used stolen CDN credentials to distribute malware through compromised JavaScript files.

## Threat Actors

### Unknown
- **Aliases:** —
- **Attribution:** —
- **Motivation:** Steal credentials and control websites
- **Confidence:** Medium
- **Evidence:** Attackers modified JavaScript files distributed via Awesome Motive's CDN and stole CDN API keys.

## Campaigns

### CDN Supply-Chain Attack
- **Aliases:** —
- **Confidence:** High
- **Description:** Attackers compromised WordPress plugins through a content distribution network (CDN) to inject malicious scripts into websites.
- **Evidence:** Malicious scripts were served to OptinMonster and TrustPulse users via Awesome Motive's CDN.

## Malware

### Self-hiding backdoor plugin (Backdoor)
- **Aliases:** —
- **Confidence:** High
- **Description:** A plugin that provides full remote access and arbitrary PHP code execution.

### WPM File Manager & Shell (Backdoor)
- **Aliases:** —
- **Confidence:** High
- **Description:** A web shell granting attackers full control of compromised websites.

## Indicators of Compromise

| IOC Value | Type | Confidence | Context |
| --- | --- | --- | --- |
| a.omappapi.com | Domain | High | OptinMonster |
| a.opmnstr.com | Domain | High | OptinMonster |
| a.optnmstr.com | Domain | High | OptinMonster |
| a.trstplse.com | Domain | High | TrustPulse |
| content-delivery-helper, v2.7.1 | Filename | High | Malicious plugin disguise |
| database-optimizer, v2.9.4 | Filename | High | Malicious plugin disguise |
| api.min.js | Filename | High | Malicious JavaScript file |
| CVE | CVE | Medium | Exploited known flaw in UpdraftPlus |

## Observed Behaviors

**1. Malicious scripts were served to unsuspecting users via a compromised CDN.**
- Category: Initial Access  |  Confidence: High
- Evidence: _Malicious scripts were served to unsuspecting OptinMonster and TrustPulse users on Friday between 22:17 UTC and 22:42 UTC._
- Artifacts: `api.min.js`

**2. Attackers collected authentication tokens and nonces to create a rogue administrator account.**
- Category: Credential Access  |  Confidence: High
- Evidence: _The malware triggered only when a WordPress administrator visited a page on an infected website, collecting authentication tokens and nonces, and using them to create a rogue administrator account._
- Artifacts: `authentication tokens, nonces`

**3. Attackers installed a self-hiding backdoor plugin and established a communication channel with a domain impersonating Tidio.**
- Category: Command and Control  |  Confidence: High
- Evidence: _The intruders then installed a self-hiding backdoor plugin and established a communication channel with a domain impersonating Tidio to send any newly captured data._
- Artifacts: `—`

**4. Attackers provided full remote access capabilities, including a web shell and arbitrary PHP code execution.**
- Category: Privilege Escalation  |  Confidence: High
- Evidence: _The plugin also provided full remote access capabilities, including a web shell ('WPM File Manager & Shell') and arbitrary PHP code execution, granting attackers full control of compromised websites._
- Artifacts: `WPM File Manager & Shell, arbitrary PHP code execution`

**5. Attackers modified JavaScript files distributed via Awesome Motive's CDN to inject malicious code.**
- Category: Command and Control  |  Confidence: High
- Evidence: _Using the stolen CDN API key, the attackers modified JavaScript files distributed via Awesome Motive's CDN, causing websites to silently load malicious code directly from the CDN._
- Artifacts: `CDN API key, JavaScript files`

**6. Attackers created rogue administrator accounts to maintain access to compromised systems.**
- Category: Persistence  |  Confidence: High
- Evidence: _The malware triggered only when a WordPress administrator visited a page on an infected website, collecting authentication tokens and nonces, and using them to create a rogue administrator account._
- Artifacts: `rogue administrator account, developer_api1, dev_xxxxxx`

## MITRE ATT&CK Mapping

| Tactic | Technique ID | Technique Name | Observed Behavior | Confidence | Similarity |
| --- | --- | --- | --- | --- | --- |
| Unknown | `T1212` | Exploitation for Credential Access | Attackers collected authentication tokens and nonces to create a rogue | Medium | 0.80 |
| Unknown | `T1070.009` | Clear Persistence | Attackers created rogue administrator accounts to maintain access to c | Medium | 0.78 |
| Unknown | `T1589.001` | Credentials | Attackers collected authentication tokens and nonces to create a rogue | Medium | 0.78 |
| Unknown | `T1078` | Valid Accounts | Attackers collected authentication tokens and nonces to create a rogue | Medium | 0.78 |
| Unknown | `T1068` | Exploitation for Privilege Escalation | Attackers provided full remote access capabilities, including a web sh | Medium | 0.76 |
| Unknown | `T1108` | Redundant Access | Attackers provided full remote access capabilities, including a web sh | Medium | 0.76 |
| Unknown | `T1051` | Shared Webroot | Attackers provided full remote access capabilities, including a web sh | Medium | 0.76 |
| Unknown | `T1027.006` | HTML Smuggling | Attackers modified JavaScript files distributed via Awesome Motive's C | Medium | 0.75 |
| Unknown | `T1102.003` | One-Way Communication | Attackers installed a self-hiding backdoor plugin and established a co | Medium | 0.75 |
| Unknown | `T1207` | Rogue Domain Controller | Attackers created rogue administrator accounts to maintain access to c | Medium | 0.74 |
| Unknown | `T1480` | Execution Guardrails | Attackers installed a self-hiding backdoor plugin and established a co | Medium | 0.74 |
| Unknown | `T1102.002` | Bidirectional Communication | Attackers installed a self-hiding backdoor plugin and established a co | Medium | 0.74 |
| Unknown | `T1078.001` | Default Accounts | Attackers created rogue administrator accounts to maintain access to c | Medium | 0.74 |
| Unknown | `T1596.004` | CDNs | Attackers modified JavaScript files distributed via Awesome Motive's C | Medium | 0.73 |
| Unknown | `T1176` | Software Extensions | Attackers modified JavaScript files distributed via Awesome Motive's C | Medium | 0.73 |
| Unknown | `T1190` | Exploit Public-Facing Application | Malicious scripts were served to unsuspecting users via a compromised  | Medium | 0.72 |
| Unknown | `T1204.005` | Malicious Library | Malicious scripts were served to unsuspecting users via a compromised  | Medium | 0.71 |

## Threat Hunt Hypotheses

### Hypothesis 1 — ✅ Huntable
> Adversary activity consistent with the Unknown tactic may be present. Observed techniques: T1212 (Exploitation for Credential Access), T1070.009 (Clear Persistence), T1589.001 (Credentials) and 14 more. Look for artifacts: api.min.js, authentication tokens, nonces, WPM File Manager & Shell.

**Evidence:** Malicious scripts were served to unsuspecting OptinMonster and TrustPulse users on Friday between 22:17 UTC and 22:42 UTC. | The malware triggered only when a WordPress administrator visited a page on an infected website, collecting authentication tokens and nonces, and using them to create a rogue administrator account. | The intruders then installed a self-hiding backdoor plugin and established a communication channel with a domain impersonating Tidio to send any newly captured data.
**Techniques:** `T1212`, `T1070.009`, `T1589.001`, `T1078`, `T1068`, `T1108`, `T1051`, `T1027.006`, `T1102.003`, `T1207`, `T1480`, `T1102.002`, `T1078.001`, `T1596.004`, `T1176`, `T1190`, `T1204.005`
**Reason:** 17 technique(s) mapped under Unknown with Medium confidence; 10 observable artifact(s) identified.

**Data Sources:**
  - EDR
  - Sysmon

**Required Telemetry:**
  - Search for artifact: api.min.js
  - Search for artifact: authentication tokens
  - Search for artifact: nonces
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
| Adversary activity consistent with the Unknown tactic may be… | ✅ | T1212, T1070.009, T1589.001, T1078, T1068, T1108, T1051, T1027.006, T1102.003, T1207, T1480, T1102.002, T1078.001, T1596 | 17 technique(s) mapped under Unknown with Medium confidence; 10 observable artif |

---
*Generated by CTI Pipeline | 2026-06-16 12:37 UTC*
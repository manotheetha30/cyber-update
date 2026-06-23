# CTI Report: WhatsApp phishing attack uses fake business docs to hack PCs

| Field | Value |
| --- | --- |
| Source | BleepingComputer |
| Published | 2026-06-22 22:42 UTC |
| URL | [https://www.bleepingcomputer.com/news/security/whatsapp-phishing-attack-uses-fake-business-docs-to-hack-pcs/](https://www.bleepingcomputer.com/news/security/whatsapp-phishing-attack-uses-fake-business-docs-to-hack-pcs/) |
| Classification | Security Incident |
| Report Generated | 2026-06-23 09:35 UTC |
| Model | cth-qwen:latest |
| LLM Processing Time | 716.63s |

---

## Executive Summary

A WhatsApp phishing campaign targets users globally by distributing obfuscated VBScript files disguised as business documents. These scripts disable UAC via registry modifications, install ManageEngine Endpoint Central for remote access, and connect to attacker-controlled servers. The campaign spreads across multiple countries, with no confirmed attribution to a specific threat actor.

## Threat Actors

### Unknown
- **Aliases:** —
- **Motivation:** —
- **Evidence:** Researchers observed Chinese language use and infrastructure overlap with IPs previously associated with ValleyRAT and Gh0st RAT activity, but no high-confidence attribution is possible.

## Campaigns

### WhatsApp VBScript Phishing Campaign
- **Aliases:** —
- **Description:** A global phishing campaign using WhatsApp to distribute obfuscated VBScript files disguised as business documents, leading to remote system access via ManageEngine Endpoint Central.
- **Evidence:** Kaspersky telemetry shows the campaign spreads across Brazil, India, Mexico, Singapore, the UK, Spain, Taiwan, Australia, Russia, Vietnam, and Malaysia.

## Malware

### VBScript payload (Backdoor)
- **Aliases:** —
- **Description:** Obfuscated VBScript files disguised as business documents, used to initiate the infection chain by downloading additional scripts and disabling UAC.

### ManageEngine Endpoint Central (Backdoor)
- **Aliases:** —
- **Description:** Legitimate IT management software repurposed for remote administration access via attacker-controlled servers.

## Indicators of Compromise

_None extracted._

## Observed Behaviors

**1. VBScript executed via WhatsApp Desktop client using Windows Script Host (wscript.exe)**
- **Evidence:** Kaspersky notes that when the initial VBScript file is delivered via WhatsApp Web, it must be downloaded, but when opened in the WhatsApp Desktop client, it can be executed directly via Windows Script Host (wscript.exe).
- **Artifacts:** `wscript.exe`, `VBScript file`
- **Context:** Execution occurs after downloading the VBScript from a compromised WhatsApp contact.

**2. VBScript fetches additional scripts from attacker's infrastructure**
- **Evidence:** If the victim downloads and opens the file on Windows, the VBScript fetches two additional scripts from the attacker's infrastructure.
- **Artifacts:** `attacker's infrastructure`
- **Context:** This step disables UAC protections and downloads a ZIP archive containing ManageEngine Endpoint Central.

**3. Registry modifications to disable UAC protections**
- **Evidence:** The VBScript fetches two additional scripts from the attacker's infrastructure, which, in turn, disable UAC protections through Registry modifications.
- **Artifacts:** `Registry modifications`
- **Context:** This occurs as part of the infection chain to bypass system defenses.

**4. Silent installation of ManageEngine Endpoint Central**
- **Evidence:** The ZIP archive containing the ManageEngine Endpoint Central program is silently installed in the background.
- **Artifacts:** `ManageEngine Endpoint Central`
- **Context:** The software is configured to connect to attacker-controlled management servers for remote administration.

**5. Configuration of ManageEngine to connect to attacker-controlled servers**
- **Evidence:** The software is configured to connect to attacker-controlled management servers, giving them remote administration access on the victim’s computer.
- **Artifacts:** `attacker-controlled servers`
- **Context:** This enables persistent remote access and control over the victim's system.

## PEAK Hunt Hypotheses

_No hunt hypotheses generated._

## MITRE ATT&CK Mapping

| Tactic | Technique ID | Technique Name | Observed Behavior |
| --- | --- | --- | --- |
| Execution | `T1059.005` | Command and Scripting Interpreter: Visual Basic | VBScript executed via WhatsApp Desktop client using Windows Script Hos |
| Command and Control | `T1105` | Ingress Tool Transfer | VBScript fetches additional scripts from attacker's infrastructure |
| Defense Impairment | `T1112` | Modify Registry | Registry modifications to disable UAC protections |
| Execution | `T1072` | Software Deployment Tools | Silent installation of ManageEngine Endpoint Central |
| Command and Control | `T1219` | Remote Access Tools | Configuration of ManageEngine to connect to attacker-controlled server |

## Threat Hunt Hypotheses

### Hypothesis 1
> If a threat actor has compromised a system, they may use vbscript executed via whatsapp desktop client usin to execute malicious code or commands. Observable indicators include: wscript.exe, VBScript file, ManageEngine Endpoint Central. This aligns with ATT&CK technique(s): T1059.005, T1072.

**Evidence:** Kaspersky notes that when the initial VBScript file is delivered via WhatsApp Web, it must be downloaded, but when opened in the WhatsApp Desktop client, it can be executed directly via Windows Script Host (wscript.exe). | The ZIP archive containing the ManageEngine Endpoint Central program is silently installed in the background.
**Techniques:** `T1059.005`, `T1072`

**Data Sources:**
  - Sysmon
  - EDR
  - Windows Event Logs

**Required Telemetry:**
  - Search for artifact: wscript.exe
  - Search for artifact: VBScript file
  - Search for artifact: ManageEngine Endpoint Central
  - Sysmon Event ID 1 (process create)
  - Windows Event ID 4688
  - EDR process execution events

### Hypothesis 2
> If a threat actor has compromised a system, they may use infrastructure development to establish a command and control channel. Observable indicators include: attacker's infrastructure, attacker-controlled servers. This aligns with ATT&CK technique(s): T1105, T1219.

**Evidence:** If the victim downloads and opens the file on Windows, the VBScript fetches two additional scripts from the attacker's infrastructure. | The software is configured to connect to attacker-controlled management servers, giving them remote administration access on the victim’s computer.
**Techniques:** `T1105`, `T1219`

**Data Sources:**
  - Firewall Logs
  - DNS Logs
  - Proxy Logs

**Required Telemetry:**
  - Search for artifact: attacker's infrastructure
  - Search for artifact: attacker-controlled servers
  - DNS query logs
  - Proxy logs (unusual destinations/beaconing)
  - Network flow analysis

### Hypothesis 3
> If a threat actor has compromised a system, they may use registry modification to disable or bypass security controls and defenses. Observable indicators include: Registry modifications. This aligns with ATT&CK technique(s): T1112.

**Evidence:** The VBScript fetches two additional scripts from the attacker's infrastructure, which, in turn, disable UAC protections through Registry modifications.
**Techniques:** `T1112`

**Data Sources:**
  - EDR
  - Windows Event Logs
  - Sysmon

**Required Telemetry:**
  - Search for artifact: Registry modifications
  - Windows Event ID 4720 (firewall changes)
  - EDR tool disable events
  - Log deletion patterns

---
*Generated by CTI Pipeline | 2026-06-23 09:35 UTC*
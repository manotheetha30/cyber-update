# Threat Hunt Generation Report: FortiBleed campaign used custom FortiGate sniffer to steal credentials

| Field | Value |
| --- | --- |
| Source | BleepingComputer |
| Published | 2026-06-22 20:01 UTC |
| URL | [https://www.bleepingcomputer.com/news/security/fortibleed-campaign-used-custom-fortigate-sniffer-to-steal-credentials/](https://www.bleepingcomputer.com/news/security/fortibleed-campaign-used-custom-fortigate-sniffer-to-steal-credentials/) |
| Classification | Security Incident |
| Report Generated | 2026-06-23 13:34 UTC |
| Model | cth-qwen:latest |
| LLM Processing Time | 654.49s |

---

## Executive Summary

The FortiBleed campaign targeted FortiGate devices using a custom sniffer tool called FortigateSniffer to steal credentials. Threat actors exploited compromised FortiGate firewalls by leveraging the diagnose sniffer packet command to capture authentication traffic, extracting credentials from protocols like RADIUS, LDAP, and Kerberos. The stolen data was processed using tools like SNIFTRAN and Hashcat for password cracking.

## Threat Actors

_None identified._

## Campaigns

### FortiBleed
- **Aliases:** —
- **Description:** Large-scale campaign targeting FortiGate devices to harvest authentication secrets via custom sniffers. The operation compromised over 430,000 FortiGate firewalls globally.
- **Evidence:** SOCRadar's report details the campaign's activity since February 2026, including credential harvesting and exploitation of FortiOS's diagnose sniffer packet functionality.

## Malware

### FortigateSniffer (Backdoor)
- **Aliases:** —
- **Description:** Golang-based tool that abused FortiOS's diagnose sniffer packet command to capture authentication traffic, extracting credentials from protocols like RADIUS, NTLM, Kerberos, and LDAP.

## Indicators of Compromise

_None extracted._

## Observed Behaviors

**1. SSH used to deploy FortigateSniffer on compromised FortiGate devices**
- **Evidence:** The tool reportedly connects to FortiGate devices over SSH and launches the FortiOS diagnose sniffer packet command.
- **Artifacts:** `SSH`, `diagnose sniffer packet`
- **Context:** Deployed after initial access via credential stuffing and brute-force attacks.

**2. Diagnose sniffer packet command executed to capture network traffic**
- **Evidence:** The command was configured to monitor traffic for authentication protocols like Kerberos, LDAP, SMB, RADIUS, and others.
- **Artifacts:** `diagnose sniffer packet`, `Kerberos`, `LDAP`
- **Context:** Used to intercept authentication traffic passing through compromised FortiGate devices.

**3. SNIFTRAN component used to reconstruct captured traffic into PCAP files**
- **Evidence:** The packet data collected from FortiGate devices was processed through a component named 'SNIFTRAN' to reconstruct traffic into PCAP files.
- **Artifacts:** `SNIFTRAN`, `PCAP`
- **Context:** Part of the credential harvesting process.

**4. Python-based PCAP Deep Analysis Toolkit used to extract cleartext credentials**
- **Evidence:** The toolkit parsed captured traffic to extract cleartext credentials, password hashes, Kerberos tickets, and other authentication artifacts.
- **Artifacts:** `Python-based PCAP Deep Analysis Toolkit`, `cleartext credentials`, `password hashes`
- **Context:** Used after data collection to process and extract sensitive information.

**5. Hashcat used to crack NTLM and Kerberos hashes**
- **Evidence:** The toolkit generated Hashcat-ready files containing NTLM and Kerberos hashes, which were cracked using GPU-based Hashcat instances.
- **Artifacts:** `Hashcat`, `NTLM hashes`, `Kerberos hashes`
- **Context:** Password cracking conducted on a distributed GPU cluster.

**6. GPU-based password cracking performed on enterprise-class GPUs**
- **Evidence:** Threat actors allegedly used 36 enterprise-class GPUs rented from a GenAI company to crack hashed credentials via Hashcat.
- **Artifacts:** `Hashcat`, `GPU cluster`, `enterprise-class GPUs`
- **Context:** Cracking operation hosted on a GenAI company's GPU compute resources.

## PEAK Hunt Hypotheses

_No hunt hypotheses generated._

## MITRE ATT&CK Mapping

| Tactic | Technique ID | Technique Name | Observed Behavior |
| --- | --- | --- | --- |
| Credential Access | `T1040` | Network Sniffing | SSH used to deploy FortigateSniffer on compromised FortiGate devices |
| Credential Access | `T1040` | Network Sniffing | Diagnose sniffer packet command executed to capture network traffic |
| Discovery | `T1040` | Network Sniffing | SNIFTRAN component used to reconstruct captured traffic into PCAP file |
| Credential Access | `T1003` | OS Credential Dumping | Python-based PCAP Deep Analysis Toolkit used to extract cleartext cred |
| Credential Access | `T1110.002` | Brute Force: Password Cracking | Hashcat used to crack NTLM and Kerberos hashes |
| Credential Access | `T1110.002` | Brute Force: Password Cracking | GPU-based password cracking performed on enterprise-class GPUs |

## Threat Hunt Hypotheses

### Hypothesis 1
> If a threat actor has compromised a system, they may use ssh used to deploy fortigatesniffer on compromised to steal credentials and authentication tokens. Observable indicators include: SSH, diagnose sniffer packet, Kerberos, and 9 more. This aligns with ATT&CK technique(s): T1040, T1040, T1003, and 2 more.

**Evidence:** The tool reportedly connects to FortiGate devices over SSH and launches the FortiOS diagnose sniffer packet command. | The command was configured to monitor traffic for authentication protocols like Kerberos, LDAP, SMB, RADIUS, and others. | The toolkit parsed captured traffic to extract cleartext credentials, password hashes, Kerberos tickets, and other authentication artifacts.
**Techniques:** `T1040`, `T1040`, `T1003`, `T1110.002`, `T1110.002`

**Data Sources:**
  - Windows Event Logs
  - EDR
  - Sysmon

**Required Telemetry:**
  - Search for artifact: SSH
  - Search for artifact: diagnose sniffer packet
  - Search for artifact: Kerberos
  - Windows Event ID 4624/4625 (logon)
  - Sysmon Event ID 10 (process access)
  - LSASS access events

### Hypothesis 2
> If a threat actor has compromised a system, they may use reconnaissance activity to discover system configuration and network topology. Observable indicators include: SNIFTRAN, PCAP. This aligns with ATT&CK technique(s): T1040.

**Evidence:** The packet data collected from FortiGate devices was processed through a component named 'SNIFTRAN' to reconstruct traffic into PCAP files.
**Techniques:** `T1040`

**Data Sources:**
  - Sysmon
  - Windows Event Logs
  - EDR

**Required Telemetry:**
  - Search for artifact: SNIFTRAN
  - Search for artifact: PCAP
  - Sysmon Event ID 1 (net/whoami/ipconfig)
  - Windows Event ID 4688
  - Registry query events

---
*Generated by Threat Hunt Generation Pipeline | 2026-06-23 13:34 UTC*
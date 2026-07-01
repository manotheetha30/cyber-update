# Threat Hunt Generation Report: Malicious PyPI packages give hackers control of Telegram bot servers

| Field | Value |
| --- | --- |
| Source | BleepingComputer |
| Published | 2026-06-30 |
| URL | [https://www.bleepingcomputer.com/news/security/malicious-pypi-packages-give-hackers-control-of-telegram-bot-servers/](https://www.bleepingcomputer.com/news/security/malicious-pypi-packages-give-hackers-control-of-telegram-bot-servers/) |
| Classification | Security Incident |
| Report Generated | 2026-07-01 03:49 UTC |
| Model | cth-qwen:latest |
| LLM Processing Time | 874.93s |

---

## Executive Summary

A campaign targeting Python developers using Telegram bots has distributed trojanized Pyrogram forks via PyPI, enabling attackers to execute arbitrary commands, access files, and exfiltrate data. The malware, hidden in a backdoor file named secret.py, grants full control over compromised bot servers through hardcoded Telegram IDs in the OWNERS list.

## Threat Actors

_None identified._

## Campaigns

### Operation Navy Ghost
- **Aliases:** —
- **Description:** Campaign distributing malicious Pyrogram forks on PyPI to compromise Telegram bot servers
- **Evidence:** Packages published between November 2025 and June 2026, shared OWNERS list, identical backdoor code

## Malware

### secret.py (Backdoor)
- **Aliases:** —
- **Description:** Hidden backdoor file in Pyrogram forks that registers Telegram command handlers for remote code execution

## Indicators of Compromise

| IOC Value | Type | Context |
| --- | --- | --- |
| VLifeGram | Malware Name | Malicious Pyrogram fork with 4,150 downloads |
| VLife-Gram | Malware Name | Malicious Pyrogram fork with 1,030 downloads |
| pyrogram-navy | Malware Name | Malicious Pyrogram fork with 2,530 downloads |
| pyrogram-styled | Malware Name | Malicious Pyrogram fork with 15,370 downloads |
| pyrogram-zeeb | Malware Name | Malicious Pyrogram fork with 432 downloads |
| kelragram | Malware Name | Malicious Pyrogram fork with 1,041 downloads |
| sepgram | Malware Name | Malicious Pyrogram fork with 264 downloads |
| pyrogram-kelra | Malware Name | Malicious Pyrogram fork with 672 downloads |
| secret.py | Filename | Backdoor file hidden in helpers module of Pyrogram forks |

## Observed Behaviors

**1. Telegram command /asu executed to run Python code on victim's machine**
- **Evidence:** When the attacker sends /asu print(os.environ) to the victim’s bot, this function compiles and executes that Python code on the victim’s machine
- **Artifacts:** `secret.py`, `/asu print(os.environ)`
- **Context:** Remote code execution via Telegram bot commands

**2. Telegram command /asi executed to run shell commands on victim's server**
- **Evidence:** When the attacker sends /asi cat /etc/passwd, this runs /bin/bash -c “cat /etc/passwd” on the victim’s server and returns the output
- **Artifacts:** `secret.py`, `/asi cat /etc/passwd`
- **Context:** Remote command execution via Telegram bot commands

**3. File system access granted to read arbitrary files on compromised server**
- **Evidence:** Once the bot is active, the threat actor can read any file on the server, dump secrets, access the victim’s Telegram chats, download the database
- **Artifacts:** `secret.py`
- **Context:** Post-compromise data exfiltration

**4. Persistent backdoor installed via Telegram bot infrastructure**
- **Evidence:** The malware is designed to operate silently, suppressing errors and disabling logging
- **Artifacts:** `secret.py`
- **Context:** Long-term access maintenance

**5. Command output exfiltrated via Telegram messages or document attachments**
- **Evidence:** The command output is then returned via Telegram messages, and if it exceeds 4096 bytes, it is sent as a document attachment to the attackers
- **Artifacts:** `secret.py`
- **Context:** Data exfiltration mechanism

## MITRE ATT&CK Mapping

| Tactic | Technique ID | Technique Name | Observed Behavior |
| --- | --- | --- | --- |
| Execution | `T1059.006` | Command and Scripting Interpreter: Python | Telegram command /asu executed to run Python code on victim's machine |
| Execution | `T1059.004` | Command and Scripting Interpreter: Unix Shell | Telegram command /asi executed to run shell commands on victim's server |
| Stealth | `T1027` | Obfuscated Files or Information | File system access granted to read arbitrary files on compromised server |
| Persistence | `T1556.001` | Modify Authentication Process: Domain Controller Authentication | Persistent backdoor installed via Telegram bot infrastructure |
| Exfiltration | `T1041` | Exfiltration Over C2 Channel | Command output exfiltrated via Telegram messages or document attachments |

## PEAK Hunt Hypotheses

### Hunt 1

#### Prepare
- **Hypothesis:** Adversaries are using Telegram bot commands to execute arbitrary code on victim systems via Python and shell commands.
- **Behavior Basis:** Telegram commands /asu and /asi are used to execute Python code and shell commands respectively, with evidence of code execution and output exfiltration via Telegram.
- **Objective:** Identify Telegram bot interactions that trigger remote code execution and command output exfiltration.
- **Required Data Sources:** Telegram bot API interaction logs, Windows Process Creation Events (Event ID 4688), Network traffic logs to Telegram servers (e.g., telegram.org)

#### Execute

**Gather Data**
- Collect Telegram bot API logs for past 30 days, focusing on /asu and /asi commands
- Capture Windows Process Creation events with CommandLine containing 'python' or '/bin/bash'
- Filter network traffic to telegram.org for payloads or exfiltration patterns

**Analysis Steps**
- Correlate Telegram bot commands with process creation events showing Python/shell execution
- Check for base64-encoded or obfuscated payloads in command outputs
- Identify exfiltration patterns matching Telegram document attachment thresholds (4096 bytes)

**Hunt Query Logic**
- SELECT * FROM Telegram_Bot_Logs WHERE Command IN ('/asu', '/asi') AND Timestamp > NOW() - 30d
- SELECT * FROM Windows_Process_Creation WHERE CommandLine LIKE '%python%' OR CommandLine LIKE '%/bin/bash%' AND Timestamp > NOW() - 30d
- SELECT * FROM Network_Traffic WHERE Destination_Host = 'telegram.org' AND Destination_Port = 80 OR 443 AND Bytes_Transferred > 4096 AND Timestamp > NOW() - 30d

**Supporting Evidence**
- Telegram commands containing '/asu print(os.environ)' or '/asi cat /etc/passwd'
- Process execution with Python or bash that matches command output patterns
- Telegram document attachments with base64-encoded payloads or exfiltrated secrets

#### Act
- **Documentation Requirements:** Record all Telegram bot interaction timestamps, associated process execution details, and network exfiltration patterns.

**Findings to Preserve**
- Validated Telegram bot command execution vectors
- Baseline for normal Telegram bot usage patterns
- Exfiltration thresholds for document attachments

**Future Hunt Recommendations**
- Monitor Telegram bot API for anomalous command patterns
- Implement correlation between Telegram bot commands and process execution
- Track exfiltration attempts to Telegram servers with size thresholds

### Hunt 2

#### Prepare
- **Hypothesis:** Adversaries are maintaining persistence through a Telegram bot backdoor with suppressed logging and file system access capabilities.
- **Behavior Basis:** The malware suppresses errors, disables logging, and grants file system access for secret dumping and database exfiltration.
- **Objective:** Detect persistent Telegram bot backdoors with file system access and data exfiltration capabilities.
- **Required Data Sources:** Windows Registry changes (Event ID 1000), File system access logs (Event ID 4663), Scheduled Task logs (Event ID 1001)

#### Execute

**Gather Data**
- Collect registry changes related to Telegram bot configuration
- Capture file access events for sensitive files (e.g., /etc/passwd, database files)
- Check for scheduled tasks related to Telegram bot persistence

**Analysis Steps**
- Identify registry entries modifying Telegram bot execution parameters
- Correlate file access events with known sensitive file paths
- Verify persistence mechanisms through scheduled tasks or startup items

**Hunt Query Logic**
- SELECT * FROM Registry_Changes WHERE Key_Path LIKE '%Telegram_bot%' AND Timestamp > NOW() - 30d
- SELECT * FROM File_System_Access WHERE File_Path LIKE '%/etc/passwd%' OR File_Path LIKE '%database%' AND Timestamp > NOW() - 30d
- SELECT * FROM Scheduled_Tasks WHERE Task_Name LIKE '%Telegram_bot%' AND Timestamp > NOW() - 30d

**Supporting Evidence**
- Registry modifications disabling logging or error suppression
- File access to secrets or databases with unusual permissions
- Scheduled tasks maintaining Telegram bot persistence

#### Act
- **Documentation Requirements:** Document registry modifications, file access anomalies, and scheduled task persistence mechanisms.

**Findings to Preserve**
- Telegram bot persistence techniques
- File system access patterns for secret dumping
- Registry-based suppression of logging artifacts

**Future Hunt Recommendations**
- Monitor registry for unauthorized Telegram bot configurations
- Track file access to sensitive paths with Telegram bot context
- Validate scheduled task integrity for persistence detection

---
*Generated by Threat Hunt Generation Pipeline | 2026-07-01 03:49 UTC*
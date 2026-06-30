# Threat Hunt Generation Report: Clean GitHub repo tricks AI coding agents into running malware

| Field | Value |
| --- | --- |
| Source | BleepingComputer |
| Published | 2026-06-27 |
| URL | [https://www.bleepingcomputer.com/news/security/clean-github-repo-tricks-ai-coding-agents-into-running-malware/](https://www.bleepingcomputer.com/news/security/clean-github-repo-tricks-ai-coding-agents-into-running-malware/) |
| Classification | Security Incident |
| Report Generated | 2026-06-28 19:58 UTC |
| Model | cth-qwen:latest |
| LLM Processing Time | 530.89s |

---

## Executive Summary

Researchers demonstrated an attack method where a clean GitHub repository tricks AI coding agents into executing a reverse shell via a DNS TXT record lookup. The attack leverages automated setup commands to trigger a shell script without malicious code in the repository, granting attackers developer privileges and access to sensitive data.

## Threat Actors

_None identified._

## Malware

_None identified._

## Indicators of Compromise

_None extracted._

## Observed Behaviors

**1. Python package setup command executed to trigger shell script**
- **Evidence:** The Python package is designed to refuse execution until initialized, generating an error that prompts the AI agent to run 'python3 -m axiom init'.
- **Artifacts:** `python3 -m axiom init`, `axiom init`
- **Context:** The AI agent automatically executes the suggested command to 'fix' the error, initiating the attack chain.

**2. DNS TXT record queried to retrieve attacker-controlled configuration value**
- **Evidence:** Executing 'python3 -m axiom init' calls a shell script that retrieves the configuration value stored in a DNS TXT record controlled by the attacker.
- **Artifacts:** `DNS TXT record`
- **Context:** The DNS lookup fetches the attacker's configuration value, which is then executed as a command.

**3. Reverse shell established with developer privileges**
- **Evidence:** The attacker obtains a shell running with the developer’s privileges, granting access to sensitive data and opportunities for persistence.
- **Artifacts:** `shell`
- **Context:** The attack chain culminates in an interactive shell executed as the developer's user.

## MITRE ATT&CK Mapping

| Tactic | Technique ID | Technique Name | Observed Behavior |
| --- | --- | --- | --- |
| Execution | `T1059.006` | Command and Scripting Interpreter: Python | Python package setup command executed to trigger shell script |
| Reconnaissance | `T1590.002` | Gather Victim Network Information: DNS | DNS TXT record queried to retrieve attacker-controlled configuration value |
| Execution | `T1059.004` | Command and Scripting Interpreter: Unix Shell | Reverse shell established with developer privileges |

## PEAK Hunt Hypotheses

### Hunt 1

#### Prepare
- **Hypothesis:** Adversaries may be using Python to execute a shell script via a package setup command, which then queries a DNS TXT record to retrieve attacker-controlled configuration data.
- **Behavior Basis:** The Python package setup command executed to trigger a shell script (artifacts: 'python3 -m axiom init', 'axiom init') and the subsequent DNS TXT record query to retrieve attacker-controlled configuration value (artifact: 'DNS TXT record'). These actions form the initial attack chain.
- **Objective:** Identify instances of Python-based command execution followed by DNS TXT record queries for configuration exfiltration.
- **Required Data Sources:** Windows Security Event Log (Event ID 4688 - Process Creation), DNS Query Logs, Command Line History (e.g., PowerShell/terminal logs)

#### Execute

**Gather Data**
- Collect Windows Security Event ID 4688 for past 30 days. Extract: ProcessName, CommandLine, ParentImage, User.
- Aggregate DNS query logs for TXT record queries over the same timeframe.
- Extract command line history for processes invoking 'python3 -m axiom init' or 'axiom init'.

**Analysis Steps**
- Search for Python processes (e.g., 'python3.exe') with command lines containing 'axiom init'.
- Correlate DNS TXT record queries with the execution of 'python3 -m axiom init' within 5 seconds.
- Validate if the retrieved DNS TXT record content contains executable commands or payloads.

**Hunt Query Logic**
- WHERE process_name = 'python3.exe' AND command_line CONTAINS 'axiom init' AND execution_time > NOW() - 30 days
- DNS query type = TXT AND query_name CONTAINS 'attacker-controlled-subdomain' AND timestamp > NOW() - 30 days
- Correlate DNS TXT queries (targeting attacker-controlled domains) WITH process creation events for 'python3.exe' WITHIN 5 seconds

**Supporting Evidence**
- Python process execution with 'axiom init' in command line
- DNS TXT record queries for attacker-controlled domains
- Execution of retrieved configuration data from DNS TXT records

#### Act
- **Documentation Requirements:** Record the timestamp, process details, DNS query targets, and any executed configuration data. Note whether the configuration data was malicious or benign.

**Findings to Preserve**
- Python-based command execution patterns
- DNS TXT record queries for attacker-controlled domains
- Correlation between setup commands and DNS exfiltration

**Future Hunt Recommendations**
- Monitor for Python processes invoking 'axiom init' or similar commands
- Establish baselines for DNS TXT record queries to detect anomalies
- Track execution of retrieved DNS configuration data

### Hunt 2

#### Prepare
- **Hypothesis:** Adversaries may be establishing a reverse shell with developer privileges to maintain persistent access and exfiltrate data.
- **Behavior Basis:** The reverse shell established with developer privileges (artifact: 'shell') represents the culmination of the attack chain, granting access to sensitive data and persistence opportunities.
- **Objective:** Detect interactive shells executed with developer privileges that may indicate reverse shell establishment.
- **Required Data Sources:** Windows Security Event Log (Event ID 4688 - Process Creation), Process Environment Block (PEB) logs, Network Connection Logs (e.g., Netstat, WMI)

#### Execute

**Gather Data**
- Collect Windows Security Event ID 4688 for past 30 days. Extract: ProcessName, CommandLine, ParentImage, User, LogonID.
- Identify processes with elevated privileges (e.g., 'developer' user) and their associated network connections.
- Extract PEB logs to verify user context for shell execution.

**Analysis Steps**
- Filter processes executed by 'developer' user with unexpected command lines (e.g., shell interaction).
- Correlate shell execution with outbound network connections to external C2 infrastructure.
- Validate if the shell process has persistence mechanisms (e.g., scheduled tasks, registry keys).

**Hunt Query Logic**
- WHERE process_name = 'cmd.exe' OR process_name = 'powershell.exe' AND user = 'developer' AND execution_time > NOW() - 30 days
- Process creation (cmd.exe/powershell.exe) FOLLOWED_BY outbound network connection to external IP/domain WITHIN 5 seconds
- WHERE logon_id = 'developer' AND process_name = 'cmd.exe' AND command_line CONTAINS 'shell' OR 'reverse'

**Supporting Evidence**
- Interactive shell processes executed as 'developer' user
- Outbound network connections to external C2 servers
- Persistence artifacts created by the shell process

#### Act
- **Documentation Requirements:** Document the user context, process details, network connections, and any persistence mechanisms observed during shell execution.

**Findings to Preserve**
- Developer user shell execution patterns
- Network connections associated with reverse shells
- Persistence mechanisms linked to the shell

**Future Hunt Recommendations**
- Monitor for shell processes executed by non-admin users with suspicious command lines
- Track network connections from developer accounts to external domains
- Analyze PEB logs to validate user context for shell execution

---
*Generated by Threat Hunt Generation Pipeline | 2026-06-28 19:58 UTC*
# Threat Hunt Generation Report: JaredFromSubway MEV bot hacked in $15 million crypto theft

| Field | Value |
| --- | --- |
| Source | BleepingComputer |
| Published | 2026-06-22 21:52 UTC |
| URL | [https://www.bleepingcomputer.com/news/security/jaredfromsubway-mev-bot-hacked-in-15-million-crypto-theft/](https://www.bleepingcomputer.com/news/security/jaredfromsubway-mev-bot-hacked-in-15-million-crypto-theft/) |
| Classification | Security Incident |
| Report Generated | 2026-06-23 12:59 UTC |
| Model | cth-qwen:latest |
| LLM Processing Time | 435.32s |

---

## Executive Summary

The JaredFromSubway MEV bot suffered a $15 million loss after an attacker exploited its opportunity-detection logic by creating fake cryptocurrency trading opportunities. The attacker manipulated the bot's automated execution system to grant ERC-20 token approvals to attacker-controlled contracts, then used the transferFrom function to withdraw WETH, USDC, and USDT from the bot's contract.

## Threat Actors

### Attacker
- **Aliases:** —
- **Motivation:** —
- **Evidence:** Deployed fake MEV opportunities to trick the bot into granting ERC-20 token approvals to attacker-controlled contracts, then used transferFrom to siphon funds.

## Malware

_None identified._

## Indicators of Compromise

_None extracted._

## Observed Behaviors

**1. ERC-20 token approvals granted to attacker-controlled contracts**
- **Evidence:** The attacker deployed contracts designed to appear as profitable MEV opportunities to JaredFromSubway's automated execution system. The bot granted ERC-20 token approvals to contracts controlled by the attacker.
- **Artifacts:** `ERC-20 token approvals`, `attacker-controlled contracts`
- **Context:** Automated execution system analyzed routes and trade opportunities, generating transactions to execute them.

**2. TransferFrom function used to withdraw funds**
- **Evidence:** Finally, the attacker used the open approvals to withdraw WETH, USDC, and USDT from the JaredFromSubway MEV bot contract via the transferFrom function.
- **Artifacts:** `transferFrom function`
- **Context:** After accumulating valid spending permissions, the attacker executed the withdrawal.

**3. Early test transactions to validate bot action routines**
- **Evidence:** The attacker planned the heist carefully, as early transactions served as harmless tests to help confirm the bot’s action routines.
- **Artifacts:** `test transactions`
- **Context:** Initial phase of the attack to ensure the bot's execution logic was functioning as expected.

**4. Modified route to prevent approval revocation**
- **Evidence:** The attacker changed the route so that the allowance was not consumed or revoked after the bot granted approvals.
- **Artifacts:** `modified route`
- **Context:** After testing, the attacker adjusted the attack vector to maintain persistent access to the approvals.

## PEAK Hunt Hypotheses

_No hunt hypotheses generated._

## MITRE ATT&CK Mapping

| Tactic | Technique ID | Technique Name | Observed Behavior |
| --- | --- | --- | --- |
| Impact | `T1496.001` | Resource Hijacking: Compute Hijacking | ERC-20 token approvals granted to attacker-controlled contracts |
| Exfiltration | `T1537` | Transfer Data to Cloud Account | TransferFrom function used to withdraw funds |
| Stealth | `T1678` | Delay Execution | Early test transactions to validate bot action routines |
| Persistence | `T1556.009` | Modify Authentication Process: Conditional Access Policies | Modified route to prevent approval revocation |

## Threat Hunt Hypotheses

### Hypothesis 1
> If a threat actor has compromised a system, they may use erc-20 token approvals granted to attacker-control to disrupt or compromise system availability. Observable indicators include: ERC-20 token approvals, attacker-controlled contracts. This aligns with ATT&CK technique(s): T1496.001.

**Evidence:** The attacker deployed contracts designed to appear as profitable MEV opportunities to JaredFromSubway's automated execution system. The bot granted ERC-20 token approvals to contracts controlled by the attacker.
**Techniques:** `T1496.001`

**Data Sources:**
  - EDR
  - Windows Event Logs
  - Sysmon

**Required Telemetry:**
  - Search for artifact: ERC-20 token approvals
  - Search for artifact: attacker-controlled contracts
  - Windows Event ID 7045 (service install)
  - EDR process termination events
  - File encryption alerts

### Hypothesis 2
> If a threat actor has compromised a system, they may use transferfrom function used to withdraw funds to exfiltrate stolen data from the network. Observable indicators include: transferFrom function. This aligns with ATT&CK technique(s): T1537.

**Evidence:** Finally, the attacker used the open approvals to withdraw WETH, USDC, and USDT from the JaredFromSubway MEV bot contract via the transferFrom function.
**Techniques:** `T1537`

**Data Sources:**
  - Proxy Logs
  - Firewall Logs
  - PCAP / Network Capture

**Required Telemetry:**
  - Search for artifact: transferFrom function
  - Proxy POST volume anomalies
  - Firewall large outbound transfers
  - DNS tunneling patterns

### Hypothesis 3
> If a threat actor has compromised a system, they may use early test transactions to validate bot action rou to evade detection and remain undetected on the system. Observable indicators include: test transactions. This aligns with ATT&CK technique(s): T1678.

**Evidence:** The attacker planned the heist carefully, as early transactions served as harmless tests to help confirm the bot’s action routines.
**Techniques:** `T1678`

**Data Sources:**
  - EDR
  - Sysmon
  - Windows Event Logs

**Required Telemetry:**
  - Search for artifact: test transactions
  - Sysmon Event ID 7 (image load)
  - Windows Event ID 4663 (object access)
  - EDR evasion detection

### Hypothesis 4
> If a threat actor has compromised a system, they may use modified route to prevent approval revocation to maintain long-term access to the system. Observable indicators include: modified route. This aligns with ATT&CK technique(s): T1556.009.

**Evidence:** The attacker changed the route so that the allowance was not consumed or revoked after the bot granted approvals.
**Techniques:** `T1556.009`

**Data Sources:**
  - Sysmon
  - Windows Event Logs
  - EDR

**Required Telemetry:**
  - Search for artifact: modified route
  - Sysmon Event ID 13 (registry set)
  - Windows Event ID 4698 (scheduled task)
  - File modification events

---
*Generated by Threat Hunt Generation Pipeline | 2026-06-23 12:59 UTC*
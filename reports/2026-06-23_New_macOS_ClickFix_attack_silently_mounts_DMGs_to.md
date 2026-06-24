# Threat Hunt Generation Report: New macOS ClickFix attack silently mounts DMGs to push infostealer

| Field | Value |
| --- | --- |
| Source | BleepingComputer |
| Published | 2026-06-23 18:30 UTC |
| URL | [https://www.bleepingcomputer.com/news/security/new-macos-clickfix-attack-silently-mounts-dmgs-to-push-infostealer/](https://www.bleepingcomputer.com/news/security/new-macos-clickfix-attack-silently-mounts-dmgs-to-push-infostealer/) |
| Classification | Security Incident |
| Report Generated | 2026-06-24 06:20 UTC |
| Model | cth-qwen:latest |
| LLM Processing Time | 822.27s |

---

## Executive Summary

A new macOS ClickFix campaign uses Terminal commands to silently download and mount malicious DMG files, deploying the Atomic macOS Stealer (AMOS) infostealer. The attack leverages fake CAPTCHA pages to trick users into executing commands that download and launch malware, stealing sensitive data from browsers, cryptocurrency wallets, and system files.

## Threat Actors

### ClickFix
- **Aliases:** —
- **Motivation:** —
- **Evidence:** Used by cybercriminals and state-sponsored groups to distribute malware via social engineering.

## Campaigns

### ClickFix
- **Aliases:** —
- **Description:** Social engineering technique using fake CAPTCHAs and browser errors to trick users into executing malicious Terminal commands.
- **Evidence:** Campaign observed using fake CAPTCHA pages to deploy Atomic macOS Stealer via Terminal commands.

## Malware

### Atomic macOS Stealer (AMOS) (Infostealer)
- **Aliases:** —
- **Description:** Steals browser credentials, cryptocurrency wallet data, Keychain data, messaging app info, user documents, and replaces legitimate apps like Ledger Live and Trezor Suite with malicious versions.

## Indicators of Compromise

| IOC Value | Type | Context |
| --- | --- | --- |
| svs-verificationdate.beer | Domain | C2 server used to host malicious DMG files |
| 196.251.107.171 | IP Address | C2 server used for command-and-control |
| s.01M0td.dmg | Filename | Malicious DMG file name used in the attack |
| curl -fsSL | URL | Command used to download DMG file silently |
| hdiutil attach -nobrowse | URL | Command used to mount DMG without user interaction |
| NNApp.app | Filename | Self-signed application bundle mounted from DMG |
| Ledger Live | Filename | Legitimate app replaced by malware |
| Trezor Suite | Filename | Legitimate app replaced by malware |

## Observed Behaviors

**1. Terminal command executed to download malicious DMG file**
- **Evidence:** Researchers observed the malware being delivered as a disk image named 's.01M0td.dmg' after executing a Terminal command.
- **Artifacts:** `curl -fsSL`, `s.01M0td.dmg`, `/tmp`, `Terminal`
- **Context:** Command executed via fake CAPTCHA page to initiate the attack

**2. DMG file mounted using hdiutil utility**
- **Evidence:** The command executes 'hdiutil attach -nobrowse' to mount the downloaded disk image without displaying it in Finder.
- **Artifacts:** `hdiutil`, `DMG file`, `/tmp`
- **Context:** Mounting occurs silently to avoid user detection

**3. Script searches for and launches .app/.pkg installers**
- **Evidence:** The script searches up to three directory levels deep for the first available .app or .pkg installer and launches it using the macOS open command.
- **Artifacts:** `.app`, `.pkg`, `open command`
- **Context:** Automated process to execute the malware payload

**4. Infostealer steals data from Chromium-based browsers**
- **Evidence:** The malware targets eight Chromium-based browsers, stealing cookies, login databases, autofill info, and payment cards.
- **Artifacts:** `Google Chrome`, `Microsoft Edge`, `Brave`, `Opera`, `Arc`, `Vivaldi`, `CocCoc`, `Yandex`
- **Context:** Data exfiltration occurs after initial payload execution

**5. Infostealer steals cryptocurrency wallet data**
- **Evidence:** The malware steals data from wallets including Exodus, Electrum, Atomic Wallet, Wasabi Wallet, Bitcoin Core, Litecoin Core, DashCore, Guarda, Binance Wallet, Dogecoin Wallet, and TonKeeper.
- **Artifacts:** `Exodus`, `Electrum`, `Atomic Wallet`, `Wasabi Wallet`, `Bitcoin Core`, `Litecoin Core`, `DashCore`, `Guarda`, `Binance Wallet`, `Dogecoin Wallet`, `TonKeeper`
- **Context:** Wallet data is harvested post-infection

**6. Data stored in ZIP archive and uploaded to C2 server**
- **Evidence:** All harvested data is stored in a ZIP archive and uploaded to the attacker's server.
- **Artifacts:** `ZIP archive`, `svs-verificationdate.beer`
- **Context:** Final stage of data exfiltration

**7. Legitimate apps replaced with malicious versions**
- **Evidence:** The malware replaces legitimate installations of Ledger Live and Trezor Suite with malicious versions.
- **Artifacts:** `Ledger Live`, `Trezor Suite`
- **Context:** Persistence and ongoing data theft

## PEAK Hunt Hypotheses

_No hunt hypotheses generated._

## MITRE ATT&CK Mapping

| Tactic | Technique ID | Technique Name | Observed Behavior |
| --- | --- | --- | --- |
| Resource Development | `T1608.001` | Stage Capabilities: Upload Malware | Terminal command executed to download malicious DMG file |
| Stealth | `T1564.013` | Hide Artifacts: Bind Mounts | DMG file mounted using hdiutil utility |
| Execution | `T1574.008` | Hijack Execution Flow: Path Interception by Search Order Hijacking | Script searches for and launches .app/.pkg installers |
| Exfiltration | `T1041` | Exfiltration Over C2 Channel | Infostealer steals data from Chromium-based browsers |
| Impact | `T1657` | Financial Theft | Infostealer steals cryptocurrency wallet data |
| Collection | `T1560.002` | Archive Collected Data: Archive via Library | Data stored in ZIP archive and uploaded to C2 server |
| Stealth | `T1070.010` | Indicator Removal: Relocate Malware | Legitimate apps replaced with malicious versions |

## Threat Hunt Hypotheses

### Hypothesis 1
> If a threat actor has compromised a system, they may use command-line execution to acquire and develop tools, infrastructure, and capabilities for attack. Observable indicators include: curl -fsSL, s.01M0td.dmg, /tmp, and 1 more. This aligns with ATT&CK technique(s): T1608.001.

**Evidence:** Researchers observed the malware being delivered as a disk image named 's.01M0td.dmg' after executing a Terminal command.
**Techniques:** `T1608.001`

**Data Sources:**
  - Proxy Logs
  - DNS Logs
  - Firewall Logs

**Required Telemetry:**
  - Search for artifact: curl -fsSL
  - Search for artifact: s.01M0td.dmg
  - Search for artifact: /tmp
  - C2 infrastructure registration logs
  - Malware development artifacts
  - Domain registration patterns

### Hypothesis 2
> If a threat actor has compromised a system, they may use file operations to evade detection and remain undetected on the system. Observable indicators include: hdiutil, DMG file, /tmp, and 2 more. This aligns with ATT&CK technique(s): T1564.013, T1070.010.

**Evidence:** The command executes 'hdiutil attach -nobrowse' to mount the downloaded disk image without displaying it in Finder. | The malware replaces legitimate installations of Ledger Live and Trezor Suite with malicious versions.
**Techniques:** `T1564.013`, `T1070.010`

**Data Sources:**
  - EDR
  - Sysmon
  - Windows Event Logs

**Required Telemetry:**
  - Search for artifact: hdiutil
  - Search for artifact: DMG file
  - Search for artifact: /tmp
  - Sysmon Event ID 7 (image load)
  - Windows Event ID 4663 (object access)
  - EDR evasion detection

### Hypothesis 3
> If a threat actor has compromised a system, they may use script searches for and launches .app/.pkg install to execute malicious code or commands. Observable indicators include: .app, .pkg, open command. This aligns with ATT&CK technique(s): T1574.008.

**Evidence:** The script searches up to three directory levels deep for the first available .app or .pkg installer and launches it using the macOS open command.
**Techniques:** `T1574.008`

**Data Sources:**
  - Sysmon
  - EDR
  - Windows Event Logs

**Required Telemetry:**
  - Search for artifact: .app
  - Search for artifact: .pkg
  - Search for artifact: open command
  - Sysmon Event ID 1 (process create)
  - Windows Event ID 4688
  - EDR process execution events

### Hypothesis 4
> If a threat actor has compromised a system, they may use infostealer steals data from chromium-based browse to exfiltrate stolen data from the network. Observable indicators include: Google Chrome, Microsoft Edge, Brave, and 5 more. This aligns with ATT&CK technique(s): T1041.

**Evidence:** The malware targets eight Chromium-based browsers, stealing cookies, login databases, autofill info, and payment cards.
**Techniques:** `T1041`

**Data Sources:**
  - Proxy Logs
  - Firewall Logs
  - PCAP / Network Capture

**Required Telemetry:**
  - Search for artifact: Google Chrome
  - Search for artifact: Microsoft Edge
  - Search for artifact: Brave
  - Proxy POST volume anomalies
  - Firewall large outbound transfers
  - DNS tunneling patterns

### Hypothesis 5
> If a threat actor has compromised a system, they may use infostealer steals cryptocurrency wallet data to disrupt or compromise system availability. Observable indicators include: Exodus, Electrum, Atomic Wallet, and 8 more. This aligns with ATT&CK technique(s): T1657.

**Evidence:** The malware steals data from wallets including Exodus, Electrum, Atomic Wallet, Wasabi Wallet, Bitcoin Core, Litecoin Core, DashCore, Guarda, Binance Wallet, Dogecoin Wallet, and TonKeeper.
**Techniques:** `T1657`

**Data Sources:**
  - EDR
  - Windows Event Logs
  - Sysmon

**Required Telemetry:**
  - Search for artifact: Exodus
  - Search for artifact: Electrum
  - Search for artifact: Atomic Wallet
  - Windows Event ID 7045 (service install)
  - EDR process termination events
  - File encryption alerts

### Hypothesis 6
> If a threat actor has compromised a system, they may use infrastructure development to collect sensitive data and files. Observable indicators include: ZIP archive, svs-verificationdate.beer. This aligns with ATT&CK technique(s): T1560.002.

**Evidence:** All harvested data is stored in a ZIP archive and uploaded to the attacker's server.
**Techniques:** `T1560.002`

**Data Sources:**
  - EDR
  - Sysmon
  - Process Execution Logs

**Required Telemetry:**
  - Search for artifact: ZIP archive
  - Search for artifact: svs-verificationdate.beer
  - Sysmon Event ID 11 (file create)
  - EDR file access events
  - Clipboard monitoring

---
*Generated by Threat Hunt Generation Pipeline | 2026-06-24 06:20 UTC*
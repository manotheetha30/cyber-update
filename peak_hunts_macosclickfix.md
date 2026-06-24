# PEAK Hunt Hypotheses

## Hunt 1

### Prepare
**Hypothesis:** Adversaries may be using command-line tools to download and execute malicious payloads from external infrastructure.

**Behavior Basis:** Terminal command executed to download a DMG file using curl, followed by mounting the file with hdiutil to execute the payload.

**Objective:** Validate if adversaries are leveraging command-line utilities to exfiltrate and execute malicious files.

**Required Data Sources:**
- command execution logs
- network traffic logs
- file system changes

### Execute

#### Gather Data
- Collect logs of command-line executions containing curl or hdiutil
- Capture network connections initiated from /tmp directory
- Review file system changes in /tmp and user directories

#### Analysis Steps
- Identify Terminal commands with curl downloading files to /tmp
- Correlate hdiutil attach events with file creation in /tmp
- Check for unusual process executions from downloaded files

#### Supporting Evidence
- Presence of curl commands downloading files to /tmp
- Execution of hdiutil to mount suspicious DMG files
- Process creation from files in /tmp directory

### Act

**Documentation Requirements:** Record command execution timestamps, network destinations, and file system modifications.

#### Findings to Preserve
- Command-line scripts downloading files to temporary directories
- Silent mounting of disk images using hdiutil
- Execution of unknown processes from /tmp

#### Future Hunt Recommendations
- Monitor for command-line tools downloading files to temporary directories
- Track unusual file mounting activities
- Investigate automated script execution patterns

---

## Hunt 2

### Prepare
**Hypothesis:** Adversaries may be exfiltrating data by compressing it into ZIP archives and uploading to a command-and-control server.

**Behavior Basis:** Harvested data is stored in a ZIP archive named 'svs-verificationdate.beer' and uploaded to a C2 server.

**Objective:** Validate if adversaries are using ZIP compression for data exfiltration to external servers.

**Required Data Sources:**
- file system changes
- network traffic logs
- data exfiltration indicators

### Execute

#### Gather Data
- Identify ZIP file creation events in user directories
- Capture network uploads containing 'svs-verificationdate.beer'
- Review C2 server communication patterns

#### Analysis Steps
- Check for ZIP archive creation with suspicious filenames
- Correlate ZIP file uploads with network connections to external domains
- Analyze data payloads for signs of credential or wallet information

#### Supporting Evidence
- Presence of ZIP files with non-standard naming patterns
- Network uploads matching C2 server IP/domain
- Exfiltrated data containing wallet or browser credentials

### Act

**Documentation Requirements:** Document ZIP file metadata, upload timestamps, and associated network destinations.

#### Findings to Preserve
- ZIP archive creation with malicious filenames
- Data exfiltration to external servers
- Evidence of cryptocurrency wallet or browser data extraction

#### Future Hunt Recommendations
- Monitor for ZIP file creation in user directories
- Track network uploads of compressed data
- Investigate patterns of data exfiltration to unknown servers

---

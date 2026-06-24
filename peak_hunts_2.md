# PEAK Hunt Hypotheses

## Hunt 1

### Prepare
**Hypothesis:** Adversaries may be using file-based payloads to create arbitrary files on the system.

**Behavior Basis:** File:// payloads used to create files on the device

**Objective:** Validate if adversaries are leveraging file-based payloads to execute arbitrary file creation operations.

**Required Data Sources:**
- file_creation_events
- system_event_logs

### Execute

#### Gather Data
- Collect file creation events with timestamps and file paths
- Review system event logs for suspicious file operations

#### Analysis Steps
- Identify files created outside of normal operational patterns
- Correlate file creation with other suspicious process or network activity

#### Supporting Evidence
- Files with non-standard extensions or paths
- File creation events with no associated user or process context

### Act

**Documentation Requirements:** Record confirmed file creation patterns and associated timestamps

#### Findings to Preserve
- List of suspicious files created
- Correlation of file creation with other malicious activity

#### Future Hunt Recommendations
- Monitor for file creation patterns matching known exploitation vectors
- Investigate files with unusual permissions or ownership

---

## Hunt 2

### Prepare
**Hypothesis:** Adversaries may be leveraging components to force file writes via user-supplied URLs.

**Behavior Basis:** Webdialer component used to write arbitrary files to the operating system

**Objective:** Validate if adversaries are exploiting components to execute file writes through user-controlled inputs.

**Required Data Sources:**
- application_logs
- network_traffic_logs

### Execute

#### Gather Data
- Collect logs of URL processing and file write operations
- Capture network traffic for URLs associated with file write attempts

#### Analysis Steps
- Identify URLs that trigger unexpected file write operations
- Analyze patterns in URL parameters correlating with file write actions

#### Supporting Evidence
- Logs showing URL parsing leading to file write operations
- Network traffic containing payloads directed at file-write endpoints

### Act

**Documentation Requirements:** Document URL patterns and file write correlations

#### Findings to Preserve
- Confirmed URL patterns associated with file writes
- Network artifacts showing payload delivery to file-write endpoints

#### Future Hunt Recommendations
- Monitor for URL-based file write attempts in application logs
- Investigate components handling user-supplied inputs for file operations

---

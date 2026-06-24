data={'peak_hunts': [{'prepare': {'hypothesis': 'Adversaries may be using command-line tools to download and execute \
malicious payloads from external infrastructure.', 'behavior_basis': 'Terminal command executed to download a \
DMG file using curl, followed by mounting the file with hdiutil to execute the payload.', 'objective': 'Validate \
if adversaries are leveraging command-line utilities to exfiltrate and execute malicious files.', 
'required_data_sources': ['command execution logs', 'network traffic logs', 'file system changes']}, 'execute': 
{'gather_data': ['Collect logs of command-line executions containing curl or hdiutil', 'Capture network \
connections initiated from /tmp directory', 'Review file system changes in /tmp and user directories'], 
'analysis_steps': ['Identify Terminal commands with curl downloading files to /tmp', 'Correlate hdiutil attach events with file creation in /tmp', 'Check for unusual process executions from downloaded files'], 
'supporting_evidence': ['Presence of curl commands downloading files to /tmp', 'Execution of hdiutil to mount suspicious DMG files', 'Process creation from files in /tmp directory']}, 'act': {'documentation_requirements': 
'Record command execution timestamps, network destinations, and file system modifications.', 
'findings_to_preserve': ['Command-line scripts downloading files to temporary directories', 'Silent mounting of disk images using hdiutil', 'Execution of unknown processes from /tmp'], 'future_hunt_recommendations': 
['Monitor for command-line tools downloading files to temporary directories', 'Track unusual file mounting activities', 'Investigate automated script execution patterns']}}, {'prepare': {'hypothesis': 'Adversaries may \
be exfiltrating data by compressing it into ZIP archives and uploading to a command-and-control server.', 
'behavior_basis': "Harvested data is stored in a ZIP archive named 'svs-verificationdate.beer' and uploaded to a \
C2 server.", 'objective': 'Validate if adversaries are using ZIP compression for data exfiltration to external \
servers.', 'required_data_sources': ['file system changes', 'network traffic logs', 'data exfiltration \
indicators']}, 'execute': {'gather_data': ['Identify ZIP file creation events in user directories', "Capture \
network uploads containing 'svs-verificationdate.beer'", 'Review C2 server communication patterns'], 
'analysis_steps': ['Check for ZIP archive creation with suspicious filenames', 'Correlate ZIP file uploads with network connections to external domains', 'Analyze data payloads for signs of credential or wallet \
information'], 'supporting_evidence': ['Presence of ZIP files with non-standard naming patterns', 'Network \
uploads matching C2 server IP/domain', 'Exfiltrated data containing wallet or browser credentials']}, 'act': 
{'documentation_requirements': 'Document ZIP file metadata, upload timestamps, and associated network \
destinations.', 'findings_to_preserve': ['ZIP archive creation with malicious filenames', 'Data exfiltration to \
external servers', 'Evidence of cryptocurrency wallet or browser data extraction'], 
'future_hunt_recommendations': ['Monitor for ZIP file creation in user directories', 'Track network uploads of \
compressed data', 'Investigate patterns of data exfiltration to unknown servers']}}]}
peak_hunts = data["peak_hunts"]

md = ["# PEAK Hunt Hypotheses\n"]

for i, hunt in enumerate(peak_hunts, 1):
    md.extend([
        f"## Hunt {i}",
        "",
        "### Prepare",
        f"**Hypothesis:** {hunt['prepare']['hypothesis']}",
        "",
        f"**Behavior Basis:** {hunt['prepare']['behavior_basis']}",
        "",
        f"**Objective:** {hunt['prepare']['objective']}",
        "",
        "**Required Data Sources:**",
    ])

    for ds in hunt["prepare"]["required_data_sources"]:
        md.append(f"- {ds}")

    md.extend([
        "",
        "### Execute",
        "",
        "#### Gather Data",
    ])

    for item in hunt["execute"]["gather_data"]:
        md.append(f"- {item}")

    md.extend([
        "",
        "#### Analysis Steps",
    ])

    for item in hunt["execute"]["analysis_steps"]:
        md.append(f"- {item}")

    md.extend([
        "",
        "#### Supporting Evidence",
    ])

    for item in hunt["execute"]["supporting_evidence"]:
        md.append(f"- {item}")

    md.extend([
        "",
        "### Act",
        "",
        f"**Documentation Requirements:** {hunt['act']['documentation_requirements']}",
        "",
        "#### Findings to Preserve",
    ])

    for item in hunt["act"]["findings_to_preserve"]:
        md.append(f"- {item}")

    md.extend([
        "",
        "#### Future Hunt Recommendations",
    ])

    for item in hunt["act"]["future_hunt_recommendations"]:
        md.append(f"- {item}")

    md.extend(["", "---", ""])

markdown_content = "\n".join(md)

with open("peak_hunts_macosclickfix.md", "w", encoding="utf-8") as f:
    f.write(markdown_content)

print("Saved peak_hunts.md")
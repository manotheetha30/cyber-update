"""
Threat Hunt Generation Pipeline – LLM Prompt Templates

DESIGN PRINCIPLE:
  The LLM does ONE job: read article content and extract raw observable facts.
  It does NOT classify behaviors by tactic. It does NOT map to ATT&CK. 
  It does NOT generate hunt hypotheses. All of that happens in separate 
  deterministic stages.

  This keeps the prompt short, the output schema tiny, and the model fast.
"""

# ── Article Classification Prompt ─────────────────────────────────────────────
CLASSIFICATION_PROMPT = """\
Article: {title}
Source:  {source} | {published_date}

{content}

---
Classify this article and return ONLY this JSON (no other text):

{{
  "classification": "Security Incident|General Information|Advisory|Unknown",
  "reason": "<brief explanation (1-2 sentences)>"
}}

CLASSIFICATION RULES:
- "Security Incident": Describes a specific attack, breach, vulnerability exploitation, malware discovery, threat actor activity, or APT campaign
- "General Information": News about security industry, conference announcements, tools/product releases, general cybersecurity tips, educational content
- "Advisory": CVE advisories, vulnerability disclosures, patches, vendor statements about known issues
- "Unknown": Cannot determine or ambiguous
"""


# ── Main Extraction Prompt ─────────────────────────────────────────────────────
EXTRACTION_PROMPT = """\
Article: {title}
Source:  {source} | {published_date}

{content}

---
Extract and return ONLY VALID JSON

BEHAVIOR EXAMPLES:
✓ "PowerShell executed with encoded command to download payload from C2"
✓ "Registry HKLM\\Software\\Run modified to add backdoor path for persistence"
✓ "Legitimate Windows tool MiniDump used to dump LSASS process memory for credential theft"
✓ "C2 communication over ICMP tunneling protocol to exfiltrate stolen data"
✓ "Scheduled task created with System privileges to execute malware on startup"

✗ "Gained persistence" (too vague)
✗ "Privilege escalation occurred" (no observable detail)
✗ "Lateral movement was conducted" (how? what tools?)
"""

PEAK_HUNT_PROMPT=""" \
Generate PEAK hunts using ONLY the provided behaviors.\

Behaviors:

{behaviors}

Return valid JSON only.
"""
"""
Threat Hunt Generation Pipeline – LLM Prompt Templates

DESIGN PRINCIPLE:
  The LLM does ONE job: read article content and extract raw observable facts.
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

{previous_context}
{content}
---
BEHAVIOR EXAMPLES:
✓ "PowerShell executed with encoded command to download payload from C2"
✓ "Registry HKLM\\Software\\Run modified to add backdoor path for persistence"
✓ "Legitimate Windows tool MiniDump used to dump LSASS process memory for credential theft"
✓ "C2 communication over ICMP tunneling protocol to exfiltrate stolen data"
✓ "Scheduled task created with System privileges to execute malware on startup"

✗ "Gained persistence" (too vague)
✗ "Privilege escalation occurred" (no observable detail)
✗ "Lateral movement was conducted" (how? what tools?)
Extract all the fields and return ONLY VALID JSON .DON'T CHANGE THE FORMAT OF SPECIFIED JSON IF A PARTICULAR FIELD HAS NO VALUE ENTER "null" OR "[]" OR "{{}}" AS APPROPRIATE. DO NOT ADD ANY OTHER TEXT.
OUTPUT ONLY IN THE BELOW JSON FORMAT.

{{
  "executive_summary": "<2-3 sentences summarising the incident, threat actors, malware, and what they did>",

  "threat_actors": [
    {{"name": "", "aliases": [], "motivation": "", "evidence": ""}}
  ],

  "campaigns": [
    {{"name": "", "aliases": [], "description": "", "evidence": ""}}
  ],

  "malware": [
    {{"name": "", "type": "Ransomware|Infostealer|Backdoor|Loader|RAT|Wiper|Dropper|Botnet|Rootkit|Unknown", "description": ""}}
  ],

  "iocs": [
    {{"value": "", "ioc_type": "IP Address|Domain|Malware Name|URL|Email|MD5|SHA1|SHA256|SHA512|Filename|Registry Key|CVE", "context": ""}}
  ],

  "behaviors": [
    {{
      "behavior": "<specific observable action: what did they do, how did they do it>",
      "evidence": "<direct quote or close paraphrase from article>",
      "artifacts": ["<filename>", "<command>", "<registry key>", "<process name>", "<network address>"],
      "context": "<optional: when did this happen, what was the goal, what came before/after>"
    }}
  ]
}}

"""


PEAK_HUNT_PROMPT=""" \
Generate PEAK hunts using ONLY the provided behaviors.\

Behaviors:

{behaviors}

Return valid JSON only.
"""
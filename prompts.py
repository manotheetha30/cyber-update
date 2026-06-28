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

Classify this article and return ONLY this JSON (no other text):
 
{{
  "classification": "Security Incident|Advisory|General Information|Unknown",
}}
 
---
Title: {title}
Source: {source} | {published_date}
{content}
---
 
CLASSIFICATION RULES:
 
"Security Incident": 
  - Specific attack, breach, or vulnerability exploitation
  - NEW vulnerability discovery (CVE found, zero-day revealed)
  - Threat actor activity (APT campaign, hacker group)
  - Malware found in wild
  - Data breach reported
 
"Advisory": 
  - Patches/fixes for vulnerabilities (vendor releases update)
  - Mitigation guidance or detection rules
  
"General Information": 
  - Security industry news (company funding, startup, acquisition)
  - Conference announcements, job postings
  - Educational content, tips, best practices
  - Tool/product releases (not security patches)
 
"Unknown": 
  - Cannot determine
 
KEY DISTINCTION:
- Vulnerability DISCOVERED = Security Incident
- Vulnerability PATCHED = Advisory
- Default to Security Incident if unsure
 
EXAMPLES:
- "Critical RCE found in Apache" → Security Incident
- "Apache releases patch for RCE" → Advisory
- "APT28 attacks company" → Security Incident
- "Microsoft warns of exploitation" → Incident
- "New security startup raises $50M" → General Information
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
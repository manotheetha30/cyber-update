"""
CTI Pipeline – LLM Prompt Templates

DESIGN PRINCIPLE:
  The LLM does ONE job: read article content and extract raw observable facts.
  It does NOT classify behaviors by tactic. It does NOT map to ATT&CK. 
  It does NOT generate hunt hypotheses. All of that happens in separate 
  deterministic stages.

  This keeps the prompt short, the output schema tiny, and the model fast.
"""

SYSTEM_PROMPT = """\
You are a Cyber Threat Intelligence analyst. Your only job is to read a \
cybersecurity article and extract raw observable facts into JSON. 

Rules:
- Extract ONLY what is explicitly stated in the article and don't repeatedly extract the same behavior which may be mentioned more than once.
- Never invent actors, malware, IOCs, or behaviors.
- IOCs are IP addresses, file hashes, domain names, urls, malware names, mac addresses, host addresses, etc.

For behaviors:
Extract concrete observable adversary actions with clear context of WHAT they did.
Do NOT try to classify by tactic — that's the mapper's job.
Focus on WHAT and HOW, not WHY or tactical classification.

Prefer behaviors that mention:
- commands executed
- processes spawned
- executables used
- protocols used
- services accessed
- files touched
- registry keys modified
- credentials obtained
- network communication patterns
- persistence mechanisms (methods used)
- privilege escalation (methods used, not the classification)

GOOD:
- "PowerShell downloaded payload from C2 server"
- "Registry Run key modified with malware path"
- "LSASS memory dumped via MiniDump"
- "ICMP used for command and control with custom protocol"
- "Scheduled task created to execute backdoor daily"
- "WMI executed remote commands on target system"
- "SOCKS5 tunnel established through compromised proxy"

BAD:
- "Attackers compromised systems" (too vague)
- "Malware infected devices" (no observable action)
- "Threat actor conducted malicious activity" (meaningless)
- "Persistence was established" (no observable detail)

If a field has no data, use an empty array [] or null.
Output ONLY valid JSON. No markdown, no explanation."""


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
Extract and return ONLY this JSON (no other text):

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

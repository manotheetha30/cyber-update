"""
Threat Hunt Generation Pipeline – Pydantic data models
Clean, minimal, strictly aligned with what the LLM actually returns.
"""
from __future__ import annotations
from datetime import datetime
from enum import Enum
from typing import Optional,List
from pydantic import BaseModel, Field


class ArticleClassification(str, Enum):
    """Classification of article relevance to security incidents."""
    SECURITY_INCIDENT = "Security Incident"
    GENERAL_INFO      = "General Information"
    ADVISORY           = "Advisory"
    UNKNOWN            = "Unknown"


class MalwareType(str, Enum):
    RANSOMWARE  = "Ransomware"
    INFOSTEALER = "Infostealer"
    BACKDOOR    = "Backdoor"
    LOADER      = "Loader"
    RAT         = "RAT"
    WIPER       = "Wiper"
    DROPPER     = "Dropper"
    BOTNET      = "Botnet"
    ROOTKIT     = "Rootkit"
    UNKNOWN     = "Unknown"



class IOCType(str, Enum):
    IP       = "IP Address"
    DOMAIN   = "Domain"
    MALWARE  = "Malware Name"
    URL      = "URL"
    EMAIL    = "Email"
    MD5      = "MD5"
    SHA1     = "SHA1"
    SHA256   = "SHA256"
    SHA512   = "SHA512"
    FILENAME = "Filename"
    REGISTRY = "Registry Key"
    CVE      = "CVE"


class DataSource(str, Enum):
    WINDOWS_EVENT_LOGS = "Windows Event Logs"
    SYSMON             = "Sysmon"
    EDR                = "EDR"
    PROXY_LOGS         = "Proxy Logs"
    DNS_LOGS           = "DNS Logs"
    EMAIL_GATEWAY      = "Email Gateway Logs"
    FIREWALL_LOGS      = "Firewall Logs"
    PCAP               = "PCAP / Network Capture"
    CLOUD_TRAIL        = "AWS CloudTrail / Cloud Audit"
    PROCESS_LOGS       = "Process Execution Logs"


# ── Feed / Extraction ─────────────────────────────────────────────────────────

class RSSArticle(BaseModel):
    title:          str
    url:            str
    source:         str
    published_date: datetime
    author:         Optional[str] = None
    summary:        Optional[str] = None


class ExtractedArticle(BaseModel):
    rss_article:       RSSArticle
    full_text:         str
    extraction_method: str
    char_count:        int
    word_count:        int
    content_hash:      str
    extracted_at:      datetime = Field(default_factory=datetime.utcnow)


# ── LLM extraction outputs (Stage A) ─────────────────────────────────────────

class ThreatActor(BaseModel):
    name:        str
    aliases:     list[str]       = []
    motivation:  Optional[str]   = None
    evidence:    Optional[str]   = None


class Campaign(BaseModel):
    name:        str
    aliases:     list[str]       = []
    description: str             = ""
    evidence:    str             = ""


class MalwareFamily(BaseModel):
    name:         str
    malware_type: MalwareType   = MalwareType.UNKNOWN
    aliases:      list[str]     = []
    description:  Optional[str] = None


class IOC(BaseModel):
    value:      str
    ioc_type:   IOCType
    context:    Optional[str]   = None


class RawBehavior(BaseModel):
    """
    A single adversary behavior extracted by the LLM with rich context.
    No tactic classification by AI — the mapper decides based on behavior description.
    """
    behavior:   str                  # what the attacker did
    evidence:   str                  # article quote/paraphrase
    artifacts:  list[str] = []       # observable items (filenames, cmds…)
    context:    Optional[str] = None # additional context for mapper (e.g., "after gaining access", "to maintain persistence")


# ── ATT&CK mapping (Stage B — pure RAG, no LLM) ──────────────────────────────

class ATTACKMapping(BaseModel):
    tactic:            str
    technique_id:      str   # e.g. T1059.001
    technique_name:    str
    observed_behavior: str


# ── Hunt hypothesis (Stage C — deterministic) ────────────────────────────────

class HuntHypothesis(BaseModel):
    hypothesis:         str
    evidence:           str
    mitre_techniques:   list[str]       = []
    data_sources:       list[DataSource] = []
    required_telemetry: list[str]       = []
    detection_query:    Optional[str]   = None


# ── Final per-article report ──────────────────────────────────────────────────


class PeakPrepare(BaseModel):
    hypothesis: str
    behavior_basis: List[str]
    objective: str
    required_data_sources: List[str]


class PeakExecute(BaseModel):
    gather_data: List[str]
    analysis_steps: List[str]
    supporting_evidence: List[str]


class PeakAct(BaseModel):
    documentation_requirements: str
    findings_to_preserve: List[str]
    future_hunt_recommendations: List[str]


class PeakHunt(BaseModel):
    prepare: PeakPrepare
    execute: PeakExecute
    act: PeakAct
    
class  HuntReport(BaseModel):
    article:            ExtractedArticle
    classification:     ArticleClassification = ArticleClassification.UNKNOWN
    executive_summary:  str                    = ""
    threat_actors:      list[ThreatActor]      = []
    campaigns:          list[Campaign]         = []
    malware:            list[MalwareFamily]    = []
    iocs:               list[IOC]              = []
    behaviors:          list[RawBehavior]      = []
    attack_mappings:    list[ATTACKMapping]    = []
    hunt_hypotheses:    list[HuntHypothesis]   = []
    peak_hunts:         list[PeakHunt]         = []
    model_used:         str                    = ""
    processing_time_s:  float                  = 0.0
    generated_at:       datetime = Field(default_factory=datetime.utcnow)

"""
Threat Hunt Generation Pipeline – Stage A: LLM Extraction
The model does ONE thing: read article content and return raw facts as JSON.

What the LLM extracts:
  - Article classification (security incident or general info)
  - executive_summary
  - threat_actors
  - campaigns
  - malware families
  - IOCs
  - raw behaviors (no tactic classification)

What this LLM does NOT do (handled in later stages):
  - ATT&CK mapping  →  attack_mapper.py  (embedding-based similarity search)
"""
from __future__ import annotations
import json
import logging
import re
import time
from typing import Any

import requests as _requests
from tenacity import retry, stop_after_attempt, wait_exponential

from settings import LLM_MAX_TOKENS, LLM_MODEL, LLM_TEMPERATURE, OLLAMA_BASE_URL
from models import (
    Campaign, ArticleClassification, ExtractedArticle,
    IOC, IOCType, MalwareFamily, MalwareType,
    RawBehavior, ThreatActor, HuntReport,
)
from prompts import CLASSIFICATION_PROMPT, EXTRACTION_PROMPT

logger = logging.getLogger(__name__)

# ── Chunking configuration ────────────────────────────────────────────────────

CHUNK_SIZE = 7_000
CHUNK_OVERLAP = 1_500
MIN_CHUNK_SIZE = 1_000


# ── Chunking utilities ────────────────────────────────────────────────────────

def _smart_chunk_text(text: str, chunk_size: int = CHUNK_SIZE, overlap: int = CHUNK_OVERLAP) -> list[str]:
    """
    Split text into overlapping chunks at sentence boundaries.
    Tries to avoid breaking mid-sentence or mid-paragraph.
    """
    if len(text) <= chunk_size:
        return [text]
    
    sentences = re.split(r'(?<=[.!?])\s+', text)
    chunks = []
    current_chunk = ""
    
    for sentence in sentences:
        if len(current_chunk) + len(sentence) + 1 < chunk_size:
            current_chunk += (" " if current_chunk else "") + sentence
        else:
            if current_chunk:
                chunks.append(current_chunk)
            if chunks and overlap > 0:
                overlap_text = chunks[-1][-overlap:]
                current_chunk = overlap_text + " " + sentence
            else:
                current_chunk = sentence
    
    if current_chunk:
        chunks.append(current_chunk)
    
    filtered = []
    for chunk in chunks:
        if len(chunk) < MIN_CHUNK_SIZE and filtered:
            filtered[-1] = filtered[-1] + " " + chunk
        else:
            filtered.append(chunk)
    
    logger.debug(f"Split article into {len(filtered)} chunks (sizes: {[len(c) for c in filtered]})")
    return filtered


@retry(stop=stop_after_attempt(2), wait=wait_exponential(multiplier=2, min=5, max=20))
def _ollama(prompt: str, model: str = LLM_MODEL, messages: list[dict] | None = None) -> str:
    """
    Call Ollama with optional chat history for context.
    If messages is provided, uses that history; otherwise uses single-turn mode.
    """
    if messages is None:
        messages = [
            {"role": "user", "content": prompt},
        ]
    
    payload = {
        "model":  model,
        "stream": False,
        "options": {
            "temperature": LLM_TEMPERATURE,
            "num_predict": LLM_MAX_TOKENS,
            "top_p":       0.9,
        },
        "messages": messages,
    }

    resp = _requests.post(
        f"{OLLAMA_BASE_URL}/api/chat",
        json=payload,
        timeout=(20,2500),
    )
    resp.raise_for_status()
    return resp.json()["message"]["content"]

# ── JSON extraction ───────────────────────────────────────────────────────────

def _parse_json(raw: str) -> dict:
    """Extract JSON from LLM output, handling various formats."""
    raw = re.sub(r"<think>.*?</think>", "", raw, flags=re.DOTALL).strip()

    for candidate in [
        raw,
        re.search(r"```(?:json)?\s*([\s\S]+?)```", raw),
        None,
    ]:
        if candidate is None:
            start = raw.find("{")
            end   = raw.rfind("}")
            if start != -1 and end != -1:
                candidate = raw[start : end + 1]
        elif hasattr(candidate, "group"):
            candidate = candidate.group(1).strip()

        if isinstance(candidate, str):
            try:
                return json.loads(candidate)
   
            except:
                from json_repair import repair_json
                return json.loads(repair_json(candidate))
        

    raise ValueError(f"No valid JSON found in LLM output:\n{raw[:400]}")


# ── Article classification ────────────────────────────────────────────────────

def _classify_article(article: ExtractedArticle) -> ArticleClassification:
    """
    Classify article as Security Incident, General Info, Advisory, or Unknown.
    Only returns Security Incident classification.
    """
    rss = article.rss_article
    content = article.full_text[:1500]  # Use first 1500 chars for classification
    
    logger.info(f"Classifying article: {rss.title[:60]}")
    
    try:
        prompt = CLASSIFICATION_PROMPT.format(
            title=rss.title,
            source=rss.source,
            published_date=rss.published_date.strftime("%Y-%m-%d"),
            content=content,
        )
        
        raw = _ollama(prompt)
        data = _parse_json(raw)
        
        classification_str = data.get("classification", "Unknown").lower()
        reason = data.get("reason", "")
        
        # Map to enum
        for cls in ArticleClassification:
            if cls.value.lower() == classification_str:
                logger.debug(f"  Classification: {cls.value} - {reason}")
                return cls
        
        return ArticleClassification.UNKNOWN
        
    except Exception as exc:
        logger.warning(f"Classification failed: {exc}")
        return ArticleClassification.UNKNOWN


# ── Field coercers ────────────────────────────────────────────────────────────

def _mtype(v: Any) -> MalwareType:
    return {t.value.lower(): t for t in MalwareType}.get(str(v).lower(), MalwareType.UNKNOWN)

def _itype(v: Any) -> IOCType:
    return {t.value.lower(): t for t in IOCType}.get(str(v).lower(), IOCType.URL)


# ── Result aggregation (for multi-chunk processing) ────────────────────────────

def _merge_reports(chunk_reports: list[dict]) -> dict:
    """
    Merge extraction results from multiple chunks with chat history.
    Deduplicates behaviors and IOCs while preserving context.
    """
    if not chunk_reports:
        return {}
    
    if len(chunk_reports) == 1:
        return chunk_reports[0]
    
    merged = {
        "executive_summary": chunk_reports[0].get("executive_summary", ""),
        "threat_actors": [],
        "campaigns": [],
        "malware": [],
        "iocs": [],
        "behaviors": []
    }
    
    # Deduplicate threat actors by name
    actors_seen = set()
    for report in chunk_reports:
        for actor in (report.get("threat_actors") or []):
            name = actor.get("name", "").lower()
            if name and name not in actors_seen:
                actors_seen.add(name)
                merged["threat_actors"].append(actor)
    
    # Deduplicate campaigns by name
    campaigns_seen = set()
    for report in chunk_reports:
        for campaign in (report.get("campaigns") or []):
            name = campaign.get("name", "").lower()
            if name and name not in campaigns_seen:
                campaigns_seen.add(name)
                merged["campaigns"].append(campaign)
    
    # Deduplicate malware by name
    malware_seen = set()
    for report in chunk_reports:
        for malware in (report.get("malware") or []):
            name = malware.get("name", "").lower()
            if name and name not in malware_seen:
                malware_seen.add(name)
                merged["malware"].append(malware)
    
    # Deduplicate IOCs by value
    iocs_by_value = {}
    for report in chunk_reports:
        for ioc in (report.get("iocs") or []):
            value = ioc.get("value", "").lower()
            if value:
                if value not in iocs_by_value:
                    iocs_by_value[value] = ioc
                else:
                    # Merge context
                    existing_ctx = iocs_by_value[value].get("context", "")
                    new_ctx = ioc.get("context", "")
                    if new_ctx and new_ctx != existing_ctx:
                        iocs_by_value[value]["context"] = f"{existing_ctx}; {new_ctx}"
    merged["iocs"] = list(iocs_by_value.values())
    
    # Deduplicate behaviors by description + context
    behaviors_by_key = {}
    for report in chunk_reports:
        for behavior in (report.get("behaviors") or []):
            desc = behavior.get("behavior", "").lower().strip()
            context = behavior.get("context", "").lower().strip()
            key = f"{desc}||{context}"  # Unique key combining behavior and context
            
            if desc:
                if key not in behaviors_by_key:
                    behaviors_by_key[key] = behavior
                else:
                    # Merge artifacts if different
                    existing_artifacts = set(behaviors_by_key[key].get("artifacts", []))
                    new_artifacts = set(behavior.get("artifacts", []))
                    behaviors_by_key[key]["artifacts"] = list(existing_artifacts | new_artifacts)
    
    merged["behaviors"] = list(behaviors_by_key.values())
    logger.info(
        f"Merged {len(chunk_reports)} chunk reports: "
        f"actors={len(merged['threat_actors'])}, "
        f"behaviors={len(merged['behaviors'])}, "
        f"iocs={len(merged['iocs'])}"
    )
    
    return merged


# ── JSON → Pydantic ───────────────────────────────────────────────────────────

def _build_report(
    article: ExtractedArticle,
    classification: ArticleClassification,
    data: dict,
    model: str,
    elapsed: float
) -> HuntReport:
    """Build HuntReport from extracted data."""
    threat_actors = [
        ThreatActor(
            name        = ta.get("name", "Unknown"),
            aliases     = ta.get("aliases", []),
            motivation  = ta.get("motivation"),
            evidence    = ta.get("evidence"),
        )
        for ta in (data.get("threat_actors") or [])
        if ta.get("name")
    ]

    campaigns = [
        Campaign(
            name        = c.get("name", "Unknown"),
            aliases     = c.get("aliases", []),
            description = c.get("description", ""),
            evidence    = c.get("evidence", ""),
        )
        for c in (data.get("campaigns") or [])
        if c.get("name")
    ]

    malware = [
        MalwareFamily(
            name         = m.get("name", "Unknown"),
            malware_type = _mtype(m.get("type", "")),
            description  = m.get("description"),
        )
        for m in (data.get("malware") or [])
        if m.get("name")
    ]

    iocs = [
        IOC(
            value      = i.get("value", ""),
            ioc_type   = _itype(i.get("ioc_type", "")),
            context    = i.get("context"),
        )
        for i in (data.get("iocs") or [])
        if i.get("value")
    ]

    behaviors = [
        RawBehavior(
            behavior   = b.get("behavior", ""),
            evidence   = b.get("evidence", ""),
            artifacts  = b.get("artifacts", []),
            context    = b.get("context"),
        )
        for b in (data.get("behaviors") or [])
        if b.get("behavior")
    ]

    return HuntReport(
        article           = article,
        classification    = classification,
        executive_summary = data.get("executive_summary", ""),
        threat_actors     = threat_actors,
        campaigns         = campaigns,
        malware           = malware,
        iocs              = iocs,
        behaviors         = behaviors,
        model_used        = model,
        processing_time_s = round(elapsed, 2),
    )


# ── Public API ────────────────────────────────────────────────────────────────

def analyze_article(article: ExtractedArticle, model: str = LLM_MODEL, use_chunking: bool = True) -> HuntReport:
    """
    Stage A: Classify article, then extract facts if it's a security incident.
    
    Supports intelligent chunking for longer articles with chat history:
    - Classifies article first
    - Skips analysis for non-incident articles
    - Splits article into overlapping chunks at sentence boundaries
    - Maintains chat history across chunks for context
    - Merges and deduplicates results
    """
    rss     = article.rss_article
    content = article.full_text
    
    logger.info("Processing [%s]: %s", model, rss.title[:70])
    t0 = time.time()
    
    try:
        # Step 1: Classify article
        classification = _classify_article(article)
        
        # Step 2: Skip non-incident articles
        if classification != ArticleClassification.SECURITY_INCIDENT:
            logger.info(
                f"  Skipping analysis: classified as {classification.value}"
            )
            return HuntReport(
                article        = article,
                classification = classification,
                model_used     = model,
                processing_time_s = round(time.time() - t0, 2),
            )
        
        # Step 3: Extract facts from security incident
        if use_chunking and len(content) > CHUNK_SIZE:
            chunks = _smart_chunk_text(content, chunk_size=CHUNK_SIZE, overlap=CHUNK_OVERLAP)
            logger.info(f"  Analyzing {len(chunks)} chunks from full article...")
            
            # Maintain chat history across chunks
            behavior_memory = []
            chunk_results = []
    
            for i, chunk in enumerate(chunks, 1):
                logger.debug(f"  [Chunk {i}/{len(chunks)}] {len(chunk)} chars")
                if behavior_memory!=[]:
                    context= f"""
                                Previous observed behaviors from earlier chunks of the SAME article:

                                {json.dumps(behavior_memory, indent=2)}

                                Use these previously extracted behaviors only as contextual memory. Correlate entities, tools, malware, commands, infrastructure, and attack sequences across chunks when evidence supports a connection.

                                Guidelines:
                                - Do NOT repeat behaviors that have already been extracted unless new details are revealed.
                                - If the current chunk expands, clarifies, or provides additional evidence for a previously observed behavior, update the context in your analysis.
                                - Identify relationships between current observations and previously observed behaviors when they appear to be part of the same attack chain.
                                - Prefer extracting NEW observable behaviors from the current chunk.
                                - Do NOT infer facts that are not supported by the current chunk or the provided context.
                                - The extraction should follow the VALID JSON format specified , and should be parsable by a JSON parser.
                                - ALWAYS return valid JSON.
                        """
                else:
                    context=""
                prompt = EXTRACTION_PROMPT.format(
                    title          = rss.title,
                    source         = rss.source,
                    published_date = rss.published_date.strftime("%Y-%m-%d"),
                    previous_context=context,
                    content        = chunk                
                )
                try:
                    raw = _ollama(prompt, model=model)
                    data = _parse_json(raw)
                    chunk_results.append(data)
                    for b in data.get("behaviors", []):
                        behavior_memory.append(b)
                except Exception as e:
                    logger.warning(f"  Chunk {i} failed: {e}")
                    continue
            
            if not chunk_results:
                raise ValueError("All chunks failed to extract")
            
            data = _merge_reports(chunk_results)
        
        else:
            # Single-pass for short articles
            if len(content) > CHUNK_SIZE:
                logger.info(f"  Article longer than {CHUNK_SIZE} chars, truncating (chunking disabled)")
                content = content[:CHUNK_SIZE] + "\n\n[truncated]"
            
            prompt = EXTRACTION_PROMPT.format(
                title          = rss.title,
                source         = rss.source,
                published_date = rss.published_date.strftime("%Y-%m-%d"),
                previous_context="",
                content        = content  
            )
            print(EXTRACTION_PROMPT)
            
            raw  = _ollama(prompt, model=model)
            print(raw)
            data = _parse_json(raw)
        
        # Build final report
        report = _build_report(article, classification, data, model, time.time() - t0)
        logger.info(
            "  → actors=%d  iocs=%d  behaviors=%d  (%.1fs)",
            len(report.threat_actors), len(report.iocs),
            len(report.behaviors), report.processing_time_s,
        )
    
    except Exception as exc:
        logger.exception("LLM failed for '%s': %s", rss.title[:60], exc)
        report = HuntReport(
            article           = article,
            classification    = ArticleClassification.UNKNOWN,
            executive_summary = f"[Extraction failed: {exc}]",
            model_used        = model,
            processing_time_s = round(time.time() - t0, 2),
        )

    return report

def analyze_articles(articles: list[ExtractedArticle], model: str = LLM_MODEL, use_chunking: bool = True) -> list[HuntReport]:
    """Analyze multiple articles."""
    reports = []
    for i, art in enumerate(articles, 1):
        reports.append(analyze_article(art, model=model, use_chunking=use_chunking))
    return reports

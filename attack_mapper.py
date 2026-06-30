"""
ATT&CK Mapper – Maps raw behaviors to MITRE ATT&CK techniques using embeddings.

Takes RawBehavior objects with rich context and maps them to techniques.
The behavior description + context + artifacts helps determine which tactic
the behavior belongs to (e.g., same technique T1234 could be initial access
or privilege escalation depending on context).
"""
from __future__ import annotations
import logging
import pickle
from sentence_transformers import SentenceTransformer
import numpy as np
from models import (
    ATTACKMapping,
    HuntReport,
    RawBehavior,
)

logger = logging.getLogger(__name__)

# Load sentence transformer for embedding
model = SentenceTransformer("./attack_mapper")

# Load pre-computed ATT&CK embeddings
with open("attack_embeddings_transformer.pkl", "rb") as f:
    data = pickle.load(f)

TECHNIQUES_IDS = data["ids"]
TECHNIQUES_METADATA = data["metadata"]
EMBEDDINGS = data["embeddings"]

logger.info("Loaded %d ATT&CK techniques", len(TECHNIQUES_IDS))


# ──────────────────────────────────────────────────────────────────────────────
# Build rich query text with context for better tactic determination
# ──────────────────────────────────────────────────────────────────────────────

def _build_query(behavior: RawBehavior) -> str:
    """
    Build a comprehensive query text from behavior, artifacts, and context.
    This helps the embedding model understand the tactical context.
    
    Example output:
      "Behavior: PowerShell executed with encoded command
       Artifacts: powershell.exe, -EncodedCommand, payload.bin
       Context: after establishing foothold, to maintain persistence"
    """
    parts = []
    
    # Core behavior is essential
    if behavior.behavior:
        parts.append(f"Behavior: {behavior.behavior}")
    
    # Artifacts provide strong signals
    if behavior.artifacts:
        artifact_str = ", ".join(behavior.artifacts[:8])
        parts.append(f"Artifacts: {artifact_str}")
    
    # Context is crucial for disambiguation
    # Example: Same technique might apply to both "initial access" and "privilege escalation"
    # Context clarifies which one: "after gaining user access" vs "from initial foothold"
    if behavior.context:
        parts.append(f"Context: {behavior.context}")
    
    # Evidence provides additional grounding
    if behavior.evidence:
        evidence_snippet = behavior.evidence
        parts.append(f"Evidence: {evidence_snippet}")
    
    query_text = " | ".join(parts)
    logger.debug(f"Query: {query_text[:150]}")
    return query_text


# ──────────────────────────────────────────────────────────────────────────────
# Single behavior mapping
# ──────────────────────────────────────────────────────────────────────────────

def map_behavior(behavior: RawBehavior, top_k: int = 1) -> list[ATTACKMapping]:
    """
    Map a single behavior to ATT&CK techniques using semantic similarity.
    
    Args:
        behavior: RawBehavior with description, artifacts, and context
        top_k: Return top K matches (default 1, best match)
    
    Returns:
        List of ATTACKMapping objects (empty if mapping fails)
    """
    if not behavior.behavior:
        return []
    
    query_text = _build_query(behavior)
    
    try:
        # Encode the query with prefix for semantic search
        query_embedding = model.encode(
            f"query: {query_text}",
            normalize_embeddings=True
        )
        
        # Compute similarity scores
        scores = EMBEDDINGS @ query_embedding
        
        # Get top K indices
        top_indices = np.argsort(scores)[::-1][:top_k]
        
        mappings = []
        for idx in top_indices:
            if idx >= len(TECHNIQUES_METADATA):
                continue
                
            technique = TECHNIQUES_METADATA[idx]
            score = float(scores[idx])
            
            # Only map if similarity is meaningful (>0.3 threshold)
            if score < 0.3:
                logger.debug(
                    f"Low similarity ({score:.3f}): {behavior.behavior[:50]} "
                    f"-> {technique['attack_id']}"
                )
                continue
            
            mapping = ATTACKMapping(
                tactic=technique["tactic"],
                technique_id=technique["attack_id"],
                technique_name=technique["name"],
                observed_behavior=behavior.behavior,
            )
            
            logger.debug(
                f"[{score:.3f}] {behavior.behavior} "
                f"-> {technique['attack_id']} ({technique['tactic']})"
            )
            
            mappings.append(mapping)
        
        return mappings
    
    except Exception as exc:
        logger.warning(f"Mapping failed for '{behavior.behavior[:50]}': {exc}")
        return []


# ──────────────────────────────────────────────────────────────────────────────
# Batch mapping
# ──────────────────────────────────────────────────────────────────────────────

def map_report(report: HuntReport) -> HuntReport:
    """
    Map all behaviors in a report to ATT&CK techniques.
    """
    if not report.behaviors:
        logger.debug("No behaviors to map")
        return report
    
    all_mappings = []
    
    for behavior in report.behaviors:
        mappings = map_behavior(behavior, top_k=1)
        
        if mappings:
            all_mappings.extend(mappings)
            
            # Log with context for debugging
            context_hint = f" (context: {behavior.context[:30]})" if behavior.context else ""
            logger.info(
                f"  {behavior.behavior[:55]}{context_hint} "
                f"-> {mappings[0].technique_id} | {mappings[0].tactic}"
            )
    
    report.attack_mappings = all_mappings
    
    logger.info(
        f"Mapped {len(report.behaviors)} behaviors -> {len(report.attack_mappings)} techniques"
    )
    
    return report


def map_reports(reports: list[HuntReport]) -> list[HuntReport]:
    """Map all reports."""
    return [map_report(r) for r in reports]

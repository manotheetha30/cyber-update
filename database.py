"""
Threat Hunt Generation Pipeline – Storage Layer
Handles articles, reports, and deduplication across multiple sources.
"""
from __future__ import annotations
import json
import logging
from datetime import datetime, timedelta

from sqlalchemy import (
    Column, DateTime, Float, Integer, String, Text,
    UniqueConstraint, create_engine, Index,
)
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from settings import DATABASE_URL
from models import HuntReport, ExtractedArticle, ArticleClassification

logger = logging.getLogger(__name__)


class Base(DeclarativeBase):
    pass


class ArticleRecord(Base):
    """
    Store extracted articles with content hash for deduplication.
    Same article from multiple sources (different URLs) will have same content_hash.
    """
    __tablename__ = "articles"
    __table_args__ = (
        UniqueConstraint("content_hash", name="uq_content_hash"),
        Index("idx_source_published", "source", "published_date"),
    )

    id                = Column(Integer, primary_key=True, autoincrement=True)
    url               = Column(String(2048), nullable=False, index=True)
    title             = Column(String(512))
    source            = Column(String(128), index=True)
    author            = Column(String(256))
    published_date    = Column(DateTime, index=True)
    extracted_at      = Column(DateTime, default=datetime.utcnow, index=True)
    extraction_method = Column(String(64))
    char_count        = Column(Integer)
    word_count        = Column(Integer)
    content_hash      = Column(String(64), unique=True, index=True)  # Deduplication key
    full_text         = Column(Text)
    sources_seen      = Column(Text, default="[]")  # JSON list of sources that have this content


class HuntReportRecord(Base):
    """
    Store Hunt reports for articles.
    Links to articles via content_hash so multiple source articles map to one report.
    """
    __tablename__ = "hunt_reports"
    __table_args__ = (
        Index("idx_content_hash", "content_hash"),
        Index("idx_generated_at", "generated_at"),
    )

    id                    = Column(Integer, primary_key=True, autoincrement=True)
    content_hash          = Column(String(64), index=True)  # Link to article via content hash
    original_urls         = Column(Text)  # JSON list of URLs from different sources
    generated_at          = Column(DateTime, default=datetime.utcnow, index=True)
    model_used            = Column(String(128))
    processing_time_s     = Column(Float)
    classification        = Column(String(64), default="Unknown")
    executive_summary     = Column(Text)
    threat_actors_json    = Column(Text)
    campaigns_json        = Column(Text)
    malware_json          = Column(Text)
    iocs_json             = Column(Text)
    behaviors_json        = Column(Text)
    attack_mappings_json  = Column(Text)
    hunt_hypotheses_json  = Column(Text)


_engine = None


def get_engine():
    global _engine
    if _engine is None:
        import os
        os.makedirs("data", exist_ok=True)
        _engine = create_engine(DATABASE_URL, echo=False)
        Base.metadata.create_all(_engine)
        logger.info("Database ready: %s", DATABASE_URL)
    return _engine


def _session() -> Session:
    return sessionmaker(bind=get_engine(), expire_on_commit=False)()


# ──────────────────────────────────────────────────────────────────────────────
# Article deduplication and storage
# ──────────────────────────────────────────────────────────────────────────────

def is_duplicate(content_hash: str) -> bool:
    """Check if an article with this content hash already exists."""
    with _session() as s:
        return s.query(ArticleRecord).filter_by(content_hash=content_hash).first() is not None


def get_article_by_hash(content_hash: str) -> ArticleRecord | None:
    """Retrieve article record by content hash."""
    with _session() as s:
        return s.query(ArticleRecord).filter_by(content_hash=content_hash).first()


def save_article(article: ExtractedArticle) -> tuple[bool, ArticleRecord]:
    """
    Save article, handling duplicates from different sources.
    
    Returns:
        (is_new, ArticleRecord): 
        - is_new=True if this is the first time seeing this content
        - ArticleRecord: the stored record (new or existing)
    """
    with _session() as s:
        existing = s.query(ArticleRecord).filter_by(
            content_hash=article.content_hash
        ).first()
        
        if existing:
            # Article already saved from another source
            # Update sources_seen list
            try:
                sources = json.loads(existing.sources_seen or "[]")
            except:
                sources = []
            
            new_source = article.rss_article.source
            if new_source not in sources:
                sources.append(new_source)
                existing.sources_seen = json.dumps(sources)
                logger.info(
                    f"Duplicate content: {article.rss_article.title[:50]} "
                    f"now seen from sources: {', '.join(sources)}"
                )
                s.commit()
            
            return False, existing
        
        # New content
        rss = article.rss_article
        rec = ArticleRecord(
            url=rss.url,
            title=rss.title,
            source=rss.source,
            author=rss.author,
            published_date=rss.published_date,
            extracted_at=article.extracted_at,
            extraction_method=article.extraction_method,
            char_count=article.char_count,
            word_count=article.word_count,
            content_hash=article.content_hash,
            full_text=article.full_text,
            sources_seen=json.dumps([rss.source]),
        )
        s.add(rec)
        s.commit()
        logger.info(f"New article saved: {rss.title[:50]}")
        return True, rec


# ──────────────────────────────────────────────────────────────────────────────
# Report storage
# ──────────────────────────────────────────────────────────────────────────────

def save_report(report: HuntReport, content_hash: str) -> None:
    """
    Save Hunt report, linking to article by content hash.
    
    Args:
        report: HuntReport with extracted intelligence
        content_hash: Content hash to link back to original article(s)
    """
    with _session() as s:
        # Check if report already exists for this content
        existing = s.query(HuntReportRecord).filter_by(content_hash=content_hash).first()
        
        if existing:
            logger.warning(f"Report already exists for content hash {content_hash}, skipping")
            return
        
        # Get original URLs
        article_rec = s.query(ArticleRecord).filter_by(
            content_hash=content_hash
        ).first()
        
        if not article_rec:
            logger.warning(f"Article not found for hash {content_hash}")
            original_urls = [report.article.rss_article.url]
        else:
            try:
                sources = json.loads(article_rec.sources_seen or "[]")
                # Reconstruct URLs: store source info for reference
                original_urls = [
                    f"source={src}" for src in sources
                ]
            except:
                original_urls = [report.article.rss_article.url]
        
        rec = HuntReportRecord(
            content_hash=content_hash,
            original_urls=json.dumps(original_urls),
            generated_at=report.generated_at,
            model_used=report.model_used,
            processing_time_s=report.processing_time_s,
            classification=report.classification.value,
            executive_summary=report.executive_summary,
            threat_actors_json=json.dumps([x.model_dump() for x in report.threat_actors]),
            campaigns_json=json.dumps([x.model_dump() for x in report.campaigns]),
            malware_json=json.dumps([x.model_dump() for x in report.malware]),
            iocs_json=json.dumps([x.model_dump() for x in report.iocs]),
            behaviors_json=json.dumps([x.model_dump() for x in report.behaviors]),
            attack_mappings_json=json.dumps([x.model_dump() for x in report.attack_mappings]),
            hunt_hypotheses_json=json.dumps([x.model_dump() for x in report.hunt_hypotheses]),
        )
        s.add(rec)
        s.commit()
        logger.debug(f"Saved report for {content_hash[:16]}")


# ──────────────────────────────────────────────────────────────────────────────
# Query helpers
# ──────────────────────────────────────────────────────────────────────────────

def get_recent_reports(days: int = 7) -> list[HuntReportRecord]:
    """Get Hunt reports generated in the last N days."""
    cutoff = datetime.utcnow() - timedelta(days=days)
    with _session() as s:
        return (s.query(HuntReportRecord)
                  .filter(HuntReportRecord.generated_at >= cutoff)
                  .order_by(HuntReportRecord.generated_at.desc())
                  .all())


def get_reports_by_classification(classification: str) -> list[HuntReportRecord]:
    """Get reports filtered by classification."""
    with _session() as s:
        return (s.query(HuntReportRecord)
                  .filter_by(classification=classification)
                  .order_by(HuntReportRecord.generated_at.desc())
                  .all())


def get_articles_by_source(source: str, days: int = 30) -> list[ArticleRecord]:
    """Get articles from a specific source in the last N days."""
    cutoff = datetime.utcnow() - timedelta(days=days)
    with _session() as s:
        return (s.query(ArticleRecord)
                  .filter(ArticleRecord.source == source)
                  .filter(ArticleRecord.published_date >= cutoff)
                  .order_by(ArticleRecord.published_date.desc())
                  .all())

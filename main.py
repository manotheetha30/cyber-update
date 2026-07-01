"""
Threat Hunt Generation Pipeline
Three-stage pipeline: A (LLM extract) → B (ATT&CK map) → C (hunt generate)

Usage:
    python main.py                    # run once (yesterday's articles)
    python main.py --schedule         # daily cron at configured time
    python main.py --lookback 3       # articles from last 3 days
    python main.py --verbose          # debug logging
"""
from __future__ import annotations
import argparse
import logging
import sys
import time
from pathlib import Path
from collections import defaultdict
from venv import logger
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.table import Table
from llm_analyzer import _classify_article
#Hugging Face
logging.getLogger("huggingface_hub").setLevel(logging.ERROR)
# HTTP requests made by HF
logging.getLogger("httpx").setLevel(logging.ERROR)
# Transformers
logging.getLogger("transformers").setLevel(logging.ERROR)
# Sentence Transformers
logging.getLogger("sentence_transformers").setLevel(logging.WARNING)
RELEVANT_KEYWORDS = [
    "cve", "vulnerability", "vulnerable", "zero", "day", "flaw", "risk", "hackers",
    "exploit", "adware", "traffic", "fake", "phishing", "hack", "bug",
    "rce", "zero-day", "0day", "malware", "ransomware", "apt","adversary","cybercrime","cyber",
    "threat actor", "exposes", "expose", "breach", "stealth", "defense",
    "incident", "campaign", "ioc", "abuse", "steal",
    "attack", "cyberattack", "spy", "cybersecurity", "breached", "exposed",
    "exploitation", "exploitated", "compromise",
    "privilege escalation", "command injection", "sql injection",
    "authentication bypass"
]

EXCLUSION_WORDS = ["webinar", "tutorial", "how to", "recap", "bulletin"]

console = Console()


def setup_logging(verbose: bool = False) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        handlers=[
            logging.StreamHandler(sys.stdout),
            logging.FileHandler("pipeline.log", mode="a"),
        ],
    )


def is_relevant(title: str) -> bool:
    """Quick relevance filter based on keywords."""
    text = f"{title}".lower()
    positive = negative = 0
    for k in RELEVANT_KEYWORDS:
        if k in text:
            positive = 1
            break
    for j in EXCLUSION_WORDS:
        if j in text:
            negative = 1
    return positive >= 1 and not negative


def run_pipeline(lookback_days: int = 1,url: str | None = None) -> dict:
    """
    Main pipeline orchestrator:
    1. Ingest RSS feeds
    2. Extract article content
    3. Classify + analyze (only security incidents)
    4. Deduplicate same content from multiple sources
    5. Map to ATT&CK
    6. Generate hunt hypotheses
    7. Save reports
    """
    from rss_ingestor import ingest_feeds
    from scraper import extract_articles
    from llm_analyzer import analyze_articles
    from attack_mapper import map_reports
    from report_generator import save_all_reports, export_ioc_csv
    from settings import LLM_MODEL
    from peak_hunt_generator import generate_peak_hunts
    from group_articles import group_news
    from models import ArticleClassification
    from models import  ExtractedArticleWithCluster
    from database import report_collection
    if url:
        stats = {
        "article_analyzed": 0,
        "article_classified_security": 0,
        "article_skipped_non_incident": 0,
        "attack_mappings": 0,
        "hunt_hypotheses": 0,
        "iocs_extracted": 0,
        "report_written": False,
        "elapsed_s": 0.0,
    }
    else:
        stats = {
        "articles_found": 0,
        "articles_extracted": 0,
        "articles_analyzed": 0,
        "articles_classified_security": 0,
        "articles_skipped_non_incident": 0,
        "attack_mappings": 0,
        "hunt_hypotheses": 0,
        "iocs_extracted": 0,
        "reports_written": 0,
        "elapsed_s": 0.0,
    }
    t0 = time.time()

    with Progress(
        SpinnerColumn(),
        TextColumn("{task.description}"),
        TimeElapsedColumn(),
        console=console
    ) as prog:
        unique_articles = []
        if url:
            t = prog.add_task("Stage 1: Extracting content...", total=None)
            extracted = extract_articles(url)
            classified_security = 1
            unique_articles.append(extracted)
            t = prog.add_task(
                f"[cyan]Stage A: LLM analysis ({LLM_MODEL})...",
                total=None
            )
            reports= analyze_articles(unique_articles)


        else:
        # ── Stage 1: RSS Ingestion ────────────────────────────────────────────
            t = prog.add_task("[cyan]Stage 1: RSS ingestion...", total=None)
            rss_articles = ingest_feeds(lookback_days=lookback_days)
            stats["articles_found"] = len(rss_articles)
            prog.update(t, description=f"[green]Stage 1 done — {len(rss_articles)} articles")

            if not rss_articles:
                console.print("[yellow]No articles found. Exiting.")
                return stats
            # Quick relevance filter
            rss_articles = [
                a for a in rss_articles
                if is_relevant(a.title)
            ]
    
        # ── Stage 2: Extract Article Content ──────────────────────────────────
            
            extracted = extract_articles(rss_articles[6:8])
            stats["articles_extracted"] = len(extracted)
            prog.update(t, description=f"Stage 2 done — {len(extracted)} extracted")
            if not extracted:
                console.print("No articles extracted. Exiting.")
                return stats
            try:
                for article in extracted:
                    #Step 1: Classify article
                    classification = _classify_article(article)
            
                # Step 2: Skip non-incident articles
                    if classification != ArticleClassification.SECURITY_INCIDENT:
                        logger.info(
                            f"  Skipping analysis: classified as {classification.value}"
                        )
                    
                    else:
                        unique_articles.append(article)
            except Exception as exc:
                logger.exception("LLM Classification failed! %s ", exc)
                stats["articles_analyzed"] = 0
                stats["articles_classified_security"] = 0
                stats["articles_skipped_non_incident"] =0
                stats["attack_mappings"]=0
                stats["iocs_extracted"]=0
                stats["hunt_hypotheses"]=0
                stats["reports_written"]=0
                stats["elapsed_s"] = round(time.time() - t0, 1)
                return stats     

            classified_security =len(unique_articles)           
            clusters = group_news(unique_articles)
            clustered_articles = []
        
            for cluster in clusters:
                articles_rss=[]
                w_count=0
                c_count=0
                method=[]
                date=[]
                text=[]
                hash=[]
                for idx in cluster:
                    article= unique_articles[idx]
                    articles_rss.append(article.rss_article)
                    w_count+=article.word_count
                    c_count+=article.char_count
                    date.append(article.extracted_at)
                    method.append(article.extraction_method)
                    text.append(article.full_text)
                    hash.append(article.content_hash)
                clustered_articles.append(ExtractedArticleWithCluster(
                    rss_article=articles_rss,
                    full_text=text,
                    extraction_method=method,
                    char_count=c_count,
                    word_count=w_count,
                    content_hash=hash,
                    extracted_at=date
                ))

        # ── Stage A: LLM Extraction + Classification ──────────────────────────
            t = prog.add_task(
                f"[cyan]Stage A: LLM analysis ({LLM_MODEL})...",
                total=None
            )
            reports = analyze_articles(clustered_articles)
        # Count classification results

        if not url:
            stats["articles_analyzed"] = len(extracted)
            stats["articles_classified_security"] = classified_security
            stats["articles_skipped_non_incident"] = len(extracted) - classified_security
        else:
            stats["article_classified_security"]=classified_security
            stats["article_skipped_non_incident"]=1-classified_security

        stats["iocs_extracted"] = sum(len(r.iocs) for r in reports)
        
        prog.update(
            t,
            description=f"[green]Stage A done — {classified_security} security incidents"
        )

        # Filter to security incidents only for further processing
        if not reports and url:
            console.print(
                "[yellow]No security incident identified in the provided URL"
            )
            stats["report_written"] =False
            stats["elapsed_s"] = round(time.time() - t0, 1)
            return stats
        elif not reports:
            console.print(
                "[yellow]No security incidents identified. No reports written."
            )
            stats["reports_written"] = 0
            stats["elapsed_s"] = round(time.time() - t0, 1)
            return stats
        
        # ── Stage B: ATT&CK Mapping ───────────────────────────────────────────
        t = prog.add_task("[cyan]Stage B: ATT&CK mapping...", total=None)
        reports = map_reports(reports)
        stats["attack_mappings"] = sum(len(r.attack_mappings) for r in reports)
        prog.update(t, description=f"[green]Stage B done — {stats['attack_mappings']} techniques mapped")

        # ── Stage C: Hunt Hypothesis Generation ────────────────────────────────
        t = prog.add_task("[cyan]Stage C: Generating hunt hypotheses...", total=None)
        for r in reports:
            r.peak_hunts = generate_peak_hunts(r)

        stats["hunt_hypotheses"] = sum(len(r.peak_hunts) for r in reports)
        prog.update(t, description=f"[green]Stage C done — {stats['hunt_hypotheses']} hypotheses")

        # ── Persist + Output ──────────────────────────────────────────────────
        t = prog.add_task("[cyan]Writing reports...", total=None)
        for r in reports:
            report_collection.insert_one(r.model_dump())
        
        paths = save_all_reports(reports)
        export_ioc_csv(reports)
        if url:
            stats["report_written"]=True
        else:
            stats["reports_written"] = len(paths)
        prog.update(t, description=f"[green]Done — {len(paths)} reports written")

    stats["elapsed_s"] = round(time.time() - t0, 1)
    return stats


def print_summary(stats: dict) -> None:
    """Print run summary table."""
    tbl = Table(title="Threat Hunt Generation Pipeline — Run Summary")
    tbl.add_column("Metric", style="cyan")
    tbl.add_column("Value", style="white")
    for k, v in stats.items():
        label = k.replace("_", " ").title()
        tbl.add_row(label, str(v))
    console.print(tbl)


def scheduled_run() -> None:
    """Run pipeline on a schedule."""
    import schedule as sched
    from settings import RUN_HOUR, RUN_MINUTE
    
    run_time = f"{RUN_HOUR:02d}:{RUN_MINUTE:02d}"
    console.print(f"[cyan]Scheduler active — daily run at {run_time} UTC")

    def job():
        console.print("\n[bold cyan]Scheduled pipeline run starting...")
        print_summary(run_pipeline())

    sched.every().day.at(run_time).do(job)
    while True:
        sched.run_pending()
        time.sleep(60)


def main() -> None:
    parser = argparse.ArgumentParser(description="Threat Hunt Generation Pipeline")
    parser.add_argument("--schedule", action="store_true", help="Run on schedule")
    parser.add_argument("--article_url",type=str,default="",help="Analyze a particular blog/article")
    parser.add_argument("--lookback", type=int, default=1, help="Days to look back")
    parser.add_argument("--verbose", action="store_true", help="Verbose logging")
    args = parser.parse_args()

    setup_logging(args.verbose)
    Path("data").mkdir(exist_ok=True)
    Path("reports").mkdir(exist_ok=True)
    if args.article_url:
        run_pipeline(url=args.article_url)
        return
    if args.schedule:
        scheduled_run()
        return

    console.print("[bold cyan]Threat Hunt Generation Pipeline — starting run[/]")
    print_summary(run_pipeline(lookback_days=args.lookback))


if __name__ == "__main__":
    main()

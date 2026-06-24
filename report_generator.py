"""
Threat Hunt Generation Pipeline – Report Generator
Renders the final HuntReport into Markdown + CSV with rich context.
"""
from __future__ import annotations
import csv
import logging
from datetime import datetime
from pathlib import Path

from settings import REPORT_DIR
from models import HuntReport

logger = logging.getLogger(__name__)
def _table(headers: list[str], rows: list[list[str]]) -> str:
    """Render a markdown table."""
    sep  = "| " + " | ".join("---" for _ in headers) + " |"
    head = "| " + " | ".join(headers) + " |"
    body = ["| " + " | ".join(str(c).replace("|", "\\|")[:120] for c in row) + " |"
            for row in rows]
    return "\n".join([head, sep] + body)


def render_report(report: HuntReport) -> str:
    """Render full Hunt report to markdown."""
    rss  = report.article.rss_article
    now  = datetime.now().strftime(r"%Y-%m-%d %H:%M UTC")
    lines: list[str] = []

    # ── Header ────────────────────────────────────────────────────────────────
    lines += [
        f"# Threat Hunt Generation Report: {rss.title}",
        "",
        f"| Field | Value |",
        f"| --- | --- |",
        f"| Source | {rss.source} |",
        f"| Published | {rss.published_date.strftime('%Y-%m-%d %H:%M UTC')} |",
        f"| URL | [{rss.url}]({rss.url}) |",
        f"| Classification | {report.classification.value} |",
        f"| Report Generated | {now} |",
        f"| Model | {report.model_used} |",
        f"| LLM Processing Time | {report.processing_time_s}s |",
        "",
        "---",
        "",
    ]

    # ── Classification Status ─────────────────────────────────────────────────
    if report.classification.value != "Security Incident":
        lines += [
            f"**Status:** {report.classification.value}",
            "",
            f"*This article was classified as '{report.classification.value}' and minimal analysis was performed.*",
            "",
            "---",
            "",
        ]

    # ── Executive Summary ─────────────────────────────────────────────────────
    lines += ["## Executive Summary", "", report.executive_summary or "_None generated._", ""]

    # ── Threat Actors ─────────────────────────────────────────────────────────
    lines += ["## Threat Actors", ""]
    if report.threat_actors:
        for ta in report.threat_actors:
            lines += [
                f"### {ta.name}",
                f"- **Aliases:** {', '.join(ta.aliases) or '—'}",
                f"- **Motivation:** {ta.motivation or '—'}",
                f"- **Evidence:** {ta.evidence or '—'}",
                "",
            ]
    else:
        lines += ["_None identified._", ""]

    # ── Campaigns ─────────────────────────────────────────────────────────────
    if report.campaigns:
        lines += ["## Campaigns", ""]
        for c in report.campaigns:
            lines += [
                f"### {c.name}",
                f"- **Aliases:** {', '.join(c.aliases) or '—'}",
                f"- **Description:** {c.description or '—'}",
                f"- **Evidence:** {c.evidence or '—'}",
                "",
            ]

    # ── Malware ───────────────────────────────────────────────────────────────
    lines += ["## Malware", ""]
    if report.malware:
        for mw in report.malware:
            lines += [
                f"### {mw.name} ({mw.malware_type.value})",
                f"- **Aliases:** {', '.join(mw.aliases) or '—'}",
                f"- **Description:** {mw.description or '—'}",
                "",
            ]
    else:
        lines += ["_None identified._", ""]

    # ── IOCs ──────────────────────────────────────────────────────────────────
    lines += ["## Indicators of Compromise", ""]
    if report.iocs:
        lines += [
            _table(
                ["IOC Value", "Type", "Context"],
                [[i.value, i.ioc_type.value, i.context or "—"]
                 for i in report.iocs],
            ), "",
        ]
    else:
        lines += ["_None extracted._", ""]

    # ── Behaviors with Rich Context ───────────────────────────────────────────
    lines += ["## Observed Behaviors", ""]
    if report.behaviors:
        for i, b in enumerate(report.behaviors, 1):
            artifacts = ", ".join(f"`{a}`" for a in b.artifacts) if b.artifacts else "—"
            lines += [
                f"**{i}. {b.behavior}**",
                f"- **Evidence:** {b.evidence}",
            ]
            
            if b.artifacts:
                lines.append(f"- **Artifacts:** {artifacts}")
            
            if b.context:
                lines.append(f"- **Context:** {b.context}")
            
            lines.append("")
    else:
        lines += ["_None extracted._", ""]


    # ── ATT&CK Mapping (Stage B) ──────────────────────────────────────────────
    lines += ["## MITRE ATT&CK Mapping", ""]
    if report.attack_mappings:
        lines += [
            _table(
                ["Tactic", "Technique ID", "Technique Name", "Observed Behavior"],
                [
                    [
                        m.tactic,
                        f"`{m.technique_id}`",
                        m.technique_name,
                        m.observed_behavior[:70]
                    ]
                    for m in report.attack_mappings
                ],
            ), "",
        ]
    else:
        lines += ["_No techniques mapped._", ""]

            
    lines += ["## PEAK Hunt Hypotheses", ""]

    if report.peak_hunts:

        for i, hunt in enumerate(report.peak_hunts, 1):

            lines += [
                f"### Hunt {i}",
                "",
                "#### Prepare",
                f"- **Hypothesis:** {hunt.prepare.hypothesis}",
                f"- **Behavior Basis:** {hunt.prepare.behavior_basis}",
                f"- **Objective:** {hunt.prepare.objective}",
                f"- **Required Data Sources:** {', '.join(hunt.prepare.required_data_sources)}",
                "",
                "#### Execute",
                "",
                "**Gather Data**",
            ]

            for item in hunt.execute.gather_data:
                lines.append(f"- {item}")

            lines += ["", "**Analysis Steps**"]

            for item in hunt.execute.analysis_steps:
                lines.append(f"- {item}")

            lines += ["", "**Supporting Evidence**"]

            for item in hunt.execute.supporting_evidence:
                lines.append(f"- {item}")

            lines += [
                "",
                "#### Act",
                f"- **Documentation Requirements:** {hunt.act.documentation_requirements}",
                "",
                "**Findings to Preserve**",
            ]

            for item in hunt.act.findings_to_preserve:
                lines.append(f"- {item}")

            lines += ["", "**Future Hunt Recommendations**"]

            for item in hunt.act.future_hunt_recommendations:
                lines.append(f"- {item}")

            lines.append("")

    else:
        lines += ["_No hunt hypotheses generated._", ""]

    lines += ["---", f"*Generated by Threat Hunt Generation Pipeline | {now}*"]
    return "\n".join(lines)


def save_report_file(report: HuntReport, output_dir: Path | None = None) -> Path:
    """Save rendered report to markdown file."""
    output_dir = Path(REPORT_DIR)
    output_dir.mkdir(parents=True, exist_ok=True)

    date_str = report.article.rss_article.published_date.strftime("%Y-%m-%d")
    title    = report.article.rss_article.title[:50]
    safe     = "".join(c if c.isalnum() or c in "- " else "_" for c in title).strip()
    path     = output_dir / f"{date_str}_{safe.replace(' ', '_')}.md"

    path.write_text(render_report(report), encoding="utf-8")
    logger.info("Report written: %s", path)
    return path


def save_all_reports(reports: list[HuntReport], output_dir: Path | None = None) -> list[Path]:
    """Save multiple reports."""
    paths = []
    for r in reports:
        try:
            paths.append(save_report_file(r, output_dir))
        except Exception as exc:
            logger.exception("Failed to write report")
    return paths


def export_ioc_csv(reports: list[HuntReport], output_dir: Path | None = None) -> Path:
    """Export all IOCs to CSV."""
    output_dir = Path(output_dir or REPORT_DIR)
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / f"{datetime.utcnow().strftime('%Y-%m-%d')}_iocs.csv"

    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=[
            "value", "type", "context", "source", "url", "published_date"
        ])
        w.writeheader()
        for r in reports:
            rss = r.article.rss_article
            for ioc in r.iocs:
                w.writerow({
                    "value":          ioc.value,
                    "type":           ioc.ioc_type.value,
                    "context":        ioc.context or "",
                    "source":         rss.source,
                    "url":            rss.url,
                    "published_date": rss.published_date.strftime("%Y-%m-%d"),
                })

    total = sum(len(r.iocs) for r in reports)
    logger.info("IOC CSV: %s (%d IOCs)", path, total)
    return path

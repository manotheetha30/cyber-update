from markdown import markdown
from weasyprint import HTML

with open(r"M:\cyber\reports\2026-06-22_FortiBleed_campaign_used_custom_FortiGate_sniffer.md", encoding="utf-8") as f:
    md = f.read()

html = markdown(md, extensions=["tables", "fenced_code"])

HTML(string=html).write_pdf("M:\\cyber\\reports\\FortiBleed_Report.pdf")
from markdown import markdown
from weasyprint import HTML

def convert_md_file_to_pdf(md_file, pdf_file):

    with open(md_file, "r", encoding="utf-8") as f:
        md = f.read()

    html = markdown(
        md,
        extensions=[
            "tables",
            "fenced_code",
            "toc",
        ],
    )

    HTML(string=html).write_pdf(pdf_file)
convert_md_file_to_pdf(
    "reports/2026-06-17_Crypto_Clipper_Campaign_Abuses_Fake_Reviews__AI_Na.md",
    "reports/report.pdf"
)
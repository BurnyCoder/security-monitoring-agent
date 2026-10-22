"""Global: reproducible validation artifact. Local: render the concise Markdown report with ReportLab.

Sources: https://docs.reportlab.com/reportlab/userguide/ch5_platypus/ and
https://docs.reportlab.com/reportlab/userguide/ch6_paragraphs/ . This intentionally supports only
the headings, paragraphs, lists, links, and explicit page breaks used by this repository's report.
"""

import re  # Translate the small authored Markdown subset without executing document content.
from html import escape  # ReportLab's XML-like paragraph syntax needs escaped literal text.
from pathlib import Path  # Resolve files relative to the repository, not the caller's working directory.

from reportlab.lib import colors  # Use the dashboard's muted teal palette for print.
from reportlab.lib.pagesizes import A4  # A portable paper format for the downloadable report.
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet  # Reuse maintained paragraph layout.
from reportlab.lib.units import mm  # Express margins in physical units.
from reportlab.platypus import PageBreak, Paragraph, SimpleDocTemplate, Table, TableStyle  # Standard flowables handle text and the pipeline figure.


def inline(text: str) -> str:
    """Global: preserve readable source citations. Local: escape first, then translate authored inline marks."""
    text = escape(text)  # Literal angle brackets cannot become layout instructions.
    text = re.sub(r"\[([^\]]+)\]\((https?://[^ )]+)\)", r'<link href="\2" color="#24766b">\1</link>', text)  # Keep official source links clickable.
    text = re.sub(r"\*\*([^*]+)\*\*", r"<b>\1</b>", text)  # Bold is used for a few outcome labels.
    return re.sub(r"`([^`]+)`", r'<font name="Courier">\1</font>', text)  # Distinguish exact model names and commands.


def footer(canvas, document) -> None:
    """Global: stable printed context. Local: number every page without changing content flow."""
    canvas.saveState()  # Do not leak footer styles into document flowables.
    canvas.setStrokeColor(colors.HexColor("#d9e3df"))  # Quiet separator matches the dashboard.
    canvas.line(20 * mm, 18 * mm, 190 * mm, 18 * mm)  # Remain inside the document margins.
    canvas.setFont("Helvetica", 8)  # Built-in font needs no machine-specific font installation.
    canvas.setFillColor(colors.HexColor("#53655f"))  # Maintain readable contrast on white paper.
    canvas.drawString(20 * mm, 13 * mm, "Sentinel | Engineering validation | Libor Burian")  # Credit the requested author.
    canvas.drawRightString(190 * mm, 13 * mm, str(document.page))  # Use the actual paginated page number.
    canvas.restoreState()  # Restore the flowable renderer's graphics state.


def architecture(styles) -> Table:
    """Global: show the evidence path. Local: a compact graph keeps the five pipeline phases distinct.

    Source: https://docs.reportlab.com/reportlab/userguide/ch7_tables/ .
    """
    phases = ["Inventory", "Sources + OSV", "Agent research", "Validation", "SQLite + UI"]  # Match the implementation wrapper's ordered phases.
    cells = []  # Alternating phase and arrow cells form a simple directed path.
    for index, phase in enumerate(phases):  # Reuse the same styles for every node.
        if index:  # Connect each node to its predecessor.
            cells.append(Paragraph("&gt;", styles["ReportBody"]))  # ASCII arrows avoid font-substitution problems.
        cells.append(Paragraph(phase, styles["ReportBody"]))  # Paragraphs wrap within their fixed node width.
    table = Table([cells], colWidths=[28 * mm if index % 2 == 0 else 6 * mm for index in range(9)])  # Fit the figure within the printable width.
    table.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "MIDDLE"), ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#edf4f0")), ("TOPPADDING", (0, 0), (-1, -1), 7), ("BOTTOMPADDING", (0, 0), (-1, -1), 7)]))  # Quiet emphasis separates the diagram from prose.
    return table  # Platypus paginates the entire figure as one unit.


def build_report() -> Path:
    """Global: one source of report prose. Local: render validation-summary.md to the committed PDF."""
    root = Path(__file__).resolve().parents[1]  # Work from a clone regardless of shell cwd.
    source = root / "reports" / "validation-summary.md"  # This Markdown is the editable report source.
    target = root / "reports" / "validation-report.pdf"  # Public report contains sanitized observations only.
    styles = getSampleStyleSheet()  # Use ReportLab's documented stylesheet foundation.
    styles.add(ParagraphStyle(name="ReportBody", fontName="Helvetica", fontSize=9.5, leading=13.5, spaceAfter=7, textColor=colors.HexColor("#233a3d")))  # Compact but readable line spacing keeps the report concise.
    styles.add(ParagraphStyle(name="ReportTitle", fontName="Helvetica-Bold", fontSize=25, leading=29, spaceAfter=16, textColor=colors.HexColor("#17343c")))  # Single clear title hierarchy.
    styles.add(ParagraphStyle(name="ReportHeading", fontName="Helvetica-Bold", fontSize=13, leading=18, spaceBefore=12, spaceAfter=7, keepWithNext=True, textColor=colors.HexColor("#24766b")))  # Keep section titles with their first paragraph.
    story = []  # Platypus flows this ordered sequence across pages.
    for block in source.read_text(encoding="utf-8").strip().split("\n\n"):  # Authored paragraphs are separated by blank lines.
        if block.strip() == "<!-- architecture -->":  # One source marker inserts the implementation diagram.
            story.append(architecture(styles))  # Keep the figure reproducible without a bitmap dependency.
        elif block.strip() == "<!-- pagebreak -->":  # Allow intentional method/results page boundaries.
            story.append(PageBreak())  # No manual y-coordinate arithmetic is needed.
        elif block.startswith("# "):  # The document has one top-level title.
            story.append(Paragraph(inline(block[2:]), styles["ReportTitle"]))  # Wrap long titles safely.
        elif block.startswith("## "):  # All report sections use the same visual level.
            story.append(Paragraph(inline(block[3:]), styles["ReportHeading"]))  # Preserve predictable heading hierarchy.
        elif block.startswith("- "):  # Lists contain parallel evidence points, not nested outlines.
            for line in block.splitlines():  # Keep each item independently wrappable.
                story.append(Paragraph(inline(line.removeprefix("- ")), styles["ReportBody"], bulletText="-"))  # Use an ASCII bullet supported by built-in fonts.
        else:  # Standard paragraphs include metadata, narrative, and citations.
            story.append(Paragraph(inline(block.replace("\n", " ")), styles["ReportBody"]))  # Join soft Markdown lines before wrapping.
    document = SimpleDocTemplate(str(target), pagesize=A4, rightMargin=20 * mm, leftMargin=20 * mm, topMargin=18 * mm, bottomMargin=25 * mm, title="Sentinel: local vulnerability monitoring validation", author="Libor Burian")  # Embed useful PDF metadata.
    document.build(story, onFirstPage=footer, onLaterPages=footer)  # The same footer applies to every actual page.
    return target  # CLI callers can locate the resulting artifact directly.


if __name__ == "__main__":  # Importing this module does not create or overwrite artifacts.
    print(build_report())  # Print only the output path; raw device evidence never enters the report.

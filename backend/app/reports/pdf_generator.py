import io
from datetime import datetime
from typing import Dict, Any, Optional
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.units import inch
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak,
    KeepTogether,
    Preformatted
)
from backend.app.models.scan import ScanResponse, Finding, SeverityEnum

# Color definitions
C_DARK = colors.HexColor("#0f172a")
C_PRIMARY = colors.HexColor("#0284c7")
C_CRITICAL = colors.HexColor("#dc2626")
C_HIGH = colors.HexColor("#ea580c")
C_MEDIUM = colors.HexColor("#d97706")
C_LOW = colors.HexColor("#2563eb")
C_INFO = colors.HexColor("#475569")
C_BG_CODE = colors.HexColor("#f8fafc")
C_BORDER = colors.HexColor("#cbd5e1")

def get_severity_color(sev: SeverityEnum):
    if sev == SeverityEnum.CRITICAL:
        return C_CRITICAL
    elif sev == SeverityEnum.HIGH:
        return C_HIGH
    elif sev == SeverityEnum.MEDIUM:
        return C_MEDIUM
    elif sev == SeverityEnum.LOW:
        return C_LOW
    return C_INFO

def generate_audit_pdf(scan_response: ScanResponse, lab_results: Optional[Dict[str, Any]] = None) -> bytes:
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        leftMargin=36,
        rightMargin=36,
        topMargin=36,
        bottomMargin=36
    )

    styles = getSampleStyleSheet()
    
    # Custom styles
    title_style = ParagraphStyle(
        "DocTitle",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=24,
        leading=28,
        textColor=C_DARK
    )
    
    subtitle_style = ParagraphStyle(
        "DocSubtitle",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=12,
        leading=16,
        textColor=C_INFO
    )

    heading1_style = ParagraphStyle(
        "Heading1",
        parent=styles["Heading1"],
        fontName="Helvetica-Bold",
        fontSize=16,
        leading=20,
        textColor=C_DARK,
        spaceBefore=12,
        spaceAfter=6
    )

    heading2_style = ParagraphStyle(
        "Heading2",
        parent=styles["Heading2"],
        fontName="Helvetica-Bold",
        fontSize=12,
        leading=16,
        textColor=C_PRIMARY,
        spaceBefore=8,
        spaceAfter=4
    )

    body_style = ParagraphStyle(
        "Body",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=9,
        leading=13,
        textColor=colors.HexColor("#334155")
    )

    code_style = ParagraphStyle(
        "CodeText",
        parent=styles["Code"],
        fontName="Courier",
        fontSize=8,
        leading=10,
        textColor=colors.HexColor("#0f172a")
    )

    story = []

    # Title & Header
    story.append(Paragraph("🛡️ WEB3 SENTINEL", title_style))
    story.append(Paragraph("Smart Contract Security Analysis & Audit Report", subtitle_style))
    story.append(Spacer(1, 10))

    # Meta Table
    scan_date = scan_response.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC")
    meta_data = [
        [Paragraph("<b>Target File:</b>", body_style), Paragraph(scan_response.target_name, body_style),
         Paragraph("<b>Audit Date:</b>", body_style), Paragraph(scan_date, body_style)],
        [Paragraph("<b>Scan ID:</b>", body_style), Paragraph(scan_response.scan_id[:18] + "...", body_style),
         Paragraph("<b>Execution Time:</b>", body_style), Paragraph(f"{scan_response.summary.execution_time_ms} ms", body_style)]
    ]
    meta_table = Table(meta_data, colWidths=[90, 180, 90, 180])
    meta_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f1f5f9")),
        ("PADDING", (0, 0), (-1, -1), 6),
        ("BOX", (0, 0), (-1, -1), 0.5, C_BORDER),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, C_BORDER),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 15))

    # Executive Summary
    story.append(Paragraph("1. Executive Summary", heading1_style))
    score = scan_response.summary.security_score
    risk_label = "CRITICAL RISK" if scan_response.summary.critical_count > 0 else (
        "HIGH RISK" if scan_response.summary.high_count > 0 else (
            "MEDIUM RISK" if scan_response.summary.medium_count > 0 else "SECURE / LOW RISK"
        )
    )

    summary_text = (
        f"Web3 Sentinel automated static and heuristic analysis was performed on <b>{scan_response.target_name}</b>. "
        f"The system identified a total of <b>{scan_response.summary.total_findings}</b> security finding(s). "
        f"The resulting security health score is calculated at <b>{score} / 100</b> ({risk_label}). "
        "Automated static verification is supplemented by sandboxed Foundry exploit reproduction."
    )
    story.append(Paragraph(summary_text, body_style))
    story.append(Spacer(1, 10))

    # Severity Breakdown Table
    sev_data = [
        ["Severity Level", "Findings Discovered", "Risk Weight", "Status"],
        ["Critical", str(scan_response.summary.critical_count), "High Impact / Immediate Drain", "Action Required" if scan_response.summary.critical_count > 0 else "Clear"],
        ["High", str(scan_response.summary.high_count), "Significant Financial / Logic Risk", "Action Required" if scan_response.summary.high_count > 0 else "Clear"],
        ["Medium", str(scan_response.summary.medium_count), "Conditional Vulnerability", "Review Recommended" if scan_response.summary.medium_count > 0 else "Clear"],
        ["Low", str(scan_response.summary.low_count), "Best Practice / Low Attack Surface", "Informational"],
        ["Informational", str(scan_response.summary.info_count), "Code Quality / Optimization", "Informational"]
    ]
    sev_table = Table(sev_data, colWidths=[110, 110, 190, 130])
    sev_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), C_DARK),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("ALIGN", (0, 0), (-1, -1), "LEFT"),
        ("ALIGN", (1, 0), (1, -1), "CENTER"),
        ("PADDING", (0, 0), (-1, -1), 5),
        ("GRID", (0, 0), (-1, -1), 0.5, C_BORDER),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
        ("TEXTCOLOR", (0, 1), (0, 1), C_CRITICAL),
        ("TEXTCOLOR", (0, 2), (0, 2), C_HIGH),
        ("TEXTCOLOR", (0, 3), (0, 3), C_MEDIUM),
        ("TEXTCOLOR", (0, 4), (0, 4), C_LOW),
    ]))
    story.append(sev_table)
    story.append(Spacer(1, 15))

    # Methodology & Scope
    story.append(Paragraph("2. Scope & Audit Methodology", heading1_style))
    method_text = (
        "The security analysis follows a multi-phase verification pipeline:<br/>"
        "• <b>Static Analysis:</b> AST traversal and Slither vulnerability detectors.<br/>"
        "• <b>Heuristic Inspection:</b> Checks for reentrancy patterns, missing access control, unchecked return values, tx.origin misuse, oracle manipulation, and unbounded loops.<br/>"
        "• <b>Controlled Exploitation Lab:</b> Local Foundry sandboxed execution verifying proof-of-concept exploits and confirming that remediated contracts successfully mitigate the vulnerabilities."
    )
    story.append(Paragraph(method_text, body_style))
    story.append(Spacer(1, 15))

    # Detailed Findings
    story.append(Paragraph("3. Detailed Vulnerability Findings", heading1_style))
    
    if not scan_response.findings:
        story.append(Paragraph("No vulnerabilities were identified during this automated scan.", body_style))
    else:
        for idx, f in enumerate(scan_response.findings, 1):
            finding_items = []
            sev_color = get_severity_color(f.severity)
            title_p = Paragraph(f"<b>{idx}. [{f.severity.value.upper()}] {f.name}</b>", heading2_style)
            finding_items.append(title_p)

            # Details table
            detail_data = [
                [Paragraph("<b>Category:</b>", body_style), Paragraph(f.category, body_style),
                 Paragraph("<b>Confidence:</b>", body_style), Paragraph(f.confidence.value, body_style)],
                [Paragraph("<b>Location:</b>", body_style), Paragraph(f"{f.file_path} (Lines {f.line_start}-{f.line_end})", body_style),
                 Paragraph("<b>Function:</b>", body_style), Paragraph(f.function_name, body_style)],
                [Paragraph("<b>Detected By:</b>", body_style), Paragraph(f.tool, body_style),
                 Paragraph("<b>Contract:</b>", body_style), Paragraph(f.contract_name, body_style)]
            ]
            d_table = Table(detail_data, colWidths=[80, 190, 80, 190])
            d_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
                ("PADDING", (0, 0), (-1, -1), 4),
                ("BOX", (0, 0), (-1, -1), 0.5, C_BORDER),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, C_BORDER),
            ]))
            finding_items.append(d_table)
            finding_items.append(Spacer(1, 4))

            # Description
            finding_items.append(Paragraph(f"<b>Technical Explanation:</b> {f.description}", body_style))
            finding_items.append(Spacer(1, 4))
            finding_items.append(Paragraph(f"<b>Impact:</b> {f.impact}", body_style))
            finding_items.append(Spacer(1, 4))

            # Code snippet if present
            if f.code_snippet:
                snippet_text = f.code_snippet.replace("\t", "    ")
                code_table = Table([[Preformatted(snippet_text, code_style)]], colWidths=[540])
                code_table.setStyle(TableStyle([
                    ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#1e293b")),
                    ("TEXTCOLOR", (0, 0), (-1, -1), colors.HexColor("#38bdf8")),
                    ("PADDING", (0, 0), (-1, -1), 6),
                    ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#475569")),
                ]))
                finding_items.append(code_table)
                finding_items.append(Spacer(1, 4))

            # Remediation
            finding_items.append(Paragraph(f"<b>Recommended Fix:</b> {f.remediation}", body_style))
            finding_items.append(Spacer(1, 10))

            story.append(KeepTogether(finding_items))

    # Controlled PoC Results if present
    if lab_results:
        story.append(Paragraph("4. Controlled Exploitation Lab Results", heading1_style))
        lab_text = (
            f"<b>Lab Scenario:</b> {lab_results.get('lab_id', 'Reentrancy')}<br/>"
            f"<b>Exploit Execution Status:</b> {'SUCCESSFULLY DEMONSTRATED' if lab_results.get('passed') else 'FAILED'}<br/>"
            f"<b>Gas Consumed:</b> {lab_results.get('gas_used', 'N/A')}<br/>"
            f"<b>Mechanics:</b> {lab_results.get('explanation', '')}"
        )
        story.append(Paragraph(lab_text, body_style))
        story.append(Spacer(1, 10))

    # Disclaimers
    story.append(Paragraph("5. Limitations & Security Disclaimer", heading1_style))
    disclaimer_text = (
        "Web3 Sentinel automated security audits are meant for developer assistance, vulnerability detection, and research. "
        "Automated tools may produce false negatives or false positives. The security score reflects heuristic metrics "
        "and must not be interpreted as absolute proof that a smart contract is secure against zero-day exploits or complex economic attacks. "
        "Developers must conduct rigorous manual audits and property-based invariant testing before committing production funds."
    )
    story.append(Paragraph(disclaimer_text, body_style))

    doc.build(story)
    return buffer.getvalue()

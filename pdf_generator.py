"""PDF Report Generator - Bilingual (ES/EN) security audit report using ReportLab."""

import io
import os
from datetime import datetime
from collections import Counter
from xml.sax.saxutils import escape as xml_escape


def esc(text: str) -> str:
    """Escape text for safe use inside ReportLab Paragraph (XML-based)."""
    if not text:
        return ""
    return xml_escape(str(text))

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT, TA_JUSTIFY
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm, cm
from reportlab.platypus import (
    BaseDocTemplate, Frame, PageTemplate, NextPageTemplate,
    Paragraph, Spacer, Table, TableStyle, HRFlowable,
    KeepTogether, PageBreak,
)
from reportlab.platypus.flowables import Flowable
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.graphics.shapes import Drawing, Rect, String, Circle
from reportlab.graphics import renderPDF

# ── Color Palette ──────────────────────────────────────────────────────────
C_BG        = colors.HexColor("#06080d")
C_SURFACE   = colors.HexColor("#111820")
C_ACCENT    = colors.HexColor("#3b82f6")
C_CRITICAL  = colors.HexColor("#ef4444")
C_HIGH      = colors.HexColor("#f97316")
C_MEDIUM    = colors.HexColor("#eab308")
C_LOW       = colors.HexColor("#3b82f6")
C_INFO      = colors.HexColor("#6b7280")
C_GREEN     = colors.HexColor("#22c55e")
C_WHITE     = colors.HexColor("#e2e8f0")
C_TEXT_DIM  = colors.HexColor("#94a3b8")
C_BORDER    = colors.HexColor("#1e2a3a")

SEV_COLORS = {
    "CRITICAL": C_CRITICAL,
    "HIGH":     C_HIGH,
    "MEDIUM":   C_MEDIUM,
    "LOW":      C_LOW,
    "INFO":     C_INFO,
}

# ── Translations ────────────────────────────────────────────────────────────
STRINGS = {
    "es": {
        "title": "REPORTE DE SEGURIDAD",
        "subtitle": "Security Guard - Análisis de Vulnerabilidades",
        "prepared_by": "Preparado por",
        "tool": "Security Guard v1.0",
        "date": "Fecha",
        "target": "Proyecto analizado",
        "files_scanned": "Archivos analizados",
        "total_findings": "Vulnerabilidades encontradas",
        "scan_duration": "Duración del análisis",
        "confidential": "CONFIDENCIAL - Solo para uso autorizado",
        # Sections
        "sec_summary": "1. RESUMEN EJECUTIVO",
        "sec_score": "Puntuación de Seguridad",
        "sec_findings_dist": "Distribución de Hallazgos",
        "sec_owasp": "Categorías OWASP Top 10",
        "sec_scanners": "2. RESULTADOS POR SCANNER",
        "sec_roadmap": "3. PLAN DE REMEDIACIÓN",
        "sec_findings": "4. HALLAZGOS DETALLADOS",
        "sec_appendix": "5. APÉNDICE - RECOMENDACIONES GENERALES",
        # Score
        "score_label": "Puntuación",
        "grade_label": "Calificación",
        "score_interpretation": "Interpretación de la puntuación",
        "score_90": "90-100 (A): Excelente - Proyecto seguro para producción",
        "score_80": "80-89  (B): Bueno - Riesgos menores, monitoreo recomendado",
        "score_70": "70-79  (C): Aceptable - Requiere mejoras antes de producción",
        "score_60": "60-69  (D): Deficiente - Vulnerabilidades significativas",
        "score_0":  "0-59   (F): Crítico - No apto para producción",
        # Table headers
        "th_severity": "Severidad",
        "th_count": "Cantidad",
        "th_penalty": "Penalización",
        "th_scanner": "Scanner",
        "th_files": "Archivos",
        "th_findings": "Hallazgos",
        "th_time": "Tiempo",
        "th_category": "Categoría",
        "th_file": "Archivo",
        "th_line": "Línea",
        # Roadmap
        "roadmap_target": "Objetivo: alcanzar 90% de seguridad",
        "roadmap_current": "Puntuación actual",
        "roadmap_needed": "Puntos necesarios",
        "roadmap_step_critical": "PASO {n}: Corregir {c} vulnerabilidades CRÍTICAS",
        "roadmap_step_high": "PASO {n}: Corregir {c} vulnerabilidades ALTAS",
        "roadmap_step_medium": "PASO {n}: Atender {c} hallazgos MEDIOS",
        "roadmap_step_general": "PASO {n}: Implementar medidas preventivas",
        "roadmap_desc_critical": "Las vulnerabilidades críticas son explotables activamente. Cada corrección recupera ~15 puntos. Requieren atención inmediata.",
        "roadmap_desc_high": "Los hallazgos de alta severidad representan riesgos significativos. Cada corrección recupera ~8 puntos. Planificar para el próximo sprint.",
        "roadmap_desc_medium": "Mejoras de buenas prácticas. Cada corrección recupera ~4 puntos.",
        "roadmap_desc_general": "Agregar escaneo de seguridad en CI/CD, hooks de pre-commit, auditoría de dependencias y pruebas de penetración periódicas.",
        "roadmap_achieved": "¡El proyecto ya cumple el objetivo del 90% de seguridad! Continúe monitoreando vulnerabilidades nuevas.",
        # Finding detail
        "finding_description": "Descripción",
        "finding_file": "Archivo",
        "finding_line": "Línea",
        "finding_category": "Categoría OWASP",
        "finding_cwe": "Identificador CWE",
        "finding_code": "Fragmento de código",
        "finding_root_cause": "Causa Raíz",
        "finding_consequences": "Consecuencias",
        "finding_attack": "Simulación de Ataque",
        "finding_rec": "Recomendación",
        "finding_na": "N/A",
        # Appendix
        "app_items": [
            ("Automatizar escaneo de seguridad",
             "Integrar herramientas como pip-audit, npm audit, o Snyk en el pipeline de CI/CD para detectar vulnerabilidades en dependencias automáticamente con cada commit."),
            ("Gestión segura de secretos",
             "Nunca hardcodear credenciales en el código fuente. Usar variables de entorno, gestores de secretos (AWS Secrets Manager, HashiCorp Vault) o archivos .env excluidos de git."),
            ("Implementar cabeceras de seguridad HTTP",
             "Configurar Content-Security-Policy, X-Frame-Options, X-Content-Type-Options, Strict-Transport-Security y Permissions-Policy en el servidor web."),
            ("Validación y sanitización de entradas",
             "Validar y sanitizar todo input de usuario en el servidor. Usar consultas parametrizadas para bases de datos. Escapar output antes de renderizarlo en HTML."),
            ("Gestión de dependencias",
             "Mantener todas las dependencias actualizadas. Usar Dependabot o Renovate para actualizaciones automáticas. Revisar el SBOM (Software Bill of Materials) regularmente."),
            ("Principio de mínimo privilegio",
             "Ejecutar aplicaciones y servicios con el mínimo de permisos necesarios. Revisar roles IAM, permisos de archivos y accesos a bases de datos periódicamente."),
            ("Manejo seguro de errores",
             "No exponer stack traces, rutas internas ni versiones de software al usuario. Implementar logging centralizado con alertas sobre errores inusuales."),
            ("Pruebas de seguridad regulares",
             "Realizar pruebas de penetración al menos una vez por año. Participar en programas de bug bounty. Mantener un proceso de reporte de vulnerabilidades responsable."),
        ],
        # Footer
        "footer_page": "Página",
        "footer_of": "de",
        "footer_conf": "Confidencial",
    },
    "en": {
        "title": "SECURITY REPORT",
        "subtitle": "Security Guard - Vulnerability Analysis",
        "prepared_by": "Prepared by",
        "tool": "Security Guard v1.0",
        "date": "Date",
        "target": "Analyzed project",
        "files_scanned": "Files scanned",
        "total_findings": "Vulnerabilities found",
        "scan_duration": "Scan duration",
        "confidential": "CONFIDENTIAL - For authorized use only",
        # Sections
        "sec_summary": "1. EXECUTIVE SUMMARY",
        "sec_score": "Security Score",
        "sec_findings_dist": "Findings Distribution",
        "sec_owasp": "OWASP Top 10 Categories",
        "sec_scanners": "2. SCANNER RESULTS",
        "sec_roadmap": "3. REMEDIATION ROADMAP",
        "sec_findings": "4. DETAILED FINDINGS",
        "sec_appendix": "5. APPENDIX - GENERAL RECOMMENDATIONS",
        # Score
        "score_label": "Score",
        "grade_label": "Grade",
        "score_interpretation": "Score interpretation",
        "score_90": "90-100 (A): Excellent - Project safe for production",
        "score_80": "80-89  (B): Good - Minor risks, monitoring recommended",
        "score_70": "70-79  (C): Acceptable - Improvements needed before production",
        "score_60": "60-69  (D): Poor - Significant vulnerabilities present",
        "score_0":  "0-59   (F): Critical - Not suitable for production",
        # Table headers
        "th_severity": "Severity",
        "th_count": "Count",
        "th_penalty": "Penalty",
        "th_scanner": "Scanner",
        "th_files": "Files",
        "th_findings": "Findings",
        "th_time": "Time",
        "th_category": "Category",
        "th_file": "File",
        "th_line": "Line",
        # Roadmap
        "roadmap_target": "Goal: reach 90% security score",
        "roadmap_current": "Current score",
        "roadmap_needed": "Points needed",
        "roadmap_step_critical": "STEP {n}: Fix {c} CRITICAL vulnerabilities",
        "roadmap_step_high": "STEP {n}: Fix {c} HIGH severity issues",
        "roadmap_step_medium": "STEP {n}: Address {c} MEDIUM findings",
        "roadmap_step_general": "STEP {n}: Implement preventive measures",
        "roadmap_desc_critical": "Critical vulnerabilities are actively exploitable. Each fix recovers ~15 points. Requires immediate attention.",
        "roadmap_desc_high": "High severity findings represent significant risks. Each fix recovers ~8 points. Plan for next sprint.",
        "roadmap_desc_medium": "Best-practice improvements. Each fix recovers ~4 points.",
        "roadmap_desc_general": "Add CI/CD security scanning, pre-commit hooks, dependency auditing, and regular penetration testing.",
        "roadmap_achieved": "The project already meets the 90% security target! Keep monitoring for new vulnerabilities.",
        # Finding detail
        "finding_description": "Description",
        "finding_file": "File",
        "finding_line": "Line",
        "finding_category": "OWASP Category",
        "finding_cwe": "CWE Identifier",
        "finding_code": "Code Snippet",
        "finding_root_cause": "Root Cause",
        "finding_consequences": "Consequences",
        "finding_attack": "Attack Simulation",
        "finding_rec": "Recommendation",
        "finding_na": "N/A",
        # Appendix
        "app_items": [
            ("Automate security scanning",
             "Integrate tools such as pip-audit, npm audit, or Snyk into the CI/CD pipeline to automatically detect dependency vulnerabilities on every commit."),
            ("Secure secrets management",
             "Never hardcode credentials in source code. Use environment variables, secrets managers (AWS Secrets Manager, HashiCorp Vault), or .env files excluded from git."),
            ("Implement HTTP security headers",
             "Configure Content-Security-Policy, X-Frame-Options, X-Content-Type-Options, Strict-Transport-Security, and Permissions-Policy on the web server."),
            ("Input validation and sanitization",
             "Validate and sanitize all user input on the server side. Use parameterized queries for databases. Escape output before rendering it in HTML."),
            ("Dependency management",
             "Keep all dependencies up to date. Use Dependabot or Renovate for automatic updates. Review the Software Bill of Materials (SBOM) regularly."),
            ("Principle of least privilege",
             "Run applications and services with the minimum required permissions. Periodically review IAM roles, file permissions, and database access."),
            ("Secure error handling",
             "Do not expose stack traces, internal paths, or software versions to users. Implement centralized logging with alerts for unusual errors."),
            ("Regular security testing",
             "Conduct penetration testing at least once a year. Participate in bug bounty programs. Maintain a responsible vulnerability disclosure process."),
        ],
        # Footer
        "footer_page": "Page",
        "footer_of": "of",
        "footer_conf": "Confidential",
    },
}


# ── Styles ──────────────────────────────────────────────────────────────────
def make_styles():
    base = getSampleStyleSheet()
    s = {}

    s["cover_title"] = ParagraphStyle(
        "cover_title", fontSize=28, textColor=C_WHITE,
        alignment=TA_CENTER, fontName="Helvetica-Bold", leading=34,
        spaceAfter=6,
    )
    s["cover_subtitle"] = ParagraphStyle(
        "cover_subtitle", fontSize=13, textColor=C_ACCENT,
        alignment=TA_CENTER, fontName="Helvetica", leading=18,
        spaceAfter=4,
    )
    s["cover_meta"] = ParagraphStyle(
        "cover_meta", fontSize=10, textColor=C_TEXT_DIM,
        alignment=TA_CENTER, fontName="Helvetica", leading=16,
    )
    s["cover_conf"] = ParagraphStyle(
        "cover_conf", fontSize=8, textColor=C_TEXT_DIM,
        alignment=TA_CENTER, fontName="Helvetica-Oblique",
    )
    s["section_title"] = ParagraphStyle(
        "section_title", fontSize=13, textColor=C_WHITE,
        fontName="Helvetica-Bold", leading=18,
        spaceBefore=16, spaceAfter=8,
    )
    s["subsection"] = ParagraphStyle(
        "subsection", fontSize=10, textColor=C_ACCENT,
        fontName="Helvetica-Bold", leading=14,
        spaceBefore=10, spaceAfter=5,
    )
    s["body"] = ParagraphStyle(
        "body", fontSize=9, textColor=C_TEXT_DIM,
        fontName="Helvetica", leading=14, spaceAfter=4,
    )
    s["body_white"] = ParagraphStyle(
        "body_white", fontSize=9, textColor=C_WHITE,
        fontName="Helvetica", leading=14, spaceAfter=4,
    )
    s["code"] = ParagraphStyle(
        "code", fontSize=7.5, textColor=colors.HexColor("#a3e635"),
        fontName="Courier", leading=11, spaceAfter=4,
        leftIndent=6,
    )
    s["finding_title"] = ParagraphStyle(
        "finding_title", fontSize=10, textColor=C_WHITE,
        fontName="Helvetica-Bold", leading=14, spaceAfter=4,
    )
    s["label"] = ParagraphStyle(
        "label", fontSize=7.5, textColor=C_TEXT_DIM,
        fontName="Helvetica-Bold", leading=11,
        textTransform="uppercase",
    )
    s["score_big"] = ParagraphStyle(
        "score_big", fontSize=52, textColor=C_WHITE,
        fontName="Helvetica-Bold", alignment=TA_CENTER, leading=60,
    )
    s["score_grade"] = ParagraphStyle(
        "score_grade", fontSize=18, textColor=C_TEXT_DIM,
        fontName="Helvetica", alignment=TA_CENTER, leading=22,
    )
    s["score_interp"] = ParagraphStyle(
        "score_interp", fontSize=8, textColor=C_TEXT_DIM,
        fontName="Courier", leading=12, spaceAfter=2,
    )
    s["roadmap_step"] = ParagraphStyle(
        "roadmap_step", fontSize=10, textColor=C_WHITE,
        fontName="Helvetica-Bold", leading=14, spaceAfter=2,
    )
    s["roadmap_desc"] = ParagraphStyle(
        "roadmap_desc", fontSize=8.5, textColor=C_TEXT_DIM,
        fontName="Helvetica", leading=13, spaceAfter=4, leftIndent=20,
    )
    s["app_title"] = ParagraphStyle(
        "app_title", fontSize=9.5, textColor=C_ACCENT,
        fontName="Helvetica-Bold", leading=13, spaceAfter=2,
    )
    s["app_body"] = ParagraphStyle(
        "app_body", fontSize=8.5, textColor=C_TEXT_DIM,
        fontName="Helvetica", leading=13, spaceAfter=8, leftIndent=10,
        alignment=TA_JUSTIFY,
    )

    return s


# ── Helper Flowables ─────────────────────────────────────────────────────────
class ColoredBox(Flowable):
    """A colored rectangle background."""
    def __init__(self, width, height, fill_color, radius=4):
        super().__init__()
        self.width = width
        self.height = height
        self.fill_color = fill_color
        self.radius = radius

    def draw(self):
        self.canv.setFillColor(self.fill_color)
        self.canv.roundRect(0, 0, self.width, self.height, self.radius, fill=1, stroke=0)


def sev_badge_table(severity: str) -> Table:
    color = SEV_COLORS.get(severity, C_INFO)
    style = ParagraphStyle("badge", fontSize=7, textColor=colors.white,
                           fontName="Helvetica-Bold", alignment=TA_CENTER)
    t = Table([[Paragraph(severity, style)]], colWidths=[50])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), color),
        ("ROUNDEDCORNERS", [3]),
        ("TOPPADDING", (0, 0), (-1, -1), 2),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
    ]))
    return t


def dark_table(headers: list, rows: list, col_widths: list) -> Table:
    data = [headers] + rows
    style = ParagraphStyle("th", fontSize=8, textColor=C_TEXT_DIM,
                           fontName="Helvetica-Bold")
    header_row = [Paragraph(str(h), style) for h in headers]
    data[0] = header_row

    t = Table(data, colWidths=col_widths, repeatRows=1)
    ts = TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#19212d")),
        ("BACKGROUND", (0, 1), (-1, -1), colors.HexColor("#0c1017")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1),
         [colors.HexColor("#0c1017"), colors.HexColor("#111820")]),
        ("TEXTCOLOR", (0, 1), (-1, -1), C_TEXT_DIM),
        ("FONTNAME", (0, 1), (-1, -1), "Helvetica"),
        ("FONTSIZE", (0, 1), (-1, -1), 8),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#1e2a3a")),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ])
    t.setStyle(ts)
    return t


# ── Page Template ─────────────────────────────────────────────────────────────
def make_doc(buffer, title: str, lang_strings: dict):
    W, H = A4
    margin = 18 * mm

    def on_page(canvas, doc):
        canvas.saveState()
        # Dark background
        canvas.setFillColor(C_BG)
        canvas.rect(0, 0, W, H, fill=1, stroke=0)
        # Top accent line
        canvas.setFillColor(C_ACCENT)
        canvas.rect(0, H - 3, W, 3, fill=1, stroke=0)
        # Bottom bar
        canvas.setFillColor(colors.HexColor("#111820"))
        canvas.rect(0, 0, W, 14 * mm, fill=1, stroke=0)
        canvas.setStrokeColor(colors.HexColor("#1e2a3a"))
        canvas.setLineWidth(0.5)
        canvas.line(margin, 14 * mm, W - margin, 14 * mm)
        # Footer text
        canvas.setFont("Helvetica", 7)
        canvas.setFillColor(C_TEXT_DIM)
        canvas.drawString(margin, 5 * mm, lang_strings["footer_conf"])
        canvas.drawString(margin + 60, 5 * mm, title)
        page_text = f"{lang_strings['footer_page']} {doc.page}"
        canvas.drawRightString(W - margin, 5 * mm, page_text)
        canvas.restoreState()

    def on_cover(canvas, doc):
        canvas.saveState()
        canvas.setFillColor(C_BG)
        canvas.rect(0, 0, W, H, fill=1, stroke=0)
        # Shield gradient header block
        canvas.setFillColor(colors.HexColor("#0c1017"))
        canvas.rect(0, H * 0.45, W, H * 0.55, fill=1, stroke=0)
        canvas.setFillColor(C_ACCENT)
        canvas.rect(0, H - 5, W, 5, fill=1, stroke=0)
        canvas.restoreState()

    frame_cover = Frame(margin, 14 * mm, W - 2 * margin, H - 20 * mm,
                        leftPadding=0, rightPadding=0, topPadding=0, bottomPadding=0)
    frame_content = Frame(margin, 14 * mm, W - 2 * margin, H - 34 * mm,
                          leftPadding=0, rightPadding=0, topPadding=0, bottomPadding=0)

    doc = BaseDocTemplate(
        buffer, pagesize=A4, title=title,
        leftMargin=margin, rightMargin=margin,
        topMargin=20 * mm, bottomMargin=18 * mm,
    )
    doc.addPageTemplates([
        PageTemplate("cover", frames=[frame_cover], onPage=on_cover),
        PageTemplate("content", frames=[frame_content], onPage=on_page),
    ])
    return doc


# ── Main Generator ─────────────────────────────────────────────────────────────
def generate_pdf(scan_data: dict, lang: str = "es") -> bytes:
    t = STRINGS.get(lang, STRINGS["es"])
    styles = make_styles()
    buffer = io.BytesIO()

    score = scan_data.get("score", 0)
    grade = scan_data.get("grade", "F")
    findings = scan_data.get("findings", [])
    sev_counts = scan_data.get("severity_counts", {})
    cat_counts = scan_data.get("category_counts", {})
    scanners = scan_data.get("scanners", [])
    target = scan_data.get("target", "")
    date = scan_data.get("date", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    total_files = sum(s.get("files_scanned", 0) for s in scanners)
    total_time = sum(s.get("time", 0) for s in scanners)

    score_color = (C_GREEN if score >= 90 else C_MEDIUM if score >= 70
                   else C_HIGH if score >= 50 else C_CRITICAL)

    doc = make_doc(buffer, t["subtitle"], t)
    story = []

    W = A4[0] - 36 * mm  # usable width

    # ─── COVER PAGE ──────────────────────────────────────────────────────────
    story.append(Spacer(1, 60 * mm))

    # Shield icon (ASCII art in a styled box)
    shield_style = ParagraphStyle("shield", fontSize=40, textColor=C_ACCENT,
                                  alignment=TA_CENTER, leading=50)
    story.append(Paragraph("&#9940;", shield_style))
    story.append(Spacer(1, 6 * mm))

    story.append(Paragraph(t["title"], styles["cover_title"]))
    story.append(Paragraph(t["subtitle"], styles["cover_subtitle"]))
    story.append(Spacer(1, 8 * mm))
    story.append(HRFlowable(width="60%", thickness=1, color=C_BORDER, spaceAfter=8 * mm))

    story.append(Paragraph(f"{t['date']}: {esc(date)}", styles["cover_meta"]))
    story.append(Paragraph(f"{t['target']}: {esc(os.path.basename(target))}", styles["cover_meta"]))
    story.append(Paragraph(f"{t['files_scanned']}: {total_files}", styles["cover_meta"]))
    story.append(Paragraph(f"{t['total_findings']}: {len(findings)}", styles["cover_meta"]))
    story.append(Spacer(1, 6 * mm))

    # Score on cover
    sc_style = ParagraphStyle("sc", fontSize=60, textColor=score_color,
                               fontName="Helvetica-Bold", alignment=TA_CENTER, leading=70)
    grade_s = ParagraphStyle("grd", fontSize=16, textColor=C_TEXT_DIM,
                              fontName="Helvetica", alignment=TA_CENTER, leading=20)
    story.append(Paragraph(f"{score}/100", sc_style))
    story.append(Paragraph(f"{t['grade_label']}: {grade}", grade_s))
    story.append(Spacer(1, 8 * mm))
    story.append(Paragraph(f"{t['prepared_by']}: {t['tool']}", styles["cover_meta"]))
    story.append(Spacer(1, 4 * mm))
    story.append(Paragraph(t["confidential"], styles["cover_conf"]))

    # Switch to content template
    story.append(NextPageTemplate("content"))
    story.append(PageBreak())

    # ─── 1. EXECUTIVE SUMMARY ────────────────────────────────────────────────
    story.append(Paragraph(t["sec_summary"], styles["section_title"]))
    story.append(HRFlowable(width="100%", thickness=0.5, color=C_BORDER, spaceAfter=6))

    # Score + grade box
    story.append(Paragraph(t["sec_score"], styles["subsection"]))

    score_cell = Table(
        [[Paragraph(f"{score}/100", styles["score_big"]),
          Paragraph(f"{t['grade_label']} {grade}", styles["score_grade"])]],
        colWidths=[W * 0.5, W * 0.5],
    )
    score_cell.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#0c1017")),
        ("BOX", (0, 0), (-1, -1), 0.5, C_BORDER),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
    ]))
    story.append(score_cell)
    story.append(Spacer(1, 4))

    interp_lines = [
        t["score_90"], t["score_80"], t["score_70"], t["score_60"], t["score_0"]
    ]
    for line in interp_lines:
        prefix = ">>>" if (
            (score >= 90 and "90-100" in line) or
            (80 <= score < 90 and "80-89" in line) or
            (70 <= score < 80 and "70-79" in line) or
            (60 <= score < 70 and "60-69" in line) or
            (score < 60 and "0-59" in line)
        ) else "   "
        story.append(Paragraph(f"{prefix} {line}", styles["score_interp"]))
    story.append(Spacer(1, 8))

    # Findings distribution table
    story.append(Paragraph(t["sec_findings_dist"], styles["subsection"]))

    sev_rows = []
    total_penalty = 0
    for sev, penalty_per in [("CRITICAL", 15), ("HIGH", 8), ("MEDIUM", 4), ("LOW", 2), ("INFO", 0)]:
        count = sev_counts.get(sev, 0)
        pen = count * penalty_per
        total_penalty += pen
        color = SEV_COLORS[sev]
        sev_p = ParagraphStyle("sp", fontSize=8, textColor=color,
                               fontName="Helvetica-Bold")
        sev_rows.append([
            Paragraph(sev, sev_p), str(count), f"-{pen} pts"
        ])
    sev_rows.append([
        Paragraph("TOTAL", ParagraphStyle("tot", fontSize=8, textColor=C_WHITE, fontName="Helvetica-Bold")),
        str(len(findings)),
        f"-{total_penalty} pts",
    ])

    sev_table = dark_table(
        [t["th_severity"], t["th_count"], t["th_penalty"]],
        sev_rows, [W * 0.4, W * 0.3, W * 0.3]
    )
    story.append(sev_table)
    story.append(Spacer(1, 8))

    # OWASP categories
    story.append(Paragraph(t["sec_owasp"], styles["subsection"]))
    max_cat = max(cat_counts.values(), default=1)
    cat_rows = []
    for cat, count in sorted(cat_counts.items(), key=lambda x: -x[1])[:10]:
        bar_pct = int((count / max_cat) * 20)
        bar = "█" * bar_pct + "░" * (20 - bar_pct)
        bar_p = ParagraphStyle("bar", fontSize=7, textColor=C_ACCENT, fontName="Courier")
        cat_rows.append([
            Paragraph(esc(cat), styles["body"]),
            Paragraph(bar, bar_p),
            str(count),
        ])
    if cat_rows:
        cat_table = dark_table(
            [t["th_category"], "", t["th_count"]],
            cat_rows, [W * 0.45, W * 0.4, W * 0.15]
        )
        story.append(cat_table)

    story.append(PageBreak())

    # ─── 2. SCANNER RESULTS ──────────────────────────────────────────────────
    story.append(Paragraph(t["sec_scanners"], styles["section_title"]))
    story.append(HRFlowable(width="100%", thickness=0.5, color=C_BORDER, spaceAfter=6))

    scanner_rows = []
    for sc in scanners:
        status = "⚠" if sc["findings_count"] > 0 else "✓"
        status_color = C_HIGH if sc["findings_count"] > 0 else C_GREEN
        status_p = ParagraphStyle("sp", fontSize=9, textColor=status_color,
                                  fontName="Helvetica-Bold")
        scanner_rows.append([
            Paragraph(f"{status} {sc['name']}", status_p),
            str(sc["files_scanned"]),
            str(sc["findings_count"]),
            f"{sc['time']}s",
        ])

    sc_table = dark_table(
        [t["th_scanner"], t["th_files"], t["th_findings"], t["th_time"]],
        scanner_rows, [W * 0.45, W * 0.18, W * 0.18, W * 0.19]
    )
    story.append(sc_table)

    story.append(PageBreak())

    # ─── 3. ROADMAP ──────────────────────────────────────────────────────────
    story.append(Paragraph(t["sec_roadmap"], styles["section_title"]))
    story.append(HRFlowable(width="100%", thickness=0.5, color=C_BORDER, spaceAfter=6))

    if score >= 90:
        story.append(Paragraph(t["roadmap_achieved"], styles["body_white"]))
    else:
        target_score = 90.0
        points_needed = max(0, target_score - score)
        story.append(Paragraph(
            f"{t['roadmap_target']} | {t['roadmap_current']}: {score}/100 | {t['roadmap_needed']}: +{points_needed:.0f}",
            styles["body"]
        ))
        story.append(Spacer(1, 8))

        step = 1
        steps = []
        if sev_counts.get("CRITICAL", 0):
            steps.append((
                t["roadmap_step_critical"].format(n=step, c=sev_counts["CRITICAL"]),
                t["roadmap_desc_critical"], C_CRITICAL
            ))
            step += 1
        if sev_counts.get("HIGH", 0):
            steps.append((
                t["roadmap_step_high"].format(n=step, c=sev_counts["HIGH"]),
                t["roadmap_desc_high"], C_HIGH
            ))
            step += 1
        if sev_counts.get("MEDIUM", 0):
            steps.append((
                t["roadmap_step_medium"].format(n=step, c=sev_counts["MEDIUM"]),
                t["roadmap_desc_medium"], C_MEDIUM
            ))
            step += 1
        steps.append((
            t["roadmap_step_general"].format(n=step),
            t["roadmap_desc_general"], C_GREEN
        ))

        for title_str, desc_str, color in steps:
            step_title = ParagraphStyle("st", fontSize=10, textColor=color,
                                        fontName="Helvetica-Bold", leading=14)
            story.append(Paragraph(f"► {title_str}", step_title))
            story.append(Paragraph(desc_str, styles["roadmap_desc"]))
            story.append(HRFlowable(width="100%", thickness=0.3, color=C_BORDER, spaceAfter=4))

    story.append(PageBreak())

    # ─── 4. DETAILED FINDINGS ────────────────────────────────────────────────
    story.append(Paragraph(t["sec_findings"], styles["section_title"]))
    story.append(HRFlowable(width="100%", thickness=0.5, color=C_BORDER, spaceAfter=6))

    for i, f in enumerate(findings, 1):
        sev = f.get("severity", "INFO")
        sev_color = SEV_COLORS.get(sev, C_INFO)

        # Finding header
        title_p = ParagraphStyle(
            "fth", fontSize=10, textColor=C_WHITE,
            fontName="Helvetica-Bold", leading=13
        )
        num_p = ParagraphStyle(
            "fnum", fontSize=9, textColor=sev_color,
            fontName="Helvetica-Bold", leading=13
        )

        header_table = Table([
            [Paragraph(f"#{i}", num_p), Paragraph(esc(f.get("title", "")), title_p)]
        ], colWidths=[25, W - 25])
        header_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#19212d")),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ("LEFTPADDING", (0, 0), (-1, -1), 8),
            ("RIGHTPADDING", (0, 0), (-1, -1), 8),
            ("LINEBELOW", (0, 0), (-1, -1), 1, sev_color),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ]))

        # Metadata row
        meta_style = ParagraphStyle("meta", fontSize=7.5, textColor=C_TEXT_DIM,
                                    fontName="Helvetica")
        file_str = esc(f.get("file_path", t["finding_na"]))
        line_str = esc(str(f.get("line_number", ""))) if f.get("line_number") else t["finding_na"]
        cwe_str = esc(f.get("cwe_id") or t["finding_na"])

        meta_table = Table([
            [
                Paragraph(f"{t['th_severity']}: {sev}", ParagraphStyle("sm", fontSize=7.5, textColor=sev_color, fontName="Helvetica-Bold")),
                Paragraph(f"{t['finding_file']}: {file_str}", meta_style),
                Paragraph(f"{t['finding_line']}: {line_str}", meta_style),
                Paragraph(f"{t['finding_cwe']}: {cwe_str}", meta_style),
            ]
        ], colWidths=[W * 0.18, W * 0.40, W * 0.14, W * 0.28])
        meta_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#0c1017")),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("LEFTPADDING", (0, 0), (-1, -1), 8),
            ("RIGHTPADDING", (0, 0), (-1, -1), 4),
            ("GRID", (0, 0), (-1, -1), 0.3, C_BORDER),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ]))

        # Category
        cat_p = ParagraphStyle("cat", fontSize=7.5, textColor=C_ACCENT, fontName="Helvetica")
        cat_str = f.get("category", t["finding_na"])

        # Description
        desc_table = Table([
            [Paragraph(t["finding_description"], styles["label"]),
             Paragraph(esc(f.get("description", "")), styles["body"])]
        ], colWidths=[W * 0.2, W * 0.8])
        desc_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#0c1017")),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("LEFTPADDING", (0, 0), (-1, -1), 8),
            ("RIGHTPADDING", (0, 0), (-1, -1), 8),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]))

        # Code snippet
        code_snippet = esc(f.get("code_snippet", "")[:300])
        code_table = Table([
            [Paragraph(t["finding_code"], styles["label"]),
             Paragraph(code_snippet, styles["code"])]
        ], colWidths=[W * 0.2, W * 0.8])
        code_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#060a0e")),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("LEFTPADDING", (0, 0), (-1, -1), 8),
            ("RIGHTPADDING", (0, 0), (-1, -1), 8),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]))

        # Root cause
        extra_items = []
        if f.get("root_cause"):
            rc_style = ParagraphStyle("rc", fontSize=8.5, textColor=colors.HexColor("#fde68a"),
                                      fontName="Helvetica", leading=12)
            rc_label = t.get("finding_root_cause", "Root Cause")
            rc_table = Table([
                [Paragraph(esc(rc_label), styles["label"]),
                 Paragraph(esc(f["root_cause"][:600]), rc_style)]
            ], colWidths=[W * 0.2, W * 0.8])
            rc_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#1a1500")),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
                ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#78350f")),
            ]))
            extra_items.append(rc_table)

        # Consequences
        if f.get("consequences"):
            cq_style = ParagraphStyle("cq", fontSize=8.5, textColor=colors.HexColor("#fca5a5"),
                                      fontName="Helvetica", leading=12)
            cq_label = t.get("finding_consequences", "Consequences")
            cq_table = Table([
                [Paragraph(esc(cq_label), styles["label"]),
                 Paragraph(esc(f["consequences"][:600]), cq_style)]
            ], colWidths=[W * 0.2, W * 0.8])
            cq_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#1a0505")),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
                ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#7f1d1d")),
            ]))
            extra_items.append(cq_table)

        # Attack simulation
        atk_items = []
        if f.get("attack_simulation"):
            atk_style = ParagraphStyle("atk", fontSize=8, textColor=colors.HexColor("#fca5a5"),
                                       fontName="Courier", leading=11)
            atk_lines = esc(f["attack_simulation"][:500])
            atk_table = Table([
                [Paragraph(t["finding_attack"], styles["label"]),
                 Paragraph(atk_lines, atk_style)]
            ], colWidths=[W * 0.2, W * 0.8])
            atk_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#1a0a0a")),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
                ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#7f1d1d")),
            ]))
            atk_items.append(atk_table)

        # Recommendation
        rec_style = ParagraphStyle("rec", fontSize=8.5, textColor=colors.HexColor("#86efac"),
                                   fontName="Helvetica", leading=12)
        rec_table = Table([
            [Paragraph(t["finding_rec"], styles["label"]),
             Paragraph(esc(f.get("recommendation", "")), rec_style)]
        ], colWidths=[W * 0.2, W * 0.8])
        rec_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#0a1a0a")),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("LEFTPADDING", (0, 0), (-1, -1), 8),
            ("RIGHTPADDING", (0, 0), (-1, -1), 8),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#14532d")),
        ]))

        story.append(KeepTogether([header_table, meta_table, desc_table, code_table]))
        for item in extra_items:
            story.append(item)
        for item in atk_items:
            story.append(item)
        story.append(rec_table)
        story.append(Spacer(1, 8))

    story.append(PageBreak())

    # ─── 5. APPENDIX ─────────────────────────────────────────────────────────
    story.append(Paragraph(t["sec_appendix"], styles["section_title"]))
    story.append(HRFlowable(width="100%", thickness=0.5, color=C_BORDER, spaceAfter=6))

    for idx, (app_title, app_body) in enumerate(t["app_items"], 1):
        story.append(Paragraph(f"{idx}. {app_title}", styles["app_title"]))
        story.append(Paragraph(app_body, styles["app_body"]))

    # Build PDF
    doc.build(story)
    buffer.seek(0)
    return buffer.read()

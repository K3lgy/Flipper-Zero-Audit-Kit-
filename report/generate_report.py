"""
generate_report.py — Générateur de rapport PDF d'audit physique Flipper Zero
Utilise ReportLab pour produire un rapport professionnel multi-sections.
"""

import os
import json
from datetime import datetime
from pathlib import Path
from collections import Counter

from reportlab.lib                     import colors
from reportlab.lib.pagesizes           import A4
from reportlab.lib.styles              import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units               import mm, cm
from reportlab.lib.enums               import TA_LEFT, TA_CENTER, TA_RIGHT, TA_JUSTIFY
from reportlab.platypus                import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, PageBreak, KeepTogether
)
from reportlab.platypus.flowables      import Flowable
from reportlab.pdfgen                  import canvas as pdfcanvas


# ──────────────────────────────────────────────────────────────────────────────
# Palette couleurs (thème cybersécurité sombre → adapté PDF clair)
# ──────────────────────────────────────────────────────────────────────────────

COLOR_DARK_BG     = colors.HexColor("#1A1A2E")
COLOR_ACCENT_CYAN = colors.HexColor("#00B4D8")
COLOR_ACCENT_BLUE = colors.HexColor("#0077B6")
COLOR_CRITIQUE    = colors.HexColor("#D62828")
COLOR_ELEVE       = colors.HexColor("#F77F00")
COLOR_MOYEN       = colors.HexColor("#F4A261")
COLOR_FAIBLE      = colors.HexColor("#2DC653")
COLOR_LIGHT_BG    = colors.HexColor("#F8F9FA")
COLOR_BORDER      = colors.HexColor("#DEE2E6")
COLOR_TEXT_DARK   = colors.HexColor("#212529")
COLOR_TEXT_MUTED  = colors.HexColor("#6C757D")
COLOR_WHITE       = colors.white
COLOR_ROW_ALT     = colors.HexColor("#F1F3F5")

SEVERITY_COLORS = {
    "CRITIQUE": COLOR_CRITIQUE,
    "ELEVE":    COLOR_ELEVE,
    "MOYEN":    COLOR_MOYEN,
    "FAIBLE":   COLOR_FAIBLE,
}

SEVERITY_ORDER = {"CRITIQUE": 0, "ELEVE": 1, "MOYEN": 2, "FAIBLE": 3}


# ──────────────────────────────────────────────────────────────────────────────
# Numérotation de pages
# ──────────────────────────────────────────────────────────────────────────────

class NumberedCanvas(pdfcanvas.Canvas):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self._draw_page_number(num_pages)
            super().showPage()
        super().save()

    def _draw_page_number(self, page_count):
        page_num = self._saved_page_states.index(dict(self.__dict__)) + 1 \
            if dict(self.__dict__) in self._saved_page_states else 1
        self.setFont("Helvetica", 8)
        self.setFillColor(COLOR_TEXT_MUTED)
        width, _ = A4
        self.drawRightString(width - 20 * mm, 10 * mm,
                             f"Page {self._pageNumber} / {page_count}")
        self.drawString(20 * mm, 10 * mm, "CONFIDENTIEL — Usage interne uniquement")
        # Ligne séparatrice footer
        self.setStrokeColor(COLOR_BORDER)
        self.line(20 * mm, 14 * mm, width - 20 * mm, 14 * mm)


# ──────────────────────────────────────────────────────────────────────────────
# Styles
# ──────────────────────────────────────────────────────────────────────────────

def build_styles() -> dict:
    base = getSampleStyleSheet()

    styles = {
        "title": ParagraphStyle(
            "title",
            parent=base["Title"],
            fontName="Helvetica-Bold",
            fontSize=26,
            textColor=COLOR_WHITE,
            alignment=TA_LEFT,
            spaceAfter=6,
        ),
        "subtitle": ParagraphStyle(
            "subtitle",
            parent=base["Normal"],
            fontName="Helvetica",
            fontSize=13,
            textColor=COLOR_ACCENT_CYAN,
            alignment=TA_LEFT,
            spaceAfter=4,
        ),
        "h1": ParagraphStyle(
            "h1",
            parent=base["Heading1"],
            fontName="Helvetica-Bold",
            fontSize=16,
            textColor=COLOR_DARK_BG,
            spaceBefore=14,
            spaceAfter=6,
            borderPad=4,
        ),
        "h2": ParagraphStyle(
            "h2",
            parent=base["Heading2"],
            fontName="Helvetica-Bold",
            fontSize=12,
            textColor=COLOR_ACCENT_BLUE,
            spaceBefore=10,
            spaceAfter=4,
        ),
        "body": ParagraphStyle(
            "body",
            parent=base["Normal"],
            fontName="Helvetica",
            fontSize=9,
            textColor=COLOR_TEXT_DARK,
            leading=14,
            spaceAfter=4,
            alignment=TA_JUSTIFY,
        ),
        "body_bold": ParagraphStyle(
            "body_bold",
            parent=base["Normal"],
            fontName="Helvetica-Bold",
            fontSize=9,
            textColor=COLOR_TEXT_DARK,
            leading=14,
        ),
        "small": ParagraphStyle(
            "small",
            parent=base["Normal"],
            fontName="Helvetica",
            fontSize=8,
            textColor=COLOR_TEXT_MUTED,
            leading=11,
        ),
        "cell": ParagraphStyle(
            "cell",
            parent=base["Normal"],
            fontName="Helvetica",
            fontSize=8,
            textColor=COLOR_TEXT_DARK,
            leading=11,
        ),
        "cell_bold": ParagraphStyle(
            "cell_bold",
            parent=base["Normal"],
            fontName="Helvetica-Bold",
            fontSize=8,
            textColor=COLOR_TEXT_DARK,
            leading=11,
        ),
        "mono": ParagraphStyle(
            "mono",
            parent=base["Code"],
            fontName="Courier",
            fontSize=7.5,
            textColor=COLOR_DARK_BG,
            backColor=COLOR_LIGHT_BG,
            leading=11,
            leftIndent=6,
            rightIndent=6,
            spaceBefore=2,
            spaceAfter=2,
        ),
        "severity_badge": ParagraphStyle(
            "severity_badge",
            parent=base["Normal"],
            fontName="Helvetica-Bold",
            fontSize=8,
            textColor=COLOR_WHITE,
            alignment=TA_CENTER,
        ),
        "meta": ParagraphStyle(
            "meta",
            parent=base["Normal"],
            fontName="Helvetica",
            fontSize=9,
            textColor=COLOR_WHITE,
            leading=13,
        ),
    }
    return styles


# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────

def severity_color(severity: str) -> colors.Color:
    return SEVERITY_COLORS.get(severity.upper(), COLOR_MOYEN)


def severity_badge_table(severity: str, score: float, styles: dict) -> Table:
    """Génère un badge coloré pour afficher la criticité."""
    color = severity_color(severity)
    score_str = f"{score:.1f}/10"
    data = [[
        Paragraph(f"<b>{severity}</b>", styles["severity_badge"]),
        Paragraph(score_str, styles["severity_badge"]),
    ]]
    t = Table(data, colWidths=[28*mm, 20*mm])
    t.setStyle(TableStyle([
        ("BACKGROUND",  (0, 0), (0, 0), color),
        ("BACKGROUND",  (1, 0), (1, 0), colors.HexColor("#343A40")),
        ("TEXTCOLOR",   (0, 0), (-1, -1), COLOR_WHITE),
        ("ALIGN",       (0, 0), (-1, -1), "CENTER"),
        ("VALIGN",      (0, 0), (-1, -1), "MIDDLE"),
        ("FONTNAME",    (0, 0), (-1, -1), "Helvetica-Bold"),
        ("FONTSIZE",    (0, 0), (-1, -1), 8),
        ("ROWBACKGROUNDS", (0, 0), (-1, -1), [color]),
        ("ROUNDEDCORNERS", [3]),
        ("TOPPADDING",  (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]))
    return t


def hr(color=COLOR_BORDER, thickness=0.5) -> HRFlowable:
    return HRFlowable(width="100%", thickness=thickness,
                      color=color, spaceAfter=4, spaceBefore=4)


# ──────────────────────────────────────────────────────────────────────────────
# Page de couverture
# ──────────────────────────────────────────────────────────────────────────────

def build_cover_page(doc_info: dict, styles: dict) -> list:
    """Construit la page de couverture du rapport."""
    story = []
    width, height = A4

    # Bloc titre sur fond coloré (simulé avec un tableau pleine largeur)
    cover_data = [[
        Paragraph(
            f"<b>RAPPORT D'AUDIT</b><br/><font size='14'>SÉCURITÉ PHYSIQUE</font>",
            styles["title"]
        )
    ]]
    cover_table = Table(cover_data, colWidths=[170*mm])
    cover_table.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), COLOR_DARK_BG),
        ("TOPPADDING",    (0, 0), (-1, -1), 18),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 18),
        ("LEFTPADDING",   (0, 0), (-1, -1), 12),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 12),
        ("ROUNDEDCORNERS", [4]),
    ]))
    story.append(cover_table)
    story.append(Spacer(1, 8*mm))

    # Informations client
    client_data = [
        [Paragraph("<b>CLIENT</b>", styles["body_bold"]),
         Paragraph(doc_info.get("client", "—"), styles["body"])],
        [Paragraph("<b>AUDITEUR</b>", styles["body_bold"]),
         Paragraph(doc_info.get("auditor", "Kapelgy"), styles["body"])],
        [Paragraph("<b>DATE D'AUDIT</b>", styles["body_bold"]),
         Paragraph(doc_info.get("audit_date", datetime.now().strftime("%d/%m/%Y")), styles["body"])],
        [Paragraph("<b>DATE DU RAPPORT</b>", styles["body_bold"]),
         Paragraph(datetime.now().strftime("%d/%m/%Y"), styles["body"])],
        [Paragraph("<b>RÉFÉRENCE</b>", styles["body_bold"]),
         Paragraph(doc_info.get("ref", f"AUDIT-{datetime.now().strftime('%Y%m%d')}"), styles["body"])],
        [Paragraph("<b>VERSION</b>", styles["body_bold"]),
         Paragraph(doc_info.get("version", "1.0"), styles["body"])],
        [Paragraph("<b>CLASSIFICATION</b>", styles["body_bold"]),
         Paragraph("<b>CONFIDENTIEL</b>", styles["body_bold"])],
    ]

    client_table = Table(client_data, colWidths=[50*mm, 120*mm])
    client_table.setStyle(TableStyle([
        ("BACKGROUND",  (0, 0), (-1, -1), COLOR_LIGHT_BG),
        ("ROWBACKGROUNDS", (0, 0), (-1, -1), [COLOR_LIGHT_BG, COLOR_WHITE]),
        ("GRID",        (0, 0), (-1, -1), 0.5, COLOR_BORDER),
        ("TOPPADDING",  (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("VALIGN",      (0, 0), (-1, -1), "MIDDLE"),
    ]))
    story.append(client_table)
    story.append(Spacer(1, 8*mm))

    # Avertissement légal
    disclaimer = (
        "Ce rapport est confidentiel et destiné exclusivement au client mentionné ci-dessus. "
        "Il ne peut être reproduit, distribué ou divulgué à des tiers sans accord écrit préalable. "
        "Les informations contenues dans ce document décrivent des vulnérabilités identifiées dans "
        "le cadre d'une mission d'audit contractuelle et légalement autorisée. "
        "Toute utilisation à d'autres fins est strictement interdite."
    )
    disc_data = [[Paragraph(f"<i>{disclaimer}</i>", styles["small"])]]
    disc_table = Table(disc_data, colWidths=[170*mm])
    disc_table.setStyle(TableStyle([
        ("BACKGROUND",  (0, 0), (-1, -1), colors.HexColor("#FFF3CD")),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING",  (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("BOX",         (0, 0), (-1, -1), 0.5, colors.HexColor("#FFEAA7")),
    ]))
    story.append(disc_table)
    story.append(PageBreak())
    return story


# ──────────────────────────────────────────────────────────────────────────────
# Résumé exécutif
# ──────────────────────────────────────────────────────────────────────────────

def build_executive_summary(all_findings: list, doc_info: dict, styles: dict) -> list:
    """Construit le résumé exécutif avec tableau de bord des criticités."""
    story = []
    story.append(Paragraph("1. RÉSUMÉ EXÉCUTIF", styles["h1"]))
    story.append(hr(COLOR_ACCENT_CYAN, 1.5))

    # Contexte
    context = doc_info.get("context", (
        "Cet audit de sécurité physique a été réalisé avec un Flipper Zero dans le cadre "
        "d'une évaluation de la posture de sécurité. L'objectif est d'identifier les "
        "vecteurs d'attaque physiques exploitables par un attaquant disposant d'un accès "
        "aux locaux (insider, visiteur, prestataire)."
    ))
    story.append(Paragraph(context, styles["body"]))
    story.append(Spacer(1, 4*mm))

    # Comptage par criticité
    counts = Counter(f.get("severity", "MOYEN") for f in all_findings)
    total  = len(all_findings)

    # Tableau de bord criticité
    dashboard_data = [
        [
            Paragraph("CRITIQUE", styles["severity_badge"]),
            Paragraph("ÉLEVÉ",    styles["severity_badge"]),
            Paragraph("MOYEN",    styles["severity_badge"]),
            Paragraph("FAIBLE",   styles["severity_badge"]),
            Paragraph("TOTAL",    styles["severity_badge"]),
        ],
        [
            Paragraph(str(counts.get("CRITIQUE", 0)), ParagraphStyle(
                "big", fontName="Helvetica-Bold", fontSize=22,
                textColor=COLOR_WHITE, alignment=TA_CENTER)),
            Paragraph(str(counts.get("ELEVE", 0)), ParagraphStyle(
                "big2", fontName="Helvetica-Bold", fontSize=22,
                textColor=COLOR_WHITE, alignment=TA_CENTER)),
            Paragraph(str(counts.get("MOYEN", 0)), ParagraphStyle(
                "big3", fontName="Helvetica-Bold", fontSize=22,
                textColor=COLOR_TEXT_DARK, alignment=TA_CENTER)),
            Paragraph(str(counts.get("FAIBLE", 0)), ParagraphStyle(
                "big4", fontName="Helvetica-Bold", fontSize=22,
                textColor=COLOR_WHITE, alignment=TA_CENTER)),
            Paragraph(str(total), ParagraphStyle(
                "big5", fontName="Helvetica-Bold", fontSize=22,
                textColor=COLOR_WHITE, alignment=TA_CENTER)),
        ],
    ]

    dashboard = Table(dashboard_data, colWidths=[32*mm]*5)
    dashboard.setStyle(TableStyle([
        # Entêtes
        ("BACKGROUND",    (0, 0), (0, 0), COLOR_CRITIQUE),
        ("BACKGROUND",    (1, 0), (1, 0), COLOR_ELEVE),
        ("BACKGROUND",    (2, 0), (2, 0), COLOR_MOYEN),
        ("BACKGROUND",    (3, 0), (3, 0), COLOR_FAIBLE),
        ("BACKGROUND",    (4, 0), (4, 0), COLOR_ACCENT_BLUE),
        # Valeurs
        ("BACKGROUND",    (0, 1), (0, 1), colors.HexColor("#FF6B6B")),
        ("BACKGROUND",    (1, 1), (1, 1), colors.HexColor("#FFB347")),
        ("BACKGROUND",    (2, 1), (2, 1), colors.HexColor("#FFD580")),
        ("BACKGROUND",    (3, 1), (3, 1), colors.HexColor("#90EE90")),
        ("BACKGROUND",    (4, 1), (4, 1), colors.HexColor("#87CEEB")),
        ("ALIGN",         (0, 0), (-1, -1), "CENTER"),
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING",    (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("GRID",          (0, 0), (-1, -1), 1, COLOR_WHITE),
    ]))
    story.append(dashboard)
    story.append(Spacer(1, 5*mm))

    # Score global
    if all_findings:
        max_score = max(f.get("score", 0) for f in all_findings)
        avg_score = sum(f.get("score", 0) for f in all_findings) / len(all_findings)
        score_text = (
            f"Score maximal relevé : <b>{max_score:.1f}/10</b> — "
            f"Score moyen : <b>{avg_score:.1f}/10</b>"
        )
        story.append(Paragraph(score_text, styles["body"]))

    # Points clés
    critique_findings = [f for f in all_findings if f.get("severity") == "CRITIQUE"]
    if critique_findings:
        story.append(Spacer(1, 3*mm))
        story.append(Paragraph("<b>Points critiques identifiés :</b>", styles["body_bold"]))
        for i, f in enumerate(critique_findings[:5], 1):
            desc = f.get("vuln_description", "")[:120]
            src  = f.get("source_file", "")
            story.append(Paragraph(
                f"• <b>[{i}]</b> {desc} ({src})", styles["body"]
            ))

    story.append(PageBreak())
    return story


# ──────────────────────────────────────────────────────────────────────────────
# Tableau récapitulatif
# ──────────────────────────────────────────────────────────────────────────────

def build_findings_table(all_findings: list, styles: dict) -> list:
    """Construit le tableau récapitulatif de tous les findings."""
    story = []
    story.append(Paragraph("2. TABLEAU RÉCAPITULATIF", styles["h1"]))
    story.append(hr(COLOR_ACCENT_CYAN, 1.5))

    # Tri par criticité puis score décroissant
    sorted_findings = sorted(
        all_findings,
        key=lambda f: (SEVERITY_ORDER.get(f.get("severity", "MOYEN"), 2), -f.get("score", 0))
    )

    headers = [
        Paragraph("<b>#</b>",          styles["cell_bold"]),
        Paragraph("<b>Criticité</b>",  styles["cell_bold"]),
        Paragraph("<b>Score</b>",      styles["cell_bold"]),
        Paragraph("<b>Type</b>",       styles["cell_bold"]),
        Paragraph("<b>Fichier source</b>", styles["cell_bold"]),
        Paragraph("<b>Description courte</b>", styles["cell_bold"]),
    ]

    table_data = [headers]
    row_styles = []

    for i, f in enumerate(sorted_findings, 1):
        sev   = f.get("severity", "MOYEN")
        score = f.get("score", 0)
        fmt   = f.get("format", "?").upper()
        src   = f.get("source_file", "—")
        desc  = (f.get("vuln_description", "") or "")[:80]
        color = severity_color(sev)

        row = [
            Paragraph(str(i), styles["cell"]),
            Paragraph(f"<b>{sev}</b>", ParagraphStyle(
                f"sev_{i}", fontName="Helvetica-Bold", fontSize=8,
                textColor=color, alignment=TA_CENTER)),
            Paragraph(f"{score:.1f}", ParagraphStyle(
                f"sc_{i}", fontName="Helvetica-Bold", fontSize=8,
                textColor=color, alignment=TA_CENTER)),
            Paragraph(fmt, styles["cell"]),
            Paragraph(src, styles["cell"]),
            Paragraph(desc, styles["cell"]),
        ]
        table_data.append(row)

        if i % 2 == 0:
            row_styles.append(("BACKGROUND", (0, i), (-1, i), COLOR_ROW_ALT))

    col_widths = [10*mm, 22*mm, 16*mm, 18*mm, 40*mm, 64*mm]
    t = Table(table_data, colWidths=col_widths, repeatRows=1)
    t.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, 0), COLOR_DARK_BG),
        ("TEXTCOLOR",     (0, 0), (-1, 0), COLOR_WHITE),
        ("ALIGN",         (0, 0), (-1, -1), "LEFT"),
        ("ALIGN",         (0, 0), (0, -1), "CENTER"),
        ("ALIGN",         (1, 0), (2, -1), "CENTER"),
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
        ("FONTNAME",      (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE",      (0, 0), (-1, -1), 8),
        ("GRID",          (0, 0), (-1, -1), 0.3, COLOR_BORDER),
        ("TOPPADDING",    (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING",   (0, 0), (-1, -1), 5),
        *row_styles,
    ]))

    story.append(t)
    story.append(PageBreak())
    return story


# ──────────────────────────────────────────────────────────────────────────────
# Détail par finding
# ──────────────────────────────────────────────────────────────────────────────

def build_finding_detail(finding: dict, index: int, styles: dict) -> list:
    """Construit la fiche détaillée d'un finding."""
    elements = []
    fmt      = finding.get("format", "?").upper()
    severity = finding.get("severity", "MOYEN")
    score    = finding.get("score", 0)
    src      = finding.get("source_file", "—")
    color    = severity_color(severity)

    # En-tête de finding
    header_data = [[
        Paragraph(f"<b>FINDING-{index:03d}</b>", ParagraphStyle(
            "fid", fontName="Helvetica-Bold", fontSize=10, textColor=COLOR_WHITE)),
        Paragraph(f"[{fmt}]", ParagraphStyle(
            "ftype", fontName="Helvetica", fontSize=9, textColor=COLOR_ACCENT_CYAN)),
        Paragraph(f"<b>{severity}</b>", ParagraphStyle(
            "fsev", fontName="Helvetica-Bold", fontSize=10,
            textColor=COLOR_WHITE, alignment=TA_RIGHT)),
        Paragraph(f"{score:.1f}/10", ParagraphStyle(
            "fsc", fontName="Helvetica-Bold", fontSize=10,
            textColor=colors.HexColor("#FFD700"), alignment=TA_RIGHT)),
    ]]
    header_table = Table(header_data, colWidths=[50*mm, 40*mm, 40*mm, 40*mm])
    header_table.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), COLOR_DARK_BG),
        ("ALIGN",         (0, 0), (1, -1), "LEFT"),
        ("ALIGN",         (2, 0), (-1, -1), "RIGHT"),
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING",    (0, 0), (-1, -1), 7),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
        ("LEFTPADDING",   (0, 0), (0, -1), 10),
        ("RIGHTPADDING",  (-1, 0), (-1, -1), 10),
    ]))
    elements.append(header_table)

    # Bande colorée criticité
    band_data = [[Paragraph(
        f"&nbsp;Source : {src}",
        ParagraphStyle("band", fontName="Helvetica", fontSize=8,
                       textColor=COLOR_WHITE)
    )]]
    band_table = Table(band_data, colWidths=[170*mm])
    band_table.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), color),
        ("TOPPADDING",    (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ("LEFTPADDING",   (0, 0), (-1, -1), 10),
    ]))
    elements.append(band_table)
    elements.append(Spacer(1, 3*mm))

    # Métadonnées techniques (selon le format)
    meta_rows = _extract_meta_rows(finding, fmt, styles)
    if meta_rows:
        meta_table = Table(meta_rows, colWidths=[50*mm, 120*mm])
        meta_table.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, -1), COLOR_LIGHT_BG),
            ("ROWBACKGROUNDS", (0, 0), (-1, -1), [COLOR_LIGHT_BG, COLOR_WHITE]),
            ("GRID",          (0, 0), (-1, -1), 0.3, COLOR_BORDER),
            ("TOPPADDING",    (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ("LEFTPADDING",   (0, 0), (-1, -1), 6),
            ("FONTSIZE",      (0, 0), (-1, -1), 8),
        ]))
        elements.append(meta_table)
        elements.append(Spacer(1, 3*mm))

    # Description de la vulnérabilité
    elements.append(Paragraph("<b>Description de la vulnérabilité :</b>", styles["body_bold"]))
    elements.append(Paragraph(finding.get("vuln_description", "—"), styles["body"]))

    # Vecteurs d'attaque
    attack_vectors = finding.get("attack_vectors", [])
    if attack_vectors:
        elements.append(Spacer(1, 2*mm))
        elements.append(Paragraph("<b>Vecteurs d'attaque :</b>", styles["body_bold"]))
        for av in attack_vectors:
            elements.append(Paragraph(f"• {av}", styles["body"]))

    # Risques additionnels
    add_risks = finding.get("additional_risks", [])
    if add_risks:
        elements.append(Spacer(1, 2*mm))
        elements.append(Paragraph("<b>Risques additionnels :</b>", styles["body_bold"]))
        for risk in add_risks:
            elements.append(Paragraph(f"• {risk}", styles["body"]))

    # Recommandation
    reco = finding.get("recommendation", "")
    if reco:
        elements.append(Spacer(1, 2*mm))
        reco_data = [[
            Paragraph("✓ RECOMMANDATION", ParagraphStyle(
                "reco_hdr", fontName="Helvetica-Bold", fontSize=8,
                textColor=COLOR_WHITE)),
            Paragraph(reco, ParagraphStyle(
                "reco_body", fontName="Helvetica", fontSize=8,
                textColor=COLOR_TEXT_DARK)),
        ]]
        reco_table = Table(reco_data, colWidths=[40*mm, 130*mm])
        reco_table.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (0, -1), COLOR_FAIBLE),
            ("BACKGROUND",    (1, 0), (1, -1), colors.HexColor("#D4EDDA")),
            ("TOPPADDING",    (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("LEFTPADDING",   (0, 0), (-1, -1), 7),
            ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
            ("BOX",           (0, 0), (-1, -1), 0.5, COLOR_FAIBLE),
        ]))
        elements.append(reco_table)

    # Référence CVE/CWE
    cve = finding.get("cve_ref")
    if cve:
        elements.append(Spacer(1, 1*mm))
        elements.append(Paragraph(f"<i>Référence : {cve}</i>", styles["small"]))

    elements.append(Spacer(1, 6*mm))
    elements.append(hr())
    return elements


def _extract_meta_rows(finding: dict, fmt: str, styles: dict) -> list:
    """Extrait les métadonnées techniques selon le format du finding."""
    rows = []
    s = styles["cell"]
    sb = styles["cell_bold"]

    if fmt in ("NFC", "RFID"):
        rows = [
            [Paragraph("Type de badge", sb), Paragraph(finding.get("card_type_normalized", "—"), s)],
            [Paragraph("UID", sb), Paragraph(finding.get("uid", "—"), s)],
            [Paragraph("Format", sb), Paragraph(finding.get("format", "—").upper(), s)],
        ]
        if finding.get("atqa"):
            rows.append([Paragraph("ATQA / SAK", sb),
                         Paragraph(f"ATQA={finding.get('atqa')} SAK={finding.get('sak', '—')}", s)])
        if finding.get("blocks_read", 0) > 0:
            rows.append([Paragraph("Blocs lus", sb),
                         Paragraph(str(finding.get("blocks_read")), s)])
        if finding.get("default_keys_detected"):
            rows.append([Paragraph("⚠ Clés par défaut", sb),
                         Paragraph("OUI — FFFFFFFFFFFF ou 000000000000", s)])

    elif fmt == "SUB":
        rows = [
            [Paragraph("Protocole", sb), Paragraph(finding.get("protocol", "—"), s)],
            [Paragraph("Fréquence", sb),
             Paragraph(f"{finding.get('frequency_mhz', 0)} MHz — {finding.get('frequency_context', '')}", s)],
            [Paragraph("Modulation", sb), Paragraph(finding.get("modulation", "—"), s)],
            [Paragraph("Usage typique", sb), Paragraph(finding.get("protocol_usage", "—"), s)],
            [Paragraph("Rejouable", sb),
             Paragraph("OUI ⚠" if finding.get("is_replay_vulnerable") else "NON ✓", s)],
        ]
        if finding.get("key"):
            rows.append([Paragraph("Clé capturée", sb), Paragraph(finding.get("key", "—"), s)])
        if finding.get("bits"):
            rows.append([Paragraph("Bits", sb), Paragraph(str(finding.get("bits")), s)])

    elif fmt == "BADUSB_LOG":
        rows = [
            [Paragraph("Machine cible", sb), Paragraph(finding.get("target_host", "—"), s)],
            [Paragraph("Utilisateur", sb), Paragraph(finding.get("target_user", "—"), s)],
            [Paragraph("Système d'exploitation", sb), Paragraph(finding.get("target_os", "—"), s)],
            [Paragraph("Statut exécution", sb), Paragraph(finding.get("execution_status", "—"), s)],
            [Paragraph("Antivirus", sb), Paragraph(finding.get("av_status", "—"), s)],
            [Paragraph("Politique USB", sb), Paragraph(finding.get("usb_policy", "—"), s)],
        ]
        if finding.get("notes"):
            rows.append([Paragraph("Notes", sb), Paragraph(finding.get("notes", "—"), s)])

    elif fmt in ("TXT", "CSV", "JSON", "LOG"):  # WiFi
        rows = [
            [Paragraph("SSID", sb), Paragraph(finding.get("ssid") or "<hidden>", s)],
            [Paragraph("BSSID", sb), Paragraph(finding.get("bssid", "—"), s)],
            [Paragraph("Sécurité", sb), Paragraph(finding.get("security", "—"), s)],
            [Paragraph("Canal", sb), Paragraph(str(finding.get("channel", "—")), s)],
            [Paragraph("Signal", sb), Paragraph(finding.get("signal_quality", "—"), s)],
            [Paragraph("Fabricant", sb), Paragraph(finding.get("vendor", "—"), s)],
        ]
        if finding.get("is_evil_twin"):
            rows.insert(0, [Paragraph("⚠ EVIL TWIN", sb),
                            Paragraph("OUI — SSID dupliqué détecté", s)])

    return rows


# ──────────────────────────────────────────────────────────────────────────────
# Recommandations consolidées
# ──────────────────────────────────────────────────────────────────────────────

def build_recommendations(all_findings: list, styles: dict) -> list:
    """Construit la section recommandations consolidées."""
    story = []
    story.append(Paragraph("4. RECOMMANDATIONS PRIORITAIRES", styles["h1"]))
    story.append(hr(COLOR_ACCENT_CYAN, 1.5))

    priorities = [
        ("CRITIQUE", "Actions immédiates (< 48h)", COLOR_CRITIQUE),
        ("ELEVE",    "Court terme (< 1 mois)",     COLOR_ELEVE),
        ("MOYEN",    "Moyen terme (< 3 mois)",      COLOR_MOYEN),
        ("FAIBLE",   "Planification annuelle",      COLOR_FAIBLE),
    ]

    for sev, label, color in priorities:
        sev_findings = [f for f in all_findings if f.get("severity") == sev]
        if not sev_findings:
            continue

        # Déduplication des recommandations
        seen_recos = set()
        unique_recos = []
        for f in sev_findings:
            reco = f.get("recommendation", "")
            if reco and reco not in seen_recos:
                seen_recos.add(reco)
                unique_recos.append(reco)

        story.append(Spacer(1, 3*mm))
        # Titre de section par criticité
        sev_header = [[
            Paragraph(f"<b>{sev}</b>", ParagraphStyle(
                f"sh_{sev}", fontName="Helvetica-Bold", fontSize=10,
                textColor=COLOR_WHITE)),
            Paragraph(label, ParagraphStyle(
                f"sl_{sev}", fontName="Helvetica", fontSize=9,
                textColor=COLOR_WHITE)),
            Paragraph(f"{len(sev_findings)} finding(s)", ParagraphStyle(
                f"sc_{sev}", fontName="Helvetica", fontSize=9,
                textColor=COLOR_WHITE, alignment=TA_RIGHT)),
        ]]
        sh_table = Table(sev_header, colWidths=[35*mm, 100*mm, 35*mm])
        sh_table.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, -1), color),
            ("TOPPADDING",    (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ("LEFTPADDING",   (0, 0), (0, -1), 8),
            ("RIGHTPADDING",  (-1, 0), (-1, -1), 8),
            ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
        ]))
        story.append(sh_table)

        for i, reco in enumerate(unique_recos, 1):
            reco_row = [[
                Paragraph(f"{i}.", styles["cell_bold"]),
                Paragraph(reco, styles["cell"]),
            ]]
            rt = Table(reco_row, colWidths=[8*mm, 162*mm])
            rt.setStyle(TableStyle([
                ("BACKGROUND",    (0, 0), (-1, -1),
                 COLOR_LIGHT_BG if i % 2 == 0 else COLOR_WHITE),
                ("TOPPADDING",    (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ("LEFTPADDING",   (0, 0), (-1, -1), 6),
                ("GRID",          (0, 0), (-1, -1), 0.3, COLOR_BORDER),
                ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
            ]))
            story.append(rt)

    story.append(PageBreak())
    return story


# ──────────────────────────────────────────────────────────────────────────────
# Générateur principal
# ──────────────────────────────────────────────────────────────────────────────

def generate_report(
    rfid_findings:   list,
    subghz_findings: list,
    wifi_findings:   list,
    badusb_findings: list,
    output_path:     str,
    doc_info:        dict,
) -> str:
    """
    Génère le rapport PDF complet.

    Args:
        rfid_findings   : liste de findings RFID/NFC
        subghz_findings : liste de findings Sub-GHz
        wifi_findings   : liste de findings WiFi
        badusb_findings : liste de findings Bad USB
        output_path     : chemin de sortie du PDF
        doc_info        : métadonnées du rapport (client, auditeur, etc.)

    Returns:
        Chemin du PDF généré
    """
    all_findings = rfid_findings + subghz_findings + wifi_findings + badusb_findings
    styles       = build_styles()
    story        = []

    # ─── Page de couverture
    story.extend(build_cover_page(doc_info, styles))

    # ─── Résumé exécutif
    story.extend(build_executive_summary(all_findings, doc_info, styles))

    # ─── Tableau récapitulatif
    if all_findings:
        story.extend(build_findings_table(all_findings, styles))

    # ─── Findings détaillés par catégorie
    story.append(Paragraph("3. FINDINGS DÉTAILLÉS", styles["h1"]))
    story.append(hr(COLOR_ACCENT_CYAN, 1.5))

    sections = [
        ("3.1 Contrôle d'accès RFID / NFC",    rfid_findings),
        ("3.2 Signaux Sub-GHz",                 subghz_findings),
        ("3.3 Réseaux WiFi",                    wifi_findings),
        ("3.4 Périphériques USB (Bad USB)",      badusb_findings),
    ]

    finding_index = 1
    for section_title, findings in sections:
        if not findings:
            continue
        story.append(Spacer(1, 4*mm))
        story.append(Paragraph(section_title, styles["h2"]))
        story.append(hr())

        sorted_f = sorted(
            findings,
            key=lambda f: (SEVERITY_ORDER.get(f.get("severity", "MOYEN"), 2), -f.get("score", 0))
        )
        for finding in sorted_f:
            block = build_finding_detail(finding, finding_index, styles)
            story.append(KeepTogether(block[:4]))
            story.extend(block[4:])
            finding_index += 1

    if finding_index > 1:
        story.append(PageBreak())

    # ─── Recommandations
    if all_findings:
        story.extend(build_recommendations(all_findings, styles))

    # ─── Génération PDF
    os.makedirs(os.path.dirname(output_path) if os.path.dirname(output_path) else ".", exist_ok=True)

    doc = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        leftMargin=20*mm,
        rightMargin=20*mm,
        topMargin=20*mm,
        bottomMargin=20*mm,
        title=f"Rapport d'audit physique — {doc_info.get('client', '')}",
        author=doc_info.get("auditor", "Kapelgy"),
        subject="Audit de sécurité physique Flipper Zero",
    )

    doc.build(story, canvasmaker=NumberedCanvas)
    print(f"\n[✓] Rapport généré : {output_path}")
    return output_path

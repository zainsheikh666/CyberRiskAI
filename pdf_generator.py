from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
import io
import datetime

def generate_pdf_report(company_name, industry, employees, domain, score, risk_level, risk_message, recommendations, breakdown, answers, ssl_result, dns_result, breach_result, attack_simulation):

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4,
        rightMargin=50, leftMargin=50, topMargin=50, bottomMargin=50)

    NAVY = colors.HexColor('#1e3a5f')
    BLUE = colors.HexColor('#1d4ed8')
    RED = colors.HexColor('#dc2626')
    AMBER = colors.HexColor('#d97706')
    GREEN = colors.HexColor('#16a34a')
    TEXT = colors.HexColor('#111827')
    GREY = colors.HexColor('#4b5563')
    WHITE = colors.white
    CARD = colors.HexColor('#f1f5f9')
    BG_RED = colors.HexColor('#fef2f2')
    BG_AMBER = colors.HexColor('#fffbeb')
    BG_GREEN = colors.HexColor('#f0fdf4')

    if score >= 60:
        score_color = RED
        risk_label = 'HIGH RISK'
        score_bg = BG_RED
    elif score >= 30:
        score_color = AMBER
        risk_label = 'MEDIUM RISK'
        score_bg = BG_AMBER
    else:
        score_color = GREEN
        risk_label = 'LOW RISK'
        score_bg = BG_GREEN

    story = []

    # HEADER
    header_data = [[
        Paragraph('CYBERRISK AI<br/><font size="8" color="#93c5fd">Cyber Threat Intelligence Platform</font>',
            ParagraphStyle('brand', fontSize=20, textColor=WHITE,
            fontName='Helvetica-Bold', leading=28)),
        Paragraph('CONFIDENTIAL REPORT<br/><font size="9" color="#ffffff">' +
            datetime.datetime.now().strftime("%d %B %Y at %H:%M") + '</font>',
            ParagraphStyle('conf', fontSize=7, textColor=colors.HexColor('#93c5fd'),
            fontName='Helvetica-Bold', alignment=TA_RIGHT, leading=16))
    ]]
    header_t = Table(header_data, colWidths=[3.5*inch, 3.5*inch])
    header_t.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), NAVY),
        ('PADDING', (0,0), (-1,-1), 18),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('LINEBELOW', (0,0), (-1,-1), 3, BLUE),
    ]))
    story.append(header_t)
    story.append(Spacer(1, 16))

    # TITLE
    story.append(Paragraph('CYBER RISK ASSESSMENT REPORT',
        ParagraphStyle('title', fontSize=16, textColor=NAVY,
        fontName='Helvetica-Bold', spaceAfter=4)))
    story.append(Paragraph(
        f'{company_name}   |   {industry}   |   {employees} employees   |   {domain}',
        ParagraphStyle('sub', fontSize=10, textColor=GREY,
        fontName='Helvetica', spaceAfter=8)))
    story.append(HRFlowable(width="100%", thickness=1.5, color=BLUE, spaceAfter=16))

    # RISK SCORE
    score_row = [[
        Paragraph(f'{score}<br/><font size="7" color="#4b5563">OUT OF 100</font>',
            ParagraphStyle('sc', fontSize=48, textColor=score_color,
            fontName='Helvetica-Bold', alignment=TA_CENTER, leading=54)),
        Paragraph(f'{risk_label}<br/><font size="10" color="#4b5563">{risk_message}</font>',
            ParagraphStyle('rl', fontSize=20, textColor=score_color,
            fontName='Helvetica-Bold', leading=28))
    ]]
    score_t = Table(score_row, colWidths=[1.8*inch, 5.2*inch])
    score_t.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), score_bg),
        ('PADDING', (0,0), (-1,-1), 18),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('LINEBEFORE', (0,0), (0,-1), 5, score_color),
        ('BOX', (0,0), (-1,-1), 1, score_color),
    ]))
    story.append(score_t)
    story.append(Spacer(1, 20))

    # LIVE SCAN RESULTS
    story.append(Paragraph('LIVE SCAN RESULTS',
        ParagraphStyle('sh', fontSize=9, textColor=BLUE, fontName='Helvetica-Bold',
        letterSpacing=1.5, spaceAfter=8)))

    scan_rows = [
        [Paragraph('CHECK', ParagraphStyle('th', fontSize=8, textColor=WHITE, fontName='Helvetica-Bold')),
         Paragraph('STATUS', ParagraphStyle('th', fontSize=8, textColor=WHITE, fontName='Helvetica-Bold')),
         Paragraph('DETAILS', ParagraphStyle('th', fontSize=8, textColor=WHITE, fontName='Helvetica-Bold'))],
        [Paragraph('SSL Certificate', ParagraphStyle('td', fontSize=9, textColor=TEXT, fontName='Helvetica')),
         Paragraph('VALID' if ssl_result.get('status') == 'valid' else 'INVALID',
            ParagraphStyle('tds', fontSize=9, fontName='Helvetica-Bold',
            textColor=GREEN if ssl_result.get('status') == 'valid' else RED)),
         Paragraph(f"Expires {ssl_result.get('expires','N/A')}" if ssl_result.get('status') == 'valid' else 'Certificate missing — data NOT encrypted',
            ParagraphStyle('td', fontSize=9, textColor=GREY, fontName='Helvetica'))],
        [Paragraph('SPF Record', ParagraphStyle('td', fontSize=9, textColor=TEXT, fontName='Helvetica')),
         Paragraph('FOUND' if dns_result.get('spf') == 'found' else 'MISSING',
            ParagraphStyle('tds', fontSize=9, fontName='Helvetica-Bold',
            textColor=GREEN if dns_result.get('spf') == 'found' else RED)),
         Paragraph('Email spoofing protected' if dns_result.get('spf') == 'found' else 'Attackers can spoof your email domain',
            ParagraphStyle('td', fontSize=9, textColor=GREY, fontName='Helvetica'))],
        [Paragraph('DMARC Record', ParagraphStyle('td', fontSize=9, textColor=TEXT, fontName='Helvetica')),
         Paragraph('FOUND' if dns_result.get('dmarc') == 'found' else 'MISSING',
            ParagraphStyle('tds', fontSize=9, fontName='Helvetica-Bold',
            textColor=GREEN if dns_result.get('dmarc') == 'found' else RED)),
         Paragraph('Email authentication active' if dns_result.get('dmarc') == 'found' else 'Email domain not protected',
            ParagraphStyle('td', fontSize=9, textColor=GREY, fontName='Helvetica'))],
        [Paragraph('Dark Web Monitor', ParagraphStyle('td', fontSize=9, textColor=TEXT, fontName='Helvetica')),
         Paragraph('BREACHED' if breach_result.get('breached') else 'CLEAN',
            ParagraphStyle('tds', fontSize=9, fontName='Helvetica-Bold',
            textColor=RED if breach_result.get('breached') else GREEN)),
         Paragraph(f"{breach_result.get('count',0)} breach(es) found" if breach_result.get('breached') else 'No credential leaks on dark web',
            ParagraphStyle('td', fontSize=9, textColor=GREY, fontName='Helvetica'))],
    ]
    scan_t = Table(scan_rows, colWidths=[1.8*inch, 1.1*inch, 4.1*inch])
    scan_t.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), NAVY),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [WHITE, CARD]),
        ('PADDING', (0,0), (-1,-1), 10),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#cbd5e1')),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
    ]))
    story.append(scan_t)
    story.append(Spacer(1, 20))

    # AI ATTACK SIMULATION
    story.append(Paragraph('AI ATTACK SIMULATION',
        ParagraphStyle('sh', fontSize=9, textColor=RED, fontName='Helvetica-Bold',
        letterSpacing=1.5, spaceAfter=4)))
    story.append(Paragraph(
        f'Based on vulnerabilities detected, this is exactly how an attacker would compromise {company_name} —',
        ParagraphStyle('si', fontSize=9, textColor=GREY, fontName='Helvetica',
        spaceAfter=8, leading=14)))

    for i, step in enumerate(attack_simulation, 1):
        st = Table([[
            Paragraph(str(i), ParagraphStyle('sn', fontSize=13, textColor=WHITE,
                fontName='Helvetica-Bold', alignment=TA_CENTER)),
            Paragraph(step, ParagraphStyle('st', fontSize=9, textColor=TEXT,
                fontName='Helvetica', leading=14))
        ]], colWidths=[0.4*inch, 6.6*inch])
        st.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (0,-1), RED),
            ('BACKGROUND', (1,0), (1,-1), BG_RED),
            ('PADDING', (0,0), (-1,-1), 10),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ('BOX', (0,0), (-1,-1), 0.5, RED),
        ]))
        story.append(st)
        story.append(Spacer(1, 4))
    story.append(Spacer(1, 16))

    # RISK BREAKDOWN
    story.append(Paragraph('RISK SCORE BREAKDOWN',
        ParagraphStyle('sh', fontSize=9, textColor=BLUE, fontName='Helvetica-Bold',
        letterSpacing=1.5, spaceAfter=8)))
    if breakdown:
        bd = [[
            Paragraph('CATEGORY', ParagraphStyle('th', fontSize=8, textColor=WHITE, fontName='Helvetica-Bold')),
            Paragraph('ISSUE', ParagraphStyle('th', fontSize=8, textColor=WHITE, fontName='Helvetica-Bold')),
            Paragraph('SEVERITY', ParagraphStyle('th', fontSize=8, textColor=WHITE, fontName='Helvetica-Bold')),
            Paragraph('POINTS', ParagraphStyle('th', fontSize=8, textColor=WHITE, fontName='Helvetica-Bold', alignment=TA_RIGHT)),
        ]]
        for item in breakdown:
            sc = RED if item['severity'] == 'high' else AMBER
            bd.append([
                Paragraph(item['category'], ParagraphStyle('td', fontSize=9, textColor=TEXT, fontName='Helvetica')),
                Paragraph(item['issue'], ParagraphStyle('td', fontSize=9, textColor=GREY, fontName='Helvetica')),
                Paragraph(item['severity'].upper(), ParagraphStyle('tds', fontSize=9, textColor=sc, fontName='Helvetica-Bold')),
                Paragraph(f"+{item['points']} pts", ParagraphStyle('tdp', fontSize=9, textColor=sc, fontName='Helvetica-Bold', alignment=TA_RIGHT)),
            ])
        bdt = Table(bd, colWidths=[1.7*inch, 2.4*inch, 1.2*inch, 1.7*inch])
        bdt.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), NAVY),
            ('ROWBACKGROUNDS', (0,1), (-1,-1), [WHITE, CARD]),
            ('PADDING', (0,0), (-1,-1), 10),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#cbd5e1')),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ]))
        story.append(bdt)
    story.append(Spacer(1, 20))

    # RECOMMENDATIONS
    story.append(Paragraph('AI RECOMMENDATIONS',
        ParagraphStyle('sh', fontSize=9, textColor=BLUE, fontName='Helvetica-Bold',
        letterSpacing=1.5, spaceAfter=8)))
    for rec in recommendations:
        if rec['type'] == 'danger':
            bg, border, sev = BG_RED, RED, 'CRITICAL'
        elif rec['type'] == 'warning':
            bg, border, sev = BG_AMBER, AMBER, 'WARNING'
        else:
            bg, border, sev = BG_GREEN, GREEN, 'PASSED'
        rt = Table([[
            Paragraph(sev, ParagraphStyle('rs', fontSize=7, textColor=WHITE,
                fontName='Helvetica-Bold', alignment=TA_CENTER, letterSpacing=0.5)),
            Paragraph(
                rec['category'].upper() + '<br/><font size="9" color="#111827">' + rec['text'] + '</font>',
                ParagraphStyle('rt', fontSize=7, textColor=GREY,
                fontName='Helvetica-Bold', leading=16))
        ]], colWidths=[0.7*inch, 6.3*inch])
        rt.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (0,-1), border),
            ('BACKGROUND', (1,0), (1,-1), bg),
            ('PADDING', (0,0), (-1,-1), 10),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ('BOX', (0,0), (-1,-1), 0.5, border),
        ]))
        story.append(rt)
        story.append(Spacer(1, 4))
    story.append(Spacer(1, 20))

    # DIGITAL DOOR LOCK
    story.append(Paragraph('DIGITAL DOOR LOCK SCORE',
        ParagraphStyle('sh', fontSize=9, textColor=BLUE, fontName='Helvetica-Bold',
        letterSpacing=1.5, spaceAfter=4)))
    story.append(Paragraph(
        'Every night business owners lock their physical doors — but are they locking their digital ones?',
        ParagraphStyle('di', fontSize=9, textColor=GREY, fontName='Helvetica',
        spaceAfter=8, leading=14)))

    door_items = [
        ('Front door', 'MFA — Main account access', answers.get('mfa') == 'yes'),
        ('Alarm system', 'Antivirus — Threat detection', answers.get('antivirus') == 'yes'),
        ('Safe & vault', 'Backups — Data protection', answers.get('backups') == 'yes'),
        ('Letterbox lock', 'SPF/DMARC — Email security', dns_result.get('spf') == 'found'),
        ('Windows & doors', 'Encryption — Data security', answers.get('encryption') == 'yes'),
        ('Security training', 'Staff awareness — Human risk', answers.get('training') == 'yes'),
    ]
    dr = [[
        Paragraph('PHYSICAL', ParagraphStyle('th', fontSize=8, textColor=WHITE, fontName='Helvetica-Bold')),
        Paragraph('CYBER EQUIVALENT', ParagraphStyle('th', fontSize=8, textColor=WHITE, fontName='Helvetica-Bold')),
        Paragraph('STATUS', ParagraphStyle('th', fontSize=8, textColor=WHITE, fontName='Helvetica-Bold')),
    ]]
    for physical, cyber, locked in door_items:
        dr.append([
            Paragraph(physical, ParagraphStyle('td', fontSize=9, textColor=TEXT, fontName='Helvetica')),
            Paragraph(cyber, ParagraphStyle('td', fontSize=9, textColor=GREY, fontName='Helvetica')),
            Paragraph('LOCKED', ParagraphStyle('tdl', fontSize=9, textColor=GREEN, fontName='Helvetica-Bold')) if locked else
            Paragraph('UNLOCKED', ParagraphStyle('tdu', fontSize=9, textColor=RED, fontName='Helvetica-Bold')),
        ])
    dt = Table(dr, colWidths=[1.6*inch, 3.8*inch, 1.6*inch])
    dt.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), NAVY),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [WHITE, CARD]),
        ('PADDING', (0,0), (-1,-1), 10),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#cbd5e1')),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
    ]))
    story.append(dt)
    story.append(Spacer(1, 30))

    # FOOTER
    story.append(HRFlowable(width="100%", thickness=1.5, color=NAVY, spaceBefore=4, spaceAfter=8))
    ft = Table([[
        Paragraph('CyberRisk AI — Protecting SMEs from Cyber Threats',
            ParagraphStyle('fl', fontSize=8, textColor=GREY, fontName='Helvetica')),
        Paragraph(f'cyberrisk.ai   |   Confidential   |   {datetime.datetime.now().strftime("%Y")}',
            ParagraphStyle('fr', fontSize=8, textColor=GREY, fontName='Helvetica', alignment=TA_RIGHT))
    ]], colWidths=[3.5*inch, 3.5*inch])
    ft.setStyle(TableStyle([('PADDING', (0,0), (-1,-1), 0)]))
    story.append(ft)

    doc.build(story)
    buffer.seek(0)
    return buffer
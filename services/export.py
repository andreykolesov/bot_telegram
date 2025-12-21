import os
import time
import pandas as pd
import tempfile
from sqlalchemy.orm import joinedload
from reportlab.lib.pagesizes import A4, landscape
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors
from database.models import AuditLog, User, DataExport, SupportTicket


def register_font():
    try:
        font_path = "C:\\Windows\\Fonts\\arial.ttf"
        if not os.path.exists(font_path):
            font_path = "arial.ttf"

        if os.path.exists(font_path):
            pdfmetrics.registerFont(TTFont('Arial', font_path))
            return 'Arial'
        else:
            return 'Helvetica'
    except:
        return 'Helvetica'


def export_audit_log(session, request_user_id, fmt):
    audit_query = session.query(
        AuditLog.timestamp,
        User.login,
        AuditLog.action_type,
        AuditLog.details
    ).join(User, AuditLog.user_id == User.id).all()

    tickets_query = session.query(SupportTicket).options(
        joinedload(SupportTicket.user),
        joinedload(SupportTicket.admin)
    ).all()

    records = []

    for row in audit_query:
        if row.timestamp:
            records.append({
                "raw_time": row.timestamp,
                "Time": row.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                "User": row.login or "Unknown",
                "Action": row.action_type,
                "Details": row.details
            })

    for t in tickets_query:
        if t.created_at:
            user_login = t.user.login if t.user else "Unknown"

            records.append({
                "raw_time": t.created_at,
                "Time": t.created_at.strftime("%Y-%m-%d %H:%M:%S"),
                "User": user_login,
                "Action": "SUPPORT_ASK",
                "Details": f"[OPEN] {t.question}"
            })

        if t.answer and t.answered_at:
            admin_login = t.admin.login if t.admin else "Admin"

            records.append({
                "raw_time": t.answered_at,
                "Time": t.answered_at.strftime("%Y-%m-%d %H:%M:%S"),
                "User": admin_login,
                "Action": "SUPPORT_REPLY",
                "Details": f"[CLOSED] Re to #{t.id}: {t.answer}"
            })

    if not records:
        return None

    records.sort(key=lambda x: x['raw_time'].timestamp() if x['raw_time'] else 0, reverse=False)

    for r in records:
        del r['raw_time']

    df = pd.DataFrame(records)
    filename = f"full_report_{int(time.time())}.{fmt}"
    path = os.path.join(tempfile.gettempdir(), filename)

    try:
        if fmt == 'csv':
            df.to_csv(path, index=False, sep=';', encoding='utf-8-sig')

        elif fmt == 'pdf':
            font_name = register_font()
            doc = SimpleDocTemplate(path, pagesize=landscape(A4))
            elements = []

            styles = getSampleStyleSheet()
            header_style = styles['Heading1']
            header_style.fontName = font_name
            elements.append(Paragraph("Audit", header_style))

            headers = ["Time", "User", "Action", "Details"]
            table_data = [headers]

            for row in df.values.tolist():
                cleaned_row = []
                for item in row:
                    str_item = str(item)
                    if len(str_item) > 80:
                        str_item = str_item[:77] + "..."
                    cleaned_row.append(str_item)
                table_data.append(cleaned_row)

            table = Table(table_data, colWidths=[110, 80, 100, 450])

            style = TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, -1), font_name),
                ('FONTSIZE', (0, 0), (-1, 0), 10),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ])
            table.setStyle(style)
            elements.append(table)

            doc.build(elements)

        else:
            return None

        admin_user = session.query(User).filter_by(telegram_id=request_user_id).first()
        if admin_user:
            export_record = DataExport(
                user_id=admin_user.id,
                export_format=fmt,
                status="success",
                file_path=path
            )
            session.add(export_record)
            session.commit()

        return path

    except Exception as e:
        return None
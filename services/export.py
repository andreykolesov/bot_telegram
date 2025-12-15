import os, time, pandas as pd, tempfile
from database.models import AuditLog, User, DataExport


def export_audit_log(session, tg_id, fmt):
    user = session.query(User).filter_by(telegram_id=tg_id).first()

    if not user:
        return None

    df = pd.read_sql(session.query(AuditLog.id, AuditLog.action_type, AuditLog.details, AuditLog.timestamp).filter_by(user_id=user.id).statement, session.bind)
    path = os.path.join(tempfile.gettempdir(), f"export_{int(time.time())}.{fmt}")

    if fmt == 'csv':
        df.to_csv(path, index=False)
    else:
        return None

    session.add(DataExport(user_id=user.id, export_format=fmt, status="success", file_path=path))
    session.commit()

    return path
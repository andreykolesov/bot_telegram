from sqlalchemy import desc
from database.db import get_session
from database.models import User, Scan


def get_user_statistics(session, user_id):
    user = session.query(User).filter_by(id=user_id).first()
    if not user:
        return None

    total = session.query(Scan).filter_by(user_id=user_id).count()
    clean = session.query(Scan).filter_by(user_id=user_id, overall_verdict='clean').count()
    infected = session.query(Scan).filter_by(user_id=user_id, overall_verdict='infected').count()
    suspicious = session.query(Scan).filter_by(user_id=user_id, overall_verdict='suspicious').count()

    last_scan = session.query(Scan).filter_by(user_id=user_id).order_by(desc(Scan.started_at)).first()
    last_active = last_scan.started_at if last_scan else None

    return {
        'reg_date': user.reg_date,
        'last_active': last_active,
        'total': total,
        'clean': clean,
        'infected': infected,
        'suspicious': suspicious
    }
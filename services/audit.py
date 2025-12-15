from database.models import AuditLog, User


def log_audit(session, user_tg_id, action, details):
    user = session.query(User).filter_by(telegram_id=user_tg_id).first()
    if user:
        session.add(AuditLog(user_id=user.id, action_type=action, details=details))
        session.commit()
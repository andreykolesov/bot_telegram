from database.models import User, UserRole, Scan, AuditLog, DataExport
from config import CREATOR_ID


def set_user_block_status(session, login, block, requester_id):
    target = session.query(User).filter_by(login=login).first()
    if not target: return False, "Пользователь не найден."
    if target.telegram_id == requester_id: return False, "Нельзя применить к себе."

    if requester_id != CREATOR_ID:
        if target.telegram_id == CREATOR_ID: return False, "Нельзя блокировать Создателя."
        if target.role.name == 'admin': return False, "Админ не может блокировать админа."

    target.is_blocked = block
    session.commit()
    status = "заблокирован" if block else "разблокирован"
    return True, f"Пользователь {login} {status}."


def delete_user_by_login(session, login, requester_id):
    target = session.query(User).filter_by(login=login).first()
    if not target: return False, "Пользователь не найден."
    if target.telegram_id == requester_id: return False, "Нельзя удалить себя."

    if requester_id != CREATOR_ID:
        if target.telegram_id == CREATOR_ID: return False, "Нельзя удалить Создателя."
        if target.role.name == 'admin': return False, "Админ не может удалить админа."

    try:
        session.query(Scan).filter_by(user_id=target.id).delete()
        session.query(AuditLog).filter_by(user_id=target.id).delete()
        session.query(DataExport).filter_by(user_id=target.id).delete()
        session.delete(target)
        session.commit()
        return True, f"Пользователь {login} удален."
    except Exception as e:
        session.rollback()
        return False, f"Ошибка: {e}"


def toggle_admin_role(session, login, requester_id):
    if requester_id != CREATOR_ID: return False, "Только Создатель может менять роли."

    target = session.query(User).filter_by(login=login).first()
    if not target: return False, "Пользователь не найден."
    if target.telegram_id == CREATOR_ID: return False, "Нельзя менять роль Создателя."

    admin_role = session.query(UserRole).filter_by(name='admin').first()
    user_role = session.query(UserRole).filter_by(name='user').first()

    if target.role_id == admin_role.id:
        target.role_id = user_role.id
        action = "разжалован"
    else:
        target.role_id = admin_role.id
        action = "повышен до Админа"

    session.commit()
    return True, f"Пользователь {login} {action}."
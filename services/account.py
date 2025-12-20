import hashlib
from sqlalchemy.orm import joinedload
from database.models import User, UserRole
from config import CREATOR_ID, PASSWORD_SALT


def hash_password(password: str) -> str:
    return hashlib.sha256((PASSWORD_SALT + password).encode()).hexdigest()


def register_user(session, tg_user, login, password):
    existing = session.query(User).filter_by(login=login).first()
    if existing and existing.telegram_id != tg_user.id:
        return False, "Этот логин уже занят другим пользователем."

    hashed_pass = hash_password(password)

    role_name = 'admin' if tg_user.id == CREATOR_ID else 'user'
    role = session.query(UserRole).filter_by(name=role_name).first()
    if not role:
        role = UserRole(name='user', description='Standard')
        session.add(role)
        session.commit()

    user = session.query(User).filter_by(telegram_id=tg_user.id).first()

    if user:
        if user.is_blocked: return False, "Ваш аккаунт заблокирован."
        user.login = login
        user.password_hash = hashed_pass
        user.role_id = role.id
        msg = "Данные обновлены"
    else:
        user = User(telegram_id=tg_user.id, login=login, password_hash=hashed_pass, role_id=role.id)
        session.add(user)
        msg = "Регистрация успешна"

    session.commit()
    return True, f"{msg}! Теперь войдите."


def authenticate_user(session, login, password, tg_id):
    hashed_pass = hash_password(password)
    user = session.query(User).options(joinedload(User.role)).filter_by(login=login).first()

    if not user: return None, "Неверный логин."
    if user.is_blocked: return None, "Ваш аккаунт заблокирован."
    if user.password_hash != hashed_pass: return None, "Неверный пароль."
    if user.telegram_id != tg_id: return None, "Этот логин привязан к другому Telegram аккаунту."

    if tg_id == CREATOR_ID and user.role.name != 'admin':
        ar = session.query(UserRole).filter_by(name='admin').first()
        if ar:
            user.role_id = ar.id
            session.commit()
            session.refresh(user)

    return user, "Вход выполнен."
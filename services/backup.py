import os
import datetime
import subprocess
from urllib.parse import urlparse
from database.models import Backup, User, AuditLog
from config import BACKUP_DIR, DB_URL, PG_DUMP_PATH


def create_local_dump():
    if not os.path.exists(BACKUP_DIR):
        os.makedirs(BACKUP_DIR)

    filename = f"backup_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.sql"
    filepath = os.path.join(BACKUP_DIR, filename)

    try:
        db_info = urlparse(DB_URL)
        username = db_info.username
        password = db_info.password
        hostname = db_info.hostname
        port = db_info.port
        dbname = db_info.path[1:]

        env = os.environ.copy()
        if password:
            env["PGPASSWORD"] = password

        command = [
            PG_DUMP_PATH,
            "-h", str(hostname),
            "-p", str(port),
            "-U", username,
            "-f", filepath,
            dbname
        ]

        subprocess.run(command, env=env, check=True)

        if not os.path.exists(filepath):
            return None, "File not created"

        return filepath, None

    except Exception as e:
        return None, str(e)


def perform_backup(session, initiator_tg_id):
    path, error = create_local_dump()

    user = session.query(User).filter_by(telegram_id=initiator_tg_id).first()
    uid = user.id if user else None

    if not path:
        if user:
            session.add(AuditLog(
                user_id=user.id,
                action_type="BACKUP",
                details=f"Failed [LOCAL]: {error}",
                ip_address="Telegram"
            ))
            session.commit()
        return f"❌ Backup Failed: {error}"

    filename = os.path.basename(path)
    file_size = os.path.getsize(path)
    size_mb = round(file_size / (1024 * 1024), 2)

    session.add(Backup(
        status="success",
        remote_url="Local Only",
        backup_size_bytes=file_size,
        initiator_id=uid
    ))

    if user:
        session.add(AuditLog(
            user_id=user.id,
            action_type="BACKUP",
            details=f"Success [LOCAL] {filename} ({size_mb} MB)",
            ip_address="Telegram"
        ))

    session.commit()

    return f"✅ Бэкап создан: {filename} ({size_mb} MB)"
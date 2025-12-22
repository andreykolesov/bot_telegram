import os
import datetime
import subprocess
from urllib.parse import urlparse
import yadisk
from database.models import Backup, User, AuditLog
from config import BACKUP_DIR, DB_URL, PG_DUMP_PATH, YANDEX_DISK_TOKEN


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


def upload_to_yandex(filepath, filename):
    if not YANDEX_DISK_TOKEN:
        return False, "Token missing"

    try:
        y = yadisk.YaDisk(token=YANDEX_DISK_TOKEN)
        if not y.check_token():
            return False, "Invalid Token"

        if not y.exists("/Backups"):
            y.mkdir("/Backups")

        y.upload(filepath, f"/Backups/{filename}")
        return True, "OK"
    except Exception as e:
        return False, str(e)


def perform_backup(session, initiator_tg_id, target="local"):
    path, error = create_local_dump()

    user = session.query(User).filter_by(telegram_id=initiator_tg_id).first()
    uid = user.id if user else None

    if not path:
        if user:
            session.add(AuditLog(
                user_id=user.id,
                action_type="BACKUP",
                details=f"Failed: {error}",
                ip_address="Telegram"
            ))
            session.commit()
        return f"❌ Backup Failed: {error}"

    filename = os.path.basename(path)
    file_size = os.path.getsize(path)
    size_mb = round(file_size / (1024 * 1024), 2)

    ya_ok = False
    log_tag = "[LOCAL]"
    db_remote_info = "Local Only"
    final_status_msg = f"✅ Бэкап создан локально: {filename}"

    if target == "yandex":
        ya_ok, ya_msg = upload_to_yandex(path, filename)
        if ya_ok:
            log_tag = "[YANDEX]"
            db_remote_info = "Yandex: OK"
            final_status_msg += f"\n☁️ Яндекс.Диск: ✅ Загружено"
        else:
            log_tag = f"[LOCAL] (Yandex Fail: {ya_msg})"
            db_remote_info = f"Yandex Error: {ya_msg}"
            final_status_msg += f"\n☁️ Яндекс.Диск: ❌ Ошибка ({ya_msg})"

    db_status = "success" if (target == "local" or ya_ok) else "partial_fail"

    session.add(Backup(
        status=db_status,
        remote_url=db_remote_info,
        backup_size_bytes=file_size,
        initiator_id=uid
    ))

    if user:
        session.add(AuditLog(
            user_id=user.id,
            action_type="BACKUP",
            details=f"Success {log_tag} {filename} ({size_mb} MB)",
            ip_address="Telegram"
        ))

    session.commit()

    return final_status_msg
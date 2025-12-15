import os, datetime
from database.models import Backup
from config import BACKUP_DIR

def perform_backup(session):
    if not os.path.exists(BACKUP_DIR):
        os.makedirs(BACKUP_DIR)

    path = os.path.join(BACKUP_DIR, f"backup_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.sql")
    with open(path, 'w') as f: f.write("-- DB Backup Placeholder")
    session.add(Backup(status="success", remote_url=f"local://{path}", backup_size_bytes=100))
    session.commit()
    
    return f"Бэкап: {path}"
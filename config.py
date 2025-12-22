import os
from dotenv import load_dotenv

load_dotenv()

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

TELEGRAM_TOKEN = os.getenv("TELEGRAM_TOKEN")
creator_id_str = os.getenv("CREATOR_ID")
CREATOR_ID = int(creator_id_str) if creator_id_str else 0

VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
VIRUSTOTAL_URL = "https://www.virustotal.com/api/v3/files"

DB_URL = os.getenv("DB_URL")

BACKUP_DIR = os.path.join(BASE_DIR, "backups")
TEMP_DIR = os.path.join(BASE_DIR, "temp")

YARA_GENERIC_PATH = os.path.join(BASE_DIR, "rules", "generic.yar")
YARA_PE_PATH = os.path.join(BASE_DIR, "rules", "pe.yar")

PG_DUMP_PATH = os.getenv("PG_DUMP_PATH", "pg_dump")

YANDEX_DISK_TOKEN = os.getenv("YANDEX_DISK_TOKEN")

ARCHIVE_EXTENSIONS = {'.zip', '.rar', '.7z', '.tar', '.gz', '.bz2', '.iso', '.arj', '.cab'}

if not TELEGRAM_TOKEN or not DB_URL:
    raise ValueError("Ошибка: Проверьте файл .env")

PASSWORD_SALT = os.getenv("PASSWORD_SALT")
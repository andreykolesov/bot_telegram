import time
import requests
import os
import yara
import pefile
from config import YARA_RULES_PATH, VIRUSTOTAL_API_KEY, VIRUSTOTAL_URL


def check_virustotal(path, file_hash):
    if not VIRUSTOTAL_API_KEY or "YOUR" in VIRUSTOTAL_API_KEY:
        return "skipped", "API Key не настроен", ""

    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    gui_link = f"https://www.virustotal.com/gui/file/{file_hash}"

    try:
        response = requests.get(f"{VIRUSTOTAL_URL}/{file_hash}", headers=headers)

        if response.status_code == 200:
            return _parse_vt_response(response.json(), gui_link)

        elif response.status_code == 404:
            return _upload_large_file(path, headers, gui_link)

        else:
            return "error", f"HTTP Error {response.status_code}", gui_link

    except Exception as e:
        return "error", str(e), gui_link


def _upload_large_file(path, headers, gui_link):
    try:
        url_resp = requests.get("https://www.virustotal.com/api/v3/files/upload_url", headers=headers)
        if url_resp.status_code != 200:
            return "error", "Не удалось получить URL загрузки", gui_link

        upload_url = url_resp.json().get("data")

        with open(path, "rb") as f:
            files = {"file": (os.path.basename(path), f)}
            upload_resp = requests.post(upload_url, headers=headers, files=files)

        if upload_resp.status_code != 200:
            return "error", f"Ошибка загрузки: {upload_resp.status_code}", gui_link

        analysis_id = upload_resp.json().get("data", {}).get("id")

        return _poll_analysis(analysis_id, headers, gui_link)

    except Exception as e:
        return "error", f"Upload exception: {e}", gui_link


def _poll_analysis(analysis_id, headers, gui_link):
    analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"

    for _ in range(20):
        time.sleep(15)
        try:
            resp = requests.get(analysis_url, headers=headers)
            if resp.status_code == 200:
                data = resp.json().get("data", {}).get("attributes", {})
                status = data.get("status")

                if status == "completed":
                    stats = data.get("stats", {})
                    malicious = stats.get("malicious", 0)
                    total = sum(stats.values())

                    if total == 0:
                        continue

                    verdict = "infected" if malicious > 0 else "clean"
                    details = f"Score: {malicious}/{total}"
                    return verdict, details, gui_link
        except Exception:
            pass

    return "timeout", "Анализ длится слишком долго (очередь VT)", gui_link


def _parse_vt_response(json_data, gui_link):
    try:
        attrs = json_data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})

        malicious = stats.get("malicious", 0)
        total = sum(stats.values())

        if total == 0:
            return "unknown", "Нет данных (Score 0/0)", gui_link

        verdict = "infected" if malicious > 0 else "clean"
        details = f"Score: {malicious}/{total}"
        return verdict, details, gui_link
    except:
        return "error", "Ошибка парсинга JSON", gui_link


def check_file_with_yara(path):
    try:
        if not os.path.exists(YARA_RULES_PATH):
            return "error", [f"File not found: {YARA_RULES_PATH}"]

        rules = yara.compile(filepath=YARA_RULES_PATH)

        matches = rules.match(path)

        if matches:
            return "infected", [str(m) for m in matches]

        return "clean", []

    except yara.Error as e:
        return "error", [f"YARA Error: {e}"]
    except Exception as e:
        return "error", [str(e)]


def analyze_pe_file(path):
    try:
        pe = pefile.PE(path)

        if len(pe.sections) < 1:
            return "suspicious", ["Аномалия: Нет секций (файл пуст или упакован)"]

        return "clean", []

    except pefile.PEFormatError:
        return "clean", []
    except Exception as e:
        return "error", [str(e)]
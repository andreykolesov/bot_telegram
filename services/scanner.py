import time
import requests
import os
import yara
import pefile
from config import YARA_RULES_PATH, VIRUSTOTAL_API_KEY, VIRUSTOTAL_URL


def check_virustotal(path, file_hash):
    if not VIRUSTOTAL_API_KEY or "YOUR" in VIRUSTOTAL_API_KEY:
        return "skipped", ["API Key не настроен"], ""

    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    gui_link = f"https://www.virustotal.com/gui/file/{file_hash}"

    try:
        response = requests.get(f"{VIRUSTOTAL_URL}/{file_hash}", headers=headers)

        if response.status_code == 200:
            return _parse_vt_response(response.json(), gui_link)

        elif response.status_code == 404:
            return _upload_large_file(path, headers, gui_link)

        else:
            return "error", [f"HTTP Error {response.status_code}"], gui_link

    except Exception as e:
        return "error", [str(e)], gui_link


def _upload_large_file(path, headers, gui_link):
    try:
        url_resp = requests.get("https://www.virustotal.com/api/v3/files/upload_url", headers=headers)
        if url_resp.status_code != 200:
            return "error", ["Ошибка получения URL загрузки"], gui_link

        upload_url = url_resp.json().get("data")

        with open(path, "rb") as f:
            files = {"file": (os.path.basename(path), f)}
            upload_resp = requests.post(upload_url, headers=headers, files=files)

        if upload_resp.status_code != 200:
            return "error", [f"Ошибка загрузки: {upload_resp.status_code}"], gui_link

        analysis_id = upload_resp.json().get("data", {}).get("id")
        return _poll_analysis(analysis_id, headers, gui_link)

    except Exception as e:
        return "error", [f"Upload error: {e}"], gui_link


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
                    results = data.get("results", {})
                    stats = data.get("stats", {})
                    return _extract_threats(results, stats, gui_link)
        except:
            pass

    return "timeout", ["Анализ длится слишком долго"], gui_link


def _parse_vt_response(json_data, gui_link):
    try:
        attrs = json_data.get("data", {}).get("attributes", {})
        results = attrs.get("last_analysis_results", {})
        stats = attrs.get("last_analysis_stats", {})

        return _extract_threats(results, stats, gui_link)
    except Exception as e:
        return "error", [f"JSON Parse Error: {e}"], gui_link


def _extract_threats(results_dict, stats_dict, gui_link):
    malicious_count = stats_dict.get("malicious", 0)
    total_count = sum(stats_dict.values())

    if total_count == 0:
        return "unknown", ["Нет данных (Score 0/0)"], gui_link

    if malicious_count == 0:
        return "clean", ["Угроз не обнаружено"], gui_link

    threat_names = []
    for engine, data in results_dict.items():
        if data.get("category") == "malicious":
            virus_name = data.get("result")
            if virus_name:
                threat_names.append(virus_name)

    unique_threats = list(set(threat_names))[:5]
    details_list = [f"Детектов: {malicious_count}/{total_count}"] + unique_threats

    return "infected", details_list, gui_link


def check_file_with_yara(path):
    try:
        if not os.path.exists(YARA_RULES_PATH):
            return "error", [f"Rules missing: {YARA_RULES_PATH}"]

        rules = yara.compile(filepath=YARA_RULES_PATH)
        matches = rules.match(path)

        if matches:
            return "infected", [str(m) for m in matches]

        return "clean", ["Правила не сработали"]

    except Exception as e:
        return "error", [str(e)]


def analyze_pe_file(path):
    try:
        pe = pefile.PE(path)
        if len(pe.sections) < 1:
            return "suspicious", ["Аномалия: Файл не содержит секций"]
        return "clean", ["Структура PE корректна"]
    except pefile.PEFormatError:
        return "clean", ["Не является PE-файлом"]
    except Exception as e:
        return "error", [str(e)]
import time
import requests
import os
import yara
import pefile
import datetime
from config import YARA_GENERIC_PATH, YARA_PE_PATH, VIRUSTOTAL_API_KEY, VIRUSTOTAL_URL


def check_virustotal(path, file_hash):
    if not VIRUSTOTAL_API_KEY or "YOUR" in VIRUSTOTAL_API_KEY:
        return "skipped", ["API Key missing"], ""

    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    gui_link = f"https://www.virustotal.com/gui/file/{file_hash}"

    try:
        response = requests.get(f"{VIRUSTOTAL_URL}/{file_hash}", headers=headers)

        if response.status_code == 200:
            return _parse_vt_response(response.json(), gui_link)

        elif response.status_code == 404:
            return _upload_large_file(path, headers, gui_link)

        else:
            return "error", [f"HTTP {response.status_code}"], gui_link

    except Exception as e:
        return "error", [str(e)], gui_link


def lookup_hash_only(hash_string):
    if not VIRUSTOTAL_API_KEY or "YOUR" in VIRUSTOTAL_API_KEY:
        return "skipped", ["API Key missing"], ""

    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    gui_link = f"https://www.virustotal.com/gui/file/{hash_string}"

    try:
        response = requests.get(f"{VIRUSTOTAL_URL}/{hash_string}", headers=headers)

        if response.status_code == 200:
            return _parse_vt_response(response.json(), gui_link)
        elif response.status_code == 404:
            return "unknown", ["Not found"], gui_link
        else:
            return "error", [f"HTTP {response.status_code}"], gui_link
    except Exception as e:
        return "error", [str(e)], gui_link


def _upload_large_file(path, headers, gui_link):
    try:
        url_resp = requests.get("https://www.virustotal.com/api/v3/files/upload_url", headers=headers)
        if url_resp.status_code != 200:
            return "error", ["Get Upload URL failed"], gui_link

        upload_url = url_resp.json().get("data")

        with open(path, "rb") as f:
            files = {"file": (os.path.basename(path), f)}
            upload_resp = requests.post(upload_url, headers=headers, files=files)

        if upload_resp.status_code != 200:
            return "error", [f"Upload failed: {upload_resp.status_code}"], gui_link

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

    return "timeout", ["Analysis timeout"], gui_link


def _parse_vt_response(json_data, gui_link):
    try:
        attrs = json_data.get("data", {}).get("attributes", {})
        results = attrs.get("last_analysis_results", {})
        stats = attrs.get("last_analysis_stats", {})
        return _extract_threats(results, stats, gui_link)
    except Exception as e:
        return "error", [f"JSON Error: {e}"], gui_link


def _extract_threats(results_dict, stats_dict, gui_link):
    malicious_count = stats_dict.get("malicious", 0)
    total_count = sum(stats_dict.values())

    if total_count == 0:
        return "unknown", ["No Data"], gui_link

    if malicious_count == 0:
        return "clean", ["Clean"], gui_link

    threat_names = []
    for engine, data in results_dict.items():
        if data.get("category") == "malicious":
            virus_name = data.get("result")
            if virus_name:
                threat_names.append(virus_name)

    unique_threats = list(set(threat_names))[:5]
    details_list = [f"Detections: {malicious_count}/{total_count}"] + unique_threats

    return "infected", details_list, gui_link


def check_file_with_yara(path):
    detected = []
    errors = []

    if os.path.exists(YARA_GENERIC_PATH):
        try:
            rules = yara.compile(filepath=YARA_GENERIC_PATH)
            matches = rules.match(path)
            for m in matches: detected.append(str(m))
        except Exception as e:
            errors.append(f"Generic: {e}")

    is_pe = False
    try:
        with open(path, "rb") as f:
            if f.read(2) == b'MZ': is_pe = True
    except:
        pass

    if is_pe and os.path.exists(YARA_PE_PATH):
        try:
            rules = yara.compile(filepath=YARA_PE_PATH)
            matches = rules.match(path)
            for m in matches: detected.append(str(m))
        except Exception as e:
            errors.append(f"PE: {e}")

    if detected:
        return "infected", detected

    if errors:
        return "clean", ["Errors suppressed"]

    return "clean", ["Clean"]


def analyze_pe_file(path):
    pe = None
    alerts = []
    risk = 0
    try:
        pe = pefile.PE(path)

        if len(pe.sections) < 1:
            alerts.append("No sections")
            risk += 10

        try:
            ts = pe.FILE_HEADER.TimeDateStamp
            cdate = datetime.datetime.fromtimestamp(ts)
            if cdate.year > datetime.datetime.now().year + 1 or cdate.year < 1990:
                risk += 1
        except:
            pass

        safe_high_entropy = ['.rsrc', '.data', '.pdata', '.reloc']

        for s in pe.sections:
            s_name = s.Name.decode(errors='ignore').strip('\x00').lower()

            if s.get_entropy() > 7.5:
                if s_name not in safe_high_entropy:
                    alerts.append(f"Packed: {s_name}")
                    risk += 3

            if (s.Characteristics & 0xE0000020) == 0xE0000020:
                alerts.append(f"RWX: {s_name}")
                risk += 4

        low_apis = {"VirtualAlloc", "VirtualProtect", "GetProcAddress", "LoadLibrary"}
        med_apis = {"InternetOpen", "URLDownloadToFile", "RegSetValue", "ShellExecute", "WinExec"}
        high_apis = {"WriteProcessMemory", "CreateRemoteThread", "SetWindowsHookEx", "GetAsyncKeyState",
                     "ReflectiveLoader"}

        found_high = []
        found_med = []

        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    if imp.name:
                        fn = imp.name.decode(errors='ignore')
                        if any(api in fn for api in high_apis):
                            found_high.append(fn)
                            risk += 5
                        elif any(api in fn for api in med_apis):
                            found_med.append(fn)
                            risk += 3
                        elif any(api in fn for api in low_apis):
                            risk += 1

        if found_high:
            alerts.append(f"Critical: {', '.join(list(set(found_high))[:3])}")

        if found_med:
            alerts.append(f"Suspicious: {', '.join(list(set(found_med))[:3])}")

        if risk >= 3: return "suspicious", alerts
        return "clean", ["Structure OK"]

    except pefile.PEFormatError:
        return "clean", ["Not PE"]
    except Exception as e:
        return "error", [str(e)]
    finally:
        if pe: pe.close()
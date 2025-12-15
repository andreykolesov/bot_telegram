import os
import hashlib
import html
import datetime
from aiogram import Router, F, types, Bot
from aiogram.fsm.context import FSMContext
from config import ARCHIVE_EXTENSIONS
from database.models import FileArtifact, Scan, ScanResult, Threat, ScannerTool
from services.audit import log_audit
from services.scanner import check_file_with_yara, analyze_pe_file, check_virustotal

router = Router()


def build_report(name, size, hash_sum, results, verdict, is_admin):
    if verdict == "infected":
        head = "🔴 <b>ОБНАРУЖЕНА УГРОЗА</b>"
        desc = "Найдены сигнатуры известных вирусов."
    elif verdict == "suspicious":
        head = "⚠️ <b>ПОДОЗРИТЕЛЬНО</b>"
        desc = "Обнаружены аномалии в структуре."
    else:
        head = "🟢 <b>ФАЙЛ ЧИСТ</b>"
        desc = "Вредоносный код не обнаружен."

    size_mb = round(size / (1024 * 1024), 2)

    msg = (
        f"{head}\n"
        f"<i>{desc}</i>\n\n"
        f"📄 <b>Файл:</b> <code>{html.escape(name)}</code>\n"
        f"📦 <b>Размер:</b> {size_mb} MB\n"
        f"{'―' * 15}\n"
    )

    for tool_name, res in results.items():
        status = res['status']

        if status == 'infected':
            icon = "❌"
        elif status == 'suspicious':
            icon = "⚠️"
        elif status == 'clean':
            icon = "✅"
        else:
            icon = "❓"

        msg += f"<b>{tool_name}</b>: {icon} {status.upper()}\n"

        details = res.get('details')
        if details and isinstance(details, list):
            if status in ['infected', 'suspicious']:
                msg += "   └ 🔎 <i>Вердикт:</i>\n"
                for item in details:
                    clean_item = html.escape(str(item))
                    msg += f"      • {clean_item}\n"

            elif tool_name == 'VirusTotal' and len(details) > 0:
                msg += f"   └ 📊 <i>{html.escape(details[0])}</i>\n"

        if res.get('link'):
            msg += f"   👉 <a href='{res['link']}'>Полный отчет на сайте</a>\n"

        msg += "\n"

    if is_admin:
        msg += f"{'―' * 15}\n🛠 <b>SHA256:</b>\n<code>{hash_sum}</code>"

    return msg


@router.message(F.document)
async def scan_file(m: types.Message, state: FSMContext, bot: Bot, session):
    doc = m.document
    ext = os.path.splitext(doc.file_name)[1].lower()

    if ext in ARCHIVE_EXTENSIONS:
        return await m.reply(f"❌ <b>Ошибка:</b> Архивы <code>{ext}</code> запрещены.", parse_mode="HTML")

    if doc.file_size > 20 * 1024 * 1024:
        return await m.reply("⚠️ Файл больше 20 МБ (Лимит Telegram).")

    path = f"./{doc.file_name}"
    stm = await m.answer("⏳ <b>Принято.</b>\nСкачивание и анализ...", parse_mode="HTML")

    try:
        await bot.download(doc, destination=path)
        data = await state.get_data()

        sha = hashlib.sha256()
        md5 = hashlib.md5()
        with open(path, "rb") as b:
            for c in iter(lambda: b.read(4096), b""):
                sha.update(c)
                md5.update(c)
        sha_hex = sha.hexdigest()
        md5_hex = md5.hexdigest()

        art = session.query(FileArtifact).filter_by(sha256_hash=sha_hex).first()
        if not art:
            art = FileArtifact(
                sha256_hash=sha_hex, md5_hash=md5_hex,
                size_bytes=doc.file_size, mime_type=doc.mime_type, extension=ext
            )
            session.add(art);
            session.commit()

        scan = Scan(user_id=data['user_id'], file_id=art.id, filename_at_upload=doc.file_name, status="processing")
        session.add(scan);
        session.commit()
        log_audit(session, m.from_user.id, "SCAN", f"File: {doc.file_name}")

        res = {}
        inf = False;
        susp = False

        yt = session.query(ScannerTool).filter_by(name="YARA").first()
        if yt:
            s, d = check_file_with_yara(path)
            session.add(ScanResult(scan_id=scan.id, scanner_tool_id=yt.id, verdict=s))
            if s == "infected":
                inf = True
                for t in d: session.add(
                    Threat(scan_result_id=scan.id, threat_type="Yara Rule", threat_name=t, danger_level="High"))
            res['YARA Rules'] = {'status': s, 'details': d}

        if ext in ['.exe', '.dll', '.sys']:
            pt = session.query(ScannerTool).filter_by(name="PEFile").first()
            if pt:
                s, d = analyze_pe_file(path)
                session.add(ScanResult(scan_id=scan.id, scanner_tool_id=pt.id, verdict=s))
                if s == "suspicious": susp = True
                res['PE Structure'] = {'status': s, 'details': d}

        vt = session.query(ScannerTool).filter_by(name="VirusTotal API").first()
        if vt:
            try:
                await stm.edit_text("⏳ <b>Облако VirusTotal...</b>", parse_mode="HTML")
            except:
                pass

            s, details, l = check_virustotal(path, sha_hex)

            raw_output = str(details[:5]) + f" | {l}"

            scan_res = ScanResult(scan_id=scan.id, scanner_tool_id=vt.id, verdict=s, raw_output=raw_output)
            session.add(scan_res)
            session.commit()

            if s == "infected":
                inf = True
                if len(details) > 1:
                    for virus_name in details[1:]:
                        session.add(
                            Threat(scan_result_id=scan_res.id, threat_type="VirusTotal Detect", threat_name=virus_name,
                                   danger_level="High"))

            res['VirusTotal'] = {'status': s, 'details': details, 'link': l}

        if inf:
            scan.overall_verdict = "infected"
        elif susp:
            scan.overall_verdict = "suspicious"
        else:
            scan.overall_verdict = "clean"

        scan.status = "finished"
        session.commit()

        report_text = build_report(
            doc.file_name,
            doc.file_size,
            sha_hex,
            res,
            scan.overall_verdict,
            data.get('is_admin')
        )

        await m.answer(report_text, parse_mode="HTML", disable_web_page_preview=True)
        await stm.delete()

    except Exception as e:
        await m.answer(f"⚠️ Ошибка: {e}")
    finally:
        if os.path.exists(path): os.remove(path)
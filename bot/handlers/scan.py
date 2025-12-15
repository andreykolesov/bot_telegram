import os, hashlib, html
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
    elif verdict == "suspicious":
        head = "⚠️ <b>ПОДОЗРИТЕЛЬНО</b>"
    else:
        head = "🟢 <b>ФАЙЛ ЧИСТ</b>"

    size_mb = round(size / (1024 * 1024), 2)

    msg = (
        f"{head}\n"
        f"📄 <b>Файл:</b> <code>{html.escape(name)}</code>\n"
        f"📦 <b>Размер:</b> {size_mb} MB\n"
        f"{'―' * 15}\n"
    )

    for tool_name, res in results.items():
        status = res['status']
        icon = "❌" if status == 'infected' else ("⚠️" if status == 'suspicious' else "✅")

        msg += f"<b>{tool_name}</b>: {icon} {status.upper()}\n"

        details = res.get('details')
        if details:
            msg += "   └ 🔎 <i>Детали:</i>\n"
            if isinstance(details, list):
                for item in details:
                    msg += f"      • {html.escape(str(item))}\n"
            else:
                msg += f"      • {html.escape(str(details))}\n"

        if res.get('link'):
            msg += f"   👉 <a href='{res['link']}'>Полный отчет на сайте</a>\n"

        msg += "\n"

    if is_admin:
        msg += f"{'―' * 15}\nSHA256: <code>{hash_sum}</code>"

    return msg


@router.message(F.document)
async def scan_file(m: types.Message, state: FSMContext, bot: Bot, session):
    doc = m.document
    ext = os.path.splitext(doc.file_name)[1].lower()

    if ext in ARCHIVE_EXTENSIONS:
        return await m.reply(f"❌ <b>Ошибка:</b> Архивы <code>{ext}</code> запрещены.", parse_mode="HTML")

    if doc.file_size > 20 * 1024 * 1024:
        return await m.reply(
            "⚠️ <b>Файл слишком большой.</b>\n"
            "Telegram запрещает ботам скачивать файлы более 20 МБ.\n"
            "Пожалуйста, загрузите файл меньшего размера.",
            parse_mode="HTML"
        )

    path = f"./{doc.file_name}"
    stm = await m.answer("⏳ <b>Принято.</b>\nСкачивание и анализ...", parse_mode="HTML")

    try:
        await bot.download(doc, destination=path)
        data = await state.get_data()

        sha = hashlib.sha256()
        with open(path, "rb") as b:
            for c in iter(lambda: b.read(4096), b""): sha.update(c)
        h = sha.hexdigest()

        art = session.query(FileArtifact).filter_by(sha256_hash=h).first()
        if not art:
            art = FileArtifact(sha256_hash=h, size_bytes=doc.file_size, mime_type=doc.mime_type, extension=ext)
            session.add(art);
            session.commit()

        scan = Scan(user_id=data['user_id'], file_id=art.id, filename_at_upload=doc.file_name, status="processing")
        session.add(scan);
        session.commit()
        log_audit(session, m.from_user.id, "SCAN", f"File: {doc.file_name}")

        res = {}
        inf = False
        susp = False

        yt = session.query(ScannerTool).filter_by(name="YARA").first()
        if yt:
            s, d = check_file_with_yara(path)
            session.add(ScanResult(scan_id=scan.id, scanner_tool_id=yt.id, verdict=s))
            if s == "infected":
                inf = True
                for t in d: session.add(
                    Threat(scan_result_id=scan.id, threat_type="Yara", threat_name=t, danger_level="High"))
            res['YARA Rules'] = {'status': s, 'details': d}

        if ext in ['.exe', '.dll']:
            pt = session.query(ScannerTool).filter_by(name="PEFile").first()
            if pt:
                s, d = analyze_pe_file(path)
                session.add(ScanResult(scan_id=scan.id, scanner_tool_id=pt.id, verdict=s))
                if s == "suspicious": susp = True
                res['PE Structure'] = {'status': s, 'details': d}

        vt = session.query(ScannerTool).filter_by(name="VirusTotal API").first()
        if vt:
            try:
                await stm.edit_text(
                    "⏳ <b>Облачное сканирование (VirusTotal)...</b>\nЭто может занять до 2-3 минут для новых файлов.",
                    parse_mode="HTML")
            except:
                pass

            s, i, l = check_virustotal(path, h)
            session.add(ScanResult(scan_id=scan.id, scanner_tool_id=vt.id, verdict=s, raw_output=f"{i}|{l}"))
            if s == "infected": inf = True
            res['VirusTotal'] = {'status': s, 'details': i, 'link': l}

        if inf:
            scan.overall_verdict = "infected"
        elif susp:
            scan.overall_verdict = "suspicious"
        else:
            scan.overall_verdict = "clean"

        scan.status = "finished"
        session.commit()

        report_text = build_report(doc.file_name, doc.file_size, h, res, scan.overall_verdict, data.get('is_admin'))

        await m.answer(report_text, parse_mode="HTML", disable_web_page_preview=True)
        await stm.delete()

    except Exception as e:
        await m.answer(f"⚠️ Ошибка: {e}")
    finally:
        if os.path.exists(path): os.remove(path)
import datetime
from aiogram import Router, F, types
from aiogram.fsm.context import FSMContext
from aiogram.types import FSInputFile
from config import CREATOR_ID
from bot.states import AdminStates
from bot.keyboards import get_admin_keyboard, get_cancel_keyboard, get_export_formats_keyboard, \
    get_backup_selection_keyboard
from services.manage import set_user_block_status, delete_user_by_login, toggle_admin_role
from services.backup import perform_backup
from services.export import export_audit_log

router = Router()


@router.callback_query(F.data == "admin_panel")
async def pan(c: types.CallbackQuery, state: FSMContext):
    d = await state.get_data()
    if not d.get('is_admin'):
        return await c.answer("Нет прав", True)

    is_creator = (c.from_user.id == CREATOR_ID)
    await c.message.edit_text("🛠 <b>Админ панель</b>", reply_markup=get_admin_keyboard(is_creator), parse_mode="HTML")


@router.callback_query(F.data == "backup_menu")
async def backup_menu(c: types.CallbackQuery):
    await c.message.edit_text("💾 <b>Выберите тип резервного копирования:</b>",
                              reply_markup=get_backup_selection_keyboard(), parse_mode="HTML")


@router.callback_query(F.data == "do_backup_local")
async def bac_local(c: types.CallbackQuery, session):
    await c.message.edit_text("⏳ Создаю локальный бэкап...", parse_mode="HTML")
    res = perform_backup(session, c.from_user.id, target="local")
    await c.message.answer(res)
    await c.message.answer("🛠 <b>Админ панель</b>", reply_markup=get_admin_keyboard(c.from_user.id == CREATOR_ID),
                           parse_mode="HTML")


@router.callback_query(F.data == "do_backup_yandex")
async def bac_yandex(c: types.CallbackQuery, session):
    await c.message.edit_text("⏳ Создаю и загружаю на Яндекс.Диск...", parse_mode="HTML")
    res = perform_backup(session, c.from_user.id, target="yandex")
    await c.message.answer(res)
    await c.message.answer("🛠 <b>Админ панель</b>", reply_markup=get_admin_keyboard(c.from_user.id == CREATOR_ID),
                           parse_mode="HTML")


@router.callback_query(F.data == "admin_export_menu")
async def export_menu(c: types.CallbackQuery, state: FSMContext):
    if not (await state.get_data()).get('is_admin'):
        return await c.answer("Нет прав", True)

    await c.message.edit_text("📂 <b>Выберите формат отчета:</b>", reply_markup=get_export_formats_keyboard(),
                              parse_mode="HTML")


@router.callback_query(F.data.in_({"export_csv", "export_pdf"}))
async def export(c: types.CallbackQuery, session, state: FSMContext):
    if not (await state.get_data()).get('is_admin'):
        return await c.answer("Нет прав", True)

    fmt = c.data.split("_")[1]
    await c.message.answer(f"⏳ Формирую отчет ({fmt.upper()})...")

    path = export_audit_log(session, c.from_user.id, fmt)

    if path:
        caption = f"📅 Лог ({fmt.upper()})\n{datetime.datetime.now().strftime('%d.%m %H:%M')}"
        await c.message.answer_document(FSInputFile(path), caption=caption)
    else:
        await c.message.answer("❌ Ошибка экспорта.")
    await c.answer()


@router.callback_query(F.data.in_({"admin_promote", "admin_block", "admin_unblock", "admin_delete"}))
async def ask(c: types.CallbackQuery, state: FSMContext):
    if c.data == "admin_promote" and c.from_user.id != CREATOR_ID:
        return await c.answer("Только Создатель", True)

    await state.update_data(act=c.data)

    txt = {
        "admin_promote": "смены прав", "admin_block": "блокировки",
        "admin_unblock": "разблокировки", "admin_delete": "удаления"
    }
    await c.message.edit_text(f"✍️ Введите <b>Логин</b> для {txt.get(c.data)}:", reply_markup=get_cancel_keyboard(),
                              parse_mode="HTML")
    await state.set_state(AdminStates.wait_input)


@router.callback_query(F.data == "admin_cancel_input")
async def canc(c: types.CallbackQuery, state: FSMContext):
    is_creator = (c.from_user.id == CREATOR_ID)
    await c.message.edit_text("🛠 <b>Админ панель</b>", reply_markup=get_admin_keyboard(is_creator), parse_mode="HTML")
    await state.set_state(None)


@router.message(AdminStates.wait_input)
async def proc(m: types.Message, state: FSMContext, session):
    d = await state.get_data();
    act, l, rid = d.get('act'), m.text, m.from_user.id

    if act == 'admin_promote':
        s, t = toggle_admin_role(session, l, rid)
    elif act == 'admin_block':
        s, t = set_user_block_status(session, l, True, rid)
    elif act == 'admin_unblock':
        s, t = set_user_block_status(session, l, False, rid)
    elif act == 'admin_delete':
        s, t = delete_user_by_login(session, l, rid)
    else:
        s, t = False, "Err"

    await m.answer(f"{'✅' if s else '⛔'} {t}")
    is_creator = (rid == CREATOR_ID)
    await m.answer("🛠 <b>Админ панель</b>", reply_markup=get_admin_keyboard(is_creator), parse_mode="HTML")
    await state.set_state(None)
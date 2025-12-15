import html
from aiogram import Router, F, types
from aiogram.fsm.context import FSMContext
from aiogram.types import FSInputFile
from config import CREATOR_ID
from bot.keyboards import get_main_menu_keyboard, get_auth_keyboard, get_back_keyboard
from services.stats import get_user_statistics
from services.export import export_audit_log

router = Router()


async def show_main_menu(msg: types.Message, state: FSMContext, edit=False):
    data = await state.get_data()
    user_id_tg = msg.chat.id
    is_admin = data.get('is_admin', False)
    username = data.get('username', 'Неизвестно')

    if user_id_tg == CREATOR_ID:
        role_str = "👑 Создатель"
    elif is_admin:
        role_str = "👮 Администратор"
    else:
        role_str = "👤 Пользователь"

    text = (
        f"🖥 <b>Главное меню</b>\n\n"
        f"👤 Логин: <code>{html.escape(username)}</code>\n"
        f"🔰 Роль: <b>{role_str}</b>\n\n"
        f"👇 Выберите действие:"
    )

    kb = get_main_menu_keyboard(is_admin)
    if edit:
        await msg.edit_text(text, reply_markup=kb, parse_mode="HTML")
    else:
        await msg.answer(text, reply_markup=kb, parse_mode="HTML")


@router.callback_query(F.data == "back_to_main")
async def back(c: types.CallbackQuery, state: FSMContext):
    await state.set_state(None)
    await show_main_menu(c.message, state, edit=True)


@router.callback_query(F.data == "logout")
async def logout(c: types.CallbackQuery, state: FSMContext):
    await state.clear()
    await c.message.edit_text("🚪 Вы успешно вышли из системы.", reply_markup=get_auth_keyboard())


@router.callback_query(F.data == "scan_mode")
async def scan(c: types.CallbackQuery):
    await c.message.edit_text(
        "📤 <b>Режим сканирования</b>\n\n"
        "Отправьте мне файл (документ, фото как файл) прямо в этот чат.\n"
        "Я проанализирую его структуру и проверю по базам.",
        reply_markup=get_back_keyboard(),
        parse_mode="HTML"
    )


@router.callback_query(F.data == "my_stats")
async def stats(c: types.CallbackQuery, state: FSMContext, session):
    data = await state.get_data()
    s = get_user_statistics(session, data['user_id'])

    if s:
        reg_fmt = s['reg_date'].strftime('%d.%m.%Y %H:%M')
        last_fmt = s['last_active'].strftime('%d.%m.%Y %H:%M') if s['last_active'] else "Нет проверок"

        bad_total = s['infected'] + s['suspicious']
        safety_percent = 100
        if s['total'] > 0:
            safety_percent = round(((s['total'] - bad_total) / s['total']) * 100, 1)

        t = (
            f"📊 <b>Расширенная статистика</b>\n"
            f"{'―' * 15}\n"
            f"📅 Регистрация: {reg_fmt}\n"
            f"🕒 Последняя активность: {last_fmt}\n"
            f"{'―' * 15}\n"
            f"📂 <b>Всего загружено файлов:</b> {s['total']}\n\n"
            f"🟢 Безопасные: {s['clean']}\n"
            f"🔴 Угрозы: {s['infected']}\n"
            f"⚠️ Подозрительные: {s['suspicious']}\n\n"
            f"🛡 <b>Индекс безопасности:</b> {safety_percent}%"
        )
        await c.message.edit_text(t, reply_markup=get_back_keyboard(), parse_mode="HTML")
    else:
        await c.message.edit_text("❌ Ошибка получения данных.", reply_markup=get_back_keyboard())


@router.callback_query(F.data == "export_csv")
async def export(c: types.CallbackQuery, session, state: FSMContext):
    data = await state.get_data()
    if not data.get('is_admin'):
        return await c.answer("⛔ Доступно только Администраторам!", show_alert=True)

    await c.message.answer("⏳ Генерирую полный отчет о действиях (CSV)...")
    path = export_audit_log(session, c.from_user.id, 'csv')

    if path:
        await c.message.answer_document(FSInputFile(path), caption="📅 Лог аудита системы")
    else:
        await c.message.answer("❌ Ошибка при создании файла.")
    await c.answer()
import html
from aiogram import Router, F, types
from aiogram.fsm.context import FSMContext
from config import CREATOR_ID
from bot.keyboards import get_main_menu_keyboard, get_auth_keyboard, get_back_keyboard
from services.stats import get_user_statistics

router = Router()

async def show_main_menu(msg: types.Message, state: FSMContext, edit=False):
    d = await state.get_data()
    uid = msg.chat.id
    role = "👑 Создатель" if uid == CREATOR_ID else ("👮 Админ" if d.get('is_admin') else "👤 Пользователь")
    text = f"🖥 <b>Главное меню</b>\n👤 Логин: <code>{html.escape(d.get('username','?'))}</code>\n🔰 Роль: <b>{role}</b>"
    kb = get_main_menu_keyboard(d.get('is_admin'))
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
    await c.message.edit_text("🚪 Вы успешно вышли.", reply_markup=get_auth_keyboard())

@router.callback_query(F.data == "scan_mode")
async def scan(c: types.CallbackQuery):
    await c.message.edit_text("📤 <b>Режим сканирования</b>\nОтправьте файл в этот чат.", reply_markup=get_back_keyboard(), parse_mode="HTML")

@router.callback_query(F.data == "my_stats")
async def stats(c: types.CallbackQuery, state: FSMContext, session):
    d = await state.get_data()
    s = get_user_statistics(session, d['user_id'])
    if s:
        bad = s['infected'] + s['suspicious']
        safe = round(((s['total'] - bad)/s['total'])*100, 1) if s['total'] > 0 else 100
        reg = s['reg_date'].strftime('%d.%m %H:%M')
        act = s['last_active'].strftime('%d.%m %H:%M') if s['last_active'] else 'Нет'
        t = (f"📊 <b>Статистика</b>\n{'―'*15}\n📅 Рег: {reg}\n🕒 Акт: {act}\n{'―'*15}\n"
             f"📂 Всего: {s['total']}\n🟢 Чистые: {s['clean']}\n🔴 Угрозы: {s['infected']}\n⚠️ Подозр.: {s['suspicious']}\n\n🛡 Индекс: {safe}%")
        await c.message.edit_text(t, reply_markup=get_back_keyboard(), parse_mode="HTML")
    else:
        await c.message.edit_text("Ошибка", reply_markup=get_back_keyboard())
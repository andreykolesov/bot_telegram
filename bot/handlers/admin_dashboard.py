from aiogram import Router, F, types
from aiogram.fsm.context import FSMContext
from config import CREATOR_ID
from bot.states import AdminStates
from bot.keyboards import get_admin_keyboard, get_cancel_keyboard
from services.manage import set_user_block_status, delete_user_by_login, toggle_admin_role
from services.backup import perform_backup

router = Router()


@router.callback_query(F.data == "admin_panel")
async def pan(c: types.CallbackQuery, state: FSMContext):
    data = await state.get_data()

    if not data.get('is_admin'):
        return await c.answer("⛔ У вас нет прав администратора", show_alert=True)

    is_creator = (c.from_user.id == CREATOR_ID)

    await c.message.edit_text(
        "🛠 <b>Админ панель</b>\nВыберите действие:",
        reply_markup=get_admin_keyboard(is_creator),
        parse_mode="HTML"
    )


@router.callback_query(F.data == "do_backup")
async def bac(c: types.CallbackQuery, session):
    await c.message.answer("⏳ Создаю резервную копию БД...")
    msg = perform_backup(session)
    await c.message.answer(f"📦 {msg}")
    await c.answer()


@router.callback_query(F.data.in_({"admin_promote", "admin_block", "admin_unblock", "admin_delete"}))
async def ask(c: types.CallbackQuery, state: FSMContext):
    if c.data == "admin_promote" and c.from_user.id != CREATOR_ID:
        return await c.answer("⛔ Только Владелец может управлять администраторами!", show_alert=True)

    await state.update_data(act=c.data)

    text_map = {
        "admin_promote": "Введите <b>Логин</b> для изменения прав (Админ/Юзер):",
        "admin_block": "Введите <b>Логин</b> для блокировки:",
        "admin_unblock": "Введите <b>Логин</b> для разблокировки:",
        "admin_delete": "Введите <b>Логин</b> для полного удаления:"
    }
    msg = text_map.get(c.data, "Введите Логин:")

    await c.message.edit_text(f"✍️ {msg}", reply_markup=get_cancel_keyboard(), parse_mode="HTML")
    await state.set_state(AdminStates.wait_input)


@router.callback_query(F.data == "admin_cancel_input")
async def cancel(c: types.CallbackQuery, state: FSMContext):
    is_creator = (c.from_user.id == CREATOR_ID)
    await c.message.edit_text("🛠 <b>Админ панель</b>", reply_markup=get_admin_keyboard(is_creator), parse_mode="HTML")
    await state.set_state(None)


@router.message(AdminStates.wait_input)
async def proc(m: types.Message, state: FSMContext, session):
    data = await state.get_data()
    act = data.get('act')
    login = m.text
    requester_id = m.from_user.id

    if act == 'admin_promote':
        success, msg = toggle_admin_role(session, login, requester_id)
    elif act == 'admin_block':
        success, msg = set_user_block_status(session, login, True, requester_id)
    elif act == 'admin_unblock':
        success, msg = set_user_block_status(session, login, False, requester_id)
    elif act == 'admin_delete':
        success, msg = delete_user_by_login(session, login, requester_id)
    else:
        success, msg = False, "Неизвестная команда"

    icon = "✅" if success else "⛔"
    await m.answer(f"{icon} {msg}")

    is_creator = (requester_id == CREATOR_ID)
    await m.answer("🛠 <b>Админ панель</b>", reply_markup=get_admin_keyboard(is_creator), parse_mode="HTML")
    await state.set_state(None)
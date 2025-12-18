import time
from aiogram import Router, F, types
from aiogram.filters import Command
from aiogram.fsm.context import FSMContext
from bot.states import AuthStates
from bot.keyboards import get_auth_keyboard
from bot.handlers.menu import show_main_menu
from services.account import authenticate_user, register_user
from services.audit import log_audit

router = Router()


@router.message(Command("start"))
async def start(msg: types.Message, state: FSMContext):
    await state.clear()
    await msg.answer("👋 <b>Secure Bot</b>\nАвторизуйтесь:", reply_markup=get_auth_keyboard(), parse_mode="HTML")


@router.message(Command("help"))
async def help_cmd(msg: types.Message):
    await msg.answer("ℹ️ <b>Справка</b>\nЗагрузите файл для проверки.\nАрхивы запрещены.", parse_mode="HTML")


@router.callback_query(F.data == "login_start")
async def login_st(c: types.CallbackQuery, state: FSMContext):
    await c.message.edit_text("✍️ Введите <b>Логин</b>:", parse_mode="HTML")
    await state.set_state(AuthStates.login_enter_login)


@router.message(AuthStates.login_enter_login)
async def login_l(m: types.Message, state: FSMContext):
    await state.update_data(tl=m.text)
    await m.answer("🔑 Введите ваш <b>Пароль</b>:", parse_mode="HTML")
    await state.set_state(AuthStates.login_enter_pass)


@router.message(AuthStates.login_enter_pass)
async def login_p(m: types.Message, state: FSMContext, session):
    data = await state.get_data()

    block_end = data.get('block_until', 0)
    current_time = time.time()

    if current_time < block_end:
        wait_seconds = int(block_end - current_time)
        await m.answer(f"⛔ <b>Ввод заблокирован.</b>\nПодождите {wait_seconds} сек.", parse_mode="HTML")
        return

    user, text = authenticate_user(session, data.get('tl'), m.text, m.from_user.id)

    if user:
        await state.update_data(
            is_authenticated=True,
            user_id=user.id,
            is_admin=(user.role.name == 'admin'),
            username=user.login,
            attempts=0,
            block_until=0
        )
        await state.set_state(None)
        await m.answer(f"✅ <b>{text}</b>", parse_mode="HTML")
        await show_main_menu(m, state)
        log_audit(session, m.from_user.id, "LOGIN", "Success")
    else:
        attempts = data.get('attempts', 0) + 1

        if attempts >= 3:
            block_time = 10
            await state.update_data(block_until=time.time() + block_time, attempts=0)
            await m.answer(
                f"❌ <b>Неверный пароль.</b>\n"
                f"Слишком много попыток.\n"
                f"⛔ <b>Блокировка на {block_time} секунд.</b>",
                parse_mode="HTML"
            )
        else:
            left = 3 - attempts
            await state.update_data(attempts=attempts)
            await m.answer(
                f"❌ <b>{text}</b>\n"
                f"Осталось попыток: {left}\n"
                f"Попробуйте снова:",
                parse_mode="HTML"
            )


@router.callback_query(F.data == "register_start")
async def reg_st(c: types.CallbackQuery, state: FSMContext):
    await c.message.edit_text("🆕 Придумайте <b>Логин</b>:", parse_mode="HTML")
    await state.set_state(AuthStates.reg_enter_login)


@router.message(AuthStates.reg_enter_login)
async def reg_l(m: types.Message, state: FSMContext):
    await state.update_data(rl=m.text)
    await m.answer("🆕 Придумайте надежный <b>Пароль</b>:", parse_mode="HTML")
    await state.set_state(AuthStates.reg_enter_pass)


@router.message(AuthStates.reg_enter_pass)
async def reg_p(m: types.Message, state: FSMContext, session):
    d = await state.get_data()
    success, text = register_user(session, m.from_user, d['rl'], m.text)

    icon = "✅" if success else "❌"
    await m.answer(f"{icon} <b>{text}</b>", reply_markup=get_auth_keyboard(), parse_mode="HTML")
    await state.clear()
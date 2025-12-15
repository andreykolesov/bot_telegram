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
    await msg.answer("👋 <b>Antivirus Bot</b>\nАвторизуйтесь:", reply_markup=get_auth_keyboard(), parse_mode="HTML")

@router.message(Command("help"))
async def help_cmd(msg: types.Message):
    await msg.answer("ℹ️ <b>Справка</b>\nЗагрузите файл для проверки.", parse_mode="HTML")

@router.callback_query(F.data == "login_start")
async def login_st(c: types.CallbackQuery, state: FSMContext):
    await c.message.edit_text("✍️ Введите <b>Логин</b>:", parse_mode="HTML")
    await state.set_state(AuthStates.login_enter_login)

@router.message(AuthStates.login_enter_login)
async def login_l(m: types.Message, state: FSMContext):
    await state.update_data(tl=m.text)
    await m.answer("🔑 Введите <b>Пароль</b>:", parse_mode="HTML")
    await state.set_state(AuthStates.login_enter_pass)

@router.message(AuthStates.login_enter_pass)
async def login_p(m: types.Message, state: FSMContext, session):
    d = await state.get_data()
    user, txt = authenticate_user(session, d['tl'], m.text, m.from_user.id)
    if user:
        await state.update_data(is_authenticated=True, user_id=user.id, is_admin=(user.role.name=='admin'), username=user.login)
        await state.set_state(None)
        await m.answer(f"✅ {txt}", parse_mode="HTML")
        await show_main_menu(m, state)
        log_audit(session, m.from_user.id, "LOGIN", "Success")
    else:
        await m.answer(f"❌ {txt}", parse_mode="HTML")
        await state.clear()

@router.callback_query(F.data == "register_start")
async def reg_st(c: types.CallbackQuery, state: FSMContext):
    await c.message.edit_text("🆕 Придумайте <b>Логин</b>:", parse_mode="HTML")
    await state.set_state(AuthStates.reg_enter_login)

@router.message(AuthStates.reg_enter_login)
async def reg_l(m: types.Message, state: FSMContext):
    await state.update_data(rl=m.text)
    await m.answer("🆕 Придумайте <b>Пароль</b>:", parse_mode="HTML")
    await state.set_state(AuthStates.reg_enter_pass)

@router.message(AuthStates.reg_enter_pass)
async def reg_p(m: types.Message, state: FSMContext, session):
    d = await state.get_data()
    success, txt = register_user(session, m.from_user, d['rl'], m.text)
    await m.answer(f"{'✅' if success else '❌'} {txt}", reply_markup=get_auth_keyboard(), parse_mode="HTML")
    await state.clear()
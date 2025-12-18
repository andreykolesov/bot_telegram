import html
from aiogram import Router, F, types, Bot
from aiogram.fsm.context import FSMContext
from bot.states import SupportStates
from bot.keyboards import get_cancel_support_keyboard, get_tickets_list_keyboard, get_ticket_actions_keyboard, \
    get_main_menu_keyboard
from services.support import create_ticket, get_open_tickets, get_ticket_by_id, answer_ticket

router = Router()


@router.callback_query(F.data == "support_ask")
async def ask(c: types.CallbackQuery, state: FSMContext):
    await c.message.edit_text("🆘 <b>Тех. поддержка</b>\nОпишите проблему одним сообщением:",
                              reply_markup=get_cancel_support_keyboard(), parse_mode="HTML")
    await state.set_state(SupportStates.ask_question)


@router.message(SupportStates.ask_question)
async def proc_q(m: types.Message, state: FSMContext, session):
    if not m.text: return await m.answer("Пришлите текст.")
    tid = create_ticket(session, (await state.get_data())['user_id'], m.text)
    await m.answer(f"✅ <b>Тикет #{tid} создан!</b>\nЖдите ответа.", parse_mode="HTML")

    is_admin = (await state.get_data()).get('is_admin')
    await m.answer("Главное меню:", reply_markup=get_main_menu_keyboard(is_admin))
    await state.set_state(None)


@router.callback_query(F.data == "support_list")
async def sl(c: types.CallbackQuery, state: FSMContext, session):
    if not (await state.get_data()).get('is_admin'): return await c.answer("Нет прав", True)
    t = get_open_tickets(session)
    if not t: return await c.answer("Нет вопросов", True)
    await c.message.edit_text(f"📨 <b>Открытые вопросы ({len(t)}):</b>", reply_markup=get_tickets_list_keyboard(t),
                              parse_mode="HTML")


@router.callback_query(F.data.startswith("support_view_"))
async def sv(c: types.CallbackQuery, session):
    tid = int(c.data.split("_")[2])
    t = get_ticket_by_id(session, tid)
    if not t: return await c.answer("Не найден", True)
    txt = f"📨 <b>Вопрос #{t.id}</b>\n👤 От: <code>{html.escape(t.user.login)}</code>\n📅 Дата: {t.created_at.strftime('%d.%m %H:%M')}\n\n📝 <b>Текст:</b>\n{html.escape(t.question)}"
    await c.message.edit_text(txt, reply_markup=get_ticket_actions_keyboard(t.id), parse_mode="HTML")


@router.callback_query(F.data.startswith("support_reply_"))
async def sr(c: types.CallbackQuery, state: FSMContext):
    await state.update_data(rtid=int(c.data.split("_")[2]))
    await c.message.edit_text("✍️ <b>Введите ответ:</b>", reply_markup=get_cancel_support_keyboard(), parse_mode="HTML")
    await state.set_state(SupportStates.answer_question)


@router.message(SupportStates.answer_question)
async def sa(m: types.Message, state: FSMContext, session, bot: Bot):
    d = await state.get_data()
    t, msg = answer_ticket(session, d['rtid'], d['user_id'], m.text)
    if not t:
        await m.answer(f"❌ Ошибка: {msg}")
        await state.set_state(None)
        return

    try:
        await bot.send_message(t.user.telegram_id,
                               f"🔔 <b>Ответ от поддержки!</b>\n\n❓ <b>Вопрос #{t.id}:</b>\n{html.escape(t.question)}\n\n👮 <b>Ответ:</b>\n{html.escape(m.text)}",
                               parse_mode="HTML")
        st = "Доставлено ✅"
    except:
        st = "Не доставлено ⚠️"

    await m.answer(f"✅ Сохранено. {st}")

    ost = get_open_tickets(session)
    if ost:
        await m.answer("Осталось:", reply_markup=get_tickets_list_keyboard(ost))
    else:
        await m.answer("Все вопросы закрыты!", reply_markup=get_main_menu_keyboard(d['is_admin']))
    await state.set_state(None)


@router.callback_query(F.data == "support_cancel")
async def sc(c: types.CallbackQuery, state: FSMContext):
    await state.set_state(None)
    await c.message.edit_text("Отмена.", reply_markup=get_main_menu_keyboard((await state.get_data()).get('is_admin')))
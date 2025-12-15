from typing import Any, Awaitable, Callable, Dict
from aiogram import BaseMiddleware
from aiogram.types import Message, CallbackQuery
from database.db import get_session
from database.models import User


class DbSessionMiddleware(BaseMiddleware):
    async def __call__(
            self,
            handler: Callable[[Message, Dict[str, Any]], Awaitable[Any]],
            event: Message | CallbackQuery,
            data: Dict[str, Any]
    ) -> Any:
        session = get_session()
        data['session'] = session
        try:
            return await handler(event, data)
        finally:
            session.close()


class AuthMiddleware(BaseMiddleware):
    async def __call__(
            self,
            handler: Callable[[Message, Dict[str, Any]], Awaitable[Any]],
            event: Message | CallbackQuery,
            data: Dict[str, Any]
    ) -> Any:
        session = data['session']
        tg_user_id = event.from_user.id

        db_user = session.query(User).filter_by(telegram_id=tg_user_id).first()
        if db_user and db_user.is_blocked:
            msg = "⛔ <b>Ваш аккаунт заблокирован, действия невозможны.</b>"
            if isinstance(event, Message):
                await event.answer(msg, parse_mode="HTML")
            else:
                await event.message.answer(msg, parse_mode="HTML"); await event.answer()
            return

        state = data['state']
        user_data = await state.get_data()

        public = ["/start", "/help", "login_start", "register_start"]

        current_cmd = event.text if isinstance(event, Message) else event.data

        if (await state.get_state()) or user_data.get("is_authenticated") or current_cmd in public:
            return await handler(event, data)

        msg = "⛔ <b>Доступ запрещен.</b>\nВойдите в систему: /start"
        if isinstance(event, Message):
            await event.answer(msg, parse_mode="HTML")
        else:
            await event.message.answer(msg, parse_mode="HTML")
            await event.answer()
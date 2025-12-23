import asyncio
import logging
from aiogram import Bot, Dispatcher
from aiogram.client.default import DefaultBotProperties
from aiogram.fsm.storage.memory import MemoryStorage
from aiogram.types import BotCommand
from config import TELEGRAM_TOKEN
from database.db import engine, Base, get_session
from database.models import UserRole, ScannerTool
from bot.middlewares import DbSessionMiddleware, AuthMiddleware
from bot.handlers import login, menu, admin_dashboard, scan, helpdesk

logging.basicConfig(level=logging.INFO)


def init_db():
    Base.metadata.create_all(engine)
    s = get_session()
    if not s.query(UserRole).filter_by(name='user').first():
        s.add(UserRole(name='user', description='Standard User'))
    if not s.query(UserRole).filter_by(name='admin').first():
        s.add(UserRole(name='admin', description='Administrator'))
    for t in ["YARA", "VirusTotal API", "PEFile"]:
        if not s.query(ScannerTool).filter_by(name=t).first():
            s.add(ScannerTool(name=t, version="1.0"))
    s.commit()
    s.close()


async def setup_bot_commands(bot: Bot):
    commands = [
        BotCommand(command="start", description="🏠 Главное меню / Вход"),
        BotCommand(command="help", description="ℹ️ Помощь и описание")
    ]
    await bot.set_my_commands(commands)


async def main():
    print("Init DB...")
    init_db()

    bot = Bot(token=TELEGRAM_TOKEN, default=DefaultBotProperties(parse_mode="HTML"))
    dp = Dispatcher(storage=MemoryStorage())
    dp.update.middleware(DbSessionMiddleware())
    dp.message.middleware(AuthMiddleware())
    dp.callback_query.middleware(AuthMiddleware())

    dp.include_routers(
        login.router,
        menu.router,
        admin_dashboard.router,
        helpdesk.router,
        scan.router
    )

    await setup_bot_commands(bot)
    await bot.delete_webhook(drop_pending_updates=True)
    await dp.start_polling(bot)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
from aiogram.types import InlineKeyboardMarkup, InlineKeyboardButton
from aiogram.utils.keyboard import InlineKeyboardBuilder


def get_auth_keyboard():
    builder = InlineKeyboardBuilder()
    builder.button(text="🔐 Вход", callback_data="login_start")
    builder.button(text="📝 Регистрация", callback_data="register_start")
    return builder.as_markup()


def get_main_menu_keyboard(is_admin: bool):
    builder = InlineKeyboardBuilder()

    builder.button(text="📤 Сканировать файл", callback_data="scan_mode")
    builder.button(text="📊 Моя статистика", callback_data="my_stats")

    if is_admin:
        builder.button(text="💾 Выгрузить отчет (CSV)", callback_data="export_csv")
        builder.button(text="🛠 Админ-панель", callback_data="admin_panel")

    builder.button(text="🚪 Выйти", callback_data="logout")

    builder.adjust(1)
    return builder.as_markup()


def get_admin_keyboard(is_creator: bool):
    builder = InlineKeyboardBuilder()

    builder.button(text="💾 Бэкап БД", callback_data="do_backup")

    if is_creator:
        builder.button(text="👑 Упр. Админами", callback_data="admin_promote")

    builder.button(text="🚫 Блок", callback_data="admin_block")
    builder.button(text="✅ Разблок", callback_data="admin_unblock")
    builder.button(text="🗑 Удалить юзера", callback_data="admin_delete")
    builder.button(text="🔙 Назад", callback_data="back_to_main")

    if is_creator:
        builder.adjust(2, 2, 1, 1)
    else:
        builder.adjust(1, 2, 1, 1)

    return builder.as_markup()


def get_back_keyboard():
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="🔙 Назад в меню", callback_data="back_to_main")]
    ])


def get_cancel_keyboard():
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="❌ Отмена", callback_data="admin_cancel_input")]
    ])
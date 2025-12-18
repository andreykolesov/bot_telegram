from aiogram.utils.keyboard import InlineKeyboardBuilder
from aiogram.types import InlineKeyboardButton, InlineKeyboardMarkup


def get_auth_keyboard():
    b = InlineKeyboardBuilder()
    b.button(text="🔐 Вход", callback_data="login_start")
    b.button(text="📝 Регистрация", callback_data="register_start")
    return b.as_markup()


def get_main_menu_keyboard(is_admin):
    b = InlineKeyboardBuilder()
    b.button(text="📤 Сканировать файл", callback_data="scan_mode")
    b.button(text="📊 Моя статистика", callback_data="my_stats")
    b.button(text="🆘 Тех. поддержка", callback_data="support_ask")

    if is_admin:
        b.button(text="🛠 Админ-панель", callback_data="admin_panel")

    b.button(text="🚪 Выйти", callback_data="logout")
    b.adjust(1)
    return b.as_markup()


def get_admin_keyboard(is_creator):
    b = InlineKeyboardBuilder()

    b.button(text="💾 Бэкап БД", callback_data="do_backup")
    b.button(text="📄 Скачать отчет (CSV)", callback_data="export_csv")
    b.button(text="📨 Вопросы пользователей", callback_data="support_list")

    if is_creator:
        b.button(text="👑 Упр. Админами", callback_data="admin_promote")

    b.button(text="🚫 Блок", callback_data="admin_block")
    b.button(text="✅ Разблок", callback_data="admin_unblock")
    b.button(text="🗑 Удалить юзера", callback_data="admin_delete")
    b.button(text="🔙 Назад в меню", callback_data="back_to_main")

    if is_creator:
        b.adjust(2, 1, 1, 2, 1, 1)
    else:
        b.adjust(2, 1, 2, 1, 1)

    return b.as_markup()


def get_back_keyboard():
    return InlineKeyboardMarkup(inline_keyboard=[[InlineKeyboardButton(text="🔙 Назад", callback_data="back_to_main")]])


def get_cancel_keyboard():
    return InlineKeyboardMarkup(
        inline_keyboard=[[InlineKeyboardButton(text="❌ Отмена", callback_data="admin_cancel_input")]])


def get_cancel_support_keyboard():
    return InlineKeyboardMarkup(
        inline_keyboard=[[InlineKeyboardButton(text="❌ Отмена", callback_data="support_cancel")]])


def get_tickets_list_keyboard(tickets):
    b = InlineKeyboardBuilder()
    for t in tickets:
        b.button(text=f"❓ #{t.id} {t.user.login}", callback_data=f"support_view_{t.id}")
    b.button(text="🔙 Назад в панель", callback_data="admin_panel")
    b.adjust(1)
    return b.as_markup()


def get_ticket_actions_keyboard(tid):
    b = InlineKeyboardBuilder()
    b.button(text="✍️ Ответить", callback_data=f"support_reply_{tid}")
    b.button(text="🔙 К списку", callback_data="support_list")
    return b.as_markup()
from aiogram.fsm.state import State, StatesGroup

class AuthStates(StatesGroup):
    login_enter_login = State()
    login_enter_pass = State()
    reg_enter_login = State()
    reg_enter_pass = State()

class AdminStates(StatesGroup):
    wait_input = State()

class SupportStates(StatesGroup):
    ask_question = State()
    answer_question = State()
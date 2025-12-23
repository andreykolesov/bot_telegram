import datetime
from sqlalchemy.orm import joinedload
from database.models import SupportTicket


def create_ticket(session, user_id, question):
    ticket = SupportTicket(user_id=user_id, question=question, status='open')
    session.add(ticket)
    session.commit()
    return ticket.id


def get_open_tickets(session):
    return session.query(SupportTicket).options(joinedload(SupportTicket.user)).filter_by(status='open').order_by(
        SupportTicket.created_at).all()


def get_ticket_by_id(session, ticket_id):
    return session.query(SupportTicket).options(joinedload(SupportTicket.user)).filter_by(id=ticket_id).first()


def answer_ticket(session, ticket_id, admin_id, answer):
    ticket = session.query(SupportTicket).filter_by(id=ticket_id).first()

    if not ticket:
        return None, "Тикет не найден"

    if ticket.status == 'closed':
        return None, "Уже отвечено"

    ticket.answer = answer
    ticket.answered_by_id = admin_id
    ticket.answered_at = datetime.datetime.now()
    ticket.status = 'closed'

    session.commit()
    return ticket, "Ответ записан"
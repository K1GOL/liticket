# Ticket implementation.

from typing import TypedDict, Optional
import time


class Ticket(TypedDict):
    """
    A representation of a ticket.
    """

    title: str
    description: str
    id: str
    queue: str
    owner: Optional[str]
    created_at: int
    updated_at: int
    status: str
    fields: dict[str, object]
    attachments: Optional[list[str]]


class TicketQueue(TypedDict):
    """
    A representation of a queue.
    """

    id: str
    name: str
    description: Optional[str]
    author: str
    tickets: list[Ticket]


class TicketStatus(TypedDict):
    """
    A representation of a status.
    """

    name: str
    description: Optional[str]
    color: Optional[str]


class User(TypedDict):
    """
    A representation of a user.
    """

    id: str
    username: str
    display_name: str
    is_admin: bool


class TicketField(TypedDict):
    """
    A representation of a custom field type.
    """

    name: str
    description: Optional[str]
    options: Optional[list[str]]
    required: bool

    # if value_type is "enum", options must be provided
    enum: bool



class TicketFieldValue(TypedDict):
    """
    A representation of a value for a custom field.
    """

    value: object
    field: TicketField


class TicketComment(TypedDict):
    """
    A representation of a ticket comment.
    """

    content: str
    created_at: int
    author: User


class TicketAttachment(TypedDict):
    """
    A representation of a ticket attachment.
    """

    id: str
    ticket: str
    name: str
    mime_type: str
    content: bytes

class HistoryChange(TypedDict):
    """
    A representation of a history change.
    """

    field: str
    old_value: str
    new_value: str


class TicketHistory(TypedDict):
    """
    A representation of a ticket's history.
    """

    ticket: str
    id: str
    changes: list[HistoryChange]
    timestamp: int
    author: str


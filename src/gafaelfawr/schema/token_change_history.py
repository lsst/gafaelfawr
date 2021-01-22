"""The token_change_history database table."""

from __future__ import annotations

from sqlalchemy import Column, DateTime, Enum, Index, Integer, String
from sqlalchemy.dialects import postgresql

from gafaelfawr.models.history import TokenChange
from gafaelfawr.models.token import TokenType
from gafaelfawr.schema.base import Base

__all__ = ["TokenChangeHistory"]


class TokenChangeHistory(Base):
    __tablename__ = "token_change_history"

    id = Column(Integer, primary_key=True)
    token = Column(String(64), nullable=False)
    username = Column(String(64), nullable=False)
    token_type = Column(Enum(TokenType), nullable=False)
    token_name = Column(String(64))
    parent = Column(String(64))
    scopes = Column(String(256), nullable=False)
    service = Column(String(64))
    expires = Column(DateTime)
    actor = Column(String(64))
    action = Column(Enum(TokenChange), nullable=False)
    old_token_name = Column(String(64))
    old_scopes = Column(String(256))
    old_expires = Column(DateTime)
    ip_address = Column(String(64).with_variant(postgresql.INET, "postgresql"))
    event_time = Column(DateTime, nullable=False)

    __table_args__ = (
        Index("token_change_history_by_time", "event_time", "id"),
        Index("token_change_history_by_token", "token", "event_time", "id"),
        Index(
            "token_change_history_by_username", "username", "event_time", "id"
        ),
    )

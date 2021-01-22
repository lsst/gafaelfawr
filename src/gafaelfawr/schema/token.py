"""The token database table."""

from __future__ import annotations

from sqlalchemy import Column, DateTime, Enum, Index, String, UniqueConstraint

from gafaelfawr.models.token import TokenType
from gafaelfawr.schema.base import Base

__all__ = ["Token"]


class Token(Base):
    __tablename__ = "token"

    token = Column(String(64), primary_key=True)
    username = Column(String(64), nullable=False)
    token_type = Column(Enum(TokenType), nullable=False)
    token_name = Column(String(64))
    scopes = Column(String(256), nullable=False)
    service = Column(String(64))
    created = Column(DateTime, nullable=False)
    last_used = Column(DateTime)
    expires = Column(DateTime)

    __table_args__ = (
        UniqueConstraint("username", "token_name"),
        Index("token_by_username", "username", "token_type", "service"),
    )

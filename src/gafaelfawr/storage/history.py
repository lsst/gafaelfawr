"""Storage for change and authentication history."""

from __future__ import annotations

from typing import TYPE_CHECKING

from gafaelfawr.schema import AdminHistory, TokenChangeHistory

if TYPE_CHECKING:
    from sqlalchemy.orm import Session

    from gafaelfawr.models.history import (
        AdminHistoryEntry,
        TokenChangeHistoryEntry,
    )

__all__ = ["AdminHistoryStore"]


class AdminHistoryStore:
    """Stores and retrieves the history of changes to token administrators.

    Parameters
    ----------
    session : `sqlalchemy.orm.Session`
        The underlying database session.
    """

    def __init__(self, session: Session) -> None:
        self._session = session

    def add(self, entry: AdminHistoryEntry) -> None:
        """Record a change to the token administrators."""
        new = AdminHistory(**entry.dict())
        self._session.add(new)


class TokenHistoryStore:
    """Stores and retrieves the history of changes to tokens.

    Parameters
    ----------
    session : `sqlalchemy.orm.Session`
        The underlying database session.
    """

    def __init__(self, session: Session) -> None:
        self._session = session

    def add(self, entry: TokenChangeHistoryEntry) -> None:
        """Record a change to a token."""
        entry_dict = entry.dict()

        # Convert the lists of scopes to the empty string for an empty list
        # and a comma-separated string otherwise.
        entry_dict["scopes"] = ",".join(sorted(entry.scopes))
        if entry.old_scopes is not None:
            entry_dict["old_scopes"] = ",".join(sorted(entry.scopes))

        new = TokenChangeHistory(**entry_dict)
        self._session.add(new)

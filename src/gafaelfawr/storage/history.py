"""Storage for change and authentication history."""

from __future__ import annotations

from typing import TYPE_CHECKING

from gafaelfawr.models.history import TokenChangeHistoryEntry
from gafaelfawr.schema import AdminHistory, TokenChangeHistory

if TYPE_CHECKING:
    from typing import List, Optional

    from sqlalchemy.orm import Session

    from gafaelfawr.models.history import AdminHistoryEntry

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
            entry_dict["old_scopes"] = ",".join(sorted(entry.old_scopes))

        new = TokenChangeHistory(**entry_dict)
        self._session.add(new)

    def list(
        self, *, token: str, username: Optional[str] = None
    ) -> List[TokenChangeHistoryEntry]:
        """Return all changes to a specific token.

        Parameters
        ----------
        token : `str`
            The token for which to retrieve history.
        username : `str`, optional
            If given, filter the return values to only tokens for the given
            username.

        Returns
        -------
        entries : List[`gafaelfawr.models.history.TokenChangeHistoryEntry`]
            List of change history entries, which may be empty.
        """
        query = self._session.query(TokenChangeHistory).filter_by(token=token)
        if username:
            query = query.filter_by(username=username)
        query = query.order_by(TokenChangeHistory.event_time)
        return [TokenChangeHistoryEntry.from_orm(e) for e in query.all()]

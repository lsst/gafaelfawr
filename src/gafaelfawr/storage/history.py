"""Storage for change and authentication history."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from sqlalchemy import and_, or_

from gafaelfawr.models.history import (
    HistoryCursor,
    PaginatedHistory,
    TokenChangeHistoryEntry,
)
from gafaelfawr.schema import AdminHistory, TokenChangeHistory
from gafaelfawr.util import normalize_datetime

if TYPE_CHECKING:
    from datetime import datetime
    from typing import Optional

    from sqlalchemy.orm import Session

    from gafaelfawr.models.history import AdminHistoryEntry
    from gafaelfawr.models.token import TokenType

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


class TokenChangeHistoryStore:
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
        self,
        *,
        cursor: Optional[HistoryCursor] = None,
        limit: Optional[int] = None,
        since: Optional[datetime] = None,
        until: Optional[datetime] = None,
        username: Optional[str] = None,
        actor: Optional[str] = None,
        key: Optional[str] = None,
        token: Optional[str] = None,
        token_type: Optional[TokenType] = None,
        ip_or_cidr: Optional[str] = None,
    ) -> PaginatedHistory[TokenChangeHistoryEntry]:
        """Return all changes to a specific token.

        Parameters
        ----------
        cursor : `gafaelfawr.models.history.HistoryCursor`, optional
            A pagination cursor specifying where to start in the results.
        limit : `int`, optional
            Limit the number of returned results.
        since : `datetime.datetime`, optional
            Limit the results to events at or after this time.
        until : `datetime.datetime`, optional
            Limit the results to events before or at this time.
        username : `str`, optional
            Limit the results to tokens owned by this user.
        actor : `str`, optional
            Limit the results to actions performed by this user.
        key : `str`, optional
            Limit the results to this token and any subtokens of this token.
            Note that this will currently pick up direct subtokens but not
            subtokens of subtokens.
        token : `str`, optional
            Limit the results to only this token.
        token_type : `gafaelfawr.models.token.TokenType`, optional
            Limit the results to tokens of this type.
        ip_or_cidr : `str`, optional
            Limit the results to changes made from this IPv4 or IPv6 address
            or CIDR block.

        Returns
        -------
        entries : List[`gafaelfawr.models.history.TokenChangeHistoryEntry`]
            List of change history entries, which may be empty.
        """
        query = self._session.query(TokenChangeHistory)

        if since:
            query = query.filter(TokenChangeHistory.event_time >= since)
        if until:
            query = query.filter(TokenChangeHistory.event_time <= until)
        if username:
            query = query.filter_by(username=username)
        if actor:
            query = query.filter_by(actor=actor)
        if key:
            query = query.filter(
                or_(
                    TokenChangeHistory.token == key,
                    TokenChangeHistory.parent == key,
                )
            )
        if token:
            query = query.filter_by(token=token)
        if token_type:
            query = query.filter_by(token_type=token_type)
        if ip_or_cidr:
            if "/" in ip_or_cidr:
                if self._session.get_bind().name == "postgres":
                    query = query.filter(":cidr >> ip_address").params(
                        cidr=ip_or_cidr
                    )
                else:
                    if ":" in str(ip_or_cidr):
                        network = re.sub("::/[0-9]+$", ":%", ip_or_cidr)
                    else:
                        network = re.sub(r"(\.0)+/[0-9]+$", ".%", ip_or_cidr)
                    query = query.filter(
                        TokenChangeHistory.ip_address.like(network)
                    )
            else:
                query = query.filter_by(ip_address=str(ip_or_cidr))

        if cursor and cursor.previous:
            query = query.order_by(
                TokenChangeHistory.event_time.desc(),
                TokenChangeHistory.id.desc(),
            )
        else:
            query = query.order_by(
                TokenChangeHistory.event_time, TokenChangeHistory.id
            )

        if cursor or limit:
            limited_query = query
            if cursor:
                if cursor.previous:
                    limited_query = limited_query.filter(
                        or_(
                            TokenChangeHistory.event_time < cursor.time,
                            and_(
                                TokenChangeHistory.event_time == cursor.time,
                                TokenChangeHistory.id < cursor.id,
                            ),
                        )
                    )
                else:
                    limited_query = limited_query.filter(
                        or_(
                            TokenChangeHistory.event_time > cursor.time,
                            and_(
                                TokenChangeHistory.event_time == cursor.time,
                                TokenChangeHistory.id >= cursor.id,
                            ),
                        )
                    )
            if limit:
                limited_query = limited_query.limit(limit + 1)
            entries = limited_query.all()
            count = query.count()
        else:
            entries = query.all()
            count = len(entries)

        prev_cursor = None
        next_cursor = None
        if cursor and cursor.previous:
            if limit:
                next_cursor = HistoryCursor(time=cursor.time, id=cursor.id)
                if len(entries) > limit:
                    prev_time = normalize_datetime(
                        entries[limit - 1].event_time
                    )
                    assert prev_time
                    prev_cursor = HistoryCursor(
                        time=prev_time,
                        id=entries[limit - 1].id,
                        previous=True,
                    )
                    entries = entries[:limit]
            entries.reverse()
        elif limit:
            if cursor:
                prev_cursor = HistoryCursor(
                    time=cursor.time, id=cursor.id, previous=True
                )
            if len(entries) > limit:
                next_time = normalize_datetime(entries[limit].event_time)
                assert next_time
                next_cursor = HistoryCursor(
                    time=next_time,
                    id=entries[limit].id,
                )
                entries = entries[:limit]

        return PaginatedHistory[TokenChangeHistoryEntry](
            entries=[TokenChangeHistoryEntry.from_orm(e) for e in entries],
            count=count,
            prev_cursor=prev_cursor,
            next_cursor=next_cursor,
        )

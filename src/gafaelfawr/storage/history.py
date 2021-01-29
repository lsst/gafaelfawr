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

    from sqlalchemy.orm import Query, Session

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
            or CIDR block.  Unless the underlying database is PostgreSQL, the
            CIDR block must be on an octet boundary.

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
            query = self._apply_ip_or_cidr_filter(query, ip_or_cidr)

        # Shunt the complicated case of a paginated query to a separate
        # function to keep the logic more transparent.
        if cursor or limit:
            return self._paginated_query(query, cursor, limit)

        # Perform the query and return the results.
        query = query.order_by(
            TokenChangeHistory.event_time, TokenChangeHistory.id
        )
        entries = query.all()
        return PaginatedHistory[TokenChangeHistoryEntry](
            entries=[TokenChangeHistoryEntry.from_orm(e) for e in entries],
            count=len(entries),
            prev_cursor=None,
            next_cursor=None,
        )

    def _paginated_query(
        self,
        query: Query,
        cursor: Optional[HistoryCursor],
        limit: Optional[int],
    ) -> PaginatedHistory[TokenChangeHistoryEntry]:
        """Run a paginated query (one with a limit or a cursor)."""
        limited_query = query

        # Apply the cursor, if there is one.
        if cursor:
            limited_query = self._apply_cursor(limited_query, cursor)

        # When retrieving a previous set of results using a previous
        # cursor, we have to reverse the sort algorithm so that the cursor
        # boundary can be applied correctly.  We'll then later reverse the
        # result set to return it in proper forward-sorted order.
        if cursor and cursor.previous:
            limited_query = limited_query.order_by(
                TokenChangeHistory.event_time.desc(),
                TokenChangeHistory.id.desc(),
            )
        else:
            limited_query = limited_query.order_by(
                TokenChangeHistory.event_time, TokenChangeHistory.id
            )

        # Grab one more element than the query limit so that we know whether
        # to create a cursor (because there are more elements) and what the
        # cursor value should be (for forward cursors).
        if limit:
            limited_query = limited_query.limit(limit + 1)

        # Execute the query twice, once to get the next bach of results and
        # once to get the count of all entries without pagination.
        entries = limited_query.all()
        count = query.count()

        # Calculate the cursors, remove the extra element we asked for, and
        # reverse the results again if we did a reverse sort because we were
        # using a previous cursor.
        prev_cursor = None
        next_cursor = None
        if cursor and cursor.previous:
            if limit:
                next_cursor = HistoryCursor.invert(cursor)
                if len(entries) > limit:
                    prev_cursor = self._build_prev_cursor(entries[limit - 1])
                    entries = entries[:limit]
            entries.reverse()
        elif limit:
            if cursor:
                prev_cursor = HistoryCursor.invert(cursor)
            if len(entries) > limit:
                next_cursor = self._build_next_cursor(entries[limit])
                entries = entries[:limit]

        # Return the results.
        return PaginatedHistory[TokenChangeHistoryEntry](
            entries=[TokenChangeHistoryEntry.from_orm(e) for e in entries],
            count=count,
            prev_cursor=prev_cursor,
            next_cursor=next_cursor,
        )

    @staticmethod
    def _apply_cursor(query: Query, cursor: HistoryCursor) -> Query:
        """Apply a cursor to a query."""
        if cursor.previous:
            return query.filter(
                or_(
                    TokenChangeHistory.event_time < cursor.time,
                    and_(
                        TokenChangeHistory.event_time == cursor.time,
                        TokenChangeHistory.id < cursor.id,
                    ),
                )
            )
        else:
            return query.filter(
                or_(
                    TokenChangeHistory.event_time > cursor.time,
                    and_(
                        TokenChangeHistory.event_time == cursor.time,
                        TokenChangeHistory.id >= cursor.id,
                    ),
                )
            )

    @staticmethod
    def _build_next_cursor(entry: TokenChangeHistory) -> HistoryCursor:
        """Construct a next cursor for entries >= the given entry."""
        next_time = normalize_datetime(entry.event_time)
        assert next_time
        return HistoryCursor(time=next_time, id=entry.id)

    @staticmethod
    def _build_prev_cursor(entry: TokenChangeHistory) -> HistoryCursor:
        """Construct a prev cursor for entries before the given entry."""
        prev_time = normalize_datetime(entry.event_time)
        assert prev_time
        return HistoryCursor(time=prev_time, id=entry.id, previous=True)

    def _apply_ip_or_cidr_filter(self, query: Query, ip_or_cidr: str) -> Query:
        """Apply an appropriate filter for an IP or CIDR block.

        If the underlying database is not PostgreSQL, which supports native
        CIDR membership queries, cheat and turn the CIDR block into a string
        wildcard.  This will only work for CIDR blocks on class boundaries,
        but the intended supported database is PostgreSQL anyway.
        """
        if "/" in ip_or_cidr:
            if self._session.get_bind().name == "postgres":
                return query.filter(":c >> ip_address").params(c=ip_or_cidr)
            else:
                if ":" in str(ip_or_cidr):
                    net = re.sub("::/[0-9]+$", ":%", ip_or_cidr)
                else:
                    net = re.sub(r"(\.0)+/[0-9]+$", ".%", ip_or_cidr)
                return query.filter(TokenChangeHistory.ip_address.like(net))
        else:
            return query.filter_by(ip_address=str(ip_or_cidr))

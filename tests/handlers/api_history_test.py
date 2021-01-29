"""Tests for paginated retrieval of history."""

from __future__ import annotations

import json
from datetime import timedelta
from ipaddress import ip_address, ip_network
from typing import TYPE_CHECKING
from urllib.parse import urlencode

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from gafaelfawr.dependencies.auth import Authenticate
from gafaelfawr.models.history import TokenChangeHistoryEntry
from gafaelfawr.models.token import AdminTokenRequest, TokenType, TokenUserInfo
from gafaelfawr.schema import TokenChangeHistory
from gafaelfawr.storage.transaction import TransactionManager
from gafaelfawr.util import current_datetime
from tests.support.constants import TEST_HOSTNAME
from tests.support.headers import parse_link

if TYPE_CHECKING:
    from typing import Any, Callable, Dict, List, Optional, Union

    from tests.support.setup import SetupTest


async def build_history(
    setup: SetupTest,
) -> List[TokenChangeHistoryEntry]:
    """Perform a bunch of token manipulations and return the history entries.

    Assume that all token manipulations generate the correct history entries,
    since that's tested in other tests.  The only point of this function is to
    build enough history that we can make interesting paginated queries of it.
    """
    token_service = setup.factory.create_token_service()

    user_info_one = TokenUserInfo(username="one")
    token_one = await token_service.create_session_token(
        user_info_one, scopes=["exec:test", "read:all"], ip_address="192.0.2.3"
    )
    token_data_one = await token_service.get_data(token_one)
    assert token_data_one
    await token_service.get_internal_token(
        token_data_one,
        "foo",
        scopes=["exec:test", "read:all"],
        ip_address="192.0.2.4",
    )
    internal_token_one_bar = await token_service.get_internal_token(
        token_data_one, "bar", scopes=["read:all"], ip_address="192.0.2.3"
    )
    token_data_internal_one_bar = await token_service.get_data(
        internal_token_one_bar
    )
    assert token_data_internal_one_bar
    await token_service.get_internal_token(
        token_data_internal_one_bar, "baz", scopes=[], ip_address="10.10.10.10"
    )
    notebook_token_one = await token_service.get_notebook_token(
        token_data_one, ip_address="198.51.100.5"
    )
    token_data_notebook_one = await token_service.get_data(notebook_token_one)
    assert token_data_notebook_one
    await token_service.get_internal_token(
        token_data_notebook_one,
        "foo",
        scopes=["exec:test"],
        ip_address="10.10.10.20",
    )

    user_info_two = TokenUserInfo(username="two")
    token_two = await token_service.create_session_token(
        user_info_two, scopes=["read:some"], ip_address="192.0.2.20"
    )
    token_data_two = await token_service.get_data(token_two)
    assert token_data_two
    user_token_two = await token_service.create_user_token(
        token_data_two,
        token_data_two.username,
        token_name="some token",
        scopes=["read:some"],
        ip_address="192.0.2.20",
    )
    token_data_user_two = await token_service.get_data(user_token_two)
    assert token_data_user_two
    await token_service.get_internal_token(
        token_data_user_two,
        "foo",
        scopes=["read:some"],
        ip_address="10.10.10.10",
    )
    assert await token_service.modify_token(
        user_token_two.key,
        token_data_user_two,
        token_data_user_two.username,
        ip_address="192.0.2.20",
        token_name="happy token",
    )

    request = AdminTokenRequest(
        username="service",
        token_type=TokenType.service,
        scopes=["admin:token"],
    )
    bootstrap_data = Authenticate._build_bootstrap_token_data()
    service_token = await token_service.create_token_from_admin_request(
        request,
        bootstrap_data,
        ip_address="2001:db8:034a:ea78:4278:4562:6578:9876",
    )
    service_token_data = await token_service.get_data(service_token)
    assert service_token_data
    assert await token_service.modify_token(
        user_token_two.key,
        service_token_data,
        ip_address="2001:db8:034a:ea78:4278:4562:6578:9876",
        scopes=["admin:token", "read:all"],
    )
    assert await token_service.modify_token(
        user_token_two.key,
        service_token_data,
        ip_address="2001:db8:034a:ea78:4278:4562:6578:af42",
        token_name="other name",
        expires=current_datetime() + timedelta(days=30),
        scopes=["read:all"],
    )
    assert await token_service.delete_token(
        token_one.key,
        service_token_data,
        username=token_data_one.username,
        ip_address="2001:db8:034a:ea78:4278:4562:6578:9876",
    )

    # Spread out the timestamps so that we can test date range queries.
    engine = create_engine(setup.config.database_url)
    session = Session(bind=engine)
    entries = session.query(TokenChangeHistory).all()
    event_time = current_datetime() - timedelta(seconds=len(entries) * 5)
    with TransactionManager(session).transaction():
        for entry in entries:
            entry.event_time = event_time
            event_time += timedelta(seconds=5)

    history = token_service.get_change_history(service_token_data)
    assert history.count == 15
    assert len(history.entries) == 15
    return history.entries


def entry_to_dict(entry: TokenChangeHistoryEntry) -> Dict[str, Any]:
    """Convert a history entry to the expected API output."""
    reduced_entry = TokenChangeHistoryEntry(**entry.reduced_dict())
    return json.loads(reduced_entry.json(exclude_unset=True))


async def check_history_request(
    setup: SetupTest,
    query: Dict[str, Union[str, int]],
    history: List[TokenChangeHistoryEntry],
    selector: Callable[[TokenChangeHistoryEntry], bool],
    *,
    username: Optional[str] = None,
) -> None:
    """Run a single request for token history and check the results."""
    encoded = urlencode(query)
    if username:
        url = f"/auth/api/v1/users/{username}/token-change-history?{encoded}"
    else:
        url = f"/auth/api/v1/history/token-changes?{encoded}"
    r = await setup.client.get(url)
    filtered = [entry_to_dict(e) for e in history if selector(e)]
    if username and len(filtered) == 0:
        assert r.status_code == 404
    else:
        assert r.status_code == 200
        assert r.json() == filtered
    assert "Link" not in r.headers
    assert "X-Total-Count" not in r.headers


async def check_pagination(
    setup: SetupTest,
    history: List[TokenChangeHistoryEntry],
    *,
    username: Optional[str] = None,
) -> None:
    """Check paginated return values.

    Step through the paginated queries following the Link URLs and check at
    each point that the prev URL also returns correct data.
    """
    query = urlencode({"limit": 5})

    # First, walk forward with a pagination step of five and check next URLs
    # and previous URLs as we go.
    if username:
        url = f"/auth/api/v1/users/{username}/token-change-history?{query}"
    else:
        url = f"/auth/api/v1/history/token-changes?{query}"
    first_url = url
    prev_data = None
    all_data = []
    for end in range(5, len(history) + 4, 5):
        r = await setup.client.get(url)
        assert r.status_code == 200
        data = r.json()
        assert data == [entry_to_dict(e) for e in history[end - 5 : end]]
        assert r.headers["X-Total-Count"] == str(len(history))

        # Check the Link contents, except for the next URL, which we'll check
        # by using it to retrieve the next data.
        link_data = parse_link(r.headers["Link"])
        assert link_data.first_url == f"https://{TEST_HOSTNAME}{first_url}"
        if end == 5:
            assert not link_data.prev_url
        else:
            assert link_data.prev_url
            r = await setup.client.get(link_data.prev_url)
            assert r.status_code == 200
            assert r.json() == prev_data
            assert r.headers["X-Total-Count"] == str(len(history))
            prev_link_data = parse_link(r.headers["Link"])
            assert prev_link_data.first_url == link_data.first_url
            assert prev_link_data.next_url == url

        # Save the data for previous URL checks.
        prev_data = data
        all_data.extend(data)

        # If we're not done, move to the next URL.
        if end < len(history):
            assert link_data.next_url
            url = link_data.next_url

    # Should be no next URL for the last batch of data.
    assert not link_data.next_url

    # data contains the last batch of data.  Walking backwards using previous
    # URLs, we should be able to reconstruct all of the data and have it
    # match.  This tests the previous URLs generated after following previous
    # URLs.
    backwards_data = data
    while link_data.prev_url:
        r = await setup.client.get(link_data.prev_url)
        assert r.status_code == 200
        assert r.headers["X-Total-Count"] == str(len(history))
        backwards_data = r.json() + backwards_data
        link_data = parse_link(r.headers["Link"])
    assert all_data == backwards_data


@pytest.mark.asyncio
async def test_admin_change_history(setup: SetupTest) -> None:
    token_data = await setup.create_session_token(scopes=["admin:token"])
    await setup.login(token_data.token)
    history = await build_history(setup)

    r = await setup.client.get("/auth/api/v1/history/token-changes")
    assert r.status_code == 200
    assert r.json() == [entry_to_dict(e) for e in history]
    assert "Link" not in r.headers
    assert "X-Total-Count" not in r.headers

    # Check making paginated requests.
    await check_pagination(setup, history)

    # Try a few different types of filtering.
    await check_history_request(
        setup,
        {"username": history[1].username},
        history,
        lambda e: e.username == history[1].username,
    )
    await check_history_request(
        setup,
        {"actor": "<bootstrap>"},
        history,
        lambda e: e.actor == "<bootstrap>",
    )
    token = history[1].token
    await check_history_request(
        setup,
        {"key": token},
        history,
        lambda e: e.token == token or e.parent == token,
    )
    await check_history_request(
        setup,
        {"token_type": "internal"},
        history,
        lambda e: e.token_type == TokenType.internal,
    )
    await check_history_request(
        setup,
        {"token_type": "internal", "key": token},
        history,
        lambda e: (
            e.token_type == TokenType.internal
            and (e.token == token or e.parent == token)
        ),
    )
    await check_history_request(
        setup,
        {"ip_address": "192.0.2.20"},
        history,
        lambda e: e.ip_address == "192.0.2.20",
    )
    cidr_block = ip_network("192.0.2.0/24")
    await check_history_request(
        setup,
        {"ip_address": "192.0.2.0/24"},
        history,
        lambda e: ip_address(e.ip_address) in cidr_block,
    )
    await check_history_request(
        setup,
        {"ip_address": "2001:db8:034a:ea78:4278:4562:6578:9876"},
        history,
        lambda e: e.ip_address == "2001:db8:034a:ea78:4278:4562:6578:9876",
    )
    cidr_block = ip_network("2001:db8::/32")
    await check_history_request(
        setup,
        {"ip_address": "2001:db8::/32"},
        history,
        lambda e: ip_address(e.ip_address) in cidr_block,
    )
    await check_history_request(
        setup,
        {"since": int(history[4].event_time.timestamp())},
        history[4:],
        lambda e: True,
    )
    await check_history_request(
        setup,
        {"until": int(history[6].event_time.timestamp())},
        history[:7],
        lambda e: True,
    )
    await check_history_request(
        setup,
        {
            "since": int(history[3].event_time.timestamp()),
            "until": int(history[7].event_time.timestamp()),
        },
        history[3:8],
        lambda e: True,
    )


@pytest.mark.asyncio
async def test_user_change_history(setup: SetupTest) -> None:
    token_data = await setup.create_session_token(username="one")
    await setup.login(token_data.token)
    history = [e for e in await build_history(setup) if e.username == "one"]

    r = await setup.client.get("/auth/api/v1/users/one/token-change-history")
    assert r.status_code == 200
    assert r.json() == [entry_to_dict(e) for e in history]
    assert "Link" not in r.headers
    assert "X-Total-Count" not in r.headers

    # Check making paginated requests.
    await check_pagination(setup, history, username="one")

    # Try a few different types of filtering.
    token = history[1].token
    await check_history_request(
        setup,
        {"key": token},
        history,
        lambda e: e.token == token or e.parent == token,
        username="one",
    )
    await check_history_request(
        setup,
        {"token_type": "internal"},
        history,
        lambda e: e.token_type == TokenType.internal,
        username="one",
    )
    await check_history_request(
        setup,
        {"token_type": "internal", "key": token},
        history,
        lambda e: (
            e.token_type == TokenType.internal
            and (e.token == token or e.parent == token)
        ),
        username="one",
    )
    await check_history_request(
        setup,
        {"ip_address": "192.0.2.3"},
        history,
        lambda e: e.ip_address == "192.0.2.3",
        username="one",
    )
    await check_history_request(
        setup,
        {"ip_address": "2001:db8:034a:ea78:4278:4562:6578:9876"},
        history,
        lambda e: e.ip_address == "2001:db8:034a:ea78:4278:4562:6578:9876",
        username="one",
    )
    cidr_block = ip_network("192.0.2.0/24")
    await check_history_request(
        setup,
        {"ip_address": "192.0.2.0/24"},
        history,
        lambda e: ip_address(e.ip_address) in cidr_block,
        username="one",
    )
    await check_history_request(
        setup,
        {"since": int(history[2].event_time.timestamp())},
        history[2:],
        lambda e: True,
        username="one",
    )
    await check_history_request(
        setup,
        {"until": int(history[3].event_time.timestamp())},
        history[:4],
        lambda e: True,
        username="one",
    )
    await check_history_request(
        setup,
        {
            "since": int(history[3].event_time.timestamp()),
            "until": int(history[4].event_time.timestamp()),
        },
        history[3:5],
        lambda e: True,
        username="one",
    )

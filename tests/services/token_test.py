"""Tests for the token service class."""

from __future__ import annotations

import json
from datetime import timedelta
from typing import TYPE_CHECKING

import pytest
from cryptography.fernet import Fernet
from pydantic import ValidationError

from gafaelfawr.exceptions import (
    BadExpiresError,
    BadScopesError,
    PermissionDeniedError,
)
from gafaelfawr.models.history import TokenChange, TokenChangeHistoryEntry
from gafaelfawr.models.token import (
    AdminTokenRequest,
    Token,
    TokenData,
    TokenGroup,
    TokenInfo,
    TokenType,
    TokenUserInfo,
)
from gafaelfawr.util import current_datetime
from tests.support.util import assert_is_now

if TYPE_CHECKING:
    from tests.support.setup import SetupTest


@pytest.mark.asyncio
async def test_session_token(setup: SetupTest) -> None:
    token_service = setup.factory.create_token_service()
    user_info = TokenUserInfo(
        username="example",
        name="Example Person",
        uid=4137,
        groups=[
            TokenGroup(name="group", id=1000),
            TokenGroup(name="another", id=3134),
        ],
    )

    token = await token_service.create_session_token(
        user_info, scopes=[], ip_address="127.0.0.1"
    )
    data = await token_service.get_data(token)
    assert data and data == TokenData(
        token=token,
        username="example",
        token_type=TokenType.session,
        scopes=[],
        created=data.created,
        expires=data.expires,
        name="Example Person",
        uid=4137,
        groups=[
            TokenGroup(name="group", id=1000),
            TokenGroup(name="another", id=3134),
        ],
    )
    assert_is_now(data.created)
    expires = data.created + timedelta(minutes=setup.config.issuer.exp_minutes)
    assert data.expires == expires

    assert token_service.get_token_info_unchecked(token.key) == TokenInfo(
        token=token.key,
        username=user_info.username,
        token_name=None,
        token_type=TokenType.session,
        scopes=data.scopes,
        created=int(data.created.timestamp()),
        last_used=None,
        expires=int(data.expires.timestamp()),
        parent=None,
    )
    assert await token_service.get_user_info(token) == user_info

    assert token_service.change_history(token.key, data) == [
        TokenChangeHistoryEntry(
            token=token.key,
            username=data.username,
            token_type=TokenType.session,
            scopes=[],
            expires=data.expires,
            actor=data.username,
            action=TokenChange.create,
            ip_address="127.0.0.1",
            event_type=data.created,
        )
    ]

    # Test a session token with scopes.
    token = await token_service.create_session_token(
        user_info, scopes=["read:all", "exec:admin"], ip_address="127.0.0.1"
    )
    data = await token_service.get_data(token)
    assert data and data.scopes == ["exec:admin", "read:all"]
    info = token_service.get_token_info_unchecked(token.key)
    assert info and info.scopes == ["exec:admin", "read:all"]


@pytest.mark.asyncio
async def test_user_token(setup: SetupTest) -> None:
    user_info = TokenUserInfo(
        username="example", name="Example Person", uid=4137
    )
    token_service = setup.factory.create_token_service()
    session_token = await token_service.create_session_token(
        user_info, scopes=["read:all", "exec:admin"], ip_address="127.0.0.1"
    )
    data = await token_service.get_data(session_token)
    assert data
    expires = current_datetime() + timedelta(days=2)

    # Scopes are provided not in sorted order to ensure they're sorted when
    # creating the token.
    user_token = await token_service.create_user_token(
        data,
        "example",
        token_name="some-token",
        scopes=["read:all", "exec:admin"],
        expires=expires,
        ip_address="192.168.0.1",
    )
    assert await token_service.get_user_info(user_token) == user_info
    info = token_service.get_token_info_unchecked(user_token.key)
    assert info and info == TokenInfo(
        token=user_token.key,
        username=user_info.username,
        token_name="some-token",
        token_type=TokenType.user,
        scopes=["exec:admin", "read:all"],
        created=info.created,
        last_used=None,
        expires=int(expires.timestamp()),
        parent=None,
    )
    assert_is_now(info.created)
    assert await token_service.get_data(user_token) == TokenData(
        token=user_token,
        username=user_info.username,
        token_type=TokenType.user,
        scopes=["exec:admin", "read:all"],
        created=info.created,
        expires=info.expires,
        name=user_info.name,
        uid=user_info.uid,
    )

    assert token_service.change_history(user_token.key, data) == [
        TokenChangeHistoryEntry(
            token=user_token.key,
            username=data.username,
            token_type=TokenType.user,
            token_name="some-token",
            scopes=["exec:admin", "read:all"],
            expires=info.expires,
            actor=data.username,
            action=TokenChange.create,
            ip_address="192.168.0.1",
            event_type=info.created,
        )
    ]


@pytest.mark.asyncio
async def test_notebook_token(setup: SetupTest) -> None:
    user_info = TokenUserInfo(
        username="example",
        name="Example Person",
        uid=4137,
        groups=[TokenGroup(name="foo", id=1000)],
    )
    token_service = setup.factory.create_token_service()
    session_token = await token_service.create_session_token(
        user_info, scopes=["read:all", "exec:admin"], ip_address="127.0.0.1"
    )
    data = await token_service.get_data(session_token)
    assert data

    token = await token_service.get_notebook_token(data, ip_address="1.0.0.1")
    assert await token_service.get_user_info(token) == user_info
    info = token_service.get_token_info_unchecked(token.key)
    assert info and info == TokenInfo(
        token=token.key,
        username=user_info.username,
        token_type=TokenType.notebook,
        scopes=["exec:admin", "read:all"],
        created=info.created,
        last_used=None,
        expires=data.expires,
        parent=session_token.key,
    )
    assert_is_now(info.created)
    assert await token_service.get_data(token) == TokenData(
        token=token,
        username=user_info.username,
        token_type=TokenType.notebook,
        scopes=["exec:admin", "read:all"],
        created=info.created,
        expires=data.expires,
        name=user_info.name,
        uid=user_info.uid,
        groups=user_info.groups,
    )

    # Creating another notebook token from the same parent token just returns
    # the same notebook token as before.
    new_token = await token_service.get_notebook_token(
        data, ip_address="127.0.0.1"
    )
    assert token == new_token

    assert token_service.change_history(token.key, data) == [
        TokenChangeHistoryEntry(
            token=token.key,
            username=data.username,
            token_type=TokenType.notebook,
            parent=data.token.key,
            scopes=["exec:admin", "read:all"],
            expires=data.expires,
            actor=data.username,
            action=TokenChange.create,
            ip_address="1.0.0.1",
            event_type=info.created,
        )
    ]

    # Check that the expiration time is capped by creating a user token that
    # doesn't expire and then creating a notebook token from it.
    user_token = await token_service.create_user_token(
        data,
        data.username,
        token_name="some token",
        scopes=[],
        expires=None,
        ip_address="127.0.0.1",
    )
    data = await token_service.get_data(user_token)
    assert data
    new_token = await token_service.get_notebook_token(
        data, ip_address="127.0.0.1"
    )
    assert new_token != token
    info = token_service.get_token_info_unchecked(new_token.key)
    assert info
    expires = info.created + timedelta(minutes=setup.config.issuer.exp_minutes)
    assert info.expires == expires


@pytest.mark.asyncio
async def test_internal_token(setup: SetupTest) -> None:
    user_info = TokenUserInfo(
        username="example",
        name="Example Person",
        uid=4137,
        groups=[TokenGroup(name="foo", id=1000)],
    )
    token_service = setup.factory.create_token_service()
    session_token = await token_service.create_session_token(
        user_info, scopes=["read:all", "exec:admin"], ip_address="127.0.0.1"
    )
    data = await token_service.get_data(session_token)
    assert data

    internal_token = await token_service.get_internal_token(
        data,
        service="some-service",
        scopes=["read:all"],
        ip_address="2001:db8::45",
    )
    assert await token_service.get_user_info(internal_token) == user_info
    info = token_service.get_token_info_unchecked(internal_token.key)
    assert info and info == TokenInfo(
        token=internal_token.key,
        username=user_info.username,
        token_type=TokenType.internal,
        service="some-service",
        scopes=["read:all"],
        created=info.created,
        last_used=None,
        expires=data.expires,
        parent=session_token.key,
    )
    assert_is_now(info.created)

    # Cannot request a scope that the parent token doesn't have.
    with pytest.raises(BadScopesError):
        await token_service.get_internal_token(
            data,
            service="some-service",
            scopes=["read:some"],
            ip_address="127.0.0.1",
        )

    # Creating another internal token from the same parent token with the same
    # parameters just returns the same internal token as before.
    new_internal_token = await token_service.get_internal_token(
        data,
        service="some-service",
        scopes=["read:all"],
        ip_address="127.0.0.1",
    )
    assert internal_token == new_internal_token

    assert token_service.change_history(internal_token.key, data) == [
        TokenChangeHistoryEntry(
            token=internal_token.key,
            username=data.username,
            token_type=TokenType.internal,
            parent=data.token.key,
            service="some-service",
            scopes=["read:all"],
            expires=data.expires,
            actor=data.username,
            action=TokenChange.create,
            ip_address="2001:db8::45",
            event_type=info.created,
        )
    ]

    # A different scope or a different service results in a new token.
    new_internal_token = await token_service.get_internal_token(
        data,
        service="some-service",
        scopes=["exec:admin"],
        ip_address="127.0.0.1",
    )
    assert internal_token != new_internal_token
    new_internal_token = await token_service.get_internal_token(
        data,
        service="another-service",
        scopes=["read:all"],
        ip_address="127.0.0.1",
    )
    assert internal_token != new_internal_token

    # Check that the expiration time is capped by creating a user token that
    # doesn't expire and then creating a notebook token from it.  Use this to
    # test a token with empty scopes.
    user_token = await token_service.create_user_token(
        data,
        data.username,
        token_name="some token",
        scopes=["exec:admin"],
        expires=None,
        ip_address="127.0.0.1",
    )
    data = await token_service.get_data(user_token)
    assert data
    new_internal_token = await token_service.get_internal_token(
        data, service="some-service", scopes=[], ip_address="127.0.0.1"
    )
    assert new_internal_token != internal_token
    info = token_service.get_token_info_unchecked(new_internal_token.key)
    assert info and info.scopes == []
    expires = info.created + timedelta(minutes=setup.config.issuer.exp_minutes)
    assert info.expires == expires


@pytest.mark.asyncio
async def test_token_from_admin_request(setup: SetupTest) -> None:
    user_info = TokenUserInfo(
        username="example", name="Example Person", uid=4137
    )
    token_service = setup.factory.create_token_service()
    token = await token_service.create_session_token(
        user_info, scopes=[], ip_address="127.0.0.1"
    )
    data = await token_service.get_data(token)
    assert data
    expires = current_datetime() + timedelta(days=2)
    request = AdminTokenRequest(
        username="otheruser",
        token_type=TokenType.user,
        token_name="some token",
        scopes=["read:all"],
        expires=expires,
        name="Other User",
        uid=1345,
        groups=[TokenGroup(name="some-group", id=4133)],
    )

    # Cannot create a token via admin request because the authentication
    # information is missing the admin:token scope.
    with pytest.raises(PermissionDeniedError):
        await token_service.create_token_from_admin_request(
            request, data, ip_address="127.0.0.1"
        )

    # Get a token with an appropriate scope.
    session_token = await token_service.create_session_token(
        user_info, scopes=["admin:token"], ip_address="127.0.0.1"
    )
    admin_data = await token_service.get_data(session_token)
    assert admin_data

    # Test a few more errors.
    request.scopes = ["bogus:scope"]
    with pytest.raises(BadScopesError):
        await token_service.create_token_from_admin_request(
            request, admin_data, ip_address="127.0.0.1"
        )
    request.scopes = ["read:all"]
    request.expires = current_datetime()
    with pytest.raises(BadExpiresError):
        await token_service.create_token_from_admin_request(
            request, admin_data, ip_address="127.0.0.1"
        )
    request.expires = expires

    # Try a successful request.
    token = await token_service.create_token_from_admin_request(
        request, admin_data, ip_address="127.0.0.1"
    )
    user_data = await token_service.get_data(token)
    assert user_data and user_data == TokenData(
        token=token, created=user_data.created, **request.dict()
    )
    assert_is_now(user_data.created)

    assert token_service.change_history(token.key, admin_data) == [
        TokenChangeHistoryEntry(
            token=token.key,
            username=request.username,
            token_type=TokenType.user,
            token_name=request.token_name,
            scopes=["read:all"],
            expires=request.expires,
            actor=admin_data.username,
            action=TokenChange.create,
            ip_address="127.0.0.1",
            event_type=user_data.created,
        )
    ]

    # Non-admins can't see other people's tokens.
    assert token_service.change_history(token.key, data) == []

    # Now request a service token with minimal data instead.
    request = AdminTokenRequest(
        username="service", token_type=TokenType.service
    )
    token = await token_service.create_token_from_admin_request(
        request, admin_data, ip_address="127.0.0.1"
    )
    service_data = await token_service.get_data(token)
    assert service_data and service_data == TokenData(
        token=token, created=service_data.created, **request.dict()
    )
    assert_is_now(service_data.created)

    assert token_service.change_history(token.key, admin_data) == [
        TokenChangeHistoryEntry(
            token=token.key,
            username=request.username,
            token_type=TokenType.service,
            scopes=[],
            expires=None,
            actor=admin_data.username,
            action=TokenChange.create,
            ip_address="127.0.0.1",
            event_type=service_data.created,
        )
    ]


@pytest.mark.asyncio
async def test_list(setup: SetupTest) -> None:
    user_info = TokenUserInfo(
        username="example", name="Example Person", uid=4137
    )
    token_service = setup.factory.create_token_service()
    session_token = await token_service.create_session_token(
        user_info, scopes=[], ip_address="127.0.0.1"
    )
    data = await token_service.get_data(session_token)
    assert data
    user_token = await token_service.create_user_token(
        data,
        data.username,
        token_name="some-token",
        scopes=[],
        ip_address="127.0.0.1",
    )
    other_user_info = TokenUserInfo(
        username="other", name="Other Person", uid=1313
    )
    other_session_token = await token_service.create_session_token(
        other_user_info, scopes=["admin:token"], ip_address="1.1.1.1"
    )
    admin_data = await token_service.get_data(other_session_token)
    assert admin_data

    session_info = token_service.get_token_info_unchecked(session_token.key)
    assert session_info
    user_token_info = token_service.get_token_info_unchecked(user_token.key)
    assert user_token_info
    other_session_info = token_service.get_token_info_unchecked(
        other_session_token.key
    )
    assert other_session_info
    assert token_service.list_tokens(data, "example") == sorted(
        (session_info, user_token_info), key=lambda t: t.token
    )
    assert token_service.list_tokens(admin_data) == sorted(
        (session_info, other_session_info, user_token_info),
        key=lambda t: t.token,
    )

    # Regular users can't retrieve all tokens.
    with pytest.raises(PermissionDeniedError):
        token_service.list_tokens(data)


@pytest.mark.asyncio
async def test_modify(setup: SetupTest) -> None:
    user_info = TokenUserInfo(
        username="example", name="Example Person", uid=4137
    )
    token_service = setup.factory.create_token_service()
    session_token = await token_service.create_session_token(
        user_info, scopes=["read:all"], ip_address="127.0.0.1"
    )
    data = await token_service.get_data(session_token)
    assert data
    user_token = await token_service.create_user_token(
        data,
        data.username,
        token_name="some-token",
        scopes=[],
        ip_address="127.0.0.1",
    )

    expires = current_datetime() + timedelta(days=50)
    await token_service.modify_token(
        user_token.key, data, token_name="happy token", ip_address="127.0.0.1"
    )
    await token_service.modify_token(
        user_token.key,
        data,
        scopes=["read:all"],
        expires=expires,
        ip_address="192.168.0.4",
    )
    info = token_service.get_token_info_unchecked(user_token.key)
    assert info and info == TokenInfo(
        token=user_token.key,
        username="example",
        token_type=TokenType.user,
        token_name="happy token",
        scopes=["read:all"],
        created=info.created,
        expires=expires,
        last_used=None,
        parent=None,
    )
    await token_service.modify_token(
        user_token.key,
        data,
        expires=None,
        no_expire=True,
        ip_address="127.0.4.5",
    )

    history = token_service.change_history(user_token.key, data)
    assert history == [
        TokenChangeHistoryEntry(
            token=user_token.key,
            username=data.username,
            token_type=TokenType.user,
            token_name="some-token",
            scopes=[],
            expires=None,
            actor=data.username,
            action=TokenChange.create,
            ip_address="127.0.0.1",
            event_time=info.created,
        ),
        TokenChangeHistoryEntry(
            token=user_token.key,
            username=data.username,
            token_type=TokenType.user,
            token_name="happy token",
            scopes=[],
            expires=None,
            actor=data.username,
            action=TokenChange.edit,
            old_token_name="some-token",
            ip_address="127.0.0.1",
            event_time=history[1].event_time,
        ),
        TokenChangeHistoryEntry(
            token=user_token.key,
            username=data.username,
            token_type=TokenType.user,
            token_name="happy token",
            scopes=["read:all"],
            expires=expires,
            actor=data.username,
            action=TokenChange.edit,
            old_scopes=[],
            old_expires=None,
            ip_address="192.168.0.4",
            event_time=history[2].event_time,
        ),
        TokenChangeHistoryEntry(
            token=user_token.key,
            username=data.username,
            token_type=TokenType.user,
            token_name="happy token",
            scopes=["read:all"],
            expires=None,
            actor=data.username,
            action=TokenChange.edit,
            old_expires=expires,
            ip_address="127.0.4.5",
            event_time=history[3].event_time,
        ),
    ]


@pytest.mark.asyncio
async def test_delete(setup: SetupTest) -> None:
    data = await setup.create_session_token()
    token_service = setup.factory.create_token_service()
    token = await token_service.create_user_token(
        data,
        data.username,
        token_name="some token",
        scopes=[],
        ip_address="127.0.0.1",
    )

    assert await token_service.delete_token(
        token.key, data, data.username, ip_address="127.0.0.1"
    )

    assert await token_service.get_data(token) is None
    assert token_service.get_token_info_unchecked(token.key) is None
    assert await token_service.get_user_info(token) is None

    assert not await token_service.delete_token(
        token.key, data, data.username, ip_address="127.0.0.1"
    )

    history = token_service.change_history(token.key, data)
    assert history == [
        TokenChangeHistoryEntry(
            token=token.key,
            username=data.username,
            token_type=TokenType.user,
            token_name="some token",
            scopes=[],
            expires=None,
            actor=data.username,
            action=TokenChange.create,
            ip_address="127.0.0.1",
            event_time=history[0].event_time,
        ),
        TokenChangeHistoryEntry(
            token=token.key,
            username=data.username,
            token_type=TokenType.user,
            token_name="some token",
            scopes=[],
            expires=None,
            actor=data.username,
            action=TokenChange.revoke,
            ip_address="127.0.0.1",
            event_time=history[1].event_time,
        ),
    ]

    # Cannot delete someone else's token.
    token = await token_service.create_user_token(
        data,
        data.username,
        token_name="some token",
        scopes=[],
        ip_address="127.0.0.1",
    )
    other_data = await setup.create_session_token(username="other")
    with pytest.raises(PermissionDeniedError):
        await token_service.delete_token(
            token.key, other_data, data.username, ip_address="127.0.0.1"
        )

    # Admins can delete soemone else's token.
    admin_data = await setup.create_session_token(
        username="admin", scopes=["admin:token"]
    )
    assert await token_service.get_data(token)
    assert await token_service.delete_token(
        token.key, admin_data, data.username, ip_address="127.0.0.1"
    )
    assert await token_service.get_data(token) is None


@pytest.mark.asyncio
async def test_invalid(setup: SetupTest) -> None:
    token_service = setup.factory.create_token_service()
    expires = timedelta(days=1).total_seconds()

    # No such key.
    token = Token()
    assert await token_service.get_data(token) is None

    # Invalid encrypted blob.
    await setup.redis.set(f"token:{token.key}", "foo", expire=expires)
    assert await token_service.get_data(token) is None

    # Malformed session.
    fernet = Fernet(setup.config.session_secret.encode())
    raw_data = fernet.encrypt(b"malformed json")
    await setup.redis.set(f"token:{token.key}", raw_data, expire=expires)
    assert await token_service.get_data(token) is None

    # Mismatched token.
    data = TokenData(
        token=Token(),
        username="example",
        token_type=TokenType.session,
        scopes=[],
        created=int(current_datetime().timestamp()),
        name="Some User",
        uid=12345,
    )
    session = fernet.encrypt(data.json().encode())
    await setup.redis.set(f"token:{token.key}", session, expire=expires)
    assert await token_service.get_data(token) is None

    # Missing required fields.
    json_data = {
        "token": {
            "key": token.key,
            "secret": token.secret,
        },
        "token_type": "session",
        "scopes": [],
        "created": int(current_datetime().timestamp()),
        "name": "Some User",
    }
    raw_data = fernet.encrypt(json.dumps(json_data).encode())
    await setup.redis.set(f"token:{token.key}", raw_data, expire=expires)
    assert await token_service.get_data(token) is None

    # Fix the session store and confirm we can retrieve the manually-stored
    # session.
    json_data["username"] = "example"
    raw_data = fernet.encrypt(json.dumps(json_data).encode())
    await setup.redis.set(f"token:{token.key}", raw_data, expire=expires)
    new_data = await token_service.get_data(token)
    assert new_data == TokenData.parse_obj(json_data)


@pytest.mark.asyncio
async def test_invalid_username(setup: SetupTest) -> None:
    user_info = TokenUserInfo(
        username="example",
        name="Example Person",
        uid=4137,
        groups=[TokenGroup(name="foo", id=1000)],
    )
    token_service = setup.factory.create_token_service()
    session_token = await token_service.create_session_token(
        user_info, scopes=["read:all", "admin:token"], ip_address="127.0.0.1"
    )
    data = await token_service.get_data(session_token)
    assert data

    # Cannot create any type of token with an invalid name.
    for user in (
        "<bootstrap>",
        "in+valid",
        " invalid",
        "invalid ",
        "in/valid",
        "in@valid",
    ):
        user_info.username = user
        with pytest.raises(PermissionDeniedError):
            await token_service.create_session_token(
                user_info, scopes=[], ip_address="127.0.0.1"
            )
        data.username = user
        with pytest.raises(PermissionDeniedError):
            await token_service.create_user_token(
                data, user, token_name="n", scopes=[], ip_address="127.0.0.1"
            )
        with pytest.raises(PermissionDeniedError):
            await token_service.get_notebook_token(
                data, ip_address="127.0.0.1"
            )
        with pytest.raises(PermissionDeniedError):
            await token_service.get_internal_token(
                data, service="s", scopes=[], ip_address="127.0.0.1"
            )
        with pytest.raises(ValidationError):
            AdminTokenRequest(username=user, token_type=TokenType.service)
        request = AdminTokenRequest(
            username="valid", token_type=TokenType.service
        )
        request.username = user
        with pytest.raises(PermissionDeniedError):
            await token_service.create_token_from_admin_request(
                request, data, ip_address="127.0.0.1"
            )

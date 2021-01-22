"""Tests for the token service class."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING

import pytest
from cryptography.fernet import Fernet
from pydantic import ValidationError

from gafaelfawr.exceptions import (
    BadExpiresError,
    BadScopesError,
    PermissionDeniedError,
)
from gafaelfawr.models.token import (
    AdminTokenRequest,
    Token,
    TokenData,
    TokenGroup,
    TokenInfo,
    TokenType,
    TokenUserInfo,
)

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
    assert data
    assert data == TokenData(
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
    now = datetime.now(tz=timezone.utc)
    assert now - timedelta(seconds=2) <= data.created <= now
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

    # Test a session token with scopes.
    token = await token_service.create_session_token(
        user_info, scopes=["read:all", "exec:admin"], ip_address="127.0.0.1"
    )
    data = await token_service.get_data(token)
    assert data
    assert data.scopes == ["exec:admin", "read:all"]
    info = token_service.get_token_info_unchecked(token.key)
    assert info
    assert info.scopes == ["exec:admin", "read:all"]

    # Cannot create a session token with a username of <bootstrap>.
    user_info.username = "<bootstrap>"
    with pytest.raises(PermissionDeniedError):
        await token_service.create_session_token(
            user_info, scopes=[], ip_address="127.0.0.1"
        )


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
    now = datetime.now(tz=timezone.utc).replace(microsecond=0)
    expires = now + timedelta(days=2)

    # Scopes are provided not in sorted order to ensure they're sorted when
    # creating the token.
    user_token = await token_service.create_user_token(
        data,
        "example",
        token_name="some-token",
        scopes=["read:all", "exec:admin"],
        expires=expires,
        ip_address="127.0.0.1",
    )
    assert await token_service.get_user_info(user_token) == user_info
    info = token_service.get_token_info_unchecked(user_token.key)
    assert info
    assert info == TokenInfo(
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
    assert now - timedelta(seconds=2) <= info.created <= now
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

    # Cannot create a user token with a username of <bootstrap>.
    data.username = "<bootstrap>"
    with pytest.raises(PermissionDeniedError):
        await token_service.create_user_token(
            data,
            "<bootstrap>",
            scopes=[],
            token_name="bootstrap-token",
            ip_address="127.0.0.1",
        )


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
    now = datetime.now(tz=timezone.utc).replace(microsecond=0)

    notebook_token = await token_service.get_notebook_token(
        data, ip_address="127.0.0.1"
    )
    assert await token_service.get_user_info(notebook_token) == user_info
    info = token_service.get_token_info_unchecked(notebook_token.key)
    assert info
    assert info == TokenInfo(
        token=notebook_token.key,
        username=user_info.username,
        token_type=TokenType.notebook,
        scopes=["exec:admin", "read:all"],
        created=info.created,
        last_used=None,
        expires=data.expires,
        parent=session_token.key,
    )
    assert now - timedelta(seconds=2) <= info.created <= now
    assert await token_service.get_data(notebook_token) == TokenData(
        token=notebook_token,
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
    new_notebook_token = await token_service.get_notebook_token(
        data, ip_address="127.0.0.1"
    )
    assert notebook_token == new_notebook_token

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
    new_notebook_token = await token_service.get_notebook_token(
        data, ip_address="127.0.0.1"
    )
    assert new_notebook_token != notebook_token
    info = token_service.get_token_info_unchecked(new_notebook_token.key)
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
        ip_address="127.0.0.1",
    )
    assert await token_service.get_user_info(internal_token) == user_info
    info = token_service.get_token_info_unchecked(internal_token.key)
    assert info
    assert info == TokenInfo(
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

    # Cannot request a scope that the parent token doesn't have.
    with pytest.raises(BadScopesError):
        await token_service.get_internal_token(
            data,
            service="some-service",
            scopes=["other:scope"],
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

    # A different scope or a different service results in a new token.
    new_internal_token = await token_service.get_internal_token(
        data, service="some-service", scopes=[], ip_address="127.0.0.1"
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
    assert info
    assert info.scopes == []
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
    now = datetime.now(tz=timezone.utc).replace(microsecond=0)
    expires = now + timedelta(days=2)
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
    data = await token_service.get_data(session_token)
    assert data

    # Test a few more errors.
    request.username = "<bootstrap>"
    with pytest.raises(PermissionDeniedError):
        await token_service.create_token_from_admin_request(
            request, data, ip_address="127.0.0.1"
        )
    request.username = "otheruser"
    request.scopes = ["bogus:scope"]
    with pytest.raises(BadScopesError):
        await token_service.create_token_from_admin_request(
            request, data, ip_address="127.0.0.1"
        )
    request.scopes = ["read:all"]
    request.expires = now
    with pytest.raises(BadExpiresError):
        await token_service.create_token_from_admin_request(
            request, data, ip_address="127.0.0.1"
        )
    request.expires = expires

    # Try a successful request.
    token = await token_service.create_token_from_admin_request(
        request, data, ip_address="127.0.0.1"
    )
    user_data = await token_service.get_data(token)
    assert user_data
    assert user_data == TokenData(
        token=token, created=user_data.created, **request.dict()
    )
    assert now <= user_data.created <= now + timedelta(seconds=5)

    # Now request a service token with minimal data instead.
    request = AdminTokenRequest(
        username="service", token_type=TokenType.service
    )
    token = await token_service.create_token_from_admin_request(
        request, data, ip_address="127.0.0.1"
    )
    service_data = await token_service.get_data(token)
    assert service_data
    assert service_data == TokenData(
        token=token, created=service_data.created, **request.dict()
    )
    assert now <= service_data.created <= now + timedelta(seconds=5)


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

    session_info = token_service.get_token_info_unchecked(session_token.key)
    assert session_info
    user_token_info = token_service.get_token_info_unchecked(user_token.key)
    assert user_token_info
    assert token_service.list_tokens(data, "example") == sorted(
        (session_info, user_token_info), key=lambda t: t.token
    )


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

    now = datetime.now(tz=timezone.utc).replace(microsecond=0)
    expires = now + timedelta(days=50)
    await token_service.modify_token(
        user_token.key, data, token_name="happy token", ip_address="127.0.0.1"
    )
    await token_service.modify_token(
        user_token.key,
        data,
        scopes=["read:all"],
        expires=expires,
        ip_address="127.0.0.1",
    )
    info = token_service.get_token_info_unchecked(user_token.key)
    assert info
    assert info == TokenInfo(
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
        created=int(datetime.now(tz=timezone.utc).timestamp()),
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
        "created": int(datetime.now(tz=timezone.utc).timestamp()),
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
        user_info, scopes=["read:all", "exec:admin"], ip_address="127.0.0.1"
    )
    data = await token_service.get_data(session_token)
    assert data

    # Cannot create a session token with an invalid username.
    for user in ("in+valid", " invalid", "invalid ", "in/valid", "in@valid"):
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

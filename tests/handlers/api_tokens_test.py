"""Tests for the ``/auth/api/v1/users/*/tokens`` and related routes."""

from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING
from unittest.mock import ANY

import pytest

from gafaelfawr.constants import COOKIE_NAME
from gafaelfawr.models.state import State
from gafaelfawr.models.token import Token, TokenGroup, TokenUserInfo
from gafaelfawr.util import current_datetime
from tests.support.constants import TEST_HOSTNAME

if TYPE_CHECKING:
    from tests.support.setup import SetupTest


@pytest.mark.asyncio
async def test_create_delete_modify(setup: SetupTest) -> None:
    user_info = TokenUserInfo(
        username="example",
        name="Example Person",
        uid=45613,
        groups=[TokenGroup(name="foo", id=12313)],
    )
    token_service = setup.factory.create_token_service()
    session_token = await token_service.create_session_token(
        user_info, scopes=["read:all", "exec:admin"], ip_address="127.0.0.1"
    )
    csrf = await setup.login(session_token)

    expires = current_datetime() + timedelta(days=100)
    r = await setup.client.post(
        "/auth/api/v1/users/example/tokens",
        headers={"X-CSRF-Token": csrf},
        json={
            "token_name": "some token",
            "scopes": ["read:all"],
            "expires": int(expires.timestamp()),
        },
    )
    assert r.status_code == 201
    assert r.json() == {"token": ANY}
    user_token = Token.from_str(r.json()["token"])
    token_url = r.headers["Location"]
    assert token_url == f"/auth/api/v1/users/example/tokens/{user_token.key}"

    r = await setup.client.get(token_url)
    assert r.status_code == 200
    info = r.json()
    assert info == {
        "token": user_token.key,
        "username": "example",
        "token_name": "some token",
        "token_type": "user",
        "scopes": ["read:all"],
        "created": ANY,
        "expires": int(expires.timestamp()),
    }

    # Check that this is the same information as is returned by the token-info
    # route.  This is a bit tricky to do since the cookie will take precedence
    # over the Authorization header, but we can't just delete the cookie since
    # we'll lose the CSRF token.  Save the cookie and delete it, and then
    # later restore it.
    cookie = setup.client.cookies.pop(COOKIE_NAME)
    r = await setup.client.get(
        "/auth/api/v1/token-info",
        headers={"Authorization": f"bearer {user_token}"},
    )
    assert r.status_code == 200
    assert r.json() == info
    setup.client.cookies.set(COOKIE_NAME, cookie, domain=TEST_HOSTNAME)

    # Listing all tokens for this user should return the user token and a
    # session token.
    r = await setup.client.get("/auth/api/v1/users/example/tokens")
    assert r.status_code == 200
    assert r.json() == sorted(
        [
            {
                "token": session_token.key,
                "username": "example",
                "token_type": "session",
                "scopes": ["exec:admin", "read:all"],
                "created": ANY,
                "expires": ANY,
            },
            info,
        ],
        key=lambda t: t["token"],
    )

    # Change the name, scope, and expiration of the token.
    new_expires = current_datetime() + timedelta(days=200)
    r = await setup.client.patch(
        token_url,
        headers={"X-CSRF-Token": csrf},
        json={
            "token_name": "happy token",
            "scopes": ["exec:admin"],
            "expires": int(new_expires.timestamp()),
        },
    )
    assert r.status_code == 201
    assert r.json() == {
        "token": user_token.key,
        "username": "example",
        "token_name": "happy token",
        "token_type": "user",
        "scopes": ["exec:admin"],
        "created": ANY,
        "expires": int(new_expires.timestamp()),
    }

    # Delete the token.
    r = await setup.client.delete(token_url, headers={"X-CSRF-Token": csrf})
    assert r.status_code == 204
    r = await setup.client.get(token_url)
    assert r.status_code == 404

    # Deleting again should return 404.
    r = await setup.client.delete(token_url, headers={"X-CSRF-Token": csrf})
    assert r.status_code == 404

    # This user should now have only one token.
    r = await setup.client.get("/auth/api/v1/users/example/tokens")
    assert r.status_code == 200
    assert len(r.json()) == 1

    # We should be able to see the change history for the token.
    r = await setup.client.get(token_url + "/change-history")
    assert r.status_code == 200
    assert r.json() == [
        {
            "token": user_token.key,
            "username": "example",
            "token_type": "user",
            "token_name": "some token",
            "scopes": ["read:all"],
            "expires": int(expires.timestamp()),
            "actor": "example",
            "action": "create",
            "ip_address": "127.0.0.1",
            "event_time": ANY,
        },
        {
            "token": user_token.key,
            "username": "example",
            "token_type": "user",
            "token_name": "happy token",
            "scopes": ["exec:admin"],
            "expires": int(new_expires.timestamp()),
            "actor": "example",
            "action": "edit",
            "old_token_name": "some token",
            "old_scopes": ["read:all"],
            "old_expires": int(expires.timestamp()),
            "ip_address": "127.0.0.1",
            "event_time": ANY,
        },
        {
            "token": user_token.key,
            "username": "example",
            "token_type": "user",
            "token_name": "happy token",
            "scopes": ["exec:admin"],
            "expires": int(new_expires.timestamp()),
            "actor": "example",
            "action": "revoke",
            "ip_address": "127.0.0.1",
            "event_time": ANY,
        },
    ]


@pytest.mark.asyncio
async def test_token_info(setup: SetupTest) -> None:
    user_info = TokenUserInfo(
        username="example",
        name="Example Person",
        uid=45613,
        groups=[TokenGroup(name="foo", id=12313)],
    )
    token_service = setup.factory.create_token_service()
    session_token = await token_service.create_session_token(
        user_info, scopes=["exec:admin"], ip_address="127.0.0.1"
    )

    r = await setup.client.get(
        "/auth/api/v1/token-info",
        headers={"Authorization": f"bearer {session_token}"},
    )
    assert r.status_code == 200
    data = r.json()
    assert data == {
        "token": session_token.key,
        "username": "example",
        "token_type": "session",
        "scopes": ["exec:admin"],
        "created": ANY,
        "expires": ANY,
    }
    now = datetime.now(tz=timezone.utc)
    created = datetime.fromtimestamp(data["created"], tz=timezone.utc)
    assert now - timedelta(seconds=2) <= created <= now
    expires = created + timedelta(minutes=setup.config.issuer.exp_minutes)
    assert datetime.fromtimestamp(data["expires"], tz=timezone.utc) == expires

    r = await setup.client.get(
        "/auth/api/v1/user-info",
        headers={"Authorization": f"bearer {session_token}"},
    )
    assert r.status_code == 200
    session_user_info = r.json()
    assert session_user_info == {
        "username": "example",
        "name": "Example Person",
        "uid": 45613,
        "groups": [
            {
                "name": "foo",
                "id": 12313,
            }
        ],
    }

    # Check the same with a user token, which has some additional associated
    # data.
    expires = now + timedelta(days=100)
    data = await token_service.get_data(session_token)
    user_token = await token_service.create_user_token(
        data,
        data.username,
        token_name="some-token",
        scopes=["exec:admin"],
        expires=expires,
        ip_address="127.0.0.1",
    )

    r = await setup.client.get(
        "/auth/api/v1/token-info",
        headers={"Authorization": f"bearer {user_token}"},
    )
    assert r.status_code == 200
    data = r.json()
    assert data == {
        "token": user_token.key,
        "username": "example",
        "token_type": "user",
        "token_name": "some-token",
        "scopes": ["exec:admin"],
        "created": ANY,
        "expires": int(expires.timestamp()),
    }

    r = await setup.client.get(
        "/auth/api/v1/user-info",
        headers={"Authorization": f"bearer {user_token}"},
    )
    assert r.status_code == 200
    assert r.json() == session_user_info

    # Test getting a list of tokens for a user.
    state = State(token=session_token)
    r = await setup.client.get(
        "/auth/api/v1/users/example/tokens",
        cookies={COOKIE_NAME: state.as_cookie()},
    )


@pytest.mark.asyncio
async def test_auth_required(setup: SetupTest) -> None:
    token_data = await setup.create_session_token()
    token = token_data.token
    csrf = await setup.login(token)

    # Replace the cookie with one containing the CSRF token but not the
    # authentication token.
    setup.logout()
    setup.client.cookies[COOKIE_NAME] = State(csrf=csrf).as_cookie()

    r = await setup.client.post(
        "/auth/api/v1/tokens",
        headers={"X-CSRF-Token": csrf},
        json={"username": "foo", "token_type": "service"},
    )
    assert r.status_code == 401

    r = await setup.client.get("/auth/api/v1/users/example/tokens")
    assert r.status_code == 401

    r = await setup.client.get(
        "/auth/api/v1/users/example/tokens",
        headers={"Authorization": f"bearer {token}"},
    )
    assert r.status_code == 401

    r = await setup.client.post(
        "/auth/api/v1/users/example/tokens",
        headers={"X-CSRF-Token": csrf},
        json={"token_name": "some token"},
    )
    assert r.status_code == 401

    r = await setup.client.get(
        f"/auth/api/v1/users/example/tokens/{token.key}"
    )
    assert r.status_code == 401

    r = await setup.client.get(
        f"/auth/api/v1/users/example/tokens/{token.key}/change-history"
    )
    assert r.status_code == 401

    r = await setup.client.delete(
        f"/auth/api/v1/users/example/tokens/{token.key}",
        headers={"X-CSRF-Token": csrf},
    )
    assert r.status_code == 401

    r = await setup.client.patch(
        f"/auth/api/v1/users/example/tokens/{token.key}",
        headers={"X-CSRF-Token": csrf},
        json={"token_name": "some token"},
    )
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_csrf_required(setup: SetupTest) -> None:
    token_data = await setup.create_session_token(scopes=["admin:token"])
    csrf = await setup.login(token_data.token)
    token_service = setup.factory.create_token_service()
    user_token = await token_service.create_user_token(
        token_data,
        token_data.username,
        token_name="foo",
        scopes=[],
        ip_address="127.0.0.1",
    )

    r = await setup.client.post(
        "/auth/api/v1/tokens",
        json={"username": "foo", "token_type": "service"},
    )
    assert r.status_code == 403
    r = await setup.client.post(
        "/auth/api/v1/tokens",
        headers={"X-CSRF-Token": f"XXX{csrf}"},
        json={"username": "foo", "token_type": "service"},
    )
    assert r.status_code == 403

    r = await setup.client.post(
        "/auth/api/v1/users/example/tokens", json={"token_name": "some token"}
    )
    assert r.status_code == 403

    r = await setup.client.post(
        "/auth/api/v1/users/example/tokens",
        headers={"X-CSRF-Token": f"XXX{csrf}"},
        json={"token_name": "some token"},
    )
    assert r.status_code == 403

    r = await setup.client.delete(
        f"/auth/api/v1/users/example/tokens/{user_token.key}"
    )
    assert r.status_code == 403

    r = await setup.client.delete(
        f"/auth/api/v1/users/example/tokens/{user_token.key}",
        headers={"X-CSRF-Token": f"XXX{csrf}"},
    )
    assert r.status_code == 403

    r = await setup.client.patch(
        f"/auth/api/v1/users/example/tokens/{user_token.key}",
        json={"token_name": "some token"},
    )
    assert r.status_code == 403

    r = await setup.client.patch(
        f"/auth/api/v1/users/example/tokens/{user_token.key}",
        headers={"X-CSRF-Token": f"XXX{csrf}"},
        json={"token_name": "some token"},
    )
    assert r.status_code == 403


@pytest.mark.asyncio
async def test_no_bootstrap(setup: SetupTest) -> None:
    token_data = await setup.create_session_token()
    token = token_data.token
    bootstrap_token = str(setup.config.bootstrap_token)

    r = await setup.client.get(
        "/auth/api/v1/users/example/tokens",
        headers={"Authorization": f"bearer {bootstrap_token}"},
    )
    assert r.status_code == 401

    r = await setup.client.post(
        "/auth/api/v1/users/example/tokens",
        headers={"Authorization": f"bearer {bootstrap_token}"},
        json={"token_name": "some token"},
    )
    assert r.status_code == 401

    r = await setup.client.get(
        f"/auth/api/v1/users/example/tokens/{token.key}",
        headers={"Authorization": f"bearer {bootstrap_token}"},
    )
    assert r.status_code == 401

    r = await setup.client.delete(
        f"/auth/api/v1/users/example/tokens/{token.key}",
        headers={"Authorization": f"bearer {bootstrap_token}"},
    )
    assert r.status_code == 401

    r = await setup.client.patch(
        f"/auth/api/v1/users/example/tokens/{token.key}",
        headers={"Authorization": f"bearer {bootstrap_token}"},
        json={"token_name": "some token"},
    )
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_modify_nonuser(setup: SetupTest) -> None:
    token_data = await setup.create_session_token()
    token = token_data.token
    csrf = await setup.login(token)

    r = await setup.client.patch(
        f"/auth/api/v1/users/{token_data.username}/tokens/{token.key}",
        headers={"X-CSRF-Token": csrf},
        json={"token_name": "happy token"},
    )
    assert r.status_code == 403
    assert r.json()["detail"]["type"] == "permission_denied"


@pytest.mark.asyncio
async def test_wrong_user(setup: SetupTest) -> None:
    token_data = await setup.create_session_token()
    csrf = await setup.login(token_data.token)
    token_service = setup.factory.create_token_service()
    user_info = TokenUserInfo(
        username="other-person", name="Some Other Person", uid=137123
    )
    other_session_token = await token_service.create_session_token(
        user_info, scopes=[], ip_address="127.0.0.1"
    )
    other_session_data = await token_service.get_data(other_session_token)
    assert other_session_data
    other_token = await token_service.create_user_token(
        other_session_data,
        "other-person",
        token_name="foo",
        scopes=[],
        ip_address="127.0.0.1",
    )

    # Get a token list.
    r = await setup.client.get("/auth/api/v1/users/other-person/tokens")
    assert r.status_code == 403
    assert r.json()["detail"]["type"] == "permission_denied"

    # Create a new user token.
    r = await setup.client.post(
        "/auth/api/v1/users/other-person/tokens",
        headers={"X-CSRF-Token": csrf},
        json={"token_name": "happy token"},
    )
    assert r.status_code == 403
    assert r.json()["detail"]["type"] == "permission_denied"

    # Get an individual token.
    r = await setup.client.get(
        f"/auth/api/v1/users/other-person/tokens/{other_token.key}"
    )
    assert r.status_code == 403
    assert r.json()["detail"]["type"] == "permission_denied"

    # Get the history of an individual token.
    r = await setup.client.get(
        f"/auth/api/v1/users/other-person/tokens/{other_token.key}"
        "/change-history"
    )
    assert r.status_code == 403
    assert r.json()["detail"]["type"] == "permission_denied"

    # Ensure you can't see someone else's token under your username either.
    r = await setup.client.get(
        f"/auth/api/v1/users/{token_data.username}/tokens/{other_token.key}"
    )
    assert r.status_code == 404

    # Or their history.
    r = await setup.client.get(
        f"/auth/api/v1/users/{token_data.username}/tokens/{other_token.key}"
        "/change-history"
    )
    assert r.status_code == 404

    # Delete a token.
    r = await setup.client.delete(
        f"/auth/api/v1/users/other-person/tokens/{other_token.key}",
        headers={"X-CSRF-Token": csrf},
    )
    assert r.status_code == 403
    assert r.json()["detail"]["type"] == "permission_denied"
    r = await setup.client.delete(
        f"/auth/api/v1/users/{token_data.username}/tokens/{other_token.key}",
        headers={"X-CSRF-Token": csrf},
    )
    assert r.status_code == 404

    # Modify a token.
    r = await setup.client.patch(
        f"/auth/api/v1/users/other-person/tokens/{other_token.key}",
        json={"token_name": "happy token"},
        headers={"X-CSRF-Token": csrf},
    )
    assert r.status_code == 403
    assert r.json()["detail"]["type"] == "permission_denied"
    r = await setup.client.patch(
        f"/auth/api/v1/users/{token_data.username}/tokens/{other_token.key}",
        json={"token_name": "happy token"},
        headers={"X-CSRF-Token": csrf},
    )
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_no_expires(setup: SetupTest) -> None:
    """Test creating a user token that doesn't expire."""
    token_data = await setup.create_session_token()
    csrf = await setup.login(token_data.token)

    r = await setup.client.post(
        f"/auth/api/v1/users/{token_data.username}/tokens",
        headers={"X-CSRF-Token": csrf},
        json={"token_name": "some token"},
    )
    assert r.status_code == 201
    token_url = r.headers["Location"]

    r = await setup.client.get(token_url)
    assert "expires" not in r.json()

    # Create a user token with an expiration and then adjust it to not expire.
    now = datetime.now(tz=timezone.utc).replace(microsecond=0)
    expires = now + timedelta(days=2)
    r = await setup.client.post(
        f"/auth/api/v1/users/{token_data.username}/tokens",
        headers={"X-CSRF-Token": csrf},
        json={
            "token_name": "another token",
            "expires": int(expires.timestamp()),
        },
    )
    assert r.status_code == 201
    user_token = Token.from_str(r.json()["token"])
    token_service = setup.factory.create_token_service()
    user_token_data = await token_service.get_data(user_token)
    assert user_token_data and user_token_data.expires == expires
    token_url = r.headers["Location"]

    r = await setup.client.get(token_url)
    assert r.json()["expires"] == int(expires.timestamp())

    r = await setup.client.patch(
        token_url,
        headers={"X-CSRF-Token": csrf},
        json={"expires": None},
    )
    assert r.status_code == 201
    assert "expires" not in r.json()

    # Check that the expiration was also changed in Redis.
    token_service = setup.factory.create_token_service()
    user_token_data = await token_service.get_data(user_token)
    assert user_token_data and user_token_data.expires is None


@pytest.mark.asyncio
async def test_duplicate_token_name(setup: SetupTest) -> None:
    """Test duplicate token names."""
    token_data = await setup.create_session_token()
    csrf = await setup.login(token_data.token)

    r = await setup.client.post(
        f"/auth/api/v1/users/{token_data.username}/tokens",
        headers={"X-CSRF-Token": csrf},
        json={"token_name": "some token"},
    )
    assert r.status_code == 201
    r = await setup.client.post(
        f"/auth/api/v1/users/{token_data.username}/tokens",
        headers={"X-CSRF-Token": csrf},
        json={"token_name": "some token"},
    )
    assert r.status_code == 422
    assert r.json()["detail"]["type"] == "duplicate_token_name"

    # Create a token with a different name and then try to modify the name to
    # conflict.
    r = await setup.client.post(
        f"/auth/api/v1/users/{token_data.username}/tokens",
        headers={"X-CSRF-Token": csrf},
        json={"token_name": "another token"},
    )
    assert r.status_code == 201
    token_url = r.headers["Location"]
    r = await setup.client.patch(
        token_url,
        headers={"X-CSRF-Token": csrf},
        json={"token_name": "some token"},
    )
    assert r.status_code == 422
    assert r.json()["detail"]["type"] == "duplicate_token_name"


@pytest.mark.asyncio
async def test_bad_expires(setup: SetupTest) -> None:
    """Test creating or modifying a token with bogus expirations."""
    token_data = await setup.create_session_token()
    csrf = await setup.login(token_data.token)

    now = int(time.time())
    bad_expires = [-now, -1, 0, now, now + (5 * 60) - 1]
    for bad_expire in bad_expires:
        r = await setup.client.post(
            f"/auth/api/v1/users/{token_data.username}/tokens",
            headers={"X-CSRF-Token": csrf},
            json={"token_name": "some token", "expires": bad_expire},
        )
        assert r.status_code == 422
        data = r.json()
        assert data["detail"]["loc"] == ["body", "expires"]
        assert data["detail"]["type"] == "bad_expires"

    # Create a valid token.
    r = await setup.client.post(
        f"/auth/api/v1/users/{token_data.username}/tokens",
        headers={"X-CSRF-Token": csrf},
        json={"token_name": "some token"},
    )
    assert r.status_code == 201
    token_url = r.headers["Location"]

    # Now try modifying the expiration time to the same bogus values.
    for bad_expire in bad_expires:
        r = await setup.client.patch(
            token_url,
            headers={"X-CSRF-Token": csrf},
            json={"expires": bad_expire},
        )
        assert r.status_code == 422
        data = r.json()
        assert data["detail"]["loc"] == ["body", "expires"]
        assert data["detail"]["type"] == "bad_expires"


@pytest.mark.asyncio
async def test_bad_scopes(setup: SetupTest) -> None:
    """Test creating or modifying a token with bogus scopes."""
    known_scopes = list(setup.config.known_scopes.keys())
    assert len(known_scopes) > 4
    token_data = await setup.create_session_token(
        scopes=known_scopes[1:3] + ["other:scope"]
    )
    csrf = await setup.login(token_data.token)

    # Check that we reject both an unknown scope and a scope that's present on
    # the session but isn't valid in the configuration.
    for bad_scope in (known_scopes[3], "other:scope"):
        r = await setup.client.post(
            f"/auth/api/v1/users/{token_data.username}/tokens",
            headers={"X-CSRF-Token": csrf},
            json={"token_name": "some token", "scopes": [bad_scope]},
        )
        assert r.status_code == 422
        data = r.json()
        assert data["detail"]["loc"] == ["body", "scopes"]
        assert data["detail"]["type"] == "bad_scopes"

    # Create a valid token with all of the scopes as the session.
    r = await setup.client.post(
        f"/auth/api/v1/users/{token_data.username}/tokens",
        headers={"X-CSRF-Token": csrf},
        json={"token_name": "some token", "scopes": known_scopes[1:3]},
    )
    assert r.status_code == 201
    token_url = r.headers["Location"]

    # Now try modifying it with the invalid scope.
    for bad_scope in (known_scopes[3], "other:scope"):
        r = await setup.client.patch(
            token_url,
            headers={"X-CSRF-Token": csrf},
            json={"scopes": [known_scopes[1], bad_scope]},
        )
        assert r.status_code == 422
        data = r.json()
        assert data["detail"]["loc"] == ["body", "scopes"]
        assert data["detail"]["type"] == "bad_scopes"


@pytest.mark.asyncio
async def test_create_admin(setup: SetupTest) -> None:
    """Test creating a token through the admin interface."""
    token_data = await setup.create_session_token(scopes=["exec:admin"])
    csrf = await setup.login(token_data.token)

    r = await setup.client.post(
        "/auth/api/v1/tokens",
        headers={"X-CSRF-Token": csrf},
        json={"username": "a-service", "token_type": "service"},
    )
    assert r.status_code == 403

    token_data = await setup.create_session_token(scopes=["admin:token"])
    csrf = await setup.login(token_data.token)

    now = datetime.now(tz=timezone.utc)
    expires = int((now + timedelta(days=2)).timestamp())
    r = await setup.client.post(
        "/auth/api/v1/tokens",
        headers={"X-CSRF-Token": csrf},
        json={
            "username": "a-service",
            "token_type": "service",
            "scopes": ["admin:token"],
            "expires": expires,
            "name": "A Service",
            "uid": 1234,
            "groups": [{"name": "some-group", "id": 12381}],
        },
    )
    assert r.status_code == 201
    assert r.json() == {"token": ANY}
    service_token = Token.from_str(r.json()["token"])
    token_url = f"/auth/api/v1/users/a-service/tokens/{service_token.key}"
    assert r.headers["Location"] == token_url

    setup.logout()
    r = await setup.client.get(
        "/auth/api/v1/token-info",
        headers={"Authorization": f"bearer {str(service_token)}"},
    )
    assert r.status_code == 200
    assert r.json() == {
        "token": service_token.key,
        "username": "a-service",
        "token_type": "service",
        "scopes": ["admin:token"],
        "created": ANY,
        "expires": expires,
    }
    r = await setup.client.get(
        "/auth/api/v1/user-info",
        headers={"Authorization": f"bearer {str(service_token)}"},
    )
    assert r.status_code == 200
    assert r.json() == {
        "username": "a-service",
        "name": "A Service",
        "uid": 1234,
        "groups": [{"name": "some-group", "id": 12381}],
    }

    r = await setup.client.post(
        "/auth/api/v1/tokens",
        headers={"Authorization": f"bearer {str(service_token)}"},
        json={"username": "a-user", "token_type": "session"},
    )
    assert r.status_code == 422
    r = await setup.client.post(
        "/auth/api/v1/tokens",
        headers={"Authorization": f"bearer {str(service_token)}"},
        json={"username": "a-user", "token_type": "user"},
    )
    assert r.status_code == 422
    r = await setup.client.post(
        "/auth/api/v1/tokens",
        headers={"Authorization": f"bearer {str(service_token)}"},
        json={
            "username": "a-user",
            "token_type": "user",
            "token_name": "some token",
            "expires": int(datetime.now(tz=timezone.utc).timestamp()),
        },
    )
    assert r.status_code == 422
    assert r.json()["detail"]["type"] == "bad_expires"
    r = await setup.client.post(
        "/auth/api/v1/tokens",
        headers={"Authorization": f"bearer {str(service_token)}"},
        json={
            "username": "a-user",
            "token_type": "user",
            "token_name": "some token",
            "scopes": ["bogus:scope"],
        },
    )
    assert r.status_code == 422
    assert r.json()["detail"]["type"] == "bad_scopes"

    r = await setup.client.post(
        "/auth/api/v1/tokens",
        headers={"Authorization": f"bearer {str(service_token)}"},
        json={
            "username": "a-user",
            "token_type": "user",
            "token_name": "some token",
        },
    )
    assert r.status_code == 201
    assert r.json() == {"token": ANY}
    user_token = Token.from_str(r.json()["token"])
    token_url = f"/auth/api/v1/users/a-user/tokens/{user_token.key}"
    assert r.headers["Location"] == token_url

    # Successfully create a user token.
    r = await setup.client.get(
        "/auth/api/v1/token-info",
        headers={"Authorization": f"bearer {str(user_token)}"},
    )
    assert r.status_code == 200
    assert r.json() == {
        "token": user_token.key,
        "username": "a-user",
        "token_type": "user",
        "token_name": "some token",
        "scopes": [],
        "created": ANY,
    }
    r = await setup.client.get(
        "/auth/api/v1/user-info",
        headers={"Authorization": f"bearer {str(user_token)}"},
    )
    assert r.status_code == 200
    assert r.json() == {"username": "a-user"}

    # Check handling of duplicate token name errors.
    r = await setup.client.post(
        "/auth/api/v1/tokens",
        headers={"Authorization": f"bearer {str(service_token)}"},
        json={
            "username": "a-user",
            "token_type": "user",
            "token_name": "some token",
        },
    )
    assert r.status_code == 422
    assert r.json()["detail"]["type"] == "duplicate_token_name"

    # Check handling of an invalid username.
    r = await setup.client.post(
        "/auth/api/v1/tokens",
        headers={"Authorization": f"bearer {str(service_token)}"},
        json={
            "username": "invalid(user)",
            "token_type": "user",
            "token_name": "some token",
        },
    )
    assert r.status_code == 422

    # Check that the bootstrap token also works.
    r = await setup.client.post(
        "/auth/api/v1/tokens",
        headers={
            "Authorization": f"bearer {str(setup.config.bootstrap_token)}"
        },
        json={"username": "other-service", "token_type": "service"},
    )
    assert r.status_code == 201

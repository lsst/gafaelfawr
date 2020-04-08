"""Initial authentication handlers (``/login``)."""

from __future__ import annotations

import base64
import logging
import os
from typing import TYPE_CHECKING

from aiohttp import ClientResponseError, web
from aiohttp_session import get_session, new_session

from jwt_authorizer.handlers import routes
from jwt_authorizer.providers import GitHubException

if TYPE_CHECKING:
    from jwt_authorizer.config import Config
    from jwt_authorizer.factory import ComponentFactory


@routes.get("/login", name="login")
async def get_login(request: web.Request) -> web.Response:
    """Handle an initial login.

    Constructs the authentication URL and redirects the user to the
    authentication provider.

    Parameters
    ----------
    request : `aiohttp.web.Request`
        Incoming request.

    Returns
    -------
    response : `aiohttp.web.Response`
        The response.

    Raises
    ------
    NotImplementedError
        If no authentication provider is configured.

    Notes
    -----
    This generates new authentication state each time the user goes to the
    /login handler.  In practice, JavaScript may kick off multiple
    authentication attempts at the same time, which can cause a successful
    authentication to be rejected if another request has overridden the state.
    The state should be reused for some interval.
    """
    config: Config = request.config_dict["jwt_authorizer/config"]
    factory: ComponentFactory = request.config_dict["jwt_authorizer/factory"]

    if not config.github:
        raise NotImplementedError("GitHub provider not configured")
    auth_provider = factory.create_github_provider(request)

    if "code" in request.query:
        session = await get_session(request)
        code = request.query["code"]
        state = request.query["state"]
        if request.query["state"] != session.pop("state", None):
            msg = "OAuth state mismatch"
            raise web.HTTPForbidden(reason=msg, text=msg)
        return_url = session.pop("rd")

        try:
            github_token = await auth_provider.get_access_token(code, state)
            user_info = await auth_provider.get_user_info(github_token)
        except GitHubException as e:
            logging.error("GitHub authentication failed: %s", str(e))
            raise web.HTTPInternalServerError(reason=str(e), text=str(e))
        except ClientResponseError:
            msg = "Cannot contact GitHub"
            logging.exception(msg)
            raise web.HTTPInternalServerError(reason=msg, text=msg)

        issuer = factory.create_token_issuer()
        ticket = await issuer.issue_token_from_github(user_info)

        ticket_prefix = config.session_store.ticket_prefix
        session = await new_session(request)
        session["ticket"] = ticket.encode(ticket_prefix)

        raise web.HTTPSeeOther(return_url)
    else:
        session = await new_session(request)
        request_url = request.query.get("rd")
        if not request_url:
            request_url = request.headers.get("X-Auth-Request-Redirect")
        if not request_url:
            msg = "No destination URL specified"
            raise web.HTTPBadRequest(reason=msg, text=msg)
        state = base64.urlsafe_b64encode(os.urandom(16)).decode()
        session["rd"] = request_url
        session["state"] = state
        redirect_url = auth_provider.get_redirect_url(state)
        raise web.HTTPSeeOther(redirect_url)

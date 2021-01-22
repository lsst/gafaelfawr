"""Initial authentication handlers (``/login``)."""

from __future__ import annotations

import base64
import os
from typing import TYPE_CHECKING, Optional

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import RedirectResponse
from httpx import HTTPError

from gafaelfawr.dependencies.context import RequestContext, context_dependency
from gafaelfawr.dependencies.return_url import return_url_with_header
from gafaelfawr.exceptions import ProviderException

if TYPE_CHECKING:
    from typing import List, Set

    from gafaelfawr.config import Config
    from gafaelfawr.models.token import TokenGroup

router = APIRouter()

__all__ = ["get_login"]


@router.get("/login")
@router.get("/oauth2/callback")
async def get_login(
    code: Optional[str] = None,
    state: Optional[str] = None,
    return_url: Optional[str] = Depends(return_url_with_header),
    context: RequestContext = Depends(context_dependency),
) -> RedirectResponse:
    """Handle an initial login or the return from a login provider.

    Notes
    -----
    Also export the login handler at ``/oauth2/callback``, the route used by
    oauth2_proxy, for compatibility with older oauth2_proxy installations.
    This avoids needing to change the redirect_uri registered with an OpenID
    Connect provider.  It can be removed once all registrations have been
    updated with the ``/login`` route.
    """
    if code:
        return await handle_provider_return(code, state, context)
    else:
        return await redirect_to_provider(return_url, context)


async def redirect_to_provider(
    return_url: Optional[str], context: RequestContext
) -> RedirectResponse:
    """Redirect the user to an external authentication provider.

    Handles the initial processing and redirect to an external provider,
    storing necessary state in the user's session cookie.

    Parameters
    ----------
    return_url : `str`, optional
        The return URL to which to send the user after authentication.
    context : `gafaelfawr.dependencies.config.RequestContext`
        The context of the incoming request.

    Returns
    -------
    response : `fastapi.RedirectResponse`
        A redirect to the authentication provider.

    Raises
    ------
    fastapi.HTTPException
        The authentication request is invalid.
    """
    if not return_url:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "loc": ["query", "rd"],
                "type": "return_url_missing",
                "msg": "No return URL given",
            },
        )
    context.state.return_url = return_url

    # Reuse the existing state if one already exists in the session cookie.
    #
    # This is subtle and requires some explanation.  Most modern webapps
    # involve a lot of background JavaScript.  If the user has a tab open when
    # their session expires, those background JavaScript requests will start
    # turning into redirects to Gafaelfawr and thus to this code.  Since there
    # isn't a good way to see whether a request is a background JavaScript
    # request versus a browser loading a page, we will generate an
    # authentication redirect for each one.
    #
    # This means that if we generate new random state for each request, there
    # is a race condition.  The user may go to a page with an expired session
    # and get redirected to log in.  While they are logging in at the external
    # provider, another open tab may kick off one of these JavaScript
    # requests, which generates a new redirect and replaces the state stored
    # in their session cookie.  Then, when they return from authentication,
    # the state will have changed, and the authentication attempt will fail.
    #
    # Work around this by reusing the same random state until the user
    # completes an authentication.  This does not entirely close the window
    # for the race condition because it's possible that two requests will both
    # see sessions without state, both generate state, and then both set
    # cookies, and only one of them will win.  However, that race condition
    # window is much smaller and is unlikely to persist across authentication
    # requests.
    state = context.state.state
    if not state:
        state = base64.urlsafe_b64encode(os.urandom(16)).decode()
        context.state.state = state

    # Get the authentication provider URL send the user there.
    auth_provider = context.factory.create_provider()
    redirect_url = auth_provider.get_redirect_url(state)
    return RedirectResponse(redirect_url)


async def handle_provider_return(
    code: str, state: Optional[str], context: RequestContext
) -> RedirectResponse:
    """Handle the return from an external authentication provider.

    Handles the target of the redirect back from an external authentication
    provider with new authentication state information.

    Parameters
    ----------
    code : `str`
        The authentication code from the provider.
    state : `str`, optional
        The opaque state used to verify that this user initiated the
        authentication.  This can be `None`, but that will always be an
        error.
    context : `gafaelfawr.dependencies.config.RequestContext`
        The context of the incoming request.

    Returns
    -------
    response : `fastapi.RedirectResponse`
        A redirect to the resource the user was trying to reach before
        authentication.

    Raises
    ------
    fastapi.HTTPException
        The authentication request is invalid or retrieving authentication
        information from the provider failed.
    """
    if not state:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "loc": ["query", "state"],
                "type": "state_mismatch",
                "msg": "No authentication state",
            },
        )

    # Extract details from the reply, check state, and get the return URL.
    if state != context.state.state:
        msg = "Authentication state mismatch"
        context.logger.warning("Authentication failed", error=msg)
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "loc": ["query", "state"],
                "msg": "Authentication state mismatch",
                "type": "state_mismatch",
            },
        )
    return_url = context.state.return_url
    if not return_url:
        msg = "Invalid authentication state: return_url not present in cookie"
        context.logger.error("Authentication failed", error=msg)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"msg": msg, "type": "return_url_not_set"},
        )
    context.rebind_logger(return_url=return_url)

    # Retrieve the user identity and authorization information based on the
    # reply from the authentication provider.
    auth_provider = context.factory.create_provider()
    try:
        user_info = await auth_provider.create_user_info(code, state)
    except ProviderException as e:
        context.logger.warning("Provider authentication failed", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"type": "provider_failed", "msg": str(e)},
        )
    except HTTPError as e:
        msg = "Cannot contact authentication provider"
        context.logger.exception(msg, error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={
                "type": "provider_connect_failed",
                "msg": f"{msg}: {str(e)}",
            },
        )

    # Construct a token.
    scopes = get_scopes_from_groups(context.config, user_info.groups)
    admin_service = context.factory.create_admin_service()
    if admin_service.is_admin(user_info.username):
        scopes = sorted(scopes + ["admin:token"])
    token_service = context.factory.create_token_service()
    token = await token_service.create_session_token(
        user_info, scopes, ip_address=context.request.client.host
    )
    context.state.token = token

    # Successful login, so clear the login state and send the user back to
    # what they were doing.
    context.state.state = None
    context.state.return_url = None
    context.logger.info(
        "Successfully authenticated user %s (%s)",
        user_info.username,
        user_info.uid,
        user=user_info.username,
        token=token.key,
        scope=" ".join(scopes),
    )
    return RedirectResponse(return_url)


def get_scopes_from_groups(
    config: Config, groups: Optional[List[TokenGroup]]
) -> List[str]:
    """Get scopes from a list of groups.

    Used to determine the scope claim of a token issued based on an OpenID
    Connect authentication.

    Parameters
    ----------
    groups : List[`gafaelfawr.models.token.TokenGroup`]
        The groups of a token.

    Returns
    -------
    scopes : List[`str`]
        The scopes generated from the group membership based on the
        ``group_mapping`` configuration parameter.
    """
    if not groups:
        return []
    scopes: Set[str] = set()
    for group in [g.name for g in groups]:
        scopes.update(config.issuer.group_mapping.get(group, set()))
    return sorted(scopes)

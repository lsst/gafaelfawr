"""Handler for authentication and authorization checking (``/auth``)."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Dict, List, Optional, Set

from fastapi import (
    APIRouter,
    Depends,
    Header,
    HTTPException,
    Query,
    Response,
    status,
)

from gafaelfawr.auth import (
    AuthError,
    AuthErrorChallenge,
    AuthType,
    generate_challenge,
)
from gafaelfawr.dependencies.auth import Authenticate
from gafaelfawr.dependencies.context import RequestContext, context_dependency
from gafaelfawr.exceptions import InsufficientScopeError
from gafaelfawr.models.token import TokenData

router = APIRouter()

__all__ = ["get_auth"]


class Satisfy(Enum):
    """Authorization strategies.

    Controls how to do authorization when there are multiple required scopes.
    A strategy of ANY allows the request if the authentication token has any
    of the required scopes.  A strategy of ALL requires that the
    authentication token have all the required scopes.
    """

    ANY = "any"
    ALL = "all"


@dataclass
class AuthConfig:
    """Configuration for an authorization request."""

    scopes: Set[str]
    """The scopes the authentication token must have."""

    satisfy: Satisfy
    """The authorization strategy if multiple scopes are required."""

    auth_type: AuthType
    """The authentication type to use in challenges."""

    notebook: bool
    """Whether to generate a notebook token."""

    delegate_to: Optional[str]
    """Internal service for which to create an internal token."""

    delegate_scopes: List[str]
    """List of scopes the delegated token should have."""


def auth_uri(
    x_original_uri: Optional[str] = Header(None),
    x_original_url: Optional[str] = Header(None),
) -> str:
    """Determine URL for which we're validating authentication.

    ``X-Original-URI`` will only be set if the auth-method annotation is set.
    That is recommended, but allow for the case where it isn't set and fall
    back on ``X-Original-URL``, which is set unconditionally.
    """
    return x_original_uri or x_original_url or "NONE"


def auth_config(
    scope: List[str] = Query(...),
    satisfy: Satisfy = Satisfy.ALL,
    auth_type: AuthType = AuthType.Bearer,
    notebook: bool = False,
    delegate_to: Optional[str] = None,
    delegate_scope: Optional[str] = None,
    auth_uri: str = Depends(auth_uri),
    context: RequestContext = Depends(context_dependency),
) -> AuthConfig:
    """Construct the configuration for an authorization request.

    A shared dependency that reads various GET parameters and headers and
    converts them into an `AuthConfig` class.

    Raises
    ------
    fastapi.HTTPException
        If ``notebook`` and ``delegate_to`` are both set.
    """
    context.rebind_logger(
        auth_uri=auth_uri,
        required_scope=" ".join(sorted(scope)),
        satisfy=satisfy.name.lower(),
    )
    if notebook and delegate_to:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={
                "loc": ["query", "delegate_to"],
                "type": "invalid_delegate",
                "msg": "delegate_to cannot be set for notebook tokens",
            },
        )
    if delegate_scope:
        delegate_scopes = [s.strip() for s in delegate_scope.split(",")]
    else:
        delegate_scopes = []
    return AuthConfig(
        scopes=set(scope) | set(delegate_scopes),
        satisfy=satisfy,
        auth_type=auth_type,
        notebook=notebook,
        delegate_to=delegate_to,
        delegate_scopes=delegate_scopes,
    )


async def authenticate_with_type(
    auth_type: AuthType = AuthType.Bearer,
    context: RequestContext = Depends(context_dependency),
) -> TokenData:
    """Set authentication challenge based on auth_type parameter."""
    authenticate = Authenticate(auth_type=auth_type, ajax_forbidden=True)
    return await authenticate(context=context)


@router.get("/auth")
async def get_auth(
    response: Response,
    auth_config: AuthConfig = Depends(auth_config),
    token_data: TokenData = Depends(authenticate_with_type),
    context: RequestContext = Depends(context_dependency),
) -> Dict[str, str]:
    """Authenticate and authorize a token.

    Notes
    -----
    Expects the following query parameters to be set:

    scope
        One or more scopes to check (required, may be given multiple times).
    satisfy (optional)
        Require that ``all`` (the default) or ``any`` of the scopes requested
        via the ``scope`` parameter be satisfied.
    auth_type (optional)
        The authentication type to use in challenges.  If given, must be
        either ``bearer`` or ``basic``.  Defaults to ``bearer``.

    Expects the following headers to be set in the request:

    Authorization
        The JWT token. This must always be the full JWT token. The token
        should be in this  header as type ``Bearer``, but it may be type
        ``Basic`` if ``x-oauth-basic`` is the username or password.  This may
        be omitted if the user has a valid session cookie instead.

    The following headers may be set in the response:

    X-Auth-Request-Client-Ip
        The IP address of the client, as determined after parsing
        X-Forwarded-For headers.
    X-Auth-Request-User
        If enabled and the field is available, this will be set from token
        based on the ``JWT_USERNAME_KEY`` field.
    X-Auth-Request-Uid
        If enabled and the field is available, this will be set from token
        based on the ``JWT_UID_KEY`` field.
    X-Auth-Request-Groups
        When a token has groups available in the ``isMemberOf`` claim, the
        names of the groups will be returned, comma-separated, in this
        header.
    X-Auth-Request-Token
        If requested by ``notebook`` or ``delegate_to``, will be set to the
        delegated token.
    X-Auth-Request-Token-Scopes
        If the token has scopes in the ``scope`` claim or derived from groups
        in the ``isMemberOf`` claim, they will be returned in this header.
    X-Auth-Request-Token-Scopes-Accepted
        A space-separated list of token scopes the reliant resource accepts.
    X-Auth-Request-Token-Scopes-Satisfy
        Whether all requested scopes must be present, or just any one of
        them.  Will be set to either ``any`` or ``all``.
    WWW-Authenticate
        If the request is unauthenticated, this header will be set.
    """
    # Determine whether the request is authorized.
    if auth_config.satisfy == Satisfy.ANY:
        authorized = any([s in token_data.scopes for s in auth_config.scopes])
    else:
        authorized = all([s in token_data.scopes for s in auth_config.scopes])

    # If not authorized, log and raise the appropriate error.
    if not authorized:
        exc = InsufficientScopeError("Token missing required scope")
        raise generate_challenge(
            context, auth_config.auth_type, exc, auth_config.scopes
        )

    # Log and return the results.
    context.logger.info("Token authorized")
    headers = await build_success_headers(context, auth_config, token_data)
    response.headers.update(headers)
    return {"status": "ok"}


@router.get("/auth/forbidden")
async def get_auth_forbidden(
    response: Response,
    auth_config: AuthConfig = Depends(auth_config),
    context: RequestContext = Depends(context_dependency),
) -> Response:
    """Error page for HTTP Forbidden (403) errors.

    Notes
    -----
    This route exists because we want to set a ``Cache-Control`` header on 403
    errors so that the browser will not cache them.  This doesn't appear to
    easily be possible with ingress-nginx without using a custom error page,
    since headers returned by an ``auth_request`` handler are not passed back
    to the client.

    This route is configured as a custom error page using an annotation like:

    .. code-block:: yaml

       nginx.ingress.kubernetes.io/configuration-snippet: |
         error_page 403 = "/auth/forbidden?scope=<scope>";

    It takes the same parameters as the ``/auth`` route and uses them to
    construct an appropriate challenge, assuming that the 403 is due to
    insufficient token scope.
    """
    error = "Token missing required scope"
    challenge = AuthErrorChallenge(
        auth_type=auth_config.auth_type,
        realm=context.config.realm,
        error=AuthError.insufficient_scope,
        error_description=error,
        scope=" ".join(sorted(auth_config.scopes)),
    )
    headers = {
        "Cache-Control": "no-cache, must-revalidate",
        "WWW-Authenticate": challenge.as_header(),
    }
    context.logger.info("Serving uncached 403 page")
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        headers=headers,
        detail={"msg": error, "type": "permission_denied"},
    )


async def build_success_headers(
    context: RequestContext, auth_config: AuthConfig, token_data: TokenData
) -> Dict[str, str]:
    """Construct the headers for successful authorization.

    Parameters
    ----------
    context : `gafaelfawr.dependencies.context.RequestContext`
        The context of the incoming request.
    auth_config : `AuthConfig`
        Configuration parameters for the authorization.
    token_data : `gafaelfawr.models.token.TokenData`
        The data from the authentication token.

    Returns
    -------
    headers : Dict[`str`, `str`]
        Headers to include in the response.
    """
    headers = {
        "X-Auth-Request-Client-Ip": context.request.client.host,
        "X-Auth-Request-Scopes-Accepted": " ".join(sorted(auth_config.scopes)),
        "X-Auth-Request-Scopes-Satisfy": auth_config.satisfy.name.lower(),
        "X-Auth-Request-Token-Scopes": " ".join(sorted(token_data.scopes)),
        "X-Auth-Request-User": token_data.username,
    }
    if token_data.uid:
        headers["X-Auth-Request-Uid"] = str(token_data.uid)
    if token_data.groups:
        groups = ",".join([g.name for g in token_data.groups])
        headers["X-Auth-Request-Groups"] = groups

    if auth_config.notebook:
        token_service = context.factory.create_token_service()
        token = await token_service.get_notebook_token(
            token_data, ip_address=context.request.client.host
        )
        headers["X-Auth-Request-Token"] = str(token)
    elif auth_config.delegate_to:
        token_service = context.factory.create_token_service()
        token = await token_service.get_internal_token(
            token_data,
            service=auth_config.delegate_to,
            scopes=auth_config.delegate_scopes,
            ip_address=context.request.client.host,
        )
        headers["X-Auth-Request-Token"] = str(token)

    return headers

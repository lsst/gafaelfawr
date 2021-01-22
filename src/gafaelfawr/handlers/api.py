"""Route handlers for the ``/auth/api/v1`` API.

All the route handlers are intentionally defined in a single file to encourage
the implementation to be very short.  All the business logic should be defined
in manager objects and the output formatting should be handled by response
models.
"""

from __future__ import annotations

from typing import List
from urllib.parse import quote

from fastapi import APIRouter, Depends, HTTPException, Path, Response, status

from gafaelfawr.constants import USERNAME_REGEX
from gafaelfawr.dependencies.auth import Authenticate
from gafaelfawr.dependencies.context import RequestContext, context_dependency
from gafaelfawr.exceptions import (
    BadExpiresError,
    BadScopesError,
    DuplicateTokenNameError,
)
from gafaelfawr.models.admin import Admin
from gafaelfawr.models.auth import APIConfig, APILoginResponse, Scope
from gafaelfawr.models.token import (
    AdminTokenRequest,
    NewToken,
    TokenData,
    TokenInfo,
    TokenUserInfo,
    UserTokenModifyRequest,
    UserTokenRequest,
)
from gafaelfawr.util import random_128_bits

__all__ = ["router"]

router = APIRouter()
authenticate = Authenticate()
authenticate_admin = Authenticate(
    require_scope="admin:token", allow_bootstrap_token=True
)
authenticate_session = Authenticate(require_session=True)


@router.get(
    "/admins",
    response_model=List[Admin],
    responses={403: {"description": "Permission denied"}},
    dependencies=[Depends(authenticate_admin)],
)
def get_admins(
    context: RequestContext = Depends(context_dependency),
) -> List[Admin]:
    admin_service = context.factory.create_admin_service()
    return admin_service.get_admins()


@router.post(
    "/admins",
    responses={403: {"description": "Permission denied"}},
    status_code=204,
)
def add_admin(
    admin: Admin,
    auth_data: TokenData = Depends(authenticate_admin),
    context: RequestContext = Depends(context_dependency),
) -> None:
    admin_service = context.factory.create_admin_service()
    admin_service.add_admin(
        admin.username,
        actor=auth_data.username,
        ip_address=context.request.client.host,
    )


@router.delete(
    "/admins/{username}",
    responses={404: {"description": "Specified user is not an administrator"}},
    status_code=204,
)
def delete_admin(
    username: str = Path(
        ...,
        title="Administrator",
        min_length=1,
        max_length=64,
        regex=USERNAME_REGEX,
    ),
    auth_data: TokenData = Depends(authenticate_admin),
    context: RequestContext = Depends(context_dependency),
) -> None:
    admin_service = context.factory.create_admin_service()
    success = admin_service.delete_admin(
        username,
        actor=auth_data.username,
        ip_address=context.request.client.host,
    )
    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "loc": ["path", "username"],
                "type": "not_found",
                "msg": "Speciried user is not an administrator",
            },
        )


@router.get("/login", response_model=APILoginResponse)
def get_login(
    auth_data: TokenData = Depends(authenticate_session),
    context: RequestContext = Depends(context_dependency),
) -> APILoginResponse:
    if not context.state.csrf:
        context.state.csrf = random_128_bits()
    known_scopes = [
        Scope(name=n, description=d)
        for n, d in sorted(context.config.known_scopes.items())
    ]
    api_config = APIConfig(scopes=known_scopes)
    return APILoginResponse(
        csrf=context.state.csrf,
        username=auth_data.username,
        scopes=auth_data.scopes,
        config=api_config,
    )


@router.get(
    "/token-info",
    response_model=TokenInfo,
    response_model_exclude_none=True,
    responses={404: {"description": "Token not found"}},
)
async def get_token_info(
    auth_data: TokenData = Depends(authenticate),
    context: RequestContext = Depends(context_dependency),
) -> TokenInfo:
    token_service = context.factory.create_token_service()
    info = token_service.get_token_info_unchecked(auth_data.token.key)
    if not info:
        msg = "Token found in Redis but not database"
        context.logger.warning(msg)
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"type": "invalid_token", "msg": msg},
        )
    else:
        return info


@router.post("/tokens", response_model=NewToken, status_code=201)
async def post_admin_tokens(
    token_request: AdminTokenRequest,
    response: Response,
    auth_data: TokenData = Depends(authenticate_admin),
    context: RequestContext = Depends(context_dependency),
) -> NewToken:
    token_service = context.factory.create_token_service()
    try:
        token = await token_service.create_token_from_admin_request(
            token_request,
            auth_data,
            ip_address=context.request.client.host,
        )
    except BadExpiresError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={
                "loc": ["body", "expires"],
                "type": "bad_expires",
                "msg": str(e),
            },
        )
    except BadScopesError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={
                "loc": ["body", "scopes"],
                "type": "bad_scopes",
                "msg": str(e),
            },
        )
    except DuplicateTokenNameError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={
                "loc": ["body", "token_name"],
                "type": "duplicate_token_name",
                "msg": str(e),
            },
        )
    response.headers["Location"] = quote(
        f"/auth/api/v1/users/{token_request.username}/tokens/{token.key}"
    )
    return NewToken(token=str(token))


@router.get(
    "/user-info",
    response_model=TokenUserInfo,
    response_model_exclude_none=True,
)
async def get_user_info(
    auth_data: TokenData = Depends(authenticate),
) -> TokenUserInfo:
    return auth_data


@router.get(
    "/users/{username}/tokens",
    response_model=List[TokenInfo],
    response_model_exclude_none=True,
)
async def get_tokens(
    username: str = Path(
        ..., min_length=1, max_length=64, regex=USERNAME_REGEX
    ),
    auth_data: TokenData = Depends(authenticate_session),
    context: RequestContext = Depends(context_dependency),
) -> List[TokenInfo]:
    token_service = context.factory.create_token_service()
    return token_service.list_tokens(auth_data, username)


@router.post(
    "/users/{username}/tokens", response_model=NewToken, status_code=201
)
async def post_tokens(
    token_request: UserTokenRequest,
    response: Response,
    username: str = Path(
        ..., min_length=1, max_length=64, regex=USERNAME_REGEX
    ),
    auth_data: TokenData = Depends(authenticate_session),
    context: RequestContext = Depends(context_dependency),
) -> NewToken:
    token_service = context.factory.create_token_service()
    token_params = token_request.dict(exclude_unset=True)
    try:
        token = await token_service.create_user_token(
            auth_data,
            username,
            ip_address=context.request.client.host,
            **token_params,
        )
    except BadExpiresError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={
                "loc": ["body", "expires"],
                "type": "bad_expires",
                "msg": str(e),
            },
        )
    except BadScopesError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={
                "loc": ["body", "scopes"],
                "type": "bad_scopes",
                "msg": str(e),
            },
        )
    except DuplicateTokenNameError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={
                "loc": ["body", "token_name"],
                "type": "duplicate_token_name",
                "msg": str(e),
            },
        )
    response.headers["Location"] = quote(
        f"/auth/api/v1/users/{username}/tokens/{token.key}"
    )
    return NewToken(token=str(token))


@router.get(
    "/users/{username}/tokens/{key}",
    response_model=TokenInfo,
    response_model_exclude_none=True,
)
async def get_token(
    username: str = Path(
        ..., min_length=1, max_length=64, regex=USERNAME_REGEX
    ),
    key: str = Path(..., min_length=22, max_length=22),
    auth_data: TokenData = Depends(authenticate_session),
    context: RequestContext = Depends(context_dependency),
) -> TokenInfo:
    token_service = context.factory.create_token_service()
    info = token_service.get_token_info(key, auth_data, username)
    if not info:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "loc": ["path", "token"],
                "type": "not_found",
                "msg": "Token not found",
            },
        )
    return info


@router.delete("/users/{username}/tokens/{key}", status_code=204)
async def delete_token(
    username: str = Path(
        ..., min_length=1, max_length=64, regex=USERNAME_REGEX
    ),
    key: str = Path(..., min_length=22, max_length=22),
    auth_data: TokenData = Depends(authenticate_session),
    context: RequestContext = Depends(context_dependency),
) -> None:
    token_service = context.factory.create_token_service()
    success = await token_service.delete_token(
        key,
        auth_data,
        username,
        ip_address=context.request.client.host,
    )
    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "loc": ["path", "token"],
                "type": "not_found",
                "msg": "Token not found",
            },
        )


@router.patch(
    "/users/{username}/tokens/{key}",
    status_code=201,
    response_model=TokenInfo,
    response_model_exclude_none=True,
)
async def patch_token(
    token_request: UserTokenModifyRequest,
    username: str = Path(
        ..., min_length=1, max_length=64, regex=USERNAME_REGEX
    ),
    key: str = Path(..., min_length=22, max_length=22),
    auth_data: TokenData = Depends(authenticate_session),
    context: RequestContext = Depends(context_dependency),
) -> TokenInfo:
    token_service = context.factory.create_token_service()
    update = token_request.dict(exclude_unset=True)
    if "expires" in update and update["expires"] is None:
        update["no_expire"] = True
    try:
        info = await token_service.modify_token(
            key,
            auth_data,
            username,
            ip_address=context.request.client.host,
            **update,
        )
    except BadExpiresError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={
                "loc": ["body", "expires"],
                "type": "bad_expires",
                "msg": str(e),
            },
        )
    except BadScopesError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={
                "loc": ["body", "scopes"],
                "type": "bad_scopes",
                "msg": str(e),
            },
        )
    except DuplicateTokenNameError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={
                "loc": ["body", "token_name"],
                "type": "duplicate_token_name",
                "msg": str(e),
            },
        )
    if not info:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "loc": ["path", "token"],
                "type": "not_found",
                "msg": "Token not found",
            },
        )
    return info

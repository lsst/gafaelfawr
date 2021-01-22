"""Manage tokens."""

from __future__ import annotations

import re
import time
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING

from gafaelfawr.constants import MINIMUM_LIFETIME, USERNAME_REGEX
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
    TokenType,
    TokenUserInfo,
)

if TYPE_CHECKING:
    from typing import List, Optional

    from structlog.stdlib import BoundLogger

    from gafaelfawr.config import Config
    from gafaelfawr.models.token import TokenInfo
    from gafaelfawr.storage.history import TokenHistoryStore
    from gafaelfawr.storage.token import TokenDatabaseStore, TokenRedisStore
    from gafaelfawr.storage.transaction import TransactionManager

__all__ = ["TokenService"]


class TokenService:
    """Manage tokens.

    Parameters
    ----------
    config : `gafaelfawr.config.Config`
        Gafaelfawr configuration.
    token_db_store : `gafaelfawr.storage.token.TokenDatabaseStore`
        The database backing store for tokens.
    token_redis_store : `gafaelfawr.storage.token.TokenRedisStore`
        The Redis backing store for tokens.
    token_history_store : `gafaelfawr.storage.history.TokenHistoryStore`
        The backing store for history of changes to tokens.
    transaction_manager : `gafaelfawr.storage.transaction.TransactionManager`
        Database transaction manager.
    logger : `structlog.BoundLogger`
        Logger to use.
    """

    def __init__(
        self,
        *,
        config: Config,
        token_db_store: TokenDatabaseStore,
        token_redis_store: TokenRedisStore,
        token_history_store: TokenHistoryStore,
        transaction_manager: TransactionManager,
        logger: BoundLogger,
    ) -> None:
        self._config = config
        self._token_db_store = token_db_store
        self._token_redis_store = token_redis_store
        self._token_history_store = token_history_store
        self._transaction_manager = transaction_manager
        self._logger = logger

    async def create_session_token(
        self, user_info: TokenUserInfo, scopes: List[str], *, ip_address: str
    ) -> Token:
        """Create a new session token.

        Parameters
        ----------
        user_info : `gafaelfawr.models.token.TokenUserInfo`
            The user information to associate with the token.
        scopes : List[`str`]
            The scopes of the token.
        ip_address : `str`
            The IP address from which the request came.

        Returns
        -------
        token : `gafaelfawr.models.token.Token`
            The newly-created token.

        Raises
        ------
        gafaelfawr.exceptions.PermissionDeniedError
            If the provided username is invalid.
        """
        self._validate_username(user_info.username)

        token = Token()
        created = datetime.now(tz=timezone.utc).replace(microsecond=0)
        expires = created + timedelta(minutes=self._config.issuer.exp_minutes)
        data = TokenData(
            token=token,
            token_type=TokenType.session,
            scopes=sorted(scopes) if scopes else [],
            created=created,
            expires=expires,
            **user_info.dict(),
        )
        history_entry = TokenChangeHistoryEntry(
            token=token.key,
            username=data.username,
            token_type=TokenType.session,
            scopes=sorted(scopes) if scopes else [],
            expires=expires,
            actor=data.username,
            action=TokenChange.create,
            ip_address=ip_address,
            event_time=created,
        )

        await self._token_redis_store.store_data(data)
        with self._transaction_manager.transaction():
            self._token_db_store.add(data)
            self._token_history_store.add(history_entry)

        return token

    async def create_user_token(
        self,
        auth_data: TokenData,
        username: str,
        *,
        token_name: str,
        scopes: Optional[List[str]] = None,
        expires: Optional[datetime] = None,
        ip_address: str,
    ) -> Token:
        """Add a new user token.

        Parameters
        ----------
        auth_data : `gafaelfawr.models.token.TokenData`
            The token data for the authentication token of the user creating
            a user token.
        username : `str`
            The username for which to create a token.
        token_name : `str`
            The name of the token.
        scopes : List[`str`] or `None`
            The scopes of the token.
        expires : `datetime` or `None`
            When the token should expire.  If not given, defaults to the
            expiration of the authentication token taken from ``data``.
        ip_address : `str`
            The IP address from which the request came.

        Returns
        -------
        token : `gafaelfawr.models.token.Token`
            The newly-created token.

        Raises
        ------
        gafaelfawr.exceptions.BadExpiresError
            The provided expiration time was invalid.
        gafaelfawr.exceptions.DuplicateTokenNameError
            A token with this name for this user already exists.
        gafaelfawr.exceptions.PermissionDeniedError
            If the given username didn't match the user information in the
            authentication token, or if the specified username is invalid.
        """
        if username != auth_data.username:
            msg = "Cannot create tokens for another user"
            raise PermissionDeniedError(msg)
        self._validate_username(username)
        self._validate_expires(expires)
        self._validate_scopes(scopes, auth_data)

        token = Token()
        created = datetime.now(tz=timezone.utc).replace(microsecond=0)
        data = TokenData(
            token=token,
            username=auth_data.username,
            token_type=TokenType.user,
            scopes=sorted(scopes) if scopes else [],
            created=created,
            expires=expires,
            name=auth_data.name,
            uid=auth_data.uid,
            groups=auth_data.groups,
        )
        history_entry = TokenChangeHistoryEntry(
            token=token.key,
            username=data.username,
            token_type=TokenType.user,
            token_name=token_name,
            scopes=sorted(scopes) if scopes else [],
            expires=expires,
            actor=auth_data.username,
            action=TokenChange.create,
            ip_address=ip_address,
            event_time=created,
        )

        await self._token_redis_store.store_data(data)
        with self._transaction_manager.transaction():
            self._token_db_store.add(data, token_name=token_name)
            self._token_history_store.add(history_entry)

        self._logger.info(
            "Created new user token",
            key=token.key,
            token_name=token_name,
            token_scope=",".join(data.scopes),
        )

        return token

    async def create_token_from_admin_request(
        self,
        request: AdminTokenRequest,
        auth_data: TokenData,
        *,
        ip_address: str,
    ) -> Token:
        """Create a new service or user token from an admin request.

        Parameters
        ----------
        request : `gafaelfawr.models.token.AdminTokenRequest`
            The incoming request.
        auth_data : `gafaelfawr.models.token.TokenData`
            The data for the authenticated user making the request.
        ip_address : `str`
            The IP address from which the request came.

        Returns
        -------
        token : `gafaelfawr.models.token.Token`
            The newly-created token.

        Raises
        ------
        gafaelfawr.exceptions.PermissionDeniedError
            If the provided username is invalid.
        """
        if "admin:token" not in auth_data.scopes:
            raise PermissionDeniedError("Missing required admin:token scope")
        self._validate_username(request.username)
        self._validate_scopes(request.scopes)
        self._validate_expires(request.expires)

        token = Token()
        created = datetime.now(tz=timezone.utc).replace(microsecond=0)
        data = TokenData(
            token=token,
            username=request.username,
            token_type=request.token_type,
            scopes=request.scopes,
            created=created,
            expires=request.expires,
            name=request.name,
            uid=request.uid,
            groups=request.groups,
        )
        history_entry = TokenChangeHistoryEntry(
            token=token.key,
            username=data.username,
            token_type=data.token_type,
            token_name=request.token_name,
            scopes=data.scopes,
            expires=request.expires,
            actor=auth_data.username,
            action=TokenChange.create,
            ip_address=ip_address,
            event_time=created,
        )

        await self._token_redis_store.store_data(data)
        with self._transaction_manager.transaction():
            self._token_db_store.add(data, token_name=request.token_name)
            self._token_history_store.add(history_entry)

        if data.token_type == TokenType.user:
            self._logger.info(
                "Created new user token",
                username=data.username,
                key=token.key,
                token_name=request.token_name,
                token_scope=",".join(data.scopes),
            )
        else:
            self._logger.info(
                "Created new service token",
                username=data.username,
                key=token.key,
                token_scope=",".join(data.scopes),
            )
        return token

    async def delete_token(
        self,
        key: str,
        auth_data: TokenData,
        username: Optional[str] = None,
        *,
        ip_address: str,
    ) -> bool:
        """Delete a token.

        Parameters
        ----------
        key : `str`
            The key of the token to delete.
        auth_data : `gafaelfawr.models.token.TokenData`
            The token data for the authentication token of the user deleting
            the token.
        username : `str`, optional
            If given, constrain deletions to tokens owned by the given user.
        ip_address : `str`
            The IP address from which the request came.

        Returns
        -------
        success : `bool`
            Whether the token was found and deleted.
        """
        info = self.get_token_info_unchecked(key, username)
        if not info:
            return False
        if info.username != auth_data.username:
            msg = f"Token owned by {info.username}, not {auth_data.username}"
            self._logger.warning("Permission denied", error=msg)
            raise PermissionDeniedError(msg)

        history_entry = TokenChangeHistoryEntry(
            token=key,
            username=info.username,
            token_type=info.token_type,
            token_name=info.token_name,
            parent=info.parent,
            scopes=info.scopes,
            service=info.service,
            expires=info.expires,
            actor=auth_data.username,
            action=TokenChange.revoke,
            ip_address=ip_address,
            event_time=datetime.now(tz=timezone.utc).replace(microsecond=0),
        )

        await self._token_redis_store.delete(key)
        with self._transaction_manager.transaction():
            success = self._token_db_store.delete(key)
            if success:
                self._token_history_store.add(history_entry)

        if success:
            self._logger.info("Deleted token", key=key, username=info.username)
        return success

    async def get_data(self, token: Token) -> Optional[TokenData]:
        """Retrieve the data for a token from Redis.

        Doubles as a way to check the validity of the token.

        Parameters
        ----------
        token : `gafaelfawr.models.token.Token`
            The token.

        Returns
        -------
        data : `gafaelfawr.models.token.TokenData` or `None`
            The data underlying the token, or `None` if the token is not
            valid.
        """
        return await self._token_redis_store.get_data(token)

    async def get_internal_token(
        self,
        token_data: TokenData,
        service: str,
        scopes: List[str],
        ip_address: str,
    ) -> Token:
        """Get or create a new internal token.

        The new token will have the same expiration time as the existing token
        on which it's based unless that expiration time is longer than the
        expiration time of normal interactive tokens, in which case it will be
        capped at the interactive token expiration time.

        Parameters
        ----------
        token_data : `gafaelfawr.models.token.TokenData`
            The authentication data on which to base the new token.
        service : `str`
            The internal service to which the token is delegated.
        scopes : List[`str`]
            The scopes the new token should have.
        ip_address : `str`
            The IP address from which the request came.

        Returns
        -------
        token : `gafaelfawr.models.token.Token`
            The newly-created token.

        Raises
        ------
        gafaelfawr.exceptions.PermissionDeniedError
            If the username is invalid.
        """
        if not set(scopes) <= set(token_data.scopes):
            raise PermissionDeniedError("Token does not have required scopes")
        self._validate_username(token_data.username)

        # See if there's already a matching internal token.
        key = self._token_db_store.get_internal_token_key(
            token_data, service, scopes
        )
        if key:
            data = await self._token_redis_store.get_data_by_key(key)
            if data:
                return data.token

        # There is not, so we need to create a new one.
        token = Token()
        created = datetime.now(tz=timezone.utc).replace(microsecond=0)
        expires = created + timedelta(minutes=self._config.issuer.exp_minutes)
        if token_data.expires and token_data.expires < expires:
            expires = token_data.expires
        data = TokenData(
            token=token,
            username=token_data.username,
            token_type=TokenType.internal,
            scopes=scopes,
            created=created,
            expires=expires,
            name=token_data.name,
            uid=token_data.uid,
            groups=token_data.groups,
        )
        history_entry = TokenChangeHistoryEntry(
            token=token.key,
            username=data.username,
            token_type=TokenType.internal,
            parent=token_data.token.key,
            scopes=scopes,
            service=service,
            expires=expires,
            actor=token_data.username,
            action=TokenChange.create,
            ip_address=ip_address,
            event_time=created,
        )

        await self._token_redis_store.store_data(data)
        with self._transaction_manager.transaction():
            self._token_db_store.add(
                data, service=service, parent=token_data.token.key
            )
            self._token_history_store.add(history_entry)

        self._logger.info(
            "Created new internal token",
            key=token.key,
            service=service,
            token_scope=",".join(data.scopes),
        )
        return token

    async def get_notebook_token(
        self, token_data: TokenData, ip_address: str
    ) -> Token:
        """Get or create a new notebook token.

        The new token will have the same expiration time as the existing token
        on which it's based unless that expiration time is longer than the
        expiration time of normal interactive tokens, in which case it will be
        capped at the interactive token expiration time.

        Parameters
        ----------
        token_data : `gafaelfawr.models.token.TokenData`
            The authentication data on which to base the new token.
        ip_address : `str`
            The IP address from which the request came.

        Returns
        -------
        token : `gafaelfawr.models.token.Token`
            The newly-created token.

        Raises
        ------
        gafaelfawr.exceptions.PermissionDeniedError
            If the username is invalid.
        """
        self._validate_username(token_data.username)

        # See if there's already a matching notebook token.
        key = self._token_db_store.get_notebook_token_key(token_data)
        if key:
            data = await self._token_redis_store.get_data_by_key(key)
            if data:
                return data.token

        # There is not, so we need to create a new one.
        token = Token()
        created = datetime.now(tz=timezone.utc).replace(microsecond=0)
        expires = created + timedelta(minutes=self._config.issuer.exp_minutes)
        if token_data.expires and token_data.expires < expires:
            expires = token_data.expires
        data = TokenData(
            token=token,
            username=token_data.username,
            token_type=TokenType.notebook,
            scopes=token_data.scopes,
            created=created,
            expires=expires,
            name=token_data.name,
            uid=token_data.uid,
            groups=token_data.groups,
        )
        history_entry = TokenChangeHistoryEntry(
            token=token.key,
            username=data.username,
            token_type=TokenType.notebook,
            parent=token_data.token.key,
            scopes=data.scopes,
            expires=expires,
            actor=token_data.username,
            action=TokenChange.create,
            ip_address=ip_address,
            event_time=created,
        )

        await self._token_redis_store.store_data(data)
        with self._transaction_manager.transaction():
            self._token_db_store.add(data, parent=token_data.token.key)
            self._token_history_store.add(history_entry)

        self._logger.info("Created new notebook token", key=token.key)
        return token

    def get_token_info(
        self, key: str, auth_data: TokenData, username: Optional[str]
    ) -> Optional[TokenInfo]:
        """Get information about a token.

        Parameters
        ----------
        key : `str`
            The key of the token.
        auth_data : `gafaelfawr.models.token.TokenData`
            The authentication data of the person requesting the token
            information, used for authorization checks.
        username : `str`, optional
            If set, constrain the result to tokens from that user and return
            `None` if the token exists but is for a different user.
        """
        info = self.get_token_info_unchecked(key, username)
        if not info:
            return None
        if info.username != auth_data.username:
            if username:
                msg = f"{auth_data.username} cannot list tokens for {username}"
                raise PermissionDeniedError(msg)
            else:
                return None
        else:
            return info

    def get_token_info_unchecked(
        self, key: str, username: Optional[str] = None
    ) -> Optional[TokenInfo]:
        """Get information about a token without checking authorization.

        Parameters
        ----------
        key : `str`
            The key of the token.
        username : `str`, optional
            If set, constrain the result to tokens from that user and return
            `None` if the token exists but is for a different user.
        """
        info = self._token_db_store.get_info(key)
        if not info:
            return None
        if username and info.username != username:
            return None
        return info

    async def get_user_info(self, token: Token) -> Optional[TokenUserInfo]:
        """Get user information associated with a token."""
        data = await self.get_data(token)
        if not data:
            return None
        return TokenUserInfo(
            username=data.username,
            name=data.name,
            uid=data.uid,
            groups=data.groups,
        )

    def list_tokens(
        self, auth_data: TokenData, username: Optional[str] = None
    ) -> List[TokenInfo]:
        """List tokens.

        Parameters
        ----------
        auth_data : `gafaelfawr.models.token.TokenData`
            The token data for the authentication token of the user making
            this modification.
        username : `str`, optional
            Limit results to the given username.

        Returns
        -------
        info : List[`gafaelfawr.models.token.TokenInfo`]
            Information for all matching tokens.

        Raises
        ------
        gafaelfawr.exceptions.PermissionDeniedError
            The user whose tokens are being listed does not match the
            authentication information.
        """
        if username and username != auth_data.username:
            msg = f"{auth_data.username} cannot list tokens for {username}"
            self._logger.warning("Permission denied", error=msg)
            raise PermissionDeniedError(msg)
        return self._token_db_store.list(username=username)

    async def modify_token(
        self,
        key: str,
        auth_data: TokenData,
        username: Optional[str] = None,
        *,
        ip_address: str,
        token_name: Optional[str] = None,
        scopes: Optional[List[str]] = None,
        expires: Optional[datetime] = None,
        no_expire: bool = False,
    ) -> Optional[TokenInfo]:
        """Modify a token.

        Parameters
        ----------
        key : `str`
            The key of the token to modify.
        auth_data : `gafaelfawr.models.token.TokenData`
            The token data for the authentication token of the user making
            this modification.
        username : `str`, optional
            If given, constrain modifications to tokens owned by the given
            user.
        ip_address : `str`
            The IP address from which the request came.
        token_name : `str`, optional
            The new name for the token.
        scopes : List[`str`], optional
            The new scopes for the token.
        expires : `datetime`, optional
            The new expiration time for the token.
        no_expire : `bool`
            If set, the token should not expire.  This is a separate parameter
            because passing `None` to ``expires`` is ambiguous.

        Returns
        -------
        info : `gafaelfawr.models.token.TokenInfo` or `None`
            Information for the updated token or `None` if it was not found.

        Raises
        ------
        gafaelfawr.exceptions.BadExpiresError
            The provided expiration time was invalid.
        gafaelfawr.exceptions.DuplicateTokenNameError
            A token with this name for this user already exists.
        gafaelfawr.exceptions.PermissionDeniedError
            The token being modified is not owned by the user identified with
            ``auth_data`` or the user attempted to modify a token type other
            than user.
        """
        info = self.get_token_info_unchecked(key, username)
        if not info:
            return None
        if info.username != auth_data.username:
            msg = f"Token owned by {info.username}, not {auth_data.username}"
            self._logger.warning("Permission denied", error=msg)
            raise PermissionDeniedError(msg)
        if info.token_type != TokenType.user:
            msg = "Only user tokens can be modified"
            self._logger.warning("Permission denied", error=msg)
            raise PermissionDeniedError(msg)
        self._validate_scopes(scopes, auth_data)
        self._validate_expires(expires)

        history_entry = TokenChangeHistoryEntry(
            token=key,
            username=info.username,
            token_type=TokenType.user,
            token_name=token_name if token_name else info.token_name,
            scopes=scopes if scopes is not None else info.scopes,
            expires=info.expires if not (expires or no_expire) else expires,
            actor=auth_data.username,
            action=TokenChange.edit,
            old_token_name=info.token_name if token_name else None,
            old_scopes=info.scopes if scopes is not None else None,
            old_expires=info.expires if (expires or no_expire) else None,
            ip_address=ip_address,
            event_time=datetime.now(tz=timezone.utc).replace(microsecond=0),
        )

        with self._transaction_manager.transaction():
            info = self._token_db_store.modify(
                key,
                token_name=token_name,
                scopes=scopes,
                expires=expires,
                no_expire=no_expire,
            )
            self._token_history_store.add(history_entry)

            # Update the expiration in Redis if needed.
            if info and (no_expire or expires):
                data = await self._token_redis_store.get_data_by_key(key)
                if data:
                    data.expires = None if no_expire else expires
                    await self._token_redis_store.store_data(data)
                else:
                    info = None

        if info:
            self._logger.info(
                "Modified token",
                key=key,
                token_name=info.token_name,
                token_scope=",".join(info.scopes),
                expires=info.expires,
            )
        return info

    def _validate_expires(self, expires: Optional[datetime]) -> None:
        """Check that a provided token expiration is valid.

        Arguments
        ---------
        expires : `datetime` or `None`
            The token expiration time.

        Raises
        ------
        gafaelfawr.exceptions.BadExpiresError
            The provided expiration time is not valid.

        Notes
        -----
        This is not done in the model because we want to be able to return
        whatever expiration time is set in the backing store in replies, even
        if it isn't valid.  (It could be done using multiple models, but
        isn't currently.)
        """
        if not expires:
            return
        if expires.timestamp() < time.time() + MINIMUM_LIFETIME:
            msg = "token must be valid for at least five minutes"
            raise BadExpiresError(msg)

    def _validate_scopes(
        self,
        scopes: Optional[List[str]],
        auth_data: Optional[TokenData] = None,
    ) -> None:
        """Check that the requested scopes are valid.

        Arguments
        ---------
        scopes : List[`str`] or `None`
            The requested scopes.
        auth_data : `gafaelfawr.models.token.TokenData`, optional
            The token used to authenticate the operation, if the scopes should
            be checked to ensure they are a subset.

        Raises
        ------
        gafaelfawr.exceptions.BadScopesError
            The requested scopes are not permitted.
        """
        if not scopes:
            return
        scopes_set = set(scopes)
        if auth_data and not (scopes_set <= set(auth_data.scopes)):
            msg = "Requested scopes are broader than your current scopes"
            raise BadScopesError(msg)
        if not (scopes_set <= self._config.known_scopes.keys()):
            msg = "Unknown scopes requested"
            raise BadScopesError(msg)

    def _validate_username(self, username: str) -> None:
        """Check that the username is valid."""
        if not re.match(USERNAME_REGEX, username):
            raise PermissionDeniedError(f"Invalid username: {username}")

"""Representation of a token or admin history event."""

from datetime import datetime
from enum import Enum
from typing import List, Optional, Union

from pydantic import BaseModel, Field, validator

from gafaelfawr.models.token import TokenType

__all__ = ["AdminChange", "TokenChange"]


class AdminChange(Enum):
    """Type of change made to a token admin."""

    add = "add"
    remove = "remove"


class AdminHistoryEntry(BaseModel):
    """A record of a change to the token administrators."""

    username: str = Field(
        ...,
        title="Username of the token administrator that was changed",
        min_length=1,
        max_length=64,
    )

    action: AdminChange = Field(..., title="Type of change that was made")

    actor: str = Field(
        ...,
        title="Username of the person making the change",
        min_length=1,
        max_length=64,
    )

    ip_address: str = Field(
        ..., title="IP address from which the change was made"
    )

    event_time: datetime = Field(..., title="When the change was made")

    class Config:
        orm_mode = True


class TokenChange(Enum):
    """Type of change made to a token."""

    create = "create"
    revoke = "revoke"
    expire = "expire"
    edit = "edit"


class TokenChangeHistoryEntry(BaseModel):
    """A record of a change to a token."""

    token: str = Field(
        ...,
        title="Key of the token that was changed",
        min_length=22,
        max_length=22,
    )

    username: str = Field(
        ...,
        title="Username of the token",
        min_length=1,
        max_length=64,
    )

    token_type: TokenType = Field(..., title="Type of the token")

    token_name: Optional[str] = Field(
        None,
        title="Name of the token",
        description=(
            "Only set for tokens of type user. If the name was changed, this"
            " will be the new name of the token."
        ),
    )

    parent: Optional[str] = Field(
        None, title="Key of parent token of this token"
    )

    scopes: List[str] = Field(..., title="Scopes of the token")

    service: Optional[str] = Field(
        None,
        title="Service to which the token was issued",
        description="Only set for tokens of type internal.",
    )

    expires: Optional[datetime] = Field(
        None,
        title="Expiration of the token",
        description=(
            "If the expiration was changed, this will be the new expiration of"
            " the token."
        ),
    )

    actor: str = Field(
        ...,
        title="Username of person making the change",
        min_length=1,
        max_length=64,
    )

    action: TokenChange = Field(..., title="Type of change that was made")

    old_token_name: Optional[str] = Field(
        None,
        title="Previous name of the token",
        description=(
            "This field will only be set for edit changes to user tokens that"
            " changed the token name."
        ),
    )

    old_scopes: Optional[List[str]] = Field(
        None,
        title="Previous scopes of the token",
        description=(
            "This field will only be set for edit changes that changed the"
            " token scopes."
        ),
    )

    old_expires: Optional[datetime] = Field(
        None,
        title="Previous expiration of the token",
        description=(
            "This field will only be set for edit changes that changed the"
            " expiration of the token.  Be aware that the value could be null"
            " if the expiration was not changed or if the token previously"
            " did not expire. To distinguish between those cases, compare"
            " old_expires to expires."
        ),
    )

    ip_address: Optional[str] = Field(
        None,
        title="IP address from which the change was made",
        description=(
            "May be null if the change was made internally, such as token"
            " deletion due to expiration."
        ),
    )

    event_time: datetime = Field(..., title="Whent he change was made")

    class Config:
        orm_mode = True

    @validator("scopes", pre=True)
    def _normalize_scopes(
        cls, v: Optional[Union[str, List[str]]]
    ) -> List[str]:
        """Convert comma-delimited scopes to a list.

        Scopes are stored in the database as a comma-delimited, sorted list.
        Convert to the list representation we want to use in Python.  Convert
        an undefined value to the empty list.
        """
        if v is None:
            return []
        elif isinstance(v, str):
            return v.split(",")
        else:
            return v

    @validator("old_scopes", pre=True)
    def _normalize_old_scopes(
        cls, v: Optional[Union[str, List[str]]]
    ) -> Optional[List[str]]:
        """Convert comma-delimited scopes to a list, preserving ``None``.

        Scopes are stored in the database as a comma-delimited, sorted list.
        Convert to the list representation we want to use in Python.
        """
        if v is None:
            return None
        elif isinstance(v, str):
            return v.split(",")
        else:
            return v

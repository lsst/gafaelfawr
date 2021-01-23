"""Representation of a token or admin history event."""

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, validator

from gafaelfawr.models.token import TokenType
from gafaelfawr.util import (
    current_datetime,
    normalize_datetime,
    normalize_scopes,
)

__all__ = [
    "AdminChange",
    "AdminHistoryEntry",
    "TokenChange",
    "TokenChangeHistoryEntry",
]


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

    event_time: datetime = Field(
        default_factory=current_datetime, title="When the change was made"
    )

    class Config:
        orm_mode = True

    _normalize_event_time = validator(
        "event_time", allow_reuse=True, pre=True
    )(normalize_datetime)


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
            "This field will only be present for edit changes to user tokens"
            " that changed the token name."
        ),
    )

    old_scopes: Optional[List[str]] = Field(
        None,
        title="Previous scopes of the token",
        description=(
            "This field will only be present for edit changes that changed the"
            " token scopes."
        ),
    )

    old_expires: Optional[datetime] = Field(
        None,
        title="Previous expiration of the token",
        description=(
            "This field will only be present for edit changes that changed the"
            " expiration of the token."
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

    event_time: datetime = Field(
        default_factory=current_datetime, title="Whent he change was made"
    )

    class Config:
        json_encoders = {datetime: lambda v: int(v.timestamp())}
        orm_mode = True

    _normalize_scopes = validator("scopes", allow_reuse=True, pre=True)(
        normalize_scopes
    )
    _normalize_expires = validator("expires", allow_reuse=True, pre=True)(
        normalize_datetime
    )
    _normalize_old_expires = validator(
        "old_expires", allow_reuse=True, pre=True
    )(normalize_datetime)
    _normalize_old_scopes = validator(
        "old_scopes", allow_reuse=True, pre=True
    )(normalize_scopes)
    _normalize_event_time = validator(
        "event_time", allow_reuse=True, pre=True
    )(normalize_datetime)

    def reduced_dict(self) -> Dict[str, Any]:
        """Custom ``dict`` method to suppress some fields.

        Excludes the ``old_`` fields for changes other than edits, and when
        the edit doesn't change those fields.
        """
        v = self.dict()

        for field in ("token_name", "parent", "service"):
            if v[field] is None:
                del v[field]
        if v["action"] == TokenChange.edit:
            for field in ("old_scopes", "old_token_name"):
                if v[field] is None:
                    del v[field]
            if v["old_expires"] is None and v["expires"] is None:
                del v["old_expires"]
        else:
            del v["old_expires"]
            del v["old_scopes"]
            del v["old_token_name"]

        return v

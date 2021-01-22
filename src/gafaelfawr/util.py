"""General utility functions."""

from __future__ import annotations

import base64
import os
from datetime import datetime, timezone
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import List, Optional, Union

__all__ = [
    "add_padding",
    "base64_to_number",
    "current_datetime",
    "normalize_datetime",
    "number_to_base64",
    "random_128_bits",
]


def add_padding(encoded: str) -> str:
    """Add padding to base64 encoded bytes.

    Parameters
    ----------
    encoded : `str`
        A base64-encoded string, possibly with the padding removed.

    Returns
    -------
    result : `str`
        A correctly-padded version of the encoded string.
    """
    underflow = len(encoded) % 4
    if underflow:
        return encoded + ("=" * (4 - underflow))
    else:
        return encoded


def base64_to_number(data: str) -> int:
    """Convert base64-encoded bytes to an integer.

    Parameters
    ----------
    data : `str`
        Base64-encoded number, possibly without padding.

    Returns
    -------
    result : `int`
        The result converted to a number.  Note that Python ints can be
        arbitrarily large.

    Notes
    -----
    Used for converting the modulus and exponent in a JWKS to integers in
    preparation for turning them into a public key.
    """
    decoded = base64.urlsafe_b64decode(add_padding(data))
    return int.from_bytes(decoded, byteorder="big")


def current_datetime() -> datetime:
    """Return the current time without microseconds."""
    return datetime.now(tz=timezone.utc).replace(microsecond=0)


def normalize_datetime(
    v: Optional[Union[int, datetime]]
) -> Optional[datetime]:
    """Pydantic validator for datetime fields.

    This decodes fields encoded as seconds since epoch and ensures that
    datetimes are always stored in the model as timezone-aware.  When read
    from databases, often they come back timezone-naive, but we use UTC as the
    timezone for every stored date.

    Parameters
    ----------
    v : `int` or `datetime` or `None`
        The field representing a `datetime`

    Returns
    -------
    v : `datetime` or `None`
        The timezone-aware `datetime` or `None` if the input was `None`.
    """
    if v is None:
        return v
    elif isinstance(v, int):
        return datetime.fromtimestamp(v, tz=timezone.utc)
    elif v.tzinfo and v.tzinfo.utcoffset(v) is not None:
        return v
    else:
        return v.replace(tzinfo=timezone.utc)


def normalize_scopes(
    v: Optional[Union[str, List[str]]]
) -> Optional[List[str]]:
    """Pydantic validator for scope fields.

    Scopes are stored in the database as a comma-delimited, sorted list.
    Convert to the list representation we want to use in Python, preserving
    `None`.

    Parameters
    ----------
    v : `str` or List[`str`] or `None`
        The field representing token scopes.

    Returns
    -------
    v : List[`str`] or `None`
        The scopes as a list.
    """
    if v is None:
        return None
    elif isinstance(v, str):
        return [] if v == "" else v.split(",")
    else:
        return v


def number_to_base64(data: int) -> bytes:
    """Convert an integer to base64-encoded bytes in big endian order.

    The base64 encoding used here is the Base64urlUInt encoding defined in RFC
    7515 and 7518, which uses the URL-safe encoding characters and omits all
    padding.

    Parameters
    ----------
    data : `int`
        Arbitrarily large number

    Returns
    -------
    result : `bytes`
        The equivalent URL-safe base64-encoded string corresponding to the
        number in big endian order.
    """
    bit_length = data.bit_length()
    byte_length = bit_length // 8 + 1
    data_as_bytes = data.to_bytes(byte_length, byteorder="big", signed=False)
    return base64.urlsafe_b64encode(data_as_bytes).rstrip(b"=")


def random_128_bits() -> str:
    """Generate random 128 bits encoded in base64 without padding."""
    return base64.urlsafe_b64encode(os.urandom(16)).decode().rstrip("=")

"""Test helper functions to parse HTTP headers."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import TYPE_CHECKING
from urllib.parse import parse_qs, urlparse

from gafaelfawr.auth import (
    AuthChallenge,
    AuthError,
    AuthErrorChallenge,
    AuthType,
)

if TYPE_CHECKING:
    from typing import Dict, List, Optional


@dataclass
class LinkData:
    """Holds the data returned in an RFC 8288 ``Link`` header."""

    prev_url: Optional[str]
    """The URL of the previous page, or `None` for the first page."""

    next_url: Optional[str]
    """The URL of the next page, or `None` for the last page."""

    first_url: str
    """The URL of the first page."""


def parse_link(header: str) -> LinkData:
    """Parse an RFC 8288 ``Link`` with pagination URLs."""
    elements = header.split(",")
    links = {}
    for element in elements:
        match = re.match(' *<([^>]+)>; rel="([^"]+)"', element)
        assert match, f"Unable to parse Link {element}"
        assert match.group(2) in ("prev", "next", "first")
        links[match.group(2)] = match.group(1)

    return LinkData(
        prev_url=links.get("prev"),
        next_url=links.get("next"),
        first_url=links["first"],
    )


def parse_www_authenticate(header: str) -> AuthChallenge:
    """Parse a ``WWW-Authenticate`` header into this representation.

    A ``WWW-Authenticate`` header consists of one or more challenges, each of
    which is an auth type, whitespace, and a series of attributes in the form
    of key="value", separated by a comma and whitespace.

    We only support a single challenge here, since Gafaelfawr only returns a
    single challenge.
    """
    auth_type_name, info = header.split(None, 1)
    auth_type = AuthType[auth_type_name]

    # A half-assed regex parser for the WWW-Authenticate header.
    #
    # Repeatedly match key/value pairs in the form key="value" and iterate
    # on them as matches.  The key will be match group 1 and the value will
    # be match group 2.
    #
    # Each attribute has to either start at the beginning of the portion of
    # the header after the auth type (\A) or follow a previous attribute with
    # a comma and whitespace (,\s*), ensuring there isn't any extraneous junk
    # in the header.
    error = None
    error_description = None
    scope = None
    for attribute in re.finditer(r'(?:\A|,\s*)([^ "=]+)="([^"]+)"', info):
        if attribute.group(1) == "realm":
            realm = attribute.group(2)
        elif attribute.group(1) == "error":
            error = attribute.group(2)
        elif attribute.group(1) == "error_description":
            error_description = attribute.group(2)
        elif attribute.group(1) == "scope":
            scope = attribute.group(2)
        else:
            assert False, f"unexpected attribute {attribute.group(1)}"
    assert realm

    if error:
        assert error_description
        return AuthErrorChallenge(
            auth_type=auth_type,
            realm=realm,
            error=AuthError[error],
            error_description=error_description,
            scope=scope,
        )
    else:
        assert not error_description
        return AuthChallenge(auth_type=auth_type, realm=realm)


def query_from_url(url: str) -> Dict[str, List[str]]:
    """Parse a URL and return its query.

    Parameters
    ----------
    url : `str`
        The URL.

    Returns
    -------
    query : Dict[`str`, List[`str`]]
        The query in the form returned by :py:func:`urllib.parse.parse_qs`.
    """
    parsed_url = urlparse(url)
    assert parsed_url.query
    return parse_qs(parsed_url.query)

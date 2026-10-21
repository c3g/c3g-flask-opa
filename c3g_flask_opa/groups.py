"""Built-in groups-source callables for the two tiers c3g-flask-opa serves.

A groups source is any zero-argument callable returning the current request's groups as a
single comma-separated string -- matching `project_tracking/authz.rego`'s `groups_header`
input field, which splits it itself (`split(input.groups_header, ",")`). Passing a raw string
here, not a pre-split list, keeps every consumer's Rego policy free to parse it however it
wants -- this library doesn't impose a group-list shape on the policy side.
"""

from __future__ import annotations

from flask import g, request


def groups_header_from_request(header_name: str = "X-Forwarded-Groups"):
    """Tier 3a: read the raw groups header oauth2-proxy already sets on every request it
    lets through. Returns `""` if the header is absent (e.g. the app isn't actually running
    behind oauth2-proxy, such as during local development).
    """

    def _read() -> str:
        return request.headers.get(header_name, "")

    return _read


def groups_header_from_g(attr: str = "groups"):
    """Tier 3b: read groups already populated on `flask.g` -- typically by `c3g-oidc` after
    validating a Bearer token -- and join them into the same comma-separated shape
    `groups_header_from_request` produces, so a policy doesn't have to care which tier
    produced its input.
    """

    def _read() -> str:
        groups = getattr(g, attr, None) or []
        return ",".join(groups)

    return _read

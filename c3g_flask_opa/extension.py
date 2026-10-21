"""The Flask extension: a before_request hook that calls OPA and enforces the result.

Usage (see README.md for the full walkthrough)::

    opa = FlaskOPA(app, groups_source=groups_header_from_request(), policy_path="my_app/authz/allow")

    @app.route("/healthz")
    @opa.exempt
    def healthz():
        return "ok"
"""

from __future__ import annotations

import os
from typing import Callable

from flask import Flask, abort, current_app, request

from .opa_client import OPAClient

DEFAULT_OPA_URL = "http://10.0.2.2:8181"


def _default_input_builder(groups_header: str) -> dict:
    """The input shape `project_tracking/authz.rego` (and any app following the same
    convention) expects. Override via `input_builder=` for an app whose policy wants
    something else -- see README.md.
    """
    return {"method": request.method, "path": request.path, "groups_header": groups_header}


class FlaskOPA:
    """Enforces one OPA policy rule on every request to a Flask app, except exempted views.

    Parameters
    ----------
    app:
        A Flask app, or `None` to call `init_app` later (the standard Flask-extension
        two-step pattern, for apps using an application factory).
    groups_source:
        Zero-argument callable returning the current request's groups as a comma-separated
        string. Required. Use `groups_header_from_request()` for Tier 3a,
        `groups_header_from_g()` for Tier 3b, or supply your own.
    input_builder:
        One-argument callable, `(groups_header) -> dict`, shaping what gets sent to OPA as
        `input`. Defaults to `{method, path, groups_header}`, matching
        `project_tracking/authz.rego`. Override if your app's policy expects a different
        shape (e.g. an `action` field instead of `method`/`path`).
    policy_path:
        The OPA rule to query, e.g. `"project_tracking/authz/allow"` -- see `OPAClient` for
        how this maps to a Rego package/rule name. Required.
    opa_url:
        Base URL of the app's local OPA sidecar. Defaults to the `C3G_OPA_URL` environment
        variable, falling back to `http://10.0.2.2:8181`.
    timeout:
        Seconds to wait for OPA before failing closed (deny). Default 2.0.
    """

    def __init__(
        self,
        app: Flask | None = None,
        *,
        groups_source: Callable[[], str] | None = None,
        input_builder: Callable[[str], dict] | None = None,
        policy_path: str | None = None,
        opa_url: str | None = None,
        timeout: float = 2.0,
    ) -> None:
        self.groups_source = groups_source
        self.input_builder = input_builder or _default_input_builder
        self.policy_path = policy_path
        self.opa_url = opa_url
        self.timeout = timeout
        self._client: OPAClient | None = None
        self._exempt_views: set = set()

        if app is not None:
            self.init_app(app)

    def init_app(self, app: Flask) -> None:
        if self.groups_source is None:
            raise ValueError(
                "FlaskOPA requires a groups_source callable -- e.g. "
                "groups_header_from_request() for Tier 3a, groups_header_from_g() for Tier "
                "3b. See README.md."
            )
        if not self.policy_path:
            raise ValueError(
                "FlaskOPA requires policy_path, the OPA rule to query -- e.g. "
                "'project_tracking/authz/allow'. See README.md."
            )

        opa_url = self.opa_url or os.environ.get("C3G_OPA_URL", DEFAULT_OPA_URL)
        self._client = OPAClient(opa_url, self.policy_path, timeout=self.timeout)
        app.before_request(self._enforce)

    def exempt(self, view):
        """Decorator: mark a view as not requiring an OPA check (e.g. a health endpoint).

        Matches Flask-WTF's `CSRFProtect.exempt` pattern: records the view function itself,
        then checks the *dispatched* view function against that set on each request -- this
        keeps working regardless of blueprint prefixes or a custom `endpoint=` name.
        """
        self._exempt_views.add(view)
        return view

    def _enforce(self):
        assert self._client is not None  # set in init_app, before any request can arrive

        view = current_app.view_functions.get(request.endpoint)
        if view in self._exempt_views:
            return

        groups_header = self.groups_source()
        opa_input = self.input_builder(groups_header)
        if not self._client.allow(opa_input):
            abort(403)

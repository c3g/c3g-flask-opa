"""Low-level, fail-closed HTTP client for an app's local OPA sidecar.

Talks to OPA's data API (`POST /v1/data/<policy path>`), which for a boolean Rego rule
returns `{"result": true|false}` -- see https://www.openpolicyagent.org/docs/rest-api. This
module has no Flask dependency; `extension.py` is the only piece that knows about Flask.
"""

from __future__ import annotations

import requests


class OPAClient:
    """Calls one policy rule on one app's local OPA sidecar.

    Parameters
    ----------
    opa_url:
        Base URL of the OPA sidecar, e.g. ``http://10.0.2.2:8181`` -- the host-loopback
        address used throughout web-app-template's deployment docs.
    policy_path:
        The rule to query, as a slash-separated path matching the Rego package and rule name
        with dots replaced by slashes -- e.g. package ``project_tracking.authz``, rule
        ``allow``, becomes ``project_tracking/authz/allow``.
    timeout:
        Seconds to wait for OPA before treating the call as failed (and therefore denied).
    """

    def __init__(self, opa_url: str, policy_path: str, *, timeout: float = 2.0) -> None:
        self.opa_url = opa_url.rstrip("/")
        self.policy_path = policy_path.strip("/")
        self.timeout = timeout

    def allow(self, input_: dict) -> bool:
        """POST `input_` to OPA and return its allow/deny answer for this rule.

        Fails closed: any network error, timeout, non-2xx response, or response that isn't
        the expected `{"result": bool}` shape is treated as deny (`False`) -- never as
        allow. An OPA outage should block requests, not silently disable authorization.
        """
        try:
            response = requests.post(
                f"{self.opa_url}/v1/data/{self.policy_path}",
                json={"input": input_},
                timeout=self.timeout,
            )
            response.raise_for_status()
            body = response.json()
        except (requests.RequestException, ValueError):
            return False
        return body.get("result") is True

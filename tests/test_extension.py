from unittest.mock import patch

import pytest
from flask import Flask

from c3g_flask_opa import FlaskOPA


def make_app(**opa_kwargs):
    app = Flask(__name__)
    app.config["TESTING"] = True
    opa = FlaskOPA(
        app,
        groups_source=lambda: "admins",
        policy_path="test_app/authz/allow",
        opa_url="http://opa.example:8181",
        **opa_kwargs,
    )

    @app.route("/thing")
    def thing():
        return "ok"

    @app.route("/healthz")
    @opa.exempt
    def healthz():
        return "ok"

    return app, opa


def test_missing_groups_source_raises():
    app = Flask(__name__)
    with pytest.raises(ValueError, match="groups_source"):
        FlaskOPA(app, policy_path="test_app/authz/allow")


def test_missing_policy_path_raises():
    app = Flask(__name__)
    with pytest.raises(ValueError, match="policy_path"):
        FlaskOPA(app, groups_source=lambda: "admins")


def test_allowed_request_passes_through():
    app, _opa = make_app()
    with patch("c3g_flask_opa.opa_client.OPAClient.allow", return_value=True):
        client = app.test_client()
        resp = client.get("/thing")
    assert resp.status_code == 200


def test_denied_request_gets_403():
    app, _opa = make_app()
    with patch("c3g_flask_opa.opa_client.OPAClient.allow", return_value=False):
        client = app.test_client()
        resp = client.get("/thing")
    assert resp.status_code == 403


def test_exempt_view_bypasses_check_even_when_opa_would_deny():
    app, _opa = make_app()
    with patch("c3g_flask_opa.opa_client.OPAClient.allow", return_value=False):
        client = app.test_client()
        resp = client.get("/healthz")
    assert resp.status_code == 200


def test_default_input_builder_shape():
    app, _opa = make_app()
    with patch("c3g_flask_opa.opa_client.OPAClient.allow", return_value=True) as allow:
        client = app.test_client()
        client.get("/thing")
    allow.assert_called_once_with({"method": "GET", "path": "/thing", "groups_header": "admins"})


def test_custom_input_builder_is_used():
    app, _opa = make_app(input_builder=lambda groups_header: {"custom": groups_header})
    with patch("c3g_flask_opa.opa_client.OPAClient.allow", return_value=True) as allow:
        client = app.test_client()
        client.get("/thing")
    allow.assert_called_once_with({"custom": "admins"})


def test_opa_url_defaults_to_the_pod_local_sidecar(monkeypatch):
    # OPA runs in the app's own podman pod, so the app reaches it on the pod's loopback.
    monkeypatch.delenv("C3G_OPA_URL", raising=False)
    opa = FlaskOPA(Flask(__name__), groups_source=lambda: "admins",
                   policy_path="test_app/authz/allow")
    assert opa._client.opa_url == "http://127.0.0.1:8181"


def test_opa_url_from_environment(monkeypatch):
    monkeypatch.setenv("C3G_OPA_URL", "http://opa.example:9999")
    opa = FlaskOPA(Flask(__name__), groups_source=lambda: "admins",
                   policy_path="test_app/authz/allow")
    assert opa._client.opa_url == "http://opa.example:9999"

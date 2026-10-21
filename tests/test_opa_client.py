"""Unit tests for OPAClient's fail-closed HTTP behaviour, mocking requests.post so these
don't need a running OPA server. See test_integration_opa_server.py for a test against
a real OPA server loaded with a real policy.
"""

from unittest.mock import Mock, patch

import pytest
import requests

from c3g_flask_opa import OPAClient


@pytest.fixture
def client():
    return OPAClient("http://opa.example:8181", "my_app/authz/allow")


def test_allow_true(client):
    response = Mock(status_code=200)
    response.json.return_value = {"result": True}
    response.raise_for_status.return_value = None
    with patch("c3g_flask_opa.opa_client.requests.post", return_value=response) as post:
        assert client.allow({"method": "GET"}) is True
    post.assert_called_once_with(
        "http://opa.example:8181/v1/data/my_app/authz/allow",
        json={"input": {"method": "GET"}},
        timeout=2.0,
    )


def test_allow_false(client):
    response = Mock(status_code=200)
    response.json.return_value = {"result": False}
    response.raise_for_status.return_value = None
    with patch("c3g_flask_opa.opa_client.requests.post", return_value=response):
        assert client.allow({"method": "GET"}) is False


def test_fails_closed_on_network_error(client):
    with patch(
        "c3g_flask_opa.opa_client.requests.post",
        side_effect=requests.ConnectionError("opa is down"),
    ):
        assert client.allow({"method": "GET"}) is False


def test_fails_closed_on_timeout(client):
    with patch(
        "c3g_flask_opa.opa_client.requests.post", side_effect=requests.Timeout("too slow")
    ):
        assert client.allow({"method": "GET"}) is False


def test_fails_closed_on_non_2xx(client):
    response = Mock(status_code=500)
    response.raise_for_status.side_effect = requests.HTTPError("500")
    with patch("c3g_flask_opa.opa_client.requests.post", return_value=response):
        assert client.allow({"method": "GET"}) is False


def test_fails_closed_on_malformed_json(client):
    response = Mock(status_code=200)
    response.raise_for_status.return_value = None
    response.json.side_effect = ValueError("not json")
    with patch("c3g_flask_opa.opa_client.requests.post", return_value=response):
        assert client.allow({"method": "GET"}) is False


def test_fails_closed_when_result_key_missing(client):
    """OPA returns no `result` key at all when the queried path is undefined -- e.g. a typo
    in policy_path, or a rule that doesn't exist. Must deny, not error out or allow.
    """
    response = Mock(status_code=200)
    response.raise_for_status.return_value = None
    response.json.return_value = {}
    with patch("c3g_flask_opa.opa_client.requests.post", return_value=response):
        assert client.allow({"method": "GET"}) is False


def test_policy_path_strips_leading_and_trailing_slashes():
    client = OPAClient("http://opa.example:8181", "/my_app/authz/allow/")
    assert client.policy_path == "my_app/authz/allow"


def test_opa_url_strips_trailing_slash():
    client = OPAClient("http://opa.example:8181/", "my_app/authz/allow")
    assert client.opa_url == "http://opa.example:8181"

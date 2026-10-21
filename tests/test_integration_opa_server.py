"""Runs c3g_flask_opa's OPAClient against a real `opa run --server`, loaded with an example
policy written for the library's default input shape (see tests/fixtures/example_app/), and
asserts its allow/deny outcomes end to end. This is what backs the claim in README.md that
the library is verified against a real OPA server, not just mocked HTTP.

Requires the `opa` CLI on PATH; skips (doesn't fail) if it isn't found, since not every dev
machine running the rest of the suite will have it installed -- except in CI (the `CI` env var
GitHub Actions sets), where a missing `opa` must fail the run instead of silently skipping.
"""

from __future__ import annotations

import os
import shutil
import socket
import subprocess
import time
from pathlib import Path

import pytest
import requests

from c3g_flask_opa import OPAClient

FIXTURE_DIR = Path(__file__).parent / "fixtures" / "example_app"
POLICY_PATH = "example_app/authz/allow"

pytestmark = pytest.mark.skipif(
    shutil.which("opa") is None and not os.environ.get("CI"),
    reason="opa CLI not found on PATH -- install it to run this integration test",
)


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="module")
def opa_client():
    port = _free_port()
    addr = f"127.0.0.1:{port}"
    proc = subprocess.Popen(
        ["opa", "run", "--server", "--addr", addr, str(FIXTURE_DIR)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        # Wait for the server to come up -- poll /health directly with a raw `requests` call,
        # NOT via OPAClient.allow(): that method fails closed on a connection error (by
        # design -- see opa_client.py), which would make this loop "succeed" on the very
        # first iteration even while the server is still refusing connections.
        deadline = time.monotonic() + 10
        last_error: Exception | None = None
        while time.monotonic() < deadline:
            try:
                resp = requests.get(f"http://{addr}/health", timeout=0.5)
                if resp.status_code == 200:
                    break
            except requests.RequestException as exc:
                last_error = exc
            time.sleep(0.1)
        else:
            proc.terminate()
            raise RuntimeError(f"opa server never came up: {last_error}")
        yield OPAClient(f"http://{addr}", POLICY_PATH, timeout=2.0)
    finally:
        proc.terminate()
        proc.wait(timeout=5)


# One allow and one deny per tier in tests/fixtures/example_app/authz.rego, plus tier
# priority, checked end-to-end through this library's HTTP client.
CASES = [
    pytest.param(
        "POST", "/admin/create_item/ITEM-1", "example-admins", True, id="admin_allowed_for_admins"
    ),
    pytest.param(
        "POST",
        "/admin/create_item/ITEM-1",
        "example-editors",
        False,
        id="admin_denied_for_editor",
    ),
    pytest.param("GET", "/admin/", "", False, id="admin_denied_with_no_groups"),
    pytest.param(
        "POST",
        "/edit/item",
        "example-editors",
        True,
        id="edit_allowed_for_editor",
    ),
    pytest.param(
        "POST",
        "/edit/item",
        "example-uploaders",
        False,
        id="edit_denied_for_uploader",
    ),
    pytest.param(
        "POST",
        "/items/ITEM-1/upload_file",
        "example-uploaders",
        True,
        id="upload_allowed_for_uploader",
    ),
    pytest.param(
        "POST",
        "/items/ITEM-1/upload_file",
        "example-viewers",
        False,
        id="upload_denied_for_viewer",
    ),
    pytest.param(
        "GET", "/items/ITEM-1", "example-viewers", True, id="read_allowed_for_viewer"
    ),
    pytest.param("GET", "/items/ITEM-1", "", False, id="read_denied_with_no_groups"),
    pytest.param(
        "DELETE",
        "/items/ITEM-1/some-legacy-action",
        "example-editors",
        True,
        id="write_fallback_allowed_for_editor",
    ),
    pytest.param(
        "DELETE",
        "/items/ITEM-1/some-legacy-action",
        "example-uploaders",
        False,
        id="write_fallback_denied_for_uploader",
    ),
    pytest.param(
        "POST",
        "/admin/create_item/ITEM-1",
        "example-editors",
        False,
        id="admin_path_takes_priority_over_write_fallback",
    ),
]


@pytest.mark.parametrize("method, path, groups_header, expected", CASES)
def test_example_policy_outcomes(opa_client, method, path, groups_header, expected):
    opa_input = {"method": method, "path": path, "groups_header": groups_header}
    assert opa_client.allow(opa_input) is expected

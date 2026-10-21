from flask import Flask, g

from c3g_flask_opa import groups_header_from_g, groups_header_from_request

app = Flask(__name__)


def test_groups_header_from_request_reads_header():
    read = groups_header_from_request()
    with app.test_request_context(headers={"X-Forwarded-Groups": "example-admins,example-viewers"}):
        assert read() == "example-admins,example-viewers"


def test_groups_header_from_request_defaults_to_empty_string():
    read = groups_header_from_request()
    with app.test_request_context():
        assert read() == ""


def test_groups_header_from_request_custom_header_name():
    read = groups_header_from_request("X-My-Groups")
    with app.test_request_context(headers={"X-My-Groups": "admins"}):
        assert read() == "admins"


def test_groups_header_from_g_joins_list():
    read = groups_header_from_g()
    with app.test_request_context():
        g.groups = ["example-admins", "example-editors"]
        assert read() == "example-admins,example-editors"


def test_groups_header_from_g_defaults_to_empty_string_when_unset():
    read = groups_header_from_g()
    with app.test_request_context():
        assert read() == ""


def test_groups_header_from_g_custom_attr():
    read = groups_header_from_g("my_groups")
    with app.test_request_context():
        g.my_groups = ["admins"]
        assert read() == "admins"

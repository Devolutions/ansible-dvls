from __future__ import absolute_import, division, print_function

__metaclass__ = type

import pytest

from ansible_collections.devolutions.dvls.plugins.module_utils import auth, lookup_base
from ansible_collections.devolutions.dvls.tests.unit.plugins.module_utils.fakes import FakeResponse

URL = "https://dvls.test"


class LookupError_(Exception):
    pass


class Display(object):
    def vvv(self, msg):
        pass

    def warning(self, msg):
        pass


@pytest.fixture
def logins(monkeypatch):
    calls = []

    def fake_login(server_base_url, app_key, app_secret):
        calls.append((app_key, app_secret))
        return "token-%s-%d" % (app_key, len(calls))

    monkeypatch.setattr(auth, "login", fake_login)
    monkeypatch.setattr(auth, "http_request", lambda *a, **k: FakeResponse(204))
    monkeypatch.setattr(lookup_base, "_session_cache", {})
    monkeypatch.setattr(lookup_base, "_cleanup_registered", True)
    return calls


def helper():
    return lookup_base.DVLSLookupHelper(Display(), LookupError_)


def test_another_identity_gets_its_own_session(logins):
    session_a = helper().authenticate(URL, "A", "secret-a")
    session_b = helper().authenticate(URL, "B", "secret-b")
    assert session_a is not session_b
    assert logins == [("A", "secret-a"), ("B", "secret-b")]


def test_the_same_identity_reuses_its_session(logins):
    first = helper().authenticate(URL, "A", "secret-a")
    assert helper().authenticate(URL, "A", "secret-a") is first
    assert logins == [("A", "secret-a")]


def test_a_rotated_secret_logs_in_again(logins):
    first = helper().authenticate(URL, "A", "old")
    second = helper().authenticate(URL, "A", "new")
    assert second is not first
    assert first.token is None
    assert logins == [("A", "old"), ("A", "new")]


def test_a_relogin_after_expiry_uses_the_session_identity(logins, monkeypatch):
    helper().authenticate(URL, "A", "secret-a")
    session_b = helper().authenticate(URL, "B", "secret-b")

    answers = [FakeResponse(401, body={"message": "Missing or invalid token."}), FakeResponse(200, body={})]
    monkeypatch.setattr(auth, "http_request", lambda *a, **k: answers.pop(0))
    assert session_b.request("GET", "server/info").status_code == 200
    assert logins == [("A", "secret-a"), ("B", "secret-b"), ("B", "secret-b")]


from __future__ import absolute_import, division, print_function

__metaclass__ = type

import pytest

from ansible_collections.devolutions.dvls.plugins.module_utils.http import raise_for_dvls_error
from ansible_collections.devolutions.dvls.plugins.module_utils.vaults import list_all
from ansible_collections.devolutions.dvls.tests.unit.plugins.module_utils.fakes import (
    FakeResponse,
    FakeSession,
)


def error_of(response):
    with pytest.raises(Exception) as excinfo:
        raise_for_dvls_error(response)
    return str(excinfo.value)


def test_ok_response_does_not_raise():
    raise_for_dvls_error(FakeResponse(200, body={}))


def test_error_keeps_status_and_message():
    message = error_of(FakeResponse(404, body={"message": "The requested resource was not found."}))
    assert message.startswith("404 ")
    assert "The requested resource was not found." in message


def test_error_keeps_field_errors():
    message = error_of(FakeResponse(400, body={"errors": [{"field": "type", "message": "Invalid value."}, {"message": "Bad."}]}))
    assert "type: Invalid value.; Bad." in message


def test_error_never_echoes_a_body_that_is_not_a_dvls_error():
    canary = "secret-canary-value"
    assert canary not in error_of(FakeResponse(502, text="<html>proxy " + canary + "</html>"))
    assert canary not in error_of(FakeResponse(500, body={"stackTrace": canary}, text=canary))
    assert canary not in error_of(FakeResponse(500, body=[canary], text=canary))


def test_list_all_does_not_echo_a_body_without_data():
    session = FakeSession(lambda m, p, q: FakeResponse(body={"secret": "secret-canary-value"}))
    with pytest.raises(ValueError) as excinfo:
        list_all(session, "vault")
    assert "secret-canary-value" not in str(excinfo.value)

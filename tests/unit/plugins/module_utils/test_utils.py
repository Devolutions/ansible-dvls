from __future__ import absolute_import, division, print_function

__metaclass__ = type

import pytest

from ansible_collections.devolutions.dvls.plugins.module_utils.utils import get_sensible_value
from ansible_collections.devolutions.dvls.tests.unit.plugins.module_utils.fakes import (
    FakeResponse,
    FakeSession,
)


def entry_handler(failing_ids=()):
    def handler(method, path, params):
        entry_id = path.rsplit("/", 1)[-1]
        if entry_id in failing_ids:
            return FakeResponse(404, body={"message": "The requested resource was not found."})
        return FakeResponse(body={"id": entry_id, "data": {"password": "pw-" + entry_id}})

    return handler


def test_returns_data_keyed_by_name():
    session = FakeSession(entry_handler())
    result = get_sensible_value(session, "v", {"data": [{"id": "1", "name": "a"}, {"id": "2", "name": "b"}]})
    assert result == {"a": {"password": "pw-1"}, "b": {"password": "pw-2"}}


def test_same_entry_listed_twice_is_read_once():
    session = FakeSession(entry_handler())
    result = get_sensible_value(session, "v", [{"id": "1", "name": "a"}, {"id": "1", "name": "a"}])
    assert result == {"a": {"password": "pw-1"}}
    assert len(session.calls) == 1


def test_two_entries_with_one_name_fail():
    session = FakeSession(entry_handler())
    with pytest.raises(ValueError) as excinfo:
        get_sensible_value(session, "v", [{"id": "1", "name": "db", "path": "Production"}, {"id": "2", "name": "db", "path": "Staging"}])
    assert "Several entries are named 'db'" in str(excinfo.value)
    assert session.calls == []


def test_an_entry_that_cannot_be_read_fails():
    session = FakeSession(entry_handler(failing_ids=("2",)))
    with pytest.raises(Exception) as excinfo:
        get_sensible_value(session, "v", [{"id": "1", "name": "a"}, {"id": "2", "name": "b"}])
    assert "404" in str(excinfo.value)


def test_entries_that_are_not_a_list_fail():
    with pytest.raises(ValueError):
        get_sensible_value(FakeSession(entry_handler()), "v", {"data": "nope"})

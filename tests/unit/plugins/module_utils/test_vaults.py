from __future__ import absolute_import, division, print_function

__metaclass__ = type

import pytest

from ansible_collections.devolutions.dvls.plugins.module_utils.vaults import (
    find_entry_by_name,
    get_vault_entry_from_full_path,
    get_vault_entry_from_path,
    normalize_path,
    same_path,
)
from ansible_collections.devolutions.dvls.tests.unit.plugins.module_utils.fakes import (
    FakeSession,
    paged,
)


@pytest.mark.parametrize(
    "path, expected",
    [
        ("Production/Database", "Production\\Database"),
        ("\\Production\\\\Database\\", "Production\\Database"),
        ("/", ""),
        (None, ""),
    ],
)
def test_normalize_path(path, expected):
    assert normalize_path(path) == expected


def test_same_path_ignores_separator_and_case():
    assert same_path("Production/Database", "production\\DATABASE")
    assert not same_path("Production", "Production\\Database")


def test_find_entry_by_name_matches_a_slash_separated_path():
    entries = [{"id": "1", "name": "db", "type": "Credential", "path": "Production\\Database"}]
    assert find_entry_by_name(entries, "db", "Production/Database")["id"] == "1"
    assert find_entry_by_name(entries, "db", "") is None


def test_full_path_lookup_sends_the_parent_folder_and_the_name():
    session = FakeSession(lambda m, p, q: paged([{"id": "1", "name": "prod-db", "type": "Credential"}]))
    result = get_vault_entry_from_full_path(session, "v", "Production/Database\\prod-db")
    path, params = session.calls[0][1:]
    assert path == "vault/v/entry"
    assert params["name"] == "prod-db"
    assert params["path"] == "Production\\Database"
    assert params["exactPath"] == "true"
    assert [e["id"] for e in result["data"]] == ["1"]


def test_full_path_lookup_at_the_root_sends_no_path():
    session = FakeSession(lambda m, p, q: paged([]))
    get_vault_entry_from_full_path(session, "v", "\\prod-db")
    params = session.calls[0][2]
    assert "path" not in params
    assert params["name"] == "prod-db"
    assert params["exactPath"] == "true"


def test_path_fetch_lists_only_the_folder():
    session = FakeSession(lambda m, p, q: paged([{"id": "1", "name": "a", "type": "Credential"}, {"id": "2", "name": "f", "type": "Folder"}]))
    result = get_vault_entry_from_path(session, "v", "tests/create-secrets")
    params = session.calls[0][2]
    assert params["path"] == "tests/create-secrets"
    assert params["exactPath"] == "true"
    assert [e["id"] for e in result["data"]] == ["1"]

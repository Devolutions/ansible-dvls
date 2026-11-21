from ansible_collections.devolutions.dvls.plugins.module_utils.http import (
    raise_for_dvls_error,
)

PAGE_SIZE = 500


def filter_folders(data, exact_match_field=None, exact_match_value=None):
    """Filter out folder entries from vault data and optionally filter for exact matches.

    Args:
        data: Either a list of entries or a dict with a 'data' key containing entries
        exact_match_field: Optional field name to match exactly (case insensitive)
        exact_match_value: Optional value to match exactly (case insensitive)

    Returns:
        Filtered data in the same format as input (list or dict)
    """

    def should_include(entry):
        if entry.get("type") == "Folder":
            return False

        if exact_match_field is not None and exact_match_value is not None:
            entry_value = entry.get(exact_match_field, "")
            if isinstance(entry_value, str) and isinstance(exact_match_value, str):
                return entry_value.lower() == exact_match_value.lower()
            else:
                return entry_value == exact_match_value

        return True

    if isinstance(data, dict) and "data" in data:
        entries = data.get("data", [])
        data["data"] = [entry for entry in entries if should_include(entry)]
        return data
    elif isinstance(data, list):
        return [entry for entry in data if should_include(entry)]
    return data


def validate_unique_entry(entries, filter_description):
    """Validate that only one entry exists in the list.

    Args:
        entries: List of entries to validate
        filter_description: Description of the filter used (e.g., "name 'my-secret'")

    Raises:
        ValueError: If multiple entries are found
    """
    if len(entries) > 1:
        raise ValueError(
            f"Multiple entries found with {filter_description}. "
            f"Found {len(entries)} entries. Please use a more specific filter "
            f"or specify the entry by ID instead."
        )


def list_all(session, path, params=None):
    """Fetch every page of a v2 list route and return the items of all pages."""
    query = dict(params or {})
    query["pageSize"] = PAGE_SIZE
    items = []
    page = 1

    while True:
        query["pageNumber"] = page
        response = session.request("GET", path, params=query)
        raise_for_dvls_error(response)

        json_data = response.json()
        if not isinstance(json_data, dict) or "data" not in json_data:
            raise ValueError(f"The response of {path} has no 'data' key.")

        data = json_data.get("data") or []
        items.extend(data)

        if not data or page >= json_data.get("totalPage", 0):
            return items

        page += 1


def get_vaults(session):
    try:
        return list_all(session, "vault")
    except Exception as e:
        raise Exception(f"An error occurred while getting vaults: {e}")


def get_vault_entry(session, vault_id, entry_id):
    try:
        response = session.request("GET", f"vault/{vault_id}/entry/{entry_id}")
        raise_for_dvls_error(response)

        return response.json()
    except Exception as e:
        raise Exception(f"An error occurred while getting a vault entry: {e}")


def get_vault_entry_from_name(session, vault_id, entry_name):
    try:
        entries = list_all(session, f"vault/{vault_id}/entry", {"name": entry_name})

        result = filter_folders(
            {"data": entries}, exact_match_field="name", exact_match_value=entry_name
        )

        validate_unique_entry(result.get("data", []), f"name '{entry_name}'")

        return result
    except Exception as e:
        raise Exception(f"An error occurred while getting a vault entry: {e}")


def get_vault_entry_from_tag(session, vault_id, entry_tag):
    try:
        entries = list_all(session, f"vault/{vault_id}/entry", {"tag": entry_tag})
        return filter_folders({"data": entries})
    except Exception as e:
        raise Exception(f"An error occurred while getting a vault entry: {e}")


def get_vault_entry_from_path(session, vault_id, entry_path):
    try:
        entries = list_all(session, f"vault/{vault_id}/entry", {"path": entry_path})
        return filter_folders(
            {"data": entries}, exact_match_field="path", exact_match_value=entry_path
        )
    except Exception as e:
        raise Exception(f"An error occurred while getting a vault entry: {e}")


def get_vault_entry_from_type(session, vault_id, entry_type):
    try:
        entries = list_all(session, f"vault/{vault_id}/entry", {"type": entry_type})
        return filter_folders(
            {"data": entries}, exact_match_field="type", exact_match_value=entry_type
        )
    except Exception as e:
        raise Exception(f"An error occurred while getting a vault entry: {e}")


def get_vault_entries(session, vault_id):
    try:
        return filter_folders(list_all(session, f"vault/{vault_id}/entry"))
    except Exception as e:
        raise Exception(f"An error occurred while getting vault entries: {e}")


def find_entry_by_name(entries, name, path=""):
    non_folder_entries = filter_folders(entries)

    matching_entries = [
        entry
        for entry in non_folder_entries
        if entry.get("name") == name and entry.get("path") == path
    ]

    validate_unique_entry(matching_entries, f"name '{name}' and path '{path}'")

    return matching_entries[0] if matching_entries else None

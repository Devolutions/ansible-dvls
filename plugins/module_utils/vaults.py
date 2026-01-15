import traceback

try:
    import requests
except ImportError:
    HAS_REQUESTS_LIBRARY = False
    REQUESTS_LIBRARY_IMPORT_ERROR = traceback.format_exc()
else:
    HAS_REQUESTS_LIBRARY_LIBRARY = True
    REQUESTS_LIBRARY_IMPORT_ERROR = None


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
        if entry.get("subType") == "Folder":
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


def get_vaults(server_base_url, token):
    vaults_url = f"{server_base_url}/api/v1/vault"
    vaults_headers = {"Content-Type": "application/json", "tokenId": token}

    try:
        response = requests.get(vaults_url, headers=vaults_headers)
        response.raise_for_status()

        json_data = response.json()
        if "data" not in json_data:
            raise ValueError(f"'data' key missing in response: {json_data}")

        return json_data.get("data", [])
    except Exception as e:
        raise Exception(f"An error occurred while getting vaults: {e}")


def get_vault_entry(server_base_url, token, vault_id, entry_id):
    vault_url = f"{server_base_url}/api/v1/vault/{vault_id}/entry/{entry_id}"
    vault_headers = {"Content-Type": "application/json", "tokenId": token}

    try:
        response = requests.get(vault_url, headers=vault_headers)
        response.raise_for_status()

        return response.json()
    except Exception as e:
        raise Exception(f"An error occurred while getting a vault entry: {e}")


def get_vault_entry_from_name(server_base_url, token, vault_id, entry_name):
    vault_url = f"{server_base_url}/api/v1/vault/{vault_id}/entry"
    vault_headers = {"Content-Type": "application/json", "tokenId": token}

    try:
        response = requests.get(
            vault_url, headers=vault_headers, params={"name": entry_name}
        )
        response.raise_for_status()

        result = response.json()

        result = filter_folders(
            result, exact_match_field="name", exact_match_value=entry_name
        )

        if isinstance(result, dict) and "data" in result:
            validate_unique_entry(result.get("data", []), f"name '{entry_name}'")

        return result
    except Exception as e:
        raise Exception(f"An error occurred while getting a vault entry: {e}")


def get_vault_entry_from_tag(server_base_url, token, vault_id, entry_tag):
    vault_url = f"{server_base_url}/api/v1/vault/{vault_id}/entry"
    vault_headers = {"Content-Type": "application/json", "tokenId": token}

    try:
        response = requests.get(
            vault_url, headers=vault_headers, params={"tag": entry_tag}
        )
        response.raise_for_status()

        result = response.json()
        return filter_folders(result)
    except Exception as e:
        raise Exception(f"An error occurred while getting a vault entry: {e}")


def get_vault_entry_from_path(server_base_url, token, vault_id, entry_path):
    vault_url = f"{server_base_url}/api/v1/vault/{vault_id}/entry"
    vault_headers = {"Content-Type": "application/json", "tokenId": token}

    try:
        response = requests.get(
            vault_url, headers=vault_headers, params={"path": entry_path}
        )
        response.raise_for_status()

        result = response.json()
        result = filter_folders(
            result, exact_match_field="path", exact_match_value=entry_path
        )

        if isinstance(result, dict) and "data" in result:
            validate_unique_entry(result.get("data", []), f"path '{entry_path}'")

        return result
    except Exception as e:
        raise Exception(f"An error occurred while getting a vault entry: {e}")


def get_vault_entry_from_type(server_base_url, token, vault_id, entry_type):
    vault_url = f"{server_base_url}/api/v1/vault/{vault_id}/entry"
    vault_headers = {"Content-Type": "application/json", "tokenId": token}

    try:
        response = requests.get(
            vault_url, headers=vault_headers, params={"type": entry_type}
        )
        response.raise_for_status()

        result = response.json()
        result = filter_folders(
            result, exact_match_field="type", exact_match_value=entry_type
        )

        if isinstance(result, dict) and "data" in result:
            validate_unique_entry(result.get("data", []), f"type '{entry_type}'")

        return result
    except Exception as e:
        raise Exception(f"An error occurred while getting a vault entry: {e}")


def get_vault_entries(server_base_url, token, vault_id):
    vault_url = f"{server_base_url}/api/v1/vault/{vault_id}/entry"
    vault_headers = {"Content-Type": "application/json", "tokenId": token}
    all_entries = []
    page = 1

    response = requests

    try:
        while True:
            response = requests.get(
                vault_url,
                headers=vault_headers,
                params={"pageNumber": page},
            )
            response.raise_for_status()
            json_data = response.json()
            if "data" not in json_data:
                raise ValueError(f"'data' key missing in response: {json_data}")
            entries = json_data.get("data", [])
            if not entries:
                break

            all_entries.extend(filter_folders(entries))

            if page >= json_data.get("totalPage", 0):
                break

            page += 1

        return all_entries
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

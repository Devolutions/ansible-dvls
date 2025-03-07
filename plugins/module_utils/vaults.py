import requests


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

        return response.json()
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

        return response.json()
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

        return response.json()
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

        return response.json()
    except Exception as e:
        raise Exception(f"An error occurred while getting a vault entry: {e}")


def get_vault_entries(server_base_url, token, vault_id):
    vault_url = f"{server_base_url}/api/v1/vault/{vault_id}/entry"
    vault_headers = {"Content-Type": "application/json", "tokenId": token}

    try:
        response = requests.get(vault_url, headers=vault_headers)
        response.raise_for_status()

        json_data = response.json()
        if "data" not in json_data:
            raise ValueError(f"'data' key missing in response: {json_data}")

        return json_data.get("data", [])
    except Exception as e:
        raise Exception(f"An error occurred while getting vault entries: {e}")


def find_entry_by_name(entries, name):
    for entry in entries:
        if entry.get("name") == name:
            return entry
    return None

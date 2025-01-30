import requests
import json

def get_vaults(server_base_url, token):
    vaults_url = f"{server_base_url}/api/v1/vault"
    vaults_headers = {
        "Content-Type": "application/json",
        "tokenId": token
    }

    try:
        response = requests.get(vaults_url, headers=vaults_headers)
        response.raise_for_status()

        json_data = response.json()
        if 'data' not in json_data:
            raise ValueError(f"'data' key missing in response: {json_data}")

        return json_data.get('data', [])
    except Exception as e:
        raise Exception(f"An error occurred while getting vaults: {e}")

def get_vault_entry(server_base_url, token, vault_id, entry_id):
    vault_url = f"{server_base_url}/api/v1/vault/{vault_id}/entry/{entry_id}"
    vault_headers = {
        "Content-Type": "application/json",
        "tokenId": token
    }

    try:
        response = requests.get(vault_url, headers=vault_headers)
        response.raise_for_status()

        return response.json()
    except Exception as e:
        raise Exception(f"An error occurred while getting a vault entry: {e}")

def get_vault_entries(server_base_url, token, vault_id):
    vault_url = f"{server_base_url}/api/v1/vault/{vault_id}/entry"
    vault_headers = {
        "Content-Type": "application/json",
        "tokenId": token
    }

    try:
        response = requests.get(vault_url, headers=vault_headers)
        response.raise_for_status()

        json_data = response.json()
        if 'data' not in json_data:
            raise ValueError(f"'data' key missing in response: {json_data}")

        return json_data.get('data', [])
    except Exception as e:
        raise Exception(f"An error occurred while getting vault entries: {e}")

def find_entry_by_name(entries, name):
    for entry in entries:
        if entry.get('name') == name:
            return entry
    return None
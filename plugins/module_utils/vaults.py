import requests
import json

def get_vaults(server_base_url, token):
    vaults_url = f"{server_base_url}/api/v1/vault"
    vaults_headers = {
        "Content-Type": "application/json",
        "tokenId": token
    }

    response = requests.get(vaults_url, headers=vaults_headers)
    try:
        result = response.json()
        return result.get('data', [])
    except ValueError:
        return []

def get_vault_entry(server_base_url, token, vault_id, entry_id):
    vault_url = f"{server_base_url}/api/v1/vault/{vault_id}/entry/{entry_id}"
    vault_headers = {
        "Content-Type": "application/json",
        "tokenId": token
    }

    response = requests.get(vault_url, headers=vault_headers)
    try:
        return response.json()
    except ValueError:
        return {}

def get_vault_entries(server_base_url, token, vault_id):
    vault_url = f"{server_base_url}/api/v1/vault/{vault_id}/entry"
    vault_headers = {
        "Content-Type": "application/json",
        "tokenId": token
    }

    response = requests.get(vault_url, headers=vault_headers)
    try:
        result = response.json()
        return result.get('data', [])
    except ValueError:
        return {}

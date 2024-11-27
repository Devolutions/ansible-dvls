#!/usr/bin/python

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = r'''
---
module: fetch_secrets

short_description: Fetch secrets from DVLS

description:
    - This module logs into the DVLS (Devolutions Server) service, retrieves specified secrets from a specified vault by name or ID.
    - The module requires DVLS application credentials, a server base URL, and either a secret name or ID.

options:
    server_base_url:
        description: The base URL of your DVLS.
        required: true
        type: str
    app_key:
        description: Application key for DVLS authentication.
        required: true
        type: str
    app_secret:
        description: Application secret for DVLS authentication.
        required: true
        type: str
    vault_id:
        description: The ID of the vault to access.
        required: true
        type: str
    secrets:
        description: A list of secrets to fetch. Each secret can be specified by name or ID.
        required: true
        type: list
        elements: dict
        suboptions:
            secret_name:
                description: The name of the secret to fetch.
                required: false
                type: str
            secret_id:
                description: The ID of the secret to fetch.
                required: false
                type: str

author:
    - Danny Bédard (@DannyBedard)
'''

EXAMPLES = r'''
# Fetch secrets from DVLS
- name: Fetch secrets
  devolutions.dvls.fetch_secrets:
    server_base_url: "https://example.yourcompagny.com"
    app_key: "{{ lookup('env', 'DVLS_APP_KEY') }}"
    app_secret: "{{ lookup('env', 'DVLS_APP_SECRET') }}"
    vault_id: "00000000-0000-0000-0000-000000000000"
    secrets:
      - secret_name: "my_secret_1"
      - secret_name: "my_secret_2"
      - secret_id: "12345678-1234-1234-1234-123456789012"
  register: secrets
'''

RETURN = r'''
secrets:
    description: The fetched secrets.
    type: dict
    returned: always
'''

from ansible.module_utils.basic import AnsibleModule
import os
import json
import requests

def login(server_base_url, app_key, app_secret):
    login_url = f"{server_base_url}/api/v1/login"
    login_data = {
        "appKey": app_key,
        "appSecret": app_secret
    }
    login_headers = {
        "Content-Type": "application/json"
    }

    response = requests.post(login_url, headers=login_headers, data=json.dumps(login_data))
    auth_response = response.json()
    token = auth_response.get('tokenId')

    if not token or token == "null":
        raise Exception("Failed to login or obtain token.")

    return token

def logout(server_base_url, token):
    logout_url = f"{server_base_url}/api/v1/logout"
    logout_headers = {
        "Content-Type": "application/json",
        "tokenId": token
    }

    requests.post(logout_url, headers=logout_headers)
    return None

def find_entry_by_name(entries, name):
    for entry in entries:
        if entry.get('name') == name:
            return entry
    return None

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

def run_module():
    module_args = dict(
        server_base_url=dict(type='str', required=True),
        app_key=dict(type='str', required=True),
        app_secret=dict(type='str', required=True),
        vault_id=dict(type='str', required=False),
        secrets=dict(
            type='list',
            elements='dict',
            options=dict(
                secret_name=dict(type='str', required=False),
                secret_id=dict(type='str', required=False)
            ),
            required=False
        )
    )

    result = dict()

    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=True
    )

    if module.check_mode:
        module.exit_json(**result)

    server_base_url = module.params['server_base_url']
    app_key = module.params['app_key']
    app_secret = module.params['app_secret']

    try:
        vault_id = module.params.get('vault_id')
        secrets = module.params.get('secrets')
    except Exception as e:
        module.fail_json(msg=str(e), **result)

    try:
        token = login(server_base_url, app_key, app_secret)

        entries = get_vault_entries(server_base_url, token, vault_id)
        fetched_secrets = {}

        if secrets:
            if not vault_id:
                module.fail_json(msg="Vault ID is required when specifying secrets.", **result)

            for secret in secrets:
                secret_name = secret.get('secret_name')
                secret_id = secret.get('secret_id')

                if not secret_name and not secret_id:
                    module.fail_json(msg="Each secret must have either a secret_name or a secret_id", **result)

                if secret_id:
                    entry = get_vault_entry(server_base_url, token, vault_id, secret_id)
                    fetched_secrets[secret_id] = entry['data']
                else:
                    entry = find_entry_by_name(entries, secret_name)
                    if not entry:
                        module.fail_json(msg=f"Secret '{secret_name}' not found", **result)
                    secret_id = entry['id']
                    entry = get_vault_entry(server_base_url, token, vault_id, secret_id)
                    fetched_secrets[secret_name] = entry['data']
        else:
            vaults = (
                [{'id': vault_id}]
                if vault_id else get_vaults(server_base_url, token)
            )

            for vault in vaults:
                vault_id = vault['id']
                entries = get_vault_entries(server_base_url, token, vault_id)
                fetched_secrets[vault_id] = {}

                for entry in entries:
                    entry_name = entry['name']
                    fetched_secrets[vault_id][entry_name] = entry['data']

        result = {'secrets': fetched_secrets}

    except Exception as e:
        module.fail_json(msg=str(e), **result)
    finally:
        logout(server_base_url, token)

    module.exit_json(**result)

def main():
    run_module()

if __name__ == '__main__':
    main()

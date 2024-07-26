#!/usr/bin/python

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = r'''
---
module: dvls

short_description: Fetch secrets from DVLS

description:
    - This module logs into the DVLS (Devolutions Vault) service, retrieves specified secrets from a specified vault by name or ID.
    - The module requires DVLS application credentials, a vault base URL, and either a secret name or ID.

options:
    vault_base_url:
        description: The base URL of the DVLS vault.
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
  dvls:
    vault_base_url: "https://dvls-ops.devolutions.com"
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

def login(vault_base_url, app_key, app_secret):
    login_url = f"{vault_base_url}/api/v1/login"
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

def get_vault_entry(vault_base_url, token, vault_id, entry_id):
    vault_url = f"{vault_base_url}/api/v1/vault/{vault_id}/entry/{entry_id}"
    vault_headers = {
        "Content-Type": "application/json",
        "tokenId": token
    }

    response = requests.get(vault_url, headers=vault_headers)
    return response.json()

def get_vault_entries(vault_base_url, token, vault_id):
    vault_url = f"{vault_base_url}/api/v1/vault/{vault_id}/entry"
    vault_headers = {
        "Content-Type": "application/json",
        "tokenId": token
    }

    response = requests.get(vault_url, headers=vault_headers)
    result = response.json()
    return result.get('data', [])

def handle_entry_type(entry):
    entry_type = entry.get('type')
    entry_subtype = entry.get('subType', '')

    if entry_type == 'Credential':
        if entry_subtype == 'ConnectionString':
            return handle_connection_string(entry)
        return handle_credential(entry)
    elif entry_type == 'ApiKey':
        return handle_apikey(entry)
    else:
        raise ValueError(f"Unknown entry type: {entry_type}")

def handle_credential(entry):
    return entry['data'].get('password')

def handle_apikey(entry):
    return entry['data'].get('apiId')

def handle_connection_string(entry):
    return entry['data'].get('connectionString')

def run_module():
    module_args = dict(
        vault_base_url=dict(type='str', required=True),
        app_key=dict(type='str', required=True),
        app_secret=dict(type='str', required=True),
        vault_id=dict(type='str', required=True),
        secrets=dict(
            type='list',
            elements='dict',
            options=dict(
                secret_name=dict(type='str', required=False),
                secret_id=dict(type='str', required=False)
            ),
            required=True
        )
    )

    result = dict(
        secrets={}
    )

    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=True
    )

    if module.check_mode:
        module.exit_json(**result)

    vault_base_url = module.params['vault_base_url']
    app_key = module.params['app_key']
    app_secret = module.params['app_secret']
    vault_id = module.params['vault_id']
    secrets = module.params['secrets']

    try:
        token = login(vault_base_url, app_key, app_secret)

        entries = get_vault_entries(vault_base_url, token, vault_id)
        fetched_secrets = {}

        for secret in secrets:
            secret_name = secret.get('secret_name')
            secret_id = secret.get('secret_id')

            if not secret_name and not secret_id:
                module.fail_json(msg="Each secret must have either a secret_name or a secret_id", **result)

            if secret_id:
                entry = get_vault_entry(vault_base_url, token, vault_id, secret_id)
                fetched_secrets[secret_id] = handle_entry_type(entry)
            else:
                entry = find_entry_by_name(entries, secret_name)
                if not entry:
                    module.fail_json(msg=f"Secret '{secret_name}' not found", **result)
                secret_id = entry['id']
                entry = get_vault_entry(vault_base_url, token, vault_id, secret_id)
                fetched_secrets[secret_name] = handle_entry_type(entry)

        result['secrets'] = fetched_secrets

    except Exception as e:
        module.fail_json(msg=str(e), **result)

    module.exit_json(**result)

def find_entry_by_name(entries, name):
    for entry in entries:
        if entry.get('name') == name:
            return entry
    return None

def main():
    run_module()

if __name__ == '__main__':
    main()

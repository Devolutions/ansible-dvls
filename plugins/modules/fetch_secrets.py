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
- name: Fetch secrets from DVLS
  devolutions.dvls.fetch_secrets:
    server_base_url: "https://example.yourcompany.com"
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
from ansible_collections.devolutions.dvls.plugins.module_utils.auth import login, logout
from ansible_collections.devolutions.dvls.plugins.module_utils.vaults import get_vaults, get_vault_entry, get_vault_entries, find_entry_by_name
import os
import json
import requests

def run_module():
    module_args = dict(
        server_base_url=dict(type='str', required=True),
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
            for secret in entries:
                entry_name = secret['name']
                entry = get_vault_entry(server_base_url, token, vault_id, secret['id'])
                fetched_secrets[entry_name] = entry['data']

        result = fetched_secrets

    except Exception as e:
        module.fail_json(msg=str(e), **result)
    finally:
        logout(server_base_url, token)

    module.exit_json(**result)

def main():
    run_module()

if __name__ == '__main__':
    main()

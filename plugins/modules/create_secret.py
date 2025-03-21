#!/usr/bin/python

DOCUMENTATION = r"""
---
module: create_secret

short_description: create or update a credential to DVLS

description:
    - Logs into the DVLS (Devolutions Server) service, checks if an entry exists at a given path, and updates or creates a Credential by name.
    - Requires DVLS application credentials, a server base URL and the data needed to create a secret.

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
    secret:
        description: the credential object, containing username and password.
        required: true
        type: dict
        suboptions:
            secret_name:
                description: the entry name/username.
                required: true
                type: str
            value:
                description: the password.
                required: true
                type: str
            secret_path:
                description: the (Folder-)Path where the secret should end up.
                required: false
                type: str
            secret_type:
                description: the type of secret that will get created.
                required: false
                type: str
                default: Credential
            secret_subtype:
                description: the secret subtype.
                required: false
                type: str
                default: Default
            secret_description:
                description: the description for the secret.
                required: false
                type: str

author:
    - Danny Bédard (@DannyBedard)
"""

EXAMPLES = r"""
- name: Upload Credential to DVLS
  devolutions.dvls.create_secret:
    server_base_url: "https://example.yourcompany.com"
    app_key: "{{ lookup('env', 'DVLS_APP_KEY') }}"
    app_secret: "{{ lookup('env', 'DVLS_APP_SECRET') }}"
    vault_id: "00000000-0000-0000-0000-000000000000"
    secret:
      secret_name: "my_secret_1"
      value: "p@ssw0rd1"
  register: secrets
"""

RETURN = r"""
id:
    description: returns the ID of the created/updated entry.
    type: dict
    returned: changed

"""

import traceback

from ansible.module_utils.basic import AnsibleModule, missing_required_lib
from ansible_collections.devolutions.dvls.plugins.module_utils.auth import login, logout
from ansible_collections.devolutions.dvls.plugins.module_utils.vaults import (
    get_vault_entries,
    find_entry_by_name,
)

try:
    import requests
except ImportError:
    HAS_REQUESTS_LIBRARY = False
    REQUESTS_LIBRARY_IMPORT_ERROR = traceback.format_exc()
else:
    HAS_REQUESTS_LIBRARY = True
    REQUESTS_LIBRARY_IMPORT_ERROR = None


def run_module():
    argument_spec = dict(
        server_base_url=dict(type="str", required=True),
        app_key=dict(type="str", required=True, no_log=True),
        app_secret=dict(type="str", required=True, no_log=True),
        vault_id=dict(type="str", required=True),
        secret=dict(
            type="dict",
            options=dict(
                secret_name=dict(type="str", required=True, no_log=False),
                value=dict(type="str", required=True, no_log=True),
                secret_path=dict(type="str", required=False, no_log=False),
                secret_type=dict(
                    type="str", required=False, default="Credential", no_log=False
                ),
                secret_subtype=dict(
                    type="str", required=False, default="Default", no_log=False
                ),
                secret_description=dict(type="str", required=False, no_log=False),
            ),
            required=True,
            no_log=False,
        ),
    )

    result = dict()

    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)

    if not HAS_REQUESTS_LIBRARY:
        module.fail_json(
            msg=missing_required_lib("requests"),
            exception=REQUESTS_LIBRARY_IMPORT_ERROR,
        )

    if module.check_mode:
        module.exit_json(**result)

    server_base_url = module.params["server_base_url"]
    app_key = module.params["app_key"]
    app_secret = module.params["app_secret"]

    secret = module.params.get("secret")
    secret_name = secret.get("secret_name")
    password = secret.get("value")
    secret_type = secret.get("secret_type")
    secret_subtype = secret.get("secret_subtype")
    secret_path = secret.get("secret_path")
    description = secret.get("secret_description")

    vault_id = module.params.get("vault_id")

    try:
        token = login(server_base_url, app_key, app_secret)
        entries = get_vault_entries(server_base_url, token, vault_id)

        vault_headers = {"Content-Type": "application/json", "tokenId": token}

        vault_body = {
            "name": secret_name,
            "type": secret_type,
            "subtype": secret_subtype,
            "path": secret_path,
            "description": description,
            "data": {"username": secret_name, "password": password},
        }

        # this filters the response by path (folder)
        path_entries = (
            [entry for entry in entries if entry.get("path") == secret_path]
            if secret_path
            else entries
        )

        # when an existing entry is found, it gets updated. Otherwise a new entry gets created
        entry = find_entry_by_name(path_entries, secret_name)
        if entry:
            vault_url = f"{server_base_url}/api/v1/vault/{vault_id}/entry/{entry['id']}"
            response = requests.put(vault_url, headers=vault_headers, json=vault_body)
            response.raise_for_status()
            result["id"] = entry["id"]
        else:
            vault_url = f"{server_base_url}/api/v1/vault/{vault_id}/entry"
            response = requests.post(vault_url, headers=vault_headers, json=vault_body)
            response.raise_for_status()
            result["id"] = response.json()["id"]

        result["changed"] = True

    except Exception as e:
        module.fail_json(msg=str(e), **result)
    finally:
        logout(server_base_url, token)

    module.exit_json(**result)


def main():
    run_module()


if __name__ == "__main__":
    main()

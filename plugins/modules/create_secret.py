#!/usr/bin/python

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: create_secret

short_description: create or update a credential to DVLS

description:
    - Logs into the DVLS (Devolutions Server) service, checks if an entry exists at a given path, and updates or creates a Credential by name.
    - Requires DVLS application credentials, a server base URL and the data needed to create a secret.

options:
    server_base_url:
        description:
            - The base URL of your DVLS.
            - Falls back to the DVLS_SERVER_BASE_URL environment variable.
        required: true
        type: str
    app_key:
        description:
            - Application key for DVLS authentication.
            - Falls back to the DVLS_APP_KEY environment variable.
        required: true
        type: str
    app_secret:
        description:
            - Application secret for DVLS authentication.
            - Falls back to the DVLS_APP_SECRET environment variable.
        required: true
        type: str
    vault_id:
        description:
            - The ID of the vault to access.
            - Falls back to the DVLS_VAULT_ID environment variable.
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

    validate_certs:
        description: Whether to verify the TLS certificate of the DVLS server.
        required: false
        type: bool
        default: true
    ca_path:
        description: Path to a CA bundle used to verify the DVLS certificate.
        required: false
        type: path
    timeout:
        description: Timeout in seconds for each HTTP request to DVLS.
        required: false
        type: int
        default: 30

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

from ansible.module_utils.basic import (
    AnsibleModule,
    env_fallback,
    missing_required_lib,
)
from ansible_collections.devolutions.dvls.plugins.module_utils.auth import login, logout
from ansible_collections.devolutions.dvls.plugins.module_utils.http import (
    HAS_REQUESTS_LIBRARY,
    REQUESTS_LIBRARY_IMPORT_ERROR,
    configure as configure_http,
    request as http_request,
)
from ansible_collections.devolutions.dvls.plugins.module_utils.vaults import (
    get_vault_entries,
    find_entry_by_name,
)


def raise_for_dvls_error(response):
    if response.ok:
        return

    raise Exception(
        f"{response.status_code} {response.reason} from {response.url}: {response.text[:500]}"
    )


def run_module():
    argument_spec = dict(
        server_base_url=dict(
            type="str", required=True, fallback=(env_fallback, ["DVLS_SERVER_BASE_URL"])
        ),
        app_key=dict(
            type="str",
            required=True,
            no_log=True,
            fallback=(env_fallback, ["DVLS_APP_KEY"]),
        ),
        app_secret=dict(
            type="str",
            required=True,
            no_log=True,
            fallback=(env_fallback, ["DVLS_APP_SECRET"]),
        ),
        validate_certs=dict(type="bool", required=False, default=True),
        ca_path=dict(type="path", required=False),
        timeout=dict(type="int", required=False, default=30),
        vault_id=dict(
            type="str", required=True, fallback=(env_fallback, ["DVLS_VAULT_ID"])
        ),
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

    configure_http(
        timeout=module.params["timeout"],
        validate_certs=module.params["validate_certs"],
        ca_path=module.params["ca_path"],
    )

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
    description = secret.get("secret_description")

    if secret.get("secret_path") is None:
        secret_path = ""
    else:
        secret_path = secret.get("secret_path")

    vault_id = module.params.get("vault_id")

    token = None

    try:
        token = login(server_base_url, app_key, app_secret)
        entries = get_vault_entries(server_base_url, token, vault_id)

        vault_headers = {"Content-Type": "application/json", "tokenId": token}

        vault_body = {
            "name": secret_name,
            "type": secret_type,
            "subType": secret_subtype,
            "path": secret_path,
            "description": description or "",
            "tags": [],
            "data": {"username": secret_name, "password": password},
        }

        # this filters the response by path (folder)
        path_entries = (
            [entry for entry in entries if entry.get("path") == secret_path]
            if secret_path
            else entries
        )

        entry = find_entry_by_name(path_entries, secret_name, secret_path)
        if entry:
            vault_body["tags"] = entry.get("tags") or []
            vault_url = f"{server_base_url}/api/v1/vault/{vault_id}/entry/{entry['id']}"
            response = http_request(
                "PUT", vault_url, headers=vault_headers, json=vault_body
            )
            raise_for_dvls_error(response)
            result["id"] = entry["id"]
        else:
            vault_url = f"{server_base_url}/api/v1/vault/{vault_id}/entry"
            response = http_request(
                "POST", vault_url, headers=vault_headers, json=vault_body
            )
            raise_for_dvls_error(response)
            result["id"] = response.json()["id"]

        result["changed"] = True

    except Exception as e:
        module.fail_json(msg=str(e), **result)
    finally:
        if token:
            try:
                logout(server_base_url, token)
            except Exception:
                module.warn("Failed to log out from DVLS.")

    module.exit_json(**result)


def main():
    run_module()


if __name__ == "__main__":
    main()

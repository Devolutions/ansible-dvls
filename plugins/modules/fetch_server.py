#!/usr/bin/python

DOCUMENTATION = r"""
---
module: fetch_server

short_description: Fetch server from DVLS

description:
    - Logs into the DVLS (Devolutions Server) service, retrieves server information and vaults list.
    - Requires DVLS application credentials and a server base URL.

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

author:
    - Danny Bédard (@DannyBedard)
"""

EXAMPLES = r"""
- name: Fetch dvls server information
  devolutions.dvls.fetch_server:
    server_base_url: "https://example.yourcompany.com"
    app_key: "{{ lookup('env', 'DVLS_APP_KEY') }}"
    app_secret: "{{ lookup('env', 'DVLS_APP_SECRET') }}"
  register: server
"""

RETURN = r"""
secrets:
    description: The server vaults and information.
    type: dict
    returned: always
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.devolutions.dvls.plugins.module_utils.auth import login, logout
from ansible_collections.devolutions.dvls.plugins.module_utils.vaults import get_vaults
from ansible_collections.devolutions.dvls.plugins.module_utils.server import (
    public_instance_information,
    private_instance_information,
)


def run_module():
    argument_spec = dict(
        server_base_url=dict(type="str", required=True),
        app_key=dict(type="str", required=True, no_log=True),
        app_secret=dict(type="str", required=True, no_log=True),
    )

    result = dict()

    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)

    if module.check_mode:
        module.exit_json(**result)

    server_base_url = module.params["server_base_url"]
    app_key = module.params["app_key"]
    app_secret = module.params["app_secret"]

    try:
        token = login(server_base_url, app_key, app_secret)
        vaults = get_vaults(server_base_url, token)

        public_info = public_instance_information(server_base_url, token)
        private_info = private_instance_information(server_base_url, token)

        if "version" not in public_info["data"]:
            raise KeyError("version missing from fetched server']")
        if "accessURI" not in private_info["data"]:
            raise KeyError("accessURI missing from fetched server")

        result = {
            "version": public_info["data"].get("version"),
            "accessURI": private_info["data"].get("accessURI"),
            "vaults": vaults,
        }

    except KeyError as ke:
        module.fail_json(msg=f"Missing expected data from server: {str(ke)}", **result)
    except Exception as e:
        module.fail_json(msg=str(e), **result)
    finally:
        logout(server_base_url, token)

    module.exit_json(**result)


def main():
    run_module()


if __name__ == "__main__":
    main()

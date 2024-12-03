#!/usr/bin/python

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = r'''
---
module: fetch_server

short_description: Fetch server from DVLS

description:
    - This module logs into the DVLS (Devolutions Server) service, retrieves server information and vaults list.
    - The module requires DVLS application credentials and a server base URL.

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
'''

EXAMPLES = r'''
- name: Fetch dvls server information
    server:
    server_base_url: "https://dvls-ops.devolutions.com"
    app_key: "{{ lookup('env', 'DVLS_APP_KEY') }}"
    app_secret: "{{ lookup('env', 'DVLS_APP_SECRET') }}"
    register: server
'''

RETURN = r'''
secrets:
    description: The server vaults and information.
    type: dict
    returned: always
'''

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.devolutions.dvls.plugins.module_utils.auth import login, logout
from ansible_collections.devolutions.dvls.plugins.module_utils.vaults import get_vaults
from ansible_collections.devolutions.dvls.plugins.module_utils.server import public_instance_information, private_instance_information
import os
import json
import requests

def run_module():
    module_args = dict(
        server_base_url=dict(type='str', required=True),
        app_key=dict(type='str', required=True),
        app_secret=dict(type='str', required=True),
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
        token = login(server_base_url, app_key, app_secret)
        vaults = get_vaults(server_base_url, token)

        public_info = public_instance_information(server_base_url, token)
        private_info = private_instance_information(server_base_url, token)

        result = {
            'expirationDate': public_info['data'].get('expirationDate'),
            'version': public_info['data'].get('version'),
            'accessURI': private_info['data'].get('accessURI'),
            'vaults': vaults
        }

    except Exception as e:
        module.fail_json(msg=str(e), **result)
    finally:
        logout(server_base_url, token)

    module.exit_json(**result)

def main():
    run_module()

if __name__ == '__main__':
    main()

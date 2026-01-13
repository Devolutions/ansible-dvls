# GNU General Public License v3.0+ (see LICENSE-GPL-3 or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
name: secret_full
author: Dion Gionet Mallet (@dion-gionet)
version_added: "1.3.0"
short_description: Retrieve complete DVLS credential object
description:
  - Fetches entire credential object from Devolutions Server (DVLS).
  - Returns same structure as fetch_secrets module.
  - Supports lookup by credential name or UUID.
  - Useful when multiple fields from the same credential are needed.
options:
  _terms:
    description:
      - Credential identifier (name or UUID) to retrieve.
    required: true
    type: str
  server_base_url:
    description:
      - DVLS server base URL.
      - Falls back to DVLS_SERVER_BASE_URL environment variable if not provided.
    type: str
    required: false
  app_key:
    description:
      - Application key for authentication.
      - Falls back to DVLS_APP_KEY environment variable if not provided.
    type: str
    required: false
  app_secret:
    description:
      - Application secret for authentication.
      - Falls back to DVLS_APP_SECRET environment variable if not provided.
    type: str
    required: false
  vault_id:
    description:
      - Vault UUID containing the credential.
      - Falls back to DVLS_VAULT_ID environment variable if not provided.
    type: str
    required: false
notes:
  - Requires network access to DVLS server.
  - Authentication token is cached for the duration of the playbook run.
  - Returns the complete credential object with all available fields.
"""

EXAMPLES = r"""
# Retrieve full credential object
- name: Get complete database credential
  debug:
    msg: "{{ lookup('devolutions.dvls.secret_full', 'prod-database') }}"

# Use multiple fields from credential
- name: Configure database connection
  set_fact:
    db_cred: "{{ lookup('devolutions.dvls.secret_full', 'prod-db') }}"

- name: Connect to database
  postgresql_db:
    name: mydb
    login_host: "{{ db_cred.domain }}"
    login_user: "{{ db_cred.username }}"
    login_password: "{{ db_cred.password }}"

# Azure Service Principal example
- name: Get Azure credentials
  set_fact:
    azure_sp: "{{ lookup('devolutions.dvls.secret_full', 'azure-prod-sp') }}"

- name: Use Azure credentials
  debug:
    msg: "Tenant: {{ azure_sp.tenantId }}, Client: {{ azure_sp.clientId }}"

# SSH Key example
- name: Get SSH credentials
  set_fact:
    ssh_cred: "{{ lookup('devolutions.dvls.secret_full', 'server-ssh-key') }}"

- name: Use SSH key
  ansible.builtin.copy:
    content: "{{ ssh_cred.privateKeyData }}"
    dest: ~/.ssh/id_rsa
    mode: '0600'

# API Key example
- name: Get API credentials
  set_fact:
    api_cred: "{{ lookup('devolutions.dvls.secret_full', 'external-api') }}"

- name: Call API
  uri:
    url: "https://api.example.com/endpoint"
    headers:
      X-API-ID: "{{ api_cred.apiId }}"
      X-API-KEY: "{{ api_cred.apiKey }}"
"""

RETURN = r"""
_raw:
  description: Complete credential object with all fields.
  type: list
  elements: dict
"""

from ansible.errors import AnsibleError
from ansible.plugins.lookup import LookupBase
from ansible.utils.display import Display

try:
    from ansible_collections.devolutions.dvls.plugins.module_utils.lookup_base import (
        DVLSLookupHelper,
    )
except ImportError as e:
    raise AnsibleError(f"Failed to import DVLS module_utils: {e}")

display = Display()


class LookupModule(LookupBase):
    """Lookup plugin to retrieve complete DVLS credential objects."""

    def __init__(self, *args, **kwargs):
        super(LookupModule, self).__init__(*args, **kwargs)
        self._helper = DVLSLookupHelper(display, AnsibleError)

    def run(self, terms, variables=None, **kwargs):
        """
        Main lookup execution method.

        Handles authentication, credential retrieval, and result transformation.
        """
        self.set_options(var_options=variables, direct=kwargs)

        config = self._helper.get_config(self.get_option, variables)
        self._helper.authenticate(
            config["server_base_url"], config["app_key"], config["app_secret"]
        )

        results = []
        for term in terms:
            try:
                credential = self._helper.get_credential(
                    config["server_base_url"], config["vault_id"], term
                )
                display.vvv(f"Successfully retrieved credential '{term}'")
                results.append(credential)

            except AnsibleError:
                raise
            except Exception as e:
                raise AnsibleError(
                    f"Failed to retrieve credential '{term}': {e}"
                ) from e

        return results

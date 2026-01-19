# GNU General Public License v3.0+ (see LICENSE-GPL-3.0 or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
name: secret
author: Dion Gionet Mallet (@dion-gionet)
version_added: "1.3.0"
short_description: Retrieve a specific field from a DVLS credential
description:
  - Fetches a single field value from a Devolutions Server (DVLS) credential entry.
  - Supports lookup by credential name, path, or UUID.
  - Credentials retrieved from specified vault using application authentication.
options:
  _terms:
    description:
      - Credential identifier (name, path, or UUID) to retrieve.
      - "Path format: 'folder\\\\subfolder\\\\credential-name'"
    required: true
    type: str
  field:
    description:
      - Field name to extract from credential.
      - Supported fields depend on credential type.
      - "Common fields include: username, password, domain, connectionString,"
      - "apiId, apiKey, tenantId, clientId, clientSecret, privateKeyData,"
      - "publicKeyData, privateKeyPassPhrase."
    type: str
    default: password
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
"""

EXAMPLES = r"""
# Retrieve password field (default)
- name: Get database password
  debug:
    msg: "{{ lookup('devolutions.dvls.secret', 'prod-database') }}"

# Retrieve specific field
- name: Get database username
  debug:
    msg: "{{ lookup('devolutions.dvls.secret', 'prod-database', field='username') }}"

# Lookup by path
- name: Get credential by full path
  debug:
    msg: "{{ lookup('devolutions.dvls.secret', 'Production\\\\Database\\\\prod-db') }}"

# Lookup by path with specific field
- name: Get username from path-specified credential
  debug:
    msg: "{{ lookup('devolutions.dvls.secret', 'Production\\\\Database\\\\prod-db', field='username') }}"

# Lookup by UUID
- name: Get API key by ID
  debug:
    msg: "{{ lookup('devolutions.dvls.secret', '12345678-1234-1234-1234-123456789012', field='apiKey') }}"

# Use in variable assignment
- name: Set database credentials
  set_fact:
    db_user: "{{ lookup('devolutions.dvls.secret', 'prod-db', field='username') }}"
    db_pass: "{{ lookup('devolutions.dvls.secret', 'prod-db', field='password') }}"

# Use path to avoid name conflicts
- name: Get specific credential when multiple have same name
  set_fact:
    staging_pass: "{{ lookup('devolutions.dvls.secret', 'Staging\\\\Database\\\\api-db', field='password') }}"
    prod_pass: "{{ lookup('devolutions.dvls.secret', 'Production\\\\Database\\\\api-db', field='password') }}"

# Override server configuration
- name: Get credential from specific server
  debug:
    msg: "{{ lookup('devolutions.dvls.secret', 'my-cred',
              server_base_url='https://dvls.example.com',
              app_key='my-key',
              app_secret='my-secret',
              vault_id='vault-uuid',
              field='password') }}"

# Use in template
- name: Configure database connection
  template:
    src: database.conf.j2
    dest: /etc/database.conf
  vars:
    db_password: "{{ lookup('devolutions.dvls.secret', 'prod-db') }}"
"""

RETURN = r"""
_raw:
  description: The requested field value from the credential.
  type: list
  elements: str
"""

from ansible.errors import AnsibleError
from ansible.plugins.lookup import LookupBase
from ansible.utils.display import Display

try:
    from ansible_collections.devolutions.dvls.plugins.module_utils.lookup_base import (
        DVLSLookupHelper,
        SUPPORTED_CREDENTIAL_FIELDS,
    )
except ImportError as e:
    raise AnsibleError(f"Failed to import DVLS module_utils: {e}")

display = Display()


class LookupModule(LookupBase):
    """Lookup plugin to retrieve a specific field from a DVLS credential."""

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
                result = self._transform_result(credential, term)
                results.append(result)

            except AnsibleError:
                raise
            except Exception as e:
                raise AnsibleError(
                    f"Failed to retrieve credential '{term}': {e}"
                ) from e

        return results

    def _transform_result(self, credential, term):
        """
        Extract a specific field from the credential.

        Args:
            credential: Complete credential object from DVLS
            term: Original lookup term

        Returns:
            str: The requested field value
        """
        field = self.get_option("field") or "password"

        if field not in SUPPORTED_CREDENTIAL_FIELDS:
            raise AnsibleError(
                f"Invalid field '{field}'. "
                f"Supported fields: {', '.join(sorted(SUPPORTED_CREDENTIAL_FIELDS))}"
            )

        field_value = credential.get(field)
        if field_value is None:
            raise AnsibleError(
                f"Field '{field}' not found in credential '{term}'. "
                f"Available fields: {', '.join(credential.keys())}"
            )

        display.vvv(f"Successfully retrieved field '{field}' from '{term}'")
        return field_value

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import atexit
import os
import re

try:
    from ansible_collections.devolutions.dvls.plugins.module_utils.auth import (
        login,
        logout,
    )
    from ansible_collections.devolutions.dvls.plugins.module_utils.vaults import (
        get_vault_entry,
        get_vault_entry_from_name,
    )
except ImportError:
    # Will be caught by lookup plugins
    pass

UUID_PATTERN = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)

SUPPORTED_CREDENTIAL_FIELDS = {
    "username",
    "password",
    "domain",
    "connectionString",
    "apiId",
    "apiKey",
    "tenantId",
    "clientId",
    "clientSecret",
    "privateKeyData",
    "publicKeyData",
    "privateKeyPassPhrase",
}


class DVLSLookupHelper:
    """Helper class for DVLS lookup plugins with shared authentication and retrieval logic."""

    def __init__(self, display_instance, ansible_error_class):
        """
        Initialize the helper.

        Args:
            display_instance: Display instance for logging
            ansible_error_class: AnsibleError class for raising exceptions
        """
        self._token = None
        self._server_base_url = None
        self._cleanup_registered = False
        self._display = display_instance
        self._ansible_error = ansible_error_class

    def _cleanup(self):
        """Cleanup method called at interpreter exit"""
        if self._token and self._server_base_url:
            try:
                self._display.vvv("Logging out from DVLS")
                logout(self._server_base_url, self._token)
            except Exception as e:
                self._display.warning(f"Failed to logout from DVLS during cleanup: {e}")

    def _is_uuid(self, value):
        """Check if a string matches UUID format"""
        return UUID_PATTERN.match(value) is not None

    def get_config(self, get_option, variables):
        """Extract configuration from options and environment variables"""
        server_base_url = get_option("server_base_url") or os.environ.get(
            "DVLS_SERVER_BASE_URL"
        )
        app_key = get_option("app_key") or os.environ.get("DVLS_APP_KEY")
        app_secret = get_option("app_secret") or os.environ.get("DVLS_APP_SECRET")
        vault_id = get_option("vault_id") or os.environ.get("DVLS_VAULT_ID")

        if not all([server_base_url, app_key, app_secret, vault_id]):
            raise self._ansible_error(
                "Missing required configuration. Set DVLS_SERVER_BASE_URL, DVLS_APP_KEY, "
                "DVLS_APP_SECRET, and DVLS_VAULT_ID environment variables or pass as parameters."
            )

        return {
            "server_base_url": server_base_url,
            "app_key": app_key,
            "app_secret": app_secret,
            "vault_id": vault_id,
        }

    def authenticate(self, server_base_url, app_key, app_secret):
        """Authenticate to DVLS and cache the token"""
        if not self._token:
            try:
                self._display.vvv(f"Authenticating to DVLS at {server_base_url}")
                self._token = login(server_base_url, app_key, app_secret)
                self._server_base_url = server_base_url

                if not self._cleanup_registered:
                    atexit.register(self._cleanup)
                    self._cleanup_registered = True
            except Exception as e:
                raise self._ansible_error(f"DVLS authentication failed: {e}") from e

    def get_credential(self, server_base_url, vault_id, term):
        """
        Retrieve a credential from DVLS by name or UUID.

        Args:
            server_base_url: DVLS server base URL
            vault_id: Vault UUID
            term: Credential identifier (name or UUID)

        Returns:
            dict: Complete credential object
        """
        self._display.vvv(f"Looking up credential: {term}")

        if self._is_uuid(term):
            self._display.vvv(f"Using ID lookup for {term}")
            response = get_vault_entry(server_base_url, self._token, vault_id, term)
            credential = response.get("data", {})
        else:
            self._display.vvv(f"Using name lookup for {term}")
            response = get_vault_entry_from_name(
                server_base_url, self._token, vault_id, term
            )
            entries = response.get("data", [])
            if not entries:
                raise self._ansible_error(
                    f"Credential '{term}' not found in vault {vault_id}"
                )
            entry_id = entries[0].get("id")
            full_response = get_vault_entry(
                server_base_url, self._token, vault_id, entry_id
            )
            credential = full_response.get("data", {})

        return credential

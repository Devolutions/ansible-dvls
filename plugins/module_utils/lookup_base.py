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
        get_vault_entry_from_path,
        validate_unique_entry,
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

_token_cache = {}
_cleanup_registered = False
_display = None


class DVLSLookupHelper:
    """Helper class for DVLS lookup plugins with shared authentication and retrieval logic."""

    def __init__(self, display_instance, ansible_error_class):
        """
        Initialize the helper.

        Args:
            display_instance: Display instance for logging
            ansible_error_class: AnsibleError class for raising exceptions
        """
        global _display
        self._display = display_instance
        self._ansible_error = ansible_error_class
        _display = display_instance

    @staticmethod
    def _cleanup_tokens():
        """Cleanup method called at interpreter exit to logout all cached tokens"""
        for server_url, token in _token_cache.items():
            try:
                logout(server_url, token)
            except (ConnectionError, TimeoutError, OSError):
                pass
            except Exception as e:
                _display.warning(f"Failed to logout from {server_url}: {e}")
        _token_cache.clear()

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
        """Authenticate to DVLS and cache the token at module level"""
        global _cleanup_registered

        if server_base_url not in _token_cache:
            try:
                self._display.vvv(f"Authenticating to DVLS at {server_base_url}")
                token = login(server_base_url, app_key, app_secret)
                _token_cache[server_base_url] = token

                if not _cleanup_registered:
                    atexit.register(DVLSLookupHelper._cleanup_tokens)
                    _cleanup_registered = True
            except Exception as e:
                raise self._ansible_error(f"DVLS authentication failed: {e}") from e
        else:
            self._display.vvv(f"Using cached token for {server_base_url}")

    def get_credential(self, server_base_url, vault_id, term):
        """
        Retrieve a credential from DVLS by name, path, or UUID.

        Args:
            server_base_url: DVLS server base URL
            vault_id: Vault UUID
            term: Credential identifier (name, path, or UUID)

        Returns:
            dict: Complete credential object
        """
        self._display.vvv(f"Looking up credential: {term}")
        token = _token_cache.get(server_base_url)
        if not token:
            raise self._ansible_error(
                f"Authentication token not found for server '{server_base_url}'. "
                "Ensure authenticate() was called first."
            )

        if self._is_uuid(term):
            self._display.vvv(f"Using ID lookup for {term}")
            response = get_vault_entry(server_base_url, token, vault_id, term)
            credential = response.get("data", {})
        elif "\\" in term:
            self._display.vvv(f"Using path lookup for {term}")
            response = get_vault_entry_from_path(
                server_base_url, token, vault_id, term
            )
            entries = response.get("data", [])
            if not entries:
                raise self._ansible_error(
                    f"Credential at path '{term}' not found in vault {vault_id}"
                )
            validate_unique_entry(entries, f"path '{term}'")
            entry_id = entries[0].get("id")
            if not entry_id:
                raise self._ansible_error(
                    f"Entry at path '{term}' is missing required 'id' field"
                )
            full_response = get_vault_entry(
                server_base_url, token, vault_id, entry_id
            )
            credential = full_response.get("data", {})
        else:
            self._display.vvv(f"Using name lookup for {term}")
            response = get_vault_entry_from_name(
                server_base_url, token, vault_id, term
            )
            entries = response.get("data", [])
            if not entries:
                raise self._ansible_error(
                    f"Credential '{term}' not found in vault {vault_id}"
                )
            validate_unique_entry(entries, f"name '{term}'")
            entry_id = entries[0].get("id")
            if not entry_id:
                raise self._ansible_error(
                    f"Entry for '{term}' is missing required 'id' field"
                )
            full_response = get_vault_entry(
                server_base_url, token, vault_id, entry_id
            )
            credential = full_response.get("data", {})

        if not credential:
            raise self._ansible_error(
                f"Credential '{term}' returned empty data from vault {vault_id}"
            )

        return credential

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import atexit
import os
import re

try:
    from ansible_collections.devolutions.dvls.plugins.module_utils.auth import (
        Session,
    )
    from ansible_collections.devolutions.dvls.plugins.module_utils.http import (
        configure as http_configure,
    )
    from ansible_collections.devolutions.dvls.plugins.module_utils.vaults import (
        get_vault_entry,
        get_vault_entry_from_full_path,
        get_vault_entry_from_name,
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
    "privateKeyOverrideUsername",
    "privateKeyOverridePassword",
}

_session_cache = {}
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
    def _cleanup_sessions():
        """Cleanup method called at interpreter exit to logout all cached sessions"""
        for (server_url, _app_key), (_app_secret, session) in _session_cache.items():
            try:
                session.logout()
            except (ConnectionError, TimeoutError, OSError):
                pass
            except Exception as e:
                _display.warning(f"Failed to logout from {server_url}: {e}")
        _session_cache.clear()

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

        http_configure(
            timeout=get_option("timeout"),
            validate_certs=get_option("validate_certs"),
            ca_path=get_option("ca_path"),
        )

        return {
            "server_base_url": server_base_url,
            "app_key": app_key,
            "app_secret": app_secret,
            "vault_id": vault_id,
        }

    def authenticate(self, server_base_url, app_key, app_secret):
        """Authenticate to DVLS and return the session, cached at module level per server and
        application identity"""
        global _cleanup_registered

        # A session is reused only for the same identity and secret: another identity must never
        # read with this one's rights, and a rotated secret must log in again.
        cache_key = (server_base_url, app_key)
        cached = _session_cache.get(cache_key)
        if cached is not None and cached[0] == app_secret:
            self._display.vvv(f"Using cached session for {server_base_url}")
            return cached[1]

        try:
            self._display.vvv(f"Authenticating to DVLS at {server_base_url}")
            session = Session(server_base_url, app_key, app_secret)
            session.login()
        except Exception as e:
            raise self._ansible_error(f"DVLS authentication failed: {e}") from e

        if cached is not None:
            try:
                cached[1].logout()
            except Exception:
                pass
        _session_cache[cache_key] = (app_secret, session)

        if not _cleanup_registered:
            atexit.register(DVLSLookupHelper._cleanup_sessions)
            _cleanup_registered = True

        return session

    def get_credential(self, session, vault_id, term):
        """
        Retrieve a credential from DVLS by name, path, or UUID.

        Args:
            session: Session returned by authenticate()
            vault_id: Vault UUID
            term: Credential identifier (name, full path 'folder\\name', or UUID)

        Returns:
            dict: Complete credential object
        """
        self._display.vvv(f"Looking up credential: {term}")

        if self._is_uuid(term):
            self._display.vvv(f"Using ID lookup for {term}")
            response = get_vault_entry(session, vault_id, term)
            credential = response.get("data", {})
        elif "\\" in term:
            self._display.vvv(f"Using path lookup for {term}")
            response = get_vault_entry_from_full_path(session, vault_id, term)
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
            full_response = get_vault_entry(session, vault_id, entry_id)
            credential = full_response.get("data", {})
        else:
            self._display.vvv(f"Using name lookup for {term}")
            response = get_vault_entry_from_name(session, vault_id, term)
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
            full_response = get_vault_entry(session, vault_id, entry_id)
            credential = full_response.get("data", {})

        if not credential:
            raise self._ansible_error(
                f"Credential '{term}' returned empty data from vault {vault_id}"
            )

        return credential

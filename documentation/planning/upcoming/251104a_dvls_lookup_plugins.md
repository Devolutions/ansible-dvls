# DVLS Lookup Plugins Implementation

**Status**: Upcoming
**Created**: 2025-11-04
**Last Updated**: 2025-11-04

## Goal & Context

Implement two complementary Ansible lookup plugins for the `devolutions.dvls` collection to enable idiomatic, inline credential retrieval from DVLS vaults. Currently, the collection only provides task-based modules (`fetch_secrets`, `create_secret`, `fetch_server`) which require full task definitions and return complete objects. Lookup plugins will allow direct variable assignment and templating, matching patterns from industry-standard PAM integrations (1Password, HashiCorp Vault, Delinea, LastPass).

**Problem**: Users need a more flexible, Ansible-native way to retrieve credentials inline within playbooks and templates, rather than using full module tasks.

**Solution**: Two lookup plugins:
1. `devolutions.dvls.secret` - Field-specific lookup (returns single field value)
2. `devolutions.dvls.secret_full` - Full object lookup (returns complete credential structure)

## References

- `plugins/modules/fetch_secrets.py` - Existing module implementation with authentication and vault query patterns
- `plugins/module_utils/auth.py` - Authentication logic to reuse (login/logout functions)
- `plugins/module_utils/vaults.py` - Vault entry retrieval functions
- [Ansible Lookup Plugin Development](https://docs.ansible.com/ansible/latest/dev_guide/developing_plugins.html#lookup-plugins) - Official plugin development guide
- [LastPass Lookup Plugin](https://docs.ansible.com/ansible/latest/collections/community/general/lastpass_lookup.html) - Reference implementation pattern
- `documentation/reference/` - Collection coding standards and security requirements

## Principles & Key Decisions

- **Idiomatic Ansible**: Follow Ansible lookup plugin conventions (inherit from `LookupBase`, return lists, use `AnsibleError` for failures)
- **Consistency with Modules**: Reuse authentication logic, maintain same credential structure as `fetch_secrets` module
- **Security First**: Support `no_log` for sensitive parameters, never log credentials, sanitize error messages
- **Performance**: Cache authentication tokens within lookup session to avoid repeated login calls
- **Flexibility**: Support both environment variables (default) and explicit parameters for configuration
- **Clear Error Messages**: Provide actionable troubleshooting guidance in all error scenarios

**Key Decision: Two Plugins vs. One**
- Separate plugins provide clearer intent and simpler syntax for common use case (field retrieval)
- Avoids parameter complexity and maintains clean API surface
- Follows precedent from other PAM integrations (1Password has similar split)

**Key Decision: Authentication Caching**
- Cache tokens per lookup plugin instance to reduce API calls
- Implement logout in plugin cleanup to maintain security
- Balance between performance and token lifecycle management

## Technical Architecture

### Plugin Structure

```
plugins/lookup/
├── secret.py          # Field-specific lookup
└── secret_full.py     # Full object lookup
```

### Data Flow

```
Playbook Variable → Lookup Plugin → Authentication (cached) → DVLS API → Field Extraction → Return Value
```

### Authentication Strategy

**Priority Order**:
1. Explicit plugin parameters (`server_base_url`, `app_key`, `app_secret`, `vault_id`)
2. Environment variables (`DVLS_SERVER_URL`, `DVLS_APP_KEY`, `DVLS_APP_SECRET`, `DVLS_VAULT_ID`)
3. Fail with clear error if neither provided

**Token Caching**:
- Store token as instance variable during first lookup call
- Reuse for subsequent calls within same plugin instance
- Implement cleanup method to logout when plugin terminates

### Entry Identification

**Supported Formats**:
- UUID (direct ID lookup): `'12345678-1234-1234-1234-123456789012'`
- Name (search by name): `'my-database-credentials'`
- Detection: UUID pattern match determines lookup method

### Field Mapping (secret.py)

**Supported Fields** (based on DVLS API credential types):
```python
VALID_FIELDS = {
    # Common fields
    'username', 'password', 'domain',
    # Connection string
    'connectionString',
    # API Key
    'apiId', 'apiKey',
    # Azure Service Principal
    'tenantId', 'clientId', 'clientSecret',
    # SSH Key
    'privateKeyData', 'publicKeyData', 'privateKeyPassPhrase'
}
```

**Default Field**: `password` (most common use case)

### Error Handling

**Error Types**:
- `AnsibleError("Authentication failed: ...")` - Login failures, invalid credentials
- `AnsibleError("Credential not found: ...")` - Entry doesn't exist in vault
- `AnsibleError("Invalid field: ...")` - Field doesn't exist on credential (secret.py only)
- `AnsibleError("Configuration error: ...")` - Missing required parameters

**Error Message Pattern**:
```python
raise AnsibleError(
    f"Failed to retrieve secret '{term}': {error_details}. "
    f"Verify DVLS_SERVER_URL, DVLS_APP_KEY, DVLS_APP_SECRET, and DVLS_VAULT_ID "
    f"are set correctly."
)
```

### Return Format

**secret.py** (Field-Specific):
```python
# Returns list with single string value
return [field_value]

# Example: lookup('devolutions.dvls.secret', 'db-creds', field='username')
# Returns: ['admin']
```

**secret_full.py** (Full Object):
```python
# Returns list with complete credential dict
return [credential_dict]

# Example: lookup('devolutions.dvls.secret_full', 'db-creds')
# Returns: [{'username': 'admin', 'password': '***', 'domain': 'prod', ...}]
```

### Integration Points

**Reuse from Existing Modules**:
- `auth.login()` - Authentication with DVLS API
- `auth.logout()` - Session cleanup
- `vaults.get_vault_entry()` - Retrieve entry by ID
- `vaults.get_vault_entry_from_name()` - Retrieve entry by name
- `utils.get_sensible_value()` - Extract credential data from API response

**New Utility Functions** (if needed):
- `_is_uuid()` - Detect UUID format for ID vs. name lookup
- `_extract_field()` - Safely extract field from credential object with validation

## Actions

### Phase 1: Foundation & secret.py (Field-Specific Plugin)
- [ ] Create `plugins/lookup/` directory structure
  - [ ] Ensure proper Ansible collection structure
  - [ ] Add `__init__.py` if needed for Python package
- [ ] Implement `plugins/lookup/secret.py`
  - [ ] Add DOCUMENTATION block with all parameters and examples
  - [ ] Implement `LookupBase.run()` method signature
  - [ ] Add parameter handling (terms, variables, kwargs)
  - [ ] Implement configuration priority (params → env vars → fail)
  - [ ] Add UUID detection helper function
  - [ ] Implement authentication with token caching
  - [ ] Add entry retrieval logic (ID vs. name)
  - [ ] Implement field extraction and validation
  - [ ] Add error handling with actionable messages
  - [ ] Implement cleanup method for logout
  - [ ] Write unit tests for helper functions (UUID detection, field validation)
- [ ] Create integration test playbook `tests/integration/test_lookup_secret.yml`
  - [ ] Test basic password field retrieval (default)
  - [ ] Test username field retrieval
  - [ ] Test custom field retrieval (apiKey, clientId, etc.)
  - [ ] Test lookup by ID
  - [ ] Test lookup by name
  - [ ] Test error scenarios (invalid field, missing credential, auth failure)
  - [ ] Test environment variable configuration
  - [ ] Test explicit parameter configuration
- [ ] Run quality checks
  - [ ] `ruff check plugins/lookup/`
  - [ ] `ansible-test sanity --python 3.13`
  - [ ] `ansible-lint tests/integration/test_lookup_secret.yml`
- [ ] Test manually with real DVLS instance
  - [ ] Build and install collection locally
  - [ ] Run integration tests with verbose output
  - [ ] Verify field values match DVLS web UI
- [ ] Update `documentation/reference/` with lookup plugin patterns
- [ ] Git commit: "feat: add secret lookup plugin for field-specific credential retrieval"

### Phase 2: secret_full.py (Full Object Plugin)
- [ ] Implement `plugins/lookup/secret_full.py`
  - [ ] Add DOCUMENTATION block with examples
  - [ ] Implement `LookupBase.run()` method
  - [ ] Reuse authentication logic from secret.py (consider shared base class)
  - [ ] Add entry retrieval logic (same as secret.py)
  - [ ] Return complete credential object structure
  - [ ] Match data structure from `fetch_secrets` module exactly
  - [ ] Add error handling with actionable messages
  - [ ] Implement cleanup method for logout
- [ ] Create integration test playbook `tests/integration/test_lookup_secret_full.yml`
  - [ ] Test full object retrieval by ID
  - [ ] Test full object retrieval by name
  - [ ] Test multiple credential types (Username/Password, API Key, SSH Key, Azure SP)
  - [ ] Verify structure matches `fetch_secrets` module output
  - [ ] Test error scenarios (missing credential, auth failure)
  - [ ] Test accessing nested fields from returned object
- [ ] Run quality checks
  - [ ] `ruff check plugins/lookup/`
  - [ ] `ansible-test sanity --python 3.13`
  - [ ] `ansible-lint tests/integration/test_lookup_secret_full.yml`
- [ ] Test manually with real DVLS instance
  - [ ] Build and install collection locally
  - [ ] Run integration tests with verbose output
  - [ ] Verify object structure completeness
- [ ] Git commit: "feat: add secret_full lookup plugin for complete credential objects"

### Phase 3: Documentation & Examples
- [ ] Create comprehensive examples for common use cases
  - [ ] Database credentials (username + password)
  - [ ] API authentication (apiId + apiKey)
  - [ ] Azure Service Principal (tenantId, clientId, clientSecret)
  - [ ] SSH key access (username, privateKeyData, privateKeyPassPhrase)
  - [ ] Using with ansible-vault for double encryption
  - [ ] Error handling and debugging tips
- [ ] Update collection README.md
  - [ ] Add lookup plugins section
  - [ ] Include syntax examples
  - [ ] Document environment variable configuration
  - [ ] Add troubleshooting section
- [ ] Create `documentation/processes/using_lookup_plugins.md`
  - [ ] When to use lookup plugins vs. modules
  - [ ] Performance considerations (caching, multiple lookups)
  - [ ] Security best practices
  - [ ] Common patterns and anti-patterns
- [ ] Validate documentation with `ansible-doc`
  - [ ] `ansible-doc -t lookup devolutions.dvls.secret`
  - [ ] `ansible-doc -t lookup devolutions.dvls.secret_full`
  - [ ] Verify examples render correctly
  - [ ] Check all parameters documented
- [ ] Git commit: "docs: add comprehensive lookup plugin documentation and examples"

### Phase 4: Advanced Features & Optimization
- [ ] Implement shared base class for common logic
  - [ ] Create `plugins/lookup/_dvls_base.py` with shared methods
  - [ ] Extract authentication, caching, and cleanup logic
  - [ ] Refactor both plugins to inherit from base
  - [ ] Ensure no functionality regression
  - [ ] Write tests for base class
- [ ] Add performance optimizations
  - [ ] Implement connection pooling for HTTP requests
  - [ ] Add response caching for repeated lookups of same credential
  - [ ] Measure and document performance improvements
- [ ] Add advanced error handling
  - [ ] Retry logic for transient network failures
  - [ ] Connection timeout configuration
  - [ ] Detailed logging (using display.vvv for debug mode)
- [ ] Add support for additional query methods
  - [ ] Query by path: `lookup('devolutions.dvls.secret', 'path:/Production/Database')`
  - [ ] Query by tag: `lookup('devolutions.dvls.secret', 'tag:production')`
  - [ ] Document new query syntax
- [ ] Run comprehensive testing
  - [ ] Full integration test suite with all query methods
  - [ ] Performance benchmarking (100+ sequential lookups)
  - [ ] Stress testing with concurrent playbook runs
- [ ] Update documentation with advanced features
- [ ] Git commit: "feat: add advanced lookup plugin features and optimizations"

### Phase 5: CI/CD Integration & Release Preparation
- [ ] Add lookup plugin tests to CI pipeline
  - [ ] Update `.github/workflows/test.yml`
  - [ ] Ensure integration tests run with DVLS credentials
  - [ ] Add sanity checks for lookup plugins
- [ ] Update collection version in `galaxy.yml`
  - [ ] Increment minor version (1.2.4 → 1.3.0)
  - [ ] Add changelog entry
- [ ] Build and test collection tarball
  - [ ] `ansible-galaxy collection build`
  - [ ] Install in fresh environment
  - [ ] Run all integration tests
  - [ ] Verify `ansible-doc` works for lookup plugins
- [ ] Create release notes
  - [ ] Document new features (lookup plugins)
  - [ ] Include migration guide from modules to lookups (when appropriate)
  - [ ] Add breaking changes section (none expected)
  - [ ] Include upgrade instructions
- [ ] Final quality gate
  - [ ] All tests pass (unit, integration, sanity)
  - [ ] All documentation renders correctly
  - [ ] No security vulnerabilities in dependencies
  - [ ] Code coverage meets standards
- [ ] Git commit: "chore: prepare v1.3.0 release with lookup plugins"

### Final Phase: Completion & Documentation
- [ ] Final testing and validation
  - [ ] Run complete test suite one final time
  - [ ] Manual testing of all documented examples
  - [ ] Cross-platform testing (Linux, macOS, Windows WSL)
  - [ ] Verify works with multiple Ansible versions (11.x, 10.x)
- [ ] Update all documentation with final implementation details
  - [ ] Ensure all README examples are tested and working
  - [ ] Update troubleshooting guide with real-world issues encountered
  - [ ] Add FAQ section based on development experience
- [ ] Review all acceptance criteria are met
  - [ ] Both lookup plugins functional and tested
  - [ ] Documentation complete and accurate
  - [ ] CI/CD pipeline includes lookup plugin tests
  - [ ] Collection builds and installs correctly
  - [ ] `ansible-doc` renders properly for both plugins
- [ ] Create GitHub release
  - [ ] Tag: `v1.3.0`
  - [ ] Attach collection tarball
  - [ ] Include comprehensive release notes
- [ ] Publish to Ansible Galaxy (if automated)
  - [ ] Verify publication successful
  - [ ] Test installation from Galaxy: `ansible-galaxy collection install devolutions.dvls`
- [ ] Update plan status from "Upcoming" to "Completed"
- [ ] **IMPORTANT**: Move this document to `documentation/planning/completed/251104a_dvls_lookup_plugins.md`
- [ ] Announce release to users via appropriate channels

## Appendix

### Technical Details

#### Plugin Class Structure (secret.py)

```python
#!/usr/bin/python

DOCUMENTATION = r"""
---
name: secret
author: Danny Bédard (@DannyBedard)
version_added: "1.3.0"
short_description: Retrieve a specific field from a DVLS credential
description:
  - Fetches a single field value from a Devolutions Server (DVLS) credential entry.
  - Supports lookup by credential name or UUID.
  - Credentials retrieved from specified vault using application authentication.
options:
  _terms:
    description:
      - Credential identifier (name or UUID) to retrieve.
    required: true
    type: str
  field:
    description:
      - Field name to extract from credential.
      - Supported fields depend on credential type.
    type: str
    default: password
  server_base_url:
    description:
      - DVLS server base URL. Falls back to DVLS_SERVER_URL environment variable.
    type: str
    required: false
  app_key:
    description:
      - Application key for authentication. Falls back to DVLS_APP_KEY environment variable.
    type: str
    required: false
  app_secret:
    description:
      - Application secret for authentication. Falls back to DVLS_APP_SECRET environment variable.
    type: str
    required: false
    no_log: true
  vault_id:
    description:
      - Vault UUID containing the credential. Falls back to DVLS_VAULT_ID environment variable.
    type: str
    required: false
notes:
  - Requires network access to DVLS server.
  - Authentication token is cached for the duration of the playbook run.
  - Supported fields include username, password, domain, connectionString, apiId, apiKey, tenantId, clientId, clientSecret, privateKeyData, publicKeyData, privateKeyPassPhrase.
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

# Lookup by UUID
- name: Get API key by ID
  debug:
    msg: "{{ lookup('devolutions.dvls.secret', '12345678-1234-1234-1234-123456789012', field='apiKey') }}"

# Use in variable assignment
- name: Set database credentials
  set_fact:
    db_user: "{{ lookup('devolutions.dvls.secret', 'prod-db', field='username') }}"
    db_pass: "{{ lookup('devolutions.dvls.secret', 'prod-db', field='password') }}"

# Override server configuration
- name: Get credential from specific server
  debug:
    msg: "{{ lookup('devolutions.dvls.secret', 'my-cred',
              server_base_url='https://dvls.example.com',
              app_key='my-key',
              app_secret='my-secret',
              vault_id='vault-uuid',
              field='password') }}"
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
import os
import re

try:
    from ansible_collections.devolutions.dvls.plugins.module_utils.auth import login, logout
    from ansible_collections.devolutions.dvls.plugins.module_utils.vaults import (
        get_vault_entry,
        get_vault_entry_from_name,
    )
    from ansible_collections.devolutions.dvls.plugins.module_utils.utils import get_sensible_value
except ImportError as e:
    raise AnsibleError(f"Failed to import DVLS module_utils: {e}")

display = Display()

# UUID pattern for credential ID detection
UUID_PATTERN = re.compile(
    r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$',
    re.IGNORECASE
)

VALID_FIELDS = {
    'username', 'password', 'domain',
    'connectionString',
    'apiId', 'apiKey',
    'tenantId', 'clientId', 'clientSecret',
    'privateKeyData', 'publicKeyData', 'privateKeyPassPhrase'
}


class LookupModule(LookupBase):
    """DVLS credential field lookup plugin."""

    def __init__(self, *args, **kwargs):
        super(LookupModule, self).__init__(*args, **kwargs)
        self._token = None
        self._server_base_url = None

    def run(self, terms, variables=None, **kwargs):
        """
        Execute the lookup.

        Args:
            terms: List of credential identifiers (names or UUIDs)
            variables: Ansible variables (used for environment variable access)
            **kwargs: Plugin parameters

        Returns:
            List of field values (one per term)
        """
        self.set_options(var_options=variables, direct=kwargs)

        # Get configuration
        server_base_url = self.get_option('server_base_url') or os.environ.get('DVLS_SERVER_URL')
        app_key = self.get_option('app_key') or os.environ.get('DVLS_APP_KEY')
        app_secret = self.get_option('app_secret') or os.environ.get('DVLS_APP_SECRET')
        vault_id = self.get_option('vault_id') or os.environ.get('DVLS_VAULT_ID')
        field = self.get_option('field') or 'password'

        # Validate configuration
        if not all([server_base_url, app_key, app_secret, vault_id]):
            raise AnsibleError(
                "Missing required configuration. Set DVLS_SERVER_URL, DVLS_APP_KEY, "
                "DVLS_APP_SECRET, and DVLS_VAULT_ID environment variables or pass as parameters."
            )

        # Validate field
        if field not in VALID_FIELDS:
            raise AnsibleError(
                f"Invalid field '{field}'. Supported fields: {', '.join(sorted(VALID_FIELDS))}"
            )

        # Authenticate (cached)
        if not self._token:
            try:
                display.vvv(f"Authenticating to DVLS at {server_base_url}")
                self._token = login(server_base_url, app_key, app_secret)
                self._server_base_url = server_base_url
            except Exception as e:
                raise AnsibleError(f"DVLS authentication failed: {e}")

        # Retrieve credentials
        results = []
        for term in terms:
            try:
                display.vvv(f"Looking up credential: {term}")

                # Determine lookup method (ID vs. name)
                if self._is_uuid(term):
                    display.vvv(f"Using ID lookup for {term}")
                    response = get_vault_entry(server_base_url, self._token, vault_id, term)
                    credential = response.get('data', {})
                else:
                    display.vvv(f"Using name lookup for {term}")
                    response = get_vault_entry_from_name(server_base_url, self._token, vault_id, term)
                    # Extract first matching entry
                    entries = response.get('data', [])
                    if not entries:
                        raise AnsibleError(f"Credential '{term}' not found in vault {vault_id}")
                    # Get full entry details
                    entry_id = entries[0].get('id')
                    full_response = get_vault_entry(server_base_url, self._token, vault_id, entry_id)
                    credential = full_response.get('data', {})

                # Extract field
                field_value = credential.get(field)
                if field_value is None:
                    raise AnsibleError(
                        f"Field '{field}' not found in credential '{term}'. "
                        f"Available fields: {', '.join(credential.keys())}"
                    )

                display.vvv(f"Successfully retrieved field '{field}' from '{term}'")
                results.append(field_value)

            except AnsibleError:
                raise
            except Exception as e:
                raise AnsibleError(f"Failed to retrieve credential '{term}': {e}")

        return results

    def _is_uuid(self, value):
        """Check if value matches UUID format."""
        return UUID_PATTERN.match(value) is not None

    def __del__(self):
        """Cleanup: logout from DVLS."""
        if self._token and self._server_base_url:
            try:
                display.vvv("Logging out from DVLS")
                logout(self._server_base_url, self._token)
            except Exception as e:
                display.warning(f"Failed to logout from DVLS: {e}")
```

#### Plugin Class Structure (secret_full.py)

```python
#!/usr/bin/python

DOCUMENTATION = r"""
---
name: secret_full
author: Danny Bédard (@DannyBedard)
version_added: "1.3.0"
short_description: Retrieve complete DVLS credential object
description:
  - Fetches entire credential object from Devolutions Server (DVLS).
  - Returns same structure as fetch_secrets module.
  - Supports lookup by credential name or UUID.
options:
  _terms:
    description:
      - Credential identifier (name or UUID) to retrieve.
    required: true
    type: str
  server_base_url:
    description:
      - DVLS server base URL. Falls back to DVLS_SERVER_URL environment variable.
    type: str
    required: false
  app_key:
    description:
      - Application key for authentication. Falls back to DVLS_APP_KEY environment variable.
    type: str
    required: false
  app_secret:
    description:
      - Application secret for authentication. Falls back to DVLS_APP_SECRET environment variable.
    type: str
    required: false
    no_log: true
  vault_id:
    description:
      - Vault UUID containing the credential. Falls back to DVLS_VAULT_ID environment variable.
    type: str
    required: false
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
import os
import re

try:
    from ansible_collections.devolutions.dvls.plugins.module_utils.auth import login, logout
    from ansible_collections.devolutions.dvls.plugins.module_utils.vaults import (
        get_vault_entry,
        get_vault_entry_from_name,
    )
except ImportError as e:
    raise AnsibleError(f"Failed to import DVLS module_utils: {e}")

display = Display()

UUID_PATTERN = re.compile(
    r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$',
    re.IGNORECASE
)


class LookupModule(LookupBase):
    """DVLS full credential object lookup plugin."""

    def __init__(self, *args, **kwargs):
        super(LookupModule, self).__init__(*args, **kwargs)
        self._token = None
        self._server_base_url = None

    def run(self, terms, variables=None, **kwargs):
        """
        Execute the lookup.

        Args:
            terms: List of credential identifiers (names or UUIDs)
            variables: Ansible variables
            **kwargs: Plugin parameters

        Returns:
            List of credential objects (one per term)
        """
        self.set_options(var_options=variables, direct=kwargs)

        # Get configuration
        server_base_url = self.get_option('server_base_url') or os.environ.get('DVLS_SERVER_URL')
        app_key = self.get_option('app_key') or os.environ.get('DVLS_APP_KEY')
        app_secret = self.get_option('app_secret') or os.environ.get('DVLS_APP_SECRET')
        vault_id = self.get_option('vault_id') or os.environ.get('DVLS_VAULT_ID')

        # Validate configuration
        if not all([server_base_url, app_key, app_secret, vault_id]):
            raise AnsibleError(
                "Missing required configuration. Set DVLS_SERVER_URL, DVLS_APP_KEY, "
                "DVLS_APP_SECRET, and DVLS_VAULT_ID environment variables or pass as parameters."
            )

        # Authenticate (cached)
        if not self._token:
            try:
                display.vvv(f"Authenticating to DVLS at {server_base_url}")
                self._token = login(server_base_url, app_key, app_secret)
                self._server_base_url = server_base_url
            except Exception as e:
                raise AnsibleError(f"DVLS authentication failed: {e}")

        # Retrieve credentials
        results = []
        for term in terms:
            try:
                display.vvv(f"Looking up credential: {term}")

                # Determine lookup method (ID vs. name)
                if self._is_uuid(term):
                    display.vvv(f"Using ID lookup for {term}")
                    response = get_vault_entry(server_base_url, self._token, vault_id, term)
                    credential = response.get('data', {})
                else:
                    display.vvv(f"Using name lookup for {term}")
                    response = get_vault_entry_from_name(server_base_url, self._token, vault_id, term)
                    entries = response.get('data', [])
                    if not entries:
                        raise AnsibleError(f"Credential '{term}' not found in vault {vault_id}")
                    entry_id = entries[0].get('id')
                    full_response = get_vault_entry(server_base_url, self._token, vault_id, entry_id)
                    credential = full_response.get('data', {})

                display.vvv(f"Successfully retrieved credential '{term}'")
                results.append(credential)

            except AnsibleError:
                raise
            except Exception as e:
                raise AnsibleError(f"Failed to retrieve credential '{term}': {e}")

        return results

    def _is_uuid(self, value):
        """Check if value matches UUID format."""
        return UUID_PATTERN.match(value) is not None

    def __del__(self):
        """Cleanup: logout from DVLS."""
        if self._token and self._server_base_url:
            try:
                display.vvv("Logging out from DVLS")
                logout(self._server_base_url, self._token)
            except Exception as e:
                display.warning(f"Failed to logout from DVLS: {e}")
```

### Implementation Context

**Environment Variable Names**:
Based on existing codebase patterns, using:
- `DVLS_SERVER_URL` (not `DVLS_SERVER_BASE_URL`) for consistency with typical URL env var naming
- `DVLS_APP_KEY`, `DVLS_APP_SECRET` - match existing module parameters
- `DVLS_VAULT_ID` - clearly identifies the target vault

**Credential Type Support**:
From DVLS API and existing module code, supported credential types:
1. **Username/Password** (Default subtype) - Fields: username, password, domain
2. **Connection String** - Field: connectionString
3. **API Key** - Fields: apiId, apiKey
4. **Azure Service Principal** - Fields: tenantId, clientId, clientSecret
5. **SSH Key** - Fields: username, privateKeyData, publicKeyData, privateKeyPassPhrase

**Performance Considerations**:
- Token caching reduces authentication overhead from O(n) to O(1) per playbook run
- Single HTTP request per credential lookup (after authentication)
- Consider implementing local credential caching for repeated lookups of same credential (Phase 4)

**Testing Strategy**:
- Integration tests require real DVLS instance with test credentials of each type
- Use same test infrastructure as existing modules (`tests/integration/configurations.yml`)
- Manual testing critical for verifying field extraction across all credential types

### Decision Documentation

**Decision: Separate vs. Combined Plugin**
- **Option A**: Single plugin with `return_full` boolean parameter
- **Option B**: Two separate plugins (chosen)
- **Rationale**: Separate plugins provide clearer API and simpler syntax. Common pattern in Ansible ecosystem (see 1Password CLI plugin structure). Easier to document and understand intent.

**Decision: Default Field**
- **Option A**: No default, require explicit field parameter
- **Option B**: Default to `password` (chosen)
- **Rationale**: Password retrieval is overwhelmingly most common use case. Reduces verbosity in typical scenarios. Matches LastPass plugin behavior.

**Decision: Authentication Caching**
- **Option A**: Authenticate on every lookup call
- **Option B**: Cache token per plugin instance (chosen)
- **Option C**: Global token cache across all plugins
- **Rationale**: Option B balances performance and security. Avoids excessive API calls while maintaining session isolation. Option C risks token sharing issues and logout complexity.

**Decision: Lookup by Name vs. ID**
- **Option A**: Require prefix syntax (`name:my-cred`, `id:uuid`)
- **Option B**: Auto-detect via UUID pattern (chosen)
- **Option C**: Separate parameter (`lookup_type='name'`)
- **Rationale**: Option B provides cleanest syntax with no ambiguity (UUIDs have distinct format). Reduces parameter complexity.

**Decision: Error Handling Approach**
- **Option A**: Return empty string on error
- **Option B**: Raise AnsibleError (chosen)
- **Option C**: Support `error_mode` parameter
- **Rationale**: Option B follows Ansible best practices for lookup plugins. Credential lookup failure should fail fast, not silently. Option C adds complexity for minimal benefit.

**Decision: Module Utils Reuse**
- **Option A**: Duplicate logic in lookup plugins
- **Option B**: Reuse existing module_utils (chosen)
- **Rationale**: DRY principle, maintains consistency with modules, reduces maintenance burden. Existing auth and vault utilities are well-tested.

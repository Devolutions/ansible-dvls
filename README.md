# Ansible Module for Devolutions Server

This Ansible module allows you to authenticate with DVLS and fetch server information, vaults, and secrets.

## Features
- Authenticate with DVLS using application identities.
- Fetch server information, vault lists, or specific secrets.
- Flexible support for static secrets or fetching all secrets in a vault.
- Lookup plugins for idiomatic inline credential retrieval in playbooks and templates.

## Requirements
- Ansible 2.18
- Python `requests` library, installed on the machine that runs the module
- A DVLS release with the public API v2 (`/api/v2`). Version 2.0.0 of the collection calls only that API; stay on
  1.x for an older DVLS.
- A DVLS application identity (create at `{your-dvls-url}/administration/applications`).
  - The application must have permissions to fetch the desired secrets.

## Upgrading to 2.0.0

The collection now calls the DVLS public API v2. An application identity's token expires 7 minutes after login, so a
request answered 401 logs in again once and is retried: lookups no longer fail in playbooks that run longer than that.
Lists are read page by page, so name, tag, path and type searches and the vault list return every match instead of the
first page, and folders of every subtype are left out of the results.

Breaking changes:

- `fetch_server`: `accessURI` is the `server_base_url` the module was given, since the API does not expose the
  access URI configured on the server. `vaults` holds the vaults as v2 returns them: `businessUnitId` replaces
  `businessUnitID`, and the PAM (Infrastructure) vault and the application identity's own user vault are no longer
  listed.
- `fetch_secrets`: a `secret_type` that is not an entry type DVLS knows (`Credential`, `Folder`, ...) fails with a
  400 on `type` instead of returning no secrets, since DVLS now applies the filter itself.
- Private key credentials no longer carry `username`, `password`, `domain` and `privateKeyCertificateData`: v1
  returned the override username and password under those names too. Read `privateKeyOverrideUsername` and
  `privateKeyOverridePassword` instead.
- Errors show the HTTP status and the message DVLS gave, never the raw response body.

Modules run on the target host by default, so that host is the one that needs
network access to DVLS and the `requests` library. Add `delegate_to: localhost`
to a task to run it from the controller instead. Lookup plugins always run on
the controller.

Set the following environment variables for DVLS authentication:
```sh
export DVLS_SERVER_BASE_URL="https://example.yourcompany.com"
export DVLS_APP_KEY="your_app_key_here"
export DVLS_APP_SECRET="your_app_secret_here"
export DVLS_VAULT_ID="00000000-0000-0000-0000-000000000000"
```

`server_base_url`, `app_key`, `app_secret` and `vault_id` fall back to these
variables when they are not passed to a task or a lookup.

## Connection options

Every module and lookup accepts:

| Option | Default | Description |
|---|---|---|
| `validate_certs` | `true` | Verify the TLS certificate of the DVLS server. |
| `ca_path` | none | Path to a CA bundle used to verify that certificate. |
| `timeout` | `30` | Timeout in seconds for each HTTP request. |

```yaml
- name: Fetch secrets from a DVLS using a private CA
  devolutions.dvls.fetch_secrets:
    vault_id: "00000000-0000-0000-0000-000000000000"
    ca_path: /etc/pki/tls/certs/internal-ca.pem
    timeout: 60
  delegate_to: localhost
  register: value
```

## Usage with static secrets file

### Example secrets.yml
Define the secrets you want to fetch in ```secrets.yml```:

```yaml
secrets:
  - secret_name: "my_secret_1"
  - secret_name: "my_secret_2"
  - secret_id: "12345678-1234-1234-1234-123456789012"
```

### Example playbook.yml
Use the following playbook to authenticate with DVLS and fetch the secrets defined in ```secrets.yml```:

```yaml
  vars_files:
    - secrets.yml
  tasks:
    - name: Fetch secrets
      devolutions.dvls.fetch_secrets:
        server_base_url: "https://example.yourcompany.com"
        app_key: "{{ lookup('env', 'DVLS_APP_KEY') }}"
        app_secret: "{{ lookup('env', 'DVLS_APP_SECRET') }}"
        vault_id: "00000000-0000-0000-0000-000000000000"
        secrets: "{{ secrets }}"
      register: value

    - name: Dump secrets
      debug:
        msg: "{{ value }}"

    - name: Dump a secret
      debug:
        msg: "{{ value['name-or-id'].password }}"
```

## Usage fetching all secrets

### Example playbook.yml using a VaultID
Use the following playbook to authenticate with DVLS and fetch every secrets from a defined VaultID:

```yaml
  tasks:
    - name: Fetch secrets
      devolutions.dvls.fetch_secrets:
        server_base_url: "https://example.yourcompany.com"
        app_key: "{{ lookup('env', 'DVLS_APP_KEY') }}"
        app_secret: "{{ lookup('env', 'DVLS_APP_SECRET') }}"
        vault_id: "00000000-0000-0000-0000-000000000000"
      register: value

    - name: Dump secrets
      debug:
        msg: "{{ value }}"

    - name: Dump a secret
      debug:
        msg: "{{ value['name-or-id'].password }}"
```

## Usage fetching server info and vaults list

```yaml
---
- name: Fetch dvls server information
  devolutions.dvls.fetch_server:
    server_base_url: "https://example.yourcompany.com"
    app_key: "{{ lookup('env', 'DVLS_APP_KEY') }}"
    app_secret: "{{ lookup('env', 'DVLS_APP_SECRET') }}"
  register: value

- name: Fetch URI
  debug:
    msg: "{{ value.accessURI }}"

- name: Fetch a vault from the list
  debug:
    msg: "{{ value.vaults[1].id }}"
```

`accessURI` is the `server_base_url` the module was given.

Example response

```json
{
    "server": {
        "accessURI": "https://example.dvls-server.com/",
        "changed": false,
        "failed": false,
        "vaults": [
            {
                "contentType": "Everything",
                "description": "Shared vault for organization",
                "id": "987f6543-d21c-43ba-987f-123456789abc",
                "name": "Organization vault",
                "securityLevel": "Standard",
                "type": "Shared",
                "visibility": "Default"
            }
        ],
        "version": "2025.1.0.0"
    }
}
```

## Using Lookup Plugins

The collection provides two lookup plugins for retrieving credentials directly in playbooks, templates, and variable assignments:

### 1. `devolutions.dvls.secret` - Field-Specific Lookup

Retrieve a single field from a credential:

```yaml
- name: Simple password lookup (default field)
  debug:
    msg: "{{ lookup('devolutions.dvls.secret', 'prod-database') }}"

- name: Get username field
  debug:
    msg: "{{ lookup('devolutions.dvls.secret', 'prod-database', field='username') }}"

- name: Set variables from credentials
  set_fact:
    db_user: "{{ lookup('devolutions.dvls.secret', 'prod-db', field='username') }}"
    db_pass: "{{ lookup('devolutions.dvls.secret', 'prod-db', field='password') }}"
```

### 2. `devolutions.dvls.secret_full` - Full Object Lookup

Retrieve the complete credential object:

```yaml
- name: Get full credential
  set_fact:
    db_cred: "{{ lookup('devolutions.dvls.secret_full', 'prod-database') }}"

- name: Use multiple fields from credential
  postgresql_db:
    name: mydb
    login_host: "{{ db_cred.domain }}"
    login_user: "{{ db_cred.username }}"
    login_password: "{{ db_cred.password }}"
```

### Configuration

Lookup plugins use the same environment variables as the modules:

```sh
export DVLS_SERVER_BASE_URL="https://example.yourcompany.com"
export DVLS_APP_KEY="your_app_key_here"
export DVLS_APP_SECRET="your_app_secret_here"
export DVLS_VAULT_ID="00000000-0000-0000-0000-000000000000"
```

You can also override these per-lookup:

```yaml
- name: Get credential from specific server
  debug:
    msg: "{{ lookup('devolutions.dvls.secret', 'my-cred',
              server_base_url='https://dvls.example.com',
              app_key='my-key',
              app_secret='my-secret',
              vault_id='vault-uuid',
              field='password') }}"
```

### Supported Fields

The `field` parameter in `devolutions.dvls.secret` supports:
- `username`, `password`, `domain` (Username/Password credentials)
- `connectionString` (Connection String)
- `apiId`, `apiKey` (API Key)
- `tenantId`, `clientId`, `clientSecret` (Azure Service Principal)
- `privateKeyData`, `publicKeyData`, `privateKeyPassPhrase`, `privateKeyOverrideUsername`, `privateKeyOverridePassword` (SSH Key)

### Lookup by Name or UUID

Both plugins support lookup by credential name or UUID:

```yaml
# By name
lookup('devolutions.dvls.secret', 'prod-database')

# By UUID
lookup('devolutions.dvls.secret', '12345678-1234-1234-1234-123456789012')
```

## Secrets definition

To access a particular field within a secret, you can use the format ```{{ secrets['name-or-id'].<field> }}```. Here's a breakdown of the available categories and their fields:

| **Category**              | **Fields**                                                                                                                |
|---------------------------|---------------------------------------------------------------------------------------------------------------------------|
| Username and password     | `domain`, `password`, `username`                                                                                          |
| Connection string         | `connectionString`                                                                                                        |
| Secret                    | `password`                                                                                                                |
| API key                   | `apiId`, `apiKey`, `tenantId`                                                                                             |
| SSH key                   | `privateKeyData`, `privateKeyOverridePassword`, `privateKeyOverrideUsername`, `privateKeyPassPhrase`, `publicKeyData`   |
| Azure service principal   | `clientId`, `clientSecret`, `subscriptionId`, `tenantId`                                                                  |


### Example using secret value
For example, if you want to access the ```apiId``` from an ```API key secret```, you would use the following syntax:

```yaml
{{ secrets['some api key'].apiId }}
```

## Usage writing secrets

If there is an existing secret in that path, it will update the secret. Otherwise a new secret entry will be created.
When a new secret was created or updated, the module will return the entry ID.

```yaml
- name: Upload Credentials to DVLS
  devolutions.dvls.create_secret:
    server_base_url: "https://example.yourcompany.com"
    app_key: "{{ lookup('env', 'DVLS_APP_KEY') }}"
    app_secret: "{{ lookup('env', 'DVLS_APP_SECRET') }}"
    vault_id: "00000000-0000-0000-0000-000000000000"
    secret:
      secret_name: "my_secret_1"
      value: "p@ssw0rd1"
```

Example with additional available options (Currently only the "Credential" type and "Default" subtype are supported):

```yaml
- name: Upload Credentials to DVLS
  devolutions.dvls.create_secret:
    server_base_url: "https://example.yourcompany.com"
    app_key: "{{ lookup('env', 'DVLS_APP_KEY') }}"
    app_secret: "{{ lookup('env', 'DVLS_APP_SECRET') }}"
    vault_id: "00000000-0000-0000-0000-000000000000"
    secret:
      secret_name: "my_secret_1"
      value: "p@ssw0rd1"
      secret_path: "path\\to\\folder"
      secret_type: "Credential"
      secret_subtype: "Default"
      secret_description: "a description for the secret"
```

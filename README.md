# DVLS Ansible Module

This Ansible module allows you to authenticate with DVLS and fetch server information, vaults, and secrets.

## Features
- Authenticate with DVLS using application identities.
- Fetch server information, vault lists, or specific secrets.
- Flexible support for static secrets or fetching all secrets in a vault.

## Requirements
- Ansible
- Python `requests` library
- A DVLS application identity (create at `{your-dvls-url}/administration/applications`).
  - The application must have permissions to fetch the desired secrets.

Set the following environment variables for DVLS authentication:
```sh
export DVLS_APP_KEY="your_app_key_here"
export DVLS_APP_SECRET="your_app_secret_here"
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
      register: secrets

    - name: Dump secrets
      debug:
        msg: "{{ secrets }}"

    - name: Dump a secret
      debug:
        msg: "{{ secrets['name-or-id'].value }}"
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
      register: secrets

    - name: Dump secrets
      debug:
        msg: "{{ secrets }}"

    - name: Dump a secret
      debug:
        msg: "{{ secrets['name-or-id'].value }}"
```

## Usage fetching server info and vaults list

```yaml
---
- name: Fetch dvls server information
    server:
    server_base_url: "https://example.yourcompany.com"
    app_key: "{{ lookup('env', 'DVLS_APP_KEY') }}"
    app_secret: "{{ lookup('env', 'DVLS_APP_SECRET') }}"
  register: server

- name: Fetch URI
  debug:
    msg: "{{ server.accessURI }}"

- name: Fetch a vault from the list
  debug:
    msg: "{{ server.vaults[1].id }}"
```

Example response

```json
{
    "server": {
        "accessURI": "https://example.dvls-server.com/",
        "changed": false,
        "expirationDate": "2030-12-31T23:59:59",
        "failed": false,
        "vaults": [
            {
                "description": "User vault for personal entries",
                "id": "123e4567-e89b-12d3-a456-426614174000",
                "type": "User"
            },
            {
                "description": "Shared vault for organization",
                "id": "987f6543-d21c-43ba-987f-123456789abc",
                "name": "Organization vault",
                "type": "Shared"
            }
        ],
        "version": "2025.1.0.0"
    }
}
```

## Secrets definition

To access a particular field within a secret, you can use the format ```{{ secrets['name-or-id'].value }}```. Here’s a breakdown of the available categories and their fields:

| **Category**              | **Fields**                                                                 |
|---------------------------|---------------------------------------------------------------------------|
| Username and password     | `domain`, `password`, `username`                                          |
| Connection string         | `connectionString`                                                       |
| Secret                    | `password`                                                               |
| API key                   | `apiId`, `apiKey`, `tenantId`                                            |
| SSH key                   | `domain`, `password`, `privateKeyData`, `privateKeyOverridePassword`, `privateKeyPassPhrase`, `publicKeyData`, `username` |
| Azure service principal   | `clientId`, `clientSecret`, `tenantId`                                   |


### Example using secret value
For example, if you want to access the ```apiId``` from an ```API key secret```, you would use the following syntax:

```yaml
{{ secrets['some api key'].apiId }}
```

## Usage writing secrets

If there is an existing secret in that path, it will update the secret. Otherwise a new secret entry will be created.
When a new secret was created, the module will return the entry ID. If an existing entry was updated, nothing will be returned.

```yaml
- name: Upload Credentials to DVLS
  devolutions.dvls.create_secret:
    server_base_url: "https://example.yourcompany.com"
    app_key: "{{ lookup('env', 'DVLS_APP_KEY') }}"
    app_secret: "{{ lookup('env', 'DVLS_APP_SECRET') }}"
    vault_id: "00000000-0000-0000-0000-000000000000"
    secret_path: "path\\to\\folder"
    secret:
      - secret_name: "my_secret_1"
      - password: "p@ssw0rd1"
  register: secrets
```
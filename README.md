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
    server_base_url: "https://dvls-ops.devolutions.com"
    app_key: "{{ lookup('env', 'DVLS_APP_KEY') }}"
    app_secret: "{{ lookup('env', 'DVLS_APP_SECRET') }}"
    register: server
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

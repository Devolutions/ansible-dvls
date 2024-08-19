# DVLS Ansible Module

This Ansible module allows you to authenticate with DVLS and fetch secrets by name or ID.

## Requirements

- Ansible
- Python requests library
- You must have a DVLS application identities, it can be created at {your-dvls-url}/administration/applications
- This application must have permission to fetch the desired secrets
- Set the necessary environment variables for DVLS authentication:

```sh
export DVLS_APP_KEY="your_app_key_here"
export DVLS_APP_SECRET="your_app_secret_here"
```

## Usage

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
---
- name: Fetch secrets from DVLS
  hosts: localhost
  vars_files:
    - secrets.yml
  tasks:
    - name: Fetch secrets
      devolutions.dvls.fetch_secrets:
        server_base_url: "https://example.yourcompagny.com"
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

To access a particular field within a secret, you can use the format ```{{ secrets['name-or-id'].value }}```. Here’s a breakdown of the available categories and their fields:

```json
"Username and password": {
    "domain": "",
    "password": "",
    "username": ""
},
"Connection string": {
    "connectionString": ""
},
"Secret": {
    "password": ""
},
"API key": {
    "apiId": "",
    "apiKey": "",
    "tenantId": ""
},
"SSH key": {
    "domain": "",
    "password": "",
    "privateKeyData": "",
    "privateKeyOverridePassword": "",
    "privateKeyPassPhrase": "",
    "publicKeyData": "",
    "username": ""
},
"Azure service principal": {
    "clientId": "",
    "clientSecret": "",
    "tenantId": ""
},
```

### Example using secret value
For example, if you want to access the ```apiId``` from an ```API key secret```, you would use the following syntax:

```yaml
{{ secrets['some api key'].apiId }}
```

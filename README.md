# DVLS Ansible Module

This Ansible module allows you to authenticate with DVLS (Devolutions Server) and fetch secrets by name or ID.

## Requirements

- Ansible
- Python requests library
- You must have an application identies, it can be created at {your-dvls-url}/administration/applications
- This application must have permission to fetch the desired secrets
- Set the necessary environment variables for DVLS authentication:

```sh
export DVLS_APP_KEY="your_app_key_here"
export DVLS_APP_SECRET="your_app_secret_here"
```

## Usage

Example secrets.yml
Define the secrets you want to fetch in secrets.yml:

```yaml
secrets:
  - secret_name: "my_secret_1"
  - secret_name: "my_secret_2"
  - secret_id: "12345678-1234-1234-1234-123456789012"
```

Example playbook.yml
Use the following playbook to authenticate with DVLS and fetch the secrets defined in secrets.yml:

```yaml
---
- name: Fetch secrets from DVLS
  hosts: localhost
  vars_files:
    - secrets.yml
  tasks:
    - name: Fetch secrets
      dvls:
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
        msg: "{{ secrets['some api key'].apiId }}"
```

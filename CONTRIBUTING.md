# Contributing to Ansible DVLS Collection
Thank you for considering contributing to the Ansible DVLS Collection! This document provides guidelines for setting up your development environment, debugging, and contributing effectively.

## Development Environment Setup

### Folder Structure

The folder structure must match the following format to ensure proper imports:

    ./ansible_collections/devolutions/dvls/<Project Files>

This means the content of this repository should be placed directly in the dvls folder, not in a subfolder like ansible-dvls. For example this file would be:

    ./ansible_collections/devolutions/dvls/CONTRIBUTING.md

### Debugging with Visual Studio Code

To debug the project in Visual Studio Code, follow these steps:

1. Copy the content from ```vscode/**``` into your local ```.vscode``` folder.
2. Update the launch.json file with the appropriate environment variables:
```json
"env": {
    "DVLS_SERVER_BASE_URL": "<url>",
    "DVLS_APP_KEY": "<app-key>",
    "DVLS_APP_SECRET": "<app-secret>",
    "DVLS_VAULT_ID": "<vault-id>",
    "PYTHONPATH": "/Users/<user>/dev/git/ansible"
}
```
  - Replace ```<url>```, ```<app-key>```, ```<app-secret>```, and ```<vault-id>``` with your actual values.
  - Ensure PYTHONPATH points to the directory just before the folder structure mentioned above.

### Python Environment

1. Create a Python virtual environment:
```bash
    python3 -m venv venv
    source venv/bin/activate  # On Windows, use venv\Scripts\activate
```
1. Install the required dependencies:
```bash
    pip install -r requirements.txt
```
## Contributing Guidelines

### Reporting Issues

If you encounter a bug or have a feature request, please open an issue in the repository. Include as much detail as possible, such as:

- Steps to reproduce the issue.
- Expected behavior.
- Actual behavior.
- Relevant logs or error messages.
- Version of the project.

### Submitting Changes

1. Fork the Repository: Create a fork of this repository in your GitHub account.
2. Create a Branch: Create a new branch for your changes.
3. Make Changes: Implement your changes and ensure they follow the project's coding standards.
4. Write Tests: Add or update tests to cover your changes.
5. Submit a Pull Request: Push your branch to your fork and open a pull request. Provide a clear description of your changes and why they are necessary.

We use [ruff](https://docs.astral.sh/ruff/) as a lint, hence the ```.ruff.toml```

## Test locally
You can also run integration tests locally before opening a pull request.

1. Building the collection:
```bash
   ansible-galaxy collection build
```
2. Install it as a dependency
```bash
    ansible-galaxy collection install ./path/to/devolutions-dvls-<version>.tar.gz # --force flag may be necessary to overwrite a previous build
```
3. Run an integration test
```bash
    ansible-playbook tests/integration/test_manage_secrets.yml
```

## License
By contributing to this project, you agree that your contributions will be licensed under the same license as this repository.

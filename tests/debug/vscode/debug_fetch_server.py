# Copy this in the .vscode folder of your project to debug your module

import sys
import os
import io
import json

# Wrap arguments under ANSIBLE_MODULE_ARGS
mock_args = {
    "ANSIBLE_MODULE_ARGS": {
        "server_base_url": os.getenv("DVLS_SERVER_BASE_URL"),
        "app_key": os.getenv("DVLS_APP_KEY"),
        "app_secret": os.getenv("DVLS_APP_SECRET")
    }
}

# Convert to bytes, wrap for stdin
input_bytes = json.dumps(mock_args).encode("utf-8")
sys.stdin = io.TextIOWrapper(io.BytesIO(input_bytes), encoding="utf-8")

# Import and run your module
from ansible_collections.devolutions.dvls.plugins.modules import fetch_server
fetch_server.main()

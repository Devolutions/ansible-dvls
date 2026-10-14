import json
from ansible_collections.devolutions.dvls.plugins.module_utils.http import (
    request as http_request,
)


def login(server_base_url, app_key, app_secret):
    login_url = f"{server_base_url}/api/v1/login"
    login_data = {"appKey": app_key, "appSecret": app_secret}
    login_headers = {"Content-Type": "application/json"}

    try:
        response = http_request(
            "POST", login_url, headers=login_headers, data=json.dumps(login_data)
        )
        response.raise_for_status()
    except Exception as e:
        raise Exception(
            f"Failed to login: Unable to reach the server. Verify your network connection and server URL: {e}"
        )

    auth_response = response.json()
    token = auth_response.get("tokenId")

    if not token or token == "null":
        raise Exception("Failed to login or obtain token.")

    return token


def logout(server_base_url, token):
    logout_url = f"{server_base_url}/api/v1/logout"
    logout_headers = {"Content-Type": "application/json", "tokenId": token}

    http_request("POST", logout_url, headers=logout_headers)
    return None

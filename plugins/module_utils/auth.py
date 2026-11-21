import json
from ansible_collections.devolutions.dvls.plugins.module_utils.http import (
    request as http_request,
    raise_for_dvls_error,
)


def login(server_base_url, app_key, app_secret):
    login_url = f"{server_base_url}/api/v2/login"
    login_data = {"appKey": app_key, "appSecret": app_secret}
    login_headers = {"Content-Type": "application/json"}

    try:
        response = http_request(
            "POST", login_url, headers=login_headers, data=json.dumps(login_data)
        )
    except Exception as e:
        raise Exception(
            f"Failed to login: Unable to reach the server. Verify your network connection and server URL: {e}"
        )

    try:
        raise_for_dvls_error(response)
    except Exception as e:
        raise Exception(f"Failed to login: {e}")

    token = response.json().get("tokenId")

    if not token or token == "null":
        raise Exception("Failed to login or obtain token.")

    return token


class Session(object):
    def __init__(self, server_base_url, app_key, app_secret):
        self.server_base_url = server_base_url
        self._app_key = app_key
        self._app_secret = app_secret
        self.token = None

    def login(self):
        self.token = login(self.server_base_url, self._app_key, self._app_secret)

    def request(self, method, path, **kwargs):
        if self.token is None:
            self.login()

        url = f"{self.server_base_url}/api/v2/{path}"
        response = self._send(method, url, kwargs)
        # A token expires a fixed time after login (7 minutes) and v2 has no refresh operation.
        if response.status_code == 401:
            self.login()
            response = self._send(method, url, kwargs)

        return response

    def _send(self, method, url, kwargs):
        headers = dict(kwargs.get("headers") or {})
        headers["tokenId"] = self.token
        if "json" in kwargs:
            headers.setdefault("Content-Type", "application/json")

        send_kwargs = dict(kwargs, headers=headers)
        return http_request(method, url, **send_kwargs)

    def logout(self):
        if self.token is None:
            return

        token = self.token
        self.token = None
        http_request(
            "POST",
            f"{self.server_base_url}/api/v2/logout",
            headers={"tokenId": token},
        )

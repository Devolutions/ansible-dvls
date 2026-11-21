# GNU General Public License v3.0+ (see LICENSE-GPL-3.0 or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import traceback

try:
    import requests
except ImportError:
    HAS_REQUESTS_LIBRARY = False
    REQUESTS_LIBRARY_IMPORT_ERROR = traceback.format_exc()
else:
    HAS_REQUESTS_LIBRARY = True
    REQUESTS_LIBRARY_IMPORT_ERROR = None

DEFAULT_TIMEOUT = 30

_options = {"timeout": DEFAULT_TIMEOUT, "verify": True}


def configure(timeout=None, validate_certs=True, ca_path=None):
    _options["timeout"] = DEFAULT_TIMEOUT if timeout is None else timeout

    if not validate_certs:
        _options["verify"] = False
    else:
        _options["verify"] = ca_path or True


def request(method, url, **kwargs):
    for key, value in _options.items():
        kwargs.setdefault(key, value)

    return requests.request(method, url, **kwargs)


def raise_for_dvls_error(response):
    if response.ok:
        return

    raise Exception(
        f"{response.status_code} {response.reason} from {response.url}{_error_detail(response)}"
    )


def _error_detail(response):
    # Only the messages of a DVLS error body are shown: any other body (a proxy page, a stack trace)
    # can carry data that must not reach the Ansible output or its logs.
    try:
        body = response.json()
    except ValueError:
        return ""

    if not isinstance(body, dict):
        return ""

    parts = []
    message = body.get("message")
    if isinstance(message, str) and message:
        parts.append(message)

    errors = body.get("errors")
    for error in errors if isinstance(errors, list) else []:
        if not isinstance(error, dict) or not isinstance(error.get("message"), str):
            continue
        field = error.get("field")
        parts.append(
            f"{field}: {error['message']}" if isinstance(field, str) and field else error["message"]
        )

    detail = "; ".join(parts)[:500]
    return f": {detail}" if detail else ""

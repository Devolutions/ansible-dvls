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

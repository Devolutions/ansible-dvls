from __future__ import absolute_import, division, print_function

__metaclass__ = type


class FakeResponse(object):
    def __init__(self, status_code=200, body=None, text=None, url="https://dvls.test/api/v2/x"):
        self.status_code = status_code
        self.ok = 200 <= status_code < 300
        self.reason = "OK" if self.ok else "Error"
        self.url = url
        self._body = body
        self.text = text if text is not None else ""

    def json(self):
        if self._body is None:
            raise ValueError("not JSON")
        return self._body


class FakeSession(object):
    """Answers session.request from a handler(method, path, params) that returns a FakeResponse."""

    def __init__(self, handler):
        self.handler = handler
        self.calls = []

    def request(self, method, path, **kwargs):
        params = dict(kwargs.get("params") or {})
        self.calls.append((method, path, params))
        return self.handler(method, path, params)


def paged(items):
    return FakeResponse(body={"data": items, "currentPage": 1, "totalPage": 1, "totalCount": len(items)})

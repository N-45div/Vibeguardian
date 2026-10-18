"""Small stand-ins for HTTP sessions so tests never touch the network."""


class FakeResponse:
    def __init__(self, status, body=None):
        self.status_code = status
        self._body = body

    def json(self):
        if self._body is None:
            raise ValueError("no json")
        return self._body


class FakeHttp:
    """Answers requests from a routing table of (method, url) -> response.

    A route may map to a list of responses, returned in order.
    """

    def __init__(self, routes):
        self.routes = {key: list(v) if isinstance(v, list) else [v] for key, v in routes.items()}
        self.calls = []

    def _answer(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs))
        queue = self.routes.get((method, url))
        if not queue:
            raise AssertionError(f"unexpected {method} {url}")
        return queue.pop(0) if len(queue) > 1 else queue[0]

    def get(self, url, **kwargs):
        return self._answer("GET", url, **kwargs)

    def post(self, url, **kwargs):
        return self._answer("POST", url, **kwargs)

    def delete(self, url, **kwargs):
        return self._answer("DELETE", url, **kwargs)

    def patch(self, url, **kwargs):
        return self._answer("PATCH", url, **kwargs)

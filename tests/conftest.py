import socket

import pytest


@pytest.fixture(autouse=True)
def no_internet(monkeypatch):
    """A test never depends on a public site: only this machine's own addresses resolve."""
    real = socket.getaddrinfo

    def local_only(host, *args, **kwargs):
        if host in (None, "localhost", "127.0.0.1", "::1", b"localhost", b"127.0.0.1"):
            return real(host, *args, **kwargs)
        raise socket.gaierror(f"no internet in tests: {host!r}")
    monkeypatch.setattr(socket, "getaddrinfo", local_only)

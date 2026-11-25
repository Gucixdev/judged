import json
from datetime import datetime, timezone
from types import SimpleNamespace

from judged import web


def fake(responses):
    def get(host, scheme="https", path="/", method="GET"):
        return responses[(scheme, path)]
    return get


GOOD = {"content-security-policy": "default-src 'self'; frame-ancestors 'none'", "x-content-type-options": "nosniff",
        "referrer-policy": "no-referrer", "permissions-policy": "camera=()"}


def test_site_good_and_bad(monkeypatch):
    monkeypatch.setattr(web, "_all_cookies", lambda h: ["sid=1; Secure; HttpOnly; SameSite=Lax"])
    good = fake({("http", "/"): (301, {"location": "https://x.test/"}, None, b""), ("https", "/"): (200, GOOD, None, b""),
                 ("https", "/.well-known/security.txt"): (200, {}, None, b"Contact: mailto:a@b\nExpires: 2999-01-01T00:00:00Z\n")})
    res = {r.id.rsplit(".", 1)[1]: r for r in web.site("x.test", good)}
    assert {r.status for r in res.values()} == {"pass"}
    monkeypatch.setattr(web, "_all_cookies", lambda h: ["sid=1"])
    bad = fake({("http", "/"): (200, {}, None, b""), ("https", "/"): (200, {"server": "nginx/1.18.0"}, None, b""),
                ("https", "/.well-known/security.txt"): (404, {}, None, b"")})
    res = {r.id.rsplit(".", 1)[1]: r for r in web.site("x.test", bad)}
    assert res["redirect"].status == "warn" and res["headers"].status == "warn" and "content-security-policy" in res["headers"].evidence
    assert res["banner"].status == "warn" and "nginx/1.18.0" in res["banner"].evidence
    assert res["cookies"].status == "warn" and "Secure/HttpOnly/SameSite" in res["cookies"].evidence
    assert res["securitytxt"].status == "warn"


def test_security_txt_expired(monkeypatch):
    monkeypatch.setattr(web, "_all_cookies", lambda h: [])
    g = fake({("http", "/"): (301, {"location": "https://x.test/"}, None, b""), ("https", "/"): (200, GOOD, None, b""),
              ("https", "/.well-known/security.txt"): (200, {}, None, b"Expires: 2001-01-01T00:00:00Z\n")})
    r = {x.id.rsplit(".", 1)[1]: x for x in web.site("x.test", g)}["securitytxt"]
    assert r.status == "warn" and "past" in r.evidence


def test_dnssec():
    run = lambda cmd, **k: SimpleNamespace(stdout="2371 13 2 ABCD\n" if cmd[-1] == "example.test" else "", returncode=0)
    assert web.dnssec("www.example.test", run).status == "pass"
    assert web.dnssec("www.other.test", run).status == "warn"


def test_rdap_expiry_longest_name_first():
    seen = []

    class R:
        def __init__(self, body): self.body = body
        def __enter__(self): return self
        def __exit__(self, *a): pass
        def read(self, n=-1): return self.body

    def opener(req, timeout=0):
        seen.append(req.full_url)
        if req.full_url.endswith("/www.example.co.uk"):
            raise OSError("404")
        return R(json.dumps({"events": [{"eventAction": "expiration", "eventDate": "2027-05-01T00:00:00Z"}]}).encode())
    name, exp = web.rdap_expiry("www.example.co.uk", opener)
    assert name == "example.co.uk" and exp == datetime(2027, 5, 1, tzinfo=timezone.utc)
    assert seen[0].endswith("/www.example.co.uk")


def test_dns_failure_is_unknown_not_a_finding():
    down = lambda cmd, **k: SimpleNamespace(stdout="", returncode=9)
    assert web.dnssec("a.example.test", down).status == "unknown"
    from judged import mail, net
    import subprocess
    orig = subprocess.run
    subprocess.run = down
    try:
        assert mail.txt("example.test") is None and net.caa("example.test") is None
    finally:
        subprocess.run = orig

import shutil
import socket
import ssl
import subprocess
import threading
import time
from datetime import date

import pytest

from judged import mail, obligations, renew


def test_decide():
    assert renew.decide(60, 21, None, 1000, 6) == "ok"
    assert renew.decide(10, 21, None, 1000, 6) == "renew"
    assert renew.decide(10, 21, 1000 - 3600, 1000, 6) == "wait"          # tried an hour ago
    assert renew.decide(10, 21, 1000 - 7 * 3600, 1000, 6) == "renew"


@pytest.mark.skipif(not shutil.which("openssl"), reason="openssl needed")
def test_renew_end_to_end(tmp_path):
    cert, key = tmp_path / "c.pem", tmp_path / "k.pem"

    def issue(days):
        return ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key), "-out", str(cert),
                "-days", str(days), "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost"]

    subprocess.run(issue(3), check=True, capture_output=True)
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(8)
    srv.settimeout(0.2)
    stop = threading.Event()

    def serve():  # loads the cert from disk on every connection, like a service after a reload
        while not stop.is_set():
            try:
                c, _ = srv.accept()
            except socket.timeout:
                continue
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(cert, key)
            try:
                ctx.wrap_socket(c, server_side=True).close()
            except OSError:
                pass

    threading.Thread(target=serve, daemon=True).start()
    e = {"host": "localhost", "port": srv.getsockname()[1], "cafile": str(cert), "when_days": 21, "cmd": issue(90)}
    try:
        st, msg, tried = renew.renew_one(e, None, dry=True)
        assert st == "would-renew" and not tried
        st, msg, tried = renew.renew_one(e, None, dry=False)
        assert st == "renewed" and tried, msg
        st, _, _ = renew.renew_one(e, None, dry=False)                    # now 90 days: nothing to do
        assert st == "ok"
        subprocess.run(issue(3), check=True, capture_output=True)
        st, msg, _ = renew.renew_one({**e, "cmd": ["true"]}, None, dry=False)  # "succeeds" but deploys nothing
        assert st == "failed" and "did not change" in msg
        st, msg, _ = renew.renew_one({**e, "cmd": ["false"]}, None, dry=False)
        assert st == "failed" and "exit 1" in msg
        # a missing program and a hung command are failures of this host, never an exception for the whole pass
        st, msg, tried = renew.renew_one({**e, "cmd": ["/nonexistent/acme-client"]}, None, dry=False)
        assert st == "failed" and tried and "did not run" in msg
        st, msg, tried = renew.renew_one({**e, "cmd": ["sleep", "5"], "timeout": 1}, None, dry=False)
        assert st == "failed" and tried and "did not run" in msg
        st, msg, tried = renew.renew_one({**e, "cmd": ["true"], "reload": ["/nonexistent/reload"]}, None, dry=False)
        assert st == "failed" and "reload did not run" in msg
    finally:
        stop.set()


def test_spf_dmarc():
    assert mail.eval_spf("d", ["v=spf1 include:x -all"]).status == "pass"
    assert mail.eval_spf("d", ["v=spf1 include:x ~all"]).status == "warn"
    assert mail.eval_spf("d", ["v=spf1 +all"]).status == "fail"
    assert mail.eval_spf("d", ["v=spf1 -all", "v=spf1 ~all"]).status == "fail"
    assert mail.eval_spf("d", []).status == "fail"
    assert mail.eval_spf("d", None).status == "unknown"
    assert mail.eval_dmarc("d", ["v=DMARC1; p=reject; rua=mailto:a@b"]).status == "pass"
    assert mail.eval_dmarc("d", ["v=DMARC1; p=none"]).status == "warn"
    assert mail.eval_dmarc("d", []).status == "fail"


def test_obligations():
    cat = obligations.catalog()
    assert {o["id"] for o in obligations.for_regions(["UK"], cat)} >= {"ce-cert", "gdpr-breach"}
    assert "nis2-incident" not in {o["id"] for o in obligations.for_regions(["UK"], cat)}
    its = obligations.items({"obligation": [{"id": "ce-cert", "last_done": date(2026, 3, 1)},
                                            {"id": "gdpr-breach"}, {"id": "ce-cert-x", "last_done": date(2026, 1, 1)}]}, cat)
    assert len(its) == 1 and its[0].expires.date() == date(2027, 3, 1)


def test_unreviewed_flag():
    from datetime import date as d
    today = d(2026, 11, 24)
    assert obligations.unreviewed({}, today)
    assert obligations.unreviewed({"reviewed": d(2026, 1, 1)}, today)          # 327 days old
    assert not obligations.unreviewed({"reviewed": d(2026, 10, 1)}, today)
    assert "[UNREVIEWED]" in obligations.report({"company": {"regions": ["UK"]}}, today)


def test_lifetime_hint():
    from judged.renew import lifetime_hint
    assert lifetime_hint(90, 21) == ""
    assert "always due" in lifetime_hint(6, 21) and "below 6" in lifetime_hint(6, 21)
    assert "always due" in lifetime_hint(21, 21)


def test_renew_pass_survives_bad_hosts_damaged_state_and_missing_apprise(tmp_path, monkeypatch, capsys):
    import json
    from judged import __main__ as m, notify, conf
    state = tmp_path / "state"
    monkeypatch.setenv("XDG_STATE_HOME", str(state))
    (state / "judged").mkdir(parents=True)
    (state / "judged" / "renew.json").write_text("{not json")
    cfg = tmp_path / "judged.conf"
    cfg.write_text(conf.template() + 'renew a.invalid port=1 cmd=true\nrenew b.invalid port=1 cmd=true\n')
    monkeypatch.setattr(notify, "send", lambda *a, **k: (_ for _ in ()).throw(ImportError("No module named apprise")))
    calls = []
    real = renew.renew_one
    def fake(e, last, dry, **kw):
        calls.append(e["host"])
        if e["host"] == "a.invalid":
            return "failed", "boom", True
        return "renewed", "ok", True
    monkeypatch.setattr(renew, "renew_one", fake)
    rc = m.renew_pass(cfg, dry=False)
    out = capsys.readouterr().out
    assert calls == ["a.invalid", "b.invalid"]                       # the first failure did not stop the second host
    assert rc == 1 and "state file" in out and "unreadable" in out   # damaged state said, not fatal
    assert out.count("notification not sent") == 2                   # missing apprise said, not fatal
    saved = json.loads((state / "judged" / "renew.json").read_text())
    assert set(saved) == {"a.invalid", "b.invalid"}                  # both attempts remembered


def test_renew_line_without_cmd_is_a_config_error():
    import pytest
    from judged import conf
    with pytest.raises(conf.ConfError, match="needs cmd"):
        conf.parse("renew example.org port=443")

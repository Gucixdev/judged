import json
import os
import stat
import subprocess
import sys
from datetime import date
from pathlib import Path
from types import SimpleNamespace

from judged import conf, notify, report
from judged.controls import Result

TODAY = date(2026, 11, 24)


def res(status, title="T", ev="e"):
    return Result(f"x.{title}", title, status, ev, {})


def test_summary_state_title_and_worst_first():
    rs = [res("fail", f"Bad {i}", "ev") for i in range(7)] + [res("warn"), res("unknown"), res("pass")]
    s, title, body = report.summary(rs, TODAY)
    assert s == "fail" and title == "judged audit: 7 to fix, 1 to review, 1 unchecked"
    assert body.splitlines()[0].startswith("2026-11-24: 7 to fix") and body.count("\n- ") == 5 and "...and 2 more to fix. Full report attached." in body
    assert report.summary([res("warn")], TODAY)[0] == "warn" and report.summary([res("unknown")], TODAY)[0] == "warn"
    ok = report.summary([res("pass")], TODAY)
    assert ok[0] == "ok" and "Full report" not in ok[2]


def test_long_evidence_is_cut_in_the_summary_only():
    long = "x" * 500
    assert len(report.summary([res("fail", "A", long)], TODAY)[2]) < 300


def fake_notts(tmp_path, code=0, err="", out=""):
    log = tmp_path / "log.json"
    exe = tmp_path / "notts"
    exe.write_text(f"#!{sys.executable}\nimport sys, json\njson.dump({{'argv': sys.argv[1:], 'stdin': sys.stdin.read()}}, open({str(log)!r}, 'w'))\n"
                   f"sys.stdout.write({out!r})\nsys.stderr.write({err!r})\nsys.exit({code})\n")
    exe.chmod(exe.stat().st_mode | stat.S_IXUSR)
    return exe, log


def test_notts_gets_the_contract_flags_summary_on_stdin_and_the_file(tmp_path):
    exe, log = fake_notts(tmp_path)
    ok, how = notify.send_report({"notts": str(exe)}, [], "fail", "Title", "Body ąę\nline2", tmp_path / "raport.md", "judged-audit-2026-11-24.md")
    got = json.loads(log.read_text())
    assert ok and "notts" in how
    a = got["argv"]
    assert a[:1] == ["send"] and a[a.index("--app") + 1] == "judged" and a[a.index("--key") + 1] == "judged-audit"
    assert a[a.index("--state") + 1] == "fail" and a[a.index("--attach") + 1].endswith("raport.md") and a[a.index("--body-file") + 1] == "-"
    assert got["stdin"] == "Body ąę\nline2"                                    # the text goes through stdin, not through argv


def test_notts_failure_is_reported_and_apprise_is_not_tried_after_it(tmp_path):
    exe, _ = fake_notts(tmp_path, code=2, err="no channel configured")
    called = []
    ok, how = notify.send_report({"notts": str(exe)}, ["tgram://x"], "ok", "t", "b", tmp_path / "r.md", "n.md", apprise_send=lambda *a, **k: called.append(1) or True)
    assert not ok and "notts exit 2: no channel configured" in how and called == []


def test_timeout_and_unstartable_notts_are_said(tmp_path):
    def boom(argv, **kw):
        raise subprocess.TimeoutExpired("notts", 180)
    ok, how = notify.send_report({}, [], "ok", "t", "b", tmp_path, "n", run=boom, which=lambda c: "/x/notts")
    assert not ok and "may or may not have been delivered" in how
    def bad(argv, **kw):
        raise OSError("exec format error")
    assert "could not be started" in notify.send_report({}, [], "ok", "t", "b", tmp_path, "n", run=bad, which=lambda c: "/x/notts")[1]


def test_apprise_door_attaches_the_file_and_other_cases(tmp_path):
    seen = {}
    def fake(urls, title, body, attach=None):
        seen.update(urls=urls, attach=attach)
        return True
    ok, how = notify.send_report({}, ["tgram://x"], "warn", "t", "b", tmp_path / "r.md", "n.md", which=lambda c: None, apprise_send=fake)
    assert ok and seen["attach"].endswith("r.md") and "apprise" in how
    assert not notify.send_report({}, [], "warn", "t", "b", tmp_path, "n", which=lambda c: None)[0]                     # nowhere to send
    assert "not on PATH" in notify.send_report({"via": "notts"}, ["tgram://x"], "ok", "t", "b", tmp_path, "n", which=lambda c: None)[1]
    assert "not one of" in notify.send_report({"via": "carrier-pigeon"}, [], "ok", "t", "b", tmp_path, "n")[1]
    apprise_only = notify.send_report({"via": "apprise"}, ["u"], "ok", "t", "b", tmp_path, "n", which=lambda c: "/x/notts", apprise_send=fake)
    assert apprise_only[0]                                                                                              # via=apprise ignores notts
    def broken(*a, **k):
        raise ValueError("bad url")
    assert "ValueError: bad url" in notify.send_report({}, ["u"], "ok", "t", "b", tmp_path, "n", which=lambda c: None, apprise_send=broken)[1]


def test_audit_notify_end_to_end_exit_codes(tmp_path, monkeypatch):
    exe, log = fake_notts(tmp_path)
    cfg = tmp_path / "j.conf"
    cfg.write_text(conf.template() + f"flatpak enabled=0\nnotify notts={exe}\ncheck always-ok cmd=\"true\" maps=ce:updates\n")
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    env = {**os.environ, "XDG_STATE_HOME": str(tmp_path / "state"), "PYTHONPATH": str(Path(__file__).parent.parent)}
    r = subprocess.run([sys.executable, "-m", "judged", "audit", "-c", str(cfg), "--notify"], capture_output=True, text=True, env=env, timeout=250)
    got = json.loads(log.read_text())
    assert "sent:" in r.stdout and (tmp_path / "state/judged/reports/raport.md").is_file()
    assert got["argv"][got["argv"].index("--attach") + 1] == str(tmp_path / "state/judged/reports/raport.md")
    bad = tmp_path / "j2.conf"
    bad.write_text(conf.template() + "flatpak enabled=0\nnotify notts=/nonexistent/notts via=notts\ncheck always-ok cmd=\"true\" maps=ce:updates\n")
    r2 = subprocess.run([sys.executable, "-m", "judged", "audit", "-c", str(bad), "--notify"], capture_output=True, text=True, env=env, timeout=250)
    assert "NOT SENT" in r2.stderr and "not on PATH" in r2.stderr


def test_audit_exit_code_3_when_clean_but_not_delivered_and_1_when_findings(tmp_path, monkeypatch, capsys):
    from judged import __main__ as m, areas
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path))
    cfg = tmp_path / "c.conf"
    cfg.write_text(conf.template())
    def go(rs, delivered):
        monkeypatch.setattr(areas, "run_all", lambda c, ctx: rs)
        monkeypatch.setattr(m.notify, "send_report", lambda *a, **k: (delivered, "why"))
        return m.audit(cfg, None, False, None, True)
    assert go([res("pass")], True) == 0
    assert go([res("pass")], False) == 3
    assert go([res("fail")], False) == 1                      # a real finding keeps priority over a delivery problem
    assert "NOT SENT: why" in capsys.readouterr().err


def test_notts_words_are_used_and_queued_is_not_called_delivered(tmp_path):
    def go(code, payload):
        exe, _ = fake_notts(tmp_path, code, out=payload)
        return notify.send_report({"notts": str(exe)}, [], "fail", "t", "b", tmp_path / "r.md", "n.md")
    ok, how = go(0, json.dumps({"disposition": "sent", "reason": "sent; hook=sent", "results": [{"name": "hook", "status": "sent", "detail": "ok"}]}))
    assert ok and "notts: sent" in how and "hook=sent" in how
    ok, how = go(0, json.dumps({"disposition": "suppressed", "reason": "unchanged: state still fail", "results": [{"name": "hook", "status": "skipped", "detail": "unchanged"}]}))
    assert ok and "suppressed (unchanged: state still fail)" in how                      # not a failure, but not called delivered either
    ok, how = go(3, json.dumps({"disposition": "queued", "reason": "sent; hook=queued", "results": [{"name": "hook", "status": "queued", "detail": "ConnectionRefused"}]}))
    assert not ok and "queued" in how and "ConnectionRefused" in how
    assert go(0, "not json at all")[0]                                                   # an older notts: the exit code still decides

"""`unknown` must reach the reader: a check that crashes, a watch that cannot look. Neither may end up as pass or as silence."""
import subprocess
from datetime import date

from judged import __main__ as main
from judged import areas, checks, conf, controls, hardening, host, net, statement

CE = {"ce": controls.load_frameworks()["ce"]}


def stated(cid):
    return controls.Result("review.x", "review x", "pass", "said", {"ce": [cid]}, attested=True)


def rows(results):
    return {cid: st for cid, _, st, _ in controls.assemble("ce", CE["ce"], results)}


def boom(*a, **k):
    raise ValueError("garbage")


def test_one_crashing_host_check_marks_its_own_requirement_and_keeps_the_others(monkeypatch):
    monkeypatch.setattr(host, "extra_uid0", boom)
    monkeypatch.setattr(host, "run", lambda cmd, timeout=20: (None, ""))
    monkeypatch.setattr(host, "disk_encryption", lambda: controls.Result("host.disk", "Disk encryption", "pass", ""))
    got = {r.id: r for r in host.all_checks()}
    assert len(got) == 7 and got["host.uid0"].status == "unknown" and "crashed" in got["host.uid0"].evidence
    assert rows([got["host.uid0"], stated("acc-privileges")])["acc-privileges"] == "unknown"


def test_when_a_whole_part_crashes_nothing_reads_pass_and_the_report_says_why(monkeypatch, tmp_path):
    class Broken:
        NAME, ORDER, run = "broken", 1, staticmethod(boom)

    monkeypatch.setattr(areas, "discover", lambda: [Broken])
    [gone] = areas.run_all({}, areas.Ctx(date(2026, 11, 25), tmp_path))
    assert gone.status == "unknown" and gone.lost
    results = [gone, stated("fw-every-device"), controls.Result("m", "m", "fail", "", {"ce": ["upd-14-days"]})]
    got = rows(results)
    assert got["fw-every-device"] == "unknown" and got["upd-14-days"] == "fail" and got["scope"] == "manual"
    for text in (controls.markdown(CE, results), controls.soa(CE, results)):
        assert "Part of judged crashed" in text and "Audit area broken" in text
    assert "Part of judged crashed" not in controls.markdown(CE, results[1:])


def test_a_crashing_hardening_audit_counts_as_lost(monkeypatch):
    class Broken:
        NAME, ORDER, check = "broken", 1, staticmethod(boom)

    monkeypatch.setattr(hardening, "discover", lambda: [Broken])
    [gone] = hardening.run_all({})
    assert gone.status == "unknown" and gone.lost


def failing_gpg(*a, **k):
    return subprocess.CompletedProcess(a, 2, "", "gpg: keybox broken")


def test_a_gpg_that_fails_is_unknown_and_not_an_empty_list(monkeypatch):
    monkeypatch.setattr(subprocess, "run", failing_gpg)
    [r] = net.gpg()
    assert r.status == "unknown" and "exit 2" in r.evidence
    unseen: list = []
    main.collect({"item": [{"kind": "gpg"}]}, unseen)
    assert unseen[0][0] == "gpg" and "keybox broken" in unseen[0][1]


def test_a_blind_watch_is_said_once_on_the_second_pass_and_again_after_a_new_outage(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path))
    cfg = tmp_path / "j.conf"
    cfg.write_text(conf.template() + "tls shop.example\nflatpak enabled=0\nfeeds enabled=0\n")
    sent, works, delivers = [], [False], [True]

    def tls(name, host_, port=443):
        if not works[0]:
            raise OSError("certificate has expired")
        return []

    def send(urls, title, body):
        if delivers[0]:
            sent.append((title, body))
        return delivers[0]

    monkeypatch.setattr(checks, "tls", tls)
    monkeypatch.setattr(main.notify, "send", send)

    def run(times=1):
        for _ in range(times):
            main.once(cfg, False)
        return len(sent)

    assert run() == 0                                   # one blip stays quiet
    delivers[0] = False
    assert run() == 0
    delivers[0] = True
    assert run() == 1                                   # what did not get out is tried again
    assert sent[0] == ("judged: cannot check tls shop.example", "OSError: certificate has expired")
    assert run(3) == 1                                  # said once
    works[0] = True
    run()
    works[0] = False
    assert run(2) == 2                                  # a new outage is news again


def test_a_watched_text_that_cannot_be_read_is_blind_too():
    first = statement.blind("official text X", "no copy", {})
    assert (first.key, first.value, first.title) == ("blind:official text X", 1, "")
    assert statement.blind("official text X", "no copy", {first.key: 1}).title == "judged: cannot check official text X"
    assert statement.blind("official text X", "no copy", {first.key: 2}).title == ""

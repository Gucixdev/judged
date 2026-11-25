import json

from judged import statement as s


def r(status, **kw):
    return s.Result("i", "t", status, "e", **kw)


def test_status_words_are_plain_strings_everywhere():
    assert s.Status.PASS == "pass" and f"{s.Status.FAIL}" == "fail" and json.dumps(r(s.Status.WARN).__dict__["status"]) == '"warn"'


def test_the_worst_statement_wins_in_any_order():
    for low, high in [("pass", "unknown"), ("unknown", "warn"), ("warn", "fail")]:
        assert s.control_status([r(low), r(high)]) == s.control_status([r(high), r(low)]) == high
    assert s.control_status([]) == "manual" and s.control_status([r("na")]) == "manual" and s.control_status([r("na", attested=True)]) == "n/a"


def test_an_alert_is_remembered_only_once_it_is_out(capsys):
    sent = []
    alerts = [s.Alert("new", 1, "A", "a"), s.Alert("old", 2, "B", "b"), s.Alert("quiet", 3)]
    ok = s.deliver(alerts, {"new": 1, "old": 2}, {"old": 9}, lambda t, b: sent.append((t, b)) or True, False)
    assert ok == {"new": 1, "old": 2, "quiet": 3} and sent == [("A", "a"), ("B", "b")]
    failed = s.deliver(alerts, {"new": 1, "old": 2}, {"old": 9}, lambda t, b: False, False)
    assert failed == {"old": 9, "quiet": 3} and "not delivered: A" in capsys.readouterr().err
    assert s.deliver(alerts, {}, {}, lambda t, b: sent.append("never"), True)["old"] == 2 and "would send: B" in capsys.readouterr().out
    assert "never" not in sent

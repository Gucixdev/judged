from datetime import datetime, timedelta, timezone

from judged import checks, core

LEAD = [30, 14, 7, 1]
NOW = datetime(2026, 11, 24, tzinfo=timezone.utc)


def item(days):
    return core.Item("date", "x", NOW + timedelta(days=days))


def test_band():
    assert core.band(40, LEAD) is None
    assert core.band(20, LEAD) == 30
    assert core.band(10, LEAD) == 14
    assert core.band(0.5, LEAD) == 1
    assert core.band(-2, LEAD) == -1


def test_alert_once_per_band_then_more_urgent():
    alerts, st = core.due([item(20)], {}, LEAD, NOW)
    assert len(alerts) == 1
    alerts, st = core.due([item(19)], st, LEAD, NOW)      # same band, silent
    assert alerts == []
    alerts, st = core.due([item(10)], st, LEAD, NOW)      # more urgent band, alerts
    assert len(alerts) == 1


def test_renewal_resets():
    _, st = core.due([item(5)], {}, LEAD, NOW)
    _, st = core.due([item(400)], st, LEAD, NOW)          # renewed far ahead
    assert st == {}
    alerts, _ = core.due([item(5)], st, LEAD, NOW)        # next cycle alerts again
    assert len(alerts) == 1


def test_expired_alerts():
    alerts, _ = core.due([item(-1)], {}, LEAD, NOW)
    assert alerts[0][1] == -1


def test_parse_gpg():
    sample = "tru::1:1:1:0:3:1:5\npub:u:255:22:ABCDEF0123456789:1700000000:1900000000::u:::scESC:::::ed25519:::0:\n" \
             "fpr:::::::::AAAA:\nuid:u::::1700000000::HASH::Name <a@b>::::::::::0:\n" \
             "sub:u:255:18:1122334455667788:1700000000::::::e:::::cv25519::\n"
    items = checks.parse_gpg(sample)
    assert [i.name for i in items] == ["pub 23456789"]    # subkey without expiry skipped

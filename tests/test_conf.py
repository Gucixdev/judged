from datetime import date

import pytest

from judged import conf, controls, obligations


def test_parse_example_file():
    from pathlib import Path
    cfg = conf.load(Path(__file__).parent.parent / "judged.example.conf")
    kinds = [i["kind"] for i in cfg["item"]]
    assert kinds == ["tls", "gpg", "domain", "site", "date", "licence", "contract", "review", "certification"]
    lic = cfg["item"][5]
    assert lic == {"kind": "licence", "name": "IDE seats", "expires": date(2027, 3, 1), "vendor": "ExampleSoft", "cost": 1200.0,
                   "currency": "EUR", "owner": "dev", "auto_renews": False}
    assert cfg["item"][6] == {"kind": "contract", "name": "Hosting", "expires": date(2027, 3, 31), "type": "supplier", "notice_days": 90, "auto_renews": True,
                               "term_months": 12, "cost": 24000.0, "currency": "EUR", "owner": "anna", "vendor": "Acme"}
    assert cfg["notify"]["lead_days"] == [30, 14, 7, 1] and cfg["company"]["regions"] == ["EU", "PL"]
    assert cfg["renew"][0]["cmd"] == ["certbot", "renew", "--cert-name", "www.example.com"] and cfg["renew"][0]["when_days"] == 21
    assert cfg["secrets"]["history"] is False and cfg["deps"]["max_lookups"] == 300
    assert cfg["obligation"] == [{"id": "iso27001-surveillance", "last_done": date(2026, 5, 1)}]


def test_errors_carry_line_numbers():
    with pytest.raises(conf.ConfError, match=r"x:2: unknown directive 'tsl'"):
        conf.parse("tls a.test\ntsl b.test", "x")
    with pytest.raises(conf.ConfError, match=r"x:1: unknown key 'histroy'"):
        conf.parse("secrets histroy=yes", "x")
    with pytest.raises(conf.ConfError, match=r"x:1: .*not a valid date"):
        conf.parse('licence "a" 2027-13-45', "x")
    with pytest.raises(conf.ConfError, match=r"x:1: licence takes 2"):
        conf.parse("licence onlyname", "x")
    with pytest.raises(conf.ConfError, match="expected 1/0"):
        conf.parse("secrets history=maybe", "x")


def test_comments_continuation_and_merge():
    cfg = conf.parse('secrets repos=a,b   # why\nsecrets \\\n  history=yes\n# whole line\n\ngpg\n')
    assert cfg["secrets"] == {"repos": ["a", "b"], "history": True} and cfg["item"] == [{"kind": "gpg"}]


def test_catalog_matches_what_the_toml_files_held():
    fw = controls.load_frameworks()
    assert set(fw) == {"ce", "gdpr", "iso27001"} and len(fw["ce"]["controls"]) == 31
    assert fw["ce"]["confirm"] is True and "confirm" not in fw["gdpr"] and "confirm" not in fw["iso27001"]
    # a config that adds its own control to ce must not switch the confirm rule off
    own = conf.parse("framework ce 'Cyber Essentials'\ncontrol ce my-extra 'Mine'")
    merged = conf.merge(conf.catalog(), own)["frameworks"]["ce"]
    assert merged["confirm"] is True and merged["controls"]["my-extra"] == "Mine" and len(merged["controls"]) == 32
    assert fw["iso27001"]["controls"]["A.5.17"] == "Authentication information"
    cat = obligations.catalog()
    assert len(cat) == 7 and {o["kind"] for o in cat} == {"periodic", "event"}
    cra = next(o for o in cat if o["id"] == "cra-vuln")
    assert cra["kind"] == "event" and "24 h" in cra["deadline"] and cra["region"] == ["EU"]
    assert all("reviewed" not in o for o in cat)                 # nothing is reviewed yet: all print [UNREVIEWED]

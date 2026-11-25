from datetime import datetime, timezone
from pathlib import Path

from judged import checks, licences, secrets


def dist(root: Path, name: str, **fields):
    d = root / f"{name}-1.0.dist-info"
    d.mkdir(parents=True)
    head = f"Metadata-Version: 2.1\nName: {name}\nVersion: 1.0\n" + "".join(f"{k}: {v}\n" for k, v in fields.items())
    (d / "METADATA").write_text(head)


def test_classify():
    assert licences.classify("MIT")[0] == "permissive"
    assert licences.classify("Apache-2.0 OR GPL-3.0-only")[0] == "permissive"        # OR: pick the easier side
    assert licences.classify("MIT AND GPL-3.0-or-later")[0] == "strong-copyleft"      # AND: both bind
    assert licences.classify("GNU Lesser General Public License v3")[0] == "weak-copyleft"
    assert licences.classify("AGPL-3.0-only") == ("strong-copyleft", "AGPL")
    assert licences.classify("")[0] == "unknown" and licences.classify("Custom Corp EULA")[0] == "unknown"


def test_env_check(tmp_path):
    dist(tmp_path, "okpkg", **{"License-Expression": "MIT"})
    assert licences.env_check(str(tmp_path), [], []).status == "pass"
    dist(tmp_path, "mystery")
    r = licences.env_check(str(tmp_path), [], [])
    assert r.status == "warn" and "mystery" in r.evidence and "unknown" in r.evidence
    dist(tmp_path, "gplpkg", **{"License-Expression": "GPL-3.0-only"})
    assert licences.env_check(str(tmp_path), [], []).status == "warn"
    assert licences.env_check(str(tmp_path), ["GPL"], []).status == "fail"           # policy denies it
    assert licences.env_check(str(tmp_path), ["GPL"], ["gplpkg"]).status == "warn"   # reviewed exception, unknown remains


def test_calendar_by_year():
    now = datetime(2026, 11, 24, tzinfo=timezone.utc)
    items = (checks.date("IDE seats", __import__("datetime").date(2027, 3, 1), "licence", {"cost": 1200, "currency": "EUR", "vendor": "V"})
             + checks.date("CRM", __import__("datetime").date(2027, 9, 1), "licence", {"cost": 800, "currency": "EUR", "auto_renews": True})
             + checks.date("Old", __import__("datetime").date(2026, 1, 1), "licence", {})
             + checks.date("plain", __import__("datetime").date(2027, 1, 1)))      # kind date: not a bought licence
    out = licences.calendar(items, now)
    assert "total 2027: 2000.00 EUR" in out and "EXPIRED" in out and "auto-renews" in out
    assert "plain" not in out and "cost ?" in out
    assert out.index("2026") < out.index("2027")


def test_identity_skips_are_reported(monkeypatch):
    monkeypatch.setattr(secrets.getpass, "getuser", lambda: "root")
    monkeypatch.setattr(secrets.socket, "gethostname", lambda: "box")
    skipped = []
    secrets.identity_terms(skipped, extra=["acme-internal"])
    assert any("username" in s for s in skipped) and any("hostname" in s for s in skipped)
    assert "acme-internal" in secrets.identity_terms(extra=["acme-internal"]).values()


def test_classify_spdx_expressions_respect_brackets_and_with():
    c = lambda s: licences.classify(s)[0]
    assert c("GPL-3.0-only AND (MIT OR Apache-2.0)") == "strong-copyleft"      # was a false pass: the OR group must not hide the GPL
    assert c("(MIT OR Apache-2.0) AND GPL-3.0-only") == "strong-copyleft"
    assert c("MIT AND (GPL-3.0-only OR Apache-2.0)") == "permissive"           # the OR group picks Apache, AND with MIT stays easy
    assert c("MIT OR Apache-2.0 AND GPL-3.0-only") == "permissive"             # AND binds tighter than OR
    assert c("GPL-2.0-only WITH Classpath-exception-2.0") == "weak-copyleft"   # linking exception
    assert c("GPL-2.0-only WITH Some-unknown-exception") == "strong-copyleft"  # an exception we do not know does not soften anything
    assert c("MIT or Apache-2.0") == "permissive" and c("GPL-3.0+") == "strong-copyleft"


def test_classify_restricted_and_words():
    c = lambda s: licences.classify(s)[0]
    for s in ("CC-BY-NC-4.0", "CC-BY-NC-SA-4.0", "CC-BY-ND-4.0", "BUSL-1.1", "Elastic-2.0", "Proprietary", "Other/Proprietary License"):
        assert c(s) == "restricted", s
    assert c("GPL-3.0-only OR Proprietary") == "strong-copyleft"                # you may take the GPL side
    assert c("MIT AND Proprietary") == "restricted"                             # both bind
    assert c("GNU General Public License v2 or later (GPLv2+)") == "strong-copyleft"
    assert c("GNU Lesser General Public License v3 or later (LGPLv3+)") == "weak-copyleft"
    assert c("Custom Corp EULA") == "unknown"


def test_classify_survives_hostile_text():
    assert licences.classify("(" * 5000 + "MIT")[0] in ("permissive", "unknown")
    assert licences.classify("MIT OR " * 3000)[0] == "permissive"
    for s in ("(", ")", "AND", "OR", "WITH", "MIT WITH", "()", "MIT AND", "AND MIT", "x" * 100000, "\x00", "MIT\n\nGPL"):
        assert licences.classify(s)[0] in licences.RANK


def test_restricted_dependency_is_flagged_and_deniable(tmp_path):
    dist(tmp_path, "assets", **{"License-Expression": "CC-BY-NC-4.0"})
    r = licences.env_check(str(tmp_path), [], [])
    assert r.status == "warn" and "assets" in r.evidence and "restricted" in r.evidence
    assert licences.env_check(str(tmp_path), ["non-commercial"], []).status == "fail"


def test_every_local_spdx_id_gets_a_class_in_its_family():
    import os
    import pytest
    root = "/usr/share/licenses/spdx"
    if not os.path.isdir(root):
        pytest.skip("no local SPDX list (Arch package `licenses`)")
    ids = [f[:-4] for f in os.listdir(root) if f.endswith(".txt")]
    assert len(ids) > 50
    for i in ids:
        cls = licences.classify(i)[0]
        assert cls != "unknown", f"{i} is in the SPDX list but not recognised"
        if i.startswith(("AGPL-", "GPL-", "GFDL-")) and not i.startswith("GPL-CC"):
            assert cls == "strong-copyleft", i
        if i.startswith("LGPL-"):
            assert cls == "weak-copyleft", i
        if "-NC" in i or "-ND" in i:
            assert cls == "restricted", i
        if i.startswith(("Apache-", "BSL-", "CC0", "Unlicense", "Artistic-2")):
            assert cls == "permissive", i
    for exc in os.listdir(os.path.join(root, "exceptions")):
        name = exc.rsplit(".", 1)[0]
        assert licences.classify(f"GPL-3.0-only WITH {name}")[0] in ("weak-copyleft", "strong-copyleft"), name

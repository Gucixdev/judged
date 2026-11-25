from datetime import date
from pathlib import Path

import pytest

from judged import areas, conf


def test_every_option_has_a_default_and_every_section_a_doc():
    sections = conf._sections()
    d, docs = conf.defaults(), conf.docs()
    for sec, keys in sections.items():
        assert sec in d, f"section {sec} has no DEFAULTS"
        assert set(d[sec]) == set(keys), f"{sec}: DEFAULTS keys differ from SPEC keys {set(d[sec]) ^ set(keys)}"
        assert docs.get(sec), f"section {sec} has no DOC line"
    assert set(d) == set(sections)                                         # no defaults for sections that do not exist


def test_template_parses_back_to_exactly_the_defaults_and_is_complete():
    cfg = conf.parse(conf.template(), "template")
    conf.require_complete(cfg, "template")
    for sec, vals in conf.defaults().items():
        assert cfg[sec] == vals, sec


def test_missing_lists_absent_section_and_absent_keys():
    cfg = conf.parse("company regions=UK\nmalware enabled=1 paths=/a\n")
    gone = conf.missing(cfg)
    assert gone["company"] == ["mail_domains"] and "database" in gone["malware"] and "enabled" not in gone["malware"]
    assert gone["flatpak"] == ["enabled", "accept", "ignore", "leftovers"]            # a whole section that is not there


def test_error_names_what_to_add_with_the_default_value():
    with pytest.raises(conf.ConfError) as e:
        conf.require_complete(conf.parse("company regions=UK\n"), "x.conf")
    msg = str(e.value)
    assert "x.conf is incomplete" in msg and "company mail_domains=" in msg and "deps projects= deny= max_lookups=300" in msg and "judged config template" in msg


def test_bool_accepts_digits_and_words_and_rejects_the_rest():
    for raw, want in (("1", True), ("0", False), ("true", True), ("False", False), ("yes", True), ("off", False)):
        assert conf.value("bool", raw) is want
    with pytest.raises(ValueError, match="1/0"):
        conf.value("bool", "2")


def test_strict_load_reads_the_file_and_includes_count_towards_completeness(tmp_path):
    full = conf.template()
    (tmp_path / "all.conf").write_text(full)
    assert conf.load_strict(tmp_path / "all.conf")["flatpak"]["enabled"] is True
    lines = [l for l in full.splitlines() if not l.startswith("#")]
    (tmp_path / "main.conf").write_text("\n".join(l for l in lines if not l.startswith("malware")) + "\ninclude extra.conf\n")
    with pytest.raises(conf.ConfError):
        conf.load_strict(tmp_path / "main.conf")                                         # malware still missing
    (tmp_path / "extra.conf").write_text("\n".join(l for l in lines if l.startswith("malware")) + "\n")
    assert "malware" in conf.load_strict(tmp_path / "main.conf")                         # supplied by the included file


def test_enabled_zero_really_skips_the_work_even_when_paths_are_set(tmp_path, monkeypatch):
    from judged import containers, malware, sandbox
    calls = []
    monkeypatch.setattr(malware, "malware_check", lambda *a, **k: calls.append("malware") or [])
    monkeypatch.setattr(sandbox, "flatpak_check", lambda *a, **k: calls.append("flatpak") or [])
    monkeypatch.setattr(sandbox, "flatpak_leftovers", lambda *a, **k: calls.append("leftovers") or [])
    monkeypatch.setattr(containers, "containers_check", lambda *a, **k: calls.append("containers") or [])
    monkeypatch.setattr(containers, "files_check", lambda *a, **k: calls.append("files") or [])
    cfg = conf.parse(conf.template() + "malware paths=/data\ncontainers projects=/p\nflatpak enabled=0\n")
    ctx = areas.Ctx(date(2026, 11, 24), tmp_path)
    for m in areas.discover():
        m.run(cfg, ctx)
    assert calls == []                                                    # all three switched off, though malware has paths
    cfg = conf.parse(conf.template() + "malware enabled=1 paths=/data\ncontainers enabled=1 projects=/p\nflatpak enabled=1\n")
    for m in areas.discover():
        m.run(cfg, ctx)
    assert {"malware", "flatpak", "leftovers", "containers", "files"} <= set(calls)


def test_the_cli_loader_is_strict(tmp_path):
    from judged import __main__ as m
    (tmp_path / "p.conf").write_text("company regions=UK\n")
    with pytest.raises(conf.ConfError, match="incomplete"):
        m.load(tmp_path / "p.conf")
    (tmp_path / "f.conf").write_text(conf.template())
    assert m.load(tmp_path / "f.conf")["company"]["regions"] == []


def test_deps_deny_falls_back_to_the_licence_deny_list(tmp_path, monkeypatch):
    from judged import deps
    seen = []
    monkeypatch.setattr(deps, "project", lambda root, deny, *a, **k: seen.append(deny) or [])
    (tmp_path / "proj").mkdir()
    ctx = areas.Ctx(date(2026, 11, 24), tmp_path)
    soft = [m for m in areas.discover() if m.NAME == "software"][0]
    soft.run(conf.parse(conf.template() + f"licences deny=GPL\ndeps projects={tmp_path}/proj\n"), ctx)
    soft.run(conf.parse(conf.template() + f"licences deny=GPL\ndeps projects={tmp_path}/proj deny=AGPL\n"), ctx)
    assert seen == [["GPL"], ["AGPL"]]


def test_audit_without_a_config_file_says_how_to_create_one(tmp_path):
    from judged import __main__ as m
    with pytest.raises(conf.ConfError, match="judged config template"):
        m.audit(tmp_path / "none.conf", None, False)


def test_the_shipped_example_config_is_complete():
    conf.require_complete(conf.load(Path(__file__).parent.parent / "judged.example.conf"), "judged.example.conf")

from pathlib import Path

from judged import areas, conf

DOC = (Path(__file__).resolve().parent.parent / "docs" / "coverage.md").read_text()


def specs():
    out = dict(conf.SPEC)
    for m in areas.discover():
        out.update(getattr(m, "SPEC", {}))
    return out


def test_every_option_is_in_the_coverage_doc():
    missing = [f"{sec}.{k}" for sec, v in specs().items() for k in v[1] if f"| `{k}` |" not in DOC]
    assert missing == []


def test_every_section_has_a_heading_and_no_option_is_undocumented():
    assert "(undocumented)" not in DOC
    for sec in specs():
        assert sec in DOC


def test_every_plugin_file_is_named():
    import importlib
    import pkgutil
    for pkg in ["hardening", "agentchecks", "codestd", "feeds", "inits", "pkgmgrs", "backups", "renewers", "licsources", "sbom"]:
        p = importlib.import_module("judged." + pkg)
        for m in pkgutil.iter_modules(p.__path__):
            assert f"`{m.name}`" in DOC, f"{pkg}/{m.name} is not listed in docs/coverage.md"

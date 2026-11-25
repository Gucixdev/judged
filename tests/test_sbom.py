import os
import json
import subprocess
import sys
from pathlib import Path

import pytest

from judged import sbom
from judged.sbom import Component, cyclonedx, spdx

DOC = {"name": "proj", "created": "2026-11-24T10:00:00Z", "notes": ["n1"],
       "components": [Component("npm", "@scope/pkg", "1.0.0"), Component("PyPI", "My_Pkg.Name", "2.0+local"), Component("Go", "github.com/a/b", "v1.2.3")]}


def test_purl_rules_for_each_ecosystem():
    assert sbom.purl("npm", "left-pad", "1.3.0") == "pkg:npm/left-pad@1.3.0"
    assert sbom.purl("npm", "@scope/pkg", "1.0.0") == "pkg:npm/%40scope/pkg@1.0.0"
    assert sbom.purl("PyPI", "My_Pkg.Name", "2.0+local") == "pkg:pypi/my-pkg-name@2.0%2Blocal"
    assert sbom.purl("Go", "github.com/a/b", "v1.2.3") == "pkg:golang/github.com/a/b@v1.2.3"
    assert sbom.purl("Maven", "org.x:lib", "1") == "pkg:maven/org.x/lib@1"
    assert sbom.purl("crates.io", "serde", "1.0.0") == "pkg:cargo/serde@1.0.0"
    assert sbom.purl("RubyGems", "rails", "7.0") == "pkg:gem/rails@7.0" and sbom.purl("Packagist", "a/b", "1") == "pkg:composer/a/b@1"
    with pytest.raises(KeyError):
        sbom.purl("Hackage", "x", "1")                                  # an unknown ecosystem is never given a made-up type


def test_collect_notes_say_when_the_list_is_empty_or_a_lockfile_is_broken(tmp_path):
    comps, notes = sbom.collect(str(tmp_path))
    assert comps == [] and any("EMPTY" in n for n in notes) and any("registry packages only" in n for n in notes)
    (tmp_path / "package-lock.json").write_text("{broken")
    comps, notes = sbom.collect(str(tmp_path))
    assert comps == [] and any("unreadable lockfile" in n for n in notes)


def test_collect_reads_a_real_lockfile_dedupes_and_sorts(tmp_path):
    (tmp_path / "Cargo.lock").write_text('[[package]]\nname = "b"\nversion = "1.0.0"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\n\n'
                                         '[[package]]\nname = "a"\nversion = "2.0.0"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\n\n'
                                         '[[package]]\nname = "mine"\nversion = "0.1.0"\n')
    comps, _ = sbom.collect(str(tmp_path))
    assert [(c.name, c.version) for c in comps] == [("a", "2.0.0"), ("b", "1.0.0")]               # the workspace crate (no source) is left out


def test_serial_is_stable_for_the_same_input_and_changes_with_it():
    a = sbom.serial("p", DOC["components"])
    assert a == sbom.serial("p", DOC["components"]) and a != sbom.serial("p", DOC["components"][:2]) and a != sbom.serial("q", DOC["components"])


def test_cyclonedx_shape_and_notes():
    d = json.loads(cyclonedx.render(DOC))
    assert d["bomFormat"] == "CycloneDX" and d["specVersion"] == "1.5" and d["serialNumber"].startswith("urn:uuid:")
    assert [c["purl"] for c in d["components"]] == [c.purl for c in DOC["components"]] and d["components"][0]["bom-ref"] == d["components"][0]["purl"]
    assert d["metadata"]["properties"][0]["value"] == "n1" and d["metadata"]["component"]["name"] == "proj"


def test_spdx_ids_are_legal_unique_and_every_package_is_described():
    d = json.loads(spdx.render(DOC))
    ids = [p["SPDXID"] for p in d["packages"]]
    assert len(set(ids)) == 3 and all(__import__("re").fullmatch(r"SPDXRef-[A-Za-z0-9.-]+", i) for i in ids)
    assert [r["relatedSpdxElement"] for r in d["relationships"]] == ids and d["spdxVersion"] == "SPDX-2.3"
    assert d["packages"][0]["externalRefs"][0]["referenceLocator"] == "pkg:npm/%40scope/pkg@1.0.0" and "n1" in d["creationInfo"]["comment"]
    twin = {**DOC, "components": [Component("npm", "a b", "1"), Component("npm", "a-b", "1")]}      # different names that clean up to the same id text
    assert len({p["SPDXID"] for p in json.loads(spdx.render(twin))["packages"]}) == 2


def test_empty_component_list_renders_valid_json_for_both():
    empty = {**DOC, "components": []}
    assert json.loads(cyclonedx.render(empty))["components"] == [] and json.loads(spdx.render(empty))["packages"] == []


def test_a_new_format_is_one_file(monkeypatch, tmp_path):
    (tmp_path / "plain.py").write_text('NAME, EXT = "plain", ".txt"\ndef render(doc):\n    return "\\n".join(c.purl for c in doc["components"])\n')
    monkeypatch.setattr(sbom, "__path__", list(sbom.__path__) + [str(tmp_path)])
    try:
        f = sbom.formats()
        assert {"cyclonedx", "spdx", "plain"} <= set(f) and f["plain"].render(DOC).splitlines()[0] == "pkg:npm/%40scope/pkg@1.0.0"
    finally:
        sys.modules.pop("judged.sbom.plain", None)


def run(*args, cwd=None):
    env = {"PYTHONPATH": str(Path(__file__).parent.parent), "PATH": "/usr/bin:/bin", "XDG_STATE_HOME": str(cwd)}
    return subprocess.run([sys.executable, "-m", "judged", "sbom", *args], capture_output=True, text=True, env=env, timeout=60)


def test_cli_stdout_out_dir_and_the_three_refusals(tmp_path):
    proj = tmp_path / "p"
    proj.mkdir()
    (proj / "package-lock.json").write_text(json.dumps({"lockfileVersion": 3, "packages": {"": {}, "node_modules/x": {"version": "1.0.0", "resolved": "https://registry.npmjs.org/x/-/x-1.0.0.tgz"}}}))
    r = run("--project", str(proj), "--format", "spdx", cwd=tmp_path)
    assert r.returncode == 0 and json.loads(r.stdout)["packages"][0]["name"] == "x" and "1 components" in r.stderr
    r = run("--project", str(proj), "--out", str(tmp_path / "o"), cwd=tmp_path)
    assert r.returncode == 0 and (tmp_path / "o" / "p.cdx.json").is_file() and r.stdout == ""
    bad = run("--project", str(proj), "--format", "nope", cwd=tmp_path)
    assert bad.returncode == 2 and "known: cyclonedx, spdx" in bad.stderr
    empty = tmp_path / "e"
    empty.mkdir()
    assert "(EMPTY)" in run("--project", str(empty), cwd=tmp_path).stderr


def test_documents_pass_the_official_schemas_when_they_are_available(tmp_path):
    """The schemas are downloaded by hand into $JUDGED_TEST_DATA/schemas (default ~/.cache/judged-tests; CycloneDX 1.5, SPDX 2.3); without them the test is skipped, not green."""
    data = Path(os.environ.get("JUDGED_TEST_DATA", str(Path.home() / ".cache/judged-tests")))
    schemas = data / "schemas"
    venv = data / "venv-schema/bin/python"
    if not (schemas / "validate.py").is_file() or not venv.is_file():
        pytest.skip("official schemas or validator not available here")
    cdx, sp = tmp_path / "a.cdx.json", tmp_path / "a.spdx.json"
    cdx.write_text(cyclonedx.render(DOC))
    sp.write_text(spdx.render(DOC))
    r = subprocess.run([str(venv), "validate.py", str(cdx), str(sp)], cwd=schemas, capture_output=True, text=True, timeout=120)
    assert "cyclonedx VALID" in r.stdout and "spdx VALID" in r.stdout and "negative control rejected: True" in r.stdout, r.stdout + r.stderr

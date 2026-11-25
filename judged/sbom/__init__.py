"""Software bill of materials from the lockfiles of your projects. Three separate parts, each replaceable:
 - components: what is in the project (this file: collect + purl), read from the same lockfile parsers the audit uses;
 - formats: one file per output format in this folder (cyclonedx.py, spdx.py), found automatically. A new format = a file with
       NAME = "myformat", EXT = ".my.json" and render(doc) -> str.   Nothing else changes.
 - the command: `judged sbom` (see __main__).
`doc` handed to a format: {"name", "created" (ISO UTC), "components": [Component], "notes": [str]}.
What is NOT in it, and the notes say so: git, path and tarball dependencies (the lockfile parsers list registry packages only),
the dependency graph (who needs whom), hashes and licences. A component list that looks complete when it is not would be worse than none."""
import glob
import hashlib
import importlib
import pkgutil
import re
import uuid
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import quote

from .. import lockfiles

PURL_TYPE = {"npm": "npm", "crates.io": "cargo", "Go": "golang", "PyPI": "pypi", "Maven": "maven", "RubyGems": "gem", "NuGet": "nuget", "Packagist": "composer"}


@dataclass(frozen=True, order=True)
class Component:
    eco: str
    name: str
    version: str

    @property
    def purl(self) -> str:
        return purl(self.eco, self.name, self.version)


def purl(eco: str, name: str, version: str) -> str:
    """Package URL (https://github.com/package-url/purl-spec). Unknown ecosystems are an error, not a made-up type."""
    t = PURL_TYPE[eco]
    if eco == "PyPI":
        name = re.sub(r"[-_.]+", "-", name).lower()
    if eco == "Maven":                                   # OSV writes group:artifact, a purl writes group/artifact
        name = name.replace(":", "/", 1)
    return f"pkg:{t}/{quote(name, safe='/')}@{quote(version, safe='')}"


def projects(patterns: list) -> list:
    return [r for pat in patterns for r in sorted(glob.glob(str(Path(pat).expanduser()))) if Path(r).is_dir()]


def collect(root: str) -> tuple:
    """(components, notes) of one project. A lockfile that cannot be read is a note, never a silently smaller list."""
    files, notes, comps = lockfiles.find(root), [], set()
    if not files:
        notes.append("no lockfile found, so this list is EMPTY, not complete")
    for f in files:
        got, err = lockfiles.read(f)
        if err:
            notes.append(f"unreadable lockfile: {err}")
        for eco, name, ver in got:
            if eco in PURL_TYPE:
                comps.add(Component(eco, name, ver))
            else:
                notes.append(f"{name} {ver}: ecosystem {eco} has no purl type here, left out")
    notes.append("registry packages only: git, path and tarball dependencies are not listed; no dependency graph, hashes or licences")
    return sorted(comps), notes


def serial(name: str, comps: list) -> str:
    """Same input, same serial: the document id is derived from what it describes, not random."""
    h = hashlib.sha256((name + "\n" + "\n".join(c.purl for c in comps)).encode()).hexdigest()
    return str(uuid.UUID(h[:32]))


def formats() -> dict:
    mods = [importlib.import_module(f"{__name__}.{m.name}") for m in pkgutil.iter_modules(__path__)]
    return {m.NAME: m for m in mods if hasattr(m, "render") and hasattr(m, "NAME")}

"""Where the licence of a dependency comes from. One file per source, found automatically. A file here has

    ECOSYSTEMS = ("npm", "crates.io")                         # the names lockfiles.py uses (OSV spelling)
    def licence(eco, name, version, get) -> str | None        # "MIT", "MIT AND ISC", "" = the registry lists none, None = version not found

`get(url) -> parsed JSON` is injected (tests give exact answers); a network error is raised as OSError and the caller reports it as unknown.
Two sources must not claim the same ecosystem. A new source is a new file, nothing else changes."""
import importlib
import pkgutil


def discover() -> list:
    return [importlib.import_module(f"{__name__}.{m.name}") for m in pkgutil.iter_modules(__path__)]


def find(eco: str):
    for m in discover():
        if eco in m.ECOSYSTEMS:
            return m
    return None


def covered() -> set:
    return {e for m in discover() for e in m.ECOSYSTEMS}
